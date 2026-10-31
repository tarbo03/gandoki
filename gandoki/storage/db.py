"""SQLite job + finding store, shared by CLI and MCP.

Design notes:
  - Never stores raw credential values. Findings are persisted as their
    redacted public-dict form — the trust boundary is identical to the
    JSON report.
  - Diff identity = (secret_type, asset_url, byte_offset). This is stable
    across re-scans unless the asset changes enough to shift offsets.
    Documented as a known limitation.
  - WAL mode enabled so CLI and MCP can run concurrently without lock
    contention. busy_timeout handles transient contention.
"""
from __future__ import annotations
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id            TEXT PRIMARY KEY,
    status        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    finished_at   TEXT,
    request_json  TEXT,
    summary_json  TEXT,
    coverage_json TEXT,
    error         TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    job_id       TEXT NOT NULL,
    finding_id   TEXT NOT NULL,
    secret_type  TEXT NOT NULL,
    asset_url    TEXT NOT NULL,
    byte_offset  INTEGER NOT NULL,
    section      TEXT NOT NULL,
    finding_json TEXT NOT NULL,
    PRIMARY KEY (job_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_identity
    ON findings (secret_type, asset_url, byte_offset);
CREATE INDEX IF NOT EXISTS idx_findings_section
    ON findings (job_id, section);
CREATE INDEX IF NOT EXISTS idx_jobs_created
    ON jobs (created_at DESC);
"""


@contextmanager
def connect(db_path: str = "gandoki.db"):
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(_SCHEMA)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def resolve_job_id(db_path: str, job_id_or_prefix: str) -> str | None:
    """Resolve a full job_id or a unique prefix to the full id.

    Returns None if not found OR if the prefix is ambiguous.
    12-char hex prefix collision is astronomically improbable (2^48 space),
    so 'ambiguous' is indistinguishable from 'not found' in practice — the
    user can retype with more characters if it ever happens.
    """
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT id FROM jobs WHERE id=?", (job_id_or_prefix,)
        ).fetchone()
        if row:
            return row[0]
        rows = conn.execute(
            "SELECT id FROM jobs WHERE id LIKE ? LIMIT 2",
            (job_id_or_prefix + "%",),
        ).fetchall()
        if len(rows) == 1:
            return rows[0][0]
        return None


def create_job(db_path: str, job_id: str, request: dict) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO jobs (id, status, created_at, request_json) "
            "VALUES (?, 'pending', ?, ?)",
            (job_id, _now(), json.dumps(request)),
        )


def update_job_status(
    db_path: str,
    job_id: str,
    status: str,
    *,
    summary: dict | None = None,
    error: str | None = None,
    coverage: dict | None = None,
) -> None:
    finished = _now() if status in ("done", "error", "timeout") else None
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE jobs SET status=?, finished_at=?, summary_json=?, "
            "coverage_json=?, error=? WHERE id=?",
            (
                status,
                finished,
                json.dumps(summary) if summary else None,
                json.dumps(coverage) if coverage else None,
                error,
                job_id,
            ),
        )


def save_findings(db_path: str, job_id: str, findings: list[dict]) -> None:
    """Findings MUST be already in public-dict form (redacted).

    We extract the (secret_type, asset_url, byte_offset, section) identity
    columns for fast diffing, and store the full dict as JSON.
    """
    if not findings:
        return
    rows = []
    for f in findings:
        rows.append((
            job_id,
            f["finding_id"],
            f["secret_type"],
            f["evidence"]["asset_url"],
            int(f["evidence"]["byte_offset"]),
            f["section"],
            json.dumps(f, default=str),
        ))
    with connect(db_path) as conn:
        conn.executemany(
            "INSERT OR REPLACE INTO findings "
            "(job_id, finding_id, secret_type, asset_url, byte_offset, section, finding_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )


def get_job(db_path: str, job_id: str) -> dict | None:
    resolved = resolve_job_id(db_path, job_id)
    if resolved is None:
        return None
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, status, created_at, finished_at, request_json, "
            "summary_json, coverage_json, error FROM jobs WHERE id=?",
            (resolved,),
        ).fetchone()
    if not row:
        return None
    return {
        "job_id": row[0],
        "status": row[1],
        "created_at": row[2],
        "finished_at": row[3],
        "request": json.loads(row[4]) if row[4] else None,
        "summary": json.loads(row[5]) if row[5] else None,
        "coverage": json.loads(row[6]) if row[6] else None,
        "error": row[7],
    }


def get_findings(
    db_path: str,
    job_id: str,
    *,
    section: str | None = None,
) -> list[dict]:
    resolved = resolve_job_id(db_path, job_id)
    if resolved is None:
        return []
    sql = "SELECT finding_json FROM findings WHERE job_id=?"
    params: list = [resolved]
    if section:
        sql += " AND section=?"
        params.append(section)
    with connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [json.loads(r[0]) for r in rows]


def list_jobs(db_path: str, limit: int = 50) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, status, created_at, finished_at, summary_json "
            "FROM jobs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {
            "job_id": r[0],
            "status": r[1],
            "created_at": r[2],
            "finished_at": r[3],
            "summary": json.loads(r[4]) if r[4] else None,
        }
        for r in rows
    ]


def diff_jobs(db_path: str, job_a: str, job_b: str) -> dict:
    """Compare ACCEPTED findings between two jobs.

    A finding's identity is (secret_type, asset_url, byte_offset).
    Returns new / fixed / persisting lists plus metadata.

    Retracted findings are NOT diffed — a finding that moved to RETRACTED
    is neither fixed nor persisting. Use `gandoki show <job>` to inspect
    retraction separately.
    """
    resolved_a = resolve_job_id(db_path, job_a)
    resolved_b = resolve_job_id(db_path, job_b)
    if resolved_a is None or resolved_b is None:
        missing = job_a if resolved_a is None else job_b
        raise ValueError(f"job not found: {missing}")
    job_a, job_b = resolved_a, resolved_b
    jd_a = get_job(db_path, job_a)
    jd_b = get_job(db_path, job_b)

    with connect(db_path) as conn:
        # Identity rows only — cheap
        def _ids(job_id):
            rows = conn.execute(
                "SELECT secret_type, asset_url, byte_offset, finding_id "
                "FROM findings WHERE job_id=? AND section='ACCEPTED'",
                (job_id,),
            ).fetchall()
            return {
                (r[0], r[1], int(r[2])): r[3] for r in rows
            }

        ids_a = _ids(job_a)
        ids_b = _ids(job_b)

        new_keys = set(ids_b) - set(ids_a)
        fixed_keys = set(ids_a) - set(ids_b)
        persisting_keys = set(ids_a) & set(ids_b)

        def _fetch_by_ids(job_id: str, finding_ids: list[str]) -> list[dict]:
            if not finding_ids:
                return []
            qmarks = ",".join("?" for _ in finding_ids)
            rows = conn.execute(
                f"SELECT finding_json FROM findings "
                f"WHERE job_id=? AND finding_id IN ({qmarks})",
                [job_id] + finding_ids,
            ).fetchall()
            return [json.loads(r[0]) for r in rows]

        new_findings = _fetch_by_ids(job_b, [ids_b[k] for k in new_keys])
        fixed_findings = _fetch_by_ids(job_a, [ids_a[k] for k in fixed_keys])
        persisting = _fetch_by_ids(job_b, [ids_b[k] for k in persisting_keys])

    return {
        "job_a": job_a,
        "job_b": job_b,
        "summary": {
            "new_count": len(new_findings),
            "fixed_count": len(fixed_findings),
            "persisting_count": len(persisting),
        },
        "new": new_findings,
        "fixed": fixed_findings,
        "persisting": persisting,
        "note": (
            "Diff compares ACCEPTED findings only. Findings that moved to "
            "RETRACTED in job_b are neither fixed nor persisting — inspect "
            "gandoki show <job_b> for retraction details."
        ),
    }


def cleanup_old_jobs(db_path: str, keep_days: int = 30) -> int:
    """Delete jobs older than keep_days. Returns number of jobs deleted."""
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=keep_days)).isoformat()
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id FROM jobs WHERE created_at < ?", (cutoff,)
        ).fetchall()
        ids = [r[0] for r in rows]
        if not ids:
            return 0
        qmarks = ",".join("?" for _ in ids)
        conn.execute(f"DELETE FROM findings WHERE job_id IN ({qmarks})", ids)
        conn.execute(f"DELETE FROM jobs WHERE id IN ({qmarks})", ids)
    return len(ids)
