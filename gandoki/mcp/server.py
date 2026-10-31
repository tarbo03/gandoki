"""MCP server exposing Gandoki as tools.

Guardrails (see docs/MCP_SERVER.md):
  1. Raw secrets are NEVER returned. Findings come back redacted via the
     same Finding.to_public_dict() the JSON report uses.
  2. Every finding carries confidence tier + validation.status + impact.caveat
     so the model summarizing it cannot overclaim.
  3. SUSPECTED findings are suppressed by default (same policy as CLI).
  4. Destructive validators never fire.
  5. Retracted findings are visible in the `retracted` array — never hidden.

TRUST BOUNDARY: this is a local-trust tool. Do not expose this server to a
network. scan_file reads any filesystem path the server user can read.
"""
from __future__ import annotations
import asyncio
import uuid
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from ..config import load_config
from ..discovery.file_input import load_domains_file
from ..pipeline.orchestrator import run_scan
from ..report.json_report import build_report
from ..storage import db


mcp = FastMCP("gandoki")


def _load_cfg() -> dict:
    try:
        return load_config("config/config.yaml")
    except FileNotFoundError:
        return load_config(Path(__file__).resolve().parents[2] / "config" / "config.yaml")


async def _execute_scan(
    *,
    domains: list[str],
    cfg: dict,
    include_suspected: bool,
    job_id: str,
) -> dict:
    db.update_job_status(cfg["db_path"], job_id, "running")
    try:
        result = await run_scan(
            cfg=cfg,
            extra_domains=domains,
            include_suspected=include_suspected,
            ai_override_enabled=cfg.get("ai", {}).get("enabled"),
        )
        report = build_report(
            result.findings,
            include_suspected=include_suspected,
            coverage_manifest=result.coverage_manifest,
        )
        rows = report["findings"] + report["retracted"]
        db.save_findings(cfg["db_path"], job_id, rows)
        db.update_job_status(
            cfg["db_path"], job_id, "done",
            summary={
                "accepted": len(report["findings"]),
                "retracted": len(report["retracted"]),
                "domains_scanned": result.domains_scanned,
            },
            coverage=result.coverage_manifest,
        )
        return {
            "status": "done",
            "job_id": job_id,
            "domains_scanned": result.domains_scanned,
            "accepted": report["findings"],
            "retracted": report["retracted"],
            "coverage": result.coverage_manifest,
            "note": (
                "FORMAT_MATCH findings were NOT validated against the "
                "third party. Treat as potentially live until rotated. "
                "Retracted findings are visible in `retracted` for spot-check."
            ),
        }
    except Exception as e:
        db.update_job_status(
            cfg["db_path"], job_id, "error", error=f"{type(e).__name__}: {e}",
        )
        return {
            "status": "error",
            "job_id": job_id,
            "error": f"{type(e).__name__}: {e}",
        }


@mcp.tool()
async def scan_domains(
    domains: list[str],
    wait: bool = True,
    timeout_s: int = 300,
    include_suspected: bool = False,
) -> dict:
    """Scan a list of domains for exposed secrets and debug exposures.

    Args:
        domains: Hostnames (e.g. ["app.example.com"]).
        wait: If True, block up to timeout_s. If False, return immediately
              with a job_id to poll via get_job.
        timeout_s: Max seconds to wait when wait=True.
        include_suspected: Include low-confidence SUSPECTED findings.

    Returns:
        {status, job_id?, accepted?, retracted?, coverage?}
        Findings are redacted. Every finding carries tier + validation.status
        + impact.caveat. Retracted findings are visible, not hidden.
    """
    if not domains:
        return {"status": "error", "error": "domains list is empty"}

    cfg = _load_cfg()
    job_id = uuid.uuid4().hex
    db.create_job(cfg["db_path"], job_id, {"domains": domains})

    coro = _execute_scan(
        domains=domains, cfg=cfg,
        include_suspected=include_suspected, job_id=job_id,
    )
    if wait:
        try:
            return await asyncio.wait_for(coro, timeout=timeout_s)
        except asyncio.TimeoutError:
            return {
                "status": "timeout",
                "job_id": job_id,
                "note": (
                    f"Scan exceeded {timeout_s}s. Job continues in background; "
                    f"poll get_job('{job_id}') for results."
                ),
            }
    asyncio.create_task(coro)
    return {
        "status": "queued",
        "job_id": job_id,
        "note": "Poll get_job(job_id) for results.",
    }


@mcp.tool()
async def scan_file(
    path: str,
    wait: bool = True,
    timeout_s: int = 300,
    include_suspected: bool = False,
) -> dict:
    """Scan a CSV or TXT domain list.

    Args:
        path: Filesystem path to a .txt or .csv file (relative to server CWD
              or absolute). .csv auto-detects a domain/url/host column.
        wait, timeout_s, include_suspected: same as scan_domains.

    Returns:
        Same shape as scan_domains, plus a `file_input` block.
    """
    try:
        loaded = load_domains_file(path)
    except FileNotFoundError as e:
        return {"status": "error", "error": str(e)}

    if not loaded.domains:
        return {
            "status": "error",
            "error": "no valid domains in file",
            "file_input": {
                "unique_domains": 0,
                "skipped_invalid_sample": loaded.skipped_invalid[:10],
            },
        }

    result = await scan_domains(
        domains=loaded.domains, wait=wait,
        timeout_s=timeout_s, include_suspected=include_suspected,
    )
    result["file_input"] = {
        "source_file": loaded.source_file,
        "unique_domains": len(loaded.domains),
        "skipped_invalid_count": len(loaded.skipped_invalid),
        "skipped_invalid_sample": loaded.skipped_invalid[:10],
        "skipped_duplicates": loaded.skipped_duplicates,
    }
    return result


@mcp.tool()
def get_job(job_id: str) -> dict:
    """Fetch job status and (if done) its findings."""
    cfg = _load_cfg()
    job = db.get_job(cfg["db_path"], job_id)
    if not job:
        return {"status": "not_found", "job_id": job_id}
    out = dict(job)
    if job["status"] == "done":
        out["accepted"] = db.get_findings(cfg["db_path"], job_id, section="ACCEPTED")
        out["retracted"] = db.get_findings(cfg["db_path"], job_id, section="RETRACTED")
    return out


@mcp.tool()
def list_jobs(limit: int = 20) -> dict:
    """List recent jobs."""
    cfg = _load_cfg()
    return {"jobs": db.list_jobs(cfg["db_path"], limit=limit)}


@mcp.tool()
def get_finding(job_id: str, finding_id: str) -> dict:
    """Fetch a single finding by id (accepted or retracted)."""
    cfg = _load_cfg()
    for f in db.get_findings(cfg["db_path"], job_id):
        if f["finding_id"] == finding_id:
            return {"status": "ok", "finding": f}
    return {"status": "not_found", "job_id": job_id, "finding_id": finding_id}


@mcp.tool()
def explain_finding(job_id: str, finding_id: str) -> dict:
    """Explain a finding in plain language, keeping the honesty contract.

    `caution` is ALWAYS populated and states exactly what was and was not
    verified.
    """
    cfg = _load_cfg()
    for f in db.get_findings(cfg["db_path"], job_id):
        if f["finding_id"] == finding_id:
            summary = (
                f"{f['secret_type']} detected on {f['evidence']['source_url']}. "
                f"Impact if valid: {f['impact']['level']}. "
                f"Confidence tier: {f['tier']}. "
                f"Validation status: {f['validation']['status']}. "
                f"Provenance: {f['evidence']['provenance']}."
            )
            caution = f"{f['impact']['caveat']} Remediation: {f['remediation']}"
            if f.get("retraction"):
                caution += f" Retracted by AI: {f['retraction']['reason']}"
            return {
                "status": "ok",
                "summary": summary,
                "caution": caution,
                "scoring": f.get("scoring"),
            }
    return {"status": "not_found"}


@mcp.tool()
def diff_jobs(job_id_a: str, job_id_b: str) -> dict:
    """Compare ACCEPTED findings between two jobs (new / fixed / persisting)."""
    cfg = _load_cfg()
    try:
        return db.diff_jobs(cfg["db_path"], job_id_a, job_id_b)
    except ValueError as e:
        return {"status": "error", "error": str(e)}


def main():
    mcp.run()


if __name__ == "__main__":
    main()
