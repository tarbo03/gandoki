"""Robust CSV/TXT domain-list loader.

.txt : one entry per line; '#' comments; blank lines ignored.
.csv : auto-detects a domain/url/host column (falls back to first column);
       supports BOM, quoted fields, comma/semicolon/tab delimiters.

Normalization: strips scheme, path, query, port, trailing dot; lowercases;
dedupes (preserving first-seen order); rejects obvious garbage.
Every skipped entry is reported — nothing is silently dropped.
"""
from __future__ import annotations
import csv
import io
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


_DOMAIN_COLUMN_ALIASES = {
    "domain", "domains", "host", "hostname", "host_name",
    "url", "urls", "website", "websites", "target", "targets",
    "site", "sites", "endpoint", "address",
}

_VALID_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


@dataclass
class LoadResult:
    domains: list[str]
    skipped_invalid: list[str]
    skipped_duplicates: int
    total_lines: int
    source_file: str


def _normalize(entry: str) -> str | None:
    entry = entry.strip().strip("\ufeff").strip('"').strip("'")
    if not entry or entry.startswith("#"):
        return None
    if "://" in entry or entry.startswith("//"):
        parsed = urlparse(entry if "://" in entry else "http:" + entry)
        host = (parsed.hostname or "").lower().rstrip(".")
    else:
        host = entry.split("/", 1)[0].split(":", 1)[0].lower().rstrip(".")
    if not host:
        return None
    candidate = host[4:] if host.startswith("www.") and "." in host[4:] else host
    if not _VALID_HOST_RE.match(candidate):
        return None
    return candidate


def load_txt(path: Path) -> LoadResult:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    seen: set[str] = set()
    domains: list[str] = []
    invalid: list[str] = []
    dups = 0
    for raw in lines:
        norm = _normalize(raw)
        if norm is None:
            if raw.strip() and not raw.strip().startswith("#"):
                invalid.append(raw.strip())
            continue
        if norm in seen:
            dups += 1
            continue
        seen.add(norm)
        domains.append(norm)
    return LoadResult(domains, invalid, dups, len(lines), str(path))


def load_csv(path: Path) -> LoadResult:
    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        dialect = csv.Sniffer().sniff(raw[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(raw), dialect)
    rows = list(reader)
    if not rows:
        return LoadResult([], [], 0, 0, str(path))

    header = [c.strip().lower() for c in rows[0]]
    col_idx = 0
    data_rows = rows
    if any(h in _DOMAIN_COLUMN_ALIASES for h in header):
        for i, h in enumerate(header):
            if h in _DOMAIN_COLUMN_ALIASES:
                col_idx = i
                break
        data_rows = rows[1:]

    seen: set[str] = set()
    domains: list[str] = []
    invalid: list[str] = []
    dups = 0
    for row in data_rows:
        if not row:
            continue
        cell = row[col_idx] if col_idx < len(row) else (row[0] if row else "")
        norm = _normalize(cell)
        if norm is None:
            if cell.strip():
                invalid.append(cell.strip())
            continue
        if norm in seen:
            dups += 1
            continue
        seen.add(norm)
        domains.append(norm)
    return LoadResult(domains, invalid, dups, len(data_rows), str(path))


def load_domains_file(path: str | Path) -> LoadResult:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"domain file not found: {p}")
    suffix = p.suffix.lower()
    if suffix == ".csv":
        return load_csv(p)
    return load_txt(p)


def parse_single_url(entry: str) -> tuple[str | None, str | None]:
    """Parse a single --url entry. Returns (host, seed_url) or (None, None).

    seed_url preserves scheme + path so the crawler can start from the exact
    URL rather than always /.

    If the user provided an explicit scheme (http://, https://), trust the
    hostname — it may be localhost, an internal hostname, or an IP. The
    explicit scheme signals deliberate intent.
    If the entry is bare (no scheme), apply the strict domain regex to
    catch typos.
    """
    entry = entry.strip()
    if not entry:
        return None, None
    had_scheme = "://" in entry
    if not had_scheme:
        entry = "https://" + entry
    parsed = urlparse(entry)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or " " in host:
        return None, None
    if had_scheme:
        return host, entry
    candidate = host[4:] if host.startswith("www.") and "." in host[4:] else host
    if not _VALID_HOST_RE.match(candidate):
        return None, None
    return candidate, entry


def merge_load_results(results: list[LoadResult]) -> LoadResult:
    """Merge multiple LoadResults, deduping across files."""
    seen: set[str] = set()
    domains: list[str] = []
    invalid: list[str] = []
    dups = 0
    total = 0
    sources = []
    for r in results:
        total += r.total_lines
        invalid.extend(r.skipped_invalid)
        sources.append(r.source_file)
        for d in r.domains:
            if d in seen:
                dups += 1
                continue
            seen.add(d)
            domains.append(d)
    return LoadResult(
        domains=domains,
        skipped_invalid=invalid,
        skipped_duplicates=dups,
        total_lines=total,
        source_file="; ".join(sources),
    )
