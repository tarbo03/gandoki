# Scan History

Every scan writes to `gandoki.db` (SQLite, WAL mode). Findings stored
**redacted** — same trust boundary as the JSON report.

## Commands

    gandoki history
    gandoki show <prefix>
    gandoki diff <a> <b>

All accept full ID or unique prefix (12+ chars).

## Diff identity

`(secret_type, asset_url, byte_offset)`. Retracted findings NOT diffed.
Use `gandoki show <job>` to inspect retractions.

## Retention

    python -c "from gandoki.storage.db import cleanup_old_jobs; cleanup_old_jobs('gandoki.db', keep_days=30)"
