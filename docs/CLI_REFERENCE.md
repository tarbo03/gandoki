# CLI Reference

## `gandoki scan`

Inputs (at least one): `--domains`, `--domains-file`, `--url`, `--scope`
Limits: `--max-domains N`, `--unlimited-domains`
Behavior: `--ignore-robots`, `--include-suspected`
AI: `--ai-enabled` / `--no-ai`, `--ai-backend openrouter|ollama`
Output: `--out`, `--html`, `--sarif`
Config: `--config`, `--rules`, `--severity-caps`

## `gandoki history [--limit N]`

List recent jobs. 12-char prefix shown; all commands accept full ID or prefix.

## `gandoki show <id_or_prefix>`

Human-readable summary. `--raw` for JSON.

## `gandoki diff <a> <b>`

Compares ACCEPTED findings. Identity: `(secret_type, asset_url, byte_offset)`.
Retracted findings are not diffed — use `show`.

## Examples

    gandoki scan --domains-file targets.csv --out out.json --html out.html
    gandoki scan --url https://app.example.com/ --out out.json --ai-enabled
    gandoki scan --scope config/scope.yaml --out out.json --sarif out.sarif
