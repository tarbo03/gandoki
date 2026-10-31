# Configuration

Three files:

- `config/config.yaml` — scan + AI + validation toggles
- `config/rules.yaml` — detectors
- `config/severity_caps.yaml` — L5 caps

## Top-level (`config.yaml`)

| Key | Default | Meaning |
|---|---|---|
| `scope_mode` | `authorized` | `authorized` or `discovery` |
| `max_domains_per_run` | `200` | Hard cap |
| `concurrency` | `20` | Global concurrent fetches |
| `per_domain_timeout_s` | `45` | Per-fetch timeout |
| `crawl_budget_s` | `60` | Per-domain budget |
| `max_pages_per_domain` | `15` | Page cap |
| `max_assets_per_page` | `40` | JS bundle cap |
| `max_response_bytes` | `10000000` | Size cap per fetch |
| `respect_robots` | `true` | RFC robots |
| `db_path` | `gandoki.db` | SQLite history |

## `validation`

Per-validator opt-in. Destructive validators (Slack, Discord) are hard-refused.
Shipped: `openai`, `stripe`, `aws_sts`, `github_whoami`.

## `ai`

Master `ai.enabled` (default false). Backends: `openrouter` or `ollama`.
