# Troubleshooting

## ModuleNotFoundError: No module named 'gandoki'

Venv not active:

    cd ~/gandoki && source venv/bin/activate
    which gandoki   # must be ~/gandoki/venv/bin/gandoki

`python -m pytest` will also fail under pyenv Python.

## No module named 'mcp'

Optional: `pip install -e .[mcp]`. CLI works without it.

## ModuleNotFoundError: No module named 'mcp.server.fastmcp'

You have `mcp>=2`. Pin: `pip install 'mcp<2'`.

## Scan finds nothing on JS-heavy site

Check manifest:

    python -m json.tool out.json | python -c "import sys,json; d=json.load(sys.stdin); print(d['coverage'])"

Look for `assets_scanned` (should be > 0), `assets_skipped_reason`,
`assets_truncated_by_limit`.

## AI not running

Check `coverage.ai_enabled`. If false:
- `ai.enabled` in config is false (default)
- OPENROUTER_API_KEY missing
- `--no-ai` was passed

## Findings missing when AI enabled

Retracted findings are in `retracted[]`, not `findings[]`.
