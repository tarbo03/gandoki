# MCP Server

WARNING: Local-trust tool. Do not expose to a network. `scan_file` reads any
filesystem path. `scan_domains` makes outbound requests from the server.

## Install

    pip install -e .[mcp]

Pinned to `mcp<2` (v2 renamed FastMCP to MCPServer).

## Run

    gandoki-mcp
    # or: python -m gandoki.mcp.server

## Tools

- `scan_domains(domains, wait=True, timeout_s=300, include_suspected=False)`
- `scan_file(path, wait=True, timeout_s=300, include_suspected=False)`
- `get_job(job_id)`
- `list_jobs(limit=20)`
- `get_finding(job_id, finding_id)`
- `explain_finding(job_id, finding_id)`
- `diff_jobs(job_id_a, job_id_b)`

## Guardrails

- Raw secrets never returned
- Every finding has tier + validation.status + impact.caveat
- SUSPECTED suppressed by default
- Destructive validators never fire
- Retracted findings visible in `retracted[]`
