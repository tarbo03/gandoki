<div align="center">
  <img src="assets/logo.png" width="600" alt="Gandoki Logo" />
</div>

# Gandoki

**A secret scanner that can't lie to you.**

*By Godwin Tarbo — [github.com/tarbo03](https://github.com/tarbo03)*

Every finding states what the tool knows and what it doesn't. The AI layer
is architecturally forbidden from inflating a finding — proven by a test in CI.

## The problem

Security scanners have a false-positive problem nobody talks about. An
automated scan that reports 200 findings, of which 180 are noise, is worse
than no scan — a human has to re-verify every claim before trusting any.

LLM-powered security tools make this worse. A hallucinated finding reads
as confidently as a real one.

## What this tool does differently

Every finding carries a confidence tier and validation status:

- **VALIDATED_LIVE** — third-party API confirmed the credential works
- **CONFIRMED_PARTIAL** — file fetched and body-verified, not tested
- **FORMAT_MATCH** — credential format matched; never tested
- **SUSPECTED** — weak match, hidden by default

Nothing is reported as VALIDATED_LIVE unless a read-only call to the third
party actually confirmed it. No exceptions.

## The AI invariant

The LLM is used for one purpose: retracting false positives. It cannot
inflate. Its write surface is exactly one field — `Finding.section`.

Enforced at three layers:

1. The verdict parser returns only `(kind, reason)`
2. The orchestrator has exactly one mutation site
3. `test_ai_asymmetry.py` feeds a hostile model response and asserts that
   `tier`, `impact`, `validation`, and `caveat` are unchanged

If that test ever fails, the tool's honesty claim is a lie.

The model cannot upgrade a FORMAT_MATCH to VALIDATED_LIVE. It cannot raise
an impact level. It can only retract — and retracted findings appear in a
visible `retracted[]` array with reason, model ID, timestamp, and input hash.

## What it does

- **55 detectors** — 25 secret types (OpenAI, Stripe, AWS, GitHub, Supabase,
  MongoDB, private keys) + 30 debug-exposure detectors (Django DEBUG=True,
  Flask Werkzeug, .env, .git, Spring actuator, phpinfo, sourcemaps)
- **8 verification layers** — content-type, body-shape, SPA-fallback,
  `<pre>` context, guard detection, error-status, traceback structure,
  third-party sourcemap recognition
- **Live validation** — read-only against OpenAI, Stripe, AWS STS, GitHub
- **Reports** — JSON, HTML (XSS-safe), SARIF
- **Coverage manifest** — every report says what was scanned and what was
  skipped and why
- **MCP server** — 7 tools for Claude Desktop, Cursor, or any MCP client
- **Scan history** — SQLite with prefix-based diff


## 🔌 MCP Server (Remote & Local)

Gandoki is a fully functional **Model Context Protocol (MCP)** server. You can use it locally via `stdio`, or connect to the hosted Azure instance.


### Connect via MCP Marketplace
Gandoki is available as a fully managed, hosted server on leading MCP marketplaces. We are continuously adding new platforms to give you the best experience.

*   **Glama.ai:** Find **Gandoki** in the [Glama MCP Registry](https://glama.ai).
*   **MCP Marketplace:** Find **Gandoki** in the [MCP Marketplace](https://mcp-marketplace.io).

*(More platforms coming soon.)*

When you connect via these marketplaces, the platform handles the session management. You will be prompted to add your OpenRouter API key to the `X-OpenRouter-Key` header so the AI features can function securely using your own quota (BYOK).


### Bring Your Own Key (BYOK) Architecture
To protect your API quotas and ensure maximum privacy, the hosted server operates on a **BYOK** model. You simply pass your OpenRouter API key in the `X-OpenRouter-Key` HTTP header when connecting.
* The key is extracted via FastMCP v3's `get_http_headers()`.
* It is used **only** for your specific scan request.
* It is **never** logged, stored, or shared.

### Run the Docker Container Locally
If you prefer to host it yourself, Gandoki includes a production-ready `Dockerfile` configured for Azure Container Apps (or AWS ECS).

```bash
docker build -t gandoki-mcp .
docker run -p 8080:8080 gandoki-mcp
```
The server will start on `http://localhost:8080/mcp`.

## What it doesn't do

- No subdomain enumeration, port scanning, or network probing
- No exploitation of any kind
- L2/L3 context gates are heuristic, not formal parsers
- Discovery mode (certstream, Common Crawl) is off by default

## Use

    gandoki scan --domains-file targets.csv --out out.json --html out.html
    gandoki scan --url https://app.example.com/ --out out.json --ai-enabled
    gandoki scan --scope config/scope.yaml --out out.json --sarif out.sarif

Defender-first. Use only on assets you own or have written authorization
to test.

## Documentation

- [Architecture & honesty contract](docs/ARCHITECTURE.md)
- [Configuration](docs/CONFIGURATION.md)
- [CLI reference](docs/CLI_REFERENCE.md)
- [MCP server & trust boundary](docs/MCP_SERVER.md)
- [Scan history & diff](docs/SCAN_HISTORY.md)
- [AI pipeline](docs/AI_PIPELINE.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## Tests

    pytest -q

80 tests. The load-bearing ones are `test_ai_asymmetry.py` and
`test_ai_recall_cannot_bypass_extractor.py`. If either goes red, the tool
can no longer claim honesty.

## 📄 License

Gandoki is released under the **Business Source License 1.1 (BSL)**.
*   You are free to read, audit, modify, and use Gandoki for non-production and internal purposes.
*   You may not offer Gandoki as a competing commercial SaaS or MCP hosting service.
*   The license automatically converts to the **Apache License 2.0** on January 1, 2030.
