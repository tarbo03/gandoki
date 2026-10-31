# AI Pipeline

Three uses of AI, none can inflate tier, impact, or validation.

## L4 — Adjudication (retraction)

Runs after live validation. Sees only FORMAT_MATCH findings.
VALIDATED_LIVE and CONFIRMED_PARTIAL are refused at code level.
Verdict: KEEP, RETRACT: <reason>, or UNCERTAIN. Fail-open on parse failure.

## Stage 0 — Recall (B-hybrid)

Model proposes byte range + claimed type. Deterministic extractor makes the
claim. `provenance` records which path was taken.

## Privacy modes

- Ollama: full context (local)
- OpenRouter: double-redacted by default. Override via
  `ai.send_raw_secrets_to_remote: true` (warns + records in manifest).

## Prompt-injection defense

- JSON-encoded context, never natural language
- Known patterns stripped + flagged
- Unparseable output -> UNCERTAIN

## Backends

- **OpenRouter** (default) — `OPENROUTER_API_KEY` env var
- **Ollama** (recommended for production) — local, no rate limits

## Non-determinism with `openrouter/free`

The default `model: "openrouter/free"` routes each call to a random available
free model. Different models retract different findings. As a result, running
the same scan twice may produce different retraction counts.

This is intentional — the router keeps the tool working when any single free
model gets retired (as happened to `llama-3.3-70b-instruct:free`). But it means
**reports are not byte-for-byte reproducible across runs**.

For reproducibility, pin a specific model:

    ai:
      openrouter:
        model: "meta-llama/llama-3.1-8b-instruct:free"

Every retraction carries `retraction.decided_by` — the exact model ID that
decided it. So even with the router, every retraction is auditable after the
fact. The non-determinism is in *which* model gets picked, not in *whether*
the audit trail exists.
