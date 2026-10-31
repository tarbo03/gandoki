# Architecture

## The principle

**If we can't prove a finding is real, we say so — we don't inflate it.**

## Pipeline

    L1 detect -> L2 context -> L3 provenance -> [live validation]
              -> L4 AI adjudication -> L5 severity cap -> report

- **L1** regex + entropy + JWT-role filter.
- **L2** context words + `<pre>`/`<code>` region check. Heuristic.
- **L3** fetch hygiene (2xx, in-body, not robots-blocked). Heuristic.
- **Live validation** (opt-in) calls the third party read-only.
- **L4** AI retraction — runs only on FORMAT_MATCH findings.
- **L5** severity caps — impact moves DOWN only.

## The AI invariant

The LLM's write surface is **one field**: `Finding.section`.
Enforced at three layers: parser returns only `(kind, reason)`; orchestrator
has one mutation site; `test_ai_asymmetry.py` asserts it in CI.

## Known limits

- L2/L3 are heuristics, not formal parsers.
- Discovery mode is off by default.
- Validators shipped: OpenAI, Stripe, AWS STS (key ID only), GitHub PAT.
