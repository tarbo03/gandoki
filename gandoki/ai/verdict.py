"""Strict parser for adjudicator model output.

Anything that does not parse to exactly KEEP / RETRACT:<reason> / UNCERTAIN
becomes UNCERTAIN (fail-open). The parser NEVER returns a field that could
mutate a Finding.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class Verdict:
    kind: str                          # "KEEP" | "RETRACT" | "UNCERTAIN"
    reason: str | None
    model_id: str
    input_hash: str


def parse_verdict(text: str, *, model_id: str, input_hash: str) -> Verdict:
    """Parse a model response. Fail-open on anything unexpected."""
    if not text:
        return Verdict("UNCERTAIN", None, model_id, input_hash)
    line = text.strip().splitlines()[0].strip() if text.strip() else ""
    if line == "KEEP":
        return Verdict("KEEP", None, model_id, input_hash)
    if line == "UNCERTAIN":
        return Verdict("UNCERTAIN", None, model_id, input_hash)
    if line.startswith("RETRACT:"):
        reason = line[len("RETRACT:"):].strip()
        if not reason:
            return Verdict("UNCERTAIN", None, model_id, input_hash)
        return Verdict("RETRACT", reason[:300], model_id, input_hash)
    return Verdict("UNCERTAIN", None, model_id, input_hash)


def parse_recall_output(text: str) -> list[dict]:
    """Parse the recall model's JSON array response.

    Returns [] on any malformed response. The caller treats an empty list
    as "model produced nothing usable" and produces no candidates — the
    deterministic pipeline is never blocked by bad model output.
    """
    import json
    import re
    if not text:
        return []
    # Find the first [...] block, in case the model wraps it in prose anyway
    m = re.search(r"\[[\s\S]*\]", text)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    cleaned: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        if "start" not in item or "end" not in item:
            continue
        try:
            start = int(item["start"])
            end = int(item["end"])
        except (TypeError, ValueError):
            continue
        kind = str(item.get("kind", "not_a_secret")).lower()
        if kind not in ("known", "novel", "not_a_secret"):
            continue
        cleaned.append({
            "start": start,
            "end": end,
            "kind": kind,
            "claimed_type": str(item.get("claimed_type", "unknown"))[:64],
        })
    return cleaned
