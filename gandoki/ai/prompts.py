"""Locked prompt templates + injection sanitization.

The adjudicator and recall templates are hashed; the client refuses to
run if the on-disk template sha256 doesn't match the constant. This
prevents an accidental edit from silently changing the classifier's
behavior in a production deployment.
"""
from __future__ import annotations
import hashlib
import json
import re


# ---- Adjudicator (L4) ----

ADJUDICATOR_TEMPLATE = """\
You are a false-positive filter for a secret scanner.
You will receive a JSON object with these keys:
  secret_type, snippet_redacted, context, asset_url, discovery_method, tier.

Decide whether this finding is:
  KEEP       — looks like a real credential in code, worth reporting.
  RETRACT    — looks like a false positive (documentation, example, test data, comment).
  UNCERTAIN  — you cannot tell.

Respond with exactly one line:
  KEEP
  RETRACT: <one-sentence reason>
  UNCERTAIN
"""

ADJUDICATOR_TEMPLATE_SHA256 = hashlib.sha256(
    ADJUDICATOR_TEMPLATE.encode()
).hexdigest()


# ---- Stage 0 recall ----

RECALL_TEMPLATE = """\
You are a secret-candidate locator. You will receive a JSON object with:
  asset_url, asset_snippet, candidate_ranges (list of {start, end, value}).

For EACH range, decide whether it looks like a credential:
  - "known"   : matches a well-known format (set claimed_type)
  - "novel"   : looks like a custom token (set claimed_type to "unknown")
  - "not_a_secret" : not a credential

Respond with exactly one JSON array. Example:
[{"start": 10240, "end": 10280, "kind": "known", "claimed_type": "openai_api_key"},
 {"start": 10400, "end": 10430, "kind": "novel", "claimed_type": "unknown"},
 {"start": 10500, "end": 10520, "kind": "not_a_secret"}]

Do NOT include any prose before or after the JSON array.
"""

RECALL_TEMPLATE_SHA256 = hashlib.sha256(RECALL_TEMPLATE.encode()).hexdigest()


# ---- Enrichment: sourcemap context recovery ----

SOURCEMAP_RECOVERY_TEMPLATE = """\
You will receive a minified JavaScript snippet and an offset.
Respond with one line describing the apparent variable name and purpose
of the value at that offset, or "unknown" if you cannot tell.
Do not speculate beyond the visible bytes.
"""


# ---- Injection sanitization ----

_INJECTION_PATTERNS = [
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:prior|previous)\s+instructions?\b"),
    re.compile(r"(?i)\bdisregard\s+(?:all\s+)?(?:prior|previous)\s+"),
    re.compile(r"(?i)\bsystem\s*:\s*"),
    re.compile(r"(?i)^\s*###\s*$", re.M),
    re.compile(r"(?i)\breturn\s+keep\b"),
    re.compile(r"(?i)\breturn\s+retract\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+"),
    re.compile(r"(?i)<\s*\|\s*im_start\s*\|>"),
]


def sanitize_context(text: str) -> tuple[str, bool]:
    """Strip common prompt-injection markers. Return (clean_text, was_flagged)."""
    flagged = False
    for pat in _INJECTION_PATTERNS:
        if pat.search(text):
            flagged = True
            text = pat.sub("[STRIPPED]", text)
    return text, flagged


def adjudicator_payload(
    *,
    secret_type: str,
    snippet_redacted: str,
    context: str,
    asset_url: str,
    discovery_method: str,
    tier: str,
) -> dict:
    return {
        "secret_type": secret_type,
        "snippet_redacted": snippet_redacted,
        "context": context,
        "asset_url": asset_url,
        "discovery_method": discovery_method,
        "tier": tier,
    }


def recall_payload(
    *,
    asset_url: str,
    asset_snippet: str,
    candidate_ranges: list[dict],
) -> dict:
    return {
        "asset_url": asset_url,
        "asset_snippet": asset_snippet,
        "candidate_ranges": candidate_ranges,
    }


def payload_hash(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode()
    ).hexdigest()
