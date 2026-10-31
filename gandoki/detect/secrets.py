"""Secret detection engine — regex + entropy + context + known-public filter.

Emits only FORMAT_MATCH, SUSPECTED, or KNOWN_PUBLIC tiers. Live validation is
performed AFTER detection by the validator registry, which may upgrade tier.
AI write surface is exactly `Finding.section` — never touched here.
"""
from __future__ import annotations
import base64
import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any

from ..models import (
    ConfidenceTier, CoverageContext, Evidence, Finding, FindingCategory,
    Impact, ImpactLevel, Provenance,
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def context_has(text: str, words: list[str]) -> bool:
    t = text.lower()
    return any(w.lower() in t for w in words)


@dataclass
class Rule:
    id: str
    category: str
    pattern: str = ""
    entropy_min: float = 0.0
    context_positive: list[str] | None = None
    context_negative: list[str] | None = None
    known_public: bool = False
    filter_reason: str = ""
    impact: str = "MEDIUM"
    capability: str = ""
    validator: str | None = None
    destructive: bool = False
    type: str = "regex"
    jwt_role: str | None = None
    filter_if_role_in: list[str] | None = None
    probe_urls: list[str] | None = None
    validate: str | None = None
    expected_content_type: str | None = None
    require_error_status: bool = False
    header_name: str | None = None
    header_value_pattern: str | None = None


def rules_from_dicts(raw: list[dict]) -> list[Rule]:
    allowed = set(Rule.__annotations__.keys())
    return [Rule(**{k: v for k, v in r.items() if k in allowed}) for r in raw]


def jwt_role(tok: str) -> str | None:
    try:
        payload = tok.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("role")
    except Exception:
        return None


def jwt_exp(tok: str) -> int | None:
    try:
        payload = tok.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return int(json.loads(base64.urlsafe_b64decode(payload)).get("exp"))
    except Exception:
        return None


_REMEDIATION = {
    "openai_api_key": "Revoke at platform.openai.com; move to server-side env; rotate.",
    "stripe_secret_key": "Roll key in Stripe Dashboard → Developers → API keys; move server-side.",
    "supabase_service_role": "Rotate service-role key in Supabase; move to server-only env; verify RLS.",
    "slack_webhook": "Delete webhook in Slack app config; move server-side only.",
    "aws_access_key_id": "Deactivate & rotate in IAM; audit CloudTrail for prior use.",
    "github_pat": "Revoke at github.com/settings/tokens; rotate.",
}


def remediation_for(t: str) -> str:
    return _REMEDIATION.get(
        t,
        "Rotate the credential; move to server-side env; verify it was never "
        "shipped in build artifacts.",
    )


class SecretEngine:
    def __init__(self, rules: list[Rule]):
        # Empty pattern compiles to match-everything — skip it rather than
        # poison the scan with thousands of zero-length findings. Operators
        # can check `engine.skipped_empty_patterns` to detect bad config.
        all_secret = [r for r in rules if r.category == "secret"]
        self.rules = [r for r in all_secret if r.pattern]
        self.skipped_empty_patterns = [r.id for r in all_secret if not r.pattern]
        self._compiled = [(r, re.compile(r.pattern)) for r in self.rules]

    def scan(
        self,
        *,
        source_url: str,
        asset_url: str,
        body: bytes,
        discovery_method: str,
        coverage: CoverageContext,
        framework_hint: str | None = None,
        builder_hint: str | None = None,
    ) -> list[Finding]:
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return []
        digest = hashlib.sha256(body).hexdigest()
        findings: list[Finding] = []

        for rule, rgx in self._compiled:
            for m in rgx.finditer(text):
                snippet = m.group(0)
                if rule.entropy_min and shannon_entropy(snippet) < rule.entropy_min:
                    continue
                ctx = text[max(0, m.start() - 100): m.end() + 100]

                if rule.type == "jwt":
                    role = jwt_role(snippet)
                    if rule.jwt_role and role != rule.jwt_role:
                        continue
                    if rule.filter_if_role_in and role in rule.filter_if_role_in:
                        continue

                if rule.context_negative and context_has(ctx, rule.context_negative):
                    continue
                strong_ctx = bool(
                    rule.context_positive and context_has(ctx, rule.context_positive)
                )

                # Negative context was already filtered above.
                # Regex + entropy passed. Absence of positive context does
                # NOT downgrade to SUSPECTED — positive context is a boost,
                # not a prerequisite. SUSPECTED is reserved for cases where
                # a deterministic check actually fired against the finding.
                if rule.known_public:
                    tier = ConfidenceTier.KNOWN_PUBLIC
                else:
                    tier = ConfidenceTier.FORMAT_MATCH

                try:
                    _impact_level = ImpactLevel[rule.impact]
                except KeyError:
                    _impact_level = ImpactLevel.MEDIUM
                impact = Impact(
                    level=_impact_level,
                    basis=(
                        f"Detector '{rule.id}' matched with "
                        f"{'positive context' if strong_ctx else 'no supporting context'}"
                    ),
                    if_valid_capability=(
                        rule.capability
                        or "Unknown — detector lacks capability description"
                    ),
                    caveat=(
                        "UNVALIDATED — key not tested against third-party API. "
                        "Presence alone does not confirm validity."
                    ),
                )
                findings.append(Finding(
                    category=FindingCategory.SECRET,
                    secret_type=rule.id,
                    tier=tier,
                    evidence=Evidence(
                        source_url=source_url,
                        asset_url=asset_url,
                        asset_sha256=digest,
                        asset_size=len(body),
                        byte_offset=m.start(),
                        matched_pattern=rule.pattern,
                        matched_snippet=snippet,
                        context_snippet=ctx,
                        discovery_method=discovery_method,
                        entropy_score=shannon_entropy(snippet),
                        provenance=Provenance.REGEX,
                    ),
                    impact=impact,
                    coverage=coverage,
                    remediation=remediation_for(rule.id),
                    framework_hint=framework_hint,
                    builder_hint=builder_hint,
                ))
        return findings
