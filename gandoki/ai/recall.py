"""Stage 0 AI recall (B-hybrid).

The model proposes byte ranges and claimed types. The extractor makes the
final claim:

  - claimed_type is a KNOWN regex type  → run that regex on the proposed range
                                          → match → FORMAT_MATCH
                                          → no match → SUSPECTED
  - claimed_type is NOVEL/unknown       → run generic deterministic extractor
                                          (entropy + adjacency + length + no negative ctx)
                                          → pass → FORMAT_MATCH (secret_type=ai_recall_unknown)
                                          → fail → SUSPECTED

`provenance` records which path was taken. The model NEVER writes
tier=FORMAT_MATCH directly. Ever.
"""
from __future__ import annotations
import hashlib
import json
import re
from dataclasses import dataclass

from ..detect.secrets import (
    Rule, remediation_for, shannon_entropy,
)
from ..models import (
    ConfidenceTier, CoverageContext, Evidence, Finding, FindingCategory,
    Impact, ImpactLevel, Provenance,
)
from .budget import AIBudget
from .client import LLMClient, LLMError
from .privacy import PrivacyMode, prepare_context
from .prompts import RECALL_TEMPLATE, recall_payload, payload_hash
from .verdict import parse_recall_output


# ---- deterministic pre-filter ----

_ASSIGNMENT_HINTS = re.compile(
    r"(?:key|token|secret|api[_-]?key|auth|password|bearer)\s*[:=]\s*[\"']",
    re.I,
)
_HIGH_ENTROPY_CANDIDATE_RE = re.compile(r"[\"']([A-Za-z0-9_\-+/=]{20,})[\"']")
_NEGATIVE_CTX_RE = re.compile(
    r"\b(example|placeholder|dummy|test[-_]?data|your[-_]key|<your|<insert)\b",
    re.I,
)


@dataclass
class Region:
    start: int
    end: int
    value: str
    score: float


def deterministic_score(text: str, start: int, end: int, value: str) -> float:
    """0..1 score used to prune which regions get sent to the model."""
    if not value or end - start < 12:
        return 0.0
    ctx = text[max(0, start - 200): end + 200]
    if _NEGATIVE_CTX_RE.search(ctx):
        return 0.0
    s = 0.0
    if _ASSIGNMENT_HINTS.search(ctx):
        s += 0.4
    ent = shannon_entropy(value)
    if ent >= 3.0:
        s += min(0.4, (ent - 2.0) / 2.5)
    if len(value) >= 24:
        s += 0.1
    if len(value) >= 40:
        s += 0.1
    return min(1.0, s)


def find_candidate_regions(text: str, *, max_regions: int) -> list[Region]:
    """Deterministic pre-filter that ranks byte regions by suspicion."""
    out: list[Region] = []
    for m in _HIGH_ENTROPY_CANDIDATE_RE.finditer(text):
        value = m.group(1)
        start, end = m.start(1), m.end(1)
        score = deterministic_score(text, start, end, value)
        if score <= 0:
            continue
        out.append(Region(start=start, end=end, value=value, score=score))
    out.sort(key=lambda r: r.score, reverse=True)
    return out[:max_regions]


# ---- generic extractor for novel claims ----

def generic_extractor(text: str, start: int, end: int) -> tuple[bool, str]:
    """Deterministic gate applied to a model-proposed novel region."""
    if start < 0 or end > len(text) or end - start < 12:
        return False, ""
    value = text[start:end]
    if not re.fullmatch(r"[A-Za-z0-9_\-+/=]{12,}", value):
        return False, ""
    if _NEGATIVE_CTX_RE.search(text[max(0, start - 100): end + 100]):
        return False, ""
    if shannon_entropy(value) < 3.5:
        return False, ""
    return True, value


class Recall:
    def __init__(
        self,
        client: LLMClient | None,
        *,
        cfg: dict,
        budget: AIBudget,
        privacy_mode: PrivacyMode,
        known_rules: list[Rule],
    ):
        self.client = client
        self.cfg = cfg
        self.budget = budget
        self.privacy_mode = privacy_mode
        self.known_rules_by_id = {r.id: r for r in known_rules if r.category == "secret"}
        ai_cfg = cfg.get("ai", {}).get("recall", {})
        self.max_regions_per_asset = int(ai_cfg.get("max_regions_per_asset", 5))
        self.max_assets_per_domain = int(
            ai_cfg.get("max_assets_per_domain_scanned_by_ai", 5)
        )
        self.min_score = float(ai_cfg.get("min_deterministic_score", 0.4))
        self.max_context_chars = int(ai_cfg.get("max_context_chars", 2000))
        self._assets_seen: dict[str, int] = {}

    async def scan(
        self,
        *,
        source_url: str,
        asset_url: str,
        body: bytes,
        discovery_method: str,
        coverage: CoverageContext,
    ) -> list[Finding]:
        """Return any Stage 0 findings from this asset. Never raises."""
        if self.client is None:
            return []
        if self._assets_seen.get(source_url, 0) >= self.max_assets_per_domain:
            return []

        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return []

        regions = find_candidate_regions(text, max_regions=self.max_regions_per_asset)
        regions = [r for r in regions if r.score >= self.min_score]
        if not regions:
            return []
        self._assets_seen[source_url] = self._assets_seen.get(source_url, 0) + 1

        if not await self.budget.acquire():
            return []

        # Prepare the snippet we send. We sample a bounded window around the
        # first region so the model has surrounding context; the model
        # proposes offsets relative to the *snippet*.
        win_start = max(0, min(r.start for r in regions) - 200)
        win_end = min(len(text), max(r.end for r in regions) + 200)
        snippet = text[win_start:win_end]
        prepared = prepare_context(snippet, self.privacy_mode, self.max_context_chars)

        candidate_ranges = [
            {"start": r.start - win_start, "end": r.end - win_start, "value": r.value}
            for r in regions
        ]
        payload = recall_payload(
            asset_url=asset_url,
            asset_snippet=prepared.text,
            candidate_ranges=candidate_ranges,
        )
        input_hash = payload_hash(payload)

        try:
            raw = await self.client.chat(
                RECALL_TEMPLATE,
                json.dumps(payload, ensure_ascii=False),
                timeout_s=30,
            )
        except LLMError:
            return []

        proposals = parse_recall_output(raw)
        findings: list[Finding] = []
        for p in proposals:
            if p["kind"] == "not_a_secret":
                continue
            abs_start = win_start + p["start"]
            abs_end = win_start + p["end"]
            if abs_start < 0 or abs_end > len(text) or abs_end <= abs_start:
                continue
            finding = self._materialize(
                text=text, start=abs_start, end=abs_end,
                claimed_type=p["claimed_type"], kind=p["kind"],
                source_url=source_url, asset_url=asset_url,
                discovery_method=discovery_method,
                coverage=coverage, digest=hashlib.sha256(body).hexdigest(),
                asset_size=len(body), input_hash=input_hash,
            )
            if finding is not None:
                findings.append(finding)
        return findings

    def _materialize(
        self, *, text: str, start: int, end: int, claimed_type: str, kind: str,
        source_url: str, asset_url: str, discovery_method: str,
        coverage: CoverageContext, digest: str, asset_size: int,
        input_hash: str,
    ) -> Finding | None:
        # Known-rule branch: run the extractor's regex on the proposed range
        if kind == "known" and claimed_type in self.known_rules_by_id:
            rule = self.known_rules_by_id[claimed_type]
            segment = text[start:end]
            m = re.search(rule.pattern, segment)
            if m:
                tier = ConfidenceTier.FORMAT_MATCH
                provenance = Provenance.AI_RECALL_REGEX_CONFIRMED
                matched = m.group(0)
                actual_offset = start + m.start()
            else:
                tier = ConfidenceTier.SUSPECTED
                provenance = Provenance.AI_RECALL_REGEX_CONFIRMED
                matched = text[start:end]
                actual_offset = start
            return self._build_finding(
                rule=rule, text=text, matched=matched, offset=actual_offset,
                source_url=source_url, asset_url=asset_url,
                discovery_method=discovery_method, coverage=coverage,
                digest=digest, asset_size=asset_size, tier=tier,
                provenance=provenance,
            )

        # Novel branch: generic deterministic extractor
        ok, value = generic_extractor(text, start, end)
        tier = ConfidenceTier.FORMAT_MATCH if ok else ConfidenceTier.SUSPECTED
        synthetic = Rule(
            id="ai_recall_unknown",
            category="secret",
            pattern=re.escape(value or text[start:end]),
            impact="MEDIUM",
            capability="Unknown credential shape — manual review required",
        )
        return self._build_finding(
            rule=synthetic, text=text,
            matched=value or text[start:end],
            offset=start, source_url=source_url, asset_url=asset_url,
            discovery_method=discovery_method, coverage=coverage,
            digest=digest, asset_size=asset_size, tier=tier,
            provenance=Provenance.AI_RECALL_GENERIC_EXTRACTOR,
        )

    def _build_finding(
        self, *, rule: Rule, text: str, matched: str, offset: int,
        source_url: str, asset_url: str, discovery_method: str,
        coverage: CoverageContext, digest: str, asset_size: int,
        tier: ConfidenceTier, provenance: Provenance,
    ) -> Finding:
        ctx = text[max(0, offset - 100): offset + len(matched) + 100]
        return Finding(
            category=FindingCategory.SECRET,
            secret_type=rule.id,
            tier=tier,
            evidence=Evidence(
                source_url=source_url, asset_url=asset_url,
                asset_sha256=digest, asset_size=asset_size,
                byte_offset=offset, matched_pattern=rule.pattern,
                matched_snippet=matched, context_snippet=ctx,
                discovery_method=discovery_method,
                entropy_score=shannon_entropy(matched),
                provenance=provenance,
            ),
            impact=Impact(
                level=ImpactLevel[rule.impact],
                basis=f"Stage 0 recall via {provenance.value}",
                if_valid_capability=(
                    rule.capability or "Unknown credential — manual review required"
                ),
                caveat=(
                    "AI-recall candidate. Extractor gate applied deterministically. "
                    "Still UNVALIDATED against third-party API."
                ),
            ),
            coverage=coverage,
            remediation=remediation_for(rule.id),
        )
