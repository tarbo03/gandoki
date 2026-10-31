"""Stage 0 recall: the extractor gate, not the model, makes the claim."""
import pytest

from gandoki.ai.budget import AIBudget
from gandoki.ai.privacy import PrivacyMode
from gandoki.ai.recall import (
    Recall, deterministic_score, find_candidate_regions, generic_extractor,
)
from gandoki.detect.secrets import Rule
from gandoki.models import ConfidenceTier, Provenance


_RULES = [Rule(
    id="openai_api_key", category="secret",
    pattern=r"sk-[A-Za-z0-9]{20,}", impact="HIGH",
    capability="OpenAI API usage",
)]

_BODY = b'apiKey = "Xk9mQ2pL7vR4nB8wJ3cF6yH1tD5sG0aZ"'


@pytest.mark.asyncio
async def test_known_claim_rejected_when_regex_does_not_match(sample_coverage):
    """Model claims openai_api_key at a range that doesn't start with sk-."""

    class WrongClaimLLM:
        model_id = "wrong"
        async def chat(self, system, user, *, timeout_s=30):
            return '[{"start": 0, "end": 20, "kind": "known", "claimed_type": "openai_api_key"}]'
        async def aclose(self): pass

    rec = Recall(
        WrongClaimLLM(), cfg={"ai": {"recall": {}}},
        budget=AIBudget(max_calls=10),
        privacy_mode=PrivacyMode.FULL_CONTEXT,
        known_rules=_RULES,
    )
    findings = await rec.scan(
        source_url="https://x", asset_url="https://x/a.js",
        body=_BODY, discovery_method="js_bundle", coverage=sample_coverage,
    )
    assert len(findings) >= 1, "expected at least one materialized finding"
    for f in findings:
        assert f.tier == ConfidenceTier.SUSPECTED, (
            f"model claim elevated to {f.tier.value} without regex match"
        )
        assert f.evidence.provenance == Provenance.AI_RECALL_REGEX_CONFIRMED


@pytest.mark.asyncio
async def test_novel_claim_rejected_when_generic_extractor_fails(sample_coverage):
    """Model claims novel at a low-entropy region. Extractor rejects → SUSPECTED."""

    class BadClaimLLM:
        model_id = "bad"
        async def chat(self, system, user, *, timeout_s=30):
            return '[{"start": 0, "end": 10, "kind": "novel", "claimed_type": "unknown"}]'
        async def aclose(self): pass

    rec = Recall(
        BadClaimLLM(), cfg={"ai": {"recall": {}}},
        budget=AIBudget(max_calls=10),
        privacy_mode=PrivacyMode.FULL_CONTEXT,
        known_rules=_RULES,
    )
    findings = await rec.scan(
        source_url="https://x", asset_url="https://x/a.js",
        body=_BODY, discovery_method="js_bundle", coverage=sample_coverage,
    )
    for f in findings:
        assert f.tier == ConfidenceTier.SUSPECTED


@pytest.mark.asyncio
async def test_novel_claim_passes_extractor_yields_format_match(sample_coverage):
    """Model claims novel at the actual high-entropy range. Extractor passes → FORMAT_MATCH."""

    class GoodLLM:
        model_id = "good"
        async def chat(self, system, user, *, timeout_s=30):
            return '[{"start": 10, "end": 42, "kind": "novel", "claimed_type": "unknown"}]'
        async def aclose(self): pass

    rec = Recall(
        GoodLLM(), cfg={"ai": {"recall": {}}},
        budget=AIBudget(max_calls=10),
        privacy_mode=PrivacyMode.FULL_CONTEXT,
        known_rules=_RULES,
    )
    findings = await rec.scan(
        source_url="https://x", asset_url="https://x/a.js",
        body=_BODY, discovery_method="js_bundle", coverage=sample_coverage,
    )
    format_matches = [f for f in findings if f.tier == ConfidenceTier.FORMAT_MATCH]
    assert len(format_matches) == 1
    assert format_matches[0].evidence.provenance == Provenance.AI_RECALL_GENERIC_EXTRACTOR


def test_generic_extractor_rejects_low_entropy():
    ok, _ = generic_extractor("aaaaaaaaaaaaaaaaaaaaaaaa", 0, 24)
    assert ok is False


def test_generic_extractor_rejects_negative_context():
    text = "example = abcdefghijklmnopqrstuvwx"
    ok, _ = generic_extractor(text, 10, 34)
    assert ok is False


def test_deterministic_score_rejects_negative_ctx():
    text = 'example = "Xk9mQ2pL7vR4nB8wJ3cF6yH1tD5sG0aZ"'
    val = "Xk9mQ2pL7vR4nB8wJ3cF6yH1tD5sG0aZ"
    assert deterministic_score(text, 10, 42, val) == 0.0
