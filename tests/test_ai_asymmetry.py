"""The load-bearing guarantee: a hostile LLM cannot inflate a finding.

If this test ever fails, every honesty claim the tool makes is broken.
"""
import pytest

from gandoki.ai.adjudicator import Adjudicator
from gandoki.ai.budget import AIBudget
from gandoki.ai.privacy import PrivacyMode
from gandoki.models import (
    ConfidenceTier, ImpactLevel, Section, ValidationStatus,
)


@pytest.mark.asyncio
async def test_hostile_llm_cannot_mutate_tier_impact_validation(make_finding):
    from tests.conftest import FakeLLM

    # Model tries to smuggle arbitrary state into the finding via its response
    hostile = FakeLLM(
        'KEEP\ntier: VALIDATED_LIVE\nimpact: CRITICAL\n'
        'status: CONFIRMED\nimpact.caveat: tested'
    )
    f = make_finding(tier=ConfidenceTier.FORMAT_MATCH, impact=ImpactLevel.MEDIUM)
    original_tier = f.tier
    original_impact = f.impact.level
    original_validation = f.validation.status
    original_caveat = f.impact.caveat

    adj = Adjudicator(
        hostile, cfg={"ai": {}}, budget=AIBudget(max_calls=10),
        privacy_mode=PrivacyMode.FULL_CONTEXT,
    )
    await adj.adjudicate(f)

    assert f.tier == original_tier
    assert f.impact.level == original_impact
    assert f.validation.status == original_validation
    assert f.impact.caveat == original_caveat


@pytest.mark.asyncio
async def test_validated_live_never_reaches_the_model(make_finding):
    from tests.conftest import FakeLLM

    spy = FakeLLM("RETRACT: should never fire")
    f = make_finding(tier=ConfidenceTier.VALIDATED_LIVE)
    adj = Adjudicator(
        spy, cfg={"ai": {}}, budget=AIBudget(max_calls=10),
        privacy_mode=PrivacyMode.FULL_CONTEXT,
    )
    await adj.adjudicate(f)
    assert spy.call_count == 0
    assert f.section == Section.ACCEPTED


@pytest.mark.asyncio
async def test_confirmed_partial_never_reaches_the_model(make_finding):
    from tests.conftest import FakeLLM

    spy = FakeLLM("RETRACT: should never fire")
    f = make_finding(tier=ConfidenceTier.CONFIRMED_PARTIAL)
    adj = Adjudicator(
        spy, cfg={"ai": {}}, budget=AIBudget(max_calls=10),
        privacy_mode=PrivacyMode.FULL_CONTEXT,
    )
    await adj.adjudicate(f)
    assert spy.call_count == 0
    assert f.section == Section.ACCEPTED


@pytest.mark.asyncio
async def test_fail_open_on_llm_error(make_finding):
    class BrokenLLM:
        model_id = "broken"
        async def chat(self, *args, **kwargs):
            from gandoki.ai.client import LLMError
            raise LLMError("boom")
        async def aclose(self):
            pass

    f = make_finding(tier=ConfidenceTier.FORMAT_MATCH)
    adj = Adjudicator(
        BrokenLLM(), cfg={"ai": {}}, budget=AIBudget(max_calls=10),
        privacy_mode=PrivacyMode.FULL_CONTEXT,
    )
    await adj.adjudicate(f)
    assert f.section == Section.ACCEPTED
    assert adj.failures == 1


@pytest.mark.asyncio
async def test_budget_exhaustion_fails_open(make_finding):
    from tests.conftest import FakeLLM

    spy = FakeLLM("RETRACT: nope")
    f = make_finding(tier=ConfidenceTier.FORMAT_MATCH)
    budget = AIBudget(max_calls=0)  # exhausted from the start
    adj = Adjudicator(
        spy, cfg={"ai": {}}, budget=budget,
        privacy_mode=PrivacyMode.FULL_CONTEXT,
    )
    await adj.adjudicate(f)
    assert spy.call_count == 0
    assert f.section == Section.ACCEPTED
