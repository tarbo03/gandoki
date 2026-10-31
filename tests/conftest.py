"""Shared fixtures for the test suite."""
from __future__ import annotations
from datetime import datetime, timezone

import pytest

from gandoki.models import (
    ConfidenceTier, CoverageContext, Evidence, Finding, FindingCategory,
    Impact, ImpactLevel, Provenance,
)


@pytest.fixture
def sample_coverage() -> CoverageContext:
    return CoverageContext(
        pages_fetched=1, assets_scanned=1, assets_failed=0,
        sources_queried=["live"], skipped=[], crawl_budget_seconds=60,
        crawl_started=datetime.now(timezone.utc),
        crawl_ended=datetime.now(timezone.utc),
    )


@pytest.fixture
def make_finding(sample_coverage):
    """Factory that builds a well-formed Finding with sane defaults."""
    def _make(
        *,
        tier: ConfidenceTier = ConfidenceTier.FORMAT_MATCH,
        impact: ImpactLevel = ImpactLevel.HIGH,
        secret_type: str = "openai_api_key",
        snippet: str = "sk-abcdefgh12345678",
        context: str = "ctx around the key",
        caveat: str = "UNVALIDATED — not tested",
        if_valid_capability: str = "attacker could use this key",
        asset_url: str = "https://x/a.js",
        source_url: str = "https://x",
        byte_offset: int = 0,
        discovery_method: str = "js_bundle",
        provenance: Provenance = Provenance.REGEX,
        category: FindingCategory = FindingCategory.SECRET,
    ) -> Finding:
        return Finding(
            category=category,
            secret_type=secret_type,
            tier=tier,
            evidence=Evidence(
                source_url=source_url, asset_url=asset_url,
                asset_sha256="a" * 64, asset_size=100, byte_offset=byte_offset,
                matched_pattern="sk-", matched_snippet=snippet,
                context_snippet=context,
                discovery_method=discovery_method,
                provenance=provenance,
            ),
            impact=Impact(
                level=impact, basis="b",
                if_valid_capability=if_valid_capability, caveat=caveat,
            ),
            coverage=sample_coverage,
            remediation="rotate",
        )
    return _make


class FakeLLM:
    """Deterministic fake LLM. Returns whatever `response` is set to."""

    def __init__(self, response: str, model_id: str = "fake:test"):
        self.response = response
        self.model_id = model_id
        self.call_count = 0

    async def chat(self, system: str, user: str, *, timeout_s: int = 30) -> str:
        self.call_count += 1
        return self.response

    async def aclose(self) -> None:
        pass
