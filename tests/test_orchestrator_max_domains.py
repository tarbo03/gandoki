"""max_domains cap and override."""
import pytest

from gandoki.pipeline import orchestrator


def _cfg(**over):
    base = {
        "max_domains_per_run": 2,
        "concurrency": 5,
        "user_agent": "test",
        "per_domain_timeout_s": 5,
        "crawl_budget_s": 5,
        "max_pages_per_domain": 1,
        "max_assets_per_page": 1,
        "max_response_bytes": 1_000_000,
        "per_host": {},
        "ai": {"enabled": False},
    }
    base.update(over)
    return base


@pytest.mark.asyncio
async def test_default_cap_applied(monkeypatch):
    calls: list[str] = []

    async def fake_crawl(host, cfg, **kwargs):
        calls.append(host)
        return {"domain": host, "findings": [], "coverage": None, "fingerprint": {}}

    monkeypatch.setattr(orchestrator, "crawl_domain", fake_crawl)

    await orchestrator.run_scan(
        cfg=_cfg(max_domains_per_run=2),
        extra_domains=["a.com", "b.com", "c.com", "d.com"],
    )
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_override_higher(monkeypatch):
    calls: list[str] = []

    async def fake_crawl(host, cfg, **kwargs):
        calls.append(host)
        return {"domain": host, "findings": [], "coverage": None, "fingerprint": {}}

    monkeypatch.setattr(orchestrator, "crawl_domain", fake_crawl)

    await orchestrator.run_scan(
        cfg=_cfg(max_domains_per_run=2),
        extra_domains=["a.com", "b.com", "c.com", "d.com"],
        max_domains_override=3,
    )
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_unlimited_domains(monkeypatch):
    calls: list[str] = []

    async def fake_crawl(host, cfg, **kwargs):
        calls.append(host)
        return {"domain": host, "findings": [], "coverage": None, "fingerprint": {}}

    monkeypatch.setattr(orchestrator, "crawl_domain", fake_crawl)

    await orchestrator.run_scan(
        cfg=_cfg(max_domains_per_run=1),
        extra_domains=["a.com", "b.com", "c.com"],
        unlimited_domains=True,
    )
    assert len(calls) == 3
