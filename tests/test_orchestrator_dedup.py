"""Orchestrator dedupes duplicate hosts and honors seed_url."""
import pytest

from gandoki.pipeline import orchestrator


def _cfg(**over):
    base = {
        "max_domains_per_run": 200,
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
async def test_duplicate_hosts_scanned_once(monkeypatch):
    calls: list[str] = []

    async def fake_crawl(host, cfg, **kwargs):
        calls.append(host)
        return {"domain": host, "findings": [], "coverage": None, "fingerprint": {}}

    monkeypatch.setattr(orchestrator, "crawl_domain", fake_crawl)

    await orchestrator.run_scan(
        cfg=_cfg(),
        extra_domains=["a.com", "b.com", "a.com", "b.com", "a.com"],
    )
    assert sorted(calls) == ["a.com", "b.com"]


@pytest.mark.asyncio
async def test_url_single_uses_seed(monkeypatch):
    seeds: list[tuple[str, str | None]] = []

    async def fake_crawl(host, cfg, **kwargs):
        seeds.append((host, kwargs.get("seed_url")))
        return {"domain": host, "findings": [], "coverage": None, "fingerprint": {}}

    monkeypatch.setattr(orchestrator, "crawl_domain", fake_crawl)

    await orchestrator.run_scan(
        cfg=_cfg(), url_single="https://app.example.com/some/path",
    )
    assert len(seeds) == 1
    host, seed = seeds[0]
    assert host == "app.example.com"
    assert seed and "some/path" in seed
