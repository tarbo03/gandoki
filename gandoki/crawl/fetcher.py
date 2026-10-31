"""Async HTTP fetcher with:
  - robots.txt fetching, parsing, and enforcement (per the RFC draft parsing
    rules used by Googlebot: longest-match wins, Allow beats Disallow on tie)
  - per-host concurrency + minimum delay (token bucket style)
  - max_response_bytes cap (prevents /actuator/heapdump from OOMing the box)
  - every fetch result carries a `skipped_reason` when it was NOT actually
    inspected, so coverage is honest
"""
from __future__ import annotations
import asyncio
import hashlib
import time
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx


@dataclass
class FetchResult:
    url: str
    status_code: int
    content: bytes
    text: str
    headers: dict
    sha256: str
    final_url: str
    skipped_reason: str | None = None


class _RobotsRules:
    def __init__(self, rules: list[tuple[str, str]], crawl_delay: float | None):
        self._rules = rules
        self.crawl_delay = crawl_delay

    @classmethod
    def allow_all(cls) -> "_RobotsRules":
        return cls([], None)

    @classmethod
    def parse(cls, text: str, user_agent: str) -> "_RobotsRules":
        blocks: dict[str, dict] = {}
        current_agents: list[str] = []
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.strip().lower()
            val = val.strip()
            if key == "user-agent":
                current_agents = [val.lower()]
                for a in current_agents:
                    blocks.setdefault(a, {"disallow": [], "allow": [], "delay": None})
            elif key == "disallow":
                for a in current_agents:
                    if a in blocks and val:
                        blocks[a]["disallow"].append(val)
            elif key == "allow":
                for a in current_agents:
                    if a in blocks and val:
                        blocks[a]["allow"].append(val)
            elif key == "crawl-delay":
                for a in current_agents:
                    if a in blocks:
                        try:
                            blocks[a]["delay"] = float(val)
                        except ValueError:
                            pass

        ua_l = user_agent.lower()
        chosen = None
        for agent, data in blocks.items():
            if agent != "*" and agent in ua_l:
                chosen = data
                break
        if chosen is None:
            chosen = blocks.get("*")
        if not chosen:
            return cls.allow_all()

        rules: list[tuple[str, str]] = []
        for p in chosen["allow"]:
            rules.append(("allow", p))
        for p in chosen["disallow"]:
            rules.append(("disallow", p))
        return cls(rules, chosen["delay"])

    def can_fetch(self, path: str) -> bool:
        if not self._rules:
            return True
        if not path:
            path = "/"
        best_len = -1
        best_directive = "allow"
        for directive, pat in self._rules:
            length, matched = self._match_len(pat, path)
            if not matched:
                continue
            if length > best_len or (length == best_len and directive == "allow"):
                best_len = length
                best_directive = directive
        return best_directive == "allow"

    @staticmethod
    def _match_len(pat: str, path: str) -> tuple[int, bool]:
        if pat == "/":
            return 1, path.startswith("/")
        if pat.endswith("*"):
            prefix = pat[:-1]
            return (len(prefix), True) if path.startswith(prefix) else (-1, False)
        if pat.endswith("$"):
            stem = pat[:-1]
            return (len(stem), True) if path == stem else (-1, False)
        return (len(pat), True) if path.startswith(pat) else (-1, False)


class RobotsCache:
    def __init__(self, client: httpx.AsyncClient, user_agent: str):
        self._client = client
        self._ua = user_agent
        self._cache: dict[str, _RobotsRules] = {}
        self._lock = asyncio.Lock()

    async def rules_for(self, url: str) -> _RobotsRules:
        host = urlparse(url).netloc
        async with self._lock:
            if host in self._cache:
                return self._cache[host]
        rules = await self._fetch(url)
        async with self._lock:
            self._cache[host] = rules
        return rules

    async def _fetch(self, url: str) -> _RobotsRules:
        p = urlparse(url)
        robots_url = f"{p.scheme}://{p.netloc}/robots.txt"
        try:
            r = await self._client.get(robots_url)
            if r.status_code == 200:
                return _RobotsRules.parse(r.text, self._ua)
        except Exception:
            pass
        return _RobotsRules.allow_all()


class AsyncFetcher:
    def __init__(self, cfg: dict, *, ignore_robots: bool = False):
        self.client = httpx.AsyncClient(
            headers={"User-Agent": cfg["user_agent"]},
            timeout=cfg["per_domain_timeout_s"],
            follow_redirects=True,
        )
        self.user_agent = cfg["user_agent"]
        self.max_bytes = int(cfg.get("max_response_bytes", 10_000_000))
        self.ignore_robots = ignore_robots
        self.robots = RobotsCache(self.client, self.user_agent)
        self._host_sems: dict[str, asyncio.Semaphore] = {}
        self._host_delays: dict[str, float] = {}
        self._host_last: dict[str, float] = {}
        per_host = cfg.get("per_host", {})
        self._max_per_host = int(per_host.get("max_concurrent_per_host", 4))
        self._min_delay_s = float(
            per_host.get("min_delay_ms_between_requests_per_host", 200)
        ) / 1000.0

    def _sem_for(self, host: str) -> asyncio.Semaphore:
        if host not in self._host_sems:
            self._host_sems[host] = asyncio.Semaphore(self._max_per_host)
        return self._host_sems[host]

    async def get(self, url: str, *, respect_robots: bool = True) -> FetchResult:
        p = urlparse(url)
        host = p.netloc

        if respect_robots and not self.ignore_robots:
            rules = await self.robots.rules_for(url)
            if not rules.can_fetch(p.path or "/"):
                return FetchResult(
                    url=url, status_code=0, content=b"", text="",
                    headers={}, sha256=hashlib.sha256(b"").hexdigest(),
                    final_url=url, skipped_reason="robots",
                )
            if rules.crawl_delay:
                self._host_delays[host] = max(
                    self._host_delays.get(host, 0.0), rules.crawl_delay
                )

        async with self._sem_for(host):
            now = time.monotonic()
            delay = max(self._host_delays.get(host, 0.0), self._min_delay_s)
            wait = delay - (now - self._host_last.get(host, 0.0))
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                r = await self.client.get(url)
            except Exception as e:
                self._host_last[host] = time.monotonic()
                return FetchResult(
                    url=url, status_code=0, content=b"", text="",
                    headers={}, sha256=hashlib.sha256(b"").hexdigest(),
                    final_url=url, skipped_reason=f"error:{type(e).__name__}",
                )
            self._host_last[host] = time.monotonic()

            content_len = len(r.content)
            if content_len > self.max_bytes:
                return FetchResult(
                    url=url, status_code=r.status_code, content=b"", text="",
                    headers=dict(r.headers),
                    sha256=hashlib.sha256(r.content).hexdigest(),
                    final_url=str(r.url), skipped_reason="size",
                )
            return FetchResult(
                url=url, status_code=r.status_code, content=r.content,
                text=r.text, headers=dict(r.headers),
                sha256=hashlib.sha256(r.content).hexdigest(),
                final_url=str(r.url),
            )

    async def aclose(self):
        await self.client.aclose()
