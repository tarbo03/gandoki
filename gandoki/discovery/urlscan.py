"""urlscan.io — free tier (100 searches/day) needs a signup API key.

Disabled by default. If no API key is configured the source returns an
error result rather than silently returning zero domains.
"""
from __future__ import annotations
import httpx

from .base import DiscoveryResult, DiscoverySource


class UrlscanSource(DiscoverySource):
    name = "urlscan"

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def discover(
        self, query: str, limit: int = 100
    ) -> DiscoveryResult:
        out = DiscoveryResult(source=self.name)
        if not self.api_key:
            out.errors.append("urlscan api_key not configured")
            return out
        try:
            async with httpx.AsyncClient(timeout=30) as c:
                r = await c.get(
                    "https://urlscan.io/api/v1/search/",
                    params={"q": query, "size": str(limit)},
                    headers={"API-Key": self.api_key},
                )
                if r.status_code != 200:
                    out.errors.append(f"HTTP {r.status_code}")
                    return out
                data = r.json()
                for res in data.get("results", []):
                    domain = res.get("page", {}).get("domain")
                    if domain:
                        out.domains.append(domain)
        except Exception as e:
            out.errors.append(str(e))
        return out
