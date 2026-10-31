"""Common Crawl index — free, no auth. Data is weeks-to-months stale.

Enabled as an advanced discovery source only. Not suitable for
"newly-registered" use cases.
"""
from __future__ import annotations
import json
from urllib.parse import urlparse

import httpx

from .base import DiscoveryResult, DiscoverySource


class CommonCrawlSource(DiscoverySource):
    name = "common_crawl"

    # Index collection ID rotates over time. Advanced users can override.
    DEFAULT_INDEX = "CC-MAIN-2024-38"

    def __init__(self, index_collection: str | None = None):
        self.index_collection = index_collection or self.DEFAULT_INDEX
        self.index_url = (
            f"https://index.commoncrawl.org/{self.index_collection}-index"
        )

    async def discover(
        self, keyword: str = "supabase", limit: int = 500
    ) -> DiscoveryResult:
        out = DiscoveryResult(source=self.name)
        try:
            async with httpx.AsyncClient(timeout=30) as c:
                r = await c.get(
                    self.index_url,
                    params={
                        "url": f"*.{keyword}.*",
                        "output": "json",
                        "limit": str(limit),
                    },
                )
                if r.status_code != 200:
                    out.errors.append(f"HTTP {r.status_code}")
                    return out
                for line in r.text.splitlines():
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                        host = urlparse(rec.get("url", "")).hostname
                        if host:
                            out.domains.append(host)
                    except (json.JSONDecodeError, AttributeError):
                        continue
        except Exception as e:
            out.errors.append(str(e))
        return out
