"""Common shape for discovery sources."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class DiscoveryResult:
    source: str
    domains: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class DiscoverySource:
    """Subclasses implement `async discover(**kwargs) -> DiscoveryResult`."""
    name: str = "base"

    async def discover(self, **kwargs) -> DiscoveryResult:
        raise NotImplementedError


def dedupe_preserve_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out
