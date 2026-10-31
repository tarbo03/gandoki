"""Shared AI call budget. Enforced at every call site (Stage 0 and L4)."""
from __future__ import annotations
import asyncio
from dataclasses import dataclass, field


@dataclass
class AIBudget:
    max_calls: int
    calls_made: int = 0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    async def acquire(self) -> bool:
        async with self._lock:
            if self.calls_made >= self.max_calls:
                return False
            self.calls_made += 1
            return True

    @property
    def exhausted(self) -> bool:
        return self.calls_made >= self.max_calls
