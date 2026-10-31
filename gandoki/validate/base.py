"""Shared types for validators."""
from __future__ import annotations
from enum import Enum


class Outcome(str, Enum):
    CONFIRMED = "CONFIRMED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    DISABLED = "DISABLED"
    REFUSED = "REFUSED"
