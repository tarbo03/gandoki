"""Two-axis scoring.

Impact = severity IF the finding is real.
Confidence = how strong the evidence is.
These are NEVER collapsed into a single number that hides one axis.
"""
from __future__ import annotations
from ..models import Finding


_IMPACT_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_CONF_WEIGHT = {
    "VALIDATED_LIVE": 4,
    "CONFIRMED_PARTIAL": 3,
    "FORMAT_MATCH": 2,
    "SUSPECTED": 1,
}


def score(f: Finding) -> dict:
    imp = _IMPACT_WEIGHT[f.impact.level.value]
    conf = _CONF_WEIGHT.get(f.tier.value, 1)
    return {
        "impact_score": imp,
        "confidence_score": conf,
        "review_priority": imp * conf,
        "rank_label": _rank(imp, conf),
    }


def _rank(imp: int, conf: int) -> str:
    if conf >= 3 and imp >= 3:
        return "P1 — validate & act now"
    if imp >= 3 and conf == 2:
        return "P2 — validate before disclosure"
    if conf >= 2:
        return "P3 — review"
    return "P4 — informational"
