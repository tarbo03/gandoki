"""L5 severity-cap engine.

Caps only ever move impact DOWN, never up. Every cap adds a non-empty
cap_reason to impact.caveat. Data-driven from config/severity_caps.yaml.
"""
from __future__ import annotations
import time
from urllib.parse import urlparse

from ..models import Finding, ImpactLevel
from .secrets import jwt_exp, jwt_role


_ORDER = [
    ImpactLevel.INFO,
    ImpactLevel.LOW,
    ImpactLevel.MEDIUM,
    ImpactLevel.HIGH,
    ImpactLevel.CRITICAL,
]
_IDX = {lvl: i for i, lvl in enumerate(_ORDER)}


def _one_level_down(level: ImpactLevel) -> ImpactLevel | None:
    i = _IDX[level]
    if i <= 0:
        return None
    return _ORDER[i - 1]


class SeverityCap:
    def __init__(self, caps: list[dict]):
        self.caps = caps

    def apply(self, finding: Finding) -> None:
        """Mutate finding.impact in place when a cap matches. First-match wins."""
        for cap in self.caps:
            detector = cap.get("detector")
            if detector != "*" and detector != finding.secret_type:
                continue
            if not self._matches(finding, cap.get("when", {})):
                continue
            new_level = self._resolve(cap.get("cap_to"), finding.impact.level)
            if new_level is None:
                continue
            if _IDX[new_level] < _IDX[finding.impact.level]:
                finding.impact.level = new_level
                finding.impact.cap_reason = cap["reason"]
                finding.impact.caveat = (
                    finding.impact.caveat.rstrip(".") + ". "
                    + f"CAPPED: {cap['reason']}."
                )
            return

    def _matches(self, f: Finding, when: dict) -> bool:
        for key, val in when.items():
            if not self._check(f, key, val):
                return False
        return True

    def _check(self, f: Finding, key: str, val) -> bool:
        snippet = f.evidence.matched_snippet
        ctx = f.evidence.context_snippet

        if key == "prefix_match":
            return snippet.startswith(val)

        if key == "adjacent_config_missing":
            return not any(k in ctx for k in val)

        if key == "jwt_role_not":
            return jwt_role(snippet) != val

        if key == "jwt_expired":
            if val is not True:
                return False
            exp = jwt_exp(snippet)
            return exp is not None and exp < time.time()

        if key == "host_mismatch":
            expected = {
                "slack_webhook": {"hooks.slack.com"},
                "discord_webhook": {"discord.com", "discordapp.com"},
            }.get(f.secret_type)
            if not expected:
                return False
            try:
                h = (urlparse(snippet).hostname or "").lower()
            except Exception:
                return True
            return h not in expected

        if key == "capability_uncorroborated":
            return f.impact.if_valid_capability.startswith("Unknown")

        return False

    @staticmethod
    def _resolve(cap_to, current: ImpactLevel) -> ImpactLevel | None:
        if cap_to is None:
            return None
        if cap_to == "-1":
            return _one_level_down(current)
        try:
            return ImpactLevel(cap_to)
        except ValueError:
            return None
