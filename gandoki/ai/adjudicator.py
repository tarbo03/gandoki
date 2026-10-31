"""L4 AI adjudication.

Runs AFTER live validation, BEFORE L5 severity cap.

Rules enforced here:
  - Only FORMAT_MATCH findings enter. VALIDATED_LIVE and CONFIRMED_PARTIAL
    are refused at code level — third-party proof outranks any model.
  - The only field this module writes on a Finding is `section` (and, when
    retracting, `retraction`). No other field is touched. EVER.
  - Fail-open: on LLMError, on bad parse, on budget exhaustion, the finding
    keeps section=ACCEPTED and continues to L5.
"""
from __future__ import annotations
from datetime import datetime, timezone

from ..models import (
    ConfidenceTier, Finding, Retraction, Section,
)
from .budget import AIBudget
from .client import LLMClient, LLMError
from .privacy import PrivacyMode, prepare_context
from .prompts import (
    ADJUDICATOR_TEMPLATE, adjudicator_payload, payload_hash,
)
from .verdict import Verdict, parse_verdict


class Adjudicator:
    def __init__(
        self,
        client: LLMClient | None,
        *,
        cfg: dict,
        budget: AIBudget,
        privacy_mode: PrivacyMode,
    ):
        self.client = client
        self.cfg = cfg
        self.budget = budget
        self.privacy_mode = privacy_mode
        self.max_context_chars = int(
            cfg.get("ai", {}).get("recall", {}).get("max_context_chars", 2000)
        )
        self.failures = 0
        self.failure_reasons: list[str] = []

    async def adjudicate(self, finding: Finding) -> None:
        """Mutate finding.section (ACCEPTED → RETRACTED) when the model says RETRACT.

        Silently no-ops in every other case, including every failure mode.
        """
        if self.client is None:
            return
        if finding.tier != ConfidenceTier.FORMAT_MATCH:
            return  # never touch VALIDATED_LIVE / CONFIRMED_PARTIAL / SUSPECTED
        if not await self.budget.acquire():
            return  # budget exhausted → leave finding accepted

        prepared = prepare_context(
            finding.evidence.context_snippet,
            self.privacy_mode,
            self.max_context_chars,
        )
        finding.evidence.context_truncated = prepared.truncated
        finding.evidence.prompt_injection_suspected = prepared.injection_flagged

        payload = adjudicator_payload(
            secret_type=finding.secret_type,
            snippet_redacted=finding._redact(finding.evidence.matched_snippet),
            context=prepared.text,
            asset_url=finding.evidence.asset_url,
            discovery_method=finding.evidence.discovery_method,
            tier=finding.tier.value,
        )
        input_hash = payload_hash(payload)

        try:
            raw = await self.client.chat(
                ADJUDICATOR_TEMPLATE,
                _format_payload(payload),
                timeout_s=int(
                    self.cfg.get("ai", {}).get("openrouter", {})
                    .get("timeout_s", 30)
                ),
            )
        except LLMError as e:
            self.failures += 1
            msg = str(e)[:240]
            if msg not in self.failure_reasons:
                self.failure_reasons.append(msg)
            return

        verdict: Verdict = parse_verdict(
            raw, model_id=self.client.model_id, input_hash=input_hash,
        )
        if verdict.kind == "RETRACT" and verdict.reason:
            finding.section = Section.RETRACTED
            finding.retraction = Retraction(
                reason=verdict.reason,
                decided_by=self.client.model_id,
                decided_at=datetime.now(timezone.utc),
                input_hash=verdict.input_hash,
            )
        # KEEP and UNCERTAIN are no-ops — no field on the finding is modified.


def _format_payload(payload: dict) -> str:
    """Serialize payload as JSON — never as natural language."""
    import json
    return json.dumps(payload, ensure_ascii=False)
