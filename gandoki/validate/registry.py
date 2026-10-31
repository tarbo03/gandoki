"""Validator registry.

Live validation is opt-in per secret type via config. Destructive validators
(Slack, Discord webhooks) are hard-refused here — they can only run through
explicit per-call opt-in (not implemented in Phase 1).
"""
from __future__ import annotations
from datetime import datetime, timezone

from ..models import ValidationResult, ValidationStatus
from . import openai as _openai, stripe as _stripe


_VALIDATORS: dict[str, tuple] = {
    "openai": (_openai.validate, False),
    "stripe_readonly": (_stripe.validate, False),
    # "slack":  (destructive — never auto-fired)
    # "aws_sts": extension point
    # "github_whoami": extension point
    # "supabase": extension point
}


async def validate_secret(
    validator_key: str | None,
    secret: str,
    cfg: dict,
) -> ValidationResult:
    if not validator_key:
        return ValidationResult(
            status=ValidationStatus.DISABLED,
            method="none",
            notes="No validator mapped for this detector.",
        )
    entry = _VALIDATORS.get(validator_key)
    if not entry:
        return ValidationResult(
            status=ValidationStatus.DISABLED,
            method=validator_key,
            notes="Validator not implemented yet.",
        )
    fn, destructive = entry
    if destructive:
        return ValidationResult(
            status=ValidationStatus.REFUSED,
            method=validator_key,
            notes="Destructive validator — auto-fire forbidden.",
        )
    if not cfg.get("validation", {}).get(validator_key, {}).get("enabled_live", False):
        return ValidationResult(
            status=ValidationStatus.DISABLED,
            method=validator_key,
            notes="Live validation disabled in config.",
        )
    try:
        ok, note = await fn(secret)
    except Exception as e:
        return ValidationResult(
            status=ValidationStatus.INCONCLUSIVE,
            method=validator_key,
            notes=f"Validator error: {e}",
            performed_at=datetime.now(timezone.utc),
        )
    now = datetime.now(timezone.utc)
    if ok is True:
        return ValidationResult(
            status=ValidationStatus.CONFIRMED,
            method=validator_key, notes=note, performed_at=now,
        )
    if ok == "partial":
        return ValidationResult(
            status=ValidationStatus.PARTIAL,
            method=validator_key, notes=note, performed_at=now,
        )
    if ok is False:
        return ValidationResult(
            status=ValidationStatus.FAILED,
            method=validator_key, notes=note, performed_at=now,
        )
    return ValidationResult(
        status=ValidationStatus.INCONCLUSIVE,
        method=validator_key, notes=note, performed_at=now,
    )
