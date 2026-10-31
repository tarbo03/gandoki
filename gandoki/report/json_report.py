"""JSON report — the honesty contract is enforced here via Finding.to_public_dict().

Retracted findings are ALWAYS emitted in a separate `retracted` array so
they are visible, not hidden. The `coverage` block is the honesty manifest.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone

from ..models import Finding, Section
from ..scoring.scorer import score


def _partition(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    accepted, retracted = [], []
    for f in findings:
        if f.tier.value == "KNOWN_PUBLIC":
            continue
        if f.section == Section.RETRACTED:
            retracted.append(f)
        else:
            accepted.append(f)
    return accepted, retracted


def build_report(
    findings: list[Finding],
    *,
    include_suspected: bool = False,
    coverage_manifest: dict | None = None,
) -> dict:
    accepted, retracted = _partition(findings)

    def _serialize(items: list[Finding]) -> list[dict]:
        rows = []
        for f in items:
            if f.tier.value == "SUSPECTED" and not include_suspected:
                continue
            d = f.to_public_dict()
            d["scoring"] = score(f)
            rows.append(d)
        return rows

    accepted_rows = _serialize(accepted)
    retracted_rows = _serialize(retracted)

    # Coverage manifest — counts of what happened at each stage.
    # Caller may pass explicit counts (orchestrator does); otherwise derive.
    manifest = coverage_manifest or {
        "candidates_detected": len(findings),
        "accepted": len(accepted_rows),
        "retracted_by_ai": len(retracted_rows),
        "suppressed_suspected": (
            sum(1 for f in accepted + retracted if f.tier.value == "SUSPECTED")
            if not include_suspected else 0
        ),
        "ai_backend": None,
        "ai_failures": 0,
    }

    return {
        "tool": "Gandoki",
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "note": (
            "Every finding states what was and was not tested. "
            "FORMAT_MATCH means the credential's format matched but it was NOT "
            "validated against the third party. Treat as potentially live until "
            "rotated. validation.status is authoritative. Retracted findings "
            "are visible in the `retracted` array with the reason."
        ),
        "coverage": manifest,
        "findings": accepted_rows,
        "retracted": retracted_rows,
    }


def write_json(
    findings: list[Finding],
    path: str,
    *,
    include_suspected: bool = False,
    coverage_manifest: dict | None = None,
) -> None:
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(
            build_report(
                findings,
                include_suspected=include_suspected,
                coverage_manifest=coverage_manifest,
            ),
            fp, indent=2, default=str,
        )
