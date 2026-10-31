"""SARIF 2.1.0 writer for GitHub Code Scanning / SAST consumers.

Retracted findings are emitted with a distinct rule-property `retracted: true`
and a `suppression` block so consumers can filter them but won't silently
drop them.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone

from ..models import Finding, Section
from ..scoring.scorer import score


def write_sarif(
    findings: list[Finding],
    path: str,
    *,
    include_suspected: bool = False,
    coverage_manifest: dict | None = None,
) -> None:
    rules_seen: dict[str, dict] = {}
    results = []
    for f in findings:
        if f.tier.value == "KNOWN_PUBLIC":
            continue
        if f.tier.value == "SUSPECTED" and not include_suspected:
            continue
        if f.secret_type not in rules_seen:
            rules_seen[f.secret_type] = {
                "id": f.secret_type,
                "name": f.secret_type,
                "shortDescription": {"text": f.secret_type},
                "properties": {
                    "category": f.category.value,
                    "impact": f.impact.level.value,
                },
            }
        s = score(f)
        result = {
            "ruleId": f.secret_type,
            "level": _sarif_level(f),
            "message": {"text": (
                f"{f.tier.value} | {f.impact.level.value} | "
                f"validation={f.validation.status.value} | "
                f"provenance={f.evidence.provenance.value} | {s['rank_label']}"
            )},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.evidence.asset_url},
                    "region": {"byteOffset": f.evidence.byte_offset},
                }
            }],
            "properties": {
                "confidence_tier": f.tier.value,
                "validation_status": f.validation.status.value,
                "provenance": f.evidence.provenance.value,
                "cluster_id": f.cluster_id,
                "finding_id": f.finding_id,
                "cap_reason": f.impact.cap_reason,
                "retracted": f.section == Section.RETRACTED,
            },
        }
        if f.section == Section.RETRACTED and f.retraction:
            result["suppressions"] = [{
                "kind": "external",
                "justification": f"AI-retracted: {f.retraction.reason}",
                "status": "accepted",
            }]
        results.append(result)

    run_props = {}
    if coverage_manifest:
        run_props["coverage_manifest"] = coverage_manifest

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Gandoki",
                    "version": "1.0",
                    "informationUri": "https://example.invalid/secrethunter",
                    "rules": list(rules_seen.values()),
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
            "properties": run_props,
        }],
    }
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(doc, fp, indent=2)


def _sarif_level(f: Finding) -> str:
    if f.impact.level.value in ("CRITICAL", "HIGH"):
        return "error"
    if f.impact.level.value == "MEDIUM":
        return "warning"
    return "note"
