"""Markdown report — human-readable, GitHub-friendly, opens in any text editor."""
from __future__ import annotations
from datetime import datetime, timezone

from ..models import ConfidenceTier, Finding, Section


def _tier_label(tier: str) -> str:
    return {
        "VALIDATED_LIVE":    "`VALIDATED_LIVE`",
        "CONFIRMED_PARTIAL": "`CONFIRMED_PARTIAL`",
        "FORMAT_MATCH":      "`FORMAT_MATCH`",
        "SUSPECTED":         "`SUSPECTED`",
    }.get(tier, f"`{tier}`")


def build_md(findings: list[Finding], *,
             include_suspected: bool = False,
             coverage_manifest: dict | None = None) -> str:
    cov = coverage_manifest or {}
    accepted: list[Finding] = []
    retracted: list[Finding] = []
    for f in findings:
        if f.tier == ConfidenceTier.KNOWN_PUBLIC:
            continue
        if f.tier == ConfidenceTier.SUSPECTED and not include_suspected:
            continue
        (retracted if f.section == Section.RETRACTED else accepted).append(f)

    impact_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    tier_rank = {"VALIDATED_LIVE": 4, "CONFIRMED_PARTIAL": 3,
                 "FORMAT_MATCH": 2, "SUSPECTED": 1}
    accepted.sort(key=lambda f: -(
        impact_rank.get(f.impact.level.value, 0)
        * tier_rank.get(f.tier.value, 0)
    ))

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    L: list[str] = []

    # ---- Header ----
    L.append("# Gandoki Scan Report")
    L.append("")
    L.append("> **Precision-first secret & debug-exposure scanner** — "
             "by [Godwin Tarbo](https://github.com/tarbo03)")
    L.append("")
    L.append(f"**Generated:** {ts}  ")
    L.append(f"**Accepted findings:** {len(accepted)}  ")
    L.append(f"**Retracted by AI:** {len(retracted)}  ")
    if cov.get("ai_enabled"):
        L.append(f"**AI backend:** `{cov.get('ai_backend') or '—'}`  ")
        L.append(f"**Privacy mode:** `{cov.get('privacy_mode') or '—'}`  ")
    L.append("")
    L.append("---")
    L.append("")

    # ---- Coverage ----
    L.append("## Coverage")
    L.append("")
    L.append("| Metric | Value |")
    L.append("|---|---|")
    L.append(f"| Domains scanned | {cov.get('domains_scanned', 0)} |")
    L.append(f"| Pages fetched | {cov.get('pages_fetched', 0)} |")
    L.append(f"| Assets scanned | {cov.get('assets_scanned', 0)} |")
    if cov.get("assets_truncated_by_limit"):
        L.append(f"| Assets truncated | {cov['assets_truncated_by_limit']} (config limit) |")
    if cov.get("assets_failed"):
        L.append(f"| Assets failed | {cov['assets_failed']} |")
    for reason, count in (cov.get("assets_skipped_reason") or {}).items():
        L.append(f"| Skipped / {reason} | {count} |")
    L.append(f"| Candidates detected | {cov.get('candidates_detected', 0)} |")
    L.append(f"| Accepted | {cov.get('accepted', 0)} |")
    L.append(f"| Retracted by AI | {cov.get('retracted_by_ai', 0)} |")
    L.append(f"| Suppressed (SUSPECTED) | {cov.get('suppressed_suspected', 0)} |")
    L.append(f"| Suppressed (known-public) | {cov.get('suppressed_known_public', 0)} |")
    L.append(f"| robots.txt ignored | {'yes' if cov.get('robots_ignored') else 'no'} |")
    L.append(f"| AI enabled | {'yes' if cov.get('ai_enabled') else 'no'} |")
    L.append(f"| AI failures | {cov.get('ai_failures', 0)} |")
    L.append("")

    # ---- Accepted findings ----
    if accepted:
        L.append(f"## Accepted findings ({len(accepted)})")
        L.append("")
        for i, f in enumerate(accepted, 1):
            L.append(f"### {i}. {_tier_label(f.tier.value)} · "
                     f"**{f.impact.level.value}** · `{f.secret_type}`")
            L.append("")
            L.append(f"- **Asset:** {f.evidence.asset_url}")
            L.append(f"- **Discovery:** `{f.evidence.discovery_method}`")
            L.append(f"- **Provenance:** `{f.evidence.provenance.value}`")
            L.append(f"- **Snippet:** `{f._redact(f.evidence.matched_snippet)}`")
            L.append(f"- **Validation:** `{f.validation.status.value}`")
            if f.impact.cap_reason:
                L.append(f"- **Cap reason:** {f.impact.cap_reason}")
            L.append(f"- **If valid:** {f.impact.if_valid_capability}")
            L.append(f"- **Caveat:** {f.impact.caveat}")
            if f.cluster_id:
                L.append(f"- **Fleet cluster:** `{f.cluster_id}`")
            L.append(f"- **Remediation:** {f.remediation}")
            L.append("")
    else:
        L.append("## Accepted findings (0)")
        L.append("")
        L.append(f"**✓ Clean scan** — no findings accepted. "
                 f"Coverage: {cov.get('pages_fetched', 0)} pages, "
                 f"{cov.get('assets_scanned', 0)} assets.")
        L.append("")

    # ---- Retracted ----
    if retracted:
        L.append(f"## Retracted by AI ({len(retracted)})")
        L.append("")
        L.append("*Visible for review — retraction is not hiding.*")
        L.append("")
        for i, f in enumerate(retracted, 1):
            L.append(f"### {i}. `{f.secret_type}` — {f.impact.level.value}")
            L.append("")
            L.append(f"- **Asset:** {f.evidence.asset_url}")
            L.append(f"- **Snippet:** `{f._redact(f.evidence.matched_snippet)}`")
            if f.retraction:
                L.append(f"- **Reason:** {f.retraction.reason}")
                L.append(f"- **Decided by:** `{f.retraction.decided_by}`")
            L.append("")
    else:
        L.append("## Retracted by AI (0)")
        L.append("")
        L.append("*No findings were retracted.*")
        L.append("")

    L.append("---")
    L.append("")
    L.append("*Report generated by [Gandoki](https://github.com/tarbo03/gandoki) — "
             "a secret scanner that can't lie to you.*")
    L.append("")
    return "\n".join(L)


def write_md(findings: list[Finding], path: str, *,
             include_suspected: bool = False,
             coverage_manifest: dict | None = None) -> None:
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(build_md(findings,
                          include_suspected=include_suspected,
                          coverage_manifest=coverage_manifest))
