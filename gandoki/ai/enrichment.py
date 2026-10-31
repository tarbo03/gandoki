"""AI enrichment — additive only. Never touches tier/impact/validation.

Items implemented:
  3. Sourcemap context recovery (evidence.recovered_context)
  4. Fleet near-clone detection (cluster_hint_ai)
  5. Triage hints (ai_review_hint) — one list for ACCEPTED, one for RETRACTED
  6. Narration (ai_narration) — opt-in, mentions retraction counts
  7. Builder provenance (builder_hint_ai)
"""
from __future__ import annotations
from datetime import datetime, timezone

from ..models import (
    AIEnrichment, Finding, Section,
)
from .client import LLMClient, LLMError
from .prompts import SOURCEMAP_RECOVERY_TEMPLATE


async def recover_sourcemap_context(
    client: LLMClient,
    finding: Finding,
) -> None:
    """Populate evidence.recovered_context. Never changes tier or anything else."""
    if client is None:
        return
    if finding.evidence.discovery_method not in ("js_bundle", "sourcemap"):
        return
    if len(finding.evidence.context_snippet) < 40:
        return
    try:
        out = await client.chat(
            SOURCEMAP_RECOVERY_TEMPLATE,
            finding.evidence.context_snippet[:1500],
            timeout_s=15,
        )
    except LLMError:
        return
    text = (out or "").strip().splitlines()[0].strip() if out else ""
    if not text or text.lower() == "unknown":
        return
    finding.evidence.recovered_context = text[:300]


def near_clone_hint(
    fingerprints: dict[str, dict],
    deterministic_clusters: dict[str, str],
    similarity_threshold: float = 0.9,
) -> dict[str, str]:
    """Compute near-clone hints using fingerprint similarity.

    A domain pair whose fingerprint similarity is high but whose deterministic
    cluster_id differs is reported as a probable near-clone.

    Returns a map: domain -> "near_clone_with:<other_domain>".
    """
    from ..fleet.fingerprint import similarity
    domains = list(fingerprints)
    hints: dict[str, str] = {}
    for i, a in enumerate(domains):
        for b in domains[i + 1:]:
            if deterministic_clusters.get(a) == deterministic_clusters.get(b):
                continue  # already same fleet deterministically — no hint needed
            sim = similarity(fingerprints[a], fingerprints[b])
            if sim >= similarity_threshold:
                hints.setdefault(a, f"near_clone_with:{b}")
                hints.setdefault(b, f"near_clone_with:{a}")
    return hints


def triage_hint(findings: list[Finding]) -> None:
    """Populate enrichment.ai_review_hint with a strict rank-based suggestion.

    Deterministic — no model call. Rank is derived from the existing scoring,
    so the hint cannot contradict the score it is annotating.
    """
    from ..scoring.scorer import score

    accepted = [f for f in findings if f.section == Section.ACCEPTED]
    retracted = [f for f in findings if f.section == Section.RETRACTED]

    accepted.sort(key=lambda f: -score(f)["review_priority"])
    for rank, f in enumerate(accepted[:30], start=1):
        _attach_hint(f, f"review_rank=#{rank} (of {len(accepted)} accepted)")

    # Retracted: suggest a subset for spot-checking
    retracted.sort(key=lambda f: -score(f)["review_priority"])
    for rank, f in enumerate(retracted[:10], start=1):
        _attach_hint(f, f"spot_check_rank=#{rank} (of {len(retracted)} retracted)")


def _attach_hint(f: Finding, hint: str) -> None:
    if f.enrichment is None:
        f.enrichment = AIEnrichment(
            generated_by="deterministic",
            generated_at=datetime.now(timezone.utc),
        )
    f.enrichment.ai_review_hint = hint


async def narrate(
    client: LLMClient,
    findings: list[Finding],
    coverage: dict,
) -> str | None:
    """Opt-in narration. Template-locked, fact-summarizing only."""
    if client is None:
        return None
    accepted = sum(1 for f in findings if f.section == Section.ACCEPTED)
    retracted = sum(1 for f in findings if f.section == Section.RETRACTED)
    prompt = (
        f"Summarize these scan results in 3 sentences. Facts:\n"
        f"  accepted findings: {accepted}\n"
        f"  retracted by AI: {retracted}\n"
        f"  ai_backend: {coverage.get('ai_backend')}\n"
        f"  ai_failures: {coverage.get('ai_failures')}\n"
        f"Only use the numbers given. Do not invent counts or severities."
    )
    try:
        out = await client.chat(
            "You summarize security scan results factually. Only restate "
            "the exact numbers provided. Never invent counts.",
            prompt,
            timeout_s=20,
        )
    except LLMError:
        return None
    return (out or "").strip()[:1000] or None


def builder_hint_from_html(html: str) -> str | None:
    """Deterministic builder/framework guess. No model call."""
    h = html.lower()
    markers = [
        ("lovable", "lovable"),
        ("bolt.new", "bolt"),
        ("v0.dev", "v0"),
        ("webflow", "webflow"),
        ("wix.com", "wix"),
        ("squarespace", "squarespace"),
        ("shopify", "shopify"),
        ("framer", "framer"),
        ("__next_data__", "nextjs"),
        ("_nuxt", "nuxt"),
        ("svelte", "svelte"),
        ("vue", "vue"),
        ("react", "react"),
        ("bubble", "bubble"),
    ]
    for marker, label in markers:
        if marker in h:
            return label
    return None
