"""Main scan pipeline.

Order per domain:
    crawl (with Stage 0 recall hook) → L1 detect → findings

Order per finding (after all crawls):
    live validation (if enabled) → L4 AI adjudicate → L5 severity cap

Then:
    cluster → triage → (opt-in narration) → return

The AI write surface is `section` only. Enforced by adjudicator, which is
only ever called here.
"""
from __future__ import annotations
import asyncio
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from ..config import load_config, load_rules_config, load_severity_caps
from ..crawl.crawler import crawl_domain
from ..crawl.fetcher import AsyncFetcher
from ..detect.debug_code import DebugEngine
from ..detect.secrets import SecretEngine, Rule, rules_from_dicts
from ..detect.severity_cap import SeverityCap
from ..discovery.base import dedupe_preserve_order
from ..discovery.ct_logs import stream_ct_matches
from ..discovery.scope import load_scope
from ..fleet.cluster import cluster_domains
from ..models import ConfidenceTier, Finding, Section
from ..validate.registry import validate_secret


@dataclass
class ScanResult:
    findings: list[Finding]
    fingerprints: dict[str, dict]
    clusters: dict[str, str]
    domains_scanned: int
    coverage_manifest: dict


# -------- AI builder (never raises; degrades gracefully) --------

@dataclass
class _AIStack:
    client: object = None
    adjudicator: object = None
    recall: object = None
    budget: object = None
    privacy_mode: str = "unknown"
    backend: Optional[str] = None
    enabled: bool = False
    requested: bool = False          # what config/flag said should happen
    disabled_reason: Optional[str] = None


def _build_ai_stack(
    cfg: dict, known_rules: list[Rule], *, override_enabled: Optional[bool] = None,
    override_backend: Optional[str] = None,
) -> _AIStack:
    stack = _AIStack()
    cfg.setdefault("ai", {})
    if override_enabled is not None:
        cfg["ai"]["enabled"] = override_enabled
    if override_backend:
        cfg["ai"]["backend"] = override_backend
    enabled = cfg["ai"].get("enabled", False)
    stack.requested = enabled
    if not enabled:
        stack.disabled_reason = (
            "--no-ai flag passed" if override_enabled is False
            else "ai.enabled is false in config (default)"
        )
        return stack
    ai_cfg = cfg["ai"]

    from ..ai.client import build_client, LLMError, verify_adjudicator_template
    from ..ai.privacy import select_mode
    from ..ai.budget import AIBudget
    from ..ai.adjudicator import Adjudicator
    from ..ai.recall import Recall

    try:
        verify_adjudicator_template()
        client = build_client(cfg)
    except LLMError as e:
        stack.disabled_reason = f"AI backend unavailable: {e}"
        print(f"[gandoki] AI disabled: {e}", flush=True)
        return stack
    if client is None:
        stack.disabled_reason = "AI client could not be constructed"
        return stack

    budget_max = int(ai_cfg.get("recall", {}).get("max_ai_calls_per_run", 500))
    budget = AIBudget(max_calls=budget_max)
    privacy = select_mode(ai_cfg.get("backend", "openrouter"), cfg)

    stack.client = client
    stack.budget = budget
    stack.privacy_mode = privacy.value
    stack.backend = f"{ai_cfg.get('backend')}:{client.model_id}"
    stack.enabled = True

    if ai_cfg.get("levels", {}).get("l4_ai_adjudication", True):
        stack.adjudicator = Adjudicator(
            client, cfg=cfg, budget=budget, privacy_mode=privacy,
        )
    if ai_cfg.get("recall", {}).get("enabled", True):
        stack.recall = Recall(
            client, cfg=cfg, budget=budget, privacy_mode=privacy,
            known_rules=known_rules,
        )
    return stack


# -------- public entry point --------

async def run_scan(
    *,
    cfg: dict,
    rules_path: str = "config/rules.yaml",
    caps_path: str = "config/severity_caps.yaml",
    scope: Optional[str] = None,
    domains: Optional[str] = None,
    extra_domains: Optional[list[str]] = None,
    url_single: Optional[str] = None,
    include_suspected: bool = False,
    ignore_robots: bool = False,
    max_domains_override: Optional[int] = None,
    unlimited_domains: bool = False,
    ai_override_enabled: Optional[bool] = None,
    ai_override_backend: Optional[str] = None,
    progress=None,
) -> ScanResult:
    if progress is None:
        from ..ui.progress import NullProgress
        progress = NullProgress()

    rules_dicts = load_rules_config(rules_path)
    rules = rules_from_dicts(rules_dicts)
    secret_engine = SecretEngine(rules)
    debug_engine = DebugEngine(rules)
    severity_cap = SeverityCap(load_severity_caps(caps_path))

    progress.phase_start("INIT", "loading rules")
    progress.phase_end("INIT")
    ai_stack = _build_ai_stack(
        cfg, rules,
        override_enabled=ai_override_enabled,
        override_backend=ai_override_backend,
    )

    # ---- assemble targets ----
    targets: list[tuple[str, Optional[str]]] = []  # (host, seed_url)

    if scope:
        for h in load_scope(scope):
            targets.append((h, None))
    if domains:
        for d in domains.split(","):
            d = d.strip()
            if d:
                targets.append((d, None))
    if extra_domains:
        for d in extra_domains:
            targets.append((d, None))
    if url_single:
        from ..discovery.file_input import parse_single_url
        h, seed = parse_single_url(url_single)
        if h:
            targets.append((h, seed))

    if cfg.get("scope_mode") == "discovery" and \
            cfg.get("discovery", {}).get("ct_logs", {}).get("enabled"):
        async for d in stream_ct_matches(
            cfg["discovery"]["ct_logs"].get("keywords", [])
        ):
            targets.append((d, None))

    # dedupe by host
    seen_hosts: set[str] = set()
    deduped: list[tuple[str, Optional[str]]] = []
    for host, seed in targets:
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        deduped.append((host, seed))
    targets = deduped

    if targets:
        seed = targets[0][1]
        host = targets[0][0]
        display_target = seed if seed else f"https://{host}"
        progress.target(display_target)

    # ---- enforce max_domains ----
    default_max = int(cfg.get("max_domains_per_run", 200))
    if unlimited_domains:
        max_allowed: object = "unlimited"
        effective_max = len(targets)
    elif max_domains_override is not None:
        max_allowed = max_domains_override
        effective_max = max_domains_override
    else:
        max_allowed = default_max
        effective_max = default_max
    if not unlimited_domains and len(targets) > effective_max:
        targets = targets[:effective_max]

    progress.phase_start("CRAWL", f"{len(targets)} domain(s)")
    # ---- crawl ----
    fetcher = AsyncFetcher(cfg, ignore_robots=ignore_robots)
    sem = asyncio.Semaphore(int(cfg.get("concurrency", 20)))
    results: list[dict] = []

    async def _one(host: str, seed: Optional[str]) -> None:
        async with sem:
            progress.domain_started(host)
            try:
                res = await crawl_domain(
                    host, cfg,
                    secret_engine=secret_engine,
                    debug_engine=debug_engine,
                    fetcher=fetcher,
                    recall_engine=ai_stack.recall,
                    seed_url=seed,
                    progress=progress,
                )
                results.append(res)
                progress.domain_done(host, findings=len(res["findings"]))
            except Exception as e:
                progress.domain_done(host, findings=0)
                results.append({
                    "domain": host,
                    "findings": [],
                    "coverage": None,
                    "fingerprint": {},
                    "error": f"{type(e).__name__}: {e}",
                })

    try:
        await asyncio.gather(*[_one(h, s) for h, s in targets])
    finally:
        await fetcher.aclose()
        if ai_stack.client is not None:
            try:
                await ai_stack.client.aclose()
            except Exception:
                pass

    # ---- post-process findings ----
    all_findings: list[Finding] = []
    fingerprints: dict[str, dict] = {}
    robots_ignored_flag = ignore_robots

    for r in results:
        fingerprints[r["domain"]] = r.get("fingerprint") or {}
        all_findings.extend(r["findings"])

    candidates_detected = len(all_findings)
    suppressed_known_public = sum(
        1 for f in all_findings if f.tier == ConfidenceTier.KNOWN_PUBLIC
    )

    # Phase: VALIDATE — live checks (read-only against third parties)
    progress.phase_end("CRAWL")
    progress.phase_start("VALIDATE", "live checks")
    progress.phase_end("VALIDATE")
    for f in all_findings:
        if f.category.value == "secret":
            await _maybe_validate(f, cfg, rules)

    # Phase: AI — L4 adjudication (retraction of FORMAT_MATCH)
    if ai_stack.adjudicator is not None:
        from ..models import ConfidenceTier as _CT
        ai_candidates = [f for f in all_findings if f.tier == _CT.FORMAT_MATCH]
        if ai_candidates:
            progress.phase_start("AI", f"{len(ai_candidates)} candidate(s)")
            for i, f in enumerate(ai_candidates, 1):
                progress.ai_call(i, len(ai_candidates))
                await ai_stack.adjudicator.adjudicate(f)

    # Phase: CAP — L5 severity caps
    progress.phase_end("AI")
    progress.phase_start("CAP", "severity caps")
    progress.phase_end("CAP")
    for f in all_findings:
        severity_cap.apply(f)

    # ---- cluster + enrich ----
    progress.phase_start("CLUSTER", "fleet grouping")
    progress.phase_end("CLUSTER")
    clusters = cluster_domains(fingerprints, threshold=0.6)

    from urllib.parse import urlparse as _urlparse
    def _host_of(url: str) -> str:
        if "://" not in url:
            return ""
        try:
            return (_urlparse(url).hostname or "").lower()
        except Exception:
            return ""

    for f in all_findings:
        f.cluster_id = clusters.get(_host_of(f.evidence.source_url))

    # triage hints (deterministic)
    progress.phase_start("ENRICH", "triage hints")
    progress.phase_end("ENRICH")
    from ..ai.enrichment import triage_hint, near_clone_hint
    from ..models import AIEnrichment
    from datetime import datetime, timezone as _tz

    triage_hint(all_findings)
    for host, hint in near_clone_hint(fingerprints, clusters).items():
        for f in all_findings:
            if _host_of(f.evidence.source_url) == host:
                if f.enrichment is None:
                    f.enrichment = AIEnrichment(
                        generated_by="deterministic",
                        generated_at=datetime.now(_tz.utc),
                    )
                f.enrichment.cluster_hint_ai = hint

    # ---- filter SUSPECTED ----
    if not include_suspected:
        visible = [f for f in all_findings if f.tier != ConfidenceTier.SUSPECTED]
    else:
        visible = all_findings

    # ---- coverage manifest ----
    # accepted/retracted must match what the report will show. KNOWN_PUBLIC
    # never appears in reports (honesty contract), so it is not "accepted".
    reportable = [f for f in visible if f.tier != ConfidenceTier.KNOWN_PUBLIC]
    accepted = sum(1 for f in reportable if f.section == Section.ACCEPTED)
    retracted = sum(1 for f in reportable if f.section == Section.RETRACTED)
    ai_failures = 0
    ai_failure_reasons: list[str] = []
    if ai_stack.adjudicator is not None:
        ai_failures = getattr(ai_stack.adjudicator, "failures", 0)
        ai_failure_reasons = list(
            getattr(ai_stack.adjudicator, "failure_reasons", [])
        )[:5]
    budget_used = ai_stack.budget.calls_made if ai_stack.budget else 0

    # Aggregate per-domain crawl stats so the manifest is self-diagnosing.
    total_pages = 0
    total_assets_ok = 0
    total_assets_failed = 0
    total_assets_truncated = 0
    all_skip_reasons: dict[str, int] = {}
    for r in results:
        cov = r.get("coverage")
        if cov is None:
            continue
        total_pages += getattr(cov, "pages_fetched", 0)
        total_assets_ok += getattr(cov, "assets_scanned", 0)
        total_assets_failed += getattr(cov, "assets_failed", 0)
        total_assets_truncated += getattr(cov, "assets_truncated", 0)
        for k, v in getattr(cov, "assets_skipped_reason", {}).items():
            all_skip_reasons[k] = all_skip_reasons.get(k, 0) + v

    manifest = {
        "pages_fetched": total_pages,
        "assets_scanned": total_assets_ok,
        "assets_failed": total_assets_failed,
        "assets_truncated_by_limit": total_assets_truncated,
        "assets_skipped_reason": all_skip_reasons,
        "candidates_detected": candidates_detected,
        "accepted": accepted,
        "retracted_by_ai": retracted,
        "suppressed_suspected": sum(
            1 for f in all_findings if f.tier == ConfidenceTier.SUSPECTED
        ) if not include_suspected else 0,
        "suppressed_known_public": suppressed_known_public,
        "ai_enabled": ai_stack.enabled,
        "ai_requested": ai_stack.requested,
        "ai_disabled_reason": ai_stack.disabled_reason,
        "ai_backend": ai_stack.backend,
        "ai_failures": ai_failures,
        "ai_failure_reasons": ai_failure_reasons,
        "ai_budget_used": budget_used,
        "ai_budget_max": (
            int(ai_stack.budget.max_calls) if ai_stack.budget else 0
        ),
        "privacy_mode": ai_stack.privacy_mode,
        "max_domains_enforced": max_allowed,
        "domains_requested": len(seen_hosts),
        "domains_scanned": len(targets),
        "robots_ignored": robots_ignored_flag,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    return ScanResult(
        findings=visible,
        fingerprints=fingerprints,
        clusters=clusters,
        domains_scanned=len(targets),
        coverage_manifest=manifest,
    )


async def _maybe_validate(f: Finding, cfg: dict, rules: list[Rule]) -> None:
    """Attempt live validation when:
         - the detector has a validator key
         - config enables live for that type
       Result may upgrade tier to VALIDATED_LIVE / CONFIRMED_PARTIAL,
       or downgrade to FORMAT_MATCH if the third party rejected it.
    """
    if f.tier == ConfidenceTier.KNOWN_PUBLIC:
        return
    rule = next((r for r in rules if r.id == f.secret_type), None)
    if rule is None or not rule.validator:
        return
    v = await validate_secret(rule.validator, f.evidence.matched_snippet, cfg)
    f.validation = v
    from ..models import ValidationStatus
    if v.status == ValidationStatus.CONFIRMED:
        f.tier = ConfidenceTier.VALIDATED_LIVE
        f.impact.caveat = (
            "VALIDATED — third-party API confirmed this credential works. "
            "Treat as live exposure."
        )
    elif v.status == ValidationStatus.PARTIAL:
        f.tier = ConfidenceTier.CONFIRMED_PARTIAL
        f.impact.caveat = (
            "PARTIAL — API accepted the credential but full scope/permissions "
            "were not verified."
        )
    elif v.status == ValidationStatus.FAILED:
        f.tier = ConfidenceTier.FORMAT_MATCH
        f.impact.caveat = (
            f"TESTED — third-party API rejected this credential at "
            f"{v.performed_at}. May already be rotated or never valid."
        )
