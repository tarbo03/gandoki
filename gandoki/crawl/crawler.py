"""Async per-domain crawler.

Returns findings, a coverage context, and a fingerprint dict used by the
fleet clusterer. Coverage is ALWAYS populated — no silent failures.

Fingerprint helpers live here (not in fleet/) so Batch 3 is self-contained.
fleet/cluster.py in Batch 4 consumes this dict; it does not re-hash.
"""
from __future__ import annotations
import base64
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse

import mmh3

from ..models import CoverageContext
from .fetcher import AsyncFetcher, FetchResult
from .js_extractor import (
    extract_inline_scripts, extract_internal_links, extract_js_imports,
    extract_js_urls, extract_sourcemap_urls,
)


# ---- fingerprint helpers (consumed by fleet/cluster.py) ----

def favicon_hash_from_bytes(icon_bytes: bytes | None) -> str | None:
    if not icon_bytes:
        return None
    return str(mmh3.hash(base64.encodebytes(icon_bytes)))


def dom_hash(html: str) -> str:
    import re
    skeleton = re.sub(r">[^<]+<", "><", html)
    skeleton = re.sub(r"\s+", " ", skeleton)
    return hashlib.sha256(skeleton.encode()).hexdigest()[:16]


def inline_scripts_hash(inline: str) -> str:
    return hashlib.sha256(inline.encode()).hexdigest()[:16]


def js_bundle_hash(urls: list[str], bodies: list[bytes]) -> str:
    pairs = sorted(zip(urls, bodies), key=lambda x: x[0])
    h = hashlib.sha256()
    for u, b in pairs:
        h.update(u.encode())
        h.update(b)
    return h.hexdigest()[:16]


# ---- crawler ----

def _now() -> datetime:
    return datetime.now(timezone.utc)


async def crawl_domain(
    domain: str,
    cfg: dict,
    *,
    secret_engine,
    debug_engine,
    fetcher: AsyncFetcher,
    recall_engine=None,
    seed_url: str | None = None,
    progress=None,
) -> dict:
    if progress is None:
        from ..ui.progress import NullProgress
        progress = NullProgress()

    progress.phase_start("CRAWL", f"crawling {domain}")

    base = seed_url or f"https://{domain}/"
    host = urlparse(base).netloc
    started = _now()

    visited: set[str] = set()
    queue: list[str] = [base]
    findings: list = []

    pages_fetched = 0
    assets_scanned = 0
    assets_failed = 0
    assets_truncated = 0
    skipped: list[str] = []
    skipped_reasons: dict[str, int] = {}

    favicon_bytes: bytes | None = None
    first_html: str | None = None
    first_inline: list[str] = []
    js_bodies: list[bytes] = []
    js_urls_ok: list[str] = []
    max_pages = int(cfg.get("max_pages_per_domain", 15))
    max_assets = int(cfg.get("max_assets_per_page", 40))
    budget_s = float(cfg.get("crawl_budget_s", 60))

    def _cov() -> CoverageContext:
        return CoverageContext(
            pages_fetched=pages_fetched,
            assets_scanned=assets_scanned,
            assets_failed=assets_failed,
            assets_truncated=assets_truncated,
            sources_queried=["live"],
            skipped=list(skipped),
            crawl_budget_seconds=int(budget_s),
            crawl_started=started,
            crawl_ended=_now(),
            assets_skipped_reason=dict(skipped_reasons),
        )

    def _bump_skip(reason: str | None) -> None:
        if not reason:
            return
        key = reason.split(":", 1)[0]
        skipped_reasons[key] = skipped_reasons.get(key, 0) + 1

    while (queue
           and pages_fetched < max_pages
           and (_now() - started).total_seconds() < budget_s):
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        page = await fetcher.get(url)
        if page.skipped_reason is not None or page.status_code == 0:
            _bump_skip(page.skipped_reason)
            assets_failed += 1
            continue
        if page.status_code >= 400:
            # Error pages (400-599) frequently leak debug info via framework
            # error handlers (Django DEBUG=True, Flask Werkzeug, Rails dev page,
            # ASP.NET detailed errors). Scan them for debug patterns but NOT
            # for secrets — error pages are unreliable credential sources.
            # A 500 page is exactly what require_error_status detectors need.
            _bump_skip(f"error_status_{page.status_code}")
            assets_failed += 1
            err_cov = _cov()
            findings += debug_engine.scan_body(
                source_url=url, asset_url=url, body=page.content,
                discovery_method="html_error", coverage=err_cov,
                headers=page.headers, status_code=page.status_code,
            )
            findings += debug_engine.scan_headers(
                source_url=url, asset_url=url, headers=page.headers,
                coverage=err_cov, body=page.content,
            )
            continue

        pages_fetched += 1
        progress.detail(f"{domain} · page {pages_fetched}")
        if first_html is None:
            first_html = page.text
            first_inline = extract_inline_scripts(page.text)

        cov = _cov()
        findings += secret_engine.scan(
            source_url=url, asset_url=url, body=page.content,
            discovery_method="html", coverage=_cov(),
        )
        findings += debug_engine.scan_body(
            source_url=url, asset_url=url, body=page.content,
            discovery_method="html", coverage=_cov(),
            headers=page.headers, status_code=page.status_code,
        )
        findings += debug_engine.scan_headers(
            source_url=url, asset_url=url, headers=page.headers,
            coverage=cov, body=page.content,
        )
        if recall_engine is not None:
            findings += await recall_engine.scan(
                source_url=url, asset_url=url, body=page.content,
                discovery_method="html", coverage=cov,
            )

        # If this "page" is actually JavaScript (linked via <a href="app.js">),
        # extract and verify its sourcemap. The JS bundle loop below only
        # handles <script src> references; direct .js links land here.
        is_js_content = (
            url.endswith((".js", ".mjs"))
            or "javascript" in page.headers.get("content-type", "").lower()
        )
        if is_js_content:
            for sm_url in extract_sourcemap_urls(page.text, url)[:5]:
                if sm_url in visited:
                    continue
                sr = await fetcher.get(sm_url)
                if sr is None or sr.skipped_reason is not None or sr.status_code != 200:
                    # Do not mark visited on fetch failure — retry from another reference
                    continue
                visited.add(sm_url)
                assets_scanned += 1
                sm_f = debug_engine.sourcemap_finding(
                    source_url=url, asset_url=sm_url, body=sr.content,
                    coverage=_cov(),
                )
                if sm_f:
                    findings.append(sm_f)

        # enqueue internal links
        for link in extract_internal_links(page.text, base, host):
            if link not in visited:
                queue.append(link)

        # JS bundles
        all_js_urls = extract_js_urls(page.text, base)
        if len(all_js_urls) > max_assets:
            assets_truncated += len(all_js_urls) - max_assets
        js_urls = all_js_urls[:max_assets]
        for jsurl in js_urls:
            jr = await fetcher.get(jsurl)
            if jr.skipped_reason is not None or jr.status_code != 200:
                _bump_skip(jr.skipped_reason)
                assets_failed += 1
                continue
            assets_scanned += 1
            progress.detail(f"{domain} · asset {assets_scanned}")
            js_bodies.append(jr.content)
            js_urls_ok.append(jsurl)

            findings += secret_engine.scan(
                source_url=url, asset_url=jsurl, body=jr.content,
                discovery_method="js_bundle", coverage=_cov(),
            )
            findings += debug_engine.scan_body(
                source_url=url, asset_url=jsurl, body=jr.content,
                discovery_method="js_bundle", coverage=_cov(),
                headers=jr.headers, status_code=jr.status_code,
            )
            if recall_engine is not None:
                findings += await recall_engine.scan(
                    source_url=url, asset_url=jsurl, body=jr.content,
                    discovery_method="js_bundle", coverage=cov,
                )

            # sourcemaps
            for sm_url in extract_sourcemap_urls(jr.text, jsurl)[:5]:
                sr = await fetcher.get(sm_url)
                if sr.skipped_reason is not None or sr.status_code != 200:
                    _bump_skip(sr.skipped_reason)
                    continue
                if b'"version"' not in sr.content[:200] \
                        and b'"sources"' not in sr.content[:500]:
                    continue
                assets_scanned += 1
                sm_f = debug_engine.sourcemap_finding(
                    source_url=url, asset_url=sm_url, body=sr.content,
                    coverage=cov,
                )
                if sm_f:
                    findings.append(sm_f)
                findings += secret_engine.scan(
                    source_url=url, asset_url=sm_url, body=sr.content,
                    discovery_method="sourcemap", coverage=cov,
                )
                if recall_engine is not None:
                    findings += await recall_engine.scan(
                        source_url=url, asset_url=sm_url, body=sr.content,
                        discovery_method="sourcemap", coverage=cov,
                    )

            # follow relative imports referenced by the bundle
            for imp in extract_js_imports(jr.text, jsurl)[:10]:
                if imp not in visited:
                    queue.append(imp)

    # probes
    probe_findings = await debug_engine.scan_probes(
        source_url=base, base_url=base, fetcher=fetcher, coverage=_cov(),
    )
    findings += probe_findings

    # favicon for fingerprint
    fav = await fetcher.get(base.rstrip("/") + "/favicon.ico")
    if fav.skipped_reason is None and fav.status_code == 200 and fav.content:
        favicon_bytes = fav.content

    fingerprint = {
        "favicon": favicon_hash_from_bytes(favicon_bytes),
        "dom": dom_hash(first_html) if first_html else None,
        "inline_scripts": (inline_scripts_hash("\n".join(first_inline))
                           if first_inline else None),
        "js_bundles": js_bundle_hash(js_urls_ok, js_bodies) if js_urls_ok else None,
    }

    # Overwrite every finding's coverage with the FINAL crawl state.
    # Without this, findings carry stale snapshots from the moment of
    # discovery (e.g., "pages=1, assets=0" for a finding on the first page
    # of a 9-page scan). A defender reading the report wants "how thorough
    # was this scan?" — that's the final stats, not the mid-crawl stats.
    final_cov = _cov()
    for f in findings:
        f.coverage = final_cov

    return {
        "domain": domain,
        "findings": findings,
        "coverage": final_cov,
        "fingerprint": fingerprint,
    }
