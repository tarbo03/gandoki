"""Enhanced debug-exposure detection engine with false-positive prevention.

FP prevention layers, applied in order:
  1. SPA fallback baseline — probe a random path first. If probes return the
     same body hash, the site is an SPA returning 200 for everything. All
     probe hits on that host downgrade to SUSPECTED.
  2. Content-type verification — probes only count if content-type matches
     the expected file type (.env → text/plain, /actuator/* → application/json,
     .DS_Store → application/octet-stream).
  3. Body-shape verification — probes verify the body actually looks like the
     expected file (env var lines, git refs, JSON with expected keys, Bud1
     magic bytes, sourcemap version 3).
  4. Context verification for signatures — tracebacks inside <pre>/<code>/
     <textarea>/markdown fences downgrade to SUSPECTED.
  5. Status verification for framework errors — Django/Flask/Rails/ASP.NET
     error pages need 4xx/5xx status (200 = probably a docs page).
  6. Guard detection for console.log — comments and NODE_ENV guards
     downgrade to SUSPECTED.
  7. Structured tracebacks — Python traces need 2+ File lines + exception;
     JS traces need 2+ `at` frames; Java traces need 2+ `at` lines.
  8. Header verification — framework leaks in Server / X-* headers are
     matched against known dev-server patterns.
"""
from __future__ import annotations
import hashlib
import json
import re
import secrets
from typing import Optional

from ..models import (
    ConfidenceTier, CoverageContext, Evidence, Finding, FindingCategory,
    Impact, ImpactLevel, Provenance,
)
from .secrets import Rule


# ============================================================
# Verification primitives
# ============================================================

def _looks_like_html(s: str) -> bool:
    head = s[:200].lower().lstrip()
    return (head.startswith("<!doctype html") or head.startswith("<html")
            or "<html" in head)


def _looks_like_json(s: str) -> bool:
    t = s.strip()
    if not t or t[0] not in "{[":
        return False
    try:
        json.loads(t)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def _verify_env_file(text: str) -> bool:
    if _looks_like_html(text):
        return False
    lines = re.findall(r"^[A-Z_][A-Z0-9_]*=.*$", text, re.MULTILINE)
    return len(lines) >= 2


def _verify_git_head(text: str) -> bool:
    s = text.strip()
    if len(s) > 200 or _looks_like_html(text):
        return False
    if s.startswith("ref: refs/"):
        return True
    return bool(re.fullmatch(r"[0-9a-f]{40}", s))


def _verify_git_config(text: str) -> bool:
    if _looks_like_html(text):
        return False
    return "[core]" in text and (
        "repositoryformatversion" in text or "bare" in text
    )


def _verify_bud1_magic(content: bytes) -> bool:
    return content[:4] == b"Bud1"


def _verify_actuator_json(text: str, required_keys: list[str]) -> bool:
    if _looks_like_html(text):
        return False
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    return any(k in data for k in required_keys)


def _verify_sourcemap(text: str) -> bool:
    if _looks_like_html(text):
        return False
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    return data.get("version") == 3 and isinstance(data.get("sources"), list)


_THIRD_PARTY_LIBRARIES = [
    "swiper", "jquery", "bootstrap", "lodash", "moment", "react", "vue",
    "d3", "three", "chart", "slick", "owl", "magnific", "lightbox",
    "fontawesome", "font-awesome", "gsap", "axios", "popper", "select2",
    "summernote", "tinymce", "ckeditor", "quill", "codemirror", "prism",
    "highlight", "isotope", "mixitup", "aos", "animate", "scrollmagic",
    "anime", "velocity", "particles", "typed", "owl-carousel", "slick-carousel",
    "datatables", "fullcalendar", "chartjs", "chart.js", "echarts", "plotly",
    "leaflet", "mapbox", "hammer", "dragula", "sortable", "cropper",
]


def _is_third_party_sourcemap(text: str, path: str) -> tuple[bool, str]:
    """Detect if a source map is for a public library, not site code.

    Returns (is_third_party, library_name).
    Checks:
      1. sourcemap `sources` field contains node_modules/<lib>/
      2. the URL path contains a known library name
    """
    # Best signal: node_modules path in the sources array
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    else:
        if isinstance(data, dict):
            sources = data.get("sources", [])
            if isinstance(sources, list):
                for src in sources:
                    if isinstance(src, str) and "node_modules/" in src:
                        m = re.search(r"node_modules/([^/]+)", src)
                        if m:
                            return True, m.group(1)

    # Fallback: library name in the URL path
    # Fallback: require the library name as a path segment, not a substring.
    # Prevents "my-d3-chart.js" from matching "d3". Slash-bounded or
    # slash-then-filename-bounded only.
    path_lower = path.lower()
    for lib in _THIRD_PARTY_LIBRARIES:
        if (f"/{lib}/" in path_lower
                or f"/{lib}.min.js" in path_lower
                or f"/{lib}.js" in path_lower):
            return True, lib
    return False, ""


def _verify_phpinfo(text: str) -> bool:
    return _looks_like_html(text) and "PHP Version" in text and "phpinfo" in text.lower()


def _verify_wp_config(text: str) -> bool:
    return "DB_PASSWORD" in text and "DB_NAME" in text


def _verify_laravel_log(text: str) -> bool:
    return bool(re.search(r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]",
                          text, re.MULTILINE))


def _verify_probe_body(validate: Optional[str], content: bytes, text: str) -> bool:
    if not validate:
        return True
    if validate.startswith("content_contains="):
        return validate.split("=", 1)[1] in text
    handlers = {
        "env_var_lines": lambda: _verify_env_file(text),
        "git_head": lambda: _verify_git_head(text),
        "git_config": lambda: _verify_git_config(text),
        "bud1_magic": lambda: _verify_bud1_magic(content),
        "phpinfo": lambda: _verify_phpinfo(text),
        "wp_config": lambda: _verify_wp_config(text),
        "laravel_log": lambda: _verify_laravel_log(text),
        "sourcemap": lambda: _verify_sourcemap(text),
        "json_or_text": lambda: text.strip() != "",
    }
    if validate.startswith("actuator_json="):
        keys = validate.split("=", 1)[1].split(",")
        return _verify_actuator_json(text, keys)
    fn = handlers.get(validate)
    return fn() if fn else True


def _verify_content_type(headers: dict, expected: Optional[str]) -> bool:
    if not expected:
        return True
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v.lower().split(";", 1)[0].strip()
            break
    if expected == "text_or_octet":
        return ct in ("text/plain", "application/octet-stream", "") or (
            "text" in ct and "html" not in ct
        )
    if expected == "json":
        return "json" in ct
    if expected == "octet":
        return ct in ("application/octet-stream", "")
    if expected == "html":
        return "html" in ct
    return True


def _is_inside_pre_block(body: str, offset: int, window: int = 500) -> bool:
    start = max(0, offset - window)
    prefix = body[start:offset].lower()
    opens = prefix.count("<pre") + prefix.count("<code") + prefix.count("<textarea")
    closes = prefix.count("</pre") + prefix.count("</code") + prefix.count("</textarea")
    return opens > closes


def _is_inside_markdown_fence(body: str, offset: int, window: int = 2000) -> bool:
    start = max(0, offset - window)
    prefix = body[start:offset]
    return prefix.count("```") % 2 == 1


def _is_inside_js_comment(body: str, offset: int) -> bool:
    line_start = body.rfind("\n", 0, offset) + 1
    if "//" in body[line_start:offset]:
        return True
    start = max(0, offset - 1000)
    prefix = body[start:offset]
    return prefix.count("/*") > prefix.count("*/")


def _is_guarded_console_log(body: str, offset: int) -> bool:
    """Detect if a console.log sits inside a NODE_ENV guard or DEBUG block."""
    window = body[max(0, offset - 600):offset + 100]
    guards = [
        r"if\s*\(\s*process\.env\.NODE_ENV\s*!==?\s*['\"]production['\"]",
        r"if\s*\(\s*process\.env\.NODE_ENV\s*===?\s*['\"]development['\"]",
        r"if\s*\(\s*DEBUG\s*",
        r"if\s*\(\s*window\.__DEV__\s*",
        r"if\s*\(\s*import\.meta\.env\.DEV\s*",
    ]
    return any(re.search(p, window) for p in guards)


# ============================================================
# Framework fingerprinting (for tier promotion context)
# ============================================================

_FRAMEWORK_MARKERS = {
    "django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
    "flask": [r"werkzeug"],
    "rails": [r"csrf-token", r"data-turbo"],
    "laravel": [r"laravel_session", r"csrf-token"],
    "aspnet": [r"__viewstate", r"__eventvalidation"],
    "spring": [r"whitelabel error page"],
    "nextjs": [r"__next_data__", r"/_next/"],
    "nuxt": [r"/_nuxt/"],
}


def _fingerprint_framework(headers: dict, body: str) -> list[str]:
    hints: list[str] = []
    h = {k.lower(): v for k, v in headers.items()}
    server = h.get("server", "").lower()
    if "werkzeug" in server:
        hints.append("flask")
    if "x-powered-by" in h:
        pb = h["x-powered-by"].lower()
        for tech in ("express", "php", "asp.net"):
            if tech in pb:
                hints.append(tech.replace(".", ""))
    head = body[:5000].lower()
    for fw, patterns in _FRAMEWORK_MARKERS.items():
        if any(re.search(p, head) for p in patterns):
            hints.append(fw)
    return list(set(hints))


# ============================================================
# Engine
# ============================================================

class DebugEngine:
    def __init__(self, rules: list[Rule]):
        self.signature_rules = [
            (r, re.compile(r.pattern)) for r in rules
            if r.category == "debug_exposure" and r.type == "signature"
        ]
        self.text_rules = [
            (r, re.compile(r.pattern)) for r in rules
            if r.category == "debug_exposure"
            and r.type not in ("signature", "probe", "sourcemap", "header")
        ]
        self.probe_rules = [
            r for r in rules
            if r.category == "debug_exposure" and r.type == "probe"
        ]
        self.header_rules = [
            r for r in rules
            if r.category == "debug_exposure" and r.type == "header"
        ]
        self.sourcemap_rule = next(
            (r for r in rules
             if r.category == "debug_exposure" and r.type == "sourcemap"),
            None,
        )

    # ---- body scan (signature + text + env-leak rules) ----

    def scan_body(
        self,
        *,
        source_url: str,
        asset_url: str,
        body: bytes,
        discovery_method: str,
        coverage: CoverageContext,
        headers: dict | None = None,
        status_code: int | None = None,
    ) -> list[Finding]:
        text = body.decode("utf-8", errors="replace")
        digest = hashlib.sha256(body).hexdigest()
        out: list[Finding] = []

        for rule, rgx in self.signature_rules:
            for m in rgx.finditer(text):
                tier = self._signature_tier(rule, m, text, status_code)
                if tier is None:
                    continue
                out.append(self._build(
                    rule, source_url, asset_url, digest, len(body),
                    m.start(), m.group(0), text, discovery_method, tier, coverage,
                ))

        for rule, rgx in self.text_rules:
            for m in rgx.finditer(text):
                tier = self._text_tier(rule, m, text)
                if tier is None:
                    continue
                out.append(self._build(
                    rule, source_url, asset_url, digest, len(body),
                    m.start(), m.group(0), text, discovery_method, tier, coverage,
                ))

        return out

    def scan_headers(
        self,
        *,
        source_url: str,
        asset_url: str,
        headers: dict,
        coverage: CoverageContext,
        body: bytes = b"",
    ) -> list[Finding]:
        """Header rules (Server, X-Powered-By, X-Debug-Token, etc.)."""
        if not headers or not self.header_rules:
            return []
        out: list[Finding] = []
        h_lower = {k.lower(): v for k, v in headers.items()}
        digest = hashlib.sha256(body).hexdigest()
        for rule in self.header_rules:
            header_name = (getattr(rule, "header_name", "") or "").lower()
            header_value_pat = getattr(rule, "header_value_pattern", "") or ""
            if not header_name:
                continue
            value = h_lower.get(header_name, "")
            if not value:
                continue
            if header_value_pat and not re.search(header_value_pat, value, re.IGNORECASE):
                continue
            out.append(self._build(
                rule, source_url, asset_url, digest, len(body), 0,
                f"{header_name}: {value}", body.decode("utf-8", errors="replace")[:200],
                "header", ConfidenceTier.FORMAT_MATCH, coverage,
            ))
        return out

    def _signature_tier(
        self,
        rule: Rule,
        m: "re.Match",
        text: str,
        status_code: int | None,
    ) -> ConfidenceTier | None:
        # Context check: docs/example fences → SUSPECTED
        if _is_inside_pre_block(text, m.start()) or _is_inside_markdown_fence(text, m.start()):
            return ConfidenceTier.SUSPECTED
        # Status check: framework error pages MUST be 4xx/5xx when status known
        if getattr(rule, "require_error_status", False) and status_code is not None:
            if 200 <= status_code < 400:
                return ConfidenceTier.SUSPECTED
        return ConfidenceTier.FORMAT_MATCH

    def _text_tier(
        self,
        rule: Rule,
        m: "re.Match",
        text: str,
    ) -> ConfidenceTier | None:
        # Docs context → SUSPECTED
        if _is_inside_pre_block(text, m.start()) or _is_inside_markdown_fence(text, m.start()):
            return ConfidenceTier.SUSPECTED
        # Structured traceback requirement
        if rule.id == "verbose_python_trace":
            # must have 2+ File lines and an exception line in a 2000-char window
            window = text[max(0, m.start() - 200):m.end() + 2000]
            file_count = len(re.findall(r'File\s+"[^"]+",\s+line\s+\d+', window))
            exc_count = len(re.findall(
                r"^\w+(?:Error|Exception|Warning):\s", window, re.MULTILINE
            ))
            if file_count < 2 or exc_count < 1:
                return ConfidenceTier.SUSPECTED
        if rule.id == "verbose_js_trace":
            window = text[max(0, m.start() - 200):m.end() + 2000]
            at_count = len(re.findall(r"at\s+\w+\s+\(", window))
            if at_count < 2:
                return ConfidenceTier.SUSPECTED
        if rule.id == "verbose_java_trace":
            window = text[max(0, m.start() - 200):m.end() + 2000]
            at_count = len(re.findall(r"^\s+at\s+[\w.$]+\(", window, re.MULTILINE))
            if at_count < 2:
                return ConfidenceTier.SUSPECTED
        # console.log guard/comment detection
        if rule.id == "console_log_sensitive":
            if _is_inside_js_comment(text, m.start()):
                return ConfidenceTier.SUSPECTED
            if _is_guarded_console_log(text, m.start()):
                return ConfidenceTier.SUSPECTED
        return ConfidenceTier.FORMAT_MATCH

    # ---- probes ----

    async def scan_probes(
        self,
        *,
        source_url: str,
        base_url: str,
        fetcher,
        coverage: CoverageContext,
    ) -> list[Finding]:
        out: list[Finding] = []
        if not self.probe_rules:
            return out

        # SPA fallback baseline — probe a random nonexistent path first
        spa_baseline = await self._fetch_spa_baseline(fetcher, base_url)

        for rule in self.probe_rules:
            urls = getattr(rule, "probe_urls", None) or []
            expected_ct = getattr(rule, "expected_content_type", None)
            for path in urls:
                url = base_url.rstrip("/") + path
                resp = await fetcher.get(url)
                if resp is None or resp.skipped_reason is not None:
                    continue
                if resp.status_code != 200:
                    continue

                # 1. SPA fallback?
                if self._is_spa_fallback(resp, spa_baseline):
                    continue

                # 2. Content-type verification
                if not _verify_content_type(resp.headers, expected_ct):
                    out.append(self._build(
                        rule, source_url, url, resp.sha256, len(resp.content),
                        0, path, resp.text[:200], "probe",
                        ConfidenceTier.SUSPECTED, coverage,
                        cap_reason=f"content-type mismatch (got {resp.headers.get('content-type','?')})",
                    ))
                    continue

                # 3. Body-shape verification
                if not _verify_probe_body(rule.validate, resp.content, resp.text):
                    out.append(self._build(
                        rule, source_url, url, resp.sha256, len(resp.content),
                        0, path, resp.text[:200], "probe",
                        ConfidenceTier.SUSPECTED, coverage,
                        cap_reason="body-shape verification failed",
                    ))
                    continue

                # 4. Success — CONFIRMED_PARTIAL
                out.append(self._build(
                    rule, source_url, url, resp.sha256, len(resp.content),
                    0, path, resp.text[:200], "probe",
                    ConfidenceTier.CONFIRMED_PARTIAL, coverage,
                ))
        return out

    async def _fetch_spa_baseline(self, fetcher, base_url: str) -> dict | None:
        random_path = "/.sh-" + secrets.token_hex(8)
        resp = await fetcher.get(base_url.rstrip("/") + random_path,
                                 respect_robots=False)
        if resp is None or resp.status_code != 200:
            return None
        ct = ""
        for k, v in resp.headers.items():
            if k.lower() == "content-type":
                ct = v.lower().split(";", 1)[0].strip()
                break
        return {
            "sha256": resp.sha256,
            "length": len(resp.content),
            "content_type": ct,
        }

    def _is_spa_fallback(self, resp, baseline: dict | None) -> bool:
        if baseline is None:
            return False
        if resp.sha256 == baseline["sha256"]:
            return True
        resp_ct = ""
        for k, v in resp.headers.items():
            if k.lower() == "content-type":
                resp_ct = v.lower().split(";", 1)[0].strip()
                break
        if ("html" in resp_ct and "html" in baseline["content_type"]
                and abs(len(resp.content) - baseline["length"]) < 200):
            return True
        return False

    # ---- sourcemap ----

    def sourcemap_finding(
        self,
        *,
        source_url: str,
        asset_url: str,
        body: bytes,
        coverage: CoverageContext,
    ) -> Finding | None:
        if not self.sourcemap_rule:
            return None
        text = body.decode("utf-8", errors="replace")
        if not _verify_sourcemap(text):
            return None

        is_third_party, library = _is_third_party_sourcemap(text, asset_url)

        if is_third_party:
            finding = self._build(
                self.sourcemap_rule, source_url, asset_url,
                hashlib.sha256(body).hexdigest(), len(body),
                0, asset_url, "", "sourcemap",
                ConfidenceTier.CONFIRMED_PARTIAL, coverage,
                cap_reason=(
                    f"third-party library source map ({library}) — "
                    f"source is publicly available on npm/unpkg; "
                    f"low actionability"
                ),
            )
            # Downgrade impact — real exposure, but not actionable
            finding.impact.level = ImpactLevel.LOW
            finding.impact.caveat = (
                f"EXPOSED but LOW IMPACT: this is a {library} library source map. "
                f"The source is already public on npm/unpkg — anyone can download "
                f"it without visiting this site. No secrets are exposed by this "
                f"file's presence. Manual review recommended only if you want to "
                f"reduce the served asset list."
            )
            return finding

        return self._build(
            self.sourcemap_rule, source_url, asset_url,
            hashlib.sha256(body).hexdigest(), len(body),
            0, asset_url, "", "sourcemap",
            ConfidenceTier.CONFIRMED_PARTIAL, coverage,
        )

    # ---- builder ----

    def _build(
        self,
        rule: Rule,
        source_url: str,
        asset_url: str,
        digest: str,
        size: int,
        offset: int,
        matched: str,
        ctx: str,
        method: str,
        tier: ConfidenceTier,
        coverage: CoverageContext,
        cap_reason: str | None = None,
    ) -> Finding:
        caveat = "Signature/response validated only. Manual confirmation recommended before disclosure."
        if cap_reason:
            caveat += f" CAPPED: {cap_reason}."
        return Finding(
            category=FindingCategory.DEBUG_EXPOSURE,
            secret_type=rule.id,
            tier=tier,
            evidence=Evidence(
                source_url=source_url, asset_url=asset_url,
                asset_sha256=digest, asset_size=size, byte_offset=offset,
                matched_pattern=rule.pattern or "",
                matched_snippet=matched,
                context_snippet=ctx[:200],
                discovery_method=method,
                provenance=Provenance.REGEX,
            ),
            impact=Impact(
                level=ImpactLevel[rule.impact],
                basis=f"Debug detector '{rule.id}' matched",
                if_valid_capability=(
                    rule.capability or "Debug exposure — verify impact manually"
                ),
                caveat=caveat,
                cap_reason=cap_reason,
            ),
            coverage=coverage,
            remediation=(
                "Disable debug mode in production; ensure DEBUG=false; "
                "remove probe targets from the public path; "
                "verify .env / .git / actuator endpoints return 404 or 403."
            ),
        )
