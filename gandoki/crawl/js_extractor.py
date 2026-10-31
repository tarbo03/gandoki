"""Extract JS bundle URLs, inline scripts, and sourcemap references."""
from __future__ import annotations
import re
from urllib.parse import urljoin


_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_INLINE_SCRIPT_RE = re.compile(r"<script(?:\s[^>]*)?>(.*?)</script>", re.S | re.I)
_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
_IMPORT_FROM_RE = re.compile(r'(?:import|from)\s*["\']([^"\']+\.js)["\']')
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)


def extract_js_urls(html: str, base_url: str) -> list[str]:
    urls: list[str] = []
    for m in _SCRIPT_SRC_RE.finditer(html):
        src = m.group(1).strip()
        if not src:
            continue
        # Accept: absolute, root-relative, .js endings, and .js?query URLs
        if (src.startswith(("http://", "https://", "//", "/"))
                or src.endswith(".js")
                or ".js?" in src):
            urls.append(urljoin(base_url, src))
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def extract_inline_scripts(html: str) -> list[str]:
    return [m.group(1) for m in _INLINE_SCRIPT_RE.finditer(html)]


def extract_sourcemap_urls(js_text: str, js_url: str) -> list[str]:
    return [urljoin(js_url, m.group(1).strip())
            for m in _SOURCEMAP_RE.finditer(js_text)]


def extract_js_imports(js_text: str, js_url: str) -> list[str]:
    """Extract relative .js imports referenced from a bundle."""
    out = []
    for m in _IMPORT_FROM_RE.finditer(js_text):
        path = m.group(1).strip()
        if path:
            out.append(urljoin(js_url, path))
    return out


def extract_internal_links(html: str, base_url: str, host: str) -> list[str]:
    from urllib.parse import urlparse
    out = []
    for m in _HREF_RE.finditer(html):
        absu = urljoin(base_url, m.group(1).strip())
        if urlparse(absu).netloc == host:
            out.append(absu)
    return out
