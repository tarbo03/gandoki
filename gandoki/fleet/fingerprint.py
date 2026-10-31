"""Fingerprint primitives.

NOTE: the actual hashing functions used during crawl live in
gandoki.crawl.crawler (so the crawler is self-contained). This module
re-exports them for callers that want to import from fleet/ only.
"""
from __future__ import annotations

from ..crawl.crawler import (
    dom_hash,
    favicon_hash_from_bytes,
    inline_scripts_hash,
    js_bundle_hash,
)


def similarity(fp_a: dict, fp_b: dict) -> float:
    """Fraction of shared non-null signals that match between two fingerprints."""
    keys = [k for k in fp_a if k in fp_b and fp_a[k] and fp_b[k]]
    if not keys:
        return 0.0
    return sum(1 for k in keys if fp_a[k] == fp_b[k]) / len(keys)


__all__ = [
    "dom_hash", "favicon_hash_from_bytes", "inline_scripts_hash",
    "js_bundle_hash", "similarity",
]
