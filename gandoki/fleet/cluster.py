"""Connected-components clustering across per-domain fingerprints.

Two domains are linked when at least `threshold` of their shared non-null
signals match. The orchestrator annotates each finding with cluster_id, so a
finding on one domain of a fleet is visibly grouped with the whole fleet.
"""
from __future__ import annotations
from collections import defaultdict

from .fingerprint import similarity


def cluster_domains(
    fingerprints: dict[str, dict],
    threshold: float = 0.6,
) -> dict[str, str]:
    domains = list(fingerprints)
    adj: dict[str, set[str]] = defaultdict(set)

    for i, a in enumerate(domains):
        for b in domains[i + 1:]:
            if similarity(fingerprints[a], fingerprints[b]) >= threshold:
                adj[a].add(b)
                adj[b].add(a)

    seen: set[str] = set()
    cluster_of: dict[str, str] = {}
    idx = 0
    for d in domains:
        if d in seen:
            continue
        cid = f"fleet_{idx:04d}"
        idx += 1
        stack = [d]
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            cluster_of[n] = cid
            stack.extend(adj[n])
    return cluster_of
