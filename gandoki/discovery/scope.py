"""Authorized-scope loader. Only these domains are scanned in authorized mode."""
from __future__ import annotations
from pathlib import Path
import yaml


def load_scope(path: str | Path) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    domains = data.get("domains", [])
    return [str(d).strip() for d in domains if str(d).strip()]
