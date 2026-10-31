"""Config loader — thin wrapper so every entrypoint reads YAML identically."""
from __future__ import annotations
from pathlib import Path
import yaml


def _resolve(path: str | Path) -> Path:
    p = Path(path)
    if p.exists():
        return p
    # fall back to repo-root config
    repo = Path(__file__).resolve().parent.parent / "config"
    candidate = repo / p.name
    if candidate.exists():
        return candidate
    raise FileNotFoundError(f"config not found: {path} (also tried {candidate})")


def load_config(path: str | Path) -> dict:
    with open(_resolve(path), "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_rules_config(path: str | Path) -> list[dict]:
    with open(_resolve(path), "r", encoding="utf-8") as f:
        return (yaml.safe_load(f) or {}).get("detectors", [])


def load_severity_caps(path: str | Path) -> list[dict]:
    with open(_resolve(path), "r", encoding="utf-8") as f:
        return (yaml.safe_load(f) or {}).get("caps", [])
