"""Privacy mode selection + context preparation.

Local (Ollama): full context allowed. Nothing leaves the machine.
Remote (OpenRouter): double-redacted context unless explicitly opted in.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from enum import Enum

from .prompts import sanitize_context


class PrivacyMode(str, Enum):
    FULL_CONTEXT = "full_context"          # local backend, nothing leaves
    REDACTED = "redacted"                  # remote, double-redacted


# Broad pattern set — catches token-like strings in the context window.
# Deliberately aggressive: false-positive redactions are fine (they cost a
# bit of context, not safety); false-negatives leak to a remote server.
_REDACT_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{20,}"),
    re.compile(r"pk_(?:live|test)_[A-Za-z0-9]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{82,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"hf_[A-Za-z0-9]{34,}"),
    re.compile(r"r8_[A-Za-z0-9]{36,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{35,}"),
    re.compile(r"pcsk_[A-Za-z0-9_\-]{32,}"),
    re.compile(r"GOCSPX-[A-Za-z0-9_\-]{28,}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"),
    re.compile(r"SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}"),
    re.compile(r"pat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64,}"),
    re.compile(r"AC[0-9a-fA-F]{32}"),
    re.compile(r"(?:postgres|mysql|redis|mongodb)(?:ql)?(?:\+srv)?://[^\s\"']+"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
]


@dataclass
class PreparedContext:
    text: str
    truncated: bool
    injection_flagged: bool
    redacted_count: int


def _redact_all(text: str) -> tuple[str, int]:
    count = 0
    for pat in _REDACT_PATTERNS:
        text, n = pat.subn("[REDACTED]", text)
        count += n
    return text, count


def select_mode(backend: str, cfg: dict) -> PrivacyMode:
    ai = cfg.get("ai", {})
    if backend == "ollama":
        return PrivacyMode.FULL_CONTEXT
    if ai.get("send_raw_secrets_to_remote", False):
        return PrivacyMode.FULL_CONTEXT
    return PrivacyMode.REDACTED


def prepare_context(
    raw_context: str,
    mode: PrivacyMode,
    max_chars: int,
) -> PreparedContext:
    text, injection = sanitize_context(raw_context)
    redacted_count = 0
    if mode == PrivacyMode.REDACTED:
        text, redacted_count = _redact_all(text)
    truncated = False
    if len(text) > max_chars:
        text = text[:max_chars]
        truncated = True
    return PreparedContext(
        text=text,
        truncated=truncated,
        injection_flagged=injection,
        redacted_count=redacted_count,
    )
