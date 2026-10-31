"""Privacy mode: local=full context, remote=double-redacted."""
from gandoki.ai.privacy import (
    PrivacyMode, prepare_context, select_mode,
)


def test_remote_redacts_secrets():
    ctx = "const k = 'sk-realkey1234567890abcdefGHIJ'; const s = 'sk_live_" + "a" * 30 + "'"
    out = prepare_context(ctx, PrivacyMode.REDACTED, 2000)
    assert "sk-realkey1234567890abcdefGHIJ" not in out.text
    assert "sk_live_" not in out.text
    assert out.redacted_count >= 2


def test_local_preserves_context():
    ctx = "const k = 'sk-realkey1234567890abcdefGHIJ'"
    out = prepare_context(ctx, PrivacyMode.FULL_CONTEXT, 2000)
    assert "sk-realkey1234567890abcdefGHIJ" in out.text
    assert out.redacted_count == 0


def test_truncation_flagged():
    ctx = "x" * 5000
    out = prepare_context(ctx, PrivacyMode.FULL_CONTEXT, max_chars=100)
    assert out.truncated is True
    assert len(out.text) == 100


def test_select_mode_ollama_is_full():
    assert select_mode("ollama", {"ai": {}}) == PrivacyMode.FULL_CONTEXT


def test_select_mode_openrouter_is_redacted_by_default():
    assert select_mode("openrouter", {"ai": {}}) == PrivacyMode.REDACTED


def test_select_mode_openrouter_opt_in_full():
    cfg = {"ai": {"send_raw_secrets_to_remote": True}}
    assert select_mode("openrouter", cfg) == PrivacyMode.FULL_CONTEXT
