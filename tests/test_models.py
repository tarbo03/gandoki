"""Honesty contract enforcement."""
import pytest

from gandoki.models import (
    ConfidenceTier, ImpactLevel, Section, ValidationResult, ValidationStatus,
)


def test_known_public_never_exported(make_finding):
    f = make_finding(tier=ConfidenceTier.KNOWN_PUBLIC)
    with pytest.raises(RuntimeError, match="KNOWN_PUBLIC"):
        f.to_public_dict()


def test_caveat_required(make_finding):
    f = make_finding(caveat="")
    with pytest.raises(RuntimeError, match="caveat"):
        f.to_public_dict()


def test_confirmed_requires_timestamp(make_finding):
    f = make_finding()
    f.validation = ValidationResult(status=ValidationStatus.CONFIRMED)
    with pytest.raises(RuntimeError, match="CONFIRMED requires"):
        f.to_public_dict()


def test_retracted_requires_record(make_finding):
    f = make_finding()
    f.section = Section.RETRACTED
    with pytest.raises(RuntimeError, match="RETRACTED"):
        f.to_public_dict()


def test_redaction(make_finding):
    f = make_finding(snippet="sk-abcdefgh12345678")
    d = f.to_public_dict()
    assert d["evidence"]["matched_snippet"] != "sk-abcdefgh12345678"
    assert "*" in d["evidence"]["matched_snippet"]
    assert d["evidence"]["provenance"] == "regex"


def test_short_snippet_fully_redacted(make_finding):
    f = make_finding(snippet="abc")
    d = f.to_public_dict()
    assert d["evidence"]["matched_snippet"] == "***"
