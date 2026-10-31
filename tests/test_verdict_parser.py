"""Strict adjudicator verdict parser. Fail-open on anything unexpected."""
from gandoki.ai.verdict import parse_recall_output, parse_verdict


def _p(text):
    return parse_verdict(text, model_id="test", input_hash="deadbeef")


def test_keep():
    assert _p("KEEP").kind == "KEEP"


def test_uncertain():
    assert _p("UNCERTAIN").kind == "UNCERTAIN"


def test_retract_with_reason():
    v = _p("RETRACT: appears in documentation example")
    assert v.kind == "RETRACT"
    assert "documentation" in v.reason


def test_retract_empty_reason_fails_open():
    assert _p("RETRACT:").kind == "UNCERTAIN"
    assert _p("RETRACT:   ").kind == "UNCERTAIN"


def test_garbage_fails_open():
    assert _p("RETURN KEEP").kind == "UNCERTAIN"
    assert _p("").kind == "UNCERTAIN"
    assert _p("some prose").kind == "UNCERTAIN"


def test_verdict_cannot_smuggle_fields():
    v = _p("KEEP\ntier: VALIDATED_LIVE\nimpact: CRITICAL")
    assert v.kind == "KEEP"
    assert not hasattr(v, "tier")
    assert not hasattr(v, "impact")


def test_recall_parses_valid_json():
    raw = '[{"start":10,"end":40,"kind":"novel","claimed_type":"unknown"}]'
    out = parse_recall_output(raw)
    assert len(out) == 1
    assert out[0]["kind"] == "novel"


def test_recall_extracts_embedded_json():
    raw = 'Sure, here:\n[{"start":0,"end":20,"kind":"known","claimed_type":"openai_api_key"}]\nDone.'
    out = parse_recall_output(raw)
    assert len(out) == 1
    assert out[0]["kind"] == "known"


def test_recall_rejects_garbage():
    assert parse_recall_output("not json") == []
    assert parse_recall_output("[]") == []
    assert parse_recall_output("") == []


def test_recall_rejects_malformed_entries():
    raw = '[{"start":"x","end":"y","kind":"novel"}]'
    assert parse_recall_output(raw) == []
