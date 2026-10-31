"""HTML report must escape attacker-controlled content (XSS-safe)."""
from gandoki.models import ConfidenceTier, ImpactLevel
from gandoki.report.html_report import write_html


def _read(p):
    return open(p, encoding="utf-8").read()


def test_snippet_script_escaped(tmp_path, make_finding):
    f = make_finding(
        snippet='<script>alert(1)</script>sk-realkey12345678',
        context='<img src=x onerror=alert(1)>',
    )
    out = tmp_path / "out.html"
    write_html([f], str(out))
    body = _read(out)
    # The security guarantee: no raw XSS payload survives into the report.
    assert "<script>alert(1)</script>" not in body
    assert "<img src=x onerror=alert(1)>" not in body
    # Escaping happened somewhere (the redacted snippet/context pass through
    # html.escape). Redaction strips "<script>" to "<scr", so we can't assert
    # the literal &lt;script&gt; — but any escaped &lt; proves the boundary holds.
    assert "&lt;" in body
    # And we can confirm the redacted snippet is present in the rendered row.
    assert "***" in body


def test_url_escaped(tmp_path, make_finding):
    f = make_finding(asset_url='https://x/"><script>alert(1)</script>')
    out = tmp_path / "out.html"
    write_html([f], str(out))
    body = _read(out)
    assert "<script>alert(1)</script>" not in body


def test_retraction_reason_escaped(tmp_path, make_finding):
    from datetime import datetime, timezone
    from gandoki.models import Retraction, Section

    f = make_finding()
    f.section = Section.RETRACTED
    f.retraction = Retraction(
        reason='<script>alert("xss")</script>',
        decided_by="test",
        decided_at=datetime.now(timezone.utc),
        input_hash="deadbeef",
    )
    out = tmp_path / "out.html"
    write_html([f], str(out))
    body = _read(out)
    assert "<script>alert(\"xss\")</script>" not in body
    assert "&lt;script&gt;" in body


def test_retracted_section_shown(tmp_path, make_finding):
    from datetime import datetime, timezone
    from gandoki.models import Retraction, Section

    f = make_finding()
    f.section = Section.RETRACTED
    f.retraction = Retraction(
        reason="false positive in docs",
        decided_by="test",
        decided_at=datetime.now(timezone.utc),
        input_hash="deadbeef",
    )
    out = tmp_path / "out.html"
    write_html([f], str(out))
    body = _read(out)
    assert "Retracted by AI adjudicator" in body
    assert "false positive in docs" in body
