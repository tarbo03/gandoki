"""Two-axis scoring (impact × confidence)."""
from gandoki.models import ConfidenceTier, ImpactLevel
from gandoki.scoring.scorer import score


def test_validated_critical_is_p1(make_finding):
    f = make_finding(tier=ConfidenceTier.VALIDATED_LIVE, impact=ImpactLevel.CRITICAL)
    s = score(f)
    assert s["rank_label"].startswith("P1")
    assert s["review_priority"] == 16


def test_format_match_critical_is_p2(make_finding):
    f = make_finding(tier=ConfidenceTier.FORMAT_MATCH, impact=ImpactLevel.CRITICAL)
    assert score(f)["rank_label"].startswith("P2")


def test_confirmed_high_is_p1(make_finding):
    f = make_finding(tier=ConfidenceTier.CONFIRMED_PARTIAL, impact=ImpactLevel.HIGH)
    assert score(f)["rank_label"].startswith("P1")


def test_format_match_medium_is_p3(make_finding):
    f = make_finding(tier=ConfidenceTier.FORMAT_MATCH, impact=ImpactLevel.MEDIUM)
    assert score(f)["rank_label"].startswith("P3")


def test_suspected_low_is_p4(make_finding):
    f = make_finding(tier=ConfidenceTier.SUSPECTED, impact=ImpactLevel.LOW)
    assert score(f)["rank_label"].startswith("P4")
