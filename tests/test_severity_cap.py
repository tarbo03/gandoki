"""L5 severity-cap table. Caps only ever move impact DOWN."""
import time

import pytest

from gandoki.config import load_severity_caps
from gandoki.detect.severity_cap import SeverityCap
from gandoki.models import ImpactLevel


def _cap():
    return SeverityCap(load_severity_caps("config/severity_caps.yaml"))


def test_stripe_test_key_capped(make_finding):
    f = make_finding(
        secret_type="stripe_secret_key",
        impact=ImpactLevel.CRITICAL,
        snippet="sk_test_" + "a" * 30,
    )
    _cap().apply(f)
    assert f.impact.level == ImpactLevel.MEDIUM
    assert f.impact.cap_reason is not None
    assert "CAPPED" in f.impact.caveat


def test_stripe_live_key_not_capped(make_finding):
    f = make_finding(
        secret_type="stripe_secret_key",
        impact=ImpactLevel.CRITICAL,
        snippet="sk_live_" + "a" * 30,
    )
    _cap().apply(f)
    assert f.impact.level == ImpactLevel.CRITICAL


def test_aws_asia_capped(make_finding):
    f = make_finding(
        secret_type="aws_access_key_id",
        impact=ImpactLevel.HIGH,
        snippet="ASIA" + "A" * 16,
    )
    _cap().apply(f)
    assert f.impact.level == ImpactLevel.MEDIUM


def test_aws_akia_not_capped(make_finding):
    f = make_finding(
        secret_type="aws_access_key_id",
        impact=ImpactLevel.HIGH,
        snippet="AKIA" + "A" * 16,
    )
    _cap().apply(f)
    assert f.impact.level == ImpactLevel.HIGH


def test_firebase_without_config_capped(make_finding):
    f = make_finding(
        secret_type="firebase_api_key",
        impact=ImpactLevel.MEDIUM,
        snippet="AAAA" + "A" * 7 + ":" + "A" * 140,
        context="just a bare key, no config block",
    )
    _cap().apply(f)
    assert f.impact.level == ImpactLevel.LOW


def test_expired_jwt_capped(make_finding):
    import base64, json
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) - 3600}).encode()
    ).rstrip(b"=").decode()
    token = f"eyJhbGciOiJIUzI1NiJ9.{payload}.sig"
    f = make_finding(
        secret_type="jwt_generic",
        impact=ImpactLevel.MEDIUM,
        snippet=token,
    )
    _cap().apply(f)
    assert f.impact.level == ImpactLevel.LOW


def test_cap_never_moves_up(make_finding):
    """Even if a stale cap rule somehow says cap_to=CRITICAL, we never move up."""
    caps = [{
        "detector": "openai_api_key",
        "when": {"prefix_match": "sk-"},
        "cap_to": "CRITICAL",
        "reason": "should never apply (upward)",
    }]
    sc = SeverityCap(caps)
    f = make_finding(impact=ImpactLevel.MEDIUM)
    sc.apply(f)
    assert f.impact.level == ImpactLevel.MEDIUM  # unchanged
