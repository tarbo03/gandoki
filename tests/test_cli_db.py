"""CLI DB write path, prefix resolution, and diff."""
import pytest

from gandoki.storage import db


def _finding(fid: str, offset: int = 100):
    return {
        "finding_id": fid,
        "secret_type": "openai_api_key",
        "section": "ACCEPTED",
        "evidence": {"asset_url": "https://x.com/a.js", "byte_offset": offset},
        "tier": "FORMAT_MATCH",
        "impact": {"level": "HIGH"},
    }


def test_create_and_get_job(tmp_path):
    p = str(tmp_path / "t.db")
    db.create_job(p, "job_a", {"domains": ["x.com"]})
    job = db.get_job(p, "job_a")
    assert job is not None
    assert job["status"] == "pending"
    assert job["request"]["domains"] == ["x.com"]


def test_save_and_get_findings(tmp_path):
    p = str(tmp_path / "t.db")
    db.create_job(p, "job_a", {})
    db.save_findings(p, "job_a", [_finding("f1")])
    rows = db.get_findings(p, "job_a")
    assert len(rows) == 1
    assert rows[0]["finding_id"] == "f1"


def test_diff_persisting(tmp_path):
    p = str(tmp_path / "t.db")
    for jid in ("a", "b"):
        db.create_job(p, jid, {})
        db.update_job_status(p, jid, "done")
        db.save_findings(p, jid, [_finding("f1", offset=100)])
    result = db.diff_jobs(p, "a", "b")
    assert result["summary"]["persisting_count"] == 1
    assert result["summary"]["new_count"] == 0
    assert result["summary"]["fixed_count"] == 0


def test_diff_new_and_fixed(tmp_path):
    p = str(tmp_path / "t.db")
    db.create_job(p, "a", {})
    db.update_job_status(p, "a", "done")
    db.save_findings(p, "a", [_finding("f_old", offset=100)])

    db.create_job(p, "b", {})
    db.update_job_status(p, "b", "done")
    db.save_findings(p, "b", [_finding("f_new", offset=200)])

    result = db.diff_jobs(p, "a", "b")
    assert result["summary"]["new_count"] == 1
    assert result["summary"]["fixed_count"] == 1


def test_prefix_resolution(tmp_path):
    p = str(tmp_path / "t.db")
    full_id = "abcdef1234567890abcdef1234567890"
    db.create_job(p, full_id, {})
    assert db.resolve_job_id(p, "abcdef123456") == full_id
    assert db.resolve_job_id(p, full_id) == full_id
    assert db.resolve_job_id(p, "zzz") is None


def test_diff_accepts_prefixes(tmp_path):
    p = str(tmp_path / "t.db")
    a, b = "abcdef1234567890abcdef1234567890", "fedcba0987654321fedcba0987654321"
    db.create_job(p, a, {})
    db.update_job_status(p, a, "done")
    db.create_job(p, b, {})
    db.update_job_status(p, b, "done")
    result = db.diff_jobs(p, "abcdef12", "fedcba09")
    assert result["job_a"] == a
    assert result["job_b"] == b
