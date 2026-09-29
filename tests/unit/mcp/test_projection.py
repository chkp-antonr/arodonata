from __future__ import annotations

from datetime import UTC, datetime, timedelta

from arodonata.mcp.projection import cache_age_seconds, project

RAW = {
    "uid": "u",
    "name": "web1",
    "type": "host",
    "domain": {"name": "General", "uid": "d"},
    "ipv4-address": "10.0.0.1",
    "color": "black",
    "comments": "c",
    "tags": [],
    "groups": [],
    "meta-info": {"creator": "admin"},
    "read-only": False,
    "nat-settings": {"auto-rule": False},
}


def test_uid_level():
    assert project(RAW, "uid") == {"uid": "u", "name": "web1", "type": "host"}


def test_standard_level_keeps_identity_and_type_specific_fields_drops_meta():
    out = project(RAW, "standard")
    assert out["ipv4-address"] == "10.0.0.1" and out["domain"] == RAW["domain"] and out["color"] == "black"
    assert "meta-info" not in out and "read-only" not in out and "nat-settings" not in out


def test_full_level_is_identity():
    assert project(RAW, "full") == RAW and project(RAW, "full") is not RAW


def test_missing_raw_returns_empty():
    assert project({}, "standard") == {}


def test_cache_age_seconds():
    now = datetime(2026, 9, 27, 12, 0, 0)
    assert cache_age_seconds(now - timedelta(seconds=90), now=now) == 90
    assert cache_age_seconds(None) is None
    aware = datetime(2026, 9, 27, 11, 59, 0, tzinfo=UTC)
    assert cache_age_seconds(aware, now=datetime(2026, 9, 27, 12, 0, 0, tzinfo=UTC)) == 60
