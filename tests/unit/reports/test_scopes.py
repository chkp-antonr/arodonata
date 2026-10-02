from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr, ValidationError

from arodonata.reports.changes import OwnedSession, RangeScope, SessionScope

SID = "SIDSENTINEL-0123456789abcdef"
T0 = datetime(2026, 9, 28, 15, 30, tzinfo=UTC)


def test_session_scope_requires_uids():
    with pytest.raises(ValidationError):
        SessionScope(domain="Domain4", session_uids=[])
    assert SessionScope(session_uids=["a", "b", "a"]).session_uids == ["a", "b"]


def test_range_scope_rejects_naive_datetime():
    with pytest.raises(ValidationError):
        RangeScope(domain="Domain4", from_date=datetime(2026, 9, 28, 15, 30))


def test_range_scope_requires_a_lower_bound():
    with pytest.raises(ValidationError, match="lower bound"):
        RangeScope(domain="Domain4")


def test_range_scope_to_session_only_rejected():
    with pytest.raises(ValidationError, match="use SessionScope for one session"):
        RangeScope(domain="Domain4", to_session="s1")


def test_range_scope_to_date_only_rejected():
    with pytest.raises(ValidationError, match="all history"):
        RangeScope(domain="Domain4", to_date=T0)


def test_range_scope_from_after_to_rejected():
    with pytest.raises(ValidationError, match="after to_date"):
        RangeScope(domain="Domain4", from_date=T0, to_date=T0 - timedelta(minutes=1))


def test_owned_session_repr_hides_sid():
    owned = OwnedSession(sid=SecretStr(SID), server_ip="192.0.2.1")
    scope = SessionScope(session_uids=["a"], owned_session=owned)
    for text in (repr(owned), str(owned), repr(scope), str(scope), owned.model_dump_json(), scope.model_dump_json()):
        assert SID not in text and SID[:8] not in text
    assert "192.0.2.1" in repr(owned)


def test_invalid_owned_session_error_hides_sid():
    with pytest.raises(ValidationError) as err:
        SessionScope(session_uids=["a"], owned_session={"sid": SID, "server_ip": 5, "extra": SID})
    assert SID not in str(err.value) and SID[:8] not in str(err.value)


def test_session_and_date_bounds_combined():
    scope = RangeScope(domain="Domain4", from_session="s1", from_date=T0, to_date=T0 + timedelta(hours=1))
    assert (scope.from_session, scope.from_date, scope.to_date) == ("s1", T0, T0 + timedelta(hours=1))
