"""Unit tests for SessionCleaner: session classification, discard flow, and edge cases."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

from arodonata.asdk.session_cleaner import CleanupResult, SessionCleaner


def _cm_result(value=None):
    """Build a MagicMock usable as `async with mock_rate_limiter.acquire(ip):`."""
    limiter = MagicMock()
    limiter.acquire.return_value.__aenter__ = AsyncMock(return_value=value)
    limiter.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
    return limiter


def _make_cleaner(transport=None, rate_limiter=None, registry=None):
    return SessionCleaner(
        transport or AsyncMock(),
        rate_limiter or _cm_result(),
        registry or MagicMock(),
    )


# --------------------------------------------------------------------------
# is_max_sessions_error
# --------------------------------------------------------------------------


def test_is_max_sessions_error_detects_cp_message():
    assert SessionCleaner.is_max_sessions_error(
        "Runtime error: You have reached the maximum number of active sessions."
        " Ask another administrator to discard or publish some of your sessions."
    )


def test_is_max_sessions_error_false_for_unrelated_message():
    assert not SessionCleaner.is_max_sessions_error("Authentication failed: wrong password")


def test_is_max_sessions_error_false_for_empty_string():
    assert not SessionCleaner.is_max_sessions_error("")


# --------------------------------------------------------------------------
# _extract_posix_millis - timestamp extraction from CP session field dicts
# --------------------------------------------------------------------------


def test_extract_posix_millis_from_posix_millis_key():
    session = {"creation-time": {"posix-millis": 1700000000000}}
    assert SessionCleaner._extract_posix_millis(session, "creation-time") == 1700000000000


def test_extract_posix_millis_converts_posix_seconds():
    session = {"creation-time": {"posix": 1700000000}}
    assert SessionCleaner._extract_posix_millis(session, "creation-time") == 1700000000000


def test_extract_posix_millis_treats_large_posix_value_as_already_ms():
    session = {"creation-time": {"posix": 1700000000000}}
    assert SessionCleaner._extract_posix_millis(session, "creation-time") == 1700000000000


def test_extract_posix_millis_missing_key_returns_zero():
    assert SessionCleaner._extract_posix_millis({}, "creation-time") == 0


def test_extract_posix_millis_non_dict_value_returns_zero():
    assert SessionCleaner._extract_posix_millis({"creation-time": "not-a-dict"}, "creation-time") == 0


def test_extract_posix_millis_empty_dict_returns_zero():
    assert SessionCleaner._extract_posix_millis({"creation-time": {}}, "creation-time") == 0


# --------------------------------------------------------------------------
# Which sessions get cleaned vs left alone (_get_session_decision / cleanup flow)
# --------------------------------------------------------------------------


async def test_cleanup_discards_disconnected_stale_zero_change_session():
    """Disconnected API session, 0 changes, older than 60 min -> discarded."""
    old_posix = int((datetime.now(UTC) - timedelta(hours=2)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-001",
            "application": "Management API",
            "connection-mode": "disconnected",
            "number-of-changes": 0,
            "tasks": [],
            "creation-time": {"posix-millis": old_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }
    mock_transport.discard_session.return_value = {"success": True, "data": {}, "message": "", "code": ""}

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 1
    assert result.skipped == 0
    mock_transport.discard_session.assert_called_once_with("10.0.0.1", "tmp-sid", "sess-001", None)


async def test_cleanup_skips_connected_sessions():
    """connection-mode='connected' sessions are never discarded regardless of age."""
    old_posix = int((datetime.now(UTC) - timedelta(days=10)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-002",
            "application": "Management API",
            "connection-mode": "connected",
            "in-work": True,
            "changes": 0,
            "last-login-time": {"posix-millis": old_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 0
    assert result.skipped == 1
    mock_transport.discard_session.assert_not_called()


async def test_cleanup_discards_stale_read_write_session_older_than_3_days():
    """Read-write / in-work session with 0 changes older than 3 days (4320 min) is discarded."""
    old_posix = int((datetime.now(UTC) - timedelta(days=5)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-rw-stale",
            "application": "Management API",
            "connection-mode": "read write",
            "in-work": True,
            "changes": 0,
            "last-login-time": {"posix-millis": old_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }
    mock_transport.discard_session.return_value = {"success": True, "data": {}, "message": "", "code": ""}

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 1
    mock_transport.discard_session.assert_called_once_with("10.0.0.1", "tmp-sid", "sess-rw-stale", None)


async def test_cleanup_skips_recent_read_write_session():
    """Read-write session with 0 changes younger than 3 days is kept."""
    recent_posix = int((datetime.now(UTC) - timedelta(hours=12)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-rw-recent",
            "application": "Management API",
            "connection-mode": "read write",
            "in-work": True,
            "changes": 0,
            "last-login-time": {"posix-millis": recent_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 0
    assert result.skipped == 1
    mock_transport.discard_session.assert_not_called()


async def test_cleanup_discards_stale_read_write_session_with_changes_older_than_7_days():
    """Read-write session with real pending changes older than 7 days (10080 min) is
    discarded too -- not just the changes==0 case. Before this, a read-write/in-work
    session with changes > 0 was NEVER discarded regardless of age, which let sessions
    accumulate real object locks indefinitely (observed at ~80 days old in practice)."""
    old_posix = int((datetime.now(UTC) - timedelta(days=10)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-rw-stale-changes",
            "application": "Management API",
            "connection-mode": "read write",
            "in-work": True,
            "changes": 12,
            "last-login-time": {"posix-millis": old_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }
    mock_transport.discard_session.return_value = {"success": True, "data": {}, "message": "", "code": ""}

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 1
    mock_transport.discard_session.assert_called_once_with("10.0.0.1", "tmp-sid", "sess-rw-stale-changes", None)


async def test_cleanup_skips_recent_read_write_session_with_changes():
    """Read-write session with pending changes younger than 7 days is kept -- real
    in-progress work gets more grace than an idle (changes==0) read-write session."""
    recent_posix = int((datetime.now(UTC) - timedelta(days=5)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-rw-recent-changes",
            "application": "Management API",
            "connection-mode": "read write",
            "in-work": True,
            "changes": 12,
            "last-login-time": {"posix-millis": recent_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 0
    assert result.skipped == 1
    mock_transport.discard_session.assert_not_called()


async def test_cleanup_discards_marked_test_session_older_than_10_min_with_changes():
    """A session named/described with the 'pytest' marker discards after just 10 min,
    even with real pending changes and read-write/in-work mode -- it doesn't have to
    wait out the 7-day real-work threshold since it's known to be disposable test data."""
    old_posix = int((datetime.now(UTC) - timedelta(minutes=30)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-test-marked",
            "application": "Management API",
            "connection-mode": "read write",
            "in-work": True,
            "changes": 5,
            "name": "pytest-integration-tests",
            "last-login-time": {"posix-millis": old_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }
    mock_transport.discard_session.return_value = {"success": True, "data": {}, "message": "", "code": ""}

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 1
    mock_transport.discard_session.assert_called_once_with("10.0.0.1", "tmp-sid", "sess-test-marked", None)


async def test_cleanup_skips_marked_test_session_younger_than_10_min():
    """A freshly-created test-marked session (still mid-test) is left alone."""
    recent_posix = int((datetime.now(UTC) - timedelta(minutes=2)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-test-fresh",
            "application": "Management API",
            "connection-mode": "read write",
            "in-work": True,
            "changes": 5,
            "description": "Automated pytest integration test session",
            "last-login-time": {"posix-millis": recent_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 0
    assert result.skipped == 1
    mock_transport.discard_session.assert_not_called()


async def test_cleanup_discards_web_api_session():
    """WEB_API sessions (HTTPS API) are treated the same as Management API sessions."""
    old_posix = int((datetime.now(UTC) - timedelta(hours=2)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-web-001",
            "application": "WEB_API",
            "connection-mode": "disconnected",
            "number-of-changes": 0,
            "tasks": [],
            "creation-time": {"posix-millis": old_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }
    mock_transport.discard_session.return_value = {"success": True, "data": {}, "message": "", "code": ""}

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 1
    mock_transport.discard_session.assert_called_once_with("10.0.0.1", "tmp-sid", "sess-web-001", None)


async def test_cleanup_skips_smartconsole_sessions():
    """SmartConsole GUI sessions (unknown application) are never touched regardless of age."""
    old_posix = int((datetime.now(UTC) - timedelta(hours=3)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-003",
            "application": "SmartConsole",
            "connection-mode": "disconnected",
            "number-of-changes": 0,
            "tasks": [],
            "creation-time": {"posix-millis": old_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 0
    assert result.skipped == 1
    mock_transport.discard_session.assert_not_called()


async def test_cleanup_skips_recent_disconnected_session():
    """Disconnected API session younger than 60 min is skipped even with 0 changes."""
    recent_posix = int((datetime.now(UTC) - timedelta(minutes=10)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-004",
            "application": "Management API",
            "connection-mode": "disconnected",
            "number-of-changes": 0,
            "tasks": [],
            "creation-time": {"posix-millis": recent_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 0
    assert result.skipped == 1
    mock_transport.discard_session.assert_not_called()


async def test_cleanup_discards_old_disconnected_session_with_changes_after_24h():
    """Disconnected API session with unpublished changes older than 24h is discarded."""
    old_posix = int((datetime.now(UTC) - timedelta(hours=25)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-005",
            "application": "Management API",
            "connection-mode": "disconnected",
            "number-of-changes": 5,
            "tasks": [],
            "creation-time": {"posix-millis": old_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }
    mock_transport.discard_session.return_value = {"success": True, "data": {}, "message": "", "code": ""}

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 1
    mock_transport.discard_session.assert_called_once_with("10.0.0.1", "tmp-sid", "sess-005", None)


async def test_cleanup_skips_disconnected_session_with_changes_under_24h():
    """Disconnected session with changes but only a few hours old is kept."""
    recent_posix = int((datetime.now(UTC) - timedelta(hours=2)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-005b",
            "application": "Management API",
            "connection-mode": "disconnected",
            "number-of-changes": 5,
            "tasks": [],
            "creation-time": {"posix-millis": recent_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 0
    assert result.skipped == 1


async def test_cleanup_skips_sessions_with_active_tasks():
    """A session with pending 'tasks' is never discarded even if otherwise stale."""
    old_posix = int((datetime.now(UTC) - timedelta(hours=5)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-tasked",
            "application": "Management API",
            "connection-mode": "disconnected",
            "number-of-changes": 0,
            "tasks": ["task-uid-1"],
            "creation-time": {"posix-millis": old_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 0
    assert result.skipped == 1
    mock_transport.discard_session.assert_not_called()


async def test_cleanup_skips_session_missing_uid():
    sessions = [{"application": "Management API", "connection-mode": "disconnected"}]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.skipped == 1
    mock_transport.discard_session.assert_not_called()


async def test_cleanup_skips_non_dict_session_entries():
    sessions = ["not-a-dict-session"]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.skipped == 1
    assert result.discarded == 0


async def test_cleanup_skips_session_with_no_usable_timestamp():
    """A session that passes every other filter but has no timestamp field is skipped."""
    sessions = [
        {
            "uid": "sess-no-ts",
            "application": "Management API",
            "connection-mode": "disconnected",
            "number-of-changes": 0,
            "tasks": [],
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.skipped == 1
    mock_transport.discard_session.assert_not_called()


async def test_cleanup_uses_changes_dict_sum_when_changes_is_a_mapping():
    """'changes' as a dict of counters (per-object-type) is summed."""
    old_posix = int((datetime.now(UTC) - timedelta(hours=2)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-dict-changes",
            "application": "Management API",
            "connection-mode": "disconnected",
            "changes": {"add": 0, "delete": 0},
            "creation-time": {"posix-millis": old_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }
    mock_transport.discard_session.return_value = {"success": True, "data": {}, "message": "", "code": ""}

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    # changes sums to 0 and age > 60min -> discard
    assert result.discarded == 1


async def test_cleanup_discards_r81_style_session_with_posix_seconds():
    """R81+ field names ('changes', 'in-work', 'connection-mode', 'last-logout-time')
    combined with a 'posix' (seconds) timestamp."""
    old_secs = int((datetime.now(UTC) - timedelta(hours=3)).timestamp())
    assert old_secs < 10_000_000_000
    sessions = [
        {
            "uid": "sess-r81",
            "application": "WEB_API",
            "connection-mode": "disconnected",
            "in-work": False,
            "changes": 0,
            "last-logout-time": {"posix": old_secs},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }
    mock_transport.discard_session.return_value = {"success": True, "data": {}, "message": "", "code": ""}

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 1
    mock_transport.discard_session.assert_called_once_with("10.0.0.1", "tmp-sid", "sess-r81", None)


async def test_cleanup_falls_back_to_last_login_time_when_last_logout_time_absent():
    old_posix = int((datetime.now(UTC) - timedelta(hours=3)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-fallback",
            "application": "Management API",
            "connection-mode": "disconnected",
            "changes": 0,
            "last-login-time": {"posix-millis": old_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }
    mock_transport.discard_session.return_value = {"success": True, "data": {}, "message": "", "code": ""}

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 1


# --------------------------------------------------------------------------
# cleanup_stale_sessions - overall flow / error handling
# --------------------------------------------------------------------------


async def test_cleanup_handles_show_sessions_exception():
    """If show_sessions raises, cleanup returns a CleanupResult with an error and 0 discarded."""
    mock_transport = AsyncMock()
    mock_transport.show_sessions.side_effect = Exception("Connection refused")

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 0
    assert len(result.errors) == 1
    assert "Connection refused" in result.errors[0]
    mock_transport.discard_session.assert_not_called()


async def test_cleanup_handles_show_sessions_unsuccessful_response():
    """An unsuccessful show-sessions response yields an empty (non-errored) result."""
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": False,
        "data": None,
        "message": "no permissions",
        "code": "err_forbidden",
    }

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result == CleanupResult()
    mock_transport.discard_session.assert_not_called()


async def test_cleanup_handles_empty_objects_list():
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": []},
        "message": "",
        "code": "",
    }

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 0
    assert result.skipped == 0
    assert result.errors == []


async def test_cleanup_discard_failure_recorded_as_error_not_exception():
    old_posix = int((datetime.now(UTC) - timedelta(hours=2)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-fail",
            "application": "Management API",
            "connection-mode": "disconnected",
            "number-of-changes": 0,
            "tasks": [],
            "creation-time": {"posix-millis": old_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }
    mock_transport.discard_session.return_value = {
        "success": False,
        "message": "cannot discard own session",
        "data": {},
        "code": "generic_err",
    }

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 0
    assert len(result.errors) == 1
    assert "sess-fail" in result.errors[0]


async def test_cleanup_discard_exception_recorded_as_error():
    old_posix = int((datetime.now(UTC) - timedelta(hours=2)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-exc",
            "application": "Management API",
            "connection-mode": "disconnected",
            "number-of-changes": 0,
            "tasks": [],
            "creation-time": {"posix-millis": old_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }
    mock_transport.discard_session.side_effect = RuntimeError("network blip")

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 0
    assert len(result.errors) == 1
    assert "network blip" in result.errors[0]


async def test_cleanup_passes_port_through_to_transport_calls():
    old_posix = int((datetime.now(UTC) - timedelta(hours=2)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-port",
            "application": "Management API",
            "connection-mode": "disconnected",
            "number-of-changes": 0,
            "tasks": [],
            "creation-time": {"posix-millis": old_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }
    mock_transport.discard_session.return_value = {"success": True, "data": {}, "message": "", "code": ""}

    cleaner = _make_cleaner(transport=mock_transport)
    await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1", port=4434)

    mock_transport.show_sessions.assert_called_once_with("10.0.0.1", "tmp-sid", 4434)
    mock_transport.discard_session.assert_called_once_with("10.0.0.1", "tmp-sid", "sess-port", 4434)


async def test_cleanup_span_uses_nested_cleanup_attribute_names(otel_spans):
    """cleanup_stale_sessions must namespace its counts under cleanup.* to
    match the identical attributes login_coordinator sets for the same
    CleanupResult shape (arodonata.cleanup.discarded / .skipped / .errors)."""
    old_posix = int((datetime.now(UTC) - timedelta(hours=2)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-attrs",
            "application": "Management API",
            "connection-mode": "disconnected",
            "number-of-changes": 0,
            "tasks": [],
            "creation-time": {"posix-millis": old_posix},
        }
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }
    mock_transport.discard_session.return_value = {"success": True, "data": {}, "message": "", "code": ""}

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 1
    span = next(s for s in otel_spans.get_finished_spans() if s.name.endswith("cleanup_stale_sessions"))
    assert span.attributes["arodonata.cleanup.discarded"] == 1
    assert span.attributes["arodonata.cleanup.skipped"] == 0
    assert span.attributes["arodonata.cleanup.errors"] == 0
    assert "arodonata.discarded" not in span.attributes
    assert "arodonata.skipped" not in span.attributes
    assert "arodonata.errors" not in span.attributes


async def test_cleanup_multiple_sessions_mixed_outcomes():
    """One discardable, one connected-and-protected, one too-recent: counts add up correctly."""
    old_posix = int((datetime.now(UTC) - timedelta(hours=2)).timestamp() * 1000)
    recent_posix = int((datetime.now(UTC) - timedelta(minutes=5)).timestamp() * 1000)
    sessions = [
        {
            "uid": "sess-a",
            "application": "Management API",
            "connection-mode": "disconnected",
            "number-of-changes": 0,
            "tasks": [],
            "creation-time": {"posix-millis": old_posix},
        },
        {
            "uid": "sess-b",
            "application": "Management API",
            "connection-mode": "connected",
            "number-of-changes": 0,
            "creation-time": {"posix-millis": old_posix},
        },
        {
            "uid": "sess-c",
            "application": "Management API",
            "connection-mode": "disconnected",
            "number-of-changes": 0,
            "tasks": [],
            "creation-time": {"posix-millis": recent_posix},
        },
    ]
    mock_transport = AsyncMock()
    mock_transport.show_sessions.return_value = {
        "success": True,
        "data": {"objects": sessions},
        "message": "",
        "code": "",
    }
    mock_transport.discard_session.return_value = {"success": True, "data": {}, "message": "", "code": ""}

    cleaner = _make_cleaner(transport=mock_transport)
    result = await cleaner.cleanup_stale_sessions("mgmt1", "", "tmp-sid", "10.0.0.1")

    assert result.discarded == 1
    assert result.skipped == 2
    mock_transport.discard_session.assert_called_once_with("10.0.0.1", "tmp-sid", "sess-a", None)
