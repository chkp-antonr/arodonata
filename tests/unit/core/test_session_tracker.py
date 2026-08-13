"""Tests for SessionChangeTracker (in-memory unpublished session changes)."""

from datetime import datetime

from arodonata.core.session_tracker import SessionChange, SessionChangeTracker


def _change(uid="abc123", name="test-host", operation="add"):
    return SessionChange(
        operation=operation,
        object_type="host",
        uid=uid,
        name=name,
        data={"uid": uid, "name": name},
    )


def test_add_and_get_change():
    tracker = SessionChangeTracker()

    tracker.add_change("mgmt1", "dmn1", _change())

    changes = tracker.get_session_changes("mgmt1", "dmn1")
    assert len(changes) == 1
    assert changes[0].uid == "abc123"


def test_add_change_appends_to_existing_session():
    tracker = SessionChangeTracker()

    tracker.add_change("mgmt1", "dmn1", _change(uid="a"))
    tracker.add_change("mgmt1", "dmn1", _change(uid="b"))

    assert [c.uid for c in tracker.get_session_changes("mgmt1", "dmn1")] == ["a", "b"]


def test_get_session_changes_unknown_returns_empty():
    tracker = SessionChangeTracker()

    assert tracker.get_session_changes("nope", "nope") == []


def test_clear_session():
    tracker = SessionChangeTracker()
    tracker.add_change("mgmt1", "dmn1", _change())

    tracker.clear_session("mgmt1", "dmn1")

    assert tracker.get_session_changes("mgmt1", "dmn1") == []


def test_clear_session_missing_is_noop():
    tracker = SessionChangeTracker()

    # Must not raise when clearing a session that was never tracked.
    tracker.clear_session("mgmt1", "dmn1")

    assert tracker.get_session_changes("mgmt1", "dmn1") == []


def test_sessions_are_independent():
    tracker = SessionChangeTracker()

    tracker.add_change("mgmt1", "dmn1", _change(uid="abc123"))
    tracker.add_change("mgmt1", "dmn2", _change(uid="def456"))

    assert tracker.get_session_changes("mgmt1", "dmn1")[0].uid == "abc123"
    assert tracker.get_session_changes("mgmt1", "dmn2")[0].uid == "def456"


def test_has_changes():
    tracker = SessionChangeTracker()

    assert tracker.has_changes("mgmt1", "dmn1") is False

    tracker.add_change("mgmt1", "dmn1", _change())

    assert tracker.has_changes("mgmt1", "dmn1") is True


def test_session_change_default_timestamp():
    change = SessionChange(operation="modify", object_type="host", uid="u", name="n")

    assert isinstance(change.timestamp, datetime)
    assert change.timestamp.tzinfo is None  # naive UTC
    assert change.data is None
