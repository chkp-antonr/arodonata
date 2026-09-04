"""Tests for DomainListRefreshTracker (per-mgmt domain-list re-fetch TTL memo).

Shared between ObjectService and RulebaseRefreshService - see the module
docstring in `arodonata.core.domain_list_refresh` for why both needed this.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from arodonata.core.domain_list_refresh import DOMAIN_LIST_REFRESH_TTL_SECONDS, DomainListRefreshTracker


class FakeClock:
    """Deterministic, advanceable time source implementing the Clock protocol."""

    def __init__(self, start: datetime) -> None:
        self._t = start

    def now(self) -> datetime:
        return self._t

    def advance(self, seconds: int) -> None:
        self._t = self._t + timedelta(seconds=seconds)


def test_default_ttl_is_one_hour():
    assert DOMAIN_LIST_REFRESH_TTL_SECONDS == 3600


def test_never_checked_is_stale():
    tracker = DomainListRefreshTracker()
    assert tracker.is_stale("mgmt1") is True


def test_marked_checked_is_not_stale_immediately():
    tracker = DomainListRefreshTracker()
    tracker.mark_checked("mgmt1")
    assert tracker.is_stale("mgmt1") is False


def test_stale_after_ttl_elapses():
    clock = FakeClock(datetime(2026, 9, 3, 12, 0, 0))
    tracker = DomainListRefreshTracker(ttl_seconds=3600, clock=clock)
    tracker.mark_checked("mgmt1")
    clock.advance(3601)
    assert tracker.is_stale("mgmt1") is True


def test_not_stale_within_ttl():
    clock = FakeClock(datetime(2026, 9, 3, 12, 0, 0))
    tracker = DomainListRefreshTracker(ttl_seconds=3600, clock=clock)
    tracker.mark_checked("mgmt1")
    clock.advance(3599)
    assert tracker.is_stale("mgmt1") is False


def test_ttl_is_configurable():
    clock = FakeClock(datetime(2026, 9, 3, 12, 0, 0))
    tracker = DomainListRefreshTracker(ttl_seconds=30, clock=clock)
    tracker.mark_checked("mgmt1")
    clock.advance(31)
    assert tracker.is_stale("mgmt1") is True


def test_tracking_is_independent_per_mgmt_name():
    clock = FakeClock(datetime(2026, 9, 3, 12, 0, 0))
    tracker = DomainListRefreshTracker(ttl_seconds=3600, clock=clock)
    tracker.mark_checked("mgmt1")
    assert tracker.is_stale("mgmt1") is False
    assert tracker.is_stale("mgmt2") is True
