"""Unit tests for LoginGate: one refusal closes the gate for every login to that MDS member.

The lock manager is a fake with a clock the test drives, and asyncio.sleep is
patched to advance that clock, so a 70 s wait takes no wall time.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from arodonata.asdk.login_gate import (
    _MAX_SLEEP_SECONDS,
    _WAKE_JITTER_SECONDS,
    LoginGate,
    LoginGateDeadlineError,
)
from arodonata.core.exceptions import ThrottlingError

WINDOW = 70


class FakeTtlLockManager:
    """distributed_locks reduced to what the gate uses: rows with an expiry, on a driven clock."""

    def __init__(self) -> None:
        self.now = datetime(2026, 9, 14, 12, 0, 0)
        self.rows: dict[str, datetime] = {}

    def clock(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)

    async def try_acquire_lock(self, lock_key: str, ttl: int):
        expires = self.rows.get(lock_key)
        if expires is not None and expires > self.now:
            return None
        self.rows[lock_key] = self.now + timedelta(seconds=ttl)
        return MagicMock(lock_key=lock_key, expires_at=self.rows[lock_key])

    async def peek_expiry(self, lock_key: str):
        expires = self.rows.get(lock_key)
        return expires if expires is not None and expires > self.now else None

    async def extend_lock(self, lock_key: str, ttl: int) -> bool:
        if lock_key not in self.rows:
            return False
        self.rows[lock_key] = max(self.rows[lock_key], self.now + timedelta(seconds=ttl))
        return True


@pytest.fixture
def lm() -> FakeTtlLockManager:
    return FakeTtlLockManager()


@pytest.fixture
def gate(lm: FakeTtlLockManager) -> LoginGate:
    return LoginGate(lm, WINDOW, now=lm.clock)


@pytest.fixture
def slept(lm: FakeTtlLockManager):
    """Patch the gate's sleep to advance the fake clock; yields the list of durations."""
    durations: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        durations.append(seconds)
        lm.advance(seconds)

    with patch("arodonata.asdk.login_gate.asyncio.sleep", fake_sleep):
        yield durations


def _far_deadline() -> float:
    return asyncio.get_running_loop().time() + 10_000


async def test_open_gate_returns_without_sleeping(gate: LoginGate, slept: list[float]) -> None:
    await gate.wait_open("mds", deadline=_far_deadline(), max_wait=900)
    assert slept == []


async def test_close_then_wait_sleeps_until_the_row_lapses(gate: LoginGate, slept: list[float]) -> None:
    await gate.close("mds")

    await gate.wait_open("mds", deadline=_far_deadline(), max_wait=900)

    assert WINDOW <= sum(slept) <= WINDOW + _WAKE_JITTER_SECONDS


async def test_sleeps_are_chunked_and_keepalive_runs_before_each_chunk(gate: LoginGate, slept: list[float]) -> None:
    """The caller holds a 90 s login lock while it waits; renew it well inside that."""
    keepalive = AsyncMock()
    await gate.close("mds")

    await gate.wait_open("mds", deadline=_far_deadline(), max_wait=900, keepalive=keepalive)

    assert slept, "a closed gate must sleep"
    assert all(chunk <= _MAX_SLEEP_SECONDS for chunk in slept)
    assert keepalive.await_count == len(slept)


async def test_a_second_refusal_extends_the_window_from_the_last_refusal(
    gate: LoginGate, lm: FakeTtlLockManager
) -> None:
    await gate.close("mds")
    lm.advance(40)
    await gate.close("mds")

    assert lm.rows["loginthrottle:mds"] == lm.now + timedelta(seconds=WINDOW)


async def test_close_on_a_live_row_goes_through_extend_lock(gate: LoginGate, lm: FakeTtlLockManager) -> None:
    lm.extend_lock = AsyncMock(wraps=lm.extend_lock)  # type: ignore[method-assign]
    await gate.close("mds")
    await gate.close("mds")
    lm.extend_lock.assert_awaited_once_with("loginthrottle:mds", WINDOW)


async def test_management_servers_are_independent(gate: LoginGate, slept: list[float]) -> None:
    await gate.close("mds-a")
    await gate.wait_open("mds-b", deadline=_far_deadline(), max_wait=900)
    assert slept == []


async def test_wait_past_the_deadline_raises_a_throttling_error_without_sleeping(
    gate: LoginGate, slept: list[float]
) -> None:
    await gate.close("mds")
    deadline = asyncio.get_running_loop().time() + 10  # the row lapses in 70 s

    with pytest.raises(LoginGateDeadlineError) as excinfo:
        await gate.wait_open("mds", deadline=deadline, max_wait=10)

    assert isinstance(excinfo.value, ThrottlingError)
    assert excinfo.value.mds_host == "mds"
    assert excinfo.value.max_wait == 10
    assert "login_max_wait=10s" in str(excinfo.value)
    assert slept == []


async def test_refusal_during_the_wait_extends_it(gate: LoginGate, lm: FakeTtlLockManager) -> None:
    """Another task's refusal while we sleep must be honoured: re-check after waking."""
    await gate.close("mds")
    slept: list[float] = []

    async def sleep_then_refuse_once(seconds: float) -> None:
        slept.append(seconds)
        lm.advance(seconds)
        if len(slept) == 1:
            await gate.close("mds")  # someone else was refused while we slept

    with patch("arodonata.asdk.login_gate.asyncio.sleep", sleep_then_refuse_once):
        await gate.wait_open("mds", deadline=_far_deadline(), max_wait=900)

    # First refusal at t=0 lapses at 70; the second, at t=first chunk, lapses at chunk+70.
    assert sum(slept) >= slept[0] + WINDOW
