"""Unit tests for RateLimiter: slot acquire/release, limit enforcement, and independence."""

from __future__ import annotations

import asyncio
import contextlib
from contextlib import asynccontextmanager
from unittest.mock import MagicMock, patch

import pytest

from arodonata.asdk.rate_limiter import RateLimiter
from arodonata.cache.lock_manager import LockAcquisitionError, LockOwnershipError


class FakeLockManager:
    """Minimal stand-in for DatabaseLockManager.

    Each distinct lock_key gets its own real asyncio.Lock, so concurrent
    `acquire()` calls for the *same* key are genuinely serialized (mirroring
    Postgres advisory-lock exclusivity), while different keys never block
    each other.
    """

    DEFAULT_TTL_RATE_LIMIT = 300

    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}
        self.acquired_keys: list[str] = []
        self.acquired_timeouts: list[int] = []
        self.renewals: list[tuple[str, str, int | None]] = []
        self.closed = False
        self.initialized = False

    async def initialize(self) -> None:
        self.initialized = True

    async def close(self) -> None:
        self.closed = True

    @asynccontextmanager
    async def acquire(self, lock_key: str, timeout: int = 30, ttl: int | None = None):
        self.acquired_keys.append(lock_key)
        self.acquired_timeouts.append(timeout)
        lock = self._locks.setdefault(lock_key, asyncio.Lock())
        async with lock:
            yield MagicMock()

    # Non-blocking surface mirroring DatabaseLockManager.try_acquire_lock /
    # release_lock: a key is either held or free, no waiting.
    async def try_acquire_lock(self, lock_key: str, ttl: int):
        lock = self._locks.setdefault(lock_key, asyncio.Lock())
        if lock.locked():
            return None
        await lock.acquire()
        self.acquired_keys.append(lock_key)
        ctx = MagicMock()
        ctx.lock_key = lock_key
        ctx.owner_id = "fake-owner"
        return ctx

    async def release_lock(self, lock_key: str, owner_id: str) -> None:
        lock = self._locks.get(lock_key)
        if lock is not None and lock.locked():
            lock.release()

    # Renewal surface mirroring DatabaseLockManager.renew_lock. `renew_result` is what
    # the next renewals return; an exception instance is raised instead.
    renew_result: bool | BaseException = True

    async def renew_lock(self, lock_key: str, owner_id: str, ttl: int | None = None) -> bool:
        self.renewals.append((lock_key, owner_id, ttl))
        if isinstance(self.renew_result, BaseException):
            raise self.renew_result
        return self.renew_result


def _make_limiter(concurrent_limit: int = 1, lock_manager: FakeLockManager | None = None):
    lm = lock_manager if lock_manager is not None else FakeLockManager()
    return RateLimiter(concurrent_limit=concurrent_limit, lock_manager=lm), lm


# --------------------------------------------------------------------------
# Slot acquire/release
# --------------------------------------------------------------------------


async def _hold_only_slot(limiter: RateLimiter) -> tuple[asyncio.Task[None], asyncio.Event]:
    """Occupy the single slot of a limit-1 limiter from another task; return (task, release)."""
    ready = asyncio.Event()
    release = asyncio.Event()

    async def holder():
        async with limiter.acquire("10.0.0.1"):
            ready.set()
            await release.wait()

    task = asyncio.create_task(holder())
    await ready.wait()
    return task, release


async def test_acquire_uses_constructed_slot_timeout_by_default():
    """acquire() with no explicit timeout waits up to this instance's slot_timeout
    for any slot to free -- not a hardcoded 30s -- and reports that timeout when
    every slot stays busy. The limiter owns the deadline; the lock manager only
    answers "is this slot free right now"."""
    limiter = RateLimiter(concurrent_limit=1, lock_manager=FakeLockManager(), slot_timeout=1)
    holder, release = await _hold_only_slot(limiter)

    async def waiter():
        async with limiter.acquire("10.0.0.1"):
            pass

    with pytest.raises(LockAcquisitionError) as exc_info:
        async with asyncio.timeout(3):
            await asyncio.create_task(waiter())
    assert exc_info.value.timeout == 1

    release.set()
    await holder


async def test_acquire_explicit_timeout_overrides_constructed_default():
    limiter = RateLimiter(concurrent_limit=1, lock_manager=FakeLockManager(), slot_timeout=90)
    holder, release = await _hold_only_slot(limiter)

    async def waiter():
        async with limiter.acquire("10.0.0.1", timeout=1):
            pass

    with pytest.raises(LockAcquisitionError) as exc_info:
        async with asyncio.timeout(3):
            await asyncio.create_task(waiter())
    assert exc_info.value.timeout == 1

    release.set()
    await holder


async def test_acquire_yields_and_releases_cleanly():
    limiter, lock_manager = _make_limiter()

    async with limiter.acquire("10.0.0.1"):
        pass

    assert lock_manager.acquired_keys == ["ratelimit:10.0.0.1:slot_0"]
    # Reentrancy bookkeeping fully cleared after release.
    assert limiter._reentrancy_count == {}


async def test_acquire_lock_key_includes_server_ip_and_slot():
    limiter, lock_manager = _make_limiter(concurrent_limit=1)

    async with limiter.acquire("192.168.1.10"):
        pass

    assert lock_manager.acquired_keys == ["ratelimit:192.168.1.10:slot_0"]


async def test_get_slot_number_is_within_valid_range():
    limiter, _ = _make_limiter(concurrent_limit=5)
    slot = limiter._get_slot_number("10.0.0.1")
    assert 0 <= slot < 5


async def test_get_slot_number_is_deterministic_within_same_task():
    limiter, _ = _make_limiter(concurrent_limit=5)
    slot1 = limiter._get_slot_number("10.0.0.1")
    slot2 = limiter._get_slot_number("10.0.0.1")
    assert slot1 == slot2


# --------------------------------------------------------------------------
# Reentrancy - nested acquire on the same task doesn't deadlock or re-lock
# --------------------------------------------------------------------------


async def test_acquire_is_reentrant_within_same_task():
    limiter, lock_manager = _make_limiter(concurrent_limit=1)

    async with limiter.acquire("10.0.0.1"):
        async with limiter.acquire("10.0.0.1"):
            # Reentrant acquire must not call lock_manager.acquire a second time.
            assert lock_manager.acquired_keys == ["ratelimit:10.0.0.1:slot_0"]

    assert limiter._reentrancy_count == {}


async def test_acquire_reentrancy_count_decrements_correctly_on_triple_nesting():
    limiter, _ = _make_limiter(concurrent_limit=1)

    async with limiter.acquire("10.0.0.1"):
        key = next(iter(limiter._reentrancy_count))
        assert limiter._reentrancy_count[key] == 1
        async with limiter.acquire("10.0.0.1"):
            assert limiter._reentrancy_count[key] == 2
            async with limiter.acquire("10.0.0.1"):
                assert limiter._reentrancy_count[key] == 3
            assert limiter._reentrancy_count[key] == 2
        assert limiter._reentrancy_count[key] == 1

    assert limiter._reentrancy_count == {}


# --------------------------------------------------------------------------
# Limit enforcement: with concurrent_limit=1, concurrent acquires on the same
# server serialize (the Nth+1 caller waits for the Nth to release).
# --------------------------------------------------------------------------


async def test_second_concurrent_acquire_waits_for_first_to_release():
    limiter, _ = _make_limiter(concurrent_limit=1)
    events: list[str] = []
    release_first = asyncio.Event()

    async def holder():
        async with limiter.acquire("10.0.0.1"):
            events.append("first-acquired")
            await release_first.wait()
            events.append("first-released")

    async def waiter():
        # Give the holder a chance to acquire first.
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        events.append("second-waiting")
        async with limiter.acquire("10.0.0.1"):
            events.append("second-acquired")

    holder_task = asyncio.create_task(holder())
    waiter_task = asyncio.create_task(waiter())

    # Let both tasks reach their waiting points.
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    release_first.set()

    await asyncio.gather(holder_task, waiter_task)

    # The second acquire must not complete before the first releases.
    assert events.index("first-released") < events.index("second-acquired")
    assert events[0] == "first-acquired"


async def test_two_concurrent_holders_never_overlap_with_limit_one():
    limiter, _ = _make_limiter(concurrent_limit=1)
    active = 0
    max_active = 0
    lock = asyncio.Lock()

    async def worker():
        nonlocal active, max_active
        async with limiter.acquire("10.0.0.1"):
            async with lock:
                active += 1
                max_active = max(max_active, active)
            await asyncio.sleep(0)
            async with lock:
                active -= 1

    await asyncio.gather(*(worker() for _ in range(5)))

    assert max_active == 1


# --------------------------------------------------------------------------
# Per-server independence
# --------------------------------------------------------------------------


async def test_different_servers_do_not_block_each_other():
    limiter, lock_manager = _make_limiter(concurrent_limit=1)
    order: list[str] = []
    release_a = asyncio.Event()

    async def hold_server_a():
        async with limiter.acquire("10.0.0.1"):
            order.append("a-acquired")
            await release_a.wait()
            order.append("a-released")

    async def hold_server_b():
        await asyncio.sleep(0)
        async with limiter.acquire("10.0.0.2"):
            order.append("b-acquired")

    task_a = asyncio.create_task(hold_server_a())
    task_b = asyncio.create_task(hold_server_b())

    await asyncio.sleep(0)
    await asyncio.sleep(0)
    # Server B's acquire should succeed while server A is still held.
    await asyncio.sleep(0)
    assert "b-acquired" in order
    assert "a-released" not in order

    release_a.set()
    await asyncio.gather(task_a, task_b)

    assert set(lock_manager.acquired_keys) == {
        "ratelimit:10.0.0.1:slot_0",
        "ratelimit:10.0.0.2:slot_0",
    }


async def test_concurrent_limit_creates_distinct_lock_keys_per_slot():
    """With multiple slots, the (server, slot) lock key remains stable per task."""
    limiter, lock_manager = _make_limiter(concurrent_limit=8)

    async with limiter.acquire("server-x"):
        pass
    async with limiter.acquire("server-y"):
        pass

    assert len(lock_manager.acquired_keys) == 2
    assert lock_manager.acquired_keys[0].startswith("ratelimit:server-x:slot_")
    assert lock_manager.acquired_keys[1].startswith("ratelimit:server-y:slot_")
    assert lock_manager.acquired_keys[0] != lock_manager.acquired_keys[1]


# --------------------------------------------------------------------------
# close()
# --------------------------------------------------------------------------


async def test_close_closes_lock_manager_and_clears_state():
    limiter, lock_manager = _make_limiter()

    async with limiter.acquire("10.0.0.1"):
        pass

    await limiter.close()

    assert lock_manager.closed is True
    assert limiter._in_process_locks == {}
    assert limiter._reentrancy_count == {}
    assert limiter._closed is True


async def test_close_is_idempotent():
    limiter, lock_manager = _make_limiter()

    await limiter.close()
    lock_manager.closed = "first-close-marker"
    await limiter.close()

    # Second call must be a no-op (would otherwise reset the marker via a
    # second real close() call on a fresh FakeLockManager instance).
    assert lock_manager.closed == "first-close-marker"


async def test_close_without_lock_manager_configured_does_not_raise():
    limiter = RateLimiter(concurrent_limit=2)
    await limiter.close()
    assert limiter._closed is True


# --------------------------------------------------------------------------
# Lazy lock-manager resolution (constructor without an explicit lock_manager)
# --------------------------------------------------------------------------


async def test_get_lock_manager_uses_global_manager_when_none_provided():
    from unittest.mock import patch

    fake_global_manager = FakeLockManager()

    async def _fake_get_global_lock_manager():
        return fake_global_manager

    limiter = RateLimiter(concurrent_limit=2)
    with patch("arodonata.cache._get_global_lock_manager", _fake_get_global_lock_manager):
        resolved = await limiter._get_lock_manager()

    assert resolved is fake_global_manager
    assert fake_global_manager.initialized is True


async def test_get_lock_manager_caches_result_across_calls():
    fake_manager = MagicMock()
    limiter = RateLimiter(concurrent_limit=2, lock_manager=fake_manager)

    first = await limiter._get_lock_manager()
    second = await limiter._get_lock_manager()

    assert first is second is fake_manager


# --------------------------------------------------------------------------
# Slot fallback: the limiter is a semaphore over N slots, not N pinned locks
# --------------------------------------------------------------------------


async def test_acquire_falls_back_to_a_free_slot_when_hashed_slot_is_busy(monkeypatch):
    """A task whose hashed slot is held must take another free slot, not wait.

    Reproduces the integration failure where a foreground login starved 90s on
    `slot_2` while slots 0 and 1 sat idle, because slot choice was a pure hash
    with no fallback.
    """
    limiter, lm = _make_limiter(concurrent_limit=3)
    monkeypatch.setattr(limiter, "_get_slot_number", lambda server_ip: 2)  # force a collision

    holder_ready = asyncio.Event()
    release_holder = asyncio.Event()

    async def holder():
        async with limiter.acquire("10.0.0.1"):
            holder_ready.set()
            await release_holder.wait()

    holder_task = asyncio.create_task(holder())
    await holder_ready.wait()

    # Must succeed promptly on a different slot while the holder still owns slot_2.
    async with asyncio.timeout(2):
        async with limiter.acquire("10.0.0.1", timeout=1):
            held_now = {k for k in lm.acquired_keys}
            assert any(k.endswith(":slot_0") or k.endswith(":slot_1") for k in held_now), held_now

    release_holder.set()
    await holder_task


async def test_acquire_raises_lock_acquisition_error_only_when_all_slots_busy(monkeypatch):
    """With every slot held, acquire() honours its timeout and raises instead of hanging."""
    from arodonata.cache.lock_manager import LockAcquisitionError

    limiter, _ = _make_limiter(concurrent_limit=2)
    monkeypatch.setattr(limiter, "_get_slot_number", lambda server_ip: 0)

    release = asyncio.Event()
    ready: list[asyncio.Event] = [asyncio.Event(), asyncio.Event()]

    async def holder(i: int):
        async with limiter.acquire("10.0.0.1"):
            ready[i].set()
            await release.wait()

    holders = [asyncio.create_task(holder(0)), asyncio.create_task(holder(1))]
    # Both holders must be able to hold simultaneously (two slots): guard so a
    # regression to pinned slots fails instead of hanging here.
    async with asyncio.timeout(2):
        await asyncio.gather(ready[0].wait(), ready[1].wait())

    async with asyncio.timeout(3):
        try:
            async with limiter.acquire("10.0.0.1", timeout=1):
                raise AssertionError("acquired although every slot was held")
        except LockAcquisitionError:
            pass

    release.set()
    await asyncio.gather(*holders)


async def test_acquire_is_reentrant_after_falling_back_to_another_slot(monkeypatch):
    """Reentrancy follows the slot actually held, not the hashed one."""
    limiter, lm = _make_limiter(concurrent_limit=3)
    monkeypatch.setattr(limiter, "_get_slot_number", lambda server_ip: 2)

    holder_ready = asyncio.Event()
    release_holder = asyncio.Event()

    async def holder():
        async with limiter.acquire("10.0.0.1"):
            holder_ready.set()
            await release_holder.wait()

    holder_task = asyncio.create_task(holder())
    await holder_ready.wait()

    async with asyncio.timeout(2):
        async with limiter.acquire("10.0.0.1", timeout=1):
            before = len(lm.acquired_keys)
            async with limiter.acquire("10.0.0.1", timeout=1):  # nested, same task
                pass
            assert len(lm.acquired_keys) == before, "nested acquire must be reentrant, not a new slot"

    release_holder.set()
    await holder_task


def test_current_task_id_isolated_in_different_contexts_when_no_task(monkeypatch):
    import contextvars

    monkeypatch.setattr(asyncio, "current_task", lambda: None)

    id1 = RateLimiter._current_task_id()
    id2 = RateLimiter._current_task_id()
    assert id1 == id2
    assert id1 > 0

    fresh_ctx = contextvars.Context()
    id3 = fresh_ctx.run(RateLimiter._current_task_id)
    assert id3 != id1


def test_default_limit_is_the_per_member_default():
    from arodonata.config.constants import DEFAULT_CONCURRENT_LIMIT

    assert RateLimiter(lock_manager=FakeLockManager())._concurrent_limit == DEFAULT_CONCURRENT_LIMIT == 4


# --------------------------------------------------------------------------
# A held slot's distributed row is renewed until release (Backlog item 20):
# a request may hold a slot longer than DEFAULT_TTL_RATE_LIMIT (a whole listing,
# a publish task), and a lapsed row lets another process take the same slot.
# --------------------------------------------------------------------------


async def test_a_held_slot_is_renewed_until_released():
    lock_manager = FakeLockManager()
    limiter = RateLimiter(concurrent_limit=1, lock_manager=lock_manager, slot_renew_interval=0.05)

    async with limiter.acquire("192.168.5.170"):
        await _until(lambda: len(lock_manager.renewals) >= 3)

    assert len(lock_manager.renewals) >= 3
    assert set(lock_manager.renewals) == {
        ("ratelimit:192.168.5.170:slot_0", "fake-owner", FakeLockManager.DEFAULT_TTL_RATE_LIMIT)
    }
    renewed_while_held = len(lock_manager.renewals)
    await asyncio.sleep(0.15)
    assert len(lock_manager.renewals) == renewed_while_held  # nothing after release


async def test_a_reentrant_acquire_does_not_start_a_second_renewal():
    lock_manager = FakeLockManager()
    limiter = RateLimiter(concurrent_limit=1, lock_manager=lock_manager, slot_renew_interval=0.05)

    async with limiter.acquire("192.168.5.170"):
        async with limiter.acquire("192.168.5.170"):
            await asyncio.sleep(0.27)

    # One renewer: ~5 renewals in 0.27 s at 0.05 s; two would give ~10.
    assert 3 <= len(lock_manager.renewals) <= 6


@pytest.mark.parametrize(
    "failure", [False, LockOwnershipError("ratelimit:192.168.5.170:slot_0", "other-owner")], ids=["gone", "taken"]
)
async def test_a_lost_slot_row_is_reported_once_and_the_request_continues(failure):
    # Row gone or owned by someone else: renewing again cannot help, so say it once and stop.
    lock_manager = FakeLockManager()
    lock_manager.renew_result = failure
    limiter = RateLimiter(concurrent_limit=1, lock_manager=lock_manager, slot_renew_interval=0.05)

    with patch("arodonata.asdk.rate_limiter.log") as log:
        async with limiter.acquire("192.168.5.170"):
            await asyncio.sleep(0.2)
        warnings = [str(c.args[0]) for c in log.return_value.warning.call_args_list]

    assert len(lock_manager.renewals) == 1
    assert len(warnings) == 1 and "ratelimit:192.168.5.170:slot_0" in warnings[0]
    assert not lock_manager._locks["ratelimit:192.168.5.170:slot_0"].locked()  # released normally


async def test_a_transient_renewal_error_is_logged_and_retried():
    lock_manager = FakeLockManager()
    lock_manager.renew_result = RuntimeError("database is locked")
    limiter = RateLimiter(concurrent_limit=1, lock_manager=lock_manager, slot_renew_interval=0.05)

    with patch("arodonata.asdk.rate_limiter.log") as log:
        async with limiter.acquire("192.168.5.170"):
            await _until(lambda: len(lock_manager.renewals) >= 2)
        warnings = [str(c.args[0]) for c in log.return_value.warning.call_args_list]

    assert len(warnings) >= 2
    assert all("ratelimit:192.168.5.170:slot_0" in w and "RuntimeError" in w for w in warnings)


async def test_renewal_stops_when_the_holder_is_cancelled():
    lock_manager = FakeLockManager()
    limiter = RateLimiter(concurrent_limit=1, lock_manager=lock_manager, slot_renew_interval=0.05)

    async def hold() -> None:
        async with limiter.acquire("192.168.5.170"):
            await asyncio.sleep(10)

    holder = asyncio.create_task(hold())
    await asyncio.sleep(0.12)
    holder.cancel()
    with pytest.raises(asyncio.CancelledError):
        await holder

    renewed = len(lock_manager.renewals)
    assert renewed >= 1
    await asyncio.sleep(0.15)
    assert len(lock_manager.renewals) == renewed
    assert not lock_manager._locks["ratelimit:192.168.5.170:slot_0"].locked()


def test_slots_are_renewed_every_third_of_their_ttl_by_default():
    limiter = RateLimiter(lock_manager=FakeLockManager())
    assert limiter._slot_renew_interval(FakeLockManager.DEFAULT_TTL_RATE_LIMIT) == 100.0


async def _until(condition, timeout: float = 5.0) -> None:
    """Poll `condition` until true (fails the test after `timeout`): no fixed sleeps on slow runners."""
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.01)


class _SlowUnwindLockManager(FakeLockManager):
    """A renewal that takes a while to unwind when cancelled, like a DB call closing its session."""

    def __init__(self) -> None:
        super().__init__()
        self.renewing = asyncio.Event()
        self.unwinding = asyncio.Event()

    async def renew_lock(self, lock_key: str, owner_id: str, ttl: int | None = None) -> bool:
        self.renewing.set()
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            self.unwinding.set()
            await asyncio.sleep(0.05)
            raise
        return True


async def test_a_cancel_during_release_never_leaks_the_slot():
    lock_manager = _SlowUnwindLockManager()
    limiter = RateLimiter(concurrent_limit=1, lock_manager=lock_manager, slot_renew_interval=0.01, slot_timeout=1)

    async def hold() -> None:
        async with limiter.acquire("192.168.5.170"):
            await lock_manager.renewing.wait()  # leave the body while a renewal is in flight

    holder = asyncio.create_task(hold())
    await asyncio.wait_for(lock_manager.unwinding.wait(), 2)  # release is waiting for the renewer
    holder.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await holder

    # The slot must be free again for this process and in the lock table.
    async with asyncio.timeout(2), limiter.acquire("192.168.5.170", timeout=1):
        pass
    assert limiter._reentrancy_count == {}


def test_a_non_positive_renew_interval_is_rejected():
    with pytest.raises(ValueError, match="slot_renew_interval"):
        RateLimiter(lock_manager=FakeLockManager(), slot_renew_interval=0)


async def test_renewal_moves_the_rows_expiry_on_a_real_lock_table(tmp_path):
    from sqlalchemy.ext.asyncio import create_async_engine

    from arodonata.cache.database import DatabaseManager
    from arodonata.cache.lock_manager import DatabaseLockManager

    # A file, not :memory:: release cancels the renewer, often mid-statement; SQLAlchemy then
    # invalidates the connection, and a reconnect to :memory: opens a new, empty database.
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'locks.db'}")
    manager = DatabaseLockManager(DatabaseManager(engine))
    await manager.initialize()
    limiter = RateLimiter(concurrent_limit=1, lock_manager=manager, slot_renew_interval=0.05)
    try:
        async with limiter.acquire("192.168.5.170"):
            first = await manager.peek_expiry("ratelimit:192.168.5.170:slot_0")
            await asyncio.sleep(1.2)  # expiry is stored at second resolution or finer; > 1 s keeps it visible
            later = await manager.peek_expiry("ratelimit:192.168.5.170:slot_0")
        assert first is not None and later is not None and later > first
    finally:
        await limiter.close()
        await engine.dispose()


# --------------------------------------------------------------------------
# FIFO hand-off (own-pagination spec D1)
# --------------------------------------------------------------------------


def _queued(limiter: RateLimiter, host: str = "10.0.0.1") -> int:
    return len(limiter._waiters.get(host, ()))


async def test_a_caller_that_releases_and_reacquires_does_not_overtake_a_waiter():
    """A pager releases after a page and asks again at once; the queued waiter must get the slot first."""
    limiter, _ = _make_limiter(concurrent_limit=1)
    order: list[str] = []
    page_done = asyncio.Event()

    async def pager():
        async with limiter.acquire("10.0.0.1"):
            order.append("page-1")
            await page_done.wait()
        async with limiter.acquire("10.0.0.1"):
            order.append("page-2")

    async def waiter():
        async with limiter.acquire("10.0.0.1"):
            order.append("waiter")

    pager_task = asyncio.create_task(pager())
    await _until(lambda: order == ["page-1"])
    waiter_task = asyncio.create_task(waiter())
    await _until(lambda: _queued(limiter) == 1)
    page_done.set()
    async with asyncio.timeout(5):
        await asyncio.gather(pager_task, waiter_task)

    assert order == ["page-1", "waiter", "page-2"]


async def test_waiters_get_the_slot_in_arrival_order():
    limiter, _ = _make_limiter(concurrent_limit=1)
    holder, release = await _hold_only_slot(limiter)
    order: list[int] = []

    async def waiter(i: int):
        async with limiter.acquire("10.0.0.1"):
            order.append(i)

    tasks = []
    for i in range(3):
        tasks.append(asyncio.create_task(waiter(i)))
        await _until(lambda n=i + 1: _queued(limiter) == n)
    release.set()
    async with asyncio.timeout(5):
        await asyncio.gather(holder, *tasks)

    assert order == [0, 1, 2]
    assert limiter._waiters == {}


async def test_a_release_wakes_the_head_without_waiting_out_its_backoff():
    limiter, _ = _make_limiter(concurrent_limit=1)
    holder, release = await _hold_only_slot(limiter)
    got_at: list[float] = []
    loop = asyncio.get_running_loop()

    async def waiter():
        async with limiter.acquire("10.0.0.1"):
            got_at.append(loop.time())

    task = asyncio.create_task(waiter())
    # Hold long enough for the waiter's backoff to grow (0.1 + 0.2 + 0.4 s): its next poll is ~0.8 s away.
    await asyncio.sleep(0.75)
    released_at = loop.time()
    release.set()
    async with asyncio.timeout(5):
        await asyncio.gather(holder, task)

    assert got_at[0] - released_at < 0.3


async def test_two_freed_slots_serve_two_waiters():
    limiter, _ = _make_limiter(concurrent_limit=2)
    release = asyncio.Event()
    ready = [asyncio.Event(), asyncio.Event()]

    async def holder(i: int):
        async with limiter.acquire("10.0.0.1"):
            ready[i].set()
            await release.wait()

    holders = [asyncio.create_task(holder(0)), asyncio.create_task(holder(1))]
    await asyncio.gather(ready[0].wait(), ready[1].wait())
    inside = 0
    both_inside = asyncio.Event()
    leave = asyncio.Event()

    async def waiter():
        nonlocal inside
        async with limiter.acquire("10.0.0.1"):
            inside += 1
            if inside == 2:
                both_inside.set()
            await leave.wait()

    waiters = [asyncio.create_task(waiter()), asyncio.create_task(waiter())]
    await _until(lambda: _queued(limiter) == 2)
    release.set()
    async with asyncio.timeout(1):
        await both_inside.wait()
    leave.set()
    await asyncio.gather(*holders, *waiters)


async def test_a_cancelled_head_hands_the_turn_to_the_next_waiter():
    limiter, _ = _make_limiter(concurrent_limit=1)
    holder, release = await _hold_only_slot(limiter)
    got: list[str] = []

    async def waiter(name: str):
        async with limiter.acquire("10.0.0.1"):
            got.append(name)

    first = asyncio.create_task(waiter("first"))
    await _until(lambda: _queued(limiter) == 1)
    second = asyncio.create_task(waiter("second"))
    await _until(lambda: _queued(limiter) == 2)
    first.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await first
    assert _queued(limiter) == 1
    release.set()
    async with asyncio.timeout(1):
        await asyncio.gather(holder, second)

    assert got == ["second"]
    assert limiter._waiters == {}


async def test_a_timed_out_head_leaves_the_queue_and_the_next_waiter_still_gets_the_slot():
    limiter, _ = _make_limiter(concurrent_limit=1)
    holder, release = await _hold_only_slot(limiter)
    got: list[str] = []

    async def impatient():
        with pytest.raises(LockAcquisitionError):
            async with limiter.acquire("10.0.0.1", timeout=0.2):
                got.append("impatient")

    async def patient():
        async with limiter.acquire("10.0.0.1", timeout=5):
            got.append("patient")

    first = asyncio.create_task(impatient())
    await _until(lambda: _queued(limiter) == 1)
    second = asyncio.create_task(patient())
    await first
    assert _queued(limiter) == 1
    release.set()
    async with asyncio.timeout(1):
        await asyncio.gather(holder, second)

    assert got == ["patient"]


async def test_a_slot_freed_by_another_process_is_found_by_the_heads_sweep():
    limiter, lm = _make_limiter(concurrent_limit=1)
    other_process = lm._locks.setdefault("ratelimit:10.0.0.1:slot_0", asyncio.Lock())
    await other_process.acquire()  # the distributed row is held elsewhere; this process's lock is free
    got = asyncio.Event()

    async def waiter():
        async with limiter.acquire("10.0.0.1", timeout=5):
            got.set()

    task = asyncio.create_task(waiter())
    await _until(lambda: _queued(limiter) == 1)
    other_process.release()  # no wake-up in this process: only the head's polling sweep can see it
    async with asyncio.timeout(3):
        await got.wait()
    await task


async def test_a_reentrant_acquire_never_queues_behind_waiters():
    limiter, _ = _make_limiter(concurrent_limit=1)
    nested_done = asyncio.Event()
    waiter_queued = asyncio.Event()

    async def holder():
        async with limiter.acquire("10.0.0.1"):
            await waiter_queued.wait()
            async with asyncio.timeout(1), limiter.acquire("10.0.0.1"):
                nested_done.set()

    async def waiter():
        async with limiter.acquire("10.0.0.1"):
            pass

    holder_task = asyncio.create_task(holder())
    await _until(lambda: bool(limiter._task_slot))
    waiter_task = asyncio.create_task(waiter())
    await _until(lambda: _queued(limiter) == 1)
    waiter_queued.set()
    async with asyncio.timeout(5):
        await asyncio.gather(holder_task, waiter_task)
    assert nested_done.is_set()


async def test_a_short_call_gets_a_slot_while_long_listings_page_through_every_slot():
    """Four paging tasks keep all four slots busy, page after page; a fifth caller must not wait for a listing to end."""
    limiter, _ = _make_limiter(concurrent_limit=4)
    pages_per_listing = 20
    finished_listings = 0
    started = asyncio.Event()

    async def listing():
        nonlocal finished_listings
        for _ in range(pages_per_listing):
            async with limiter.acquire("10.0.0.1"):
                started.set()
                await asyncio.sleep(0.02)  # one page
        finished_listings += 1

    listings = [asyncio.create_task(listing()) for _ in range(4)]
    await started.wait()
    await asyncio.sleep(0.05)
    finished_when_served: list[int] = []
    async with limiter.acquire("10.0.0.1", timeout=5):
        finished_when_served.append(finished_listings)
    await asyncio.gather(*listings)

    assert finished_when_served == [0]


class _FailOnceLockManager(FakeLockManager):
    """The first slot attempt fails like a busy or dropped database; later ones behave normally."""

    def __init__(self) -> None:
        super().__init__()
        self.failed = False

    async def try_acquire_lock(self, lock_key: str, ttl: int):
        if not self.failed:
            self.failed = True
            raise RuntimeError("database is locked")
        return await super().try_acquire_lock(lock_key, ttl)


async def test_a_failed_slot_attempt_does_not_leave_the_slot_taken_in_this_process():
    limiter, _ = _make_limiter(concurrent_limit=1, lock_manager=_FailOnceLockManager())

    with pytest.raises(RuntimeError, match="database is locked"):
        async with limiter.acquire("10.0.0.1", timeout=1):
            pass

    async with asyncio.timeout(2), limiter.acquire("10.0.0.1", timeout=1):
        pass
    assert limiter._waiters == {}


class _HangOnceLockManager(FakeLockManager):
    """The first slot attempt hangs in the database until its task is cancelled."""

    def __init__(self) -> None:
        super().__init__()
        self.hanging = asyncio.Event()

    async def try_acquire_lock(self, lock_key: str, ttl: int):
        if not self.hanging.is_set():
            self.hanging.set()
            await asyncio.Event().wait()  # only cancellation ends this
        return await super().try_acquire_lock(lock_key, ttl)


async def test_a_cancel_during_a_slot_attempt_does_not_leave_the_slot_taken_in_this_process():
    lm = _HangOnceLockManager()
    limiter, _ = _make_limiter(concurrent_limit=1, lock_manager=lm)

    async def acquire_once():
        async with limiter.acquire("10.0.0.1", timeout=5):
            pass

    task = asyncio.create_task(acquire_once())
    await lm.hanging.wait()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task

    async with asyncio.timeout(2), limiter.acquire("10.0.0.1", timeout=1):
        pass
    assert limiter._waiters == {}


class _OtherProcessHoldsSlot1(FakeLockManager):
    """slot_1's row is held by another process (always busy); one chosen attempt on it stalls on `gate`."""

    def __init__(self) -> None:
        super().__init__()
        self.slot_1_calls = 0
        self.stall_on_call = 0
        self.stalled = asyncio.Event()
        self.gate = asyncio.Event()

    async def try_acquire_lock(self, lock_key: str, ttl: int):
        if lock_key.endswith(":slot_1"):
            self.slot_1_calls += 1
            if self.slot_1_calls == self.stall_on_call:
                self.stalled.set()
                await self.gate.wait()
            return None
        return await super().try_acquire_lock(lock_key, ttl)


async def test_a_release_during_the_heads_sweep_is_not_lost(monkeypatch):
    """The head has already passed the freed slot when the release lands; it must re-sweep at once, not after its backoff."""
    lm = _OtherProcessHoldsSlot1()
    limiter, _ = _make_limiter(concurrent_limit=2, lock_manager=lm)
    monkeypatch.setattr(limiter, "_get_slot_number", lambda server_ip: 0)  # every sweep: slot_0, then slot_1
    # slot_1 attempts: 1 fast path, 2 head at once, 3/4/5 after 0.1/0.2/0.4 s backoff. Stall the 5th:
    # the head's next backoff is then 0.8 s, so only the wake-up can explain a prompt acquisition.
    lm.stall_on_call = 5
    holder, release = await _hold_only_slot(limiter)  # takes slot_0 (free, first in the sweep)
    loop = asyncio.get_running_loop()
    got_at: list[float] = []

    async def waiter():
        async with limiter.acquire("10.0.0.1", timeout=10):
            got_at.append(loop.time())

    task = asyncio.create_task(waiter())
    async with asyncio.timeout(5):
        await lm.stalled.wait()  # the head is mid-sweep: slot_0 seen busy, now on slot_1
    release.set()
    await holder  # slot_0 released and the head woken while its sweep is still running
    sweep_ends_at = loop.time()
    lm.gate.set()
    async with asyncio.timeout(5):
        await task

    assert got_at[0] - sweep_ends_at < 0.4
