"""Unit tests for RateLimiter: slot acquire/release, limit enforcement, and independence."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import MagicMock

import pytest

from arodonata.asdk.rate_limiter import RateLimiter
from arodonata.cache.lock_manager import LockAcquisitionError


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
