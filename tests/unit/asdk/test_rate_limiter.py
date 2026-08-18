"""Unit tests for RateLimiter: slot acquire/release, limit enforcement, and independence."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import MagicMock

from arodonata.asdk.rate_limiter import RateLimiter


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


def _make_limiter(concurrent_limit: int = 1, lock_manager: FakeLockManager | None = None):
    lm = lock_manager if lock_manager is not None else FakeLockManager()
    return RateLimiter(concurrent_limit=concurrent_limit, lock_manager=lm), lm


# --------------------------------------------------------------------------
# Slot acquire/release
# --------------------------------------------------------------------------


async def test_acquire_uses_constructed_slot_timeout_by_default():
    """acquire() with no explicit timeout must pass this instance's slot_timeout
    through to the lock manager -- not a hardcoded 30s -- so a caller waiting for a
    free concurrency slot gets as long as the RateLimiter was configured for."""
    lock_manager = FakeLockManager()
    limiter = RateLimiter(concurrent_limit=1, lock_manager=lock_manager, slot_timeout=90)

    async with limiter.acquire("10.0.0.1"):
        pass

    assert lock_manager.acquired_timeouts == [90]


async def test_acquire_explicit_timeout_overrides_constructed_default():
    lock_manager = FakeLockManager()
    limiter = RateLimiter(concurrent_limit=1, lock_manager=lock_manager, slot_timeout=90)

    async with limiter.acquire("10.0.0.1", timeout=5):
        pass

    assert lock_manager.acquired_timeouts == [5]


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
