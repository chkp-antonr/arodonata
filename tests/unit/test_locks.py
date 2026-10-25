"""Adversarial unit tests for SqlLockAdapter (`W13`, `W16`, `I6`)."""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import patch

from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from arodonata.adapters.storage import DatabaseLockManager, DatabaseManager, DistributedLockRecord


async def test_lock_expiration_uses_database_utc_clock_not_skewed_host_clock() -> None:
    """Verify `SqlLockAdapter` evaluates `expires_at` using DB UTC clock rather than skewed local host clock (`W16`)."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    try:
        simulated_db_clock = datetime(2026, 10, 25, 12, 0, 0)

        async def _fake_db_now(_session: AsyncSession) -> datetime:
            return simulated_db_clock

        lock_a = DatabaseLockManager(db, default_owner_id="worker-a", db_now_fn=_fake_db_now)
        lock_b = DatabaseLockManager(db, default_owner_id="worker-b", db_now_fn=_fake_db_now)

        # Acquire lock with worker-a for 60s according to DB clock (expires at 12:01:00)
        assert await lock_a.acquire("sync:mds1:CMA1:objects", ttl_seconds=60.0) is True

        # Even if host utc_now() is skewed +2 hours into the future, worker-b must NOT steal the lock
        # because DB clock is still 12:00:00 (< 12:01:00).
        with patch(
            "arodonata.adapters.storage.lock_adapter.utc_now",
            return_value=simulated_db_clock + timedelta(hours=2),
        ):
            assert await lock_b.acquire("sync:mds1:CMA1:objects", ttl_seconds=60.0) is False

        # Advance DB clock past 12:01:00 -> now worker-b can reclaim the expired lock
        simulated_db_clock = datetime(2026, 10, 25, 12, 1, 5)
        assert await lock_b.acquire("sync:mds1:CMA1:objects", ttl_seconds=60.0) is True
    finally:
        await db.close()


async def test_lock_renew_and_owner_verified_release() -> None:
    """Verify `renew()` extends active locks only for the matching owner, and `release()` refuses wrong owners (`W13`, `I6`)."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    try:
        simulated_db_clock = datetime(2026, 10, 25, 12, 0, 0)

        async def _fake_db_now(_session: AsyncSession) -> datetime:
            return simulated_db_clock

        lock_mgr = DatabaseLockManager(db, default_owner_id="worker-a", db_now_fn=_fake_db_now)

        assert await lock_mgr.acquire("lock:key1", ttl_seconds=30.0, owner_id="worker-a") is True

        # Re-acquiring while active must return False (renewal must use renew())
        assert await lock_mgr.acquire("lock:key1", ttl_seconds=30.0, owner_id="worker-a") is False

        # Wrong owner cannot renew or release
        assert await lock_mgr.renew("lock:key1", ttl_seconds=120.0, owner_id="worker-imposter") is False
        assert await lock_mgr.release("lock:key1", owner_id="worker-imposter") is False
        assert await lock_mgr.release("lock:key1", owner_id="") is False

        # Active owner can renew
        simulated_db_clock = datetime(2026, 10, 25, 12, 0, 20)
        assert await lock_mgr.renew("lock:key1", ttl_seconds=120.0, owner_id="worker-a") is True

        async with db.session() as session:
            rec = await session.get(DistributedLockRecord, "lock:key1")
            assert rec is not None
            assert rec.expires_at == simulated_db_clock + timedelta(seconds=120.0)

        # Once expired, renew() returns False
        simulated_db_clock = datetime(2026, 10, 25, 12, 5, 0)
        assert await lock_mgr.renew("lock:key1", ttl_seconds=60.0, owner_id="worker-a") is False

        # Matching owner can release
        assert await lock_mgr.release("lock:key1", owner_id="worker-a") is True
    finally:
        await db.close()


async def test_lock_adapter_retries_transient_operational_error() -> None:
    """Verify `SqlLockAdapter` retries transient `database is locked` / deadlock errors (`I6`)."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    try:
        calls = 0

        async def _flaky_db_now(_session: AsyncSession) -> datetime:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OperationalError("SELECT", {}, Exception("database is locked"))
            return datetime(2026, 10, 25, 12, 0, 0)

        lock_mgr = DatabaseLockManager(db, default_owner_id="worker-a", db_now_fn=_flaky_db_now)
        assert await lock_mgr.acquire("lock:transient", ttl_seconds=30.0, owner_id="worker-a") is True
        assert calls == 2
    finally:
        await db.close()
