"""Tests for arodonata.cache.lock_manager (distributed database lock manager).

The DatabaseLockManager tests instantiate the manager directly over a real
in-memory SQLite DatabaseManager (bypassing the autouse `mock_lock_manager`
fixture from conftest.py, which only patches the *global* accessor). The
`distributed_lock` decorator tests intentionally go through that patched
global accessor, since that is exactly the seam it exists to mock.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from arodonata.cache.database import DatabaseManager
from arodonata.cache.lock_manager import (
    DatabaseLockManager,
    LockAcquisitionError,
    LockContext,
    LockOwnershipError,
    distributed_lock,
    generate_owner_id,
    get_current_lock_context,
)
from arodonata.cache.models import DistributedLock

# NOTE: asyncio_mode = "auto" (pyproject.toml) auto-detects async def tests;
# no explicit pytest.mark.asyncio needed.


# --------------------------------------------------------------------------
# Fixtures: real in-memory SQLite DatabaseManager (no mocking)
# --------------------------------------------------------------------------


@pytest.fixture
async def engine() -> AsyncGenerator[AsyncEngine]:
    eng = create_async_engine("sqlite+aiosqlite:///:memory:")
    yield eng
    await eng.dispose()


@pytest.fixture
async def db_manager(engine: AsyncEngine) -> DatabaseManager:
    manager = DatabaseManager(engine)
    await manager.initialize()
    return manager


# --------------------------------------------------------------------------
# generate_owner_id
# --------------------------------------------------------------------------


def test_generate_owner_id_format(monkeypatch: pytest.MonkeyPatch) -> None:
    """owner id follows 'hostname:pid:worker_id' using WORKER_ID from env."""
    monkeypatch.setenv("WORKER_ID", "worker-7")
    owner_id = generate_owner_id()
    parts = owner_id.split(":")
    assert len(parts) == 3
    assert parts[1] == str(os.getpid())
    assert parts[2] == "worker-7"


def test_generate_owner_id_defaults_worker_to_main(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without WORKER_ID/GUNICORN_WORKER_ID set, the worker segment defaults to 'main'."""
    monkeypatch.delenv("WORKER_ID", raising=False)
    monkeypatch.delenv("GUNICORN_WORKER_ID", raising=False)
    owner_id = generate_owner_id()
    assert owner_id.endswith(":main")


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


def test_lock_acquisition_error_carries_key_and_timeout() -> None:
    err = LockAcquisitionError("my-key", 30)
    assert err.lock_key == "my-key"
    assert err.timeout == 30
    assert "my-key" in str(err)
    assert "30" in str(err)


def test_lock_ownership_error_carries_key_and_owner() -> None:
    err = LockOwnershipError("my-key", "owner-1")
    assert err.lock_key == "my-key"
    assert err.owner_id == "owner-1"
    assert "my-key" in str(err)
    assert "owner-1" in str(err)


# --------------------------------------------------------------------------
# LockContext
# --------------------------------------------------------------------------


def test_lock_context_repr() -> None:
    now = datetime.now(UTC).replace(tzinfo=None)
    ctx = LockContext("my-key", "owner-1", now, now, 60, manager=None)  # type: ignore[arg-type]
    text = repr(ctx)
    assert "my-key" in text
    assert "owner-1" in text


async def test_lock_context_renew_delegates_to_manager_with_own_ttl() -> None:
    fake_manager = AsyncMock()
    fake_manager.renew_lock = AsyncMock(return_value=True)
    now = datetime.now(UTC).replace(tzinfo=None)
    ctx = LockContext("k", "o", now, now, 60, manager=fake_manager)

    result = await ctx.renew()

    assert result is True
    fake_manager.renew_lock.assert_awaited_once_with("k", "o", 60)


async def test_lock_context_renew_with_explicit_ttl_overrides_default() -> None:
    fake_manager = AsyncMock()
    fake_manager.renew_lock = AsyncMock(return_value=True)
    now = datetime.now(UTC).replace(tzinfo=None)
    ctx = LockContext("k", "o", now, now, 60, manager=fake_manager)

    await ctx.renew(ttl=120)

    fake_manager.renew_lock.assert_awaited_once_with("k", "o", 120)


async def test_renew_if_needed_skips_renewal_before_threshold() -> None:
    """No renewal when elapsed time is below threshold * ttl (time is injected, never slept)."""
    acquired_at = datetime(2026, 1, 1, 0, 0, 0)
    fake_manager = AsyncMock()
    fake_manager.renew_lock = AsyncMock(return_value=True)
    ctx = LockContext("k", "o", acquired_at, acquired_at + timedelta(seconds=60), ttl=60, manager=fake_manager)

    with patch("arodonata.cache.lock_manager.datetime") as mock_dt:
        # 20s elapsed of a 60s TTL = 33%, below the 50% threshold.
        mock_dt.now.return_value = acquired_at + timedelta(seconds=20)
        result = await ctx.renew_if_needed(threshold=0.5)

    assert result is False
    fake_manager.renew_lock.assert_not_called()


async def test_renew_if_needed_renews_after_threshold() -> None:
    """Renewal fires once elapsed time exceeds threshold * ttl."""
    acquired_at = datetime(2026, 1, 1, 0, 0, 0)
    fake_manager = AsyncMock()
    fake_manager.renew_lock = AsyncMock(return_value=True)
    ctx = LockContext("k", "o", acquired_at, acquired_at + timedelta(seconds=60), ttl=60, manager=fake_manager)

    with patch("arodonata.cache.lock_manager.datetime") as mock_dt:
        # 40s elapsed of a 60s TTL = 67%, above the 50% threshold.
        mock_dt.now.return_value = acquired_at + timedelta(seconds=40)
        result = await ctx.renew_if_needed(threshold=0.5)

    assert result is True
    fake_manager.renew_lock.assert_awaited_once_with("k", "o", 60)


async def test_renew_if_needed_boundary_is_exclusive() -> None:
    """Elapsed time exactly equal to threshold * ttl does not trigger renewal
    ('> threshold', not '>=')."""
    acquired_at = datetime(2026, 1, 1, 0, 0, 0)
    fake_manager = AsyncMock()
    fake_manager.renew_lock = AsyncMock(return_value=True)
    ctx = LockContext("k", "o", acquired_at, acquired_at + timedelta(seconds=60), ttl=60, manager=fake_manager)

    with patch("arodonata.cache.lock_manager.datetime") as mock_dt:
        mock_dt.now.return_value = acquired_at + timedelta(seconds=30)  # exactly 50%
        result = await ctx.renew_if_needed(threshold=0.5)

    assert result is False
    fake_manager.renew_lock.assert_not_called()


# --------------------------------------------------------------------------
# get_current_lock_context (outside any decorated function)
# --------------------------------------------------------------------------


def test_get_current_lock_context_returns_none_by_default() -> None:
    assert get_current_lock_context() is None


# --------------------------------------------------------------------------
# DatabaseLockManager - acquire / release / is_lock_held
# --------------------------------------------------------------------------


async def test_acquire_and_release_lock_happy_path(db_manager: DatabaseManager) -> None:
    manager = DatabaseLockManager(db_manager)

    lock = await manager.acquire_lock("happy-key", timeout=5, ttl=30)

    assert lock.lock_key == "happy-key"
    assert lock.owner_id == manager._owner_id
    assert await manager.is_lock_held("happy-key", lock.owner_id) is True

    await manager.release_lock("happy-key", lock.owner_id)

    assert await manager.is_lock_held("happy-key", lock.owner_id) is False


async def test_acquire_context_manager_releases_on_exit(db_manager: DatabaseManager) -> None:
    manager = DatabaseLockManager(db_manager)

    async with manager.acquire("ctx-key", timeout=5, ttl=30) as lock:
        assert isinstance(lock, LockContext)
        assert await manager.is_lock_held("ctx-key", lock.owner_id) is True

    assert await manager.is_lock_held("ctx-key", lock.owner_id) is False


async def test_release_lock_raises_on_ownership_mismatch(db_manager: DatabaseManager) -> None:
    manager = DatabaseLockManager(db_manager)
    lock = await manager.acquire_lock("rel-key", timeout=5, ttl=30)

    with pytest.raises(LockOwnershipError):
        await manager.release_lock("rel-key", "someone-else")

    # Lock must still be held by its original owner after the failed release.
    assert await manager.is_lock_held("rel-key", lock.owner_id) is True


async def test_release_lock_is_idempotent_when_missing(db_manager: DatabaseManager) -> None:
    manager = DatabaseLockManager(db_manager)
    # Releasing a lock key that was never acquired must not raise.
    await manager.release_lock("never-acquired", "some-owner")


# --------------------------------------------------------------------------
# DatabaseLockManager - contention
# --------------------------------------------------------------------------


async def test_acquire_lock_raises_on_contention_after_timeout(
    db_manager: DatabaseManager,
) -> None:
    """A second acquire on an already-held key eventually raises LockAcquisitionError.

    asyncio.sleep is patched to a no-op so the retry/backoff loop never
    performs a real wait; the short `timeout` value bounds the loop.
    """
    manager = DatabaseLockManager(db_manager)
    held = await manager.acquire_lock("busy-key", timeout=30, ttl=60)

    with (
        patch("arodonata.cache.lock_manager.asyncio.sleep", AsyncMock()),
        pytest.raises(LockAcquisitionError) as exc_info,
    ):
        await manager.acquire_lock("busy-key", timeout=0.05, ttl=60)

    assert exc_info.value.lock_key == "busy-key"
    assert exc_info.value.timeout == 0.05

    await manager.release_lock("busy-key", held.owner_id)


async def test_acquire_lock_for_different_key_is_not_blocked_by_contended_key(
    db_manager: DatabaseManager,
) -> None:
    """A slow/contended acquisition on one key must not block a concurrent
    acquisition on an unrelated key.

    Regression test: DatabaseLockManager previously serialized ALL lock
    acquisitions (regardless of key) behind a single process-wide
    asyncio.Lock held for the full retry-until-timeout loop, so one
    contended key head-of-line blocked every other key in the same process.
    """
    manager = DatabaseLockManager(db_manager)
    held = await manager.acquire_lock("key-a", timeout=5, ttl=60)

    contended_task = asyncio.create_task(manager.acquire_lock("key-a", timeout=0.3, ttl=60))
    await asyncio.sleep(0.05)  # let it enter its retry loop

    other = await asyncio.wait_for(manager.acquire_lock("key-b", timeout=1, ttl=60), timeout=0.15)
    assert other.lock_key == "key-b"

    with pytest.raises(LockAcquisitionError):
        await contended_task

    await manager.release_lock("key-a", held.owner_id)
    await manager.release_lock("key-b", other.owner_id)


# --------------------------------------------------------------------------
# DatabaseLockManager - renew_lock
# --------------------------------------------------------------------------


async def test_renew_lock_extends_expiration(db_manager: DatabaseManager) -> None:
    manager = DatabaseLockManager(db_manager)
    lock = await manager.acquire_lock("renew-key", timeout=5, ttl=30)

    renewed = await manager.renew_lock("renew-key", lock.owner_id, ttl=120)

    assert renewed is True
    async with db_manager.session() as session:
        result = await session.execute(select(DistributedLock).where(DistributedLock.lock_key == "renew-key"))
        row = result.scalar_one()
        assert row.expires_at > lock.expires_at


async def test_renew_lock_raises_on_ownership_mismatch(db_manager: DatabaseManager) -> None:
    manager = DatabaseLockManager(db_manager)
    await manager.acquire_lock("own-key", timeout=5, ttl=30)

    with pytest.raises(LockOwnershipError):
        await manager.renew_lock("own-key", "someone-else", ttl=60)


async def test_renew_lock_returns_false_when_missing(db_manager: DatabaseManager) -> None:
    manager = DatabaseLockManager(db_manager)
    result = await manager.renew_lock("missing-key", "some-owner", ttl=60)
    assert result is False


async def test_renew_lock_uses_default_ttl_when_not_specified(db_manager: DatabaseManager) -> None:
    manager = DatabaseLockManager(db_manager)
    lock = await manager.acquire_lock("default-ttl-key", timeout=5, ttl=30)

    await manager.renew_lock("default-ttl-key", lock.owner_id)

    async with db_manager.session() as session:
        result = await session.execute(select(DistributedLock).where(DistributedLock.lock_key == "default-ttl-key"))
        row = result.scalar_one()
        expected_min_expiry = datetime.now(UTC).replace(tzinfo=None) + timedelta(
            seconds=manager.DEFAULT_TTL_ASSET_REFRESH - 5
        )
        assert row.expires_at > expected_min_expiry


# --------------------------------------------------------------------------
# DatabaseLockManager - cleanup of expired locks (now handled by the upsert's
# WHERE clause in _try_acquire; see test_acquire_steals_expired_lock below)
# --------------------------------------------------------------------------


async def test_acquire_lock_succeeds_after_previous_lock_expired(
    db_manager: DatabaseManager,
) -> None:
    """A new acquire_lock call cleans up an expired row for the same key first."""
    manager = DatabaseLockManager(db_manager)
    past = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=10)

    async with db_manager.session() as session:
        session.add(DistributedLock(lock_key="expired-key", owner_id="old-owner", acquired_at=past, expires_at=past))

    lock = await manager.acquire_lock("expired-key", timeout=5, ttl=30)

    assert lock.owner_id == manager._owner_id
    assert await manager.is_lock_held("expired-key", lock.owner_id) is True


async def test_acquire_steals_expired_lock(db_manager: DatabaseManager) -> None:
    """An expired lock row is atomically replaced by the new owner."""
    manager = DatabaseLockManager(db_manager)
    past = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=10)
    async with db_manager.session() as session:
        session.add(
            DistributedLock(
                lock_key="steal-me",
                owner_id="dead-owner",
                acquired_at=past - timedelta(seconds=60),
                expires_at=past,
            )
        )

    lock = await manager.acquire_lock("steal-me", timeout=2, ttl=30)

    assert lock.owner_id == manager._owner_id
    async with db_manager.session() as session:
        row = (
            await session.execute(select(DistributedLock).where(DistributedLock.lock_key == "steal-me"))
        ).scalar_one()
    assert row.owner_id == manager._owner_id
    assert row.expires_at > datetime.now(UTC).replace(tzinfo=None)


async def test_acquire_blocked_by_live_lock_raises_after_timeout(db_manager: DatabaseManager) -> None:
    """A live lock held by another owner still blocks until timeout."""
    manager = DatabaseLockManager(db_manager)
    future = datetime.now(UTC).replace(tzinfo=None) + timedelta(seconds=300)
    async with db_manager.session() as session:
        session.add(
            DistributedLock(
                lock_key="held",
                owner_id="live-owner",
                acquired_at=datetime.now(UTC).replace(tzinfo=None),
                expires_at=future,
            )
        )

    with pytest.raises(LockAcquisitionError):
        await manager.acquire_lock("held", timeout=1, ttl=30)

    # Original owner untouched
    async with db_manager.session() as session:
        row = (await session.execute(select(DistributedLock).where(DistributedLock.lock_key == "held"))).scalar_one()
    assert row.owner_id == "live-owner"


async def test_acquire_fresh_key_inserts_row(db_manager: DatabaseManager) -> None:
    """Acquiring an unheld key inserts the row and returns a valid context."""
    manager = DatabaseLockManager(db_manager)
    lock = await manager.acquire_lock("fresh", timeout=2, ttl=30)
    assert lock.lock_key == "fresh"
    async with db_manager.session() as session:
        row = (await session.execute(select(DistributedLock).where(DistributedLock.lock_key == "fresh"))).scalar_one()
    assert row.owner_id == manager._owner_id


# --------------------------------------------------------------------------
# DatabaseLockManager - unknown-rowcount (-1) DBAPI quirk
#
# Some DBAPI drivers report `rowcount == -1` ("unknown") for RETURNING-less
# DML instead of a real count. `_try_acquire` must not treat that as failure:
# a false "held by someone else" would make the caller retry forever against
# the row it itself just wrote, self-deadlocking until the TTL expires.
# `_try_acquire` verifies via a SELECT in that case instead of trusting -1.
# --------------------------------------------------------------------------


async def test_acquire_succeeds_when_driver_reports_unknown_rowcount(
    db_manager: DatabaseManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """rowcount == -1 on a genuinely-successful upsert must not be mistaken for failure."""
    from sqlalchemy.engine.cursor import CursorResult

    manager = DatabaseLockManager(db_manager)
    monkeypatch.setattr(CursorResult, "rowcount", property(lambda self: -1))

    lock = await manager.acquire_lock("unknown-rowcount-key", timeout=2, ttl=30)

    assert lock.owner_id == manager._owner_id
    async with db_manager.session() as session:
        row = (
            await session.execute(select(DistributedLock).where(DistributedLock.lock_key == "unknown-rowcount-key"))
        ).scalar_one()
    assert row.owner_id == manager._owner_id


async def test_acquire_blocked_by_live_lock_when_driver_reports_unknown_rowcount(
    db_manager: DatabaseManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The -1/unknown-rowcount verification path must still correctly report
    failure (not just false-positive success) when the lock is genuinely
    held by a live owner."""
    from sqlalchemy.engine.cursor import CursorResult

    manager = DatabaseLockManager(db_manager)
    future = datetime.now(UTC).replace(tzinfo=None) + timedelta(seconds=300)
    async with db_manager.session() as session:
        session.add(
            DistributedLock(
                lock_key="held-unknown-rowcount",
                owner_id="live-owner",
                acquired_at=datetime.now(UTC).replace(tzinfo=None),
                expires_at=future,
            )
        )

    monkeypatch.setattr(CursorResult, "rowcount", property(lambda self: -1))

    with (
        patch("arodonata.cache.lock_manager.asyncio.sleep", AsyncMock()),
        pytest.raises(LockAcquisitionError),
    ):
        await manager.acquire_lock("held-unknown-rowcount", timeout=0.05, ttl=30)

    async with db_manager.session() as session:
        row = (
            await session.execute(select(DistributedLock).where(DistributedLock.lock_key == "held-unknown-rowcount"))
        ).scalar_one()
    assert row.owner_id == "live-owner"


async def test_release_succeeds_when_driver_reports_unknown_rowcount(
    db_manager: DatabaseManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """rowcount == -1 on a DELETE whose row still exists (still owned by us)
    afterward must not be mistaken for an ownership failure.

    Unlike the acquire/renew unknown-rowcount cases, a real DELETE that
    matches genuinely removes the row - so merely patching
    `CursorResult.rowcount` on a real DELETE (as the acquire/renew tests do)
    would still leave the follow-up SELECT finding nothing, hitting the
    already-idempotent "not found" path instead of the "we own it, rowcount
    was ambiguous" path this test targets. To reach that path, the *first*
    DELETE is faked as a no-op reporting rowcount=-1 (row deliberately left
    in place); the SELECT then finds the still-present, still-owned-by-us
    row, and the fix's rare-path re-run performs the real DELETE.
    """
    from sqlalchemy import Delete
    from sqlalchemy.ext.asyncio import AsyncSession

    manager = DatabaseLockManager(db_manager)
    lock = await manager.acquire_lock("release-unknown-rowcount-key", timeout=2, ttl=30)

    real_execute = AsyncSession.execute
    delete_calls = [0]

    class _FakeUnknownRowcountResult:
        rowcount = -1

    async def fake_execute(self, stmt, *args, **kwargs):
        if isinstance(stmt, Delete):
            delete_calls[0] += 1
            if delete_calls[0] == 1:
                # First DELETE: fake a no-op with an ambiguous rowcount -
                # the row is deliberately left in place to model the quirk.
                return _FakeUnknownRowcountResult()
        return await real_execute(self, stmt, *args, **kwargs)

    monkeypatch.setattr(AsyncSession, "execute", fake_execute)

    # Must not raise LockOwnershipError.
    await manager.release_lock("release-unknown-rowcount-key", lock.owner_id)

    # The rare path's re-run DELETE (the second, real one) must have
    # actually removed the row.
    assert delete_calls[0] == 2
    monkeypatch.undo()
    async with db_manager.session() as session:
        row = (
            await session.execute(
                select(DistributedLock).where(DistributedLock.lock_key == "release-unknown-rowcount-key")
            )
        ).scalar_one_or_none()
    assert row is None


async def test_renew_succeeds_when_driver_reports_unknown_rowcount(
    db_manager: DatabaseManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """rowcount == -1 on a genuinely-successful UPDATE must not be mistaken
    for an ownership failure. The rare path's SELECT finds the row WE own,
    so renew must return True rather than raise LockOwnershipError."""
    from sqlalchemy.engine.cursor import CursorResult

    manager = DatabaseLockManager(db_manager)
    lock = await manager.acquire_lock("renew-unknown-rowcount-key", timeout=2, ttl=30)

    monkeypatch.setattr(CursorResult, "rowcount", property(lambda self: -1))

    renewed = await manager.renew_lock("renew-unknown-rowcount-key", lock.owner_id, ttl=60)

    assert renewed is True


# --------------------------------------------------------------------------
# _build_acquire_stmt - dialect-compile coverage (no live DB connection
# required; covers the postgresql path that no fixture in this file exercises)
# --------------------------------------------------------------------------


def test_build_acquire_stmt_compiles_for_postgresql() -> None:
    from sqlalchemy.dialects import postgresql

    from arodonata.cache.lock_manager import _build_acquire_stmt

    now = datetime(2026, 1, 1, 0, 0, 0)
    expires_at = now + timedelta(seconds=30)
    stmt = _build_acquire_stmt("postgresql", "pg-key", "pg-owner", now, expires_at)

    compiled = str(stmt.compile(dialect=postgresql.dialect()))

    assert "ON CONFLICT" in compiled
    assert "DO UPDATE" in compiled
    assert "WHERE" in compiled
    assert "expires_at" in compiled


def test_build_acquire_stmt_compiles_for_sqlite() -> None:
    from sqlalchemy.dialects import sqlite

    from arodonata.cache.lock_manager import _build_acquire_stmt

    now = datetime(2026, 1, 1, 0, 0, 0)
    expires_at = now + timedelta(seconds=30)
    stmt = _build_acquire_stmt("sqlite", "sqlite-key", "sqlite-owner", now, expires_at)

    compiled = str(stmt.compile(dialect=sqlite.dialect()))

    assert "ON CONFLICT" in compiled
    assert "DO UPDATE" in compiled
    assert "WHERE" in compiled
    assert "expires_at" in compiled


def test_build_acquire_stmt_raises_for_unsupported_dialect() -> None:
    from arodonata.cache.lock_manager import _build_acquire_stmt

    now = datetime(2026, 1, 1, 0, 0, 0)
    with pytest.raises(NotImplementedError, match="mysql"):
        _build_acquire_stmt("mysql", "k", "o", now, now)


# --------------------------------------------------------------------------
# DatabaseLockManager - initialize / close
# --------------------------------------------------------------------------


async def test_initialize_delegates_to_db_manager(db_manager: DatabaseManager) -> None:
    manager = DatabaseLockManager(db_manager)
    await manager.initialize()
    assert db_manager.is_initialized is True


async def test_close_is_a_noop(db_manager: DatabaseManager) -> None:
    manager = DatabaseLockManager(db_manager)
    await manager.close()  # must not raise


# --------------------------------------------------------------------------
# distributed_lock decorator (goes through the autouse-mocked global accessor
# from tests/unit/conftest.py — that is the seam it exists to exercise).
# --------------------------------------------------------------------------


async def test_distributed_lock_decorator_happy_path(mock_lock_manager: AsyncMock) -> None:
    @distributed_lock("widget:{name}", timeout=10, ttl=20)
    async def do_work(name: str) -> str:
        ctx = get_current_lock_context()
        assert ctx is mock_lock_manager.acquire_lock.return_value
        return f"done-{name}"

    result = await do_work(name="alpha")

    assert result == "done-alpha"
    mock_lock_manager.acquire_lock.assert_awaited_once_with("widget:alpha", 10, 20)
    mock_lock_manager.release_lock.assert_awaited_once()
    # Context var must be reset after the call completes.
    assert get_current_lock_context() is None


async def test_distributed_lock_uses_manager_default_ttl_when_not_specified(
    mock_lock_manager: AsyncMock,
) -> None:
    @distributed_lock("widget:{name}")
    async def do_work(name: str) -> str:
        return name

    await do_work(name="beta")

    mock_lock_manager.acquire_lock.assert_awaited_once_with("widget:beta", 30, 300)


async def test_distributed_lock_key_template_supports_positional_args(
    mock_lock_manager: AsyncMock,
) -> None:
    @distributed_lock("widget:{name}")
    async def do_work(name: str) -> str:
        return name

    await do_work("zeta")

    mock_lock_manager.acquire_lock.assert_awaited_once_with("widget:zeta", 30, 300)


async def test_distributed_lock_missing_template_param_raises_value_error(
    mock_lock_manager: AsyncMock,
) -> None:
    @distributed_lock("widget:{missing_param}")
    async def do_work(name: str) -> str:
        return name

    with pytest.raises(ValueError, match="missing_param"):
        await do_work(name="alpha")


async def test_distributed_lock_plain_function_propagates_release_failure(
    mock_lock_manager: AsyncMock,
) -> None:
    """Unlike the async-generator wrapper, a plain function's release failure
    is NOT swallowed - it propagates to the caller."""
    mock_lock_manager.release_lock = AsyncMock(side_effect=RuntimeError("release boom"))

    @distributed_lock("widget:{name}")
    async def do_work(name: str) -> str:
        return name

    with pytest.raises(RuntimeError, match="release boom"):
        await do_work(name="epsilon")


async def test_distributed_lock_async_generator_happy_path(mock_lock_manager: AsyncMock) -> None:
    @distributed_lock("stream:{name}")
    async def stream(name: str) -> AsyncGenerator[str]:
        yield "a"
        yield "b"

    items = [item async for item in stream(name="gamma")]

    assert items == ["a", "b"]
    mock_lock_manager.acquire_lock.assert_awaited_once_with("stream:gamma", 30, 300)
    mock_lock_manager.release_lock.assert_awaited_once()


async def test_distributed_lock_async_generator_logs_release_failure(
    mock_lock_manager: AsyncMock,
) -> None:
    """A release failure during generator cleanup is logged, not raised, and
    must not mask the generator's own yielded values."""
    mock_lock_manager.release_lock = AsyncMock(side_effect=RuntimeError("db down"))

    @distributed_lock("stream:{name}")
    async def stream(name: str) -> AsyncGenerator[str]:
        yield "x"
        yield "y"

    with patch("arodonata.cache.lock_manager.log") as mock_log:
        items = [item async for item in stream(name="delta")]

    assert items == ["x", "y"]
    mock_log.return_value.warning.assert_called_once()
    warning_msg = mock_log.return_value.warning.call_args.args[0]
    assert "stream:delta" in warning_msg
    assert "db down" in warning_msg
