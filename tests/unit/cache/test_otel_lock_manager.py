"""OTEL span tests for DatabaseLockManager: incident-grade lock diagnostics."""

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from arodonata.cache.database import DatabaseManager
from arodonata.cache.lock_manager import DatabaseLockManager, LockAcquisitionError


@pytest.fixture
async def lock_manager():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    manager = DatabaseLockManager(DatabaseManager(engine))
    await manager.initialize()
    yield manager
    await engine.dispose()


async def test_acquire_release_spans_with_lock_attrs(otel_spans, lock_manager):
    ctx = await lock_manager.acquire_lock("login:mgmt1:", timeout=5, ttl=30)
    await lock_manager.release_lock("login:mgmt1:", ctx.owner_id)
    spans = {s.name: s for s in otel_spans.get_finished_spans()}
    acquire = next(s for n, s in spans.items() if n.endswith("acquire_lock"))
    assert acquire.attributes["arodonata.lock.key"] == "login:mgmt1:"
    assert acquire.attributes["arodonata.lock.ttl"] == 30
    assert acquire.attributes["arodonata.lock.attempts"] == 0
    assert acquire.attributes["arodonata.lock.wait_seconds"] >= 0


async def test_acquisition_timeout_records_error_with_wait_context(otel_spans, lock_manager):
    await lock_manager.acquire_lock("contended", timeout=5, ttl=60)
    other = DatabaseLockManager(lock_manager._db_manager)
    with pytest.raises(LockAcquisitionError):
        await other.acquire_lock("contended", timeout=1, ttl=60)
    spans = [
        s
        for s in otel_spans.get_finished_spans()
        if s.name.endswith("acquire_lock") and s.status.status_code.name == "ERROR"
    ]
    assert len(spans) == 1
    assert spans[0].attributes["arodonata.lock.attempts"] >= 1
    assert spans[0].attributes["arodonata.lock.wait_seconds"] >= 1
    assert any(e.name == "exception" for e in spans[0].events)


async def test_acquire_steal_emits_only_acquire_lock_span(otel_spans, lock_manager):
    """Stealing an expired lock is a single atomic upsert inside acquire_lock -
    there is no more separate _cleanup_expired_lock span.

    The seeded row is given a distinct fake owner ("dead-owner") rather than
    being written via `lock_manager.acquire_lock(...)`: both DatabaseLockManager
    instances in this test share one process, so `generate_owner_id()` (which
    derives from hostname:pid:worker_id) returns the SAME value for both -
    `ctx.owner_id == other._owner_id` would be tautologically true regardless
    of whether a steal actually happened. Seeding a different owner and then
    asserting the row's owner_id in the DB actually changed proves the steal
    occurred.
    """
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    from arodonata.cache.models import DistributedLock

    past = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=1)
    async with lock_manager._db_manager.session() as session:
        session.add(
            DistributedLock(
                lock_key="short",
                owner_id="dead-owner",
                acquired_at=past - timedelta(seconds=30),
                expires_at=past,
            )
        )

    other = DatabaseLockManager(lock_manager._db_manager)
    ctx = await other.acquire_lock("short", timeout=5, ttl=30)

    assert ctx.owner_id == other._owner_id
    async with lock_manager._db_manager.session() as session:
        row = (await session.execute(select(DistributedLock).where(DistributedLock.lock_key == "short"))).scalar_one()
    assert row.owner_id == other._owner_id
    assert row.owner_id != "dead-owner"

    span_names = [s.name for s in otel_spans.get_finished_spans()]
    assert not any(n.endswith("_cleanup_expired_lock") for n in span_names)
    assert sum(n.endswith("acquire_lock") for n in span_names) == 1


async def test_lock_flow_works_without_provider(lock_manager):
    # NOTE: does not genuinely prove the no-provider case in-process (see
    # test_traced_code_runs_correctly_with_no_provider_configured in
    # tests/unit/api/test_otel_client_surface.py for the real subprocess
    # coverage). Still validates correct return values regardless.
    ctx = await lock_manager.acquire_lock("noprov", timeout=5, ttl=30)
    await lock_manager.release_lock("noprov", ctx.owner_id)
