"""Tests for DatabaseManager (async engine/session management)."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlmodel import Field, SQLModel

from arodonata.cache.database import DatabaseManager, _build_schema_version_upsert_stmt
from arodonata.cache.models import SchemaVersion
from arodonata.cache.schema_version import compute_schema_hash


class _Widget(SQLModel, table=True):
    """Local model used to prove sessions can read/write real tables."""

    __tablename__ = "db_manager_test_widget"  # type: ignore[assignment]

    id: int = Field(primary_key=True)
    name: str = Field(default="")


@pytest.fixture
async def engine() -> AsyncGenerator[AsyncEngine]:
    """In-memory SQLite async engine, disposed after the test."""
    eng = create_async_engine("sqlite+aiosqlite:///:memory:")
    yield eng
    await eng.dispose()


@pytest.fixture
async def db_manager(engine: AsyncEngine) -> DatabaseManager:
    manager = DatabaseManager(engine)
    await manager.initialize()
    return manager


async def test_is_initialized_false_before_initialize(engine: AsyncEngine) -> None:
    """is_initialized reports False until initialize() has run."""
    manager = DatabaseManager(engine)
    assert manager.is_initialized is False


async def test_initialize_sets_is_initialized_true(db_manager: DatabaseManager) -> None:
    """initialize() flips is_initialized to True."""
    assert db_manager.is_initialized is True


async def test_initialize_is_idempotent(db_manager: DatabaseManager) -> None:
    """Calling initialize() a second time is a safe no-op."""
    await db_manager.initialize()
    assert db_manager.is_initialized is True


def test_engine_property_returns_underlying_engine(engine: AsyncEngine) -> None:
    """engine property exposes the exact engine passed to the constructor."""
    manager = DatabaseManager(engine)
    assert manager.engine is engine


async def test_session_yields_working_async_session(db_manager: DatabaseManager) -> None:
    """session() yields an AsyncSession that can execute queries and commits on exit."""
    async with db_manager.session() as session:
        widget = _Widget(id=1, name="alpha")
        session.add(widget)

    # New session sees the committed row.
    async with db_manager.session() as session:
        result = await session.execute(text("SELECT name FROM db_manager_test_widget WHERE id=1"))
        row = result.fetchone()
        assert row is not None
        assert row[0] == "alpha"


async def test_session_rolls_back_on_exception(db_manager: DatabaseManager) -> None:
    """An exception inside the session block triggers a rollback and propagates."""
    with pytest.raises(RuntimeError, match="boom"):
        async with db_manager.session() as session:
            widget = _Widget(id=2, name="beta")
            session.add(widget)
            raise RuntimeError("boom")

    async with db_manager.session() as session:
        result = await session.execute(text("SELECT COUNT(*) FROM db_manager_test_widget WHERE id=2"))
        assert result.scalar_one() == 0


async def test_session_raises_when_sessionmaker_missing(engine: AsyncEngine) -> None:
    """session() raises RuntimeError if the sessionmaker was cleared out."""
    manager = DatabaseManager(engine)
    manager._sessionmaker = None  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="not properly initialized"):
        async with manager.session():
            pass


# --------------------------------------------------------------------------
# _build_schema_version_upsert_stmt - dialect-compile coverage (no live DB
# connection required; covers the postgresql path that no fixture in this
# file exercises, since the fixtures here are all sqlite+aiosqlite).
# --------------------------------------------------------------------------


def test_store_schema_hash_compiles_for_postgresql() -> None:
    from datetime import datetime

    from sqlalchemy.dialects import postgresql

    stmt = _build_schema_version_upsert_stmt("postgresql", "a" * 64, datetime(2026, 1, 1))

    compiled = str(stmt.compile(dialect=postgresql.dialect()))

    assert "ON CONFLICT" in compiled
    assert "DO UPDATE" in compiled
    assert "schema_hash" in compiled


def test_store_schema_hash_compiles_for_sqlite() -> None:
    from datetime import datetime

    from sqlalchemy.dialects import sqlite

    stmt = _build_schema_version_upsert_stmt("sqlite", "b" * 64, datetime(2026, 1, 1))

    compiled = str(stmt.compile(dialect=sqlite.dialect()))

    assert "ON CONFLICT" in compiled
    assert "DO UPDATE" in compiled
    assert "schema_hash" in compiled


def test_build_schema_version_upsert_stmt_returns_none_for_unsupported_dialect() -> None:
    """Unsupported dialects fall back to SELECT-then-write in _store_schema_hash."""
    from datetime import datetime

    assert _build_schema_version_upsert_stmt("mysql", "c" * 64, datetime(2026, 1, 1)) is None


async def test_store_schema_hash_uses_select_then_write_fallback_for_unsupported_dialect(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The unsupported-dialect (`else`) branch of _store_schema_hash is
    exercised directly by forcing the engine's dialect name off the sqlite
    fixture, covering the previously-untested fallback path."""
    manager = DatabaseManager(engine)
    await manager.initialize()

    monkeypatch.setattr(type(manager.engine.dialect), "name", "mysql", raising=False)

    new_hash = "d" * 64
    await manager._store_schema_hash(new_hash)

    async with manager.session() as session:
        stmt = select(SchemaVersion).where(SchemaVersion.schema_hash == new_hash)  # type: ignore
        row = (await session.execute(stmt)).scalar_one()
    assert row.schema_hash == new_hash

    # Calling again exercises the "row already exists" (else) branch of the
    # fallback's SELECT-then-write, updating updated_at in place.
    await manager._store_schema_hash(new_hash)
    async with manager.session() as session:
        stmt = select(SchemaVersion).where(SchemaVersion.schema_hash == new_hash)  # type: ignore
        rows = (await session.execute(stmt)).scalars().all()
    assert len(rows) == 1


async def test_initialize_stores_schema_hash(engine: AsyncEngine) -> None:
    """First initialize() persists the metadata hash in arodonata_schema_version."""
    manager = DatabaseManager(engine)
    await manager.initialize()

    current_hash = compute_schema_hash(SQLModel.metadata)
    async with manager.session() as session:
        stmt = select(SchemaVersion).where(SchemaVersion.schema_hash == current_hash)  # type: ignore
        row = (await session.execute(stmt)).scalar_one()
    assert row.schema_hash == current_hash


async def test_second_initialize_skips_migration_scan(engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch) -> None:
    """A new manager over an already-current DB must not run ensure_missing_columns."""
    await DatabaseManager(engine).initialize()

    scan_spy = AsyncMock()
    monkeypatch.setattr("arodonata.db_utils.ensure_missing_columns", scan_spy)

    manager2 = DatabaseManager(engine)
    await manager2.initialize()

    scan_spy.assert_not_awaited()
    assert manager2.is_initialized


async def test_initialize_rescans_on_hash_mismatch(engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch) -> None:
    """A stale stored hash (no row for the current metadata) triggers the
    full scan, after which a row for the current hash is stored."""
    manager = DatabaseManager(engine)
    await manager.initialize()

    # Simulate a stale row (e.g. left over from an older arodonata version)
    # that does not match the current metadata hash.
    async with manager.session() as session:
        await session.execute(SchemaVersion.__table__.delete())
        session.add(SchemaVersion(schema_hash="0" * 64))
        await session.commit()

    scan_spy = AsyncMock()
    monkeypatch.setattr("arodonata.db_utils.ensure_missing_columns", scan_spy)

    manager2 = DatabaseManager(engine)
    await manager2.initialize()

    scan_spy.assert_awaited()
    current_hash = compute_schema_hash(SQLModel.metadata)
    async with manager2.session() as session:
        stmt = select(SchemaVersion).where(SchemaVersion.schema_hash == current_hash)  # type: ignore
        row = (await session.execute(stmt)).scalar_one()
    assert row.schema_hash == current_hash


async def test_force_env_var_bypasses_fast_path(engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch) -> None:
    """ARODONATA_FORCE_SCHEMA_SCAN forces the scan even when the hash matches."""
    await DatabaseManager(engine).initialize()

    scan_spy = AsyncMock()
    monkeypatch.setattr("arodonata.db_utils.ensure_missing_columns", scan_spy)
    monkeypatch.setenv("ARODONATA_FORCE_SCHEMA_SCAN", "1")

    manager2 = DatabaseManager(engine)
    await manager2.initialize()

    scan_spy.assert_awaited()


async def test_store_schema_hash_is_concurrency_safe(engine: AsyncEngine) -> None:
    """Concurrent INSERT race on fresh table is resolved atomically (no IntegrityError)."""
    import asyncio

    manager1 = DatabaseManager(engine)
    manager2 = DatabaseManager(engine)

    # Initialize to create the table (but not the version row)
    await manager1.initialize()

    # Delete the version row to simulate a fresh state
    async with manager1.session() as session:
        await session.execute(SchemaVersion.__table__.delete())
        await session.commit()

    current_hash = compute_schema_hash(SQLModel.metadata)

    # Both instances race to INSERT the same row concurrently
    # Old code: one raises IntegrityError; new code: both succeed
    await asyncio.gather(
        manager1._store_schema_hash(current_hash),
        manager2._store_schema_hash(current_hash),
    )

    # Verify exactly one row exists with correct hash (atomic upsert succeeded)
    async with manager1.session() as session:
        rows = (await session.execute(select(SchemaVersion))).scalars().all()
    assert len(rows) == 1
    assert rows[0].schema_hash == current_hash


async def test_store_schema_hash_is_row_per_hash(engine: AsyncEngine) -> None:
    """Two different metadata hashes (e.g. different DISABLED_PLUGINS across
    processes sharing one DB) each get their own row instead of clobbering
    each other's — the single mutable-row design would thrash: every init
    would mismatch the other's hash, pay the full scan, and overwrite it."""
    manager = DatabaseManager(engine)
    await manager.initialize()

    hash_a = "a" * 64
    hash_b = "b" * 64
    await manager._store_schema_hash(hash_a)
    await manager._store_schema_hash(hash_b)

    assert await manager._stored_hash_matches(hash_a)
    assert await manager._stored_hash_matches(hash_b)

    async with manager.session() as session:
        rows = (await session.execute(select(SchemaVersion))).scalars().all()
    stored_hashes = {row.schema_hash for row in rows}
    assert hash_a in stored_hashes
    assert hash_b in stored_hashes


async def test_initialize_degrades_gracefully_on_hash_check_failure(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """initialize() completes successfully even if hash check raises (full scan runs)."""
    # First init to set up the DB
    await DatabaseManager(engine).initialize()

    # Monkeypatch the session to raise on the first execute call (the hash check)
    call_count = [0]

    class RaisingSession:
        async def execute(self, stmt):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call (hash check) raises; subsequent calls succeed
                raise RuntimeError("Simulated DB failure in hash check")
            # For subsequent calls (actual migrations), delegate to a real session
            async with engine.begin() as conn:
                return await conn.execute(stmt)

        async def commit(self):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    # Create a custom sessionmaker that returns our raising session
    class MockSessionMaker:
        def __call__(self):
            return RaisingSession()

    scan_spy = AsyncMock()
    monkeypatch.setattr("arodonata.db_utils.ensure_missing_columns", scan_spy)

    manager2 = DatabaseManager(engine)
    manager2._sessionmaker = MockSessionMaker()

    # initialize() should not raise despite hash check failure
    await manager2.initialize()

    # Full scan must have run (hash check degraded to full scan)
    scan_spy.assert_awaited()
    assert manager2.is_initialized


async def test_initialize_degrades_gracefully_on_store_hash_failure(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """initialize() completes successfully even if storing the schema hash
    raises — a hash-store failure must never block startup; the only cost is
    that the next initialize() call re-runs the full scan (mirrors
    test_initialize_degrades_gracefully_on_hash_check_failure above, but for
    the write side instead of the read side of the fast path)."""
    # First init to set up the DB with a real manager.
    await DatabaseManager(engine).initialize()

    class RaisingSession:
        async def execute(self, stmt):
            raise RuntimeError("Simulated DB failure in store hash")

        async def commit(self):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    class MockSessionMaker:
        def __call__(self):
            return RaisingSession()

    scan_spy = AsyncMock()
    monkeypatch.setattr("arodonata.db_utils.ensure_missing_columns", scan_spy)

    manager2 = DatabaseManager(engine)
    manager2._sessionmaker = MockSessionMaker()

    # initialize() should not raise despite both the hash check and the
    # hash store failing against the raising sessionmaker.
    await manager2.initialize()

    scan_spy.assert_awaited()
    assert manager2.is_initialized is True


async def test_store_schema_hash_degrades_gracefully_on_failure(
    engine: AsyncEngine,
) -> None:
    """_store_schema_hash logs and returns without raising when the session
    execute fails, in isolation from initialize()."""
    manager = DatabaseManager(engine)
    await manager.initialize()

    class RaisingSession:
        async def execute(self, stmt):
            raise RuntimeError("Simulated DB failure in store hash")

        async def commit(self):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    class MockSessionMaker:
        def __call__(self):
            return RaisingSession()

    manager._sessionmaker = MockSessionMaker()  # type: ignore[assignment]

    # Must not raise.
    await manager._store_schema_hash("f" * 64)
