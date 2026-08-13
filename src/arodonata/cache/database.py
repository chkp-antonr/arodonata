"""SQLModel async database engine and session management.

This module provides the database connection infrastructure.
All other modules access the database through CacheRepository.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)
from sqlmodel import SQLModel

from ..logger import lazy_logger
from .models import DistributedLock, SchemaVersion  # noqa: F401

log = lazy_logger("arodonata.cache.database")


def _build_schema_version_upsert_stmt(
    dialect_name: str,
    schema_hash: str,
    updated_at: datetime,
) -> Any | None:
    """Build the dialect-specific INSERT ... ON CONFLICT DO UPDATE upsert for
    arodonata_schema_version, keyed on `schema_hash` (the table's primary key).

    Extracted as a standalone helper (rather than inlined in
    `_store_schema_hash`) so it can be exercised directly by dialect-compile
    tests without a live database connection — same pattern as
    `_build_acquire_stmt` in lock_manager.py.

    Args:
        dialect_name: SQLAlchemy dialect name (`engine.dialect.name`), e.g.
            "postgresql" or "sqlite".
        schema_hash: SHA-256 hash of the applied model metadata (primary key).
        updated_at: Naive UTC timestamp to write on insert/update.

    Returns:
        An `Insert` construct with `.on_conflict_do_update(...)` applied,
        ready to `session.execute(...)`, or None if `dialect_name` is neither
        "postgresql" nor "sqlite" (caller falls back to SELECT-then-write).
    """
    table = SchemaVersion.__table__  # type: ignore[attr-defined]

    if dialect_name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as dialect_insert
    elif dialect_name == "sqlite":
        from sqlalchemy.dialects.sqlite import insert as dialect_insert  # type: ignore[assignment]
    else:
        return None

    return (
        dialect_insert(table)
        .values(schema_hash=schema_hash, updated_at=updated_at)
        .on_conflict_do_update(
            index_elements=[table.c.schema_hash],
            set_={"updated_at": updated_at},
        )
    )


class DatabaseManager:
    """Manages database sessions from pre-configured engine.

    Applications create and own the AsyncEngine lifecycle.
    This class wraps the engine and provides session management.

    Example:
        from sqlalchemy.ext.asyncio import create_async_engine

        # Main app creates engine from its own config
        engine = create_async_engine("postgresql+asyncpg://...")

        db = DatabaseManager(engine)
        await db.initialize()

        async with db.session() as session:
            # Use session for queries
            pass

        # Note: App is responsible for disposing the engine
        await engine.dispose()
    """

    def __init__(self, engine: AsyncEngine) -> None:
        """Initialize database manager with pre-configured engine.

        Args:
            engine: Pre-configured AsyncEngine instance owned by the application.
                   The application is responsible for disposing this engine.
        """
        self._engine = engine
        self._sessionmaker = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        self._init_lock = asyncio.Lock()
        self._initialized = False

    @property
    def engine(self) -> AsyncEngine:
        """Get the underlying engine."""
        return self._engine

    @property
    def is_initialized(self) -> bool:
        """Check if database tables have been initialized."""
        return self._initialized

    async def initialize(self) -> None:
        """Create database tables if needed and add any missing columns.

        Fast path: when the stored schema hash in arodonata_schema_version
        matches the hash of the currently registered SQLModel metadata, the
        per-table migration scan is skipped entirely (1 round trip).
        Set ARODONATA_FORCE_SCHEMA_SCAN=1 to force the full scan.
        """
        if self._initialized:
            return

        async with self._init_lock:
            if self._initialized:
                return

            import os

            from ..db_utils import ensure_missing_columns
            from .schema_version import compute_schema_hash

            current_hash = compute_schema_hash(SQLModel.metadata)
            force_scan = bool(os.environ.get("ARODONATA_FORCE_SCHEMA_SCAN"))

            if force_scan:
                log().info("ARODONATA_FORCE_SCHEMA_SCAN set; running full migration scan")
            elif await self._stored_hash_matches(current_hash):
                log().debug("Schema hash matches; skipping migration scan")
                self._initialized = True
                return
            else:
                log().info(
                    "No stored schema hash matches this metadata "
                    f"(hash={current_hash[:12]}...); running full migration scan"
                )

            log().debug("Creating database tables if needed")

            # First pass: create any tables that don't exist yet.
            async with self._engine.begin() as conn:
                await conn.run_sync(SQLModel.metadata.create_all)

            # Add columns and indexes present in each registered model but
            # missing from its live table (handles upgrades; safe on fresh
            # DBs — no-op when complete). Applied to every table in
            # SQLModel's shared metadata, not just arodonata's own models, so
            # consuming applications' tables get the same auto-migration
            # without arodonata needing to import their model classes.
            for table in SQLModel.metadata.tables.values():
                await ensure_missing_columns(self._engine, table)

            # Second pass: create any indexes that are now satisfiable after the
            # column additions above (no-op on tables already fully up to date).
            async with self._engine.begin() as conn:
                await conn.run_sync(SQLModel.metadata.create_all)

            await self._store_schema_hash(current_hash)

            self._initialized = True
            log().debug("Database tables initialized")

    async def _stored_hash_matches(self, current_hash: str) -> bool:
        """Return True if arodonata_schema_version has a row for current_hash.

        Any failure (missing table on a fresh DB, connection hiccup) returns
        False so init degrades to the full scan — never blocks startup.
        """
        from sqlalchemy import select

        try:
            async with self._sessionmaker() as session:
                stmt = select(SchemaVersion).where(SchemaVersion.schema_hash == current_hash)  # type: ignore
                row = (await session.execute(stmt)).scalar_one_or_none()
                return row is not None
        except Exception as e:  # noqa: BLE001 - degrade to full scan on any failure
            log().debug(f"Schema version check failed ({e}); running full scan")
            return False

    async def _store_schema_hash(self, current_hash: str) -> None:
        """Upsert the arodonata_schema_version row keyed on current_hash.

        Row-per-hash (schema_hash is the primary key): each distinct metadata
        hash gets its own row, so processes registering different model sets
        against the same DB never overwrite each other's stored hash.

        Uses dialect-aware atomic upsert (INSERT ... ON CONFLICT DO UPDATE)
        built by `_build_schema_version_upsert_stmt` (same pattern as
        `_build_acquire_stmt` in lock_manager.py) to be concurrency-safe
        across multiple DatabaseManager instances. On failure, logs a warning
        and returns — hash store failures never block initialization (next
        init will re-scan if the hash is missing).
        """
        from datetime import UTC, datetime

        try:
            now = datetime.now(UTC).replace(tzinfo=None)
            dialect_name = self._engine.dialect.name
            stmt = _build_schema_version_upsert_stmt(dialect_name, current_hash, now)

            if stmt is not None:
                async with self._sessionmaker() as session:
                    await session.execute(stmt)
                    await session.commit()
                return

            # Fallback for unsupported dialects: SELECT-then-write (not
            # atomic, but better than crashing; this whole method is called
            # from inside initialize()'s effective try/except so failures
            # here just mean the next init() re-scans).
            from sqlalchemy import select

            async with self._sessionmaker() as session:
                sel_stmt = select(SchemaVersion).where(
                    SchemaVersion.schema_hash == current_hash  # type: ignore
                )
                row = (await session.execute(sel_stmt)).scalar_one_or_none()
                if row is None:
                    session.add(SchemaVersion(schema_hash=current_hash, updated_at=now))
                else:
                    row.updated_at = now
                await session.commit()
        except Exception as e:  # noqa: BLE001 - never fail startup
            log().warning(f"Failed to store schema hash ({e}); next init will re-scan")

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession]:
        """Get an async database session.

        Yields:
            AsyncSession for database operations.

        Raises:
            RuntimeError: If database not initialized.
        """
        if not self._sessionmaker:
            raise RuntimeError("DatabaseManager not properly initialized")

        async with self._sessionmaker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise


__all__ = ["DatabaseManager"]
