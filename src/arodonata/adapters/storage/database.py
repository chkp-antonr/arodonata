"""Database lifecycle manager and SHA-256 schema hash auto-migration (`DatabaseManager`)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import Connection, MetaData, event, inspect, select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from arodonata.adapters.storage import tables as _tables  # noqa: F401
from arodonata.adapters.storage.tables import SchemaVersionRecord
from arodonata.core.models.common import utc_now
from arodonata.core.telemetry import span_attrs, traced

DEFAULT_MEMORY_SQLITE_URL = "sqlite+aiosqlite:///:memory:"


def compute_schema_hash(metadata: MetaData | None = None) -> str:
    """Compute a deterministic SHA-256 hex digest over registered SQLModel tables, columns, and indexes."""
    target_meta = metadata if metadata is not None else SQLModel.metadata
    schema_repr: list[dict[str, Any]] = []

    for table_name in sorted(target_meta.tables.keys()):
        table = target_meta.tables[table_name]
        columns_info = [
            {
                "name": col.name,
                "type": str(col.type),
                "nullable": bool(col.nullable),
                "primary_key": bool(col.primary_key),
            }
            for col in sorted(table.columns, key=lambda c: c.name)
        ]
        indexes_info = [
            {
                "name": idx.name or "",
                "columns": [c.name for c in idx.columns],
                "unique": bool(idx.unique),
            }
            for idx in sorted(table.indexes, key=lambda i: i.name or "")
        ]
        schema_repr.append(
            {
                "table": table_name,
                "columns": columns_info,
                "indexes": indexes_info,
            }
        )

    serialized = json.dumps(schema_repr, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _attach_sqlite_busy_timeout(engine: AsyncEngine, busy_timeout_ms: int) -> None:
    """Configure SQLite connections to enforce a busy timeout (`PRAGMA busy_timeout`)."""
    if engine.dialect.name != "sqlite":
        return

    def _on_connect(dbapi_connection: Any, _connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
        finally:
            cursor.close()

    event.listen(engine.sync_engine, "connect", _on_connect)


class DatabaseManager:
    """Manages SQLAlchemy AsyncEngine, sessions, and SHA-256 schema hash auto-migration."""

    def __init__(
        self,
        engine: AsyncEngine | str | None = None,
        *,
        busy_timeout_ms: int = 30000,
        metadata: MetaData | None = None,
    ) -> None:
        self._busy_timeout_ms = busy_timeout_ms
        self._metadata = metadata if metadata is not None else SQLModel.metadata
        self._initialized = False
        self._last_schema_hash: str | None = None
        self._migration_inspection_count = 0

        if engine is None:
            self._engine = self._create_engine(DEFAULT_MEMORY_SQLITE_URL, busy_timeout_ms=busy_timeout_ms)
            self._owns_engine = True
        elif isinstance(engine, str):
            self._engine = self._create_engine(engine, busy_timeout_ms=busy_timeout_ms)
            self._owns_engine = True
        else:
            self._engine = engine
            self._owns_engine = False
            _attach_sqlite_busy_timeout(self._engine, busy_timeout_ms)

        self._session_factory = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    @staticmethod
    def _create_engine(url: str, *, busy_timeout_ms: int = 30000) -> AsyncEngine:
        """Create an `AsyncEngine` for SQLite or PostgreSQL."""
        if url.startswith("sqlite"):
            is_memory = ":memory:" in url or "mode=memory" in url
            connect_args: dict[str, Any] = {
                "check_same_thread": False,
                "timeout": max(1.0, busy_timeout_ms / 1000.0),
            }
            if is_memory:
                engine = create_async_engine(
                    url,
                    connect_args=connect_args,
                    poolclass=StaticPool,
                )
            else:
                engine = create_async_engine(url, connect_args=connect_args)
            _attach_sqlite_busy_timeout(engine, busy_timeout_ms)
            return engine

        return create_async_engine(url, pool_pre_ping=True)

    @property
    def engine(self) -> AsyncEngine:
        """Return the underlying `AsyncEngine`."""
        return self._engine

    @property
    def owns_engine(self) -> bool:
        """Return `True` if this `DatabaseManager` created and owns the `AsyncEngine`."""
        return self._owns_engine

    @property
    def is_initialized(self) -> bool:
        """Return `True` after `initialize()` has completed."""
        return self._initialized

    @property
    def migration_inspection_count(self) -> int:
        """Number of times full per-table column/index migration inspection ran."""
        return self._migration_inspection_count

    @traced
    async def initialize(self) -> str:
        """Initialize schema and apply missing tables/columns/indexes when `schema_hash` changes.

        Skips per-table inspection if the current `schema_hash` is already recorded in
        `arodonata_schema_version`.
        """
        schema_hash = compute_schema_hash(self._metadata)
        span_attrs(db_dialect=self._engine.dialect.name, schema_hash=schema_hash[:12])

        async with self._engine.begin() as conn:
            # 1. Ensure arodonata_schema_version table exists first
            await conn.run_sync(
                lambda sync_conn: SchemaVersionRecord.__table__.create(  # type: ignore[attr-defined]
                    sync_conn, checkfirst=True
                )
            )

            # 2. Check if current schema_hash is already recorded
            existing = await conn.execute(
                select(SchemaVersionRecord).where(
                    SchemaVersionRecord.schema_hash == schema_hash  # type: ignore[arg-type]
                )
            )
            if existing.scalar_one_or_none() is not None:
                self._initialized = True
                self._last_schema_hash = schema_hash
                span_attrs(schema_migrated=False)
                return schema_hash

            # 3. Apply new tables, missing columns, and missing indexes
            await conn.run_sync(self._apply_schema_evolution_sync)
            self._migration_inspection_count += 1

            # 4. Record the new schema_hash
            await conn.execute(
                SchemaVersionRecord.__table__.insert().values(  # type: ignore[attr-defined]
                    schema_hash=schema_hash,
                    applied_at=utc_now(),
                )
            )

        self._initialized = True
        self._last_schema_hash = schema_hash
        span_attrs(schema_migrated=True)
        return schema_hash

    def _apply_schema_evolution_sync(self, sync_conn: Connection) -> None:
        """Create missing tables and safely add missing columns and indexes on existing tables."""
        self._metadata.create_all(sync_conn, checkfirst=True)
        inspector = inspect(sync_conn)
        existing_tables = set(inspector.get_table_names())
        dialect = sync_conn.dialect
        preparer = dialect.identifier_preparer

        for table_name, table in self._metadata.tables.items():
            if table_name not in existing_tables:
                continue

            existing_col_names = {col["name"] for col in inspector.get_columns(table_name)}
            for col in table.columns:
                if col.name not in existing_col_names:
                    col_type_sql = col.type.compile(dialect=dialect)
                    quoted_table = preparer.quote(table_name)
                    quoted_col = preparer.quote(col.name)
                    default_clause = ""
                    if not col.nullable and not col.primary_key:
                        default_clause = " NULL"
                    sync_conn.execute(
                        text(f"ALTER TABLE {quoted_table} ADD COLUMN {quoted_col} {col_type_sql}{default_clause}")
                    )

            existing_idx_names = {idx["name"] for idx in inspector.get_indexes(table_name) if idx.get("name")}
            for idx in table.indexes:
                if idx.name and idx.name not in existing_idx_names:
                    idx.create(sync_conn, checkfirst=True)

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Provide an transactional `AsyncSession` scope."""
        async with self._session_factory() as session:
            yield session

    @traced
    async def close(self) -> None:
        """Dispose of the underlying `AsyncEngine` if owned by this `DatabaseManager`."""
        if self._owns_engine:
            await self._engine.dispose()
