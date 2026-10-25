"""Database lifecycle manager and SHA-256 schema hash auto-migration (`DatabaseManager`)."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, DateTime, MetaData, Table, event, inspect, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DatabaseError, IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from arodonata.adapters.storage import tables as _tables  # noqa: F401
from arodonata.adapters.storage.tables import ARODONATA_TABLE_NAMES, SchemaVersionRecord
from arodonata.core.models.common import utc_now
from arodonata.core.telemetry import span_attrs, traced

DEFAULT_MEMORY_SQLITE_URL = "sqlite+aiosqlite:///:memory:"
PG_ADVISORY_MIGRATION_LOCK_KEY = 7281940251839201

LEGACY_V1_TABLE_FINGERPRINTS: dict[str, frozenset[str]] = {
    "domains": frozenset({"mdm_dmn"}),
    "sid_cache": frozenset({"mgmt_dmn_key"}),
}


def _column_type_family(col_type: Any) -> str:
    """Normalize a SQLAlchemy column type into a coarse cross-dialect type family."""
    if isinstance(col_type, DateTime):
        return "datetime"
    type_name = type(col_type).__name__.upper()
    col_str = str(col_type).upper()
    if "BOOL" in type_name or "BOOL" in col_str:
        return "boolean"
    if "INT" in type_name or "INT" in col_str:
        return "integer"
    if "FLOAT" in type_name or "REAL" in type_name or "NUMERIC" in type_name or "DECIMAL" in type_name:
        return "float"
    if "JSON" in type_name or "JSON" in col_str:
        return "json"
    if "DATE" in type_name or "TIME" in type_name or "TIMESTAMP" in col_str:
        return "datetime"
    return "string"


def _managed_tables(metadata: MetaData) -> list[tuple[str, Table]]:
    """Return sorted `(table_name, table)` pairs managed by `DatabaseManager`.

    When `metadata` is the global `SQLModel.metadata`, only Arodonata's own tables
    (`ARODONATA_TABLE_NAMES`) are included so foreign host application tables sharing
    `SQLModel.metadata` are never hashed, created, or altered by Arodonata.
    """
    restrict_to_arodonata = metadata is SQLModel.metadata
    return [
        (name, metadata.tables[name])
        for name in sorted(metadata.tables.keys())
        if not restrict_to_arodonata or name in ARODONATA_TABLE_NAMES
    ]


def _is_benign_concurrent_ddl_error(exc: BaseException) -> bool:
    """Return `True` if `exc` is a duplicate column/table/index error from a concurrent worker."""
    msg = str(exc).lower()
    return any(
        token in msg
        for token in (
            "duplicate column",
            "already exists",
            "duplicate key",
            "unique constraint",
        )
    )


def _is_table_schema_incompatible(inspector: Any, table_name: str, table: Table) -> bool:
    """Return `True` if an existing Arodonata table is incompatible with the v2 `table` model.

    Detects:
    1. Primary key column mismatch.
    2. Orphaned legacy `NOT NULL` columns without a server default that no longer exist in v2.
    3. Legacy timezone-aware `TIMESTAMPTZ` columns where v2 expects naive UTC `DateTime(timezone=False)`.
    4. Column type family changes (e.g. `INTEGER` vs `VARCHAR`/`TEXT` vs `DATETIME`) (`I1`).
    5. Model `NOT NULL` columns missing from an existing table (or nullable in DB when model requires `NOT NULL`
       and table is an Arodonata cache table) (`I1`).
    """
    pk_info = inspector.get_pk_constraint(table_name) or {}
    existing_pk = set(pk_info.get("constrained_columns") or [])
    expected_pk = {col.name for col in table.primary_key.columns}
    if existing_pk != expected_pk:
        return True

    existing_cols = inspector.get_columns(table_name)
    existing_cols_by_name = {c["name"]: c for c in existing_cols}
    model_cols_by_name = {col.name: col for col in table.columns}

    for col_info in existing_cols:
        col_name = col_info["name"]
        model_col = model_cols_by_name.get(col_name)
        if model_col is None:
            # Orphaned column removed in v2: if NOT NULL without default, INSERTs would fail
            if not col_info.get("nullable", True) and col_info.get("default") is None:
                return True
            continue

        # Check TIMESTAMPTZ -> TIMESTAMP WITHOUT TIME ZONE mismatch
        if isinstance(model_col.type, DateTime) and not model_col.type.timezone:
            existing_tz = getattr(col_info.get("type"), "timezone", False)
            if existing_tz is True:
                return True

        # Check column type family mismatch (I1)
        existing_type = col_info.get("type")
        if existing_type is not None:
            expected_family = _column_type_family(model_col.type)
            actual_family = _column_type_family(existing_type)
            # In SQLite, JSON and BOOLEAN often map to TEXT/JSON or INTEGER/BOOLEAN
            if expected_family != actual_family and not (
                {expected_family, actual_family} <= {"json", "string"}
                or {expected_family, actual_family} <= {"boolean", "integer"}
            ):
                return True

        # Check nullable -> NOT NULL tightening on existing column
        if not model_col.nullable and not model_col.primary_key and col_info.get("nullable", True):
            return True

    # If a newly added model column is NOT NULL without a server default on an existing Arodonata table,
    # recreating the cache table ensures the NOT NULL constraint is enforced rather than relaxed to NULL (I1).
    if table_name in ARODONATA_TABLE_NAMES:
        for col in table.columns:
            if col.name not in existing_cols_by_name and not col.nullable and not col.primary_key:
                return True

    return False


def compute_schema_hash(metadata: MetaData | None = None) -> str:
    """Compute a deterministic SHA-256 hex digest over managed SQLModel tables, columns, and indexes."""
    target_meta = metadata if metadata is not None else SQLModel.metadata
    schema_repr: list[dict[str, Any]] = []

    for table_name, table in _managed_tables(target_meta):
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
        self._init_lock = asyncio.Lock()
        self._session_lock = asyncio.Lock()

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

        self._serialize_sessions = self._engine.dialect.name == "sqlite"

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
                db_path = make_url(url).database
                if db_path and db_path != ":memory:":
                    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
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

        Serializes schema inspection and DDL across workers (`pg_advisory_xact_lock` on PostgreSQL,
        `BEGIN IMMEDIATE` + in-process lock on SQLite) and verifies both `arodonata_schema_version`
        and the existence of all managed tables before skipping migration.
        """
        schema_hash = compute_schema_hash(self._metadata)
        dialect_name = self._engine.dialect.name
        span_attrs(db_dialect=dialect_name, schema_hash=schema_hash[:12])

        async with self._init_lock, self._engine.connect() as conn:
            if dialect_name == "sqlite":
                await conn.exec_driver_sql("BEGIN IMMEDIATE")
                in_explicit_tx = True
            else:
                in_explicit_tx = False

            try:
                if not in_explicit_tx:
                    await conn.begin()
                if dialect_name == "postgresql":
                    await conn.execute(text(f"SELECT pg_advisory_xact_lock({PG_ADVISORY_MIGRATION_LOCK_KEY})"))

                # 1. Ensure arodonata_schema_version table exists and matches v2 schema
                await conn.run_sync(self._ensure_schema_version_table_sync)

                # 2. Check if current schema_hash is already recorded AND all managed tables exist (I2)
                existing = await conn.execute(
                    select(SchemaVersionRecord).where(
                        SchemaVersionRecord.schema_hash == schema_hash  # type: ignore[arg-type]
                    )
                )
                hash_recorded = existing.scalar_one_or_none() is not None
                if hash_recorded:
                    all_tables_exist = await conn.run_sync(self._all_managed_tables_exist_sync)
                    if all_tables_exist:
                        if in_explicit_tx:
                            await conn.exec_driver_sql("COMMIT")
                        else:
                            await conn.commit()
                        self._initialized = True
                        self._last_schema_hash = schema_hash
                        span_attrs(schema_migrated=False)
                        return schema_hash

                # 3. Apply new tables, drop positively fingerprinted v1 tables, and add missing columns/indexes
                await conn.run_sync(self._apply_schema_evolution_sync)
                self._migration_inspection_count += 1

                # 4. Record the new schema_hash inside a savepoint to tolerate concurrent worker inserts
                if not hash_recorded:
                    try:
                        async with conn.begin_nested():
                            await conn.execute(
                                SchemaVersionRecord.__table__.insert().values(  # type: ignore[attr-defined]
                                    schema_hash=schema_hash,
                                    applied_at=utc_now(),
                                )
                            )
                    except IntegrityError:
                        pass

                if in_explicit_tx:
                    await conn.exec_driver_sql("COMMIT")
                else:
                    await conn.commit()
            except BaseException:
                if in_explicit_tx:
                    await conn.exec_driver_sql("ROLLBACK")
                else:
                    await conn.rollback()
                raise

        self._initialized = True
        self._last_schema_hash = schema_hash
        span_attrs(schema_migrated=True)
        return schema_hash

    def _all_managed_tables_exist_sync(self, sync_conn: Connection) -> bool:
        """Return `True` if every managed table exists and no legacy v1 fingerprinted table remains."""
        inspector = inspect(sync_conn)
        existing_tables = set(inspector.get_table_names())
        for legacy_name, required_cols in LEGACY_V1_TABLE_FINGERPRINTS.items():
            if legacy_name in existing_tables:
                cols = {c["name"] for c in inspector.get_columns(legacy_name)}
                if required_cols <= cols:
                    return False
        return all(table_name in existing_tables for table_name, _ in _managed_tables(self._metadata))

    @staticmethod
    def _ensure_schema_version_table_sync(sync_conn: Connection) -> None:
        """Create `arodonata_schema_version` or recreate it if upgrading from an incompatible v1 schema."""
        sv_table: Table = SchemaVersionRecord.__table__  # type: ignore[attr-defined]
        inspector = inspect(sync_conn)
        if sv_table.name in set(inspector.get_table_names()):
            if _is_table_schema_incompatible(inspector, sv_table.name, sv_table):
                with sync_conn.begin_nested():
                    sv_table.drop(sync_conn, checkfirst=True)
                    sv_table.create(sync_conn, checkfirst=True)
            return

        try:
            with sync_conn.begin_nested():
                sv_table.create(sync_conn, checkfirst=True)
        except DatabaseError as exc:
            if not _is_benign_concurrent_ddl_error(exc):
                raise

    def _apply_schema_evolution_sync(self, sync_conn: Connection) -> None:
        """Create missing tables, drop positively fingerprinted legacy v1 tables, and add columns/indexes safely."""
        managed = _managed_tables(self._metadata)
        inspector = inspect(sync_conn)
        existing_tables = set(inspector.get_table_names())
        dialect = sync_conn.dialect
        preparer = dialect.identifier_preparer

        # Drop legacy v1 unprefixed tables ONLY when positive v1 column fingerprint matches (C5)
        for legacy_name, required_cols in LEGACY_V1_TABLE_FINGERPRINTS.items():
            if legacy_name in existing_tables:
                existing_legacy_cols = {c["name"] for c in inspector.get_columns(legacy_name)}
                if required_cols <= existing_legacy_cols:
                    quoted_legacy = preparer.quote(legacy_name)
                    with sync_conn.begin_nested():
                        sync_conn.execute(text(f"DROP TABLE IF EXISTS {quoted_legacy}"))
                    existing_tables.discard(legacy_name)

        for table_name, table in managed:
            if table_name not in existing_tables:
                try:
                    with sync_conn.begin_nested():
                        table.create(sync_conn, checkfirst=True)
                except DatabaseError as exc:
                    if not _is_benign_concurrent_ddl_error(exc):
                        raise
                continue

            # If this is an Arodonata cache table with an incompatible schema, recreate it
            if table_name in ARODONATA_TABLE_NAMES and _is_table_schema_incompatible(inspector, table_name, table):
                with sync_conn.begin_nested():
                    table.drop(sync_conn, checkfirst=True)
                    table.create(sync_conn, checkfirst=True)
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
                    try:
                        with sync_conn.begin_nested():
                            sync_conn.execute(
                                text(
                                    f"ALTER TABLE {quoted_table} ADD COLUMN {quoted_col} {col_type_sql}{default_clause}"
                                )
                            )
                    except DatabaseError as exc:
                        if not _is_benign_concurrent_ddl_error(exc):
                            raise

            existing_idx_names = {idx["name"] for idx in inspector.get_indexes(table_name) if idx.get("name")}
            for idx in table.indexes:
                if idx.name and idx.name not in existing_idx_names:
                    try:
                        with sync_conn.begin_nested():
                            idx.create(sync_conn, checkfirst=True)
                    except DatabaseError as exc:
                        if not _is_benign_concurrent_ddl_error(exc):
                            raise

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Provide a transactional `AsyncSession` scope."""
        if self._serialize_sessions:
            async with self._session_lock, self._session_factory() as session:
                yield session
        else:
            async with self._session_factory() as session:
                yield session

    @traced
    async def close(self) -> None:
        """Dispose of the underlying `AsyncEngine` if owned by this `DatabaseManager`."""
        if self._owns_engine:
            await self._engine.dispose()
