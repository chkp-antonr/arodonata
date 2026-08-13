"""Database utilities for arodonata.

Provides generalized error handling for SQLModel table initialization
with automatic recovery on schema changes.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Table, text
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlmodel import SQLModel

from .logger import get_logger

logger = get_logger(__name__)


async def safe_init_table(
    engine_or_conn: Any,
    table_class: type[SQLModel],
    table_name: str | None = None,
) -> bool:
    """Initialize a SQLModel table with automatic recovery on schema errors.

    If the table exists but has a different schema (e.g., columns added/removed),
    this function will:
    1. Log the error at CRITICAL level
    2. Drop the problematic table
    3. Recreate it with the correct schema

    Args:
        engine_or_conn: AsyncEngine or AsyncConnection
        table_class: SQLModel class to initialize
        table_name: Optional table name (defaults to table_class.__tablename__)

    Returns:
        True if table was created/recreated successfully, False otherwise
    """
    if table_name is None:
        table_name = (
            table_class.__tablename__ if isinstance(table_class.__tablename__, str) else table_class.__tablename__()
        )

    try:
        # Try to create the table normally
        if isinstance(engine_or_conn, AsyncEngine):
            async with engine_or_conn.begin() as conn:
                await conn.run_sync(table_class.metadata.create_all)
        else:
            await engine_or_conn.run_sync(table_class.metadata.create_all)
        return True

    except Exception as e:
        error_msg = str(e).lower()
        # Check if it's a schema-related error
        schema_keywords = ["column", "schema", "duplicate", "already exists", "does not exist", "type mismatch"]
        if any(keyword in error_msg for keyword in schema_keywords):
            logger.critical(f"Schema mismatch detected for table '{table_name}': {e}. Dropping and recreating table.")
            try:
                # Need a connection to execute DROP
                async def _recreate(conn):
                    await conn.execute(text(f"DROP TABLE IF EXISTS {table_name} CASCADE"))
                    table_class.metadata.create_all(conn.engine)  # create_all expects sync engine/conn

                if isinstance(engine_or_conn, AsyncEngine):
                    async with engine_or_conn.begin() as conn:
                        await conn.execute(text(f"DROP TABLE IF EXISTS {table_name} CASCADE"))
                        await conn.run_sync(table_class.metadata.create_all)
                else:
                    await engine_or_conn.execute(text(f"DROP TABLE IF EXISTS {table_name} CASCADE"))
                    await engine_or_conn.run_sync(table_class.metadata.create_all)

                logger.info(f"Successfully recreated table '{table_name}' with correct schema")
                return True
            except Exception as recreate_error:
                logger.error(f"Failed to recreate table '{table_name}': {recreate_error}")
                return False
        else:
            # Not a schema error, re-raise
            logger.error(f"Non-schema error initializing table '{table_name}': {e}")
            raise


def _add_missing_columns(sync_conn: Any, table: Table, table_name: str, model_columns: dict[str, Any]) -> None:
    """Add columns present in the model but missing from the live table."""
    inspector = sa_inspect(sync_conn)
    existing = {col["name"] for col in inspector.get_columns(table_name)}
    for col_name, col in model_columns.items():
        if col_name not in existing:
            col_type_str = col.type.compile(dialect=sync_conn.dialect)
            nullable = "" if col.nullable else " NOT NULL"
            sync_conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type_str}{nullable}"))
            logger.info(f"Auto-migrated: added column '{col_name}' to '{table_name}'")


def _warn_orphaned_columns(sync_conn: Any, table_name: str, model_columns: dict[str, Any]) -> None:
    """Warn about columns on the live table that aren't in the model.

    Columns that exist on the live table but were removed/renamed from the
    model are never dropped automatically — a NOT NULL orphan silently
    breaks every insert that no longer populates it, so surface it loudly
    instead of leaving it to fail at insert time with a confusing error.
    """
    inspector = sa_inspect(sync_conn)
    existing = {col["name"] for col in inspector.get_columns(table_name)}
    orphaned = existing - set(model_columns)
    if orphaned:
        orphan_details = {
            col_name: next(
                (c["nullable"] is False for c in inspector.get_columns(table_name) if c["name"] == col_name),
                False,
            )
            for col_name in orphaned
        }
        not_null_orphans = [name for name, is_not_null in orphan_details.items() if is_not_null]
        logger.critical(
            f"Column(s) {sorted(orphaned)} exist on '{table_name}' but not in the "
            f"model — likely removed or renamed. Auto-migration will NOT drop them. "
            + (
                f"{sorted(not_null_orphans)} are NOT NULL and will break inserts that "
                f"don't populate them — drop manually once verified safe, e.g.: "
                + "; ".join(f"ALTER TABLE {table_name} DROP COLUMN {name}" for name in sorted(not_null_orphans))
                if not_null_orphans
                else "They are nullable, so inserts are unaffected, but consider dropping them."
            )
        )


def _create_missing_indexes(sync_conn: Any, table: Table, table_name: str) -> None:
    """Create any indexes defined in the model that are missing from the live
    table. Covers columns added by ``_add_missing_columns`` as well as indexes
    dropped manually.
    """
    inspector = sa_inspect(sync_conn)
    existing_indexes = {idx["name"] for idx in inspector.get_indexes(table_name)}
    for index in table.indexes:
        if index.name not in existing_indexes:
            index.create(sync_conn, checkfirst=False)
            logger.info(f"Auto-migrated: created index '{index.name}' on '{table_name}'")


async def ensure_missing_columns(
    engine_or_conn: Any,
    table_class: type[SQLModel] | Table,
) -> None:
    """Add any columns present in the SQLModel but missing from the live table.

    Accepts either a mapped SQLModel class or a raw SQLAlchemy ``Table``
    (e.g. from ``SQLModel.metadata.tables.values()``), so callers can migrate
    every registered table generically instead of listing classes by hand.

    Safe for both PostgreSQL and SQLite. Uses inspect to check before altering,
    so no IF NOT EXISTS dialect differences needed.
    """
    table: Table = table_class.__table__ if hasattr(table_class, "__table__") else table_class  # type: ignore[assignment]
    table_name = table.name
    model_columns = {col.name: col for col in table.columns}

    def _sync_add_missing(sync_conn: Any) -> None:
        inspector = sa_inspect(sync_conn)
        # Table might not exist yet (create_all handles that separately)
        if not inspector.has_table(table_name):
            return
        _add_missing_columns(sync_conn, table, table_name, model_columns)
        _warn_orphaned_columns(sync_conn, table_name, model_columns)
        _create_missing_indexes(sync_conn, table, table_name)

    try:
        if isinstance(engine_or_conn, AsyncEngine):
            async with engine_or_conn.begin() as conn:
                await conn.run_sync(_sync_add_missing)
        else:
            await engine_or_conn.run_sync(_sync_add_missing)
    except Exception as e:
        logger.error(f"Failed to ensure columns for '{table_name}': {e}")
        raise


__all__ = ["safe_init_table", "ensure_missing_columns"]
