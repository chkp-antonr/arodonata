"""Database utilities for arodonata.

Provides generalized error handling for SQLModel table initialization
with automatic recovery on schema changes.
"""

from __future__ import annotations

from datetime import date, datetime, time
from decimal import Decimal
from typing import Any

from sqlalchemy import Column, Dialect, Table, text
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlmodel import SQLModel

from .logger import get_logger

logger = get_logger(__name__)

# What the database says when another worker created the column or index first.
# SQLite: "duplicate column name: x", "index ix_x already exists"; PostgreSQL:
# 'column "x" of relation "y" already exists', 'relation "ix_x" already exists'.
_DUPLICATE_OBJECT_MARKERS = ("duplicate column", "already exists")

# The value existing rows get when a NOT NULL column is added and the column
# declares no default of its own, keyed on the column's declared Python type.
# Checked in order, so bool precedes int and datetime precedes date (each is a
# subclass of the next). Deliberately *constants*: SQLite rejects a non-constant
# ADD COLUMN default (CURRENT_TIMESTAMP and friends), so an epoch sentinel is
# the only portable choice for a temporal column.
_TYPE_ZERO_VALUES: tuple[tuple[type, Any], ...] = (
    (bool, False),
    (int, 0),
    (float, 0.0),
    (Decimal, Decimal(0)),
    (str, ""),
    (bytes, b""),
    (datetime, datetime(1970, 1, 1)),
    (date, date(1970, 1, 1)),
    (time, time(0, 0)),
    (dict, {}),
    (list, []),
)

# Types SQLAlchemy has no literal_processor for (JSON). Both SQLite and
# PostgreSQL read these strings as the empty JSON container.
_LITERAL_FALLBACKS: tuple[tuple[type, str], ...] = ((dict, "'{}'"), (list, "'[]'"))


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


def _declared_python_type(col_type: Any) -> type | None:
    """The Python type a column's declared SQL type maps to, or None if it has none.

    Three places to ask, because ``python_type`` is not reliably implemented on
    the outermost type: the type itself; the wrapped ``impl`` of a
    ``TypeDecorator`` (SQLModel declares every ``str`` field as ``AutoString``,
    which is one and raises ``NotImplementedError`` for its own Python type);
    and finally the type's affinity (``String``, ``Integer``, ...).
    """
    candidates: list[Any] = [col_type]
    impl = getattr(col_type, "impl_instance", None)
    if impl is not None:
        candidates.append(impl)
    affinity = getattr(col_type, "_type_affinity", None)
    if affinity is not None:
        candidates.append(affinity())
    for candidate in candidates:
        try:
            python_type = candidate.python_type
        except (NotImplementedError, TypeError, AttributeError):
            continue
        if isinstance(python_type, type):
            return python_type
    return None


def _not_null_default_value(col: Column[Any]) -> Any:
    """The Python value existing rows should get for a new NOT NULL column.

    The column's own scalar default first -- ``Field(default="")`` lands there as
    a ``ScalarElementColumnDefault``, so the migrated rows match what the model
    says a fresh row would hold -- then a zero value derived from the declared
    type.

    Raises:
        ValueError: If the type offers nothing sensible; the caller turns that
            into a loud failure rather than emitting DDL the database rejects.
    """
    default = col.default
    if default is not None and getattr(default, "is_scalar", False):
        # `arg` lives on ScalarElementColumnDefault, not on the DefaultGenerator
        # base that `col.default` is typed as -- read it through getattr rather
        # than narrowing a union SQLAlchemy does not expose.
        scalar_arg = getattr(default, "arg", None)
        if scalar_arg is not None:
            return scalar_arg

    python_type = _declared_python_type(col.type)
    if python_type is None:
        raise ValueError(
            f"column '{col.name}' is NOT NULL and its type {col.type!r} declares no Python type, "
            "so no backfill default can be derived"
        )

    for candidate, zero in _TYPE_ZERO_VALUES:
        if issubclass(python_type, candidate):
            return zero
    raise ValueError(
        f"column '{col.name}' is NOT NULL and its type {col.type!r} (Python {python_type!r}) has no portable zero value"
    )


def _not_null_default_sql(col: Column[Any], dialect: Dialect) -> str:
    """The SQL literal for a new NOT NULL column's ``DEFAULT`` clause.

    A NOT NULL column cannot be added to a populated table without one: both
    SQLite ("Cannot add a NOT NULL column with default value NULL") and
    PostgreSQL refuse. An explicit ``server_default`` wins; otherwise the value
    from ``_not_null_default_value`` is rendered by the *dialect's own* literal
    processor, which is what keeps this portable -- a boolean false is ``0`` on
    SQLite and ``false`` on PostgreSQL.

    Raises:
        ValueError: If no portable literal can be produced. Failing loudly here
            is the point: broken DDL is worse than no DDL.
    """
    if col.server_default is not None:
        arg = getattr(col.server_default, "arg", None)
        if arg is None:
            raise ValueError(f"column '{col.name}' has a server_default this migration cannot render")
        return str(getattr(arg, "text", arg))

    value = _not_null_default_value(col)
    processor = None
    try:
        processor = col.type.literal_processor(dialect=dialect)
    except NotImplementedError:
        processor = None
    if processor is not None:
        try:
            return processor(value)
        except Exception as exc:  # noqa: BLE001 - fall through to the literal fallbacks below
            logger.debug(f"No literal processor output for '{col.name}' ({col.type!r}): {exc}")

    for candidate, literal in _LITERAL_FALLBACKS:
        if isinstance(value, candidate):
            return literal
    raise ValueError(
        f"column '{col.name}' is NOT NULL and its type {col.type!r} has no literal representation "
        f"for dialect '{dialect.name}'"
    )


def _is_duplicate_object_error(exc: BaseException) -> bool:
    """True when the database is saying the column or index we just tried to add is already there."""
    message = str(exc).lower()
    return any(marker in message for marker in _DUPLICATE_OBJECT_MARKERS)


def _add_missing_columns(sync_conn: Any, table: Table, table_name: str, model_columns: dict[str, Any]) -> None:
    """Add columns present in the model but missing from the live table.

    A NOT NULL addition carries a rendered ``DEFAULT`` so it works on a table
    that already has rows (see ``_not_null_default_sql``); a column whose type
    has no portable default fails loudly instead of emitting DDL the database
    will reject.

    Each ``ALTER`` runs in its own savepoint because inspect-then-alter is a
    TOCTOU window: two workers starting together both see the column missing and
    both issue the ``ALTER``. The loser is told the column already exists, which
    is precisely the state it wanted, so that one error is tolerated. The
    savepoint is what makes tolerating it possible -- on PostgreSQL a failed
    statement aborts the surrounding transaction and would take every later
    column with it.
    """
    inspector = sa_inspect(sync_conn)
    existing = {col["name"] for col in inspector.get_columns(table_name)}
    for col_name, col in model_columns.items():
        if col_name in existing:
            continue
        # Resolved before the type is compiled so the actionable message wins
        # over the compiler's for a column that can never be migrated.
        suffix = ""
        if not col.nullable:
            try:
                suffix = f" NOT NULL DEFAULT {_not_null_default_sql(col, sync_conn.dialect)}"
            except ValueError as exc:
                raise ValueError(
                    f"Cannot auto-migrate '{table_name}': {exc}. Give the column a server_default, "
                    "or make it nullable, or migrate it by hand."
                ) from exc
        col_type_str = col.type.compile(dialect=sync_conn.dialect)
        ddl = f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type_str}{suffix}"
        savepoint = sync_conn.begin_nested()
        try:
            sync_conn.execute(text(ddl))
        except Exception as exc:
            savepoint.rollback()
            if _is_duplicate_object_error(exc):
                logger.info(
                    f"Column '{col_name}' already present on '{table_name}' "
                    f"(added concurrently by another worker) - continuing"
                )
                continue
            raise
        savepoint.commit()
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

    Savepointed and duplicate-tolerant for the same reason as
    ``_add_missing_columns``: inspect-then-create is a TOCTOU window, and two
    workers starting together both see the index missing.
    """
    inspector = sa_inspect(sync_conn)
    existing_indexes = {idx["name"] for idx in inspector.get_indexes(table_name)}
    for index in table.indexes:
        if index.name in existing_indexes:
            continue
        savepoint = sync_conn.begin_nested()
        try:
            index.create(sync_conn, checkfirst=False)
        except Exception as exc:
            savepoint.rollback()
            if _is_duplicate_object_error(exc):
                logger.info(
                    f"Index '{index.name}' already present on '{table_name}' "
                    f"(created concurrently by another worker) - continuing"
                )
                continue
            raise
        savepoint.commit()
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
