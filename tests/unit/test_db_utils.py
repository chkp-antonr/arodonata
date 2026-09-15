"""Tests for arodonata.db_utils (safe_init_table / ensure_missing_columns).

Uses an in-memory SQLite engine (via aiosqlite) so no real database or
network access is required.
"""

from __future__ import annotations

from typing import ClassVar
from unittest.mock import patch

import pytest
from sqlalchemy import Column, Index, Integer, MetaData, Table, text
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.types import NullType
from sqlmodel import Field, SQLModel

from arodonata.db_utils import ensure_missing_columns, safe_init_table


class _Widget(SQLModel, table=True):
    __tablename__: ClassVar[str] = "_widget_test_table"
    __table_args__ = {"extend_existing": True}

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(default="")
    extra_field: str | None = Field(default=None)


class _Gadget(SQLModel, table=True):
    """Model with a named index, used to exercise index auto-migration."""

    __tablename__: ClassVar[str] = "_gadget_test_table"
    __table_args__ = (
        Index("ix_gadget_name", "name"),
        {"extend_existing": True},
    )

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(default="")


class _Sprocket(SQLModel, table=True):
    """Model whose new columns are all NOT NULL, one per default-rendering route.

    ``label`` carries a scalar Python default, ``enabled`` a boolean (rendered
    ``0`` on SQLite, ``false`` on PostgreSQL), ``count`` a numeric, and
    ``tag`` a NOT NULL string with no default at all.
    """

    __tablename__: ClassVar[str] = "_sprocket_test_table"
    __table_args__ = {"extend_existing": True}

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(default="")
    label: str = Field(default="")
    enabled: bool = Field(default=False)
    count: int = Field(default=0)
    tag: str


async def _create_old_widget_schema(engine):
    async with engine.begin() as conn:
        await conn.execute(text("CREATE TABLE _widget_test_table (id INTEGER PRIMARY KEY, name VARCHAR)"))


def _get_columns_sync(sync_conn, table_name):
    return {col["name"] for col in sa_inspect(sync_conn).get_columns(table_name)}


# =============================================================================
# ensure_missing_columns
# =============================================================================


@pytest.mark.asyncio
async def test_ensure_missing_columns_adds_column_via_model_class():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        await _create_old_widget_schema(engine)
        await ensure_missing_columns(engine, _Widget)

        async with engine.connect() as conn:
            columns = await conn.run_sync(_get_columns_sync, "_widget_test_table")

        assert "extra_field" in columns
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_ensure_missing_columns_adds_column_via_raw_table():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        await _create_old_widget_schema(engine)
        await ensure_missing_columns(engine, _Widget.__table__)

        async with engine.connect() as conn:
            columns = await conn.run_sync(_get_columns_sync, "_widget_test_table")

        assert "extra_field" in columns
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_ensure_missing_columns_is_noop_when_table_absent():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        # No table created — should return without raising.
        await ensure_missing_columns(engine, _Widget)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_ensure_missing_columns_adds_not_null_columns_to_a_populated_table():
    """The case that broke every upgrading consumer: NOT NULL onto a table with rows.

    ``ALTER TABLE t ADD COLUMN c VARCHAR NOT NULL`` with no ``DEFAULT`` is
    rejected outright by SQLite ("Cannot add a NOT NULL column with default
    value NULL") and by PostgreSQL whenever the table is non-empty, so the
    exception escaped ``DatabaseManager.initialize()`` and the application never
    started. An empty table happens to accept it, which is why a fresh lab
    database and the rest of this file stayed green.
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE TABLE _sprocket_test_table (id INTEGER PRIMARY KEY, name VARCHAR)"))
            await conn.execute(text("INSERT INTO _sprocket_test_table (id, name) VALUES (1, 'pre-existing')"))

        await ensure_missing_columns(engine, _Sprocket)

        async with engine.connect() as conn:
            columns = await conn.run_sync(_get_columns_sync, "_sprocket_test_table")
            row = await conn.execute(
                text("SELECT name, label, enabled, count, tag FROM _sprocket_test_table WHERE id = 1")
            )
            values = row.one()

        assert {"label", "enabled", "count", "tag"} <= columns
        # The existing row is backfilled with each column's own default, or the
        # zero value of its declared type when it has none (`tag`).
        assert values == ("pre-existing", "", 0, 0, "")
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_ensure_missing_columns_second_pass_is_a_noop():
    """Two migration passes over the same table: the second adds nothing and raises nothing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE TABLE _sprocket_test_table (id INTEGER PRIMARY KEY, name VARCHAR)"))
            await conn.execute(text("INSERT INTO _sprocket_test_table (id, name) VALUES (1, 'row')"))

        await ensure_missing_columns(engine, _Sprocket)
        await ensure_missing_columns(engine, _Sprocket)

        async with engine.connect() as conn:
            columns = await conn.run_sync(_get_columns_sync, "_sprocket_test_table")
        assert columns == {"id", "name", "label", "enabled", "count", "tag"}
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_ensure_missing_columns_tolerates_a_column_added_concurrently(caplog):
    """Inspect-then-ALTER is a TOCTOU window; the worker that loses the race must not fail.

    Two gunicorn workers starting together both observe the new schema hash and
    both run the scan. The loser's ``ALTER`` is told the column already exists —
    the state it wanted — and must carry on adding the remaining columns rather
    than re-raising into ``initialize()``. The stale inspector below is exactly
    what the loser sees: the column is missing when it looks, present when it
    writes.
    """

    class _StaleInspector:
        def __init__(self, real, hidden):
            self._real = real
            self._hidden = hidden

        def has_table(self, table_name):
            return self._real.has_table(table_name)

        def get_columns(self, table_name):
            return [c for c in self._real.get_columns(table_name) if c["name"] not in self._hidden]

        def get_indexes(self, table_name):
            return self._real.get_indexes(table_name)

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            # `label` is already there (the winner added it) but hidden below.
            await conn.execute(
                text(
                    "CREATE TABLE _sprocket_test_table "
                    "(id INTEGER PRIMARY KEY, name VARCHAR, label VARCHAR NOT NULL DEFAULT '')"
                )
            )
            await conn.execute(text("INSERT INTO _sprocket_test_table (id, name) VALUES (1, 'row')"))

        with patch("arodonata.db_utils.sa_inspect", lambda conn: _StaleInspector(sa_inspect(conn), {"label"})):
            await ensure_missing_columns(engine, _Sprocket)

        async with engine.connect() as conn:
            columns = await conn.run_sync(_get_columns_sync, "_sprocket_test_table")

        # The duplicate was tolerated and the columns after it still landed.
        assert {"label", "enabled", "count", "tag"} <= columns
        assert any("added concurrently" in r.message for r in caplog.records)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_ensure_missing_columns_fails_loudly_when_no_default_can_be_rendered():
    """Broken DDL is worse than no DDL: an unmigratable NOT NULL column says so."""
    metadata = MetaData()
    table = Table(
        "_oddball_test_table",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("payload", NullType(), nullable=False),
    )
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE TABLE _oddball_test_table (id INTEGER PRIMARY KEY)"))

        with pytest.raises(ValueError, match="Cannot auto-migrate '_oddball_test_table'"):
            await ensure_missing_columns(engine, table)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_ensure_missing_columns_warns_on_nullable_orphaned_column(caplog):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("CREATE TABLE _gadget_test_table (id INTEGER PRIMARY KEY, name VARCHAR, legacy_col VARCHAR)")
            )
        await ensure_missing_columns(engine, _Gadget)
        critical_records = [r for r in caplog.records if r.levelname == "CRITICAL"]
        assert len(critical_records) == 1
        message = critical_records[0].message
        assert "legacy_col" in message
        assert "They are nullable, so inserts are unaffected" in message
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_ensure_missing_columns_flags_not_null_orphaned_column(caplog):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "CREATE TABLE _gadget_test_table "
                    "(id INTEGER PRIMARY KEY, name VARCHAR, "
                    "legacy_required VARCHAR NOT NULL DEFAULT '')"
                )
            )
        await ensure_missing_columns(engine, _Gadget)
        critical_records = [r for r in caplog.records if r.levelname == "CRITICAL"]
        assert len(critical_records) == 1
        message = critical_records[0].message
        assert "legacy_required" in message
        assert "ALTER TABLE _gadget_test_table DROP COLUMN legacy_required" in message
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_ensure_missing_columns_creates_missing_index():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE TABLE _gadget_test_table (id INTEGER PRIMARY KEY, name VARCHAR)"))
        await ensure_missing_columns(engine, _Gadget)

        async with engine.connect() as conn:
            index_names = await conn.run_sync(
                lambda sync_conn: {idx["name"] for idx in sa_inspect(sync_conn).get_indexes("_gadget_test_table")}
            )
        assert "ix_gadget_name" in index_names
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_ensure_missing_columns_tolerates_an_index_created_concurrently(caplog):
    """Index creation is the same TOCTOU window as the column ALTER, in the same function.

    Left untolerated, the loser of the index race fails startup exactly as the
    loser of the column race did — just one statement later.
    """

    class _IndexBlindInspector:
        def __init__(self, real):
            self._real = real

        def has_table(self, table_name):
            return self._real.has_table(table_name)

        def get_columns(self, table_name):
            return self._real.get_columns(table_name)

        def get_indexes(self, table_name):
            return []

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE TABLE _gadget_test_table (id INTEGER PRIMARY KEY, name VARCHAR)"))
            await conn.execute(text("CREATE INDEX ix_gadget_name ON _gadget_test_table (name)"))

        with patch("arodonata.db_utils.sa_inspect", lambda conn: _IndexBlindInspector(sa_inspect(conn))):
            await ensure_missing_columns(engine, _Gadget)

        assert any("created concurrently" in r.message for r in caplog.records)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_ensure_missing_columns_accepts_connection_not_just_engine():
    """ensure_missing_columns should also work when passed an AsyncConnection."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        await _create_old_widget_schema(engine)
        async with engine.begin() as conn:
            await ensure_missing_columns(conn, _Widget)

        async with engine.connect() as conn:
            columns = await conn.run_sync(_get_columns_sync, "_widget_test_table")
        assert "extra_field" in columns
    finally:
        await engine.dispose()


# =============================================================================
# safe_init_table
# =============================================================================


@pytest.mark.asyncio
async def test_safe_init_table_creates_fresh_table():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        result = await safe_init_table(engine, _Widget)
        assert result is True

        async with engine.connect() as conn:
            columns = await conn.run_sync(_get_columns_sync, "_widget_test_table")
        assert "extra_field" in columns
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_safe_init_table_uses_explicit_table_name():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        result = await safe_init_table(engine, _Widget, table_name="_widget_test_table")
        assert result is True
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_safe_init_table_accepts_connection():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            result = await safe_init_table(conn, _Widget)
        assert result is True
    finally:
        await engine.dispose()
