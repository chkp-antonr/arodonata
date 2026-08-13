"""Tests for arodonata.db_utils (safe_init_table / ensure_missing_columns).

Uses an in-memory SQLite engine (via aiosqlite) so no real database or
network access is required.
"""

from __future__ import annotations

from typing import ClassVar

import pytest
from sqlalchemy import Index, text
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import create_async_engine
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
