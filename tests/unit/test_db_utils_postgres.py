"""PostgreSQL upgrade path: startup auto-migration widens rulebase action/track VARCHAR(32) -> VARCHAR(64).

Opt-in: runs only when ``ARODONATA_PG_TEST_URL`` points at a PostgreSQL database (``postgresql+asyncpg://...``).
Everything happens in a throwaway schema (dropped before and after), so the database's own tables are untouched.
SQLite ignores VARCHAR lengths, which is why these checks need a real server.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from arodonata.cache import models  # noqa: F401  (registers tables)
from arodonata.cache.database import DatabaseManager

PG_URL = os.getenv("ARODONATA_PG_TEST_URL", "")
SCHEMA = "arodonata_pg_test"
UID_36 = "6c488338-8eec-4103-ad21-cd461ac2c472"

pytestmark = pytest.mark.skipif(
    not PG_URL.startswith("postgresql"), reason="set ARODONATA_PG_TEST_URL to a PostgreSQL test database"
)


async def _admin(sql: str) -> None:
    engine = create_async_engine(PG_URL)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql))
    finally:
        await engine.dispose()


@pytest.fixture
async def pg_engine() -> AsyncIterator[AsyncEngine]:
    await _admin(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")
    await _admin(f"CREATE SCHEMA {SCHEMA}")
    engine = create_async_engine(PG_URL, connect_args={"server_settings": {"search_path": SCHEMA}})
    try:
        yield engine
    finally:
        await engine.dispose()
        await _admin(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")


async def _lengths(engine: AsyncEngine, table: str) -> dict[str, int | None]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT column_name, character_maximum_length FROM information_schema.columns "
                "WHERE table_schema = :schema AND table_name = :table AND column_name IN ('action', 'track')"
            ),
            {"schema": SCHEMA, "table": table},
        )
        return {name: length for name, length in rows}


async def _as_v1_11(engine: AsyncEngine, action_type: str = "VARCHAR(32)") -> None:
    """A database created by v1.11: current tables, rulebase_access.action/track as VARCHAR(32), one row."""
    await DatabaseManager(engine).initialize()
    async with engine.begin() as conn:
        await conn.execute(text(f"ALTER TABLE rulebase_access ALTER COLUMN action TYPE {action_type}"))
        await conn.execute(text("ALTER TABLE rulebase_access ALTER COLUMN track TYPE VARCHAR(32)"))
        await conn.execute(text("DELETE FROM arodonata_schema_version"))  # as if the stored hash were v1.11's
        await conn.execute(
            text(
                "INSERT INTO rulebase_access (id, uid, rule_number, name, enabled, layer_name, mgmt_name, domain_name,"
                " sources, destinations, services, action, track, update_time)"
                " VALUES ('m:d:L:r1', 'r1', 1, 'old', true, 'L', 'm', 'd', '', '', '', 'accept', 'Log', now())"
            )
        )


async def test_startup_widens_varchar32_columns_on_postgresql(pg_engine):
    await _as_v1_11(pg_engine)
    assert await _lengths(pg_engine, "rulebase_access") == {"action": 32, "track": 32}

    await DatabaseManager(pg_engine).initialize()  # the upgraded process starting up

    assert await _lengths(pg_engine, "rulebase_access") == {"action": 64, "track": 64}
    async with pg_engine.begin() as conn:
        kept = (await conn.execute(text("SELECT action FROM rulebase_access WHERE uid = 'r1'"))).scalar_one()
        await conn.execute(
            text(
                "INSERT INTO rulebase_access (id, uid, rule_number, name, enabled, layer_name, mgmt_name, domain_name,"
                " sources, destinations, services, action, track, update_time)"
                f" VALUES ('m:d:L:r2', 'r2', 2, 'new', true, 'L', 'm', 'd', '', '', '', '{UID_36}', '{UID_36}', now())"
            )
        )
    assert kept == "accept"


async def test_second_startup_is_a_no_op(pg_engine, monkeypatch):
    await _as_v1_11(pg_engine)
    await DatabaseManager(pg_engine).initialize()
    monkeypatch.setenv("ARODONATA_FORCE_SCHEMA_SCAN", "1")
    await DatabaseManager(pg_engine).initialize()
    assert await _lengths(pg_engine, "rulebase_access") == {"action": 64, "track": 64}


async def test_wider_live_column_is_never_narrowed(pg_engine):
    await _as_v1_11(pg_engine, action_type="VARCHAR(128)")
    await DatabaseManager(pg_engine).initialize()
    assert await _lengths(pg_engine, "rulebase_access") == {"action": 128, "track": 64}
