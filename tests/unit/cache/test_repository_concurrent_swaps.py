"""Concurrent per-domain swaps on a real SQLite file all succeed (parallel domain refresh)."""

from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel

from arodonata.cache import models  # noqa: F401  (registers tables on metadata)
from arodonata.cache.database import DatabaseManager
from arodonata.cache.models import CPObject
from arodonata.cache.repository import CacheRepository


def _objects(domain: str, n: int) -> list[CPObject]:
    return [
        CPObject(
            id=f"m1:{domain}:{i}", uid=f"{domain}-{i}", name=f"o{i}", type="host", mgmt_name="m1", domain_name=domain
        )
        for i in range(n)
    ]


async def test_concurrent_swaps_of_several_domains_on_a_sqlite_file_all_succeed(tmp_path):
    # A short busy timeout makes a writer that has to wait fail at once with "database is locked"
    # (SQLite's implicit 5 s only hides this until a swap is large enough).
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'cache.db'}", connect_args={"timeout": 0.05})
    try:
        async with engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
        repo = CacheRepository(DatabaseManager(engine))
        domains = [f"D{i}" for i in range(4)]

        for _ in range(2):  # first load, then a replace of existing rows
            results = await asyncio.gather(
                *(repo.replace_domain_objects("m1", d, _objects(d, 2000)) for d in domains), return_exceptions=True
            )
            assert [r for r in results if isinstance(r, BaseException)] == []

        for d in domains:
            assert len(await repo.get_objects(object_type=None, mgmt_names=["m1"], domain_names=[d])) == 2000
    finally:
        await engine.dispose()
