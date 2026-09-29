from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from arodonata.cache import models  # noqa: F401  (registers tables on metadata)
from arodonata.cache.database import DatabaseManager
from arodonata.cache.models import CPObject, RulebaseAccess, RulebaseNAT
from arodonata.cache.repository import CacheRepository


@pytest.fixture
async def repo():
    """Create a repository backed by a shared in-memory SQLite database.

    Mirrors the fixture in test_repository.py: a single StaticPool connection is shared
    across sessions so every session sees the same data (a plain ``:memory:`` URL without
    StaticPool would hand out a fresh, empty database per connection).
    """
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    repository = CacheRepository(DatabaseManager(engine))
    yield repository
    await engine.dispose()


def _obj(uid: str, ts: datetime, domain: str = "General") -> CPObject:
    return CPObject(
        id=f"mgmt1:{domain}:{uid}",
        uid=uid,
        name=uid,
        type="host",
        mgmt_name="mgmt1",
        domain_name=domain,
        update_time=ts,
    )


async def test_last_update_none_when_empty(repo):
    assert await repo.get_objects_last_update() is None


async def test_last_update_is_max_and_filters_by_domain(repo):
    await repo.upsert_objects(
        [
            _obj("a", datetime(2026, 1, 1)),
            _obj("b", datetime(2026, 3, 1)),
            _obj("c", datetime(2026, 2, 1), domain="Other"),
        ]
    )
    assert await repo.get_objects_last_update() == datetime(2026, 3, 1)
    assert await repo.get_objects_last_update(domain_names=["Other"]) == datetime(2026, 2, 1)
    assert await repo.get_objects_last_update(mgmt_names=["nope"]) is None


def _access(uid: str, ts: datetime, domain: str = "General") -> RulebaseAccess:
    return RulebaseAccess(
        id=f"mgmt1:{domain}:Network:{uid}",
        uid=uid,
        rule_number=1,
        name=uid,
        enabled=True,
        layer_name="Network",
        mgmt_name="mgmt1",
        domain_name=domain,
        update_time=ts,
    )


def _nat(uid: str, ts: datetime, domain: str = "General") -> RulebaseNAT:
    return RulebaseNAT(
        id=f"mgmt1:{domain}:Standard:{uid}",
        uid=uid,
        rule_number=1,
        name=uid,
        enabled=True,
        layer_name="Standard",
        mgmt_name="mgmt1",
        domain_name=domain,
        update_time=ts,
    )


async def test_rulebase_last_update_none_when_empty(repo):
    for kind in ("access", "nat", "https", "threat"):
        assert await repo.get_rulebase_last_update(kind) is None


async def test_access_rulebase_last_update_is_max_and_filters_by_scope(repo):
    await repo.upsert_rulebases(
        [
            _access("a", datetime(2026, 1, 1)),
            _access("b", datetime(2026, 3, 1)),
            _access("c", datetime(2026, 2, 1), domain="Other"),
        ]
    )
    await repo.upsert_objects([_obj("o", datetime(2026, 9, 1))])
    assert await repo.get_rulebase_last_update("access") == datetime(2026, 3, 1)
    assert await repo.get_rulebase_last_update("access", domain_names=["Other"]) == datetime(2026, 2, 1)
    assert await repo.get_rulebase_last_update("access", mgmt_names=["nope"]) is None
    assert await repo.get_rulebase_last_update("nat") is None


async def test_nat_rulebase_last_update_reads_the_nat_table(repo):
    await repo.upsert_rulebases([_nat("n1", datetime(2026, 4, 1)), _nat("n2", datetime(2026, 5, 1))])
    await repo.upsert_rulebases([_access("a", datetime(2026, 8, 1))])
    assert await repo.get_rulebase_last_update("nat", mgmt_names=["mgmt1"]) == datetime(2026, 5, 1)
    assert await repo.get_rulebase_last_update("nat", domain_names=["General"]) == datetime(2026, 5, 1)


async def test_rulebase_last_update_rejects_unknown_type(repo):
    with pytest.raises(ValueError, match="access, nat, https, threat"):
        await repo.get_rulebase_last_update("bogus")
