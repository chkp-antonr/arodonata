"""Unit tests for CacheRepository rulebase operations.

Real in-memory SQLite, tables created from SQLModel metadata. Covers rule
retrieval by model type / layer / enabled flag, ordering, upsert (single and
bulk, insert then update), and scoped deletes.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from arodonata.cache import models  # noqa: F401  (registers tables on metadata)
from arodonata.cache.database import DatabaseManager
from arodonata.cache.models import RulebaseAccess, RulebaseNAT
from arodonata.cache.repository import CacheRepository


@pytest.fixture
async def repo():
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


@asynccontextmanager
async def open_session(repo: CacheRepository):
    """Yield a DB session for exercising the explicit-session code paths.

    CacheRepository exposes no public seam for obtaining a session, so this
    is the ONE place in this module that reaches into the private `_db`.
    """
    async with repo._db.session() as session:
        yield session


def make_access(
    uid: str,
    *,
    rule_number: int,
    mgmt="m1",
    domain="",
    layer="Network",
    enabled=True,
    **kw,
) -> RulebaseAccess:
    return RulebaseAccess(
        id=f"{mgmt}:{domain}:{layer}:{uid}",
        uid=uid,
        rule_number=rule_number,
        name=kw.pop("name", f"rule-{uid}"),
        enabled=enabled,
        layer_name=layer,
        mgmt_name=mgmt,
        domain_name=domain,
        **kw,
    )


def make_nat(uid: str, *, rule_number: int, mgmt="m1", domain="", layer="NAT") -> RulebaseNAT:
    return RulebaseNAT(
        id=f"{mgmt}:{domain}:{layer}:{uid}",
        uid=uid,
        rule_number=rule_number,
        name=f"nat-{uid}",
        enabled=True,
        layer_name=layer,
        mgmt_name=mgmt,
        domain_name=domain,
    )


async def test_upsert_rulebases_and_get_ordered(repo):
    n = await repo.upsert_rulebases(
        [
            make_access("r3", rule_number=3),
            make_access("r1", rule_number=1),
            make_access("r2", rule_number=2),
        ]
    )
    assert n == 3
    rules = await repo.get_rulebase(RulebaseAccess)
    # results ordered by rule_number
    assert [r.rule_number for r in rules] == [1, 2, 3]


async def test_upsert_rulebases_empty(repo):
    assert await repo.upsert_rulebases([]) == 0


async def test_upsert_rulebases_with_session(repo):
    async with open_session(repo) as session:
        n = await repo.upsert_rulebases([make_access("r1", rule_number=1)], session=session)
    assert n == 1
    assert len(await repo.get_rulebase(RulebaseAccess)) == 1


async def test_upsert_rulebase_single_with_and_without_session(repo):
    await repo.upsert_rulebase(make_access("r1", rule_number=1))
    async with open_session(repo) as session:
        await repo.upsert_rulebase(make_access("r2", rule_number=2), session=session)
    rules = await repo.get_rulebase(RulebaseAccess)
    assert {r.uid for r in rules} == {"r1", "r2"}


async def test_upsert_rulebase_conflict_updates_in_place(repo):
    await repo.upsert_rulebase(make_access("r1", rule_number=1, name="before"))
    await repo.upsert_rulebase(make_access("r1", rule_number=1, name="after"))
    rules = await repo.get_rulebase(RulebaseAccess)
    assert len(rules) == 1
    assert rules[0].name == "after"


async def test_get_rulebase_is_type_scoped(repo):
    await repo.upsert_rulebases([make_access("a1", rule_number=1)])
    await repo.upsert_rulebases([make_nat("n1", rule_number=1)])
    access = await repo.get_rulebase(RulebaseAccess)
    nat = await repo.get_rulebase(RulebaseNAT)
    assert {r.uid for r in access} == {"a1"}
    assert {r.uid for r in nat} == {"n1"}


async def test_get_rulebase_filter_by_layer(repo):
    await repo.upsert_rulebases(
        [
            make_access("a1", rule_number=1, layer="Network"),
            make_access("a2", rule_number=2, layer="DMZ"),
        ]
    )
    dmz = await repo.get_rulebase(RulebaseAccess, filters={"layer_name": "DMZ"})
    assert {r.uid for r in dmz} == {"a2"}


async def test_get_rulebase_filter_by_enabled(repo):
    await repo.upsert_rulebases(
        [
            make_access("a1", rule_number=1, enabled=True),
            make_access("a2", rule_number=2, enabled=False),
        ]
    )
    enabled = await repo.get_rulebase(RulebaseAccess, filters={"enabled": True})
    assert {r.uid for r in enabled} == {"a1"}


async def test_get_rulebase_scope_by_mgmt_and_domain(repo):
    await repo.upsert_rulebases(
        [
            make_access("a1", rule_number=1, mgmt="m1", domain="d1"),
            make_access("a2", rule_number=2, mgmt="m2", domain="d2"),
        ]
    )
    scoped = await repo.get_rulebase(RulebaseAccess, mgmt_names=["m1"], domain_names=["d1"])
    assert {r.uid for r in scoped} == {"a1"}


async def test_get_rulebase_empty(repo):
    assert await repo.get_rulebase(RulebaseAccess) == []


async def test_delete_rulebase_by_domain(repo):
    await repo.upsert_rulebases(
        [
            make_access("a1", rule_number=1, mgmt="m1", domain="d1"),
            make_access("a2", rule_number=2, mgmt="m1", domain="d1"),
            make_access("a3", rule_number=3, mgmt="m1", domain="d2"),
        ]
    )
    deleted = await repo.delete_rulebase(RulebaseAccess, "m1", "d1")
    assert deleted == 2
    remaining = await repo.get_rulebase(RulebaseAccess)
    assert {r.uid for r in remaining} == {"a3"}


async def test_delete_rulebase_by_layer(repo):
    await repo.upsert_rulebases(
        [
            make_access("a1", rule_number=1, layer="Network"),
            make_access("a2", rule_number=2, layer="DMZ"),
        ]
    )
    deleted = await repo.delete_rulebase(RulebaseAccess, "m1", "", layer_name="DMZ")
    assert deleted == 1
    remaining = await repo.get_rulebase(RulebaseAccess)
    assert {r.uid for r in remaining} == {"a1"}
