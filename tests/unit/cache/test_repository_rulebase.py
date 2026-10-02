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
from arodonata.cache.models import RulebaseAccess, RulebaseLayer, RulebaseNAT, RulebaseSyncState
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


def sync(domain="d1", **kw):
    return RulebaseSyncState(id=f"m1:{domain}", mgmt_name="m1", domain_name=domain, format_version=2, status="ok", **kw)


def layer_row(uid, domain="d1"):
    return RulebaseLayer(
        id=f"m1:{domain}:access:{uid}", mgmt_name="m1", domain_name=domain, rulebase_type="access", layer_uid=uid
    )


async def test_replace_domain_rulebases_swaps_domain_rows_only(repo):
    await repo.upsert_rulebases(
        [
            make_access("old", rule_number=1, mgmt="m1", domain="d1"),
            make_access("other", rule_number=1, mgmt="m1", domain="d2"),
        ]
    )
    new = make_access("new", rule_number=1, mgmt="m1", domain="d1")
    n = await repo.replace_domain_rulebases("m1", "d1", [new, new, layer_row("L")], sync(session_uid="s1"))
    assert n == 1
    assert [r.uid for r in await repo.get_rulebase(RulebaseAccess, ["m1"], ["d1"])] == ["new"]
    assert [r.uid for r in await repo.get_rulebase(RulebaseAccess, ["m1"], ["d2"])] == ["other"]
    assert (await repo.get_rulebase_sync_state("m1", "d1")).session_uid == "s1"


async def test_replace_domain_rulebases_commit_failure_keeps_rows_and_state(repo, monkeypatch):
    await repo.replace_domain_rulebases(
        "m1", "d1", [make_access("old", rule_number=1, mgmt="m1", domain="d1")], sync(session_uid="s1")
    )
    from sqlalchemy.ext.asyncio import AsyncSession

    async def _boom(self, *args, **kwargs):
        raise RuntimeError("simulated commit failure")

    monkeypatch.setattr(AsyncSession, "commit", _boom)
    with pytest.raises(RuntimeError, match="simulated commit failure"):
        await repo.replace_domain_rulebases(
            "m1", "d1", [make_access("new", rule_number=1, mgmt="m1", domain="d1")], sync(session_uid="s2")
        )
    monkeypatch.undo()
    assert [r.uid for r in await repo.get_rulebase(RulebaseAccess, ["m1"], ["d1"])] == ["old"]
    assert (await repo.get_rulebase_sync_state("m1", "d1")).session_uid == "s1"


async def test_replace_domain_rulebases_uses_one_session(repo, monkeypatch):
    real = repo._db.session
    opened = []

    def spy():
        opened.append(1)
        return real()

    monkeypatch.setattr(repo._db, "session", spy)
    await repo.replace_domain_rulebases("m1", "d1", [make_access("new", rule_number=1, mgmt="m1", domain="d1")], sync())
    assert opened == [1]


async def test_first_v2_replace_purges_old_format_rows(repo):
    await repo.upsert_rulebases(
        [make_access("pre-v2", rule_number=1, mgmt="m1", domain="d1")]
    )  # id mgmt:domain:layer_name:uid, layer_uid NULL
    await repo.replace_domain_rulebases("m1", "d1", [], sync())
    assert await repo.get_rulebase(RulebaseAccess, ["m1"], ["d1"]) == []


async def test_mark_rulebase_sync_failed_keeps_session_and_format(repo):
    await repo.replace_domain_rulebases("m1", "d1", [], sync(session_uid="s1"))
    await repo.mark_rulebase_sync_failed("m1", "d1", "dirty session")
    st = await repo.get_rulebase_sync_state("m1", "d1")
    assert (st.status, st.last_error, st.session_uid, st.format_version) == ("failed", "dirty session", "s1", 2)


async def test_mark_rulebase_sync_failed_without_state_creates_unready_row(repo):
    await repo.mark_rulebase_sync_failed("m1", "d9", "boom")
    st = await repo.get_rulebase_sync_state("m1", "d9")
    assert (st.status, st.format_version, st.session_uid) == ("failed", 0, None)


async def test_get_rulebase_orders_by_layer_then_rule_number(repo):
    await repo.upsert_rulebases(
        [
            make_access("b1", rule_number=1, layer="B"),
            make_access("a2", rule_number=2, layer="A"),
            make_access("b2", rule_number=2, layer="B"),
            make_access("a1", rule_number=1, layer="A"),
        ]
    )
    assert [r.uid for r in await repo.get_rulebase(RulebaseAccess)] == ["a1", "a2", "b1", "b2"]


async def test_get_rulebase_keeps_same_named_layers_apart(repo):
    await repo.upsert_rulebases(
        [
            make_access("g1", rule_number=1, layer_uid="uid-g"),
            make_access("d1", rule_number=1, layer_uid="uid-d"),
            make_access("g2", rule_number=2, layer_uid="uid-g"),
            make_access("d2", rule_number=2, layer_uid="uid-d"),
        ]
    )
    assert [r.uid for r in await repo.get_rulebase(RulebaseAccess)] == ["d1", "d2", "g1", "g2"]


async def test_get_rulebase_excludes_place_holders(repo):
    rule = make_access("r1", rule_number=1)
    placeholder = make_access("ph", rule_number=2)
    placeholder.kind = "place-holder"
    await repo.upsert_rulebases([rule, placeholder])
    assert [r.uid for r in await repo.get_rulebase(RulebaseAccess)] == ["r1"]


def test_repository_uses_shared_model_map():
    from arodonata.cache import repository
    from arodonata.cache.models import RULEBASE_MODELS

    assert repository._RULEBASE_MODELS is RULEBASE_MODELS
