"""Unit tests for arodonata.cache.repository.CacheRepository.

Uses a real in-memory SQLite database (via aiosqlite) with tables created
from the SQLModel metadata - no mocks of the DB layer. A single StaticPool
connection is shared across sessions so every session sees the same data.

Rulebase operations live in test_repository_rulebase.py.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete as sa_delete
from sqlalchemy import select as sa_select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from arodonata.cache import models  # noqa: F401  (registers tables on metadata)
from arodonata.cache.database import DatabaseManager
from arodonata.cache.models import (
    Asset,
    CPObject,
    Domain,
    LastPublishedSession,
    SIDCache,
)
from arodonata.cache.repository import CacheRepository, _sid_key


@pytest.fixture
async def repo():
    """Create a repository backed by a shared in-memory SQLite database."""
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


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


@asynccontextmanager
async def open_session(repo: CacheRepository):
    """Yield a DB session for exercising the explicit-session code paths.

    CacheRepository exposes no public seam for obtaining a session, so this
    is the ONE place in this module that reaches into the private `_db`.
    """
    async with repo._db.session() as session:
        yield session


def make_object(uid: str, *, mgmt="m1", domain="", **kw) -> CPObject:
    """Build a CPObject with the standard composite id key."""
    return CPObject(
        id=f"{mgmt}:{domain}:{uid}",
        uid=uid,
        name=kw.pop("name", f"obj-{uid}"),
        type=kw.pop("type", "host"),
        mgmt_name=mgmt,
        domain_name=domain,
        **kw,
    )


def make_asset(name: str, *, mgmt="m1", domain="", atype="gateway", **kw) -> Asset:
    return Asset(
        asset_id=f"{mgmt}:{domain}:{name}",
        name=name,
        asset_type=atype,
        asset_uid=kw.pop("asset_uid", f"uid-{name}"),
        mgmt_name=mgmt,
        domain_name=domain,
        **kw,
    )


# ==========================================================================
# Composite key helper
# ==========================================================================


def test_sid_key_api_key_mode():
    assert _sid_key("mgmt1", "dom1") == "mgmt1:dom1"


def test_sid_key_credential_mode_includes_username():
    assert _sid_key("mgmt1", "dom1", "alice") == "mgmt1:dom1:alice"


# ==========================================================================
# SID operations
# ==========================================================================


async def test_set_and_get_sid(repo):
    await repo.set_sid("m1", "dom1", "sid-123", "10.0.0.1")
    record = await repo.get_sid("m1", "dom1")
    assert record is not None
    assert record.sid == "sid-123"
    assert record.server_ip == "10.0.0.1"


async def test_get_sid_miss_returns_none(repo):
    assert await repo.get_sid("m1", "missing") is None


async def test_set_sid_update_existing(repo):
    await repo.set_sid("m1", "dom1", "sid-1", "10.0.0.1")
    await repo.set_sid("m1", "dom1", "sid-2", "10.0.0.2", uid="u-9")
    # Clear memory to verify DB was actually updated (not just memory)
    repo._sid_memory.clear()
    record = await repo.get_sid("m1", "dom1")
    assert record.sid == "sid-2"
    assert record.server_ip == "10.0.0.2"
    assert record.uid == "u-9"
    # still a single row
    assert len(await repo.list_all_sids()) == 1


async def test_set_sid_update_refreshes_last_keepalive_in_db_and_memory(repo):
    """Regression test: re-login must update last_keepalive in both DB and memory."""
    # Seed initial SID
    await repo.set_sid("m1", "dom1", "sid-1", "10.0.0.1")
    old_time = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=1)

    # Age the DB row's last_keepalive conceptually
    async with open_session(repo) as session:
        row = (await session.execute(sa_select(SIDCache))).scalar_one()
        row.last_keepalive = old_time

    # Re-login (second set_sid for same key)
    before_update = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=1)
    await repo.set_sid("m1", "dom1", "sid-2", "10.0.0.1")

    # Verify memory was updated
    key = _sid_key("m1", "dom1")
    assert repo._sid_memory[key].last_keepalive >= before_update

    # Verify DB was updated (read directly, memory is cleared for this check)
    repo._sid_memory.clear()
    async with open_session(repo) as session:
        row = (await session.execute(sa_select(SIDCache))).scalar_one()
    assert row.last_keepalive >= before_update
    assert row.last_keepalive > old_time


async def test_set_and_get_sid_credential_mode_scopes_by_user(repo):
    await repo.set_sid("m1", "dom1", "sid-alice", "10.0.0.1", username="alice")
    await repo.set_sid("m1", "dom1", "sid-bob", "10.0.0.1", username="bob")
    alice = await repo.get_sid("m1", "dom1", username="alice")
    bob = await repo.get_sid("m1", "dom1", username="bob")
    assert alice.sid == "sid-alice"
    assert bob.sid == "sid-bob"
    assert len(await repo.list_all_sids()) == 2


async def test_get_sid_with_explicit_session(repo):
    async with open_session(repo) as session:
        await repo.set_sid("m1", "dom1", "sid-x", "10.0.0.1", session=session)
    # Clear memory to verify explicit-session path is exercised (not memory shortcut)
    repo._sid_memory.clear()
    async with open_session(repo) as session:
        record = await repo.get_sid("m1", "dom1", session=session)
    assert record.sid == "sid-x"


async def test_get_sid_fresh_within_max_age(repo):
    await repo.set_sid("m1", "dom1", "sid-fresh", "10.0.0.1")
    record = await repo.get_sid("m1", "dom1", max_age_seconds=3600)
    assert record is not None
    assert record.sid == "sid-fresh"


async def _insert_sid(repo, *, key, sid="s", server_ip="1.1.1.1", created_at, keepalive=None):
    async with open_session(repo) as session:
        session.add(
            SIDCache(
                mgmt_dmn_key=key,
                sid=sid,
                server_ip=server_ip,
                created_at=created_at,
                last_keepalive=keepalive,
            )
        )


async def test_get_sid_expired_is_deleted(repo):
    old = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=7200)
    await _insert_sid(repo, key="m1:dom1", created_at=old)
    result = await repo.get_sid("m1", "dom1", max_age_seconds=60)
    assert result is None
    # expired entry removed from cache
    assert await repo.list_all_sids() == []


async def test_delete_sid(repo):
    await repo.set_sid("m1", "dom1", "sid-1", "10.0.0.1")
    await repo.delete_sid("m1", "dom1")
    assert await repo.get_sid("m1", "dom1") is None


async def test_clear_sessions_all(repo):
    await repo.set_sid("m1", "a", "s1", "10.0.0.1")
    await repo.set_sid("m1", "b", "s2", "10.0.0.2")
    count = await repo.clear_sessions()
    assert count == 2
    assert await repo.list_all_sids() == []


async def test_clear_sessions_older_than(repo):
    now = datetime.now(UTC).replace(tzinfo=None)
    await _insert_sid(repo, key="m1:old", created_at=now - timedelta(seconds=7200))
    await _insert_sid(repo, key="m1:new", created_at=now)
    count = await repo.clear_sessions(older_than_seconds=60)
    assert count == 1
    remaining = await repo.list_all_sids()
    assert [r.mgmt_dmn_key for r in remaining] == ["m1:new"]


async def test_list_all_sids_empty(repo):
    assert await repo.list_all_sids() == []


async def test_update_keepalive_existing(repo):
    now = datetime.now(UTC).replace(tzinfo=None)
    stale = now - timedelta(seconds=3600)
    await _insert_sid(repo, key="m1:dom1", created_at=stale, keepalive=stale)
    await repo.update_keepalive("m1", "dom1")
    record = await repo.get_sid("m1", "dom1")
    # keepalive must actually move forward from the seeded stale value
    assert record.last_keepalive is not None
    assert record.last_keepalive != stale
    assert record.last_keepalive > stale


async def test_update_keepalive_missing_is_noop(repo):
    # should not raise even when no record exists
    await repo.update_keepalive("m1", "missing")
    assert await repo.get_sid("m1", "missing") is None


async def test_list_stale_keepalives(repo):
    now = datetime.now(UTC).replace(tzinfo=None)
    await _insert_sid(repo, key="m1:none", created_at=now, keepalive=None)
    await _insert_sid(repo, key="m1:stale", created_at=now, keepalive=now - timedelta(seconds=1200))
    await _insert_sid(repo, key="m1:fresh", created_at=now, keepalive=now)
    stale = await repo.list_stale_keepalives(threshold_seconds=600)
    keys = {r.mgmt_dmn_key for r in stale}
    assert keys == {"m1:none", "m1:stale"}


async def test_get_by_sid_hit_and_miss(repo):
    await repo.set_sid("m1", "dom1", "sid-abc", "10.0.0.1")
    assert (await repo.get_by_sid("sid-abc")).mgmt_dmn_key == "m1:dom1"
    assert await repo.get_by_sid("nope") is None


async def test_get_by_uid_hit_and_miss(repo):
    await repo.set_sid("m1", "dom1", "sid-abc", "10.0.0.1", uid="uid-1")
    assert (await repo.get_by_uid("uid-1")).sid == "sid-abc"
    assert await repo.get_by_uid("nope") is None


async def test_get_uid_by_sid(repo):
    await repo.set_sid("m1", "dom1", "sid-abc", "10.0.0.1", uid="uid-1")
    assert await repo.get_uid_by_sid("sid-abc") == "uid-1"
    assert await repo.get_uid_by_sid("nope") is None


async def test_get_sid_by_uid(repo):
    await repo.set_sid("m1", "dom1", "sid-abc", "10.0.0.1", uid="uid-1")
    assert await repo.get_sid_by_uid("uid-1") == "sid-abc"
    assert await repo.get_sid_by_uid("nope") is None


# ==========================================================================
# Asset operations (gateways / servers)
# ==========================================================================


async def test_upsert_and_get_assets(repo):
    n = await repo.upsert_assets([make_asset("gw1"), make_asset("gw2")])
    assert n == 2
    assets = await repo.get_assets()
    assert {a.name for a in assets} == {"gw1", "gw2"}


async def test_upsert_assets_empty_returns_zero(repo):
    assert await repo.upsert_assets([]) == 0


async def test_upsert_assets_blank_parent_becomes_none(repo):
    asset = make_asset("gw1", parent_asset_id="")
    await repo.upsert_assets([asset])
    stored = await repo.get_assets(asset_ids=[asset.asset_id])
    assert stored[0].parent_asset_id is None


async def test_upsert_asset_single_with_and_without_session(repo):
    await repo.upsert_asset(make_asset("gw1"))
    async with open_session(repo) as session:
        await repo.upsert_asset(make_asset("gw2"), session=session)
    names = {a.name for a in await repo.get_assets()}
    assert names == {"gw1", "gw2"}


async def test_upsert_assets_with_session(repo):
    async with open_session(repo) as session:
        n = await repo.upsert_assets([make_asset("gw1")], session=session)
    assert n == 1
    assert len(await repo.get_assets()) == 1


async def test_get_assets_filter_by_type_and_mgmt(repo):
    await repo.upsert_assets(
        [
            make_asset("gw1", mgmt="m1", atype="gateway"),
            make_asset("srv1", mgmt="m1", atype="server"),
            make_asset("gw2", mgmt="m2", atype="gateway"),
        ]
    )
    gateways = await repo.get_assets(asset_types=["gateway"])
    assert {a.name for a in gateways} == {"gw1", "gw2"}
    m2_only = await repo.get_assets(mgmt_names=["m2"])
    assert {a.name for a in m2_only} == {"gw2"}


async def test_delete_assets_filters(repo):
    await repo.upsert_assets(
        [
            make_asset("gw1", mgmt="m1", domain="d1"),
            make_asset("gw2", mgmt="m2", domain="d2"),
        ]
    )
    deleted = await repo.delete_assets(mgmt_names=["m1"])
    assert deleted == 1
    remaining = await repo.get_assets()
    assert {a.name for a in remaining} == {"gw2"}


async def test_delete_assets_by_domain(repo):
    await repo.upsert_assets([make_asset("gw1", domain="d1"), make_asset("gw2", domain="d2")])
    deleted = await repo.delete_assets(domain_names=["d2"])
    assert deleted == 1


async def test_delete_assets_all(repo):
    await repo.upsert_assets([make_asset("gw1"), make_asset("gw2")])
    assert await repo.delete_assets() == 2
    assert await repo.get_assets() == []


async def test_get_assets_filter_by_domain_names(repo):
    await repo.upsert_assets(
        [
            make_asset("gw1", domain="d1"),
            make_asset("gw2", domain="d2"),
        ]
    )
    d1_only = await repo.get_assets(domain_names=["d1"])
    assert {a.name for a in d1_only} == {"gw1"}


# ==========================================================================
# Local fields (path/ip_address/ssh_ip) preservation across a raw refresh
# ==========================================================================


async def test_restore_asset_local_fields_fills_in_blanked_values(repo):
    # Simulates the post-refresh state: the asset row was deleted and
    # recreated from live API data, which never sets path/ip_address/ssh_ip.
    await repo.upsert_assets([make_asset("gw1")])

    snapshot = {
        make_asset("gw1").asset_id: {
            "path": "/ssot/mgmt1/gw1",
            "ip_address": "1.2.3.4",
            "ssh_ip": "1.2.3.4",
        }
    }
    restored = await repo.restore_asset_local_fields(snapshot)

    assert restored == 1
    asset = (await repo.get_assets())[0]
    assert asset.path == "/ssot/mgmt1/gw1"
    assert asset.ip_address == "1.2.3.4"
    assert asset.ssh_ip == "1.2.3.4"


async def test_restore_asset_local_fields_never_overwrites_a_legitimate_value(repo):
    # The refresh itself set a real ip_address this time - restore must not
    # clobber it with the stale pre-refresh snapshot value.
    await repo.upsert_assets([make_asset("gw1", ip_address="5.6.7.8")])

    snapshot = {
        make_asset("gw1").asset_id: {
            "path": "/ssot/mgmt1/gw1",
            "ip_address": "1.2.3.4",
            "ssh_ip": "",
        }
    }
    restored = await repo.restore_asset_local_fields(snapshot)

    assert restored == 1
    asset = (await repo.get_assets())[0]
    assert asset.path == "/ssot/mgmt1/gw1"  # was blank, restored
    assert asset.ip_address == "5.6.7.8"  # was set, left alone
    assert asset.ssh_ip == ""  # snapshot had nothing to restore


async def test_restore_asset_local_fields_skips_asset_no_longer_in_cache(repo):
    snapshot = {"mgmt1::gone": {"path": "/x", "ip_address": "1.1.1.1", "ssh_ip": "1.1.1.1"}}

    restored = await repo.restore_asset_local_fields(snapshot)

    assert restored == 0


async def test_restore_asset_local_fields_empty_snapshot_is_a_noop(repo):
    assert await repo.restore_asset_local_fields({}) == 0


# ==========================================================================
# Domain operations
# ==========================================================================


async def test_upsert_and_get_domain(repo):
    domain = Domain.build(mgmt_name="m1", domain_name="d1", active_ip="10.0.0.1")
    await repo.upsert_domain(domain)
    fetched = await repo.get_domain("m1:d1")
    assert fetched is not None
    assert fetched.domain_name == "d1"


async def test_get_domain_miss(repo):
    assert await repo.get_domain("m1:nope") is None


async def test_get_domains_no_filter(repo):
    await repo.upsert_domain(Domain.build(mgmt_name="m1", domain_name="d1", active_ip="1"))
    await repo.upsert_domain(Domain.build(mgmt_name="m2", domain_name="d2", active_ip="2"))
    assert len(await repo.get_domains()) == 2


async def test_get_domains_singular_filter(repo):
    await repo.upsert_domain(Domain.build(mgmt_name="m1", domain_name="d1", active_ip="1"))
    await repo.upsert_domain(Domain.build(mgmt_name="m2", domain_name="d2", active_ip="2"))
    result = await repo.get_domains(mgmt_name="m1")
    assert {d.domain_name for d in result} == {"d1"}


async def test_get_domains_plural_filter(repo):
    await repo.upsert_domain(Domain.build(mgmt_name="m1", domain_name="d1", active_ip="1"))
    await repo.upsert_domain(Domain.build(mgmt_name="m2", domain_name="d2", active_ip="2"))
    await repo.upsert_domain(Domain.build(mgmt_name="m3", domain_name="d3", active_ip="3"))
    result = await repo.get_domains(mgmt_names=["m1", "m3"])
    assert {d.domain_name for d in result} == {"d1", "d3"}


# ==========================================================================
# CPObject operations
# ==========================================================================


async def test_upsert_objects_empty(repo):
    assert await repo.upsert_objects([]) == 0


async def test_upsert_objects_with_session(repo):
    async with open_session(repo) as session:
        n = await repo.upsert_objects([make_object("u1")], session=session)
    assert n == 1
    assert len(await repo.get_objects()) == 1


async def test_upsert_objects_conflict_updates_in_place(repo):
    await repo.upsert_objects([make_object("u1", name="before", color="red")])
    # Same composite id -> merge should update, not insert a new row.
    n = await repo.upsert_objects([make_object("u1", name="after", color="blue")])
    assert n == 1
    all_objs = await repo.get_objects()
    assert len(all_objs) == 1
    assert all_objs[0].name == "after"
    assert all_objs[0].color == "blue"


async def test_get_object_by_uid_hit_and_miss(repo):
    await repo.upsert_objects([make_object("u1")])
    assert (await repo.get_object_by_uid("u1")).uid == "u1"
    assert await repo.get_object_by_uid("missing") is None


async def test_get_object_by_uid_scoped_by_mgmt_and_domain(repo):
    await repo.upsert_objects(
        [
            make_object("u1", mgmt="m1", domain="d1"),
            make_object("u1", mgmt="m2", domain="d2"),
        ]
    )
    hit = await repo.get_object_by_uid("u1", mgmt_name="m2", domain_name="d2")
    assert hit.mgmt_name == "m2"
    # wrong domain -> miss
    assert await repo.get_object_by_uid("u1", mgmt_name="m1", domain_name="d2") is None


async def test_get_objects_by_ip(repo):
    await repo.upsert_objects(
        [
            make_object("u1", ipv4_address="10.0.0.5"),
            make_object("u2", ipv4_address_first="10.0.0.5"),
            make_object("u3", ipv4_address="10.0.0.9"),
        ]
    )
    hits = await repo.get_objects_by_ip("10.0.0.5")
    assert {o.uid for o in hits} == {"u1", "u2"}


async def test_get_objects_by_ip_with_scope_filters(repo):
    await repo.upsert_objects(
        [
            make_object("u1", mgmt="m1", domain="d1", ipv4_address="10.0.0.5"),
            make_object("u2", mgmt="m2", domain="d2", ipv4_address="10.0.0.5"),
        ]
    )
    hits = await repo.get_objects_by_ip("10.0.0.5", mgmt_names=["m1"], domain_names=["d1"])
    assert {o.uid for o in hits} == {"u1"}


async def test_get_objects_by_subnet(repo):
    await repo.upsert_objects(
        [
            make_object("u1", type="network", subnet4="192.168.1.0"),
            make_object("u2", type="network", subnet4="192.168.2.0"),
        ]
    )
    hits = await repo.get_objects_by_subnet("192.168.1.0", mgmt_names=["m1"], domain_names=[""])
    assert {o.uid for o in hits} == {"u1"}


async def test_get_objects_in_ip_range(repo):
    await repo.upsert_objects(
        [
            make_object(
                "u1",
                type="address-range",
                ipv4_address_first="10.0.0.1",
                ipv4_address_last="10.0.0.10",
            ),
            make_object(
                "u2",
                type="address-range",
                ipv4_address_first="10.0.1.1",
                ipv4_address_last="10.0.1.10",
            ),
        ]
    )
    hits = await repo.get_objects_in_ip_range("10.0.0.1", "10.0.0.10", mgmt_names=["m1"], domain_names=[""])
    assert {o.uid for o in hits} == {"u1"}


async def test_get_objects_by_name_exact_and_wildcard(repo):
    await repo.upsert_objects(
        [
            make_object("u1", name="web-server-1"),
            make_object("u2", name="web-server-2"),
            make_object("u3", name="db-server"),
        ]
    )
    exact = await repo.get_objects_by_name("db-server")
    assert {o.uid for o in exact} == {"u3"}
    wild = await repo.get_objects_by_name("web-*", mgmt_names=["m1"], domain_names=[""])
    assert {o.uid for o in wild} == {"u1", "u2"}


async def test_get_objects_by_uids_empty_returns_empty(repo):
    assert await repo.get_objects_by_uids([]) == []


async def test_get_objects_by_uids(repo):
    await repo.upsert_objects([make_object("u1"), make_object("u2"), make_object("u3")])
    hits = await repo.get_objects_by_uids(["u1", "u3"], mgmt_names=["m1"], domain_names=[""])
    assert {o.uid for o in hits} == {"u1", "u3"}


async def test_get_objects_no_filters(repo):
    await repo.upsert_objects([make_object("u1"), make_object("u2")])
    assert len(await repo.get_objects()) == 2


async def test_get_objects_type_and_scope_filters(repo):
    await repo.upsert_objects(
        [
            make_object("u1", type="host", mgmt="m1", domain="d1"),
            make_object("u2", type="network", mgmt="m1", domain="d1"),
            make_object("u3", type="host", mgmt="m2", domain="d2"),
        ]
    )
    hosts_m1 = await repo.get_objects(object_type="host", mgmt_names=["m1"], domain_names=["d1"])
    assert {o.uid for o in hosts_m1} == {"u1"}


async def test_get_objects_filters_exact_and_wildcard(repo):
    await repo.upsert_objects(
        [
            make_object("u1", name="web-1", color="red"),
            make_object("u2", name="web-2", color="blue"),
        ]
    )
    exact = await repo.get_objects(filters={"color": "red"})
    assert {o.uid for o in exact} == {"u1"}
    wild = await repo.get_objects(filters={"name": "web-*"})
    assert {o.uid for o in wild} == {"u1", "u2"}


async def test_get_objects_filter_unknown_key_is_ignored(repo):
    await repo.upsert_objects([make_object("u1")])
    # unknown key logs a warning and does not filter anything out
    result = await repo.get_objects(filters={"not_a_column": "x"})
    assert len(result) == 1


async def test_get_objects_by_type(repo):
    await repo.upsert_objects(
        [
            make_object("u1", type="group", mgmt="m1", domain="d1"),
            make_object("u2", type="host", mgmt="m1", domain="d1"),
        ]
    )
    groups = await repo.get_objects_by_type("group", mgmt_names=["m1"], domain_names=["d1"])
    assert {o.uid for o in groups} == {"u1"}


async def test_get_objects_by_members(repo):
    await repo.upsert_objects(
        [
            make_object("g1", type="group", members='"u1","u2"'),
            make_object("g2", type="group", members='"u3"'),
            make_object("u1", type="host"),
        ]
    )
    groups = await repo.get_objects_by_members("u1", mgmt_names=["m1"], domain_names=[""])
    assert {o.uid for o in groups} == {"g1"}


async def test_delete_domain_objects(repo):
    await repo.upsert_objects(
        [
            make_object("u1", mgmt="m1", domain="d1"),
            make_object("u2", mgmt="m1", domain="d1"),
            make_object("u3", mgmt="m1", domain="d2"),
        ]
    )
    deleted = await repo.delete_domain_objects("m1", "d1")
    assert deleted == 2
    remaining = await repo.get_objects()
    assert {o.uid for o in remaining} == {"u3"}


async def test_delete_object_present_and_absent(repo):
    await repo.upsert_objects([make_object("u1", mgmt="m1", domain="d1")])
    assert await repo.delete_object("u1", "m1", "d1") == 1
    # deleting again removes nothing
    assert await repo.delete_object("u1", "m1", "d1") == 0


# ==========================================================================
# LastPublishedSession operations
# ==========================================================================


async def test_last_published_session_write_and_read(repo):
    record = LastPublishedSession(
        id="m1:d1",
        mgmt_name="m1",
        domain_name="d1",
        published_time=datetime(2026, 1, 1),
        uid="sess-uid",
    )
    await repo.upsert_last_published_session(record)
    fetched = await repo.get_last_published_session("m1", "d1")
    assert fetched is not None
    assert fetched.uid == "sess-uid"


async def test_get_last_published_session_miss(repo):
    assert await repo.get_last_published_session("m1", "nope") is None


async def test_upsert_last_published_session_updates(repo):
    await repo.upsert_last_published_session(
        LastPublishedSession(id="m1:d1", mgmt_name="m1", domain_name="d1", uid="old")
    )
    await repo.upsert_last_published_session(
        LastPublishedSession(id="m1:d1", mgmt_name="m1", domain_name="d1", uid="new")
    )
    fetched = await repo.get_last_published_session("m1", "d1")
    assert fetched.uid == "new"


# ==========================================================================
# Lifecycle
# ==========================================================================


async def test_initialize_and_close():
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    db_manager = DatabaseManager(engine)
    repository = CacheRepository(db_manager)
    await repository.initialize()
    assert db_manager.is_initialized is True
    # tables usable after initialize
    await repository.set_sid("m1", "d1", "s1", "10.0.0.1")
    assert (await repository.get_sid("m1", "d1")).sid == "s1"
    await repository.close()
    await engine.dispose()


# ==========================================================================
# In-memory SID cache
# ==========================================================================


async def test_get_sid_served_from_memory_after_set(repo: CacheRepository) -> None:
    """After set_sid, get_sid works even if the DB row vanishes (memory hit)."""
    await repo.set_sid("m1", "d1", "sid-abc", "10.0.0.1")

    async with open_session(repo) as session:
        await session.execute(sa_delete(SIDCache))
        await session.commit()

    record = await repo.get_sid("m1", "d1")
    assert record is not None
    assert record.sid == "sid-abc"


async def test_get_sid_falls_back_to_db_for_new_instance(repo: CacheRepository) -> None:
    """A fresh repository (next run) finds the previous run's SID via the DB."""
    await repo.set_sid("m1", "d1", "sid-abc", "10.0.0.1")

    repo2 = CacheRepository(repo._db)
    record = await repo2.get_sid("m1", "d1")
    assert record is not None
    assert record.sid == "sid-abc"


async def test_expired_memory_entry_falls_through_to_db(repo: CacheRepository) -> None:
    """An aged memory copy is evicted and the DB decides (here: also gone)."""
    await repo.set_sid("m1", "d1", "sid-abc", "10.0.0.1")

    # Age the memory copy and remove the DB row
    key = next(iter(repo._sid_memory))
    repo._sid_memory[key].created_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=2)
    async with open_session(repo) as session:
        await session.execute(sa_delete(SIDCache))
        await session.commit()

    record = await repo.get_sid("m1", "d1", max_age_seconds=3600)
    assert record is None
    assert key not in repo._sid_memory


async def test_delete_sid_evicts_memory(repo: CacheRepository) -> None:
    await repo.set_sid("m1", "d1", "sid-abc", "10.0.0.1")
    await repo.delete_sid("m1", "d1")
    assert await repo.get_sid("m1", "d1") is None


async def test_clear_sessions_evicts_memory(repo: CacheRepository) -> None:
    await repo.set_sid("m1", "d1", "sid-abc", "10.0.0.1")
    await repo.clear_sessions()
    assert await repo.get_sid("m1", "d1") is None


async def test_update_keepalive_updates_memory_and_db(repo: CacheRepository) -> None:
    await repo.set_sid("m1", "d1", "sid-abc", "10.0.0.1")
    before = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=1)

    await repo.update_keepalive("m1", "d1")

    key = next(iter(repo._sid_memory))
    assert repo._sid_memory[key].last_keepalive >= before
    async with open_session(repo) as session:
        row = (await session.execute(sa_select(SIDCache))).scalar_one()
    assert row.last_keepalive is not None and row.last_keepalive >= before
