"""Unit tests for arodonata.cache.object_service.ObjectService.

Cache-first search, input classification, group-membership expansion, UID
lookup, and refresh delegation. Uses a real in-memory SQLite database (shared
via StaticPool so every session sees the same data) for cache reads/writes;
only the API-refresh seam on the client (``api_call`` / ``api_query`` /
``get_mgmt_names`` / ``_domain_service``) is mocked.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from arodonata import GLOBAL_DOMAIN_NAME
from arodonata.api.schemas import ApiCallResult, ApiQueryResult
from arodonata.cache import models  # noqa: F401  (registers tables on metadata)
from arodonata.cache.database import DatabaseManager
from arodonata.cache.models import CPObject, Domain, LastPublishedSession
from arodonata.cache.object_service import (
    GroupNode,
    ObjectService,
    RefreshMode,
    SearchResult,
    SearchType,
    classify_input,
)

# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------


@pytest.fixture
async def db():
    """A DatabaseManager backed by a shared in-memory SQLite database."""
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    manager = DatabaseManager(engine)
    manager._initialized = True
    yield manager
    await engine.dispose()


def make_client(mgmt_names: list[str] | None = None) -> MagicMock:
    """Build a client double exposing only the API-refresh seam."""
    client = MagicMock()
    client.get_mgmt_names = MagicMock(return_value=mgmt_names or [])
    client.api_call = AsyncMock()
    client.api_query = AsyncMock()
    return client


def make_service(db: DatabaseManager, client: MagicMock | None = None) -> ObjectService:
    return ObjectService(db_manager=db, client=client or make_client(["mgmt1"]))


def cpobj(uid, name, obj_type, *, mgmt="mgmt1", domain="dmn1", **kw) -> CPObject:
    return CPObject(
        id=f"{mgmt}:{domain}:{uid}",
        uid=uid,
        name=name,
        type=obj_type,
        mgmt_name=mgmt,
        domain_name=domain,
        **kw,
    )


async def collect(agen):
    return [item async for item in agen]


# ---------------------------------------------------------------------------
# classify_input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected_type", "expected_clean"),
    [
        ("127.0.0.1", SearchType.HOST, "127.0.0.1"),
        ("10.0.0.5", SearchType.HOST, "10.0.0.5"),
        ("192.168.1.0/24", SearchType.NETWORK, "192.168.1.0/24"),
        ("10.0.0.0/255.255.255.0", SearchType.NETWORK, "10.0.0.0/255.255.255.0"),
        ("10.0.0.1-10.0.0.10", SearchType.RANGE, "10.0.0.1-10.0.0.10"),
        ("10.0.0.1 - 10.0.0.10", SearchType.RANGE, "10.0.0.1 - 10.0.0.10"),
        ("web-server-01", SearchType.NAME, "web-server-01"),
        ("Any", SearchType.NAME, "Any"),
        ("999.999.999.999", SearchType.NAME, "999.999.999.999"),
        ("web-*", SearchType.NAME, "web-*"),
    ],
)
def test_classify_input(raw, expected_type, expected_clean):
    search_type, cleaned = classify_input(raw)
    assert search_type == expected_type
    assert cleaned == expected_clean


def test_classify_input_strips_whitespace():
    search_type, cleaned = classify_input("   10.0.0.1   ")
    assert search_type == SearchType.HOST
    assert cleaned == "10.0.0.1"


# ---------------------------------------------------------------------------
# Result data classes
# ---------------------------------------------------------------------------


def test_group_node_defaults_children_to_list():
    node = GroupNode(uid="u", name="n", domain="d", depth=0)
    assert node.children == []


def test_group_node_preserves_explicit_children():
    child = GroupNode(uid="c", name="child", domain="d", depth=1)
    node = GroupNode(uid="u", name="n", domain="d", depth=0, children=[child])
    assert node.children == [child]


def test_search_result_construction():
    result = SearchResult(search_term="x", search_type=SearchType.NAME, objects=[])
    assert result.memberships is None
    assert result.objects == []


# ---------------------------------------------------------------------------
# _fetch_objects_from_db — per-search-type dispatch
# ---------------------------------------------------------------------------


async def test_fetch_by_host_ip(db):
    service = make_service(db)
    await service._cache.upsert_objects([cpobj("h1", "host-a", "host", ipv4_address="10.0.0.5")])
    objects = await service._fetch_objects_from_db(SearchType.HOST, "10.0.0.5", ["mgmt1"], None)
    assert [o.uid for o in objects] == ["h1"]


async def test_fetch_by_subnet(db):
    service = make_service(db)
    await service._cache.upsert_objects(
        [cpobj("n1", "net-a", "network", subnet4="192.168.1.0", subnet_mask="255.255.255.0")]
    )
    objects = await service._fetch_objects_from_db(SearchType.NETWORK, "192.168.1.0", ["mgmt1"], None)
    assert [o.uid for o in objects] == ["n1"]


async def test_fetch_by_range(db):
    service = make_service(db)
    await service._cache.upsert_objects(
        [cpobj("r1", "range-a", "address-range", ipv4_address_first="10.0.0.1", ipv4_address_last="10.0.0.10")]
    )
    objects = await service._fetch_objects_from_db(SearchType.RANGE, "10.0.0.1 - 10.0.0.10", ["mgmt1"], None)
    assert [o.uid for o in objects] == ["r1"]


async def test_fetch_by_range_without_dash_returns_empty(db):
    service = make_service(db)
    objects = await service._fetch_objects_from_db(SearchType.RANGE, "10.0.0.1", ["mgmt1"], None)
    assert objects == []


async def test_fetch_by_name(db):
    service = make_service(db)
    await service._cache.upsert_objects([cpobj("h1", "web-server", "host")])
    objects = await service._fetch_objects_from_db(SearchType.NAME, "web-server", ["mgmt1"], None)
    assert [o.uid for o in objects] == ["h1"]


async def test_fetch_by_name_wildcard(db):
    service = make_service(db)
    await service._cache.upsert_objects(
        [cpobj("h1", "web-server-01", "host"), cpobj("h2", "web-server-02", "host"), cpobj("h3", "db-01", "host")]
    )
    objects = await service._fetch_objects_from_db(SearchType.NAME, "web-*", ["mgmt1"], None)
    assert {o.uid for o in objects} == {"h1", "h2"}


# ---------------------------------------------------------------------------
# search_objects
# ---------------------------------------------------------------------------


async def test_search_empty_input_yields_empty_name_result(db):
    service = make_service(db)
    results = await collect(service.search_objects("   ,  , "))
    assert len(results) == 1
    assert results[0].search_type == SearchType.NAME
    assert results[0].objects == []


async def test_search_no_mgmt_servers_yields_empty(db):
    service = make_service(db, make_client(mgmt_names=[]))
    results = await collect(service.search_objects("web-server"))
    assert len(results) == 1
    assert results[0].objects == []


async def test_search_by_name_hit(db):
    service = make_service(db)
    await service._cache.upsert_objects([cpobj("h1", "web-server", "host", ipv4_address="10.0.0.5")])
    results = await collect(service.search_objects("web-server", mgmt_names=["mgmt1"]))
    assert len(results) == 1
    assert results[0].search_type == SearchType.NAME
    assert [o.uid for o in results[0].objects] == ["h1"]
    assert results[0].memberships is None


async def test_search_by_ip_hit(db):
    service = make_service(db)
    await service._cache.upsert_objects([cpobj("h1", "web-server", "host", ipv4_address="10.0.0.5")])
    results = await collect(service.search_objects("10.0.0.5", mgmt_names=["mgmt1"]))
    assert results[0].search_type == SearchType.HOST
    assert [o.uid for o in results[0].objects] == ["h1"]


async def test_search_cache_miss_yields_empty_objects(db):
    service = make_service(db)
    results = await collect(service.search_objects("nonexistent", mgmt_names=["mgmt1"]))
    assert len(results) == 1
    assert results[0].objects == []
    assert results[0].memberships is None


async def test_search_multiple_terms(db):
    service = make_service(db)
    await service._cache.upsert_objects(
        [cpobj("h1", "web-server", "host", ipv4_address="10.0.0.5"), cpobj("h2", "db-server", "host")]
    )
    results = await collect(service.search_objects("web-server, db-server", mgmt_names=["mgmt1"]))
    assert [r.search_term for r in results] == ["web-server", "db-server"]


async def test_search_max_depth_zero_skips_memberships(db):
    service = make_service(db)
    await service._cache.upsert_objects(
        [
            cpobj("h1", "web-server", "host", ipv4_address="10.0.0.5"),
            cpobj("g1", "web-group", "group", members='"h1"'),
        ]
    )
    results = await collect(service.search_objects("web-server", mgmt_names=["mgmt1"], max_depth=0))
    assert results[0].objects
    assert results[0].memberships is None


async def test_search_with_group_membership(db):
    service = make_service(db)
    await service._cache.upsert_objects(
        [
            cpobj("h1", "web-server", "host", ipv4_address="10.0.0.5"),
            cpobj("g1", "web-group", "group", members='"h1"'),
        ]
    )
    results = await collect(service.search_objects("web-server", mgmt_names=["mgmt1"]))
    memberships = results[0].memberships
    assert memberships is not None
    assert "h1" in memberships
    assert memberships["h1"][0].name == "web-group"


async def test_search_objects_found_but_no_memberships(db):
    service = make_service(db)
    await service._cache.upsert_objects([cpobj("h1", "web-server", "host", ipv4_address="10.0.0.5")])
    results = await collect(service.search_objects("web-server", mgmt_names=["mgmt1"]))
    assert results[0].objects
    assert results[0].memberships is None


# ---------------------------------------------------------------------------
# _resolve_group_memberships — group expansion & cycle handling
# ---------------------------------------------------------------------------


async def test_resolve_memberships_no_groups(db):
    service = make_service(db)
    await service._cache.upsert_objects([cpobj("h1", "host", "host")])
    result = await service._resolve_group_memberships("h1", "mgmt1", "dmn1")
    assert result == []


async def test_resolve_memberships_max_depth_reached(db):
    service = make_service(db)
    result = await service._resolve_group_memberships("h1", "mgmt1", "dmn1", max_depth=2, current_depth=2)
    assert result == []


async def test_resolve_memberships_nested_children(db):
    service = make_service(db)
    await service._cache.upsert_objects(
        [
            cpobj("h1", "host", "host"),
            cpobj("gA", "group-A", "group", members='"h1"'),
            cpobj("gB", "group-B", "group", members='"gA"'),
        ]
    )
    result = await service._resolve_group_memberships("h1", "mgmt1", "dmn1", max_depth=3)
    assert len(result) == 1
    node_a = result[0]
    assert node_a.name == "group-A"
    assert node_a.depth == 0
    assert len(node_a.children) == 1
    assert node_a.children[0].name == "group-B"
    assert node_a.children[0].depth == 1


async def test_resolve_memberships_avoids_cycle(db):
    service = make_service(db)
    # group gA contains the host AND itself -> resolving gA's parents finds gA
    # again, which must be skipped via the visited set.
    await service._cache.upsert_objects(
        [
            cpobj("h1", "host", "host"),
            cpobj("gA", "group-A", "group", members='"h1","gA"'),
        ]
    )
    result = await service._resolve_group_memberships("h1", "mgmt1", "dmn1", max_depth=5)
    assert len(result) == 1
    assert result[0].children == []


# ---------------------------------------------------------------------------
# refresh_objects — mode / delegation paths
# ---------------------------------------------------------------------------


async def test_refresh_skip_mode(db):
    service = make_service(db)
    results = await collect(service.refresh_objects(mode="skip"))
    assert results == [{"message": "Refresh skipped (mode=skip)", "status": "skipped"}]


async def test_refresh_invalid_mode_defaults_to_skip(db):
    service = make_service(db)
    results = await collect(service.refresh_objects(mode="bogus"))
    assert results[0]["status"] == "skipped"


async def test_refresh_no_mgmt_servers(db):
    service = make_service(db, make_client(mgmt_names=[]))
    results = await collect(service.refresh_objects(mode="force"))
    assert results == [{"message": "No management servers available", "status": "error"}]


async def test_refresh_force_full_flow(db):
    client = make_client(mgmt_names=["mgmt1"])
    client.api_query.return_value = ApiQueryResult(
        success=True,
        objects=[{"uid": "o1", "name": "obj-1", "type": "host", "ipv4-address": "10.0.0.9"}],
    )
    client.api_call.return_value = ApiCallResult(
        success=True,
        data={"meta-info": {"last-modify-time": {"iso-8601": "2026-03-25T00:00:00+0000"}}},
    )
    service = make_service(db, client)
    await service._cache.upsert_domain(Domain.build(mgmt_name="mgmt1", domain_name="dmn1", active_ip="1.2.3.4"))

    results = await collect(service.refresh_objects(mode="force"))
    statuses = [r.get("status") for r in results]
    assert "processing_mgmt" in statuses
    assert "refreshing_domain" in statuses
    assert "type_fetched" in statuses
    assert "domain_complete" in statuses
    # one object type fetched per OBJECT_TYPES entry
    assert statuses.count("type_fetched") == len(ObjectService.OBJECT_TYPES)
    # objects were written to the cache
    stored = await service._cache.get_objects_by_name("obj-1", mgmt_names=["mgmt1"])
    assert stored


async def test_refresh_check_mode_refreshes_only_stale_domain(db):
    """End-to-end CHECK mode through the public refresh_objects() seam.

    dmnFresh has cached objects and an up-to-date LastPublishedSession (the
    API reports an older publish time) -> skipped. dmnStale has no cached
    objects -> stale -> refreshed. Proves refresh_objects wires mode=CHECK
    through _refresh_mgmt_server into _get_domains_to_refresh.
    """
    client = make_client(mgmt_names=["mgmt1"])
    client.api_call.return_value = ApiCallResult(
        success=True,
        data={"meta-info": {"last-modify-time": {"iso-8601": "2026-01-01T00:00:00+0000"}}},
    )
    client.api_query.return_value = ApiQueryResult(success=True, objects=[])
    service = make_service(db, client)
    await service._cache.upsert_domain(Domain.build(mgmt_name="mgmt1", domain_name="dmnFresh", active_ip="1.1.1.1"))
    await service._cache.upsert_domain(Domain.build(mgmt_name="mgmt1", domain_name="dmnStale", active_ip="1.1.1.2"))
    await service._cache.upsert_objects([cpobj("h1", "host", "host", domain="dmnFresh")])
    await service._cache.upsert_last_published_session(
        LastPublishedSession(
            id="mgmt1:dmnFresh",
            mgmt_name="mgmt1",
            domain_name="dmnFresh",
            published_time=datetime(2026, 6, 1),
        )
    )

    results = await collect(service.refresh_objects(mode="check"))

    refreshed = [r["domain_name"] for r in results if r.get("status") == "refreshing_domain"]
    assert refreshed == ["dmnStale"]
    completed = [r["domain_name"] for r in results if r.get("status") == "domain_complete"]
    assert completed == ["dmnStale"]
    # the fresh domain's cached object survived (was not cleared by a refresh)
    assert await service._cache.get_objects_by_name("host", mgmt_names=["mgmt1"])


async def test_refresh_mgmt_server_no_domains(db):
    client = make_client(mgmt_names=["mgmt1"])
    del client._domain_service  # hasattr(...) -> False
    service = make_service(db, client)
    results = await collect(service._refresh_mgmt_server("mgmt1", None, RefreshMode.FORCE))
    statuses = [r.get("status") for r in results]
    assert statuses == ["processing_mgmt", "no_domains"]


# ---------------------------------------------------------------------------
# _get_domains_to_refresh
# ---------------------------------------------------------------------------


async def test_get_domains_force_returns_all(db):
    service = make_service(db)
    await service._cache.upsert_domain(Domain.build(mgmt_name="mgmt1", domain_name="dmnA", active_ip="1.1.1.1"))
    await service._cache.upsert_domain(Domain.build(mgmt_name="mgmt1", domain_name="dmnB", active_ip="1.1.1.2"))
    domains = await service._get_domains_to_refresh("mgmt1", None, RefreshMode.FORCE)
    assert set(domains) == {"dmnA", "dmnB"}


async def test_get_domains_filters_by_domain_names(db):
    service = make_service(db)
    await service._cache.upsert_domain(Domain.build(mgmt_name="mgmt1", domain_name="dmnA", active_ip="1.1.1.1"))
    await service._cache.upsert_domain(Domain.build(mgmt_name="mgmt1", domain_name="dmnB", active_ip="1.1.1.2"))
    domains = await service._get_domains_to_refresh("mgmt1", ["dmnA"], RefreshMode.FORCE)
    assert domains == ["dmnA"]


async def test_get_domains_empty_cache_populated_from_api(db):
    client = make_client(mgmt_names=["mgmt1"])
    service = make_service(db, client)

    async def _populate(mgmt_name):
        await service._cache.upsert_domain(Domain.build(mgmt_name=mgmt_name, domain_name="dmnX", active_ip="9.9.9.9"))

    client._domain_service = MagicMock()
    client._domain_service.populate_domain_cache = AsyncMock(side_effect=_populate)

    domains = await service._get_domains_to_refresh("mgmt1", None, RefreshMode.FORCE)
    assert domains == ["dmnX"]
    client._domain_service.populate_domain_cache.assert_awaited_once_with("mgmt1")


async def test_get_domains_empty_cache_api_returns_none(db):
    client = make_client(mgmt_names=["mgmt1"])
    service = make_service(db, client)
    client._domain_service = MagicMock()
    client._domain_service.populate_domain_cache = AsyncMock()  # no-op, cache stays empty
    domains = await service._get_domains_to_refresh("mgmt1", None, RefreshMode.FORCE)
    assert domains == []


async def test_get_domains_no_domain_service(db):
    client = make_client(mgmt_names=["mgmt1"])
    del client._domain_service
    service = make_service(db, client)
    domains = await service._get_domains_to_refresh("mgmt1", None, RefreshMode.FORCE)
    assert domains == []


async def test_get_domains_populate_raises(db):
    client = make_client(mgmt_names=["mgmt1"])
    service = make_service(db, client)
    client._domain_service = MagicMock()
    client._domain_service.populate_domain_cache = AsyncMock(side_effect=RuntimeError("boom"))
    domains = await service._get_domains_to_refresh("mgmt1", None, RefreshMode.FORCE)
    assert domains == []


async def test_get_domains_to_refresh_excludes_global_by_default(db):
    service = make_service(db)
    await service._cache.upsert_domain(Domain.build(mgmt_name="mgmt1", domain_name="dmnA", active_ip="1.1.1.1"))
    await service._cache.upsert_domain(
        Domain.build(mgmt_name="mgmt1", domain_name=GLOBAL_DOMAIN_NAME, domain_uid="", active_ip="9.9.9.9")
    )
    domains = await service._get_domains_to_refresh("mgmt1", None, RefreshMode.FORCE)
    assert set(domains) == {"dmnA"}


async def test_get_domains_to_refresh_includes_global_when_requested(db):
    service = make_service(db)
    await service._cache.upsert_domain(Domain.build(mgmt_name="mgmt1", domain_name="dmnA", active_ip="1.1.1.1"))
    await service._cache.upsert_domain(
        Domain.build(mgmt_name="mgmt1", domain_name=GLOBAL_DOMAIN_NAME, domain_uid="", active_ip="9.9.9.9")
    )
    domains = await service._get_domains_to_refresh("mgmt1", None, RefreshMode.FORCE, include_global=True)
    assert set(domains) == {"dmnA", GLOBAL_DOMAIN_NAME}


async def test_get_domains_to_refresh_explicit_global_name(db):
    """Asking to refresh ["Global"] must find it even with include_global left False.

    Before Task 1, this returned [] (no Global row existed at all). With
    Task 1's row present, the table read must still reach it despite the
    default include_global=False, or the intersection filters it out before
    it can match.
    """
    service = make_service(db)
    await service._cache.upsert_domain(Domain.build(mgmt_name="mgmt1", domain_name="dmnA", active_ip="1.1.1.1"))
    await service._cache.upsert_domain(
        Domain.build(mgmt_name="mgmt1", domain_name=GLOBAL_DOMAIN_NAME, domain_uid="", active_ip="9.9.9.9")
    )
    domains = await service._get_domains_to_refresh("mgmt1", [GLOBAL_DOMAIN_NAME], RefreshMode.FORCE)
    assert domains == [GLOBAL_DOMAIN_NAME]


async def test_get_domains_check_mode_filters_stale(db):
    client = make_client(mgmt_names=["mgmt1"])
    # dmnFresh has cached objects + an up-to-date published session; API reports
    # an older time -> not stale. dmnStale has no cached objects -> stale.
    client.api_call.return_value = ApiCallResult(
        success=True,
        data={"meta-info": {"last-modify-time": {"iso-8601": "2026-01-01T00:00:00+0000"}}},
    )
    service = make_service(db, client)
    await service._cache.upsert_domain(Domain.build(mgmt_name="mgmt1", domain_name="dmnFresh", active_ip="1.1.1.1"))
    await service._cache.upsert_domain(Domain.build(mgmt_name="mgmt1", domain_name="dmnStale", active_ip="1.1.1.2"))
    await service._cache.upsert_objects([cpobj("h1", "host", "host", domain="dmnFresh")])
    await service._cache.upsert_last_published_session(
        LastPublishedSession(
            id="mgmt1:dmnFresh",
            mgmt_name="mgmt1",
            domain_name="dmnFresh",
            published_time=datetime(2026, 6, 1),
        )
    )

    domains = await service._get_domains_to_refresh("mgmt1", None, RefreshMode.CHECK)
    assert domains == ["dmnStale"]


# ---------------------------------------------------------------------------
# _is_domain_stale / _compare_published_times
# ---------------------------------------------------------------------------


async def test_is_domain_stale_true_when_no_cached_objects(db):
    client = make_client(mgmt_names=["mgmt1"])
    service = make_service(db, client)
    assert await service._is_domain_stale("mgmt1", "dmn1") is True
    client.api_call.assert_not_awaited()


async def test_is_domain_stale_true_when_no_cached_session(db):
    client = make_client(mgmt_names=["mgmt1"])
    client.api_call.return_value = ApiCallResult(
        success=True,
        data={"meta-info": {"last-modify-time": {"iso-8601": "2026-03-25T00:00:00+0000"}}},
    )
    service = make_service(db, client)
    await service._cache.upsert_objects([cpobj("h1", "host", "host")])
    assert await service._is_domain_stale("mgmt1", "dmn1") is True


async def test_is_domain_stale_true_when_api_time_newer(db):
    client = make_client(mgmt_names=["mgmt1"])
    client.api_call.return_value = ApiCallResult(
        success=True,
        data={"meta-info": {"last-modify-time": {"iso-8601": "2026-03-25T00:00:00+0000"}}},
    )
    service = make_service(db, client)
    await service._cache.upsert_objects([cpobj("h1", "host", "host")])
    await service._cache.upsert_last_published_session(
        LastPublishedSession(
            id="mgmt1:dmn1", mgmt_name="mgmt1", domain_name="dmn1", published_time=datetime(2026, 3, 1)
        )
    )
    assert await service._is_domain_stale("mgmt1", "dmn1") is True


async def test_is_domain_stale_false_when_api_time_not_newer(db):
    client = make_client(mgmt_names=["mgmt1"])
    client.api_call.return_value = ApiCallResult(
        success=True,
        data={"meta-info": {"last-modify-time": {"iso-8601": "2026-03-01T00:00:00+0000"}}},
    )
    service = make_service(db, client)
    await service._cache.upsert_objects([cpobj("h1", "host", "host")])
    await service._cache.upsert_last_published_session(
        LastPublishedSession(
            id="mgmt1:dmn1", mgmt_name="mgmt1", domain_name="dmn1", published_time=datetime(2026, 3, 25)
        )
    )
    assert await service._is_domain_stale("mgmt1", "dmn1") is False


async def test_is_domain_stale_false_on_api_exception(db):
    client = make_client(mgmt_names=["mgmt1"])
    client.api_call.side_effect = RuntimeError("network error")
    service = make_service(db, client)
    await service._cache.upsert_objects([cpobj("h1", "host", "host")])
    assert await service._is_domain_stale("mgmt1", "dmn1") is False


async def test_compare_published_times_false_when_api_unsuccessful(db):
    client = make_client(mgmt_names=["mgmt1"])
    client.api_call.return_value = ApiCallResult(success=False, data=None)
    service = make_service(db, client)
    assert await service._compare_published_times("mgmt1", "dmn1") is False


async def test_compare_published_times_uses_empty_domain_for_system(db):
    client = make_client(mgmt_names=["mgmt1"])
    client.api_call.return_value = ApiCallResult(success=True, data={})
    service = make_service(db, client)
    await service._compare_published_times("mgmt1", "SMC User")
    assert client.api_call.await_args.kwargs["domain"] == ""


# ---------------------------------------------------------------------------
# _parse_api_timestamp
# ---------------------------------------------------------------------------


def test_parse_timestamp_none(db):
    service = make_service(db)
    assert service._parse_api_timestamp(None) is None


def test_parse_timestamp_iso_with_offset(db):
    service = make_service(db)
    parsed = service._parse_api_timestamp({"iso-8601": "2026-03-25T12:00:00+0000"})
    assert parsed == datetime(2026, 3, 25, 12, 0, 0)
    assert parsed.tzinfo is None


def test_parse_timestamp_iso_with_z(db):
    service = make_service(db)
    parsed = service._parse_api_timestamp({"iso-8601": "2026-03-25T12:00:00Z"})
    assert parsed == datetime(2026, 3, 25, 12, 0, 0)


def test_parse_timestamp_posix_fallback(db):
    service = make_service(db)
    # invalid iso forces the posix branch
    parsed = service._parse_api_timestamp({"iso-8601": "not-a-date", "posix": 1000})
    assert parsed == datetime(1970, 1, 1, 0, 0, 1)


def test_parse_timestamp_all_invalid(db):
    service = make_service(db)
    assert service._parse_api_timestamp({"iso-8601": "bad", "posix": "bad"}) is None


def test_parse_timestamp_empty_dict(db):
    service = make_service(db)
    assert service._parse_api_timestamp({}) is None


# ---------------------------------------------------------------------------
# refresh_last_published_session
# ---------------------------------------------------------------------------


async def test_refresh_last_published_session_upserts(db):
    client = make_client(mgmt_names=["mgmt1"])
    client.api_call.return_value = ApiCallResult(
        success=True,
        data={
            "meta-info": {"last-modify-time": {"iso-8601": "2026-03-25T00:00:00+0000"}},
            "uid": "session-uid-1",
            "name": "session-1",
            "ip-address": "10.0.0.5",
            "creator": "admin",
            "description": "desc",
        },
    )
    service = make_service(db, client)
    record = await service.refresh_last_published_session("mgmt1", "domainA")

    client.api_call.assert_awaited_once_with(
        mgmt_name="mgmt1", domain="domainA", command="show-last-published-session", payload={}
    )
    assert record is not None
    assert record.id == "mgmt1:domainA"
    assert record.uid == "session-uid-1"
    stored = await service._cache.get_last_published_session("mgmt1", "domainA")
    assert stored is not None


async def test_refresh_last_published_session_empty_domain_for_smc_user(db):
    client = make_client(mgmt_names=["mgmt1"])
    client.api_call.return_value = ApiCallResult(success=True, data={})
    service = make_service(db, client)
    await service.refresh_last_published_session("mgmt1", "SMC User")
    assert client.api_call.await_args.kwargs["domain"] == ""


async def test_refresh_last_published_session_no_timestamp_returns_none(db):
    client = make_client(mgmt_names=["mgmt1"])
    client.api_call.return_value = ApiCallResult(success=True, data={"meta-info": {}})
    service = make_service(db, client)
    assert await service.refresh_last_published_session("mgmt1", "domainA") is None


async def test_refresh_last_published_session_failure_returns_none(db):
    client = make_client(mgmt_names=["mgmt1"])
    client.api_call.return_value = ApiCallResult(success=False, data=None)
    service = make_service(db, client)
    assert await service.refresh_last_published_session("mgmt1", "domainA") is None


async def test_refresh_last_published_session_exception_returns_none(db):
    client = make_client(mgmt_names=["mgmt1"])
    client.api_call.side_effect = RuntimeError("network error")
    service = make_service(db, client)
    assert await service.refresh_last_published_session("mgmt1", "domainA") is None


# ---------------------------------------------------------------------------
# _collect_objects_by_type
# ---------------------------------------------------------------------------


async def test_collect_objects_by_type_success(db):
    client = make_client(mgmt_names=["mgmt1"])
    client.api_query.return_value = ApiQueryResult(
        success=True,
        objects=[{"uid": "o1", "name": "obj-1", "type": "host", "ipv4-address": "10.0.0.9"}],
    )
    service = make_service(db, client)
    objects, error = await service._collect_objects_by_type("mgmt1", "dmn1", "host")
    assert error is None
    assert [o.uid for o in objects] == ["o1"]
    client.api_query.assert_awaited_once()
    assert client.api_query.await_args.kwargs["command"] == "show-hosts"


async def test_collect_objects_by_type_api_error(db):
    client = make_client(mgmt_names=["mgmt1"])
    client.api_query.return_value = ApiQueryResult(success=False, message="boom")
    service = make_service(db, client)
    objects, error = await service._collect_objects_by_type("mgmt1", "dmn1", "network")
    assert objects == []
    assert error == "boom"


async def test_collect_objects_by_type_exception(db):
    client = make_client(mgmt_names=["mgmt1"])
    client.api_query.side_effect = RuntimeError("kaboom")
    service = make_service(db, client)
    objects, error = await service._collect_objects_by_type("mgmt1", "dmn1", "group")
    assert objects == []
    assert "kaboom" in error


# ---------------------------------------------------------------------------
# _refresh_domain — collect-then-swap
# ---------------------------------------------------------------------------


def _stub_api_success_for_all_types(client: MagicMock) -> None:
    """Configure ``client.api_query`` to succeed (empty results) for every
    ``show-<type>s`` command issued by ``ObjectService.OBJECT_TYPES``."""
    client.api_query.return_value = ApiQueryResult(success=True, objects=[])


def _stub_api_failure_for_type(client: MagicMock, object_type: str) -> None:
    """Configure ``client.api_query`` so only one type's command fails.

    Earlier OBJECT_TYPES entries (e.g. "host") still succeed; the given
    type's ``show-<type>s`` command reports ``success=False``.
    """
    failing_command = f"show-{object_type}s"

    def _side_effect(*, mgmt_name, command, domain, details_level):
        if command == failing_command:
            return ApiQueryResult(success=False, message="boom")
        return ApiQueryResult(success=True, objects=[])

    client.api_query.side_effect = _side_effect


async def test_refresh_domain_replaces_stale_objects_on_success(db):
    """Collect-then-swap: stale objects are gone only via the final atomic
    replace, not an upfront delete."""
    client = make_client(mgmt_names=["mgmt1"])
    _stub_api_success_for_all_types(client)
    client.api_call.return_value = ApiCallResult(
        success=True,
        data={"meta-info": {"last-modify-time": {"iso-8601": "2026-03-25T00:00:00+0000"}}},
    )
    service = make_service(db, client)
    # pre-seed a stale object that must be cleared by the successful refresh
    await service._cache.upsert_objects([cpobj("old", "stale-obj", "host")])
    results = await collect(service._refresh_domain("mgmt1", "dmn1"))
    assert results[0]["status"] == "refreshing_domain"
    assert results[-1]["status"] == "domain_complete"
    remaining = await service._cache.get_objects_by_name("stale-obj", mgmt_names=["mgmt1"])
    assert remaining == []


async def test_refresh_domain_swaps_once_on_success(db):
    """All types collected first, then exactly one atomic replace + session stamp."""
    client = make_client(mgmt_names=["mgmt1"])
    _stub_api_success_for_all_types(client)
    client.api_call.return_value = ApiCallResult(
        success=True,
        data={"meta-info": {"last-modify-time": {"iso-8601": "2026-03-25T00:00:00+0000"}}},
    )
    service = make_service(db, client)
    service._cache.replace_domain_objects = AsyncMock(wraps=service._cache.replace_domain_objects)
    service._cache.delete_domain_objects = AsyncMock(wraps=service._cache.delete_domain_objects)

    events = await collect(service._refresh_domain("m1", "d1"))

    service._cache.replace_domain_objects.assert_awaited_once()
    args = service._cache.replace_domain_objects.await_args
    assert args.args[0:2] == ("m1", "d1")
    service._cache.delete_domain_objects.assert_not_awaited()
    assert events[-1]["status"] == "domain_complete"


async def test_refresh_domain_failure_keeps_old_cache_and_no_session_stamp(db):
    """If any show-<type>s call fails: no delete, no replace, no session stamp."""
    client = make_client(mgmt_names=["mgmt1"])
    _stub_api_failure_for_type(client, "network")  # hosts ok, networks fail
    service = make_service(db, client)
    # pre-seed cache contents that must survive the aborted refresh untouched
    await service._cache.upsert_objects([cpobj("old", "stale-obj", "host")])
    service._cache.replace_domain_objects = AsyncMock()
    service._cache.delete_domain_objects = AsyncMock()
    service.refresh_last_published_session = AsyncMock()

    events = await collect(service._refresh_domain("m1", "d1"))

    service._cache.replace_domain_objects.assert_not_awaited()
    service._cache.delete_domain_objects.assert_not_awaited()
    service.refresh_last_published_session.assert_not_awaited()
    assert events[-1]["status"] == "domain_failed"
    # old cache contents untouched
    remaining = await service._cache.get_objects_by_name("stale-obj", mgmt_names=["mgmt1"])
    assert remaining


# ---------------------------------------------------------------------------
# _extract_* helpers & _api_object_to_cpobject
# ---------------------------------------------------------------------------


def test_extract_ip_fields_host(db):
    service = make_service(db)
    assert service._extract_ip_fields("host", {"ipv4-address": "10.0.0.1"}) == (
        "10.0.0.1",
        "",
        "",
        "",
        "",
    )


def test_extract_ip_fields_network(db):
    service = make_service(db)
    assert service._extract_ip_fields("network", {"subnet4": "10.0.0.0", "subnet-mask": "255.255.255.0"}) == (
        "",
        "10.0.0.0",
        "255.255.255.0",
        "",
        "",
    )


def test_extract_ip_fields_range(db):
    service = make_service(db)
    assert service._extract_ip_fields(
        "address-range", {"ipv4-address-first": "10.0.0.1", "ipv4-address-last": "10.0.0.9"}
    ) == ("", "", "", "10.0.0.1", "10.0.0.9")


def test_extract_ip_fields_other_type(db):
    service = make_service(db)
    assert service._extract_ip_fields("group", {}) == ("", "", "", "", "")


def test_extract_group_members_non_group(db):
    service = make_service(db)
    assert service._extract_group_members("host", {"members": ["x"]}) == ""


def test_extract_group_members_string_and_dict(db):
    service = make_service(db)
    members = service._extract_group_members("group", {"members": ["uid-1", {"uid": "uid-2"}, {"uid": ""}, 123]})
    assert members == '"uid-1","uid-2"'


def test_extract_group_members_not_a_list(db):
    service = make_service(db)
    assert service._extract_group_members("group", {"members": "oops"}) == ""


def test_extract_tags_strings_and_dicts(db):
    service = make_service(db)
    assert service._extract_tags({"tags": ["t1", {"name": "t2"}]}) == "t1,t2"


def test_extract_tags_not_a_list(db):
    service = make_service(db)
    assert service._extract_tags({"tags": "nope"}) == ""


def test_api_object_to_cpobject_success(db):
    service = make_service(db)
    obj = service._api_object_to_cpobject(
        {
            "uid": "u1",
            "name": "host-1",
            "type": "host",
            "ipv4-address": "10.0.0.1",
            "tags": [{"name": "prod"}],
            "domain": {"name": "System Data", "uid": "dom-uid"},
        },
        mgmt_name="mgmt1",
        domain_name="dmn1",
    )
    assert obj is not None
    assert obj.id == "mgmt1:dmn1:u1"
    assert obj.ipv4_address == "10.0.0.1"
    assert obj.original_domain == "System Data"
    assert obj.original_domain_uid == "dom-uid"


def test_api_object_to_cpobject_domain_not_dict(db):
    service = make_service(db)
    # SRC BUG: original_domain_uid extraction guards against a non-dict
    # ``domain`` (isinstance check, line ~903), but original_domain extraction
    # at line ~913 unconditionally calls ``.get("name")`` on it. A string
    # ``domain`` therefore raises AttributeError, the outer try/except swallows
    # it, and conversion fails (returns None) instead of degrading gracefully.
    obj = service._api_object_to_cpobject(
        {"uid": "u1", "name": "host-1", "type": "host", "domain": "not-a-dict"},
        mgmt_name="mgmt1",
        domain_name="dmn1",
    )
    assert obj is None


def test_api_object_to_cpobject_missing_uid_or_name(db):
    service = make_service(db)
    assert service._api_object_to_cpobject({"uid": "", "name": "x"}, "mgmt1", "dmn1") is None
    assert service._api_object_to_cpobject({"uid": "u", "name": ""}, "mgmt1", "dmn1") is None


def test_api_object_to_cpobject_malformed_timestamp_dict_returns_none(db):
    service = make_service(db)
    # A creation-time dict with neither "iso-8601" nor "posix" keys is
    # explicitly treated as malformed (see api_object_to_cpobject's guard) and
    # raises ValueError by design, caught by the outer try/except -> None.
    obj = service._api_object_to_cpobject(
        {"uid": "u1", "name": "host-1", "type": "host", "creation-time": {"unexpected": "dict"}},
        mgmt_name="mgmt1",
        domain_name="dmn1",
    )
    assert obj is None


# ---------------------------------------------------------------------------
# Session-uid staleness comparison (unambiguous vs minute-resolution times)
# ---------------------------------------------------------------------------


async def test_is_domain_stale_true_when_uid_differs_despite_equal_times(db):
    """CP publish-times have minute resolution: a publish in the same minute
    as the cached baseline is invisible to timestamp comparison. The session
    uid comparison is authoritative."""
    client = make_client(mgmt_names=["mgmt1"])
    client.api_call.return_value = ApiCallResult(
        success=True,
        data={
            "uid": "uid-NEW",
            "meta-info": {"last-modify-time": {"iso-8601": "2026-03-25T00:00:00+0000"}},
        },
    )
    service = make_service(db, client)
    await service._cache.upsert_objects([cpobj("h1", "host", "host")])
    await service._cache.upsert_last_published_session(
        LastPublishedSession(
            id="mgmt1:dmn1",
            mgmt_name="mgmt1",
            domain_name="dmn1",
            published_time=datetime(2026, 3, 25),  # identical minute
            uid="uid-OLD",
        )
    )
    assert await service._is_domain_stale("mgmt1", "dmn1") is True


async def test_is_domain_stale_false_when_uid_matches(db):
    """Matching session uids mean nothing was published — fresh, regardless
    of small timestamp representation differences."""
    client = make_client(mgmt_names=["mgmt1"])
    client.api_call.return_value = ApiCallResult(
        success=True,
        data={
            "uid": "uid-SAME",
            "meta-info": {"last-modify-time": {"iso-8601": "2026-03-25T00:00:00+0000"}},
        },
    )
    service = make_service(db, client)
    await service._cache.upsert_objects([cpobj("h1", "host", "host")])
    await service._cache.upsert_last_published_session(
        LastPublishedSession(
            id="mgmt1:dmn1",
            mgmt_name="mgmt1",
            domain_name="dmn1",
            published_time=datetime(2026, 3, 25),
            uid="uid-SAME",
        )
    )
    assert await service._is_domain_stale("mgmt1", "dmn1") is False


async def test_is_domain_stale_falls_back_to_time_when_uid_missing(db):
    """Records tracked before the uid was stored (or API responses without a
    uid) keep the timestamp comparison."""
    client = make_client(mgmt_names=["mgmt1"])
    client.api_call.return_value = ApiCallResult(
        success=True,
        data={"meta-info": {"last-modify-time": {"iso-8601": "2026-03-25T00:00:00+0000"}}},
    )
    service = make_service(db, client)
    await service._cache.upsert_objects([cpobj("h1", "host", "host")])
    await service._cache.upsert_last_published_session(
        LastPublishedSession(
            id="mgmt1:dmn1",
            mgmt_name="mgmt1",
            domain_name="dmn1",
            published_time=datetime(2026, 3, 1),  # older -> stale via time
        )
    )
    assert await service._is_domain_stale("mgmt1", "dmn1") is True


# ---------------------------------------------------------------------------
# fetch_full_object + module-level converter
# ---------------------------------------------------------------------------


def test_api_object_to_cpobject_module_function_full_fidelity():
    from arodonata.cache.object_service import api_object_to_cpobject

    raw = {
        "uid": "u1",
        "name": "rng1",
        "type": "address-range",
        "ipv4-address-first": "10.0.0.1",
        "ipv4-address-last": "10.0.0.9",
        "comments": "c",
        "tags": [{"name": "t1"}, {"name": "t2"}],
        "color": "red",
        "interfaces": [{"name": "eth0", "ipv4-address": "10.0.0.1"}],
        "nat-settings": {"auto-rule": False},
        "domain": {"name": "dmn1", "uid": "du1"},
        "creation-time": {"posix": 1755000000000},
        "last-modify-time": {"posix": 1755000060000},
    }
    obj = api_object_to_cpobject(raw, "mgmt1", "dmn1")
    assert obj is not None
    assert obj.id == "mgmt1:dmn1:u1"
    assert obj.ipv4_address_first == "10.0.0.1"
    assert obj.ipv4_address_last == "10.0.0.9"
    assert obj.tags == "t1,t2"
    assert obj.comments == "c"
    assert obj.interfaces == [{"name": "eth0", "ipv4-address": "10.0.0.1"}]
    assert obj.nat_settings == {"auto-rule": False}
    assert obj.original_domain_uid == "du1"
    assert obj.creation_time is not None
    assert obj.last_modify_time is not None


def test_service_converter_delegates_to_module_function(db):
    service = make_service(db)
    raw = {"uid": "u1", "name": "h1", "type": "host", "ipv4-address": "10.1.1.1"}
    obj = service._api_object_to_cpobject(api_obj=raw, mgmt_name="m1", domain_name="d1")
    assert obj is not None and obj.ipv4_address == "10.1.1.1"


async def test_fetch_full_object_unwraps_object_payload(db):
    client = make_client(["mgmt1"])
    client.api_call.return_value = ApiCallResult(
        success=True, data={"object": {"uid": "u1", "name": "h1", "type": "host"}}
    )
    service = make_service(db, client)

    raw = await service.fetch_full_object("mgmt1", "dmn1", "u1")

    assert raw == {"uid": "u1", "name": "h1", "type": "host"}
    call = client.api_call.await_args.kwargs
    assert call["command"] == "show-object"
    assert call["payload"] == {"uid": "u1"}
    assert call["details_level"] == "full"
    assert call["domain"] == "dmn1"


async def test_fetch_full_object_special_domains_use_empty_api_domain(db):
    client = make_client(["mgmt1"])
    client.api_call.return_value = ApiCallResult(
        success=True, data={"object": {"uid": "u1", "name": "h1", "type": "host"}}
    )
    service = make_service(db, client)

    await service.fetch_full_object("mgmt1", "SMC User", "u1")

    assert client.api_call.await_args.kwargs["domain"] == ""


async def test_fetch_full_object_clean_not_found_returns_none(db):
    client = make_client(["mgmt1"])
    client.api_call.return_value = ApiCallResult(
        success=False, data=None, message="Requested object [u1] not found", code="generic_err_object_not_found"
    )
    service = make_service(db, client)

    assert await service.fetch_full_object("mgmt1", "dmn1", "u1") is None


async def test_fetch_full_object_other_failure_raises(db):
    client = make_client(["mgmt1"])
    client.api_call.return_value = ApiCallResult(success=False, data=None, message="boom", code="err_boom")
    service = make_service(db, client)

    with pytest.raises(RuntimeError, match="boom"):
        await service.fetch_full_object("mgmt1", "dmn1", "u1")


async def test_fetch_full_object_missing_object_key_raises(db):
    client = make_client(["mgmt1"])
    client.api_call.return_value = ApiCallResult(success=True, data={"unexpected": 1})
    service = make_service(db, client)

    with pytest.raises(RuntimeError, match="no object payload"):
        await service.fetch_full_object("mgmt1", "dmn1", "u1")


# ---------------------------------------------------------------------------
# refresh_objects(mode="incremental")
# ---------------------------------------------------------------------------


def _lps(uid="sess-old", *, mgmt="m1", domain="d1"):
    return LastPublishedSession(
        id=f"{mgmt}:{domain}",
        mgmt_name=mgmt,
        domain_name=domain,
        published_time=datetime(2026, 7, 1),
        uid=uid,
    )


async def _seed_incremental_domain(db, *, baseline=True, domain="d1"):
    """One domain with one cached host and (optionally) a baseline stamp."""
    async with db.session() as session:
        session.add(Domain.build(mgmt_name="m1", domain_name=domain, active_ip="1.1.1.1"))
        session.add(cpobj("old-1", "old-host", "host", mgmt="m1", domain=domain))
        if baseline:
            session.add(_lps(domain=domain))
        await session.commit()


async def _seed_incremental_domain_empty(db, *, mgmt="m1", domain="d1"):
    """A domain with a Domain row + baseline stamp but NO cached CPObject rows."""
    async with db.session() as session:
        session.add(Domain.build(mgmt_name=mgmt, domain_name=domain, active_ip="1.1.1.1"))
        session.add(_lps(mgmt=mgmt, domain=domain))
        await session.commit()


def _stale_probe_response():
    """show-last-published-session response with a NEW session uid -> stale."""
    return ApiCallResult(
        success=True,
        data={"uid": "sess-new", "meta-info": {"last-modify-time": {"posix": 1755100000000}}},
    )


async def test_incremental_mode_applies_diff_and_advances_baseline(db):
    await _seed_incremental_domain(db)
    client = make_client(["m1"])

    # api_call serves: staleness probe (stale), show-object re-fetch, final baseline stamp.
    def api_call_side_effect(**kwargs):
        if kwargs["command"] == "show-last-published-session":
            return _stale_probe_response()
        if kwargs["command"] == "show-object":
            return ApiCallResult(
                success=True,
                data={"object": {"uid": "u1", "name": "h1", "type": "host", "ipv4-address": "10.5.5.5"}},
            )
        raise AssertionError(f"unexpected api_call: {kwargs['command']}")

    client.api_call.side_effect = lambda **kw: api_call_side_effect(**kw)
    client._api_adapter.show_changes = AsyncMock(
        return_value={
            "success": True,
            "data": {"changes": [{"uid": "u1", "type": "host", "change-type": "add", "name": "h1"}]},
        }
    )
    service = make_service(db, client)

    events = await collect(service.refresh_objects(mgmt_names=["m1"], mode="incremental"))

    statuses = [e.get("status") for e in events]
    assert "domain_incremental" in statuses
    assert "refreshing_domain" not in statuses  # no full reload happened
    inc = next(e for e in events if e.get("status") == "domain_incremental")
    assert inc["count"] == 1 and inc["mgmt_name"] == "m1" and inc["domain_name"] == "d1"

    # The re-fetched object is in cache alongside the untouched old row.
    async with db.session() as session:
        rows = (await session.execute(select(CPObject))).scalars().all()
    by_uid = {r.uid: r for r in rows}
    assert by_uid["u1"].ipv4_address == "10.5.5.5"
    assert "old-1" in by_uid

    # Baseline advanced to the new session uid.
    async with db.session() as session:
        lps = (await session.execute(select(LastPublishedSession))).scalars().one()
    assert lps.uid == "sess-new"


async def test_incremental_mode_skips_fresh_domain(db):
    await _seed_incremental_domain(db)
    client = make_client(["m1"])
    # Probe returns the SAME session uid as the stored baseline -> fresh.
    client.api_call.return_value = ApiCallResult(
        success=True,
        data={"uid": "sess-old", "meta-info": {"last-modify-time": {"posix": 1750000000000}}},
    )
    service = make_service(db, client)

    events = await collect(service.refresh_objects(mgmt_names=["m1"], mode="incremental"))

    statuses = [e.get("status") for e in events]
    assert "domain_incremental" not in statuses and "refreshing_domain" not in statuses
    assert "no_domains" in statuses
    client._api_adapter.show_changes.assert_not_called()


async def test_incremental_mode_guard_falls_back_to_full_reload(db):
    await _seed_incremental_domain(db, baseline=False)  # no baseline -> FallbackToFull
    client = make_client(["m1"])

    def api_call_side_effect(**kwargs):
        if kwargs["command"] == "show-last-published-session":
            return _stale_probe_response()
        raise AssertionError(f"unexpected api_call: {kwargs['command']}")

    client.api_call.side_effect = lambda **kw: api_call_side_effect(**kw)

    # Per-command responses: only show-hosts returns an object, the other
    # three types return empty (a single return_value would insert the same
    # uid four times and violate the swap's primary key).
    def api_query_side_effect(**kwargs):
        if kwargs["command"] == "show-hosts":
            return ApiQueryResult(
                success=True, objects=[{"uid": "n1", "name": "new-host", "type": "host", "ipv4-address": "10.7.7.7"}]
            )
        return ApiQueryResult(success=True, objects=[])

    client.api_query.side_effect = lambda **kw: api_query_side_effect(**kw)
    service = make_service(db, client)

    events = await collect(service.refresh_objects(mgmt_names=["m1"], mode="incremental"))

    statuses = [e.get("status") for e in events]
    fb = next(e for e in events if e.get("status") == "domain_fallback")
    assert "no baseline" in fb["reason"]
    # Fallback ran the normal full-reload event stream and swapped the domain.
    assert "refreshing_domain" in statuses and "domain_complete" in statuses
    async with db.session() as session:
        rows = (await session.execute(select(CPObject))).scalars().all()
    assert {r.uid for r in rows} == {"n1"}  # old-1 swapped away atomically


async def test_incremental_mode_fallback_full_reload_failure_keeps_stamp(db):
    await _seed_incremental_domain(db, baseline=False)
    client = make_client(["m1"])

    def api_call_side_effect(**kwargs):
        if kwargs["command"] == "show-last-published-session":
            return _stale_probe_response()
        raise AssertionError(f"unexpected api_call: {kwargs['command']}")

    client.api_call.side_effect = lambda **kw: api_call_side_effect(**kw)
    client.api_query.return_value = ApiQueryResult(success=False, objects=[], message="api down")
    service = make_service(db, client)

    events = await collect(service.refresh_objects(mgmt_names=["m1"], mode="incremental"))

    statuses = [e.get("status") for e in events]
    assert "domain_fallback" in statuses and "domain_failed" in statuses
    # Old cache row survives; no baseline was ever stamped.
    async with db.session() as session:
        rows = (await session.execute(select(CPObject))).scalars().all()
        stamps = (await session.execute(select(LastPublishedSession))).scalars().all()
    assert {r.uid for r in rows} == {"old-1"}
    assert stamps == []


async def test_incremental_mode_zero_in_scope_changes_advances_baseline_only(db):
    await _seed_incremental_domain(db)
    client = make_client(["m1"])

    def api_call_side_effect(**kwargs):
        if kwargs["command"] == "show-last-published-session":
            return _stale_probe_response()
        raise AssertionError(f"unexpected api_call: {kwargs['command']}")

    client.api_call.side_effect = lambda **kw: api_call_side_effect(**kw)
    client._api_adapter.show_changes = AsyncMock(
        return_value={
            "success": True,
            "data": {"changes": [{"uid": "r1", "type": "access-rule", "change-type": "set", "name": "r1"}]},
        }
    )
    service = make_service(db, client)

    events = await collect(service.refresh_objects(mgmt_names=["m1"], mode="incremental"))

    inc = next(e for e in events if e.get("status") == "domain_incremental")
    assert inc["count"] == 0
    async with db.session() as session:
        lps = (await session.execute(select(LastPublishedSession))).scalars().one()
    assert lps.uid == "sess-new"  # rules-only publish: baseline advanced, objects untouched


async def test_incremental_mode_empty_cache_falls_back_to_full_reload(db):
    """A domain with a baseline stamp but zero cached CPObject rows must not
    get only the diff applied on top of an incomplete cache: that would stamp
    the domain fresh while leaving it permanently missing objects. Mirrors
    the coordinator's empty-cache guard (cache_refresh_coordinator.py
    _ensure_one's `_is_empty` check, lines 87-89)."""
    await _seed_incremental_domain_empty(db)
    client = make_client(["m1"])

    def api_call_side_effect(**kwargs):
        if kwargs["command"] == "show-last-published-session":
            return _stale_probe_response()
        raise AssertionError(f"unexpected api_call: {kwargs['command']}")

    client.api_call.side_effect = lambda **kw: api_call_side_effect(**kw)
    client._api_adapter.show_changes = AsyncMock()  # must never be reached
    _stub_api_success_for_all_types(client)
    service = make_service(db, client)

    events = await collect(service.refresh_objects(mgmt_names=["m1"], mode="incremental"))

    statuses = [e.get("status") for e in events]
    fb = next(e for e in events if e.get("status") == "domain_fallback")
    assert fb["reason"] == "empty domain cache"
    assert "refreshing_domain" in statuses and "domain_complete" in statuses
    assert "domain_incremental" not in statuses
    client._api_adapter.show_changes.assert_not_called()


async def test_incremental_fallback_matches_check_mode_end_state(db):
    """Spec's headline safety claim: when a diff exceeds the cap, the
    incremental path's fallback full reload leaves the cache in exactly the
    same end state that mode="check" (a direct full reload) would produce.

    Uses two identically-seeded domains in the same db: d1 goes through
    mode="incremental" with max_incremental_changes=0 (so the 1-add diff
    always exceeds the cap and falls back); d2 goes through mode="check"
    directly. Both must land on the same CPObject rows and the same
    LastPublishedSession uid.
    """
    await _seed_incremental_domain(db, domain="d1")
    await _seed_incremental_domain(db, domain="d2")

    client = make_client(["m1"])

    def api_call_side_effect(**kwargs):
        if kwargs["command"] == "show-last-published-session":
            return _stale_probe_response()
        raise AssertionError(f"unexpected api_call: {kwargs['command']}")

    client.api_call.side_effect = lambda **kw: api_call_side_effect(**kw)

    def api_query_side_effect(**kwargs):
        if kwargs["command"] == "show-hosts":
            return ApiQueryResult(
                success=True,
                objects=[{"uid": "n1", "name": "new-host", "type": "host", "ipv4-address": "10.7.7.7"}],
            )
        return ApiQueryResult(success=True, objects=[])

    client.api_query.side_effect = lambda **kw: api_query_side_effect(**kw)
    client._api_adapter.show_changes = AsyncMock(
        return_value={
            "success": True,
            "data": {"changes": [{"uid": "u1", "type": "host", "change-type": "add", "name": "h1"}]},
        }
    )

    service = make_service(db, client)
    service.max_incremental_changes = 0  # any non-empty diff exceeds the cap

    inc_events = await collect(service.refresh_objects(mgmt_names=["m1"], domain_names=["d1"], mode="incremental"))
    inc_statuses = [e.get("status") for e in inc_events]
    assert "domain_fallback" in inc_statuses
    assert "refreshing_domain" in inc_statuses and "domain_complete" in inc_statuses
    assert "domain_incremental" not in inc_statuses

    check_events = await collect(service.refresh_objects(mgmt_names=["m1"], domain_names=["d2"], mode="check"))
    check_statuses = [e.get("status") for e in check_events]
    assert "domain_complete" in check_statuses

    async with db.session() as session:
        rows = (await session.execute(select(CPObject))).scalars().all()
    by_domain: dict[str, list[tuple]] = {}
    for r in rows:
        by_domain.setdefault(r.domain_name, []).append((r.uid, r.name, r.type, r.ipv4_address, r.members))
    assert sorted(by_domain["d1"]) == sorted(by_domain["d2"])

    async with db.session() as session:
        lps_rows = (await session.execute(select(LastPublishedSession))).scalars().all()
    lps_by_domain = {r.domain_name: r.uid for r in lps_rows}
    assert lps_by_domain["d1"] == lps_by_domain["d2"]


def test_object_service_max_incremental_changes_param(db):
    service = ObjectService(db_manager=db, client=make_client(["m1"]), max_incremental_changes=42)
    assert service.max_incremental_changes == 42
    assert service._make_refresher()._max_changes == 42
