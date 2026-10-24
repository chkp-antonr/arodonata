"""Unit tests for `SearchService` (`search_objects`, `describe_objects`, `query_objects`, `get_cache_status`)."""

from __future__ import annotations

from collections.abc import Awaitable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext, SessionOverlay, WriteSession, write_session_context
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainInfo, DomainSyncState
from arodonata.core.models.objects import CPObject
from arodonata.core.models.services import CPService
from arodonata.core.services import (
    DomainService,
    DomainSyncCoordinator,
    ObjectService,
    SearchService,
    ServiceCacheService,
    classify_search_term,
)


class SearchFakeApi:
    """No-op `ApiPort` double for cache-backed search tests."""

    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ) -> ApiCallResult:
        return ApiCallResult(success=True, data={})

    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        *,
        domain: str | None = None,
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        limit: int = 300,
    ) -> ApiQueryResult:
        return ApiQueryResult(success=True, objects=[], total=0)

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        return "ded-sid", "10.0.0.1"

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> Awaitable[bool]:
        async def _noop() -> bool:
            return True

        return _noop()

    async def close(self, *, logout: bool | None = None) -> None:
        return None


def test_classify_search_term_variants() -> None:
    """`classify_search_term` distinguishes IPv4, CIDR, range, wildcard, UID, and object name."""
    assert classify_search_term("10.1.10.50").kind == "ipv4"
    assert classify_search_term("10.1.0.0/16").kind == "cidr"
    assert classify_search_term("10.1.10.10-10.1.10.99").kind == "range"
    assert classify_search_term("web-prod-*").kind == "wildcard"
    assert classify_search_term("550e8400-e29b-41d4-a716-446655440000").kind == "uid"
    assert classify_search_term("corp-db-primary").kind == "name"


@pytest.mark.asyncio
async def test_search_objects_ip_containment_and_recursive_group_membership_and_overlay() -> None:
    """`search_objects` resolves direct matches (host, containing network, containing range) and recursive parent groups up to `max_depth`, reflecting active `WriteSession` overlays."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = SearchFakeApi()

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    domain_service.tracker.mark_refreshed("mds1")
    await cache.upsert_domains(
        [DomainInfo(mgmt_name="mds1", uid="d1", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1")]
    )

    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    obj_service = ObjectService(settings=settings, api=api, cache=cache, coordinator=coordinator)
    svc_service = ServiceCacheService(settings=settings, api=api, cache=cache, coordinator=coordinator)
    search_service = SearchService(cache=cache, object_service=obj_service, service_cache=svc_service)

    host_uid = "550e8400-e29b-41d4-a716-446655440001"
    await cache.replace_domain_objects(
        "mds1",
        "Corp",
        [
            CPObject(
                uid=host_uid,
                name="srv-app-50",
                type="host",
                mgmt_name="mds1",
                domain_name="Corp",
                ipv4_address="10.1.10.50",
            ),
            CPObject(
                uid="net-1",
                name="net-10-1-10",
                type="network",
                mgmt_name="mds1",
                domain_name="Corp",
                subnet4="10.1.10.0",
                mask_length4=24,
            ),
            CPObject(
                uid="rng-1",
                name="rng-pool",
                type="address-range",
                mgmt_name="mds1",
                domain_name="Corp",
                ipv4_address_first="10.1.10.40",
                ipv4_address_last="10.1.10.60",
            ),
            CPObject(
                uid="grp-tier1",
                name="G_App_Servers",
                type="group",
                mgmt_name="mds1",
                domain_name="Corp",
                members=[host_uid],
            ),
            CPObject(
                uid="grp-tier2",
                name="G_All_Prod",
                type="group",
                mgmt_name="mds1",
                domain_name="Corp",
                members=["grp-tier1"],
            ),
            CPObject(
                uid="grp-tier3",
                name="G_Enterprise",
                type="group",
                mgmt_name="mds1",
                domain_name="Corp",
                members=["grp-tier2"],
            ),
        ],
        types=["host", "network", "address-range", "group"],
    )

    # 1. Search by IP "10.1.10.50" with max_depth=2
    res = await search_service.search_objects("10.1.10.50", mgmt_name="mds1", max_depth=2, cache_mode="cache")
    matched_uids = {m.uid for m in res.matches}
    assert matched_uids == {host_uid, "net-1", "rng-1"}

    # Check group hierarchy for host_uid up to depth 2 (G_App_Servers at depth=1, G_All_Prod at depth=2; G_Enterprise at depth=3 excluded)
    host_groups = res.memberships.get(host_uid, [])
    assert [(g.name, g.depth) for g in host_groups] == [("G_App_Servers", 1), ("G_All_Prod", 2)]

    # 2. Search with WriteSession overlay adding a new host and a group containing it
    overlay = SessionOverlay("mds1", "Corp")
    overlay.record_object_upsert(
        CPObject(
            uid="h-overlay",
            name="srv-staged-99",
            type="host",
            mgmt_name="mds1",
            domain_name="Corp",
            ipv4_address="10.1.10.99",
        )
    )
    overlay.record_object_upsert(
        CPObject(
            uid="grp-tier1",
            name="G_App_Servers",
            type="group",
            mgmt_name="mds1",
            domain_name="Corp",
            members=[host_uid, "h-overlay"],
        )
    )
    ws = WriteSession(mgmt_name="mds1", domain_name="Corp", sid="s-write", server_ip="10.1.0.1", overlay=overlay)
    with write_session_context(ws):
        res_overlay = await search_service.search_objects(
            "srv-staged-*", mgmt_name="mds1", max_depth=2, cache_mode="cache"
        )
        assert [m.uid for m in res_overlay.matches] == ["h-overlay"]
        assert [g.name for g in res_overlay.memberships["h-overlay"]] == ["G_App_Servers", "G_All_Prod"]

    # 3. Verify get_group_members recursive expansion
    members = await search_service.get_group_members("mds1", "Corp", "G_Enterprise", recursive=True, cache_mode="cache")
    assert {m.name for m in members} == {"G_All_Prod", "G_App_Servers", "srv-app-50"}

    await db.close()


@pytest.mark.asyncio
async def test_describe_objects_query_objects_and_cache_status() -> None:
    """`describe_objects`, `query_objects` (with `group_by`, `aggregate='count'`, `original_domain`), and `get_cache_status` work across domains."""
    t0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
    now = t0 + timedelta(seconds=45)

    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = SearchFakeApi()

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port, now_fn=lambda: now)
    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
        now_fn=lambda: now,
    )
    obj_service = ObjectService(settings=settings, api=api, cache=cache, coordinator=coordinator, now_fn=lambda: now)
    svc_service = ServiceCacheService(
        settings=settings, api=api, cache=cache, coordinator=coordinator, now_fn=lambda: now
    )
    search_service = SearchService(
        cache=cache,
        object_service=obj_service,
        service_cache=svc_service,
        now_fn=lambda: now,
    )

    await cache.replace_domain_objects(
        "mds1",
        "Corp",
        [
            CPObject(
                uid="h1",
                name="h-local-1",
                type="host",
                mgmt_name="mds1",
                domain_name="Corp",
                original_domain="Corp",
                ipv4_address="10.1.0.10",
                tags=["prod"],
            ),
            CPObject(
                uid="h2",
                name="h-global-shared",
                type="host",
                mgmt_name="mds1",
                domain_name="Corp",
                original_domain="Global",
                ipv4_address="10.0.0.50",
                tags=["shared"],
            ),
            CPObject(
                uid="n1",
                name="net-corp",
                type="network",
                mgmt_name="mds1",
                domain_name="Corp",
                original_domain="Corp",
                subnet4="10.1.0.0",
                mask_length4=24,
            ),
        ],
        types=["host", "network"],
    )
    await cache.replace_domain_services(
        "mds1",
        "Corp",
        [
            CPService(
                uid="s1",
                name="https",
                type="service-tcp",
                mgmt_name="mds1",
                domain_name="Corp",
                port="443",
                protocol="tcp",
            )
        ],
        types=["service-tcp"],
    )
    await cache.upsert_sync_state(
        DomainSyncState(
            mgmt_name="mds1",
            domain_name="Corp",
            scope="objects",
            item_type="host",
            last_published_at=t0,
            last_session_uid="sess-abc",
            synced_at=t0,
            status="ok",
            object_count=2,
        )
    )

    desc = await search_service.describe_objects(mgmt_name="mds1")
    assert desc["total_objects"] == 3
    assert desc["total_services"] == 1
    assert desc["object_types"] == {"host": 2, "network": 1}
    assert desc["service_types"] == {"service-tcp": 1}

    # Grouped aggregation by (domain_name, type)
    grouped = await search_service.query_objects(
        mgmt_name="mds1",
        types=["host", "network"],
        group_by=["domain_name", "type"],
        aggregate="count",
    )
    assert grouped["total"] == 3
    assert grouped["groups"] == [
        {"domain_name": "Corp", "type": "host", "count": 2},
        {"domain_name": "Corp", "type": "network", "count": 1},
    ]

    # Filter local vs global via scope_origin
    local_only = await search_service.query_objects(mgmt_name="mds1", types=["host"], scope_origin="local")
    assert local_only["total"] == 1
    assert local_only["objects"][0]["name"] == "h-local-1"

    global_only = await search_service.query_objects(mgmt_name="mds1", types=["host"], scope_origin="global")
    assert global_only["total"] == 1
    assert global_only["objects"][0]["name"] == "h-global-shared"

    # Cache status reports cache_age_seconds = 45.0
    status = await search_service.get_cache_status(mgmt_name="mds1")
    assert status["total_entries"] == 1
    entry = status["entries"][0]
    assert entry["cache_age_seconds"] == 45.0
    assert entry["last_session_uid"] == "sess-abc"

    await db.close()
