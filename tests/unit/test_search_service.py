"""Unit tests for `SearchService` (`search_objects`, `describe_objects`, `query_objects`, `get_cache_status`)."""

from __future__ import annotations

from collections.abc import Awaitable
from datetime import datetime, timedelta
from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext, SessionOverlay, WriteSession, write_session_context
from arodonata.core.errors import AmbiguousObjectError, ValidationError
from arodonata.core.models.assets import Asset
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


@pytest.mark.spec("SCN-CACHE-002-3", "SCN-CACHE-013-1")
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
    assert host_groups[0].id == "mds1:Corp:grp-tier1"
    assert host_groups[0].object_id == "mds1:Corp:G_App_Servers"
    assert host_groups[0].parent_uids == ["grp-tier2"]
    assert host_groups[0].parent_object_ids == ["mds1:Corp:G_All_Prod"]
    assert host_groups[1].id == "mds1:Corp:grp-tier2"
    assert host_groups[1].object_id == "mds1:Corp:G_All_Prod"
    assert host_groups[1].parent_uids == ["grp-tier3"]
    assert host_groups[1].parent_object_ids == ["mds1:Corp:G_Enterprise"]

    # Search by composite object_id and wildcard composite object_id
    res_obj_id = await search_service.search_objects(
        "mds1:Corp:srv-app-50", mgmt_name="mds1", exact_match=True, cache_mode="cache"
    )
    assert [m.uid for m in res_obj_id.matches] == [host_uid]

    res_obj_wild = await search_service.search_objects(
        "mds1:Corp:srv-app-*", mgmt_name="mds1", exact_match=True, cache_mode="cache"
    )
    assert [m.uid for m in res_obj_wild.matches] == [host_uid]

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

    # 3. Verify get_group_members recursive expansion on network groups, service-groups, and cluster/VSX assets
    members = await search_service.get_group_members("mds1", "Corp", "G_Enterprise", recursive=True, cache_mode="cache")
    assert {m.name for m in members} == {"G_All_Prod", "G_App_Servers", "srv-app-50"}

    await cache.replace_domain_services(
        "mds1",
        "Corp",
        [
            CPService(
                uid="svc-http",
                name="http",
                type="service-tcp",
                mgmt_name="mds1",
                domain_name="Corp",
                port="80",
                protocol="tcp",
            ),
            CPService(
                uid="svc-https",
                name="https",
                type="service-tcp",
                mgmt_name="mds1",
                domain_name="Corp",
                port="443",
                protocol="tcp",
            ),
            CPService(
                uid="svc-grp-web",
                name="SG_Web",
                type="service-group",
                mgmt_name="mds1",
                domain_name="Corp",
                members=["svc-http", "svc-https"],
            ),
        ],
        types=["service-tcp", "service-group"],
    )
    svc_members = await search_service.get_group_members("mds1", "Corp", "SG_Web", recursive=True, cache_mode="cache")
    assert {m.name for m in svc_members} == {"http", "https"}

    await cache.replace_domain_assets(
        "mds1",
        "Corp",
        [
            Asset(
                uid="cl-1",
                name="corp-cluster",
                type="simple-cluster",
                mgmt_name="mds1",
                domain_name="Corp",
                member_uids=["cm-1", "cm-2"],
            ),
            Asset(
                uid="cm-1",
                name="corp-cluster-m1",
                type="cluster-member",
                mgmt_name="mds1",
                domain_name="Corp",
                parent_uid="cl-1",
                parent_name="corp-cluster",
            ),
            Asset(
                uid="cm-2",
                name="corp-cluster-m2",
                type="cluster-member",
                mgmt_name="mds1",
                domain_name="Corp",
                parent_uid="cl-1",
                parent_name="corp-cluster",
            ),
        ],
    )
    cluster_members = await search_service.get_group_members(
        "mds1", "Corp", "corp-cluster", recursive=True, cache_mode="cache"
    )
    assert [m.name for m in cluster_members] == ["corp-cluster-m1", "corp-cluster-m2"]

    # Also test get_group_members by composite object_id, service_id, and asset_id
    members_by_obj_id = await search_service.get_group_members(
        "mds1", "Corp", "mds1:Corp:G_Enterprise", recursive=True, cache_mode="cache"
    )
    assert {m.name for m in members_by_obj_id} == {"G_All_Prod", "G_App_Servers", "srv-app-50"}

    svc_members_by_id = await search_service.get_group_members(
        "mds1", "Corp", "mds1:Corp:SG_Web", recursive=True, cache_mode="cache"
    )
    assert {m.name for m in svc_members_by_id} == {"http", "https"}

    cluster_members_by_asset_id = await search_service.get_group_members(
        "mds1", "Corp", "mds1:Corp:corp-cluster", recursive=True, cache_mode="cache"
    )
    assert [m.name for m in cluster_members_by_asset_id] == ["corp-cluster-m1", "corp-cluster-m2"]

    await db.close()


@pytest.mark.asyncio
async def test_describe_objects_query_objects_and_cache_status() -> None:
    """`describe_objects`, `query_objects` (with `group_by`, `aggregate='count'`, `original_domain`), and `get_cache_status` work across domains."""
    t0 = datetime(2026, 10, 23, 12, 0, 0)
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
    await cache.replace_domain_assets(
        "mds1",
        "Corp",
        [
            Asset(
                uid="gw1",
                name="corp-fw-01",
                type="simple-gateway",
                mgmt_name="mds1",
                domain_name="Corp",
                ipv4_address="10.1.0.254",
            )
        ],
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
    assert desc["total_assets"] == 1
    assert desc["object_types"] == {"host": 2, "network": 1}
    assert desc["service_types"] == {"service-tcp": 1}
    assert desc["asset_types"] == {"simple-gateway": 1}
    for expected_field in ("id", "object_id", "service_id", "asset_id", "parent_id", "parent_asset_id"):
        assert expected_field in desc["filterable_fields"]

    # query_objects(..., aggregate="describe") delegates to describe_objects
    desc_via_query = await search_service.query_objects(mgmt_name="mds1", include_global=True, aggregate="describe")
    assert desc_via_query == desc

    # query_objects with composite object_id / service_id / asset_id in name_pattern
    by_comp_obj = await search_service.query_objects(mgmt_name="mds1", name_pattern="mds1:Corp:h-local-1")
    assert by_comp_obj["total"] == 1
    assert by_comp_obj["objects"][0]["object_id"] == "mds1:Corp:h-local-1"

    by_comp_svc = await search_service.query_objects(
        mgmt_name="mds1", types=["service-tcp"], name_pattern="mds1:Corp:https"
    )
    assert by_comp_svc["total"] == 1
    assert by_comp_svc["objects"][0]["service_id"] == "mds1:Corp:https"

    by_comp_asset = await search_service.query_objects(
        mgmt_name="mds1", types=["simple-gateway"], name_pattern="mds1:Corp:corp-fw-*"
    )
    assert by_comp_asset["total"] == 1
    assert by_comp_asset["objects"][0]["asset_id"] == "mds1:Corp:corp-fw-01"

    # query_objects with short service alias ("tcp") and asset alias ("gateway")
    svc_alias_res = await search_service.query_objects(mgmt_name="mds1", types=["tcp"])
    assert svc_alias_res["total"] == 1
    assert svc_alias_res["objects"][0]["name"] == "https"

    gw_alias_res = await search_service.query_objects(mgmt_name="mds1", types=["gateway"])
    assert gw_alias_res["total"] == 1
    assert gw_alias_res["objects"][0]["name"] == "corp-fw-01"

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


@pytest.mark.spec("SCN-CACHE-013-2")
@pytest.mark.asyncio
async def test_search_objects_exact_match_and_wildcards() -> None:
    """Verify `exact_match=True` matches `.example.com` without matching `sub.example.com`, while preserving `*` and `?` wildcards and parent group traversal."""
    db = DatabaseManager()
    await db.initialize()
    try:
        cache = SqlCacheAdapter(db)
        lock_port = SqlLockAdapter(db)
        api = SearchFakeApi()
        settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")
        domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
        coordinator = DomainSyncCoordinator(
            settings=settings,
            api=api,
            cache=cache,
            lock_port=lock_port,
            domain_service=domain_service,
        )
        obj_service = ObjectService(settings=settings, api=api, cache=cache, coordinator=coordinator)
        search_service = SearchService(cache=cache, object_service=obj_service)

        await cache.upsert_domains([DomainInfo(mgmt_name="mds1", uid="d1", name="Corp")])
        await cache.replace_domain_objects(
            "mds1",
            "Corp",
            [
                CPObject.from_cp_dict(
                    "mds1",
                    "Corp",
                    {"uid": "dom-exact", "name": ".example.com", "type": "dns-domain", "is-sub-domain": True},
                ),
                CPObject.from_cp_dict(
                    "mds1",
                    "Corp",
                    {"uid": "dom-sub", "name": ".sub.example.com", "type": "dns-domain", "is-sub-domain": True},
                ),
                CPObject.from_cp_dict(
                    "mds1",
                    "Corp",
                    {"uid": "grp-domains", "name": "G_Allowed_Domains", "type": "group", "members": ["dom-exact"]},
                ),
            ],
            types=["dns-domain", "group"],
        )

        # Substring search (exact_match=False) matches both .example.com and .sub.example.com
        sub_res = await search_service.search_objects(
            ".example.com",
            mgmt_name="mds1",
            domains=["Corp"],
            exact_match=False,
            cache_mode="cache",
        )
        assert {m.name for m in sub_res.matches} == {".example.com", ".sub.example.com"}

        # Exact search (exact_match=True) matches ONLY .example.com and resolves its parent group
        exact_res = await search_service.search_objects(
            ".example.com",
            mgmt_name="mds1",
            domains=["Corp"],
            exact_match=True,
            cache_mode="cache",
        )
        assert [m.name for m in exact_res.matches] == [".example.com"]
        assert [g.name for g in exact_res.memberships["dom-exact"]] == ["G_Allowed_Domains"]

        # Wildcard search (*.example.com) still matches both even with exact_match=True
        wild_res = await search_service.search_objects(
            "*.example.com",
            mgmt_name="mds1",
            domains=["Corp"],
            exact_match=True,
            cache_mode="cache",
        )
        assert {m.name for m in wild_res.matches} == {".example.com", ".sub.example.com"}
    finally:
        await db.close()


class CountingSearchApi(SearchFakeApi):
    """Fake API that counts `api_call` and `api_query` invocations."""

    def __init__(self) -> None:
        self.call_count = 0
        self.query_count = 0

    async def api_call(
        self, mgmt_name: str, command: str, payload: dict[str, Any] | None = None, **kwargs: Any
    ) -> ApiCallResult:
        self.call_count += 1
        return await super().api_call(mgmt_name, command, payload, **kwargs)

    async def api_query(self, mgmt_name: str, command: str, **kwargs: Any) -> ApiQueryResult:
        self.query_count += 1
        return await super().api_query(mgmt_name, command, **kwargs)


@pytest.mark.spec("SCN-CACHE-013-3", "SCN-CACHE-014-1")
@pytest.mark.asyncio
async def test_cross_domain_get_group_members_cache_only_global_visibility_and_ambiguity() -> None:
    """`SearchService.get_group_members` with `domain=None` rejects blank targets, triggers zero remote syncs, includes Global, and raises `AmbiguousObjectError` on multi-domain collisions (`W3`, `I3`)."""
    db = DatabaseManager()
    await db.initialize()
    try:
        cache = SqlCacheAdapter(db)
        lock_port = SqlLockAdapter(db)
        api = CountingSearchApi()
        settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")
        domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
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

        # Blank or whitespace group_name_or_uid is rejected with ValidationError immediately
        with pytest.raises(ValidationError, match="group_name_or_uid must not be empty"):
            await search_service.get_group_members("mds1", None, "   ")

        await cache.upsert_domains(
            [
                DomainInfo(mgmt_name="mds1", uid="d-corp", name="Corp"),
                DomainInfo(mgmt_name="mds1", uid="d-dmz", name="DMZ"),
                DomainInfo(mgmt_name="mds1", uid="d-glob", name="Global", is_global=True),
            ]
        )
        await cache.replace_domain_objects(
            "mds1",
            "Global",
            [
                CPObject(uid="h-glob-1", name="glob-dns", type="host", mgmt_name="mds1", domain_name="Global"),
                CPObject(
                    uid="g-glob-1",
                    name="GlobalSharedGroup",
                    type="group",
                    mgmt_name="mds1",
                    domain_name="Global",
                    members=["h-glob-1"],
                ),
            ],
            types=["host", "group"],
        )
        await cache.replace_domain_objects(
            "mds1",
            "Corp",
            [
                CPObject(uid="h-corp-1", name="corp-srv", type="host", mgmt_name="mds1", domain_name="Corp"),
                CPObject(
                    uid="g-shared-corp",
                    name="SharedGroup",
                    type="group",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    members=["h-corp-1"],
                ),
            ],
            types=["host", "group"],
        )
        await cache.replace_domain_objects(
            "mds1",
            "DMZ",
            [
                CPObject(uid="h-dmz-1", name="dmz-srv", type="host", mgmt_name="mds1", domain_name="DMZ"),
                CPObject(
                    uid="g-shared-dmz",
                    name="SharedGroup",
                    type="group",
                    mgmt_name="mds1",
                    domain_name="DMZ",
                    members=["h-dmz-1"],
                ),
            ],
            types=["host", "group"],
        )

        # 1. Global group is visible when domain=None and triggers zero API calls even with cache_mode="smart"
        glob_members = await search_service.get_group_members("mds1", None, "GlobalSharedGroup", cache_mode="smart")
        assert [m.name for m in glob_members] == ["glob-dns"]
        assert api.call_count == 0
        assert api.query_count == 0

        # 2. Multi-domain collision raises AmbiguousObjectError without triggering API calls
        with pytest.raises(AmbiguousObjectError) as exc_info:
            await search_service.get_group_members("mds1", None, "SharedGroup", cache_mode="smart")
        assert len(exc_info.value.candidates) == 2
        assert {c["domain_name"] for c in exc_info.value.candidates} == {"Corp", "DMZ"}
        assert api.call_count == 0
        assert api.query_count == 0

        # 3. Disambiguating via composite ID (mds1:Corp:SharedGroup) succeeds even when domain=None
        corp_members = await search_service.get_group_members("mds1", None, "mds1:Corp:SharedGroup", cache_mode="cache")
        assert [m.name for m in corp_members] == ["corp-srv"]

        # 4. Asset-only search (`types=["gateway"]`, `max_depth=2`) still resolves group memberships from cached groups
        from arodonata.core.models.assets import Asset

        await cache.replace_domain_assets(
            "mds1",
            "Corp",
            [
                Asset(
                    uid="gw-corp-01",
                    name="corp-fw-01",
                    type="simple-gateway",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    ipv4_address="10.1.0.254",
                )
            ],
        )
        await cache.upsert_objects(
            [
                CPObject(
                    uid="grp-corp-firewalls",
                    name="G_Corp_Firewalls",
                    type="group",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    members=["gw-corp-01"],
                )
            ]
        )
        gw_search = await search_service.search_objects(
            "corp-fw-01",
            mgmt_name="mds1",
            domains=["Corp"],
            types=["gateway"],
            max_depth=2,
            cache_mode="cache",
        )
        assert [m.name for m in gw_search.matches] == ["corp-fw-01"]
        gw_match_uid = gw_search.matches[0].uid
        assert gw_match_uid in gw_search.memberships
        assert [g.name for g in gw_search.memberships[gw_match_uid]] == ["G_Corp_Firewalls"]
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_query_objects_cpmi_asset_equivalents_and_group_by_aliases() -> None:
    """`query_objects` matches Check Point `Cpmi*` asset classes via short aliases and resolves `group_by` aliases."""
    db = DatabaseManager()
    await db.initialize()
    try:
        cache = SqlCacheAdapter(db)
        lock_port = SqlLockAdapter(db)
        api = SearchFakeApi()
        settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")
        domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
        coordinator = DomainSyncCoordinator(
            settings=settings,
            api=api,
            cache=cache,
            lock_port=lock_port,
            domain_service=domain_service,
        )
        object_service = ObjectService(settings=settings, api=api, cache=cache, coordinator=coordinator)
        service_cache = ServiceCacheService(settings=settings, api=api, cache=cache, coordinator=coordinator)
        search_service = SearchService(
            cache=cache,
            object_service=object_service,
            service_cache=service_cache,
        )

        await cache.replace_domain_assets(
            "mds1",
            "Perimeter",
            [
                Asset(
                    uid="gw-1",
                    name="perim-gw-01",
                    type="CpmiGatewayPlain",
                    mgmt_name="mds1",
                    domain_name="Perimeter",
                ),
                Asset(
                    uid="cl-1",
                    name="perim-cl-01",
                    type="CpmiGatewayCluster",
                    mgmt_name="mds1",
                    domain_name="Perimeter",
                ),
                Asset(
                    uid="m-1",
                    name="perim-cl-01-m1",
                    type="CpmiVsxClusterMember",
                    mgmt_name="mds1",
                    domain_name="Perimeter",
                ),
                Asset(
                    uid="vsx-1",
                    name="perim-vsx-01",
                    type="CpmiVsxClusterNetobj",
                    mgmt_name="mds1",
                    domain_name="Perimeter",
                ),
                Asset(
                    uid="vs-1",
                    name="perim-vs-01",
                    type="CpmiVsNetobj",
                    mgmt_name="mds1",
                    domain_name="Perimeter",
                ),
            ],
        )

        res = await search_service.query_objects(
            mgmt_name="mds1",
            types=["gateway", "cluster", "member", "vsx", "vs"],
            group_by=["domain", "asset_type"],
            aggregate="count",
            cache_mode="cache",
        )
        assert res["total"] == 5
        assert res["group_by"] == ["domain_name", "type"]
        assert all(g["domain"] == "Perimeter" and g["domain_name"] == "Perimeter" for g in res["groups"])
        assert {g["asset_type"] for g in res["groups"]} == {
            "CpmiGatewayPlain",
            "CpmiGatewayCluster",
            "CpmiVsxClusterMember",
            "CpmiVsxClusterNetobj",
            "CpmiVsNetobj",
        }
        assert all(g["type"] == g["asset_type"] for g in res["groups"])

        # Canonical keys must not inject alias keys
        canon = await search_service.query_objects(
            mgmt_name="mds1",
            types=["cluster"],
            group_by=["domain_name", "type"],
            aggregate="count",
            cache_mode="cache",
        )
        assert canon["groups"] == [{"domain_name": "Perimeter", "type": "CpmiGatewayCluster", "count": 1}]
    finally:
        await db.close()


@pytest.mark.spec("SCN-CLIENT-005-1")
async def test_search_service_find_object_cache_fallbacks_and_single_asset_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify SearchService.find_object falls back to CachePort for services/assets and scans assets once per pass."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    try:
        cache = SqlCacheAdapter(db)
        lock_port = SqlLockAdapter(db)
        api = SearchFakeApi()
        settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")
        domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
        coordinator = DomainSyncCoordinator(
            settings=settings,
            api=api,
            cache=cache,
            lock_port=lock_port,
            domain_service=domain_service,
        )
        object_service = ObjectService(settings=settings, api=api, cache=cache, coordinator=coordinator)
        # Omit optional service_cache and asset_service intentionally (F5)
        search_service = SearchService(cache=cache, object_service=object_service)

        await cache.upsert_domains(
            [
                DomainInfo(mgmt_name="mds1", uid="d-corp", name="Corp"),
                DomainInfo(mgmt_name="mds1", uid="d-dmz", name="DMZ"),
            ]
        )
        await cache.replace_domain_services(
            "mds1",
            "Corp",
            [
                CPService.from_cp_dict(
                    "mds1",
                    "Corp",
                    {"uid": "svc-8443", "name": "tcp_8443", "type": "service-tcp", "port": "8443"},
                )
            ],
            types=["service-tcp"],
        )
        await cache.replace_domain_assets(
            "mds1",
            "Corp",
            [
                Asset(
                    uid="gw-corp-1",
                    name="CorpGw01",
                    type="CpmiGatewayPlain",
                    mgmt_name="mds1",
                    domain_name="Corp",
                )
            ],
        )

        # Single-domain fallback lookups for services and assets
        found_svc = await search_service.find_object(
            "mds1",
            "Corp",
            "tcp_8443",
            obj_type="service-tcp",
            cache_mode="cache",
        )
        assert isinstance(found_svc, CPService) and found_svc.uid == "svc-8443"

        found_gw = await search_service.find_object(
            "mds1",
            "Corp",
            "CorpGw01",
            obj_type="gateway",
            cache_mode="cache",
        )
        assert isinstance(found_gw, Asset) and found_gw.uid == "gw-corp-1"

        # Active WriteSession overlay for service UID works even without service_cache
        overlay = SessionOverlay(mgmt_name="mds1", domain_name="Corp")
        overlay_svc = CPService.from_cp_dict(
            "mds1",
            "Corp",
            {"uid": "uid-overlay-svc", "name": "tcp_9443", "type": "service-tcp", "port": "9443"},
        )
        overlay.record_service_upsert(overlay_svc)
        ws = WriteSession(
            mgmt_name="mds1",
            domain_name="Corp",
            sid="ws-sid-1",
            server_ip="10.1.0.1",
            overlay=overlay,
        )
        with write_session_context(ws):
            found_ws_svc = await search_service.find_object(
                "mds1",
                "Corp",
                "uid-overlay-svc",
                obj_type="service-tcp",
                cache_mode="cache",
            )
            assert isinstance(found_ws_svc, CPService) and found_ws_svc.name == "tcp_9443"

        # Cross-domain lookup runs get_assets only once across Pass 1 + Pass 2
        get_assets_calls = 0
        orig_get_assets = cache.get_assets

        async def _spy_get_assets(*args: Any, **kwargs: Any) -> list[Asset]:
            nonlocal get_assets_calls
            get_assets_calls += 1
            return await orig_get_assets(*args, **kwargs)

        monkeypatch.setattr(cache, "get_assets", _spy_get_assets)

        ci_gw = await search_service.find_object("mds1", None, "corpgw01", cache_mode="cache")
        assert isinstance(ci_gw, Asset) and ci_gw.uid == "gw-corp-1"
        assert get_assets_calls == 1

        get_assets_calls = 0
        missing = await search_service.find_object("mds1", None, "totally-nonexistent", cache_mode="cache")
        assert missing is None
        assert get_assets_calls == 1
    finally:
        await db.close()


@pytest.mark.spec("SCN-CLIENT-003-1", "SCN-CACHE-013-1")
async def test_search_and_overlay_domain_isolation_and_global_membership_merge() -> None:
    """SCN-CLIENT-003-1 & SCN-CACHE-013-1: Isolate WriteSession overlays and merge Global UID memberships."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = SearchFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")
    domain_svc = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    coord = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_svc,
    )
    obj_svc = ObjectService(settings=settings, api=api, cache=cache, coordinator=coord)
    svc_svc = ServiceCacheService(settings=settings, api=api, cache=cache, coordinator=coord)
    search_service = SearchService(
        cache=cache,
        object_service=obj_svc,
        service_cache=svc_svc,
    )
    try:
        await cache.upsert_domains(
            [
                DomainInfo(mgmt_name="mds1", uid="d-a", name="DomainA"),
                DomainInfo(mgmt_name="mds1", uid="d-b", name="DomainB"),
                DomainInfo(mgmt_name="mds1", uid="d-c", name="Corp"),
            ]
        )
        # Global object u-global-1 present in both DomainA and DomainB with domain-specific parent groups
        await cache.replace_domain_objects(
            "mds1",
            "DomainA",
            [
                CPObject(
                    uid="u-global-1",
                    name="g_DNS_Server",
                    type="host",
                    mgmt_name="mds1",
                    domain_name="DomainA",
                    original_domain="Global",
                    ipv4_address="10.0.0.53",
                ),
                CPObject(
                    uid="g-dom-a",
                    name="Grp_DomainA_DNS",
                    type="group",
                    mgmt_name="mds1",
                    domain_name="DomainA",
                    members=["u-global-1"],
                ),
            ],
            types=["host", "group"],
        )
        await cache.replace_domain_objects(
            "mds1",
            "DomainB",
            [
                CPObject(
                    uid="u-global-1",
                    name="g_DNS_Server",
                    type="host",
                    mgmt_name="mds1",
                    domain_name="DomainB",
                    original_domain="Global",
                    ipv4_address="10.0.0.53",
                ),
                CPObject(
                    uid="g-dom-b",
                    name="Grp_DomainB_DNS",
                    type="group",
                    mgmt_name="mds1",
                    domain_name="DomainB",
                    members=["u-global-1"],
                ),
            ],
            types=["host", "group"],
        )
        await cache.replace_domain_objects(
            "mds1",
            "Global",
            [
                CPObject(
                    uid="u-glob-only",
                    name="h-glob-only",
                    type="host",
                    mgmt_name="mds1",
                    domain_name="Global",
                    ipv4_address="10.99.99.99",
                )
            ],
            types=["host"],
        )

        # DA-030: Search across domains retains BOTH DomainA and DomainB parent groups for u-global-1
        res = await search_service.search_objects("10.0.0.53", mgmt_name="mds1", cache_mode="cache")
        assert "u-global-1" in res.memberships
        group_ids = {n.id for n in res.memberships["u-global-1"]}
        assert group_ids == {"mds1:DomainA:g-dom-a", "mds1:DomainB:g-dom-b"}

        # DA-024: Global WriteSession overlay must not leak when include_global=False or domain excluded
        glob_overlay = SessionOverlay("mds1", "Global")
        glob_overlay.record_object_upsert(
            CPObject(
                uid="u-glob-ov",
                name="h-glob-overlay",
                type="host",
                mgmt_name="mds1",
                domain_name="Global",
                ipv4_address="10.0.0.53",
            )
        )
        ws_glob = WriteSession(
            mgmt_name="mds1", domain_name="Global", sid="s-glob", server_ip="10.0.0.1", overlay=glob_overlay
        )
        with write_session_context(ws_glob):
            objs_no_glob = await obj_svc.get_objects("mds1", None, include_global=False, cache_mode="cache")
            assert all(o.uid != "u-glob-ov" for o in objs_no_glob)
            s_no_glob = await search_service.search_objects(
                "10.0.0.53",
                mgmt_name="mds1",
                include_global=False,
                cache_mode="cache",
            )
            assert all(m.uid != "u-glob-ov" for m in s_no_glob.matches)
            desc_no_glob = await search_service.describe_objects(mgmt_name="mds1", include_global=False)
            assert "Global" not in desc_no_glob["domains"]

        # Multi-domain search_objects excludes overlay from unlisted domain "Corp"
        corp_overlay = SessionOverlay("mds1", "Corp")
        corp_overlay.record_object_upsert(
            CPObject(
                uid="u-corp-ov",
                name="h-corp-overlay",
                type="host",
                mgmt_name="mds1",
                domain_name="Corp",
                ipv4_address="10.0.0.53",
            )
        )
        ws_corp = WriteSession(
            mgmt_name="mds1", domain_name="Corp", sid="s-corp", server_ip="10.0.0.1", overlay=corp_overlay
        )
        with write_session_context(ws_corp):
            multi_dom_search = await search_service.search_objects(
                "10.0.0.53",
                mgmt_name="mds1",
                domains=["DomainA", "DomainB"],
                cache_mode="cache",
            )
            assert all(m.uid != "u-corp-ov" for m in multi_dom_search.matches)
            q_multi = await search_service.query_objects(
                mgmt_name="mds1",
                domains=["DomainA", "DomainB"],
                cache_mode="cache",
            )
            assert all(item["uid"] != "u-corp-ov" for item in q_multi["objects"])
    finally:
        await db.close()


@pytest.mark.spec("SCN-CACHE-006-2", "SCN-CLIENT-005-1")
async def test_find_object_on_demand_types_and_single_force_refresh() -> None:
    """SCN-CACHE-006-2 & SCN-CLIENT-005-1 (DA-005): On-demand non-default obj_type sync and single force reload."""

    class _TrackingApi(SearchFakeApi):
        def __init__(self) -> None:
            self.queried: list[str] = []

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
            if command == "show-last-published-session":
                return ApiCallResult(
                    success=True,
                    data={"uid": "sess-app-1", "publish-time": {"iso-8601": "2026-10-23T12:00:00Z"}},
                )
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
            self.queried.append(command)
            if command == "show-application-sites":
                return ApiQueryResult(
                    success=True,
                    objects=[{"uid": "app-1", "name": "MyAppSite", "type": "application-site"}],
                    total=1,
                )
            if command == "show-services-other":
                return ApiQueryResult(
                    success=True,
                    objects=[{"uid": "so-1", "name": "CustomProto", "type": "service-other", "ip-protocol": 47}],
                    total=1,
                )
            if command == "show-hosts":
                return ApiQueryResult(
                    success=True,
                    objects=[{"uid": "h-1", "name": "ForceHost", "type": "host", "ipv4-address": "10.0.0.10"}],
                    total=1,
                )
            return ApiQueryResult(success=True, objects=[], total=0)

    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = _TrackingApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=300)
    domain_svc = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    domain_svc.tracker.mark_refreshed("mds1")
    await cache.upsert_domains([DomainInfo(mgmt_name="mds1", uid="d1", name="Corp")])
    coord = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_svc,
    )
    obj_svc = ObjectService(settings=settings, api=api, cache=cache, coordinator=coord)
    svc_svc = ServiceCacheService(settings=settings, api=api, cache=cache, coordinator=coord)
    search_service = SearchService(
        cache=cache,
        object_service=obj_svc,
        service_cache=svc_svc,
    )
    try:
        # 1. smart mode refreshes non-default obj_type="application-site" on demand
        app = await search_service.find_object(
            "mds1",
            "Corp",
            "MyAppSite",
            obj_type="application-site",
            cache_mode="smart",
        )
        assert isinstance(app, CPObject) and app.uid == "app-1"
        assert "show-application-sites" in api.queried

        # 2. smart mode refreshes non-default obj_type="service-other" on demand
        api.queried.clear()
        svc_other = await search_service.find_object(
            "mds1",
            "Corp",
            "CustomProto",
            obj_type="service-other",
            cache_mode="smart",
        )
        assert isinstance(svc_other, CPService) and svc_other.uid == "so-1"
        assert api.queried == ["show-services-other"]

        # 3. force mode with obj_type="host" name lookup reloads show-hosts exactly ONCE
        api.queried.clear()
        forced = await search_service.find_object("mds1", "Corp", "ForceHost", obj_type="host", cache_mode="force")
        assert isinstance(forced, CPObject) and forced.uid == "h-1"
        assert api.queried == ["show-hosts"]
    finally:
        await db.close()


@pytest.mark.spec("SCN-CACHE-014-1", "SCN-CLIENT-005-1")
async def test_resolve_group_with_members_isolation_precedence_and_query_bounds() -> None:
    """SCN-CACHE-014-1 & SCN-CLIENT-005-1 (DA-031, VVAH-SEARCH-01): Cluster isolation, container precedence, and query bounds."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = SearchFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")
    domain_svc = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    coord = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_svc,
    )
    obj_svc = ObjectService(settings=settings, api=api, cache=cache, coordinator=coord)
    svc_svc = ServiceCacheService(settings=settings, api=api, cache=cache, coordinator=coord)
    search_service = SearchService(
        cache=cache,
        object_service=obj_svc,
        service_cache=svc_svc,
    )
    try:
        await cache.upsert_domains(
            [
                DomainInfo(mgmt_name="mds1", uid="d-a", name="DomainA"),
                DomainInfo(mgmt_name="mds1", uid="d-b", name="DomainB"),
            ]
        )
        # Non-group host "DNS" in DomainA alongside service-group "DNS" in DomainA + group "CrossScope" in DomainA
        await cache.replace_domain_objects(
            "mds1",
            "DomainA",
            [
                CPObject(uid="h-dns", name="DNS", type="host", mgmt_name="mds1", domain_name="DomainA"),
                CPObject(
                    uid="h-1",
                    name="h-1",
                    type="host",
                    mgmt_name="mds1",
                    domain_name="DomainA",
                    ipv4_address="10.0.0.1",
                ),
                CPObject(
                    uid="grp-cross",
                    name="CrossScope",
                    type="group",
                    mgmt_name="mds1",
                    domain_name="DomainA",
                    members=["h-1"],
                ),
            ],
            types=["host", "group"],
        )
        await cache.replace_domain_services(
            "mds1",
            "DomainA",
            [
                CPService(
                    uid="s-53", name="udp-53", type="service-udp", mgmt_name="mds1", domain_name="DomainA", port="53"
                ),
                CPService(
                    uid="sg-dns",
                    name="DNS",
                    type="service-group",
                    mgmt_name="mds1",
                    domain_name="DomainA",
                    members=["s-53"],
                ),
                CPService(
                    uid="s-non-grp",
                    name="Cluster01",
                    type="service-tcp",
                    mgmt_name="mds1",
                    domain_name="DomainA",
                    port="80",
                ),
            ],
            types=["service-udp", "service-group", "service-tcp"],
        )
        await cache.replace_domain_services(
            "mds1",
            "DomainB",
            [
                CPService(
                    uid="sg-cross-b",
                    name="CrossScope",
                    type="service-group",
                    mgmt_name="mds1",
                    domain_name="DomainB",
                    members=[],
                )
            ],
            types=["service-group"],
        )
        # Two clusters named Cluster01 in DomainA and DomainB with parent_name="Cluster01"
        await cache.replace_domain_assets(
            "mds1",
            "DomainA",
            [
                Asset(
                    uid="clu-a", name="Cluster01", type="CpmiGatewayCluster", mgmt_name="mds1", domain_name="DomainA"
                ),
                Asset(
                    uid="mA1",
                    name="NodeA1",
                    type="CpmiClusterMember",
                    mgmt_name="mds1",
                    domain_name="DomainA",
                    parent_name="Cluster01",
                ),
            ],
        )
        await cache.replace_domain_assets(
            "mds1",
            "DomainB",
            [
                Asset(
                    uid="clu-b", name="Cluster01", type="CpmiGatewayCluster", mgmt_name="mds1", domain_name="DomainB"
                ),
                Asset(
                    uid="mB1",
                    name="NodeB1",
                    type="CpmiClusterMember",
                    mgmt_name="mds1",
                    domain_name="DomainB",
                    parent_uid="clu-b",
                    parent_name="Cluster01",
                ),
                Asset(
                    uid="mB2-noname",
                    name="NodeB2",
                    type="CpmiClusterMember",
                    mgmt_name="mds1",
                    domain_name="DomainB",
                    parent_name="Cluster01",
                ),
            ],
        )

        # 1. Host "DNS" does NOT shadow service-group "DNS"
        dns_target, dns_members = await search_service.resolve_group_with_members(
            "mds1",
            "DomainA",
            "DNS",
            cache_mode="cache",
        )
        assert isinstance(dns_target, CPService) and dns_target.uid == "sg-dns"
        assert [m.uid for m in dns_members] == ["s-53"]

        # 2. Non-group service "Cluster01" does NOT shadow Cluster01 asset, and DomainB members do NOT leak
        clu_target, clu_members = await search_service.resolve_group_with_members(
            "mds1",
            "DomainA",
            "Cluster01",
            cache_mode="cache",
        )
        assert isinstance(clu_target, Asset) and clu_target.uid == "clu-a"
        assert [m.uid for m in clu_members] == ["mA1"]

        # 3. Cross-scope container collision (CPObject group vs CPService service-group across domains) raises AmbiguousObjectError
        with pytest.raises(AmbiguousObjectError):
            await search_service.resolve_group_with_members("mds1", None, "CrossScope", cache_mode="cache")

        # 4. VVAH-SEARCH-01: query_objects bounds limit (<= 1000), offset (>= 0), and group_by slices
        bulk_hosts = [
            CPObject(uid=f"bh-{i:04d}", name=f"bulk-{i:04d}", type="host", mgmt_name="mds1", domain_name="DomainB")
            for i in range(1005)
        ]
        await cache.replace_domain_objects("mds1", "DomainB", bulk_hosts, types=["host"])
        bounded = await search_service.query_objects(mgmt_name="mds1", limit=99999, offset=-10, cache_mode="cache")
        assert len(bounded["objects"]) == 1000
        assert bounded["from"] == 1
        assert bounded["to"] == 1000

        grouped_page = await search_service.query_objects(
            mgmt_name="mds1",
            domain_name="DomainB",
            types=["host"],
            group_by=["name"],
            limit=3,
            offset=2,
            cache_mode="cache",
        )
        assert grouped_page["total_groups"] == 1005
        assert len(grouped_page["groups"]) == 3
    finally:
        await db.close()


@pytest.mark.spec("SCN-CACHE-018-2")
def test_decomposed_search_package_compat_traced_and_shared_asset_linking() -> None:
    """Verify `search_service` compatibility exports, `@traced` method parity, and shared cluster/VSX asset linking."""
    from arodonata.core.models.assets import Asset
    from arodonata.core.services import search_service as legacy_mod
    from arodonata.core.services.asset_service import ClusterRelationshipManager, VSXRelationshipManager
    from arodonata.core.services.search import SearchService as PkgSearchService
    from arodonata.core.services.search import classify_search_term as pkg_classify

    assert legacy_mod.SearchService is PkgSearchService
    assert legacy_mod.classify_search_term is pkg_classify
    for method_name in (
        "search_objects",
        "resolve_group_with_members",
        "get_group_members",
        "find_object",
        "describe_objects",
        "query_objects",
        "get_cache_status",
    ):
        fn = getattr(PkgSearchService, method_name)
        assert hasattr(fn, "__wrapped__")
        assert fn.__qualname__ == f"SearchService.{method_name}"

    parent_clu = Asset(
        id="mds1:Corp:clu-1",
        asset_id="mds1:Corp:Cluster1",
        mgmt_name="mds1",
        domain_name="Corp",
        uid="clu-1",
        name="Cluster1",
        type="simple-cluster",
        raw_data={"members": ["mem-1"]},
    )
    mem_clu = Asset(
        id="mds1:Corp:mem-1",
        asset_id="mds1:Corp:Member1",
        mgmt_name="mds1",
        domain_name="Corp",
        uid="mem-1",
        name="Member1",
        type="cluster-member",
    )
    enriched_clu = {a.uid: a for a in ClusterRelationshipManager().enrich([parent_clu, mem_clu])}
    assert enriched_clu["mem-1"].parent_uid == "clu-1"
    assert enriched_clu["clu-1"].member_uids == ["mem-1"]

    vsx_p = Asset(
        id="mds1:DC:vsx-1",
        asset_id="mds1:DC:VSX1",
        mgmt_name="mds1",
        domain_name="DC",
        uid="vsx-1",
        name="VSX1",
        type="vsx-gateway",
    )
    vs_c = Asset(
        id="mds1:Tenant:vs-1",
        asset_id="mds1:Tenant:VS1",
        mgmt_name="mds1",
        domain_name="Tenant",
        uid="vs-1",
        name="VS1",
        type="virtual-system",
        raw_data={"vsx-gateway": {"uid": "vsx-1"}},
    )
    reconciled = {a.uid: a for a in VSXRelationshipManager(api=None).reconcile_cross_domain([vsx_p, vs_c])}  # type: ignore[arg-type]
    assert reconciled["vs-1"].parent_id == vsx_p.id
    assert reconciled["vsx-1"].virtual_system_uids == ["vs-1"]


async def test_search_service_group_by_validation_telemetry_range_exact_and_single_domain_refresh() -> None:
    """DA-011/DA-013/DA-019/DA-025/DA-028/DA-030: SearchService safety, module metadata, and freshness."""
    from arodonata.core.errors import ServerIdentityError
    from arodonata.core.models.domains import RefreshOutcome
    from arodonata.core.services.search.terms import matches_classified_term

    assert SearchService.__module__ == "arodonata.core.services.search_service"
    assert SearchService.search_objects.__module__ == "arodonata.core.services.search_service"

    # DA-030: IP range exact_match=True enforces containment
    host_inside = CPObject(
        id="m:d:h1",
        object_id="m:d:h1",
        uid="h1",
        name="H1",
        type="host",
        mgmt_name="m",
        domain_name="d",
        ipv4_address="10.0.0.5",
    )
    range_wider = CPObject.from_cp_dict(
        "m",
        "d",
        {
            "uid": "r1",
            "name": "R1",
            "type": "address-range",
            "ipv4-address-first": "10.0.0.1",
            "ipv4-address-last": "10.0.0.20",
        },
    )
    term_range = classify_search_term("10.0.0.4-10.0.0.10")
    assert matches_classified_term(host_inside, term_range, exact_match=True) is True
    assert matches_classified_term(range_wider, term_range, exact_match=True) is False
    assert matches_classified_term(range_wider, term_range, exact_match=False) is True

    # DA-011, DA-013, DA-019, DA-028 using lightweight stubs
    refreshed_scopes: list[str] = []

    class _StubCache:
        async def get_domains(self, mgmt_name: str, *, include_global: bool = True) -> list[DomainInfo]:
            return [DomainInfo(id="m:Corp", mgmt_name="m", uid="d1", name="Corp", domain_type="domain")]

        async def get_objects(self, **kwargs: Any) -> list[CPObject]:
            return []

        async def get_services(self, **kwargs: Any) -> list[CPService]:
            return []

        async def get_assets(self, **kwargs: Any) -> list[Asset]:
            return []

    class _StubObjSvc:
        async def refresh_objects(self, **kwargs: Any) -> RefreshOutcome:
            refreshed_scopes.append("objects")
            return RefreshOutcome(scope="objects")

        async def get_objects(self, **kwargs: Any) -> list[CPObject]:
            return [host_inside] if kwargs.get("names") or kwargs.get("uids") else []

    class _StubSvcCache:
        async def refresh_services(self, **kwargs: Any) -> RefreshOutcome:
            refreshed_scopes.append("services")
            return RefreshOutcome(scope="services")

        async def get_services(self, **kwargs: Any) -> list[CPService]:
            return []

    s = SearchService(
        cache=_StubCache(),  # type: ignore[arg-type]
        object_service=_StubObjSvc(),  # type: ignore[arg-type]
        service_cache=_StubSvcCache(),  # type: ignore[arg-type]
    )

    with pytest.raises(ValidationError, match="Unsupported group_by"):
        await s.query_objects(group_by=["__class__"], cache_mode="cache")

    # DA-028: port filter skips objects refresh
    await s.query_objects(mgmt_name="m", port="443", cache_mode="smart")
    assert refreshed_scopes == ["services"]

    # DA-019: single-domain find_object still invokes refresh_objects even when object exists in cache
    refreshed_scopes.clear()
    found = await s.find_object("m", None, "H1", cache_mode="smart")
    assert found is not None and found.uid == "h1"
    assert refreshed_scopes == ["objects"]

    # DA-013: ServerIdentityError propagates through resolve_implicit_domain_mode
    class _EmptyDomainCache(_StubCache):
        async def get_domains(self, mgmt_name: str, *, include_global: bool = True) -> list[DomainInfo]:
            return []

    class _BoomDomSvc:
        async def get_domains(self, **kwargs: Any) -> list[DomainInfo]:
            raise ServerIdentityError("cert changed")

    s._cache = _EmptyDomainCache()  # type: ignore[assignment]
    s._object_service._coordinator = type("C", (), {"_domain_service": _BoomDomSvc()})()  # type: ignore[attr-defined]
    with pytest.raises(ServerIdentityError, match="cert changed"):
        await s.resolve_implicit_domain_mode("m", None, "smart")
