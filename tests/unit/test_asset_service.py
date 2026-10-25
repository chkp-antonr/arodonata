"""Unit tests for `AssetRefreshService`, `ClusterRelationshipManager`, and `VSXRelationshipManager`."""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Any

import pytest

from arodonata.adapters.sse import to_sse_event
from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainInfo
from arodonata.core.services import (
    AssetRefreshService,
    DomainService,
    DomainSyncCoordinator,
)


class AssetFakeApi:
    """In-memory `ApiPort` double for `AssetRefreshService` tests."""

    def __init__(self) -> None:
        self.gateways_by_domain: dict[str, list[dict[str, Any]]] = {
            "Corp": [
                {
                    "uid": "cl-1",
                    "name": "corp-cluster-01",
                    "type": "simple-cluster",
                    "ipv4-address": "10.1.0.10",
                    "cluster-member-names": [
                        {"uid": "cm-1", "name": "corp-gw-01a", "type": "cluster-member", "ipv4-address": "10.1.0.11"},
                        "cm-2",
                    ],
                },
                {
                    "uid": "cm-2",
                    "name": "corp-gw-01b",
                    "type": "cluster-member",
                    "ipv4-address": "10.1.0.12",
                },
                {
                    "uid": "cm-3",
                    "name": "corp-gw-01c",
                    "type": "cluster-member",
                    "ipv4-address": "10.1.0.13",
                    "cluster": {"uid": "cl-1", "name": "corp-cluster-01"},
                },
            ],
            "DC": [
                {
                    "uid": "vsx-1",
                    "name": "dc-vsx-cluster",
                    "type": "vsx-cluster",
                    "ipv4-address": "10.2.0.10",
                }
            ],
        }
        self.generic_objects_by_class: dict[tuple[str, str], list[dict[str, Any]]] = {
            ("DC", "com.checkpoint.objects.classes.dummy.CpmiVsxClusterNetobj"): [
                {
                    "uid": "vsx-1",
                    "name": "dc-vsx-cluster",
                    "virtual-systems": [
                        {"uid": "vs-101", "name": "dc-vs-dmz"},
                    ],
                }
            ],
            ("DC", "com.checkpoint.objects.classes.dummy.CpmiVsNetobj"): [
                {
                    "uid": "vs-101",
                    "name": "dc-vs-dmz",
                    "type": "virtual-system",
                    "ipv4-address": "10.2.101.1",
                    "vsx-gateway": {"uid": "vsx-1", "name": "dc-vsx-cluster"},
                },
                {
                    "uid": "vs-102",
                    "name": "dc-vs-internal",
                    "type": "CpmiVsNetobj",
                    "ipv4-address": "10.2.102.1",
                    "contained-in": "vsx-1",
                },
            ],
        }

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
                data={"uid": f"asset-sess-{domain}", "publish-time": {"iso-8601": "2026-10-23T16:00:00Z"}},
            )
        if command == "show-session":
            return ApiCallResult(success=True, data={"locks": 0, "changes": 0, "number-of-published-changes": 0})
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
        dom = domain or "Corp"
        if command == "show-gateways-and-servers":
            objs = self.gateways_by_domain.get(dom, [])
            return ApiQueryResult(success=True, objects=objs, total=len(objs))
        if command == "show-generic-objects" and payload:
            cls_name = str(payload.get("class-name") or "")
            objs = self.generic_objects_by_class.get((dom, cls_name), [])
            return ApiQueryResult(success=True, objects=objs, total=len(objs))
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


@pytest.mark.asyncio
async def test_asset_refresh_cluster_and_vsx_relationships_and_streaming() -> None:
    """`AssetRefreshService` resolves cluster members and VSX virtual systems across domains concurrently and emits SSE-convertible events."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = AssetFakeApi()

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    domain_service.tracker.mark_refreshed("mds1")
    await cache.upsert_domains(
        [
            DomainInfo(mgmt_name="mds1", uid="d1", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1"),
            DomainInfo(mgmt_name="mds1", uid="d2", name="DC", active_ip="10.2.0.1", active_mds_ip="10.0.0.2"),
        ]
    )

    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    asset_service = AssetRefreshService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )

    events = [ev async for ev in asset_service.stream_refresh_assets(mgmt_name="mds1", mode="force")]
    assert len(events) >= 4
    sse_events = [to_sse_event(ev) for ev in events]
    assert all(s.event for s in sse_events)

    # Verify ClusterRelationshipManager in Corp domain
    corp_assets = {a.uid: a for a in await asset_service.get_assets("mds1", "Corp", cache_mode="cache")}
    assert {"cl-1", "cm-1", "cm-2", "cm-3"} == set(corp_assets.keys())
    cluster = corp_assets["cl-1"]
    assert set(cluster.member_uids) == {"cm-1", "cm-2", "cm-3"}
    for m_uid in ("cm-1", "cm-2", "cm-3"):
        member = corp_assets[m_uid]
        assert member.parent_uid == "cl-1"
        assert member.parent_name == "corp-cluster-01"

    # Verify VSXRelationshipManager in DC domain (via encapsulated generic-object queries)
    dc_assets = {a.uid: a for a in await asset_service.get_assets("mds1", "DC", cache_mode="cache")}
    assert {"vsx-1", "vs-101", "vs-102"} == set(dc_assets.keys())
    vsx_parent = dc_assets["vsx-1"]
    assert set(vsx_parent.virtual_system_uids) == {"vs-101", "vs-102"}
    for vs_uid in ("vs-101", "vs-102"):
        vs = dc_assets[vs_uid]
        assert vs.parent_uid == "vsx-1"
        assert vs.parent_name == "dc-vsx-cluster"

    # Verify domain_sync_state for scope="assets", item_type="*"
    st_corp = await cache.get_sync_state("mds1", "Corp", "assets", "*")
    st_dc = await cache.get_sync_state("mds1", "DC", "assets", "*")
    assert st_corp is not None and st_corp.status == "ok" and st_corp.object_count == 4
    assert st_dc is not None and st_dc.status == "ok" and st_dc.object_count == 3

    await db.close()
