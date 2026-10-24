"""Unit tests for `ObjectService`."""

from __future__ import annotations

from collections.abc import Awaitable
from datetime import UTC, datetime
from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext, SessionOverlay, WriteSession, write_session_context
from arodonata.core.models.common import DEFAULT_OBJECT_TYPES, ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainInfo, DomainSyncState
from arodonata.core.models.objects import CPObject
from arodonata.core.services import (
    DomainService,
    DomainSyncCoordinator,
    ObjectService,
)


class ObjectFakeApi:
    """In-memory `ApiPort` double for `ObjectService` tests."""

    def __init__(self) -> None:
        self.published_session: dict[str, Any] = {
            "uid": "sess-1",
            "publish-time": {"iso-8601": "2026-10-23T12:00:00Z"},
        }
        self.query_data: dict[str, list[dict[str, Any]]] = {
            "show-hosts": [
                {"uid": "h1", "name": "web-01", "type": "host", "ipv4-address": "10.1.1.10"},
                {"uid": "h2", "name": "db-01", "type": "host", "ipv4-address": "10.1.1.20"},
            ],
            "show-networks": [
                {"uid": "n1", "name": "net-corp", "type": "network", "subnet4": "10.1.1.0", "mask-length4": 24},
            ],
            "show-address-ranges": [
                {
                    "uid": "r1",
                    "name": "range-dhcp",
                    "type": "address-range",
                    "ipv4-address-first": "10.1.1.100",
                    "ipv4-address-last": "10.1.1.200",
                }
            ],
            "show-groups": [
                {"uid": "g1", "name": "grp-servers", "type": "group", "members": ["h1", "h2"]},
            ],
            "show-dns-domains": [
                {"uid": "d1", "name": ".corp.example.com", "type": "dns-domain", "is-sub-domain": True},
            ],
        }
        self.changes_response: ApiCallResult | None = None
        self.objects_by_uid: dict[str, dict[str, Any]] = {}
        self.query_calls: list[str] = []
        self.call_commands: list[str] = []

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
        self.call_commands.append(command)
        if command == "show-last-published-session":
            return ApiCallResult(success=True, data=self.published_session)
        if command == "show-session":
            return ApiCallResult(success=True, data={"locks": 0, "changes": 0, "number-of-published-changes": 0})
        if command == "show-changes" and self.changes_response is not None:
            return self.changes_response
        if command == "show-object" and payload:
            uid = str(payload.get("uid") or "")
            if uid in self.objects_by_uid:
                return ApiCallResult(success=True, data={"object": self.objects_by_uid[uid]})
            return ApiCallResult(success=False, status_code=404, error_message="not found")
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
        self.query_calls.append(command)
        items = self.query_data.get(command, [])
        return ApiQueryResult(success=True, objects=items, total=len(items))

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
async def test_object_service_default_types_and_type_scoped_replacement() -> None:
    """`ObjectService` syncs the 5 default types and replaces only requested `types` without wiping other cached types."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = ObjectFakeApi()

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    domain_service.tracker.mark_refreshed("mds1")
    await cache.upsert_domains(
        [DomainInfo(mgmt_name="mds1", uid="dom1", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1")]
    )

    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    obj_service = ObjectService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )

    # 1. Default refresh syncs ("host", "network", "address-range", "group", "dns-domain")
    outcome = await obj_service.refresh_objects(mgmt_name="mds1", mode="smart")
    assert outcome.refreshed_domains == ["mds1:Corp"]
    assert outcome.total_items == 6

    all_cached = await cache.get_objects("mds1", "Corp")
    assert len(all_cached) == 6
    for t in DEFAULT_OBJECT_TYPES:
        st = await cache.get_sync_state("mds1", "Corp", "objects", t)
        assert st is not None
        assert st.status == "ok"
        assert st.last_session_uid == "sess-1"

    # 2. Type-scoped replacement: refresh only types=["wildcard"] without wiping hosts/networks
    api.query_data["show-wildcards"] = [
        {
            "uid": "w1",
            "name": "wild-printer",
            "type": "wildcard",
            "ipv4-address": "10.1.0.5",
            "ipv4-mask-wildcard": "0.0.255.0",
        }
    ]
    await obj_service.refresh_objects(mgmt_name="mds1", types=["wildcard"], mode="force")

    hosts_still_there = await cache.get_objects("mds1", "Corp", types=["host"])
    assert len(hosts_still_there) == 2
    wildcards = await cache.get_objects("mds1", "Corp", types=["wildcard"])
    assert len(wildcards) == 1
    assert wildcards[0].name == "wild-printer"

    await db.close()


@pytest.mark.asyncio
async def test_object_service_smart_fast_incremental_diff_and_fallback() -> None:
    """`mode='smart-fast'` applies `show-changes` diff (upserts & deletes) and falls back to full reload when `> max_incremental_changes`."""
    t1 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = ObjectFakeApi()

    settings = ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        api_key="secret",
        cache_ttl=0,
        max_incremental_changes=2,
    )
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    domain_service.tracker.mark_refreshed("mds1")
    await cache.upsert_domains(
        [DomainInfo(mgmt_name="mds1", uid="dom1", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1")]
    )

    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    obj_service = ObjectService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )

    # Seed initial state at sess-1
    await cache.replace_domain_objects(
        "mds1",
        "Corp",
        [
            CPObject(
                uid="h1", name="web-01", type="host", mgmt_name="mds1", domain_name="Corp", ipv4_address="10.1.1.10"
            ),
            CPObject(
                uid="h2", name="db-01", type="host", mgmt_name="mds1", domain_name="Corp", ipv4_address="10.1.1.20"
            ),
        ],
        types=["host"],
    )
    await cache.upsert_sync_state(
        DomainSyncState(
            mgmt_name="mds1",
            domain_name="Corp",
            scope="objects",
            item_type="host",
            last_published_at=t1,
            last_session_uid="sess-1",
            synced_at=t1,
            status="ok",
            object_count=2,
        )
    )

    # Advance server published session to sess-2 with 2 changes (<= max_incremental_changes=2):
    # - h1 deleted
    # - h3 added
    api.published_session = {
        "uid": "sess-2",
        "publish-time": {"iso-8601": "2026-10-23T12:05:00Z"},
    }
    api.changes_response = ApiCallResult(
        success=True,
        data={
            "tasks": [
                {
                    "task-details": [
                        {
                            "changes": [
                                {
                                    "operations": {
                                        "added-objects": [{"uid": "h3", "type": "host", "name": "app-01"}],
                                        "modified-objects": [],
                                        "deleted-objects": [{"uid": "h1", "type": "host", "name": "web-01"}],
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        },
    )
    api.objects_by_uid["h3"] = {
        "uid": "h3",
        "name": "app-01",
        "type": "host",
        "ipv4-address": "10.1.1.30",
    }

    api.query_calls.clear()
    events = [
        ev
        async for ev in obj_service.stream_refresh_objects(
            mgmt_name="mds1",
            types=["host"],
            mode="smart-fast",
        )
    ]
    assert any("incremental" in ev.message.lower() for ev in events)
    # Full show-hosts query was NOT called!
    assert "show-hosts" not in api.query_calls

    cached_hosts = await cache.get_objects("mds1", "Corp", types=["host"])
    assert {h.uid for h in cached_hosts} == {"h2", "h3"}

    # Now advance to sess-3 with 3 changes (> max_incremental_changes=2) -> must fall back to full reload!
    api.published_session = {
        "uid": "sess-3",
        "publish-time": {"iso-8601": "2026-10-23T12:10:00Z"},
    }
    api.changes_response = ApiCallResult(
        success=True,
        data={
            "changes": [
                {
                    "operations": {
                        "added-objects": [
                            {"uid": "h4", "type": "host"},
                            {"uid": "h5", "type": "host"},
                            {"uid": "h6", "type": "host"},
                        ]
                    }
                }
            ]
        },
    )
    api.query_data["show-hosts"] = [{"uid": "h10", "name": "reloaded-host", "type": "host", "ipv4-address": "10.9.9.9"}]

    await obj_service.refresh_objects(mgmt_name="mds1", types=["host"], mode="smart-fast")
    assert "show-hosts" in api.query_calls
    reloaded = await cache.get_objects("mds1", "Corp", types=["host"])
    assert [h.uid for h in reloaded] == ["h10"]

    # Verify WriteSession overlay on get_objects / get_object_by_uid
    overlay = SessionOverlay("mds1", "Corp")
    overlay.record_object_upsert(
        CPObject(uid="h-uncommitted", name="stage-host", type="host", mgmt_name="mds1", domain_name="Corp")
    )
    overlay.record_object_delete(uid="h10")
    ws = WriteSession(mgmt_name="mds1", domain_name="Corp", sid="s-write", server_ip="10.1.0.1", overlay=overlay)
    with write_session_context(ws):
        visible = await obj_service.get_objects("mds1", "Corp", types=["host"], cache_mode="cache")
        assert [h.uid for h in visible] == ["h-uncommitted"]
        assert await obj_service.get_object_by_uid("mds1", "Corp", "h10", cache_mode="cache") is None
        overlaid_obj = await obj_service.get_object_by_uid("mds1", "Corp", "h-uncommitted", cache_mode="cache")
        assert overlaid_obj is not None and overlaid_obj.name == "stage-host"

    await db.close()
