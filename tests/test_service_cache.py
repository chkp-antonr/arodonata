"""Unit tests for `ServiceCacheService`."""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext, SessionOverlay, WriteSession, write_session_context
from arodonata.core.models.common import DEFAULT_SERVICE_TYPES, ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainInfo
from arodonata.core.models.services import CPService
from arodonata.core.services import (
    DomainService,
    DomainSyncCoordinator,
    ServiceCacheService,
)


class ServiceFakeApi:
    """In-memory `ApiPort` double for `ServiceCacheService` tests."""

    def __init__(self) -> None:
        self.query_data: dict[str, list[dict[str, Any]]] = {
            "show-services-tcp": [
                {"uid": "st1", "name": "https", "type": "service-tcp", "port": "443", "protocol": "tcp"},
                {"uid": "st2", "name": "ssh", "type": "service-tcp", "port": "22", "protocol": "tcp"},
            ],
            "show-services-udp": [
                {"uid": "su1", "name": "dns-udp", "type": "service-udp", "port": "53", "protocol": "udp"},
            ],
            "show-services-icmp": [
                {"uid": "si1", "name": "echo-request", "type": "service-icmp", "icmp-type": 8, "icmp-code": 0},
            ],
            "show-service-groups": [
                {"uid": "sg1", "name": "web-services", "type": "service-group", "members": ["st1", "su1"]},
            ],
            "show-services-other": [
                {"uid": "so1", "name": "gre-proto", "type": "service-other", "ip-protocol": 47},
            ],
        }
        self.queried_commands: list[str] = []

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
                data={"uid": "svc-sess-1", "publish-time": {"iso-8601": "2026-10-23T15:00:00Z"}},
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
        self.queried_commands.append(command)
        objs = self.query_data.get(command, [])
        return ApiQueryResult(success=True, objects=objs, total=len(objs))

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
async def test_service_cache_default_types_and_selective_on_demand_refresh() -> None:
    """`ServiceCacheService` syncs the 4 default service types and syncs `service-other` on demand without wiping `service-tcp`."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = ServiceFakeApi()

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
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
    svc_service = ServiceCacheService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )

    # 1. Default refresh loads ("service-tcp", "service-udp", "service-icmp", "service-group")
    outcome = await svc_service.refresh_services(mgmt_name="mds1", mode="smart")
    assert outcome.refreshed_domains == ["mds1:Corp"]
    assert outcome.total_items == 5
    assert "show-services-other" not in api.queried_commands

    for s_type in DEFAULT_SERVICE_TYPES:
        st = await cache.get_sync_state("mds1", "Corp", "services", s_type)
        assert st is not None
        assert st.status == "ok"
        assert st.last_session_uid == "svc-sess-1"

    # 2. On-demand refresh of types=["service-other"] preserves existing service-tcp rows
    api.queried_commands.clear()
    events = [
        ev
        async for ev in svc_service.stream_refresh_services(
            mgmt_name="mds1",
            types=["service-other"],
            mode="smart",
        )
    ]
    assert any(ev.item_type == "service-other" for ev in events)
    assert api.queried_commands == ["show-services-other"]

    tcp_rows = await cache.get_services("mds1", "Corp", types=["service-tcp"])
    assert len(tcp_rows) == 2
    other_rows = await cache.get_services("mds1", "Corp", types=["service-other"])
    assert len(other_rows) == 1
    assert other_rows[0].name == "gre-proto"

    other_state = await cache.get_sync_state("mds1", "Corp", "services", "service-other")
    assert other_state is not None
    assert other_state.status == "ok"
    assert other_state.object_count == 1

    # 3. Verify WriteSession overlay on get_services / get_service_by_uid
    overlay = SessionOverlay("mds1", "Corp")
    overlay.record_service_upsert(
        CPService(
            uid="st-new", name="custom-tcp-8443", type="service-tcp", mgmt_name="mds1", domain_name="Corp", port="8443"
        )
    )
    overlay.record_service_delete(uid="st1")
    ws = WriteSession(mgmt_name="mds1", domain_name="Corp", sid="s-write", server_ip="10.1.0.1", overlay=overlay)
    with write_session_context(ws):
        svcs = await svc_service.get_services("mds1", "Corp", types=["service-tcp"], cache_mode="cache")
        assert {s.uid for s in svcs} == {"st2", "st-new"}
        assert await svc_service.get_service_by_uid("mds1", "Corp", "st1", cache_mode="cache") is None
        added_svc = await svc_service.get_service_by_uid("mds1", "Corp", "st-new", cache_mode="cache")
        assert added_svc is not None and added_svc.port == "8443"

    await db.close()
