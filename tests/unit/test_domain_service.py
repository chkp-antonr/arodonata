"""Unit tests for `DomainService` and `DomainListRefreshTracker`."""

from __future__ import annotations

from collections.abc import Awaitable
from datetime import datetime, timedelta
from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext
from arodonata.core.errors import ConfigurationError, DomainNotFoundError
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.services.domain_service import (
    DomainListRefreshTracker,
    DomainService,
    parse_domain_dict,
)


class FakeApiPort:
    """In-memory `ApiPort` double for domain discovery tests."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any] | None, str | None]] = []
        self.responses: dict[tuple[str, str], list[ApiCallResult]] = {}

    def queue_response(self, mgmt_name: str, command: str, result: ApiCallResult) -> None:
        self.responses.setdefault((mgmt_name, command), []).append(result)

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
        self.calls.append((mgmt_name, command, payload, domain))
        queue = self.responses.get((mgmt_name, command), [])
        if queue:
            return queue.pop(0) if len(queue) > 1 else queue[0]
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


@pytest.mark.asyncio
async def test_domain_discovery_global_synthesis_and_opt_in_visibility() -> None:
    """`get_domains` discovers MDS domains, synthesizes `Global`, and filters `Global` unless `include_global=True`."""
    now = datetime(2026, 10, 23, 18, 0, 0)
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = FakeApiPort()

    api.queue_response(
        "mds1",
        "show-domains",
        ApiCallResult(
            success=True,
            data={
                "objects": [
                    {
                        "uid": "dom-uid-1",
                        "name": "Corp",
                        "type": "domain",
                        "servers": [
                            {
                                "name": "corp_cma_1",
                                "ipv4-address": "10.10.1.11",
                                "active": True,
                                "multi-domain-server": {"ipv4-address": "10.10.0.1"},
                            },
                            {
                                "name": "corp_cma_2",
                                "ipv4-address": "10.10.2.11",
                                "active": False,
                                "multi-domain-server": {"ipv4-address": "10.10.0.2"},
                            },
                        ],
                    },
                    {
                        "uid": "dom-uid-2",
                        "name": "DMZ",
                        "type": "domain",
                        "servers": [
                            {
                                "name": "dmz_cma_1",
                                "ipv4-address": "10.10.2.12",
                                "active": True,
                                "multi-domain-server": {"ipv4-address": "10.10.0.2"},
                            }
                        ],
                    },
                ]
            },
        ),
    )
    api.queue_response(
        "mds1",
        "show-global-domain",
        ApiCallResult(
            success=True,
            data={
                "uid": "global-uid-1",
                "name": "Global",
                "type": "global",
            },
        ),
    )

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.10.0.1", api_key="secret")
    service = DomainService(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        now_fn=lambda: now,
    )

    # Default include_global=False excludes Global
    domains_no_global = await service.get_domains("mds1", include_global=False)
    assert [d.name for d in domains_no_global] == ["Corp", "DMZ"]
    corp = domains_no_global[0]
    assert corp.active_ip == "10.10.1.11"
    assert corp.active_mds_ip == "10.10.0.1"
    assert corp.standby_ips == ["10.10.2.11"]

    # include_global=True includes Global without re-querying show-domains (within 1h TTL)
    call_count_before = len(api.calls)
    domains_with_global = await service.get_domains("mds1", include_global=True)
    assert len(api.calls) == call_count_before
    assert [d.name for d in domains_with_global] == ["Corp", "DMZ", "Global"]
    global_dom = next(d for d in domains_with_global if d.name == "Global")
    assert global_dom.is_global is True
    assert global_dom.uid == "global-uid-1"

    await db.close()


@pytest.mark.asyncio
async def test_domain_list_refresh_tracker_1_hour_ttl_and_force() -> None:
    """`DomainListRefreshTracker` skips re-fetching within 1 hour and re-fetches after 3600s or on `mode='force'`."""
    clock = [datetime(2026, 10, 23, 12, 0, 0)]
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeApiPort()

    api.queue_response(
        "mds1",
        "show-domains",
        ApiCallResult(
            success=True,
            data={"objects": [{"uid": "u1", "name": "DomA", "type": "domain"}]},
        ),
    )

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", domain_list_ttl=3600)
    tracker = DomainListRefreshTracker(ttl_seconds=3600.0, now_fn=lambda: clock[0])
    service = DomainService(
        settings=settings,
        api=api,
        cache=cache,
        tracker=tracker,
        now_fn=lambda: clock[0],
    )

    # First call fetches from server
    res1 = await service.get_domains("mds1")
    assert [d.name for d in res1] == ["DomA"]
    show_domains_calls = [c for c in api.calls if c[1] == "show-domains"]
    assert len(show_domains_calls) == 1

    # Advance 59 minutes (3540s < 3600s) -> no re-fetch
    clock[0] = clock[0] + timedelta(minutes=59)
    await service.get_domains("mds1")
    show_domains_calls = [c for c in api.calls if c[1] == "show-domains"]
    assert len(show_domains_calls) == 1

    # Advance past 1 hour (61 minutes total) -> re-fetches show-domains
    clock[0] = clock[0] + timedelta(minutes=2)
    await service.get_domains("mds1")
    show_domains_calls = [c for c in api.calls if c[1] == "show-domains"]
    assert len(show_domains_calls) == 2

    # Force mode always re-fetches even immediately
    await service.get_domains("mds1", cache_mode="force")
    show_domains_calls = [c for c in api.calls if c[1] == "show-domains"]
    assert len(show_domains_calls) == 3

    await db.close()


@pytest.mark.asyncio
async def test_domain_failover_active_ip_re_resolution() -> None:
    """`refresh_domain_failover` updates `active_ip` and `active_mds_ip` when a domain fails over to standby."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeApiPort()

    # Initial topology: CMA on 10.10.1.11 (MDS 10.10.0.1) is active, 10.10.2.11 (MDS 10.10.0.2) is standby
    api.queue_response(
        "mds1",
        "show-domains",
        ApiCallResult(
            success=True,
            data={
                "objects": [
                    {
                        "uid": "dom-1",
                        "name": "Finance",
                        "servers": [
                            {
                                "ipv4-address": "10.10.1.11",
                                "active": True,
                                "multi-domain-server": {"ipv4-address": "10.10.0.1"},
                            },
                            {
                                "ipv4-address": "10.10.2.11",
                                "active": False,
                                "multi-domain-server": {"ipv4-address": "10.10.0.2"},
                            },
                        ],
                    }
                ]
            },
        ),
    )
    # Failover topology: CMA on 10.10.2.11 (MDS 10.10.0.2) is now active
    api.queue_response(
        "mds1",
        "show-domains",
        ApiCallResult(
            success=True,
            data={
                "objects": [
                    {
                        "uid": "dom-1",
                        "name": "Finance",
                        "servers": [
                            {
                                "ipv4-address": "10.10.1.11",
                                "active": False,
                                "multi-domain-server": {"ipv4-address": "10.10.0.1"},
                            },
                            {
                                "ipv4-address": "10.10.2.11",
                                "active": True,
                                "multi-domain-server": {"ipv4-address": "10.10.0.2"},
                            },
                        ],
                    }
                ]
            },
        ),
    )

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.10.0.1", api_key="secret")
    service = DomainService(settings=settings, api=api, cache=cache)

    dom_initial = await service.get_domain("mds1", "Finance")
    assert dom_initial.active_ip == "10.10.1.11"
    assert dom_initial.active_mds_ip == "10.10.0.1"
    assert dom_initial.standby_ips == ["10.10.2.11"]

    dom_failover = await service.refresh_domain_failover("mds1", "Finance")
    assert dom_failover is not None
    assert dom_failover.active_ip == "10.10.2.11"
    assert dom_failover.active_mds_ip == "10.10.0.2"
    assert dom_failover.standby_ips == ["10.10.1.11"]

    with pytest.raises(DomainNotFoundError):
        await service.get_domain("mds1", "NonExistentDomain", cache_mode="cache")

    with pytest.raises(ConfigurationError):
        await service.get_domains("unknown_mgmt")

    parsed = parse_domain_dict("mds1", {"name": "BareDomain"}, default_host="10.10.0.1")
    assert parsed.active_ip == "10.10.0.1"
    assert parsed.active_mds_ip == "10.10.0.1"

    await db.close()


@pytest.mark.asyncio
async def test_domain_service_paginates_show_domains_across_multiple_pages() -> None:
    """Adversarial test for I14: `DomainService` paginates `show-domains` when `total` exceeds first page."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeApiPort()

    api.queue_response(
        "mds1",
        "show-domains",
        ApiCallResult(
            success=True,
            data={
                "objects": [{"uid": "d1", "name": "DomPage1", "type": "domain"}],
                "total": 2,
            },
        ),
    )
    api.queue_response(
        "mds1",
        "show-domains",
        ApiCallResult(
            success=True,
            data={
                "objects": [{"uid": "d2", "name": "DomPage2", "type": "domain"}],
                "total": 2,
            },
        ),
    )

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.10.0.1", api_key="secret")
    service = DomainService(settings=settings, api=api, cache=cache)

    domains = await service.get_domains("mds1")
    assert [d.name for d in domains] == ["DomPage1", "DomPage2"]
    await db.close()
