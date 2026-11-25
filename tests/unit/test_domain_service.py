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


@pytest.mark.spec("SCN-SESS-001-1")
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


@pytest.mark.spec("SCN-SESS-001-2")
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


@pytest.mark.spec("SCN-SESS-001-2")
@pytest.mark.asyncio
async def test_domain_service_falls_back_to_standard_details_level_on_rbac_rejection_and_preserves_cached_cma_ips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`DomainService` retries `show-domains` with `details-level='standard'` only on RBAC rejection, preserves cached CMA IPs, and does NOT fall back on 5xx errors."""
    from arodonata.core.models.domains import DomainInfo
    from arodonata.core.services import domain_service as dom_mod
    from arodonata.core.services.domain_service import SYSTEM_DOMAIN_KEY

    debug_logs: list[tuple[str, dict[str, Any]]] = []
    warning_logs: list[tuple[str, dict[str, Any]]] = []
    orig_debug = dom_mod.logger.debug
    orig_warning = dom_mod.logger.warning

    def _spy_debug(msg: str, *args: Any, **kwargs: Any) -> None:
        debug_logs.append((msg, kwargs))
        orig_debug(msg, *args, **kwargs)

    def _spy_warning(msg: str, *args: Any, **kwargs: Any) -> None:
        warning_logs.append((msg, kwargs))
        orig_warning(msg, *args, **kwargs)

    monkeypatch.setattr(dom_mod.logger, "debug", _spy_debug)
    monkeypatch.setattr(dom_mod.logger, "warning", _spy_warning)

    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeApiPort()

    # Seed an existing cached domain with known CMA active_ip ("10.10.2.50") and servers list
    await cache.upsert_domains(
        [
            DomainInfo(
                mgmt_name="mds1",
                uid="d-std-1",
                name="StandardDomain",
                active_ip="10.10.2.50",
                active_mds_ip="10.10.0.2",
                standby_ips=["10.10.2.51"],
                servers=[{"name": "cma-std-1", "ipv4-address": "10.10.2.50", "active": True}],
            )
        ]
    )

    api.queue_response(
        "mds1",
        "show-domains",
        ApiCallResult(
            success=False,
            status_code=403,
            error_code="err_forbidden",
            error_message="Permission denied for details-level full",
        ),
    )
    api.queue_response(
        "mds1",
        "show-domains",
        ApiCallResult(
            success=True,
            data={
                "objects": [
                    {"uid": "d-std-1", "name": "StandardDomain", "type": "domain"},
                    {"uid": "d-std-2", "name": "NewColdDomain", "type": "domain"},
                ],
                "total": 2,
            },
        ),
    )

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.10.0.1", api_key="secret")
    service = DomainService(settings=settings, api=api, cache=cache)

    domains = await service.refresh_domains("mds1", mode="force")
    by_name = {d.name: d for d in domains}
    assert set(by_name.keys()) == {"StandardDomain", "NewColdDomain"}
    # Previously cached CMA IPs and servers MUST be preserved when standard omits `servers`!
    assert by_name["StandardDomain"].active_ip == "10.10.2.50"
    assert by_name["StandardDomain"].active_mds_ip == "10.10.0.2"
    assert by_name["StandardDomain"].standby_ips == ["10.10.2.51"]
    assert len(by_name["StandardDomain"].servers) == 1
    # Brand-new domain with no cached servers falls back to MDS host
    assert by_name["NewColdDomain"].active_ip == "10.10.0.1"

    assert any("Discovering domains" in m and kw.get("mgmt_name") == "mds1" for m, kw in debug_logs)
    assert any("Cached 3 domain(s)" in m and kw.get("count") == 3 for m, kw in debug_logs)
    assert any("retrying with details-level=standard" in m and kw.get("mgmt_name") == "mds1" for m, kw in warning_logs)

    # Now verify that a transient 500 error on `show-domains` (`details-level=full`) does NOT trigger
    # the `details-level=standard` fallback, records `status="failed"`, and keeps existing cached domains intact.
    warning_logs.clear()
    api.calls.clear()
    api.responses.clear()
    api.queue_response(
        "mds1",
        "show-domains",
        ApiCallResult(
            success=False,
            status_code=500,
            error_code="generic_server_error",
            error_message="Internal server error",
        ),
    )

    domains_after_500 = await service.refresh_domains("mds1", mode="force")
    show_domains_calls = [c for c in api.calls if c[1] == "show-domains"]
    assert len(show_domains_calls) == 1
    assert show_domains_calls[0][2]["details-level"] == "full"
    assert {d.name for d in domains_after_500} == {"StandardDomain", "NewColdDomain"}
    sync_state = await cache.get_sync_state("mds1", SYSTEM_DOMAIN_KEY, "domains", "*")
    assert sync_state is not None and sync_state.status == "failed"
    assert any("Domain discovery via show-domains failed" in m for m, _ in warning_logs)

    await db.close()


@pytest.mark.asyncio
async def test_domain_service_catches_authentication_and_transport_errors_and_preserves_cached_domains() -> None:
    """`DomainService` catches `AuthenticationError` / `TransportError` from `api_call('show-domains')`, skips standard retry, records failed sync state, and preserves cached domains (while re-raising `ServerIdentityError`)."""
    from arodonata.core.errors import (
        AuthenticationError,
        ServerIdentityError,
        TransportError,
    )
    from arodonata.core.models.domains import DomainInfo
    from arodonata.core.services.domain_service import SYSTEM_DOMAIN_KEY

    class RaisingApiPort(FakeApiPort):
        def __init__(self) -> None:
            super().__init__()
            self.exc_to_raise: Exception | None = None

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
            self.calls.append((mgmt_name, command, dict(payload or {}), domain))
            if self.exc_to_raise is not None:
                raise self.exc_to_raise
            return await super().api_call(
                mgmt_name,
                command,
                payload,
                domain=domain,
                sid=sid,
                server_ip=server_ip,
                wait_for_task=wait_for_task,
                timeout=timeout,
            )

    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = RaisingApiPort()
    settings = ArodonataSettings(mgmt_name="smsNP82", mgmt_ip="10.192.11.138", api_key="secret")
    service = DomainService(settings=settings, api=api, cache=cache)

    # 1. Cold cache + AuthenticationError on login during show-domains -> returns [], records failed, 1 call only
    api.exc_to_raise = AuthenticationError(
        "Login to 'smsNP82' ('System Data' at 10.192.11.138) timed out or failed: Connect call failed"
    )
    cold_domains = await service.get_domains("smsNP82", cache_mode="force")
    assert cold_domains == []
    assert len([c for c in api.calls if c[1] == "show-domains"]) == 1
    st = await cache.get_sync_state("smsNP82", SYSTEM_DOMAIN_KEY, "domains", "*")
    assert st is not None
    assert st.status == "failed"
    assert "10.192.11.138" in (st.last_error or "")

    # 2. Warm cache + TransportError -> preserves previously cached domains!
    await cache.upsert_domains(
        [
            DomainInfo(
                mgmt_name="smsNP82",
                uid="dom-warm-1",
                name="WarmDom",
                active_ip="10.192.11.138",
                active_mds_ip="10.192.11.138",
            )
        ]
    )
    api.calls.clear()
    api.exc_to_raise = TransportError("Connection reset by peer")
    warm_domains = await service.get_domains("smsNP82", cache_mode="force")
    assert [d.name for d in warm_domains] == ["WarmDom"]
    assert len([c for c in api.calls if c[1] == "show-domains"]) == 1

    # 3. TLS ServerIdentityError MUST still propagate immediately (fail-closed security rule)
    api.exc_to_raise = ServerIdentityError("Fingerprint mismatch on 10.192.11.138")
    with pytest.raises(ServerIdentityError):
        await service.get_domains("smsNP82", cache_mode="force")

    await db.close()


@pytest.mark.spec("SCN-CACHE-004-3")
def test_domain_list_refresh_tracker_global_invalidate_none_forces_refresh() -> None:
    """SCN-CACHE-004-3 (DA-002): DomainListRefreshTracker.invalidate(None) overrides persisted_synced_at within TTL."""
    clock = [datetime(2026, 11, 23, 12, 0, 0)]
    tracker = DomainListRefreshTracker(ttl_seconds=3600.0, now_fn=lambda: clock[0])
    persisted_ts = clock[0] - timedelta(seconds=30)

    # Without invalidation, persisted_synced_at 30s ago is fresh (< 3600s)
    assert (
        tracker.needs_refresh(
            "mds1",
            has_cached_domains=True,
            persisted_synced_at=persisted_ts,
            mode="smart",
        )
        is False
    )

    # Calling invalidate(None) forces refresh even when persisted_synced_at is recent (and even at frozen clock)
    tracker.invalidate(None)
    assert (
        tracker.needs_refresh(
            "mds1",
            has_cached_domains=True,
            persisted_synced_at=persisted_ts,
            mode="smart",
        )
        is True
    )

    # Once refreshed, it becomes fresh again
    tracker.mark_refreshed("mds1", clock[0])
    assert (
        tracker.needs_refresh(
            "mds1",
            has_cached_domains=True,
            persisted_synced_at=clock[0],
            mode="smart",
        )
        is False
    )


@pytest.mark.spec("SCN-SESS-013-1")
@pytest.mark.asyncio
async def test_canonical_domain_parser_mds_standard_fallback_and_shared_write_session_lifecycle() -> None:
    """Verify canonical `parse_domain_entry`/`parse_domain_dict` parity, MDS RBAC fallback preserving cached CMA IPs, and shared WriteSession lifecycle."""
    from arodonata.adapters.checkpoint import response_classifiers
    from arodonata.adapters.checkpoint import sessions as sessions_mod
    from arodonata.adapters.checkpoint.rate_limiter import RateLimiter
    from arodonata.adapters.checkpoint.target_resolver import fetch_domain_topology_from_mds
    from arodonata.core.config import ServerEndpointConfig
    from arodonata.core.context import open_api_write_session
    from arodonata.core.models.domains import DomainInfo, parse_domain_entry

    # 1. Identity and parity of parse_domain_entry / parse_domain_dict
    assert sessions_mod.parse_domain_entry is response_classifiers.parse_domain_entry is parse_domain_entry
    raw_dom = {
        "uid": "d-uid-1",
        "name": "Corp",
        "servers": [{"ipv4-address": "10.1.0.5", "active": True, "multi-domain-server": "mds-a"}],
    }
    d_entry = parse_domain_entry("mds1", raw_dom, mds_ip_by_name={"mds-a": "10.0.0.10"})
    d_dict = parse_domain_dict("mds1", raw_dom, mds_ip_by_name={"mds-a": "10.0.0.10"})
    assert d_entry.active_ip == d_dict.active_ip == "10.1.0.5"
    assert d_entry.active_mds_ip == d_dict.active_mds_ip == "10.0.0.10"

    # 2. fetch_domain_topology_from_mds falls back to details-level="standard" on 403 and preserves cached CMA IP
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    await cache.upsert_domains(
        [
            DomainInfo(
                mgmt_name="mds1",
                uid="d-corp",
                name="Corp",
                active_ip="10.9.9.9",
                active_mds_ip="10.0.0.1",
                servers=[{"ipv4-address": "10.9.9.9", "active": True}],
            )
        ]
    )

    seen_levels: list[str] = []

    class _FallbackTransport:
        async def execute(self, host: str, cmd: str, payload: dict[str, Any], **kwargs: Any) -> ApiCallResult:
            lvl = str(payload.get("details-level") or "")
            seen_levels.append(lvl)
            if cmd == "show-domains" and lvl == "full":
                return ApiCallResult(
                    success=False, status_code=403, error_code="err_forbidden", error_message="forbidden"
                )
            if cmd == "show-domains" and lvl == "standard":
                return ApiCallResult(
                    success=True, data={"objects": [{"uid": "d-corp", "name": "Corp", "type": "domain"}]}
                )
            return ApiCallResult(success=False)

    async def _fake_ro(*args: Any, **kwargs: Any) -> tuple[str, str]:
        return "sys-sid", "10.0.0.1"

    async def _fake_id() -> str | None:
        return None

    matched = await fetch_domain_topology_from_mds(
        mgmt_name="mds1",
        domain_name="Corp",
        endpoint=ServerEndpointConfig(name="mds1", host="10.0.0.1"),
        transport=_FallbackTransport(),  # type: ignore[arg-type]
        cache=cache,
        rate_limiter=RateLimiter(concurrent_limit=10),
        settings=ArodonataSettings(),
        known_mds_ips=set(),
        get_readonly_session_fn=_fake_ro,
        resolve_identity_fn=_fake_id,
    )
    assert seen_levels == ["full", "standard"]
    assert matched is not None
    assert matched.active_ip == "10.9.9.9"

    # 3. Shared WriteSession lifecycle via open_api_write_session (publish on clean exit, discard on exception, logout)
    calls: list[str] = []

    class _FakeApi:
        async def create_dedicated_session(self, *args: Any, **kwargs: Any) -> tuple[str, str]:
            return "ws-sid-1", "10.1.0.1"

        async def api_call(self, mgmt: str, cmd: str, *args: Any, **kwargs: Any) -> ApiCallResult:
            calls.append(cmd)
            return ApiCallResult(success=True, data={})

        async def logout_sid(self, mgmt: str, sid: str, **kwargs: Any) -> bool:
            calls.append(f"logout:{sid}")
            return True

    async with open_api_write_session(_FakeApi(), "mds1", "Corp"):  # type: ignore[arg-type]
        pass
    assert calls == ["publish", "logout:ws-sid-1"]
    await db.close()


async def test_discover_mds_domains_stalled_pagination_and_write_session_error_preservation() -> None:
    """DA-021/DA-022/DA-029: Stop on stalled domain pagination and preserve body exception on discard failure."""
    from arodonata.core.context import open_api_write_session
    from arodonata.core.services._domain_discovery import discover_mds_domains

    calls = 0

    async def _stalled_exec(cmd: str, payload: dict[str, Any]) -> ApiCallResult:
        nonlocal calls
        if cmd == "show-domains":
            calls += 1
            return ApiCallResult(
                success=True,
                data={
                    "total": 999,
                    "objects": [{"uid": "d1", "name": "Corp", "type": "domain", "servers": []}],
                },
            )
        return ApiCallResult(success=True, data={"objects": []})

    disc = await discover_mds_domains("mds1", _stalled_exec, existing_domains=[])
    assert len(disc.domains) == 1
    assert calls == 2

    class _FailingDiscardApi:
        async def create_dedicated_session(self, *args: Any, **kwargs: Any) -> tuple[str, str]:
            return "ws-sid-err", "10.0.0.1"

        async def api_call(self, mgmt: str, cmd: str, *args: Any, **kwargs: Any) -> ApiCallResult:
            if cmd == "discard":
                raise RuntimeError("discard boom")
            return ApiCallResult(success=True, data={})

        async def logout_sid(self, mgmt: str, sid: str, **kwargs: Any) -> bool:
            return True

    with pytest.raises(ValueError, match="original body error"):
        async with open_api_write_session(_FailingDiscardApi(), "mds1", "Corp"):  # type: ignore[arg-type]
            raise ValueError("original body error")
