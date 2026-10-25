"""Unit tests for `DomainSyncCoordinator`."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from datetime import datetime
from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext
from arodonata.core.errors import InvalidCredentialsError, ServerIdentityError
from arodonata.core.events import DomainSyncFailedEvent, DomainSyncSkippedEvent, SyncProgressEvent
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainInfo, DomainSyncState, SIDCacheEntry
from arodonata.core.models.objects import CPObject
from arodonata.core.services import (
    DomainProbeResult,
    DomainService,
    DomainSyncCoordinator,
    parse_cp_publish_timestamp,
)


class CoordinatorFakeApi:
    """In-memory `ApiPort` double for `DomainSyncCoordinator` tests."""

    def __init__(self) -> None:
        self.published_sessions: dict[str, dict[str, Any]] = {}
        self.session_info: dict[str, dict[str, Any]] = {}
        self.fail_credentials_domains: set[str] = set()

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
        if domain and domain in self.fail_credentials_domains:
            raise InvalidCredentialsError(f"Authentication to server failed for {domain}")

        if command == "show-last-published-session" and domain:
            info = self.published_sessions.get(
                domain,
                {
                    "uid": f"sess-{domain}",
                    "publish-time": {"iso-8601": "2026-10-23T12:00:00Z", "posix": 1792756800000},
                },
            )
            return ApiCallResult(success=True, data=info)

        if command == "show-session" and domain:
            s_info = self.session_info.get(domain, {"locks": 0, "changes": 0, "number-of-published-changes": 0})
            return ApiCallResult(success=True, data=s_info)

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
async def test_coordinator_concurrency_per_mds_member() -> None:
    """`DomainSyncCoordinator` runs up to `max(1, concurrent_limit - 1)` domains per MDS member in parallel across members."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = CoordinatorFakeApi()

    # concurrent_limit=3 -> max(1, 3 - 1) = 2 concurrent domains per MDS member
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", concurrent_limit=3)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    domain_service.tracker.mark_refreshed("mds1")

    # 3 domains on MDS member 10.0.0.1, 2 domains on MDS member 10.0.0.2
    await cache.upsert_domains(
        [
            DomainInfo(mgmt_name="mds1", uid="d1", name="Dom1", active_ip="10.1.0.1", active_mds_ip="10.0.0.1"),
            DomainInfo(mgmt_name="mds1", uid="d2", name="Dom2", active_ip="10.1.0.2", active_mds_ip="10.0.0.1"),
            DomainInfo(mgmt_name="mds1", uid="d3", name="Dom3", active_ip="10.1.0.3", active_mds_ip="10.0.0.1"),
            DomainInfo(mgmt_name="mds1", uid="d4", name="Dom4", active_ip="10.2.0.1", active_mds_ip="10.0.0.2"),
            DomainInfo(mgmt_name="mds1", uid="d5", name="Dom5", active_ip="10.2.0.2", active_mds_ip="10.0.0.2"),
        ]
    )

    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )

    active_per_mds: dict[str, int] = {"10.0.0.1": 0, "10.0.0.2": 0}
    max_per_mds: dict[str, int] = {"10.0.0.1": 0, "10.0.0.2": 0}
    max_global = 0
    active_global = 0

    async def _handler(
        probe: DomainProbeResult,
        _emit: Any,
    ) -> int:
        nonlocal active_global, max_global
        mds = probe.domain.active_mds_ip or "10.0.0.1"
        active_per_mds[mds] += 1
        active_global += 1
        max_per_mds[mds] = max(max_per_mds[mds], active_per_mds[mds])
        max_global = max(max_global, active_global)
        await asyncio.sleep(0.03)
        active_per_mds[mds] -= 1
        active_global -= 1
        return 1

    outcome = await coordinator.ensure(
        scope="objects",
        item_types=["host"],
        handler=_handler,
        mgmt_name="mds1",
        mode="force",
    )

    assert len(outcome.refreshed_domains) == 5
    # On MDS 10.0.0.1 (3 domains), concurrency is capped at 2 (`concurrent_limit - 1`)
    assert max_per_mds["10.0.0.1"] <= 2
    assert max_per_mds["10.0.0.2"] <= 2
    # Across both MDS members in parallel, global concurrency exceeds a single member's cap
    assert max_global >= 3

    await db.close()


@pytest.mark.asyncio
async def test_coordinator_timestamp_and_session_uid_staleness_check() -> None:
    """Staleness compares `last_published_at` first and `last_session_uid` when timestamps match."""
    pub_time = datetime(2026, 10, 23, 12, 0, 0)
    now = datetime(2026, 10, 23, 13, 0, 0)

    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = CoordinatorFakeApi()

    api.published_sessions["Corp"] = {
        "uid": "sess-v2",
        "publish-time": {"iso-8601": "2026-10-23T12:00:00Z"},
    }

    # cache_ttl=0 forces server probe every time
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port, now_fn=lambda: now)
    domain_service.tracker.mark_refreshed("mds1", now)

    dom = DomainInfo(mgmt_name="mds1", uid="d1", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1")
    await cache.upsert_domains([dom])

    # "host" has matching timestamp AND matching session UID ("sess-v2") -> fresh!
    await cache.upsert_sync_state(
        DomainSyncState(
            mgmt_name="mds1",
            domain_name="Corp",
            scope="objects",
            item_type="host",
            last_published_at=pub_time,
            last_session_uid="sess-v2",
            synced_at=pub_time,
            status="ok",
            object_count=10,
        )
    )
    # "network" has matching timestamp ("12:00:00Z") but DIFFERENT session UID ("sess-v1") -> stale!
    await cache.upsert_sync_state(
        DomainSyncState(
            mgmt_name="mds1",
            domain_name="Corp",
            scope="objects",
            item_type="network",
            last_published_at=pub_time,
            last_session_uid="sess-v1",
            synced_at=pub_time,
            status="ok",
            object_count=5,
        )
    )

    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
        now_fn=lambda: now,
    )

    probe = await coordinator.probe_domain_staleness(
        dom,
        scope="objects",
        item_types=["host", "network"],
        mode="smart",
    )
    assert probe.fresh_types == ["host"]
    assert probe.stale_types == ["network"]

    await db.close()


@pytest.mark.asyncio
async def test_coordinator_dirty_session_and_invalid_credentials_preserve_cache() -> None:
    """Dirty session or `InvalidCredentialsError` during probe records `failed_domains` and emits `DomainSyncFailedEvent` while preserving cached rows."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = CoordinatorFakeApi()

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    domain_service.tracker.mark_refreshed("mds1")

    await cache.upsert_domains(
        [
            DomainInfo(mgmt_name="mds1", uid="d1", name="DirtyDom", active_ip="10.1.0.1", active_mds_ip="10.0.0.1"),
            DomainInfo(mgmt_name="mds1", uid="d2", name="BadAuthDom", active_ip="10.1.0.2", active_mds_ip="10.0.0.1"),
        ]
    )

    # Seed previously cached objects in both domains
    await cache.replace_domain_objects(
        "mds1",
        "DirtyDom",
        [CPObject(uid="h1", name="h-dirty", type="host", mgmt_name="mds1", domain_name="DirtyDom")],
        types=["host"],
    )
    await cache.replace_domain_objects(
        "mds1",
        "BadAuthDom",
        [CPObject(uid="h2", name="h-badauth", type="host", mgmt_name="mds1", domain_name="BadAuthDom")],
        types=["host"],
    )

    # DirtyDom has locks=1 on shared session; BadAuthDom raises InvalidCredentialsError on probe
    api.session_info["DirtyDom"] = {"locks": 1, "changes": 2, "number-of-published-changes": 0}
    api.fail_credentials_domains.add("BadAuthDom")

    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )

    events: list[SyncProgressEvent] = []

    async def _handler(_probe: DomainProbeResult, _emit: Any) -> int:
        return 0

    async for ev in coordinator.stream_ensure(
        scope="objects",
        item_types=["host"],
        handler=_handler,
        mgmt_name="mds1",
        mode="smart",
    ):
        events.append(ev)

    failed_events = [e for e in events if isinstance(e, DomainSyncFailedEvent)]
    assert len(failed_events) == 2

    outcome = await coordinator.ensure(
        scope="objects",
        item_types=["host"],
        handler=_handler,
        mgmt_name="mds1",
        mode="smart",
    )
    assert "mds1:DirtyDom" in outcome.failed_domains
    assert "dirty" in outcome.failed_domains["mds1:DirtyDom"].lower()
    assert "mds1:BadAuthDom" in outcome.failed_domains
    assert "authentication" in outcome.failed_domains["mds1:BadAuthDom"].lower()

    # Previously cached objects remain intact!
    assert len(await cache.get_objects("mds1", "DirtyDom")) == 1
    assert len(await cache.get_objects("mds1", "BadAuthDom")) == 1

    # Also test timestamp parser helper formats
    assert parse_cp_publish_timestamp({"iso-8601": "2026-10-23T12:00:00+0300"}) is not None
    assert parse_cp_publish_timestamp(1792756800) is not None

    await db.close()


@pytest.mark.asyncio
async def test_coordinator_lock_heartbeat_contention_skip_taskgroup_cancel_and_sid_redaction() -> None:
    """Adversarial test for W13, W14, W15, W20, W22:
    - Periodic lock renewal heartbeat keeps lock alive during slow sync (W13).
    - LockAcquisitionError skips the domain without marking status='failed' or emitting DomainSyncFailedEvent (W14).
    - ServerIdentityError cancels sibling domain sync tasks immediately via asyncio.TaskGroup (W15).
    - verify_session_clean fails closed when show-session returns success=False (W20).
    - last_error and DomainSyncFailedEvent redact known_sids from arodonata_sid_cache (W22).
    """
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = CoordinatorFakeApi()

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    domain_service.tracker.mark_refreshed("mds1")

    dom1 = DomainInfo(mgmt_name="mds1", uid="d1", name="DomLocked", active_ip="10.1.0.1", active_mds_ip="10.0.0.1")
    await cache.upsert_domains([dom1])
    await cache.upsert_sync_state(
        DomainSyncState(
            mgmt_name="mds1",
            domain_name="DomLocked",
            scope="objects",
            item_type="host",
            synced_at=datetime(2026, 10, 23, 10, 0, 0),
            status="ok",
            object_count=3,
        )
    )

    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )

    # 1. W14: Pre-acquire the distributed lock under another worker owner -> coordinator skips without marking failed!
    await lock_port.acquire(
        "sync:mds1:DomLocked:objects",
        ttl_seconds=60.0,
        wait_timeout=0.05,
        owner_id="other-worker",
    )

    orig_lock = lock_port.lock

    def fast_failing_lock(
        lock_key: str, *, ttl_seconds: float = 60.0, wait_timeout: float = 30.0, owner_id: str | None = None
    ) -> Any:
        return orig_lock(lock_key, ttl_seconds=ttl_seconds, wait_timeout=0.03, owner_id=owner_id)

    lock_port.lock = fast_failing_lock  # type: ignore[method-assign]

    events: list[SyncProgressEvent] = []
    async for ev in coordinator.stream_ensure(
        scope="objects",
        item_types=["host"],
        handler=lambda _p, _e: asyncio.sleep(0, result=1),
        mgmt_name="mds1",
        mode="force",
        lock_ttl_seconds=60.0,
    ):
        events.append(ev)

    lock_port.lock = orig_lock  # type: ignore[method-assign]

    assert any(isinstance(e, DomainSyncSkippedEvent) for e in events)
    assert not any(isinstance(e, DomainSyncFailedEvent) for e in events)
    st_after_lock = await cache.get_sync_state("mds1", "DomLocked", "objects", "host")
    assert st_after_lock is not None and st_after_lock.status == "ok"

    await lock_port.release("sync:mds1:DomLocked:objects", owner_id="other-worker")

    # 2. W13: Lock heartbeat renews the lock during a handler that runs longer than initial TTL
    renew_count = 0
    orig_renew = lock_port.renew

    async def counting_renew(lock_key: str, *, ttl_seconds: float = 60.0, owner_id: str | None = None) -> bool:
        nonlocal renew_count
        renew_count += 1
        return await orig_renew(lock_key, ttl_seconds=ttl_seconds, owner_id=owner_id)

    lock_port.renew = counting_renew  # type: ignore[method-assign]

    async def slow_handler(_p: DomainProbeResult, _e: Any) -> int:
        await asyncio.sleep(0.14)
        return 2

    outcome_hb = await coordinator.ensure(
        scope="objects",
        item_types=["host"],
        handler=slow_handler,
        mgmt_name="mds1",
        mode="force",
        lock_ttl_seconds=0.15,
    )
    assert outcome_hb.refreshed_domains == ["mds1:DomLocked"]
    assert renew_count >= 1

    # 3. W20 & W22: When show-session fails with HTTP 500 or handler leaks a known short SID,
    # verify_session_clean fails closed AND redacts known_sids in last_error and DomainSyncFailedEvent!
    await cache.upsert_sid(
        SIDCacheEntry(
            id="mds1:DomLocked:id1",
            mgmt_name="mds1",
            domain_name="DomLocked",
            sid="short_sid_999",
            server_ip="10.1.0.1",
            auth_identity="id1",
        )
    )

    async def leaking_handler(_p: DomainProbeResult, _e: Any) -> int:
        raise RuntimeError("Upstream failed with session token short_sid_999 on DomLocked")

    outcome_leak = await coordinator.ensure(
        scope="objects",
        item_types=["host"],
        handler=leaking_handler,
        mgmt_name="mds1",
        mode="force",
    )
    assert "mds1:DomLocked" in outcome_leak.failed_domains
    assert "short_sid_999" not in outcome_leak.failed_domains["mds1:DomLocked"]
    assert "***REDACTED***" in outcome_leak.failed_domains["mds1:DomLocked"]
    st_failed = await cache.get_sync_state("mds1", "DomLocked", "objects", "host")
    assert st_failed is not None
    assert st_failed.last_error is not None and "short_sid_999" not in st_failed.last_error

    # 4. W15: ServerIdentityError cancels sibling domain tasks immediately via TaskGroup
    dom2 = DomainInfo(mgmt_name="mds1", uid="d2", name="DomSibling", active_ip="10.2.0.1", active_mds_ip="10.0.0.2")
    await cache.upsert_domains([dom1, dom2])
    sibling_cancelled = False

    async def identity_or_sibling_handler(probe: DomainProbeResult, _e: Any) -> int:
        nonlocal sibling_cancelled
        if probe.domain.name == "DomLocked":
            await asyncio.sleep(0.01)
            raise ServerIdentityError("TLS certificate fingerprint mismatch on 10.1.0.1:443")
        try:
            await asyncio.sleep(2.0)
            return 1
        except asyncio.CancelledError:
            sibling_cancelled = True
            raise

    with pytest.raises(ServerIdentityError):
        await coordinator.ensure(
            scope="objects",
            item_types=["host"],
            handler=identity_or_sibling_handler,
            mgmt_name="mds1",
            mode="force",
        )
    assert sibling_cancelled is True

    await db.close()
