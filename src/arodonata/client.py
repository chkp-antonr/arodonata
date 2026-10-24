"""Primary composition root and unified developer facade (`ArodonataClient`).

Wires `ApiPort` (`AMgmtClient`), `CachePort` (`SqlCacheAdapter`), and `LockPort` (`SqlLockAdapter`)
into core domain services (`DomainService`, `DomainSyncCoordinator`, `ObjectService`,
`ServiceCacheService`, `AssetRefreshService`, `SearchService`), defaulting `engine=None` to an
auto-owned in-memory SQLite engine (`sqlite+aiosqlite:///:memory:`).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Sequence
from contextlib import asynccontextmanager, contextmanager, suppress
from datetime import datetime
from typing import Any, Literal

from sqlalchemy.ext.asyncio import AsyncEngine

from arodonata.adapters.checkpoint import AMgmtClient
from arodonata.adapters.checkpoint.client import SERVICE_COMMAND_TYPES, _update_overlay_from_command
from arodonata.adapters.checkpoint.pager import DEFAULT_PAGE_LIMIT
from arodonata.adapters.checkpoint.rate_limiter import LoginGate, RateLimiter
from arodonata.adapters.checkpoint.sessions import normalize_domain_key
from arodonata.adapters.checkpoint.task_waiter import TaskWaiter
from arodonata.adapters.checkpoint.tls import TrustPolicy
from arodonata.adapters.checkpoint.transport import ApiTransport, VerifiedConnectionPool
from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import (
    AuthContext,
    SessionOverlay,
    UserContext,
    WriteSession,
    get_user_context,
    get_write_session,
    write_session_context,
)
from arodonata.core.context import (
    auth_context as _ctx_auth_context,
)
from arodonata.core.context import (
    user_context as _ctx_user_context,
)
from arodonata.core.errors import SessionError
from arodonata.core.events import SyncProgressEvent
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import (
    ApiCallResult,
    ApiQueryResult,
    CacheMode,
    SyncScope,
    utc_now,
)
from arodonata.core.models.domains import DomainInfo, RefreshOutcome
from arodonata.core.models.objects import CPObject, SearchResult
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    HttpsRuleEntry,
    NatRuleEntry,
    RulebaseType,
    ThreatRuleEntry,
)
from arodonata.core.models.services import CPService
from arodonata.core.ports import ApiPort, AuthProvider, CachePort, LockPort
from arodonata.core.services import (
    AssetRefreshService,
    ClusterRelationshipManager,
    DomainListRefreshTracker,
    DomainService,
    DomainSyncCoordinator,
    ObjectService,
    SearchService,
    ServiceCacheService,
    VSXRelationshipManager,
)
from arodonata.core.telemetry import span_attrs, traced
from arodonata.reports import (
    MAX_UID_LOOKUPS,
    ChangeReport,
    RenderedReportBundle,
    RenderOptions,
    ReportScope,
)
from arodonata.reports import (
    build_change_report as _build_change_report,
)
from arodonata.reports import (
    collect_change_report as _collect_change_report,
)
from arodonata.reports import (
    render_change_report as _render_change_report,
)
from arodonata.rulebase import (
    CachedRulebaseSource,
    FilteredRulebaseResult,
    NumberedLayerRulebase,
    PackageRulebase,
    PolicyPackageInfo,
    RulebaseRefreshService,
    RuleFormat,
    RuleLocations,
)


class ArodonataClient:
    """Unified composition root and async facade for Check Point Management & MDSM."""

    def __init__(
        self,
        settings: ArodonataSettings | None = None,
        *,
        engine: AsyncEngine | str | None = None,
        db_manager: DatabaseManager | None = None,
        cache: CachePort | None = None,
        lock_port: LockPort | None = None,
        api: ApiPort | None = None,
        transport: ApiTransport | None = None,
        trust_policy: TrustPolicy | None = None,
        connection_pool: VerifiedConnectionPool | None = None,
        task_waiter: TaskWaiter | None = None,
        rate_limiter: RateLimiter | None = None,
        login_gate: LoginGate | None = None,
        auth_provider: AuthProvider | None = None,
        domain_tracker: DomainListRefreshTracker | None = None,
        cluster_manager: ClusterRelationshipManager | None = None,
        vsx_manager: VSXRelationshipManager | None = None,
        monotonic_fn: Callable[[], float] = time.monotonic,
        now_fn: Callable[[], datetime] = utc_now,
        sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
        **settings_kwargs: Any,
    ) -> None:
        self._settings = settings if settings is not None else ArodonataSettings(**settings_kwargs)
        self._settings.configure_tracing()
        self._now = now_fn

        if db_manager is not None:
            self._db = db_manager
            self._owns_engine = db_manager.owns_engine
        else:
            eff_engine = engine if engine is not None else self._settings.database_url
            self._db = DatabaseManager(
                engine=eff_engine if engine is not None else None,
                busy_timeout_ms=self._settings.sqlite_busy_timeout_ms,
            )
            self._owns_engine = self._db.owns_engine

        self._cache: CachePort = cache if cache is not None else SqlCacheAdapter(self._db)
        self._lock_port: LockPort = lock_port if lock_port is not None else SqlLockAdapter(self._db)

        if api is not None:
            self._api: ApiPort = api
            self._amgmt: AMgmtClient | None = api if isinstance(api, AMgmtClient) else None
        else:
            self._amgmt = AMgmtClient(
                self._settings,
                db_manager=self._db,
                cache=self._cache,
                lock_port=self._lock_port,
                transport=transport,
                trust_policy=trust_policy,
                connection_pool=connection_pool,
                task_waiter=task_waiter,
                rate_limiter=rate_limiter,
                login_gate=login_gate,
                auth_provider=auth_provider,
                on_domain_invalidated=self._handle_amgmt_domain_invalidated,
                monotonic_fn=monotonic_fn,
                now_fn=now_fn,
                sleep_fn=sleep_fn,
            )
            self._api = self._amgmt

        self._domain_service = DomainService(
            settings=self._settings,
            api=self._api,
            cache=self._cache,
            lock_port=self._lock_port,
            tracker=domain_tracker,
            now_fn=now_fn,
        )
        self._sync_coordinator = DomainSyncCoordinator(
            settings=self._settings,
            api=self._api,
            cache=self._cache,
            lock_port=self._lock_port,
            domain_service=self._domain_service,
            now_fn=now_fn,
        )
        self._object_service = ObjectService(
            settings=self._settings,
            api=self._api,
            cache=self._cache,
            coordinator=self._sync_coordinator,
            now_fn=now_fn,
        )
        self._service_cache = ServiceCacheService(
            settings=self._settings,
            api=self._api,
            cache=self._cache,
            coordinator=self._sync_coordinator,
            now_fn=now_fn,
        )
        self._asset_service = AssetRefreshService(
            settings=self._settings,
            api=self._api,
            cache=self._cache,
            coordinator=self._sync_coordinator,
            cluster_manager=cluster_manager,
            vsx_manager=vsx_manager,
            now_fn=now_fn,
        )
        self._search_service = SearchService(
            cache=self._cache,
            object_service=self._object_service,
            service_cache=self._service_cache,
            now_fn=now_fn,
        )
        self._rulebase_refresh = RulebaseRefreshService(
            settings=self._settings,
            api=self._api,
            cache=self._cache,
            coordinator=self._sync_coordinator,
            now_fn=now_fn,
        )
        self._rulebase_source = CachedRulebaseSource(
            cache=self._cache,
            refresh_service=self._rulebase_refresh,
            object_service=self._object_service,
            service_cache=self._service_cache,
            now_fn=now_fn,
        )
        self._warmup_tasks: set[asyncio.Task[Any]] = set()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def settings(self) -> ArodonataSettings:
        """Active `ArodonataSettings`."""
        return self._settings

    @property
    def db(self) -> DatabaseManager:
        """Underlying `DatabaseManager`."""
        return self._db

    @property
    def owns_engine(self) -> bool:
        """Return `True` if this client auto-created and owns its SQLAlchemy `AsyncEngine`."""
        return self._owns_engine

    @property
    def cache(self) -> CachePort:
        """Active `CachePort` adapter."""
        return self._cache

    @property
    def lock_port(self) -> LockPort:
        """Active `LockPort` adapter."""
        return self._lock_port

    @property
    def api(self) -> ApiPort:
        """Active `ApiPort` adapter."""
        return self._api

    @property
    def amgmt(self) -> AMgmtClient | None:
        """Underlying `AMgmtClient` if constructed with the default transport adapter."""
        return self._amgmt

    @property
    def domain_service(self) -> DomainService:
        """Core `DomainService`."""
        return self._domain_service

    @property
    def sync_coordinator(self) -> DomainSyncCoordinator:
        """Core `DomainSyncCoordinator`."""
        return self._sync_coordinator

    @property
    def object_service(self) -> ObjectService:
        """Core `ObjectService`."""
        return self._object_service

    @property
    def service_cache(self) -> ServiceCacheService:
        """Core `ServiceCacheService`."""
        return self._service_cache

    @property
    def asset_service(self) -> AssetRefreshService:
        """Core `AssetRefreshService`."""
        return self._asset_service

    @property
    def search_service(self) -> SearchService:
        """Core `SearchService`."""
        return self._search_service

    @property
    def rulebase_refresh(self) -> RulebaseRefreshService:
        """Rulebase snapshot refresh service (`RulebaseRefreshService`)."""
        return self._rulebase_refresh

    @property
    def rulebase_source(self) -> CachedRulebaseSource:
        """Cached rulebase introspection and numbering source (`CachedRulebaseSource`)."""
        return self._rulebase_source

    @property
    def warmup_tasks(self) -> set[asyncio.Task[Any]]:
        """Currently running background warm-up tasks."""
        return {t for t in self._warmup_tasks if not t.done()}

    # ------------------------------------------------------------------
    # Lifecycle Management
    # ------------------------------------------------------------------

    async def initialize(self, *, run_startup_cleanup: bool = True) -> None:
        """Initialize the database schema and optionally schedule startup session cleanup."""
        if not self._db.is_initialized:
            await self._db.initialize()
        if self._amgmt is not None:
            await self._amgmt.initialize(run_startup_cleanup=run_startup_cleanup)

    async def __aenter__(self) -> ArodonataClient:
        await self.initialize(run_startup_cleanup=True)
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()

    @traced
    async def close(self, *, logout: bool | None = None) -> None:
        """Cancel running background warm-up tasks immediately, drain startup cleanup, close transport, and dispose owned engine."""
        # 1. Cancel any running background warm-up tasks immediately
        active_warmups = [t for t in self._warmup_tasks if not t.done()]
        for task in active_warmups:
            task.cancel()
        if active_warmups:
            await asyncio.gather(*active_warmups, return_exceptions=True)
        self._warmup_tasks.clear()

        # 2. Determine automatic logout policy: True if client auto-created in-memory DB, False if external engine
        should_logout = self._owns_engine if logout is None else bool(logout)

        # 3. Close AMgmtClient / ApiPort (drains startup cleanup tasks & logs out according to policy)
        await self._api.close(logout=should_logout)

        # 4. Dispose SQLAlchemy engine only if owned (`self._db.close()` checks `owns_engine`)
        await self._db.close()

    # ------------------------------------------------------------------
    # Domain Invalidation & Explicit Background Cache Warm-Up
    # ------------------------------------------------------------------

    def _handle_amgmt_domain_invalidated(self, mgmt_name: str, domain: str | None) -> None:
        self._sync_coordinator.invalidate_domain(mgmt_name, domain)

    def invalidate_domain(self, mgmt_name: str, domain: str | None = None) -> None:
        """Invalidate freshness memos for `(mgmt_name, domain)` so the next smart read re-checks published head."""
        self._sync_coordinator.invalidate_domain(mgmt_name, domain)
        if self._amgmt is not None and (mgmt_name, normalize_domain_key(domain)) not in self._amgmt.invalidated_domains:
            self._amgmt._invalidated_domains.add((mgmt_name, normalize_domain_key(domain)))

    def start_object_cache_warmup(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        include_services: bool = False,
        mode: CacheMode = "smart",
    ) -> asyncio.Task[RefreshOutcome]:
        """Explicitly schedule background object (and optional service) cache warm-up."""

        async def _run_warmup() -> RefreshOutcome:
            if not self._db.is_initialized:
                await self._db.initialize()
            obj_outcome = await self.refresh_objects(
                mgmt_name=mgmt_name,
                domains=domains,
                types=types,
                include_global=include_global,
                mode=mode,
            )
            if include_services:
                await self.refresh_services(
                    mgmt_name=mgmt_name,
                    domains=domains,
                    include_global=include_global,
                    mode=mode,
                )
            return obj_outcome

        task = asyncio.create_task(_run_warmup())
        self._warmup_tasks.add(task)
        task.add_done_callback(self._warmup_tasks.discard)
        return task

    # ------------------------------------------------------------------
    # Raw API Transport Delegation (`ApiPort`)
    # ------------------------------------------------------------------

    @traced
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
        """Execute a Check Point Management API command, updating active `WriteSession` overlay and invalidating domain on `publish`."""
        if not self._db.is_initialized:
            await self._db.initialize()

        clean_cmd = command.strip().lstrip("/")
        dom_key = normalize_domain_key(domain)
        active_ws = get_write_session(mgmt_name=mgmt_name, domain_name=dom_key if domain is not None else None)

        eff_sid = sid
        eff_ip = server_ip
        if eff_sid is None and active_ws is not None and self._amgmt is None:
            eff_sid = active_ws.sid
            eff_ip = eff_ip or active_ws.server_ip

        res = await self._api.api_call(
            mgmt_name,
            command,
            payload,
            domain=domain,
            sid=eff_sid,
            server_ip=eff_ip,
            wait_for_task=wait_for_task,
            timeout=timeout,
        )

        # If using a custom ApiPort implementation (not AMgmtClient), ensure overlay & invalidation still run
        if self._amgmt is None:
            if active_ws is not None and (sid is None or sid == active_ws.sid):
                _update_overlay_from_command(active_ws.overlay, clean_cmd, payload, res)
            if clean_cmd == "publish" and res.success:
                eff_domain = domain or (active_ws.domain_name if active_ws is not None else None)
                self.invalidate_domain(mgmt_name, eff_domain)
        elif clean_cmd == "publish" and res.success:
            eff_domain = domain or (active_ws.domain_name if active_ws is not None else None)
            self.invalidate_domain(mgmt_name, eff_domain)

        return res

    @traced
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
        limit: int = DEFAULT_PAGE_LIMIT,
    ) -> ApiQueryResult:
        """Execute a continuity-verified paginated Check Point object listing query."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._api.api_query(
            mgmt_name,
            command,
            domain=domain,
            details_level=details_level,
            payload=payload,
            sid=sid,
            server_ip=server_ip,
            limit=limit,
        )

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        """Open an isolated write session outside `sid_cache`, returning `(sid, server_ip)`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._api.create_dedicated_session(
            mgmt_name,
            domain,
            auth=auth,
            session_name=session_name,
            session_description=session_description,
        )

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> Awaitable[bool]:
        """Log out a specific session identifier."""
        return self._api.logout_sid(mgmt_name, sid, server_ip=server_ip)

    # ------------------------------------------------------------------
    # Context Managers (`auth_context`, `user_context`, `write_session`)
    # ------------------------------------------------------------------

    @contextmanager
    def auth_context(
        self,
        auth: AuthContext | None = None,
        *,
        username: str | None = None,
        password: str | None = None,
        api_key: str | None = None,
        user_id: str | None = None,
    ) -> Iterator[AuthContext]:
        """Bind runtime administrator credentials (`AuthContext`) in `contextvars`."""
        with _ctx_auth_context(
            auth,
            username=username,
            password=password,
            api_key=api_key,
            user_id=user_id,
        ) as resolved:
            yield resolved

    @contextmanager
    def user_context(
        self,
        user: UserContext | None = None,
        *,
        user_id: str | None = None,
        username: str | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
        client_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> Iterator[UserContext]:
        """Bind operator attribution metadata (`UserContext`) in `contextvars`."""
        with _ctx_user_context(
            user,
            user_id=user_id,
            username=username,
            session_name=session_name,
            session_description=session_description,
            client_id=client_id,
            extra=extra,
        ) as resolved:
            yield resolved

    @asynccontextmanager
    async def write_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        user: UserContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
        publish_on_exit: bool = True,
    ) -> AsyncIterator[WriteSession]:
        """Open a context-bound isolated `WriteSession` with `SessionOverlay` read-your-own-writes isolation."""
        if not self._db.is_initialized:
            await self._db.initialize()

        if self._amgmt is not None:
            async with self._amgmt.write_session(
                mgmt_name,
                domain,
                auth=auth,
                user=user,
                session_name=session_name,
                session_description=session_description,
                publish_on_exit=publish_on_exit,
            ) as ws:
                yield ws
            return

        # Fallback for custom ApiPort implementations injected in tests
        dom_key = normalize_domain_key(domain)
        resolved_user = user or get_user_context()
        eff_name = session_name or (resolved_user.session_name if resolved_user else None)
        eff_desc = session_description or (resolved_user.session_description if resolved_user else None)

        sid, server_ip = await self._api.create_dedicated_session(
            mgmt_name,
            domain,
            auth=auth,
            session_name=eff_name,
            session_description=eff_desc,
        )
        ws = WriteSession(
            mgmt_name=mgmt_name,
            domain_name=dom_key,
            sid=sid,
            server_ip=server_ip,
            session_name=eff_name,
            auth=auth,
            user=resolved_user,
            overlay=SessionOverlay(mgmt_name, dom_key),
        )
        try:
            with write_session_context(ws):
                try:
                    yield ws
                except BaseException:
                    if not ws.discarded and not ws.published:
                        with suppress(Exception):
                            await self.api_call(
                                mgmt_name,
                                "discard",
                                {},
                                domain=domain,
                                sid=ws.sid,
                                server_ip=ws.server_ip,
                            )
                        ws.discarded = True
                        ws.overlay.clear()
                    raise

                if publish_on_exit and not ws.published and not ws.discarded:
                    pub_res = await self.api_call(
                        mgmt_name,
                        "publish",
                        {},
                        domain=domain,
                        sid=ws.sid,
                        server_ip=ws.server_ip,
                        wait_for_task=True,
                    )
                    if not pub_res.success:
                        ws.overlay.clear()
                        raise SessionError(
                            f"Failed to publish WriteSession on {mgmt_name!r} ({dom_key!r}): "
                            f"{pub_res.error_message or 'publish failed'}"
                        )
                    ws.published = True
                    ws.overlay.clear()
                    self.invalidate_domain(mgmt_name, domain)
        finally:
            ws.overlay.clear()
            await self.logout_sid(mgmt_name, ws.sid, server_ip=ws.server_ip)

    # ------------------------------------------------------------------
    # Paired Refresh & Streaming Methods
    # ------------------------------------------------------------------

    @traced
    async def refresh_objects(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Synchronize network objects across target domains and return `RefreshOutcome`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._object_service.refresh_objects(
            mgmt_name=mgmt_name,
            domains=domains,
            types=types,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    async def stream_refresh_objects(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while synchronizing network objects."""
        if not self._db.is_initialized:
            await self._db.initialize()
        async for ev in self._object_service.stream_refresh_objects(
            mgmt_name=mgmt_name,
            domains=domains,
            types=types,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield ev

    @traced
    async def refresh_services(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Synchronize service objects across target domains and return `RefreshOutcome`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._service_cache.refresh_services(
            mgmt_name=mgmt_name,
            domains=domains,
            types=types,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    async def stream_refresh_services(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while synchronizing service objects."""
        if not self._db.is_initialized:
            await self._db.initialize()
        async for ev in self._service_cache.stream_refresh_services(
            mgmt_name=mgmt_name,
            domains=domains,
            types=types,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield ev

    @traced
    async def refresh_assets(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Synchronize gateway, cluster, VSX, and server assets across domains and return `RefreshOutcome`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._asset_service.refresh_assets(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    async def stream_refresh_assets(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while synchronizing gateway, cluster, VSX, and server assets."""
        if not self._db.is_initialized:
            await self._db.initialize()
        async for ev in self._asset_service.stream_refresh_assets(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield ev

    @traced
    async def refresh_rulebases(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Synchronize policy rulebase snapshots across target domains and return `RefreshOutcome`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._rulebase_refresh.refresh_rulebases(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    async def stream_refresh_rulebases(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while synchronizing policy rulebase snapshots."""
        if not self._db.is_initialized:
            await self._db.initialize()
        async for ev in self._rulebase_refresh.stream_refresh_rulebases(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield ev

    # ------------------------------------------------------------------
    # Typed Read Facade
    # ------------------------------------------------------------------

    @traced
    async def get_domains(
        self,
        mgmt_name: str | None = None,
        *,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[DomainInfo]:
        """Return discovered domains, excluding `Global` unless `include_global=True`.

        Never triggers implicit background object-cache warm-up.
        """
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._domain_service.get_domains(
            mgmt_name=mgmt_name,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_gateways(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[Asset]:
        """Return cached gateway, cluster, VSX, and server `Asset` models."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._asset_service.get_assets(
            mgmt_name=mgmt_name,
            domain=domain,
            types=types,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_hosts(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject]:
        """Return cached `host` `CPObject` models, merging any active `WriteSession` overlay."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._object_service.get_objects(
            mgmt_name=mgmt_name,
            domain=domain,
            types=["host"],
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_networks(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject]:
        """Return cached `network` `CPObject` models, merging any active `WriteSession` overlay."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._object_service.get_objects(
            mgmt_name=mgmt_name,
            domain=domain,
            types=["network"],
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_address_ranges(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject]:
        """Return cached `address-range` `CPObject` models, merging any active `WriteSession` overlay."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._object_service.get_objects(
            mgmt_name=mgmt_name,
            domain=domain,
            types=["address-range"],
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_dns_domains(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject]:
        """Return cached `dns-domain` `CPObject` models, merging any active `WriteSession` overlay."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._object_service.get_objects(
            mgmt_name=mgmt_name,
            domain=domain,
            types=["dns-domain"],
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_groups(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject]:
        """Return cached `group` `CPObject` models, merging any active `WriteSession` overlay."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._object_service.get_objects(
            mgmt_name=mgmt_name,
            domain=domain,
            types=["group"],
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_objects(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        types: Sequence[str] | None = None,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject]:
        """Return cached network `CPObject` models across `types`, merging any active `WriteSession` overlay."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._object_service.get_objects(
            mgmt_name=mgmt_name,
            domain=domain,
            types=types,
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_services(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        types: Sequence[str] | None = None,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPService]:
        """Return cached `CPService` models, merging any active `WriteSession` overlay."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._service_cache.get_services(
            mgmt_name=mgmt_name,
            domain=domain,
            types=types,
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_object_by_uid(
        self,
        mgmt_name: str,
        domain: str,
        uid: str,
        *,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> CPObject | None:
        """Return a single `CPObject` by `(mgmt_name, domain, uid)`, respecting any active `WriteSession` overlay."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._object_service.get_object_by_uid(
            mgmt_name,
            domain,
            uid,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_access_rules(
        self,
        mgmt_name: str,
        domain: str,
        *,
        layer_uid: str | None = None,
        layer_name: str | None = None,
    ) -> list[AccessRuleEntry]:
        """Return cached access-control rules for `(mgmt_name, domain)`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        snapshot = await self._cache.get_domain_rulebase(mgmt_name, domain)
        rules = snapshot.access_rules
        if layer_uid is not None:
            rules = [r for r in rules if r.layer_uid == layer_uid]
        if layer_name is not None:
            rules = [r for r in rules if r.layer_name == layer_name]
        return rules

    @traced
    async def get_nat_rules(
        self,
        mgmt_name: str,
        domain: str,
        *,
        package_uid: str | None = None,
        package_name: str | None = None,
    ) -> list[NatRuleEntry]:
        """Return cached NAT rules for `(mgmt_name, domain)`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        snapshot = await self._cache.get_domain_rulebase(mgmt_name, domain)
        rules = snapshot.nat_rules
        if package_uid is not None:
            rules = [r for r in rules if r.package_uid == package_uid]
        if package_name is not None:
            rules = [r for r in rules if r.package_name == package_name]
        return rules

    @traced
    async def get_https_rules(
        self,
        mgmt_name: str,
        domain: str,
        *,
        layer_uid: str | None = None,
        layer_name: str | None = None,
    ) -> list[HttpsRuleEntry]:
        """Return cached HTTPS inspection rules for `(mgmt_name, domain)`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        snapshot = await self._cache.get_domain_rulebase(mgmt_name, domain)
        rules = snapshot.https_rules
        if layer_uid is not None:
            rules = [r for r in rules if r.layer_uid == layer_uid]
        if layer_name is not None:
            rules = [r for r in rules if r.layer_name == layer_name]
        return rules

    @traced
    async def get_threat_rules(
        self,
        mgmt_name: str,
        domain: str,
        *,
        layer_uid: str | None = None,
        layer_name: str | None = None,
    ) -> list[ThreatRuleEntry]:
        """Return cached Threat Prevention rules for `(mgmt_name, domain)`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        snapshot = await self._cache.get_domain_rulebase(mgmt_name, domain)
        rules = snapshot.threat_rules
        if layer_uid is not None:
            rules = [r for r in rules if r.layer_uid == layer_uid]
        if layer_name is not None:
            rules = [r for r in rules if r.layer_name == layer_name]
        return rules

    @traced
    async def get_policy_packages(
        self,
        mgmt_name: str,
        domain_name: str | None = None,
        *,
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> list[PolicyPackageInfo]:
        """Return cached `PolicyPackageInfo` entries for `(mgmt_name, domain_name)`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._rulebase_source.get_policy_packages(
            mgmt_name,
            domain_name,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_package_rulebase(
        self,
        mgmt_name: str,
        domain_name: str | None,
        package: str,
        *,
        rulebase_type: RulebaseType = "access",
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> PackageRulebase:
        """Return a SmartConsole-numbered `PackageRulebase` for `package` in `(mgmt_name, domain_name)`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._rulebase_source.get_package_rulebase(
            mgmt_name,
            domain_name,
            package,
            rulebase_type=rulebase_type,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_layer_rulebase(
        self,
        mgmt_name: str,
        domain_name: str | None,
        layer: str,
        *,
        rulebase_type: RulebaseType | None = None,
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> NumberedLayerRulebase:
        """Return a SmartConsole-numbered `NumberedLayerRulebase` for `layer` in `(mgmt_name, domain_name)`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._rulebase_source.get_layer_rulebase(
            mgmt_name,
            domain_name,
            layer,
            rulebase_type=rulebase_type,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def locate_rules(
        self,
        mgmt_name: str,
        domain_name: str | None = None,
        *,
        rule_uids: Sequence[str] | None = None,
        layer_uids: Sequence[str] | None = None,
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> RuleLocations:
        """Locate SmartConsole rule numbers and layer prefixes across all packages and layers of a domain."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._rulebase_source.locate_rules(
            mgmt_name,
            domain_name,
            rule_uids=rule_uids,
            layer_uids=layer_uids,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def filter_rulebase(
        self,
        mgmt_name: str,
        domain_name: str | None = None,
        *,
        package: str | None = None,
        layer: str | None = None,
        rulebase_type: RulebaseType = "access",
        filter_query: str = "",
        output_format: RuleFormat = "model_friendly",
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> FilteredRulebaseResult:
        """Evaluate `filter_query` locally against cached rulebase and cached objects/services."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._rulebase_source.filter_rulebase(
            mgmt_name,
            domain_name,
            package=package,
            layer=layer,
            rulebase_type=rulebase_type,
            filter_query=filter_query,
            output_format=output_format,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def collect_change_report(
        self,
        scopes: Sequence[ReportScope | dict[str, Any]],
        *,
        options: RenderOptions | None = None,
        max_uid_lookups: int = MAX_UID_LOOKUPS,
    ) -> ChangeReport:
        """Collect read-only auditable session change evidence (`ChangeReport`) across `scopes`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await _collect_change_report(
            self._api,
            self._cache,
            scopes,
            options=options,
            max_uid_lookups=max_uid_lookups,
            now_fn=self._now,
        )

    @traced
    def render_change_report(
        self,
        report: ChangeReport,
        *,
        formats: Sequence[str] = ("html", "markdown", "json"),
        options: RenderOptions | None = None,
    ) -> RenderedReportBundle:
        """Render a `ChangeReport` offline into any requested subset of `'html'`, `'json'`, and `'markdown'`."""
        return _render_change_report(
            report,
            formats=formats,
            options=options,
        )

    @traced
    async def build_change_report(
        self,
        scopes: Sequence[ReportScope | dict[str, Any]],
        *,
        formats: Sequence[str] = ("html", "markdown", "json"),
        options: RenderOptions | None = None,
        max_uid_lookups: int = MAX_UID_LOOKUPS,
    ) -> RenderedReportBundle:
        """Collect and render a `ChangeReport` across `scopes` into `formats`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await _build_change_report(
            self._api,
            self._cache,
            scopes,
            formats=formats,
            options=options,
            max_uid_lookups=max_uid_lookups,
            now_fn=self._now,
        )

    # ------------------------------------------------------------------
    # Search, Structured Aggregation, and Domain Helper Methods
    # ------------------------------------------------------------------

    @traced
    async def search_objects(
        self,
        query: str,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        max_depth: int = 2,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> SearchResult:
        """Search cached objects across comma-separated terms and resolve parent groups up to `max_depth`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._search_service.search_objects(
            query,
            mgmt_name=mgmt_name,
            domains=domains,
            types=types,
            include_global=include_global,
            max_depth=max_depth,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def describe_objects(
        self,
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        include_global: bool = True,
    ) -> dict[str, Any]:
        """Return progressive-disclosure schema and summary counts for cached objects and services."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._search_service.describe_objects(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            include_global=include_global,
        )

    @traced
    async def query_objects(
        self,
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        domains: Sequence[str] | None = None,
        types: Sequence[str] | None = None,
        scope_origin: Literal["all", "local", "global"] = "all",
        name_pattern: str | None = None,
        ip_subnet: str | None = None,
        port: str | None = None,
        protocol: str | None = None,
        tags: Sequence[str] | None = None,
        include_global: bool = False,
        group_by: Sequence[str] | None = None,
        aggregate: Literal["count", "list"] = "list",
        limit: int = 100,
        offset: int = 0,
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> dict[str, Any]:
        """Execute structured cross-domain filtering, grouping, and counting over cached objects and services."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._search_service.query_objects(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            domains=domains,
            types=types,
            scope_origin=scope_origin,
            name_pattern=name_pattern,
            ip_subnet=ip_subnet,
            port=port,
            protocol=protocol,
            tags=tags,
            include_global=include_global,
            group_by=group_by,
            aggregate=aggregate,
            limit=limit,
            offset=offset,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_cache_status(
        self,
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        scope: SyncScope | None = None,
    ) -> dict[str, Any]:
        """Inspect `domain_sync_state` across scopes and return per-domain/per-type freshness and `cache_age_seconds`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._search_service.get_cache_status(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            scope=scope,
        )

    @traced
    async def add_object(
        self,
        mgmt_name: str,
        obj_type: str,
        payload: dict[str, Any],
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
    ) -> ApiCallResult:
        """Create a Check Point object (`add-<obj_type>`) using active `WriteSession` context or explicit `sid`."""
        clean_type = obj_type.strip().lower().removeprefix("add-")
        span_attrs(mgmt_name=mgmt_name, domain=domain, object_type=clean_type)
        return await self.api_call(
            mgmt_name,
            f"add-{clean_type}",
            payload,
            domain=domain,
            sid=sid,
            server_ip=server_ip,
        )

    @traced
    async def set_object(
        self,
        mgmt_name: str,
        obj_type: str,
        payload: dict[str, Any],
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
    ) -> ApiCallResult:
        """Update a Check Point object (`set-<obj_type>`) using active `WriteSession` context or explicit `sid`."""
        clean_type = obj_type.strip().lower().removeprefix("set-")
        span_attrs(mgmt_name=mgmt_name, domain=domain, object_type=clean_type)
        return await self.api_call(
            mgmt_name,
            f"set-{clean_type}",
            payload,
            domain=domain,
            sid=sid,
            server_ip=server_ip,
        )

    @traced
    async def delete_object(
        self,
        mgmt_name: str,
        obj_type: str,
        *,
        uid: str | None = None,
        name: str | None = None,
        payload: dict[str, Any] | None = None,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
    ) -> ApiCallResult:
        """Delete a Check Point object (`delete-<obj_type>`) by `uid` or `name`."""
        clean_type = obj_type.strip().lower().removeprefix("delete-")
        req_payload: dict[str, Any] = dict(payload or {})
        if uid is not None:
            req_payload["uid"] = uid
        if name is not None:
            req_payload["name"] = name
        span_attrs(mgmt_name=mgmt_name, domain=domain, object_type=clean_type)
        return await self.api_call(
            mgmt_name,
            f"delete-{clean_type}",
            req_payload,
            domain=domain,
            sid=sid,
            server_ip=server_ip,
        )

    @traced
    async def find_object(
        self,
        mgmt_name: str,
        domain: str,
        name_or_uid: str,
        *,
        obj_type: str | None = None,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> CPObject | CPService | None:
        """Find a single `CPObject` or `CPService` by exact `uid` or `name` in `(mgmt_name, domain)`, including active `WriteSession` overlay."""
        if not self._db.is_initialized:
            await self._db.initialize()

        clean_type = obj_type.strip().lower() if obj_type else None
        is_service_type = clean_type is not None and (
            clean_type in SERVICE_COMMAND_TYPES or clean_type.startswith("service-")
        )

        if not is_service_type:
            by_uid = await self._object_service.get_object_by_uid(
                mgmt_name,
                domain,
                name_or_uid,
                cache_mode=cache_mode,
                cache_ttl=cache_ttl,
            )
            if by_uid is not None and (clean_type is None or by_uid.type == clean_type):
                return by_uid

            objs = await self._object_service.get_objects(
                mgmt_name=mgmt_name,
                domain=domain,
                types=[clean_type] if clean_type else None,
                names=[name_or_uid],
                include_global=(domain == "Global"),
                cache_mode="cache" if cache_mode != "force" else cache_mode,
                cache_ttl=cache_ttl,
            )
            if objs:
                return objs[0]

        if is_service_type or clean_type is None:
            svc_by_uid = await self._service_cache.get_service_by_uid(
                mgmt_name,
                domain,
                name_or_uid,
                cache_mode=cache_mode,
                cache_ttl=cache_ttl,
            )
            if svc_by_uid is not None and (clean_type is None or svc_by_uid.type == clean_type):
                return svc_by_uid

            svcs = await self._service_cache.get_services(
                mgmt_name=mgmt_name,
                domain=domain,
                types=[clean_type] if clean_type else None,
                names=[name_or_uid],
                include_global=(domain == "Global"),
                cache_mode="cache" if cache_mode != "force" else cache_mode,
                cache_ttl=cache_ttl,
            )
            if svcs:
                return svcs[0]

        return None

    @traced
    async def get_group_members(
        self,
        mgmt_name: str,
        domain: str,
        group_name_or_uid: str,
        *,
        recursive: bool = True,
        max_depth: int = 5,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject]:
        """Resolve direct (and optionally recursive) member `CPObject` items for a group in `(mgmt_name, domain)`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._search_service.get_group_members(
            mgmt_name,
            domain,
            group_name_or_uid,
            recursive=recursive,
            max_depth=max_depth,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )


__all__ = [
    "ArodonataClient",
]
