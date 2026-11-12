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

import arlogi
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
from arodonata.api_reference import (
    DEFAULT_API_VERSION,
    ApiReferenceEngine,
    get_api_reference,
    normalize_api_version,
)
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
from arodonata.core.errors import AmbiguousObjectError, SessionError, ValidationError, redact_sid
from arodonata.core.events import CPCRUDEvent, SyncProgressEvent
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import (
    CANONICAL_ASSET_TYPES,
    ApiCallResult,
    ApiQueryResult,
    CacheMode,
    SyncScope,
    normalize_any_type,
    normalize_object_type,
    utc_now,
)
from arodonata.core.models.domains import DomainInfo, RefreshOutcome, WarmupStatusEntry
from arodonata.core.models.objects import CPObject, SearchResult
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    HttpsRuleEntry,
    NatRuleEntry,
    RulebaseType,
    ThreatRuleEntry,
)
from arodonata.core.models.services import CPService
from arodonata.core.models.topology import (
    AffectedGatewayCandidate,
    ExportedTopologyPrefix,
    GatewayTopologyEntry,
    RouteCollectionOutcome,
    TopologyAnnotation,
    TopologyDiagnostic,
    TopologyDiagnosticSeverity,
    TopologyReconciliationReport,
    TopologySourceType,
    TopologyZone,
)
from arodonata.core.ports import ApiPort, AuthProvider, CachePort, GatewayCliCallable, GatewayCliPort, LockPort
from arodonata.core.services import (
    AssetRefreshService,
    ClusterRelationshipManager,
    DomainListRefreshTracker,
    DomainService,
    DomainSyncCoordinator,
    ObjectService,
    SearchService,
    ServiceCacheService,
    TopologyService,
    VSXRelationshipManager,
)
from arodonata.core.telemetry import span_attrs, traced
from arodonata.cpcrud import CPCRUDService
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

logger = arlogi.get_logger(__name__)

_MAX_WARMUP_STATUS_ENTRIES = 128
_WarmupFlightKey = tuple[str, tuple[str, ...], tuple[str, ...], bool, bool, bool]


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
        gateway_cli: GatewayCliPort | GatewayCliCallable | None = None,
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
                engine=eff_engine,
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
            asset_service=self._asset_service,
            now_fn=now_fn,
        )
        self._rulebase_refresh = RulebaseRefreshService(
            settings=self._settings,
            api=self._api,
            cache=self._cache,
            coordinator=self._sync_coordinator,
            now_fn=now_fn,
        )
        self._topology_service = TopologyService(
            settings=self._settings,
            api=self._api,
            cache=self._cache,
            coordinator=self._sync_coordinator,
            asset_service=self._asset_service,
            object_service=self._object_service,
            rulebase_refresh=self._rulebase_refresh,
            gateway_cli=gateway_cli,
            now_fn=now_fn,
        )
        self._rulebase_source = CachedRulebaseSource(
            cache=self._cache,
            refresh_service=self._rulebase_refresh,
            object_service=self._object_service,
            service_cache=self._service_cache,
            now_fn=now_fn,
        )
        self._cpcrud = CPCRUDService(
            settings=self._settings,
            api=self._api,
            cache=self._cache,
            on_domain_invalidated=self.invalidate_domain,
            ensure_initialized=self._ensure_db_initialized,
            now_fn=now_fn,
        )
        self._warmup_tasks: set[asyncio.Task[Any]] = set()
        self._warmup_flights: dict[_WarmupFlightKey, asyncio.Task[RefreshOutcome]] = {}
        self._warmup_status: dict[_WarmupFlightKey, WarmupStatusEntry] = {}
        self._api_reference: ApiReferenceEngine | None = None

    async def _ensure_db_initialized(self) -> None:
        if not self._db.is_initialized:
            await self._db.initialize()

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
    def topology_service(self) -> TopologyService:
        """Core `TopologyService`."""
        return self._topology_service

    def set_gateway_cli(self, gateway_cli: GatewayCliPort | GatewayCliCallable | None) -> None:
        """Register or replace the optional SSH/CLI callback or `GatewayCliPort` adapter."""
        self._topology_service.set_gateway_cli(gateway_cli)

    @property
    def rulebase_refresh(self) -> RulebaseRefreshService:
        """Rulebase snapshot refresh service (`RulebaseRefreshService`)."""
        return self._rulebase_refresh

    @property
    def rulebase_source(self) -> CachedRulebaseSource:
        """Cached rulebase introspection and numbering source (`CachedRulebaseSource`)."""
        return self._rulebase_source

    @property
    def cpcrud(self) -> CPCRUDService:
        """Declarative Check Point Policy-as-Code CRUD engine (`CPCRUDService`)."""
        return self._cpcrud

    @property
    def api_reference(self) -> ApiReferenceEngine:
        """Offline Check Point API Reference & Payload Validation Engine (`ApiReferenceEngine`)."""
        if self._api_reference is None:
            self._api_reference = get_api_reference()
        return self._api_reference

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
        self._warmup_flights.clear()

        # 2. Determine automatic logout policy: True if client auto-created in-memory DB, False if persistent DB or external engine
        is_ephemeral_db = self._owns_engine and ":memory:" in (self._settings.database_url or "")
        should_logout = is_ephemeral_db if logout is None else bool(logout)

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

    def _resolve_warmup_mgmt_key(self, mgmt_name: str | None) -> str:
        clean = (mgmt_name or "").strip()
        if clean:
            return clean
        if self._settings.mgmt_name:
            return self._settings.mgmt_name
        if len(self._settings.mgmt_names) == 1:
            return self._settings.mgmt_names[0]
        return "*"

    def _evict_warmup_status_if_needed(self) -> None:
        while len(self._warmup_status) > _MAX_WARMUP_STATUS_ENTRIES:
            evict_key: _WarmupFlightKey | None = None
            for k, entry in self._warmup_status.items():
                if entry.status != "running":
                    evict_key = k
                    break
            if evict_key is None:
                break
            self._warmup_status.pop(evict_key, None)

    def get_warmup_status(self, mgmt_name: str | None = None) -> list[WarmupStatusEntry]:
        """Return structured status entries for active and recent background warm-up flights."""
        filter_mgmt = mgmt_name.strip() if isinstance(mgmt_name, str) and mgmt_name.strip() else None
        return [
            entry.model_copy(deep=True)
            for entry in self._warmup_status.values()
            if filter_mgmt is None or entry.mgmt_name == filter_mgmt
        ]

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
        """Explicitly schedule single-flight deduplicated background object (and optional service) cache warm-up."""
        eff_mgmt = self._resolve_warmup_mgmt_key(mgmt_name)
        raw_domains: Sequence[str] = [domains] if isinstance(domains, str) else (domains or ())
        norm_domains = tuple(sorted({d.strip() for d in raw_domains if d and d.strip()}))
        norm_types = (
            tuple(sorted({normalize_object_type(str(t)) for t in types if t and str(t).strip()}))
            if types is not None
            else ()
        )
        flight_key: _WarmupFlightKey = (
            eff_mgmt,
            norm_domains,
            norm_types,
            bool(include_global),
            bool(include_services),
            bool(mode == "force"),
        )

        existing = self._warmup_flights.get(flight_key)
        if existing is not None and not existing.done():
            return existing

        status_entry = WarmupStatusEntry(
            mgmt_name=eff_mgmt,
            domains=list(norm_domains),
            types=list(norm_types),
            include_global=bool(include_global),
            include_services=bool(include_services),
            status="running",
            started_at=self._now(),
        )
        self._warmup_status[flight_key] = status_entry
        self._evict_warmup_status_if_needed()

        async def _run_warmup() -> RefreshOutcome:
            try:
                if not self._db.is_initialized:
                    await self._db.initialize()
                obj_outcome = await self.refresh_objects(
                    mgmt_name=mgmt_name,
                    domains=domains,
                    types=types,
                    include_global=include_global,
                    mode=mode,
                )
                merged_refreshed = list(obj_outcome.refreshed_domains)
                merged_skipped = list(obj_outcome.skipped_domains)
                merged_failed = {k: redact_sid(str(v)) for k, v in obj_outcome.failed_domains.items()}
                total_items = obj_outcome.total_items

                if include_services:
                    svc_outcome = await self.refresh_services(
                        mgmt_name=mgmt_name,
                        domains=domains,
                        include_global=include_global,
                        mode=mode,
                    )
                    for d in svc_outcome.refreshed_domains:
                        if d not in merged_refreshed:
                            merged_refreshed.append(d)
                    for d in svc_outcome.skipped_domains:
                        if d not in merged_skipped and d not in merged_refreshed:
                            merged_skipped.append(d)
                    for k, v in svc_outcome.failed_domains.items():
                        merged_failed[k] = redact_sid(str(v))
                    total_items += svc_outcome.total_items

                status_entry.refreshed_domains = merged_refreshed
                status_entry.failed_domains = merged_failed
                status_entry.completed_at = self._now()
                if merged_failed:
                    err_summary = "; ".join(f"{k}: {v}" for k, v in merged_failed.items())
                    status_entry.error = err_summary
                    if not merged_refreshed:
                        status_entry.status = "failed"
                        logger.warning(
                            "background_object_cache_warmup_failed",
                            mgmt_name=eff_mgmt,
                            domains=list(norm_domains),
                            error=err_summary,
                        )
                    else:
                        status_entry.status = "completed"
                else:
                    status_entry.status = "completed"

                return RefreshOutcome(
                    scope="objects",
                    refreshed_domains=merged_refreshed,
                    skipped_domains=merged_skipped,
                    failed_domains=merged_failed,
                    total_items=total_items,
                )
            except asyncio.CancelledError:
                status_entry.status = "cancelled"
                status_entry.completed_at = self._now()
                raise
            except Exception as exc:
                err_msg = redact_sid(str(exc))
                failed_map = {f"{eff_mgmt}:{d}": err_msg for d in norm_domains} if norm_domains else {eff_mgmt: err_msg}
                status_entry.status = "failed"
                status_entry.error = err_msg
                status_entry.failed_domains = dict(failed_map)
                status_entry.completed_at = self._now()
                logger.warning(
                    "background_object_cache_warmup_failed",
                    mgmt_name=eff_mgmt,
                    domains=list(norm_domains),
                    error=err_msg,
                )
                return RefreshOutcome(scope="objects", failed_domains=dict(failed_map))

        task = asyncio.create_task(_run_warmup())
        self._warmup_tasks.add(task)
        self._warmup_flights[flight_key] = task

        def _on_warmup_done(done_task: asyncio.Task[RefreshOutcome]) -> None:
            self._warmup_tasks.discard(done_task)
            if self._warmup_flights.get(flight_key) is done_task:
                self._warmup_flights.pop(flight_key, None)
            if not done_task.cancelled():
                with suppress(BaseException):
                    _ = done_task.exception()

        task.add_done_callback(_on_warmup_done)
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
                        with suppress(BaseException):
                            await asyncio.shield(
                                self.api_call(
                                    mgmt_name,
                                    "discard",
                                    {},
                                    domain=domain,
                                    sid=ws.sid,
                                    server_ip=ws.server_ip,
                                )
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
                        with suppress(BaseException):
                            await asyncio.shield(
                                self.api_call(
                                    mgmt_name,
                                    "discard",
                                    {},
                                    domain=domain,
                                    sid=ws.sid,
                                    server_ip=ws.server_ip,
                                )
                            )
                        ws.discarded = True
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
            with suppress(BaseException):
                await asyncio.shield(self.logout_sid(mgmt_name, ws.sid, server_ip=ws.server_ip))

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

    @traced
    async def refresh_policy_packages(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Synchronize lightweight policy package catalogs (`item_type='packages'`) without downloading rulebases."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._rulebase_refresh.refresh_policy_packages(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    async def stream_refresh_policy_packages(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while synchronizing lightweight policy package catalogs."""
        if not self._db.is_initialized:
            await self._db.initialize()
        async for ev in self._rulebase_refresh.stream_refresh_policy_packages(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield ev

    @traced
    async def refresh_package_rulebase(
        self,
        mgmt_name: str,
        domain_name: str | None,
        package: str,
        *,
        rulebase_type: RulebaseType = "access",
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Synchronize only the layers belonging to `(package, rulebase_type)` without pulling other packages or rulebase types."""
        if not self._db.is_initialized:
            await self._db.initialize()
        resolved_dom = (
            domain_name.strip()
            if domain_name is not None and domain_name.strip()
            else await self._rulebase_source.resolve_domain_for_target(
                mgmt_name,
                domain_name,
                package,
                kind="package",
                rulebase_type=rulebase_type,
                cache_mode=mode,
                cache_ttl=cache_ttl,
            )
        )
        return await self._rulebase_refresh.refresh_package_rulebase(
            mgmt_name,
            resolved_dom,
            package,
            rulebase_type=rulebase_type,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def refresh_topology(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        gateways: Sequence[str] | str | None = None,
        collect_routes: bool = False,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Synchronize gateway interface topology across target domains (or specific `gateways`) and return `RefreshOutcome`."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._topology_service.refresh_topology(
            mgmt_name=mgmt_name,
            domains=domains,
            gateways=gateways,
            collect_routes=collect_routes,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    async def stream_refresh_topology(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        gateways: Sequence[str] | str | None = None,
        collect_routes: bool = False,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while synchronizing gateway interface topology."""
        if not self._db.is_initialized:
            await self._db.initialize()
        async for ev in self._topology_service.stream_refresh_topology(
            mgmt_name=mgmt_name,
            domains=domains,
            gateways=gateways,
            collect_routes=collect_routes,
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
    async def get_gateway_topology(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        gateway: str | None = None,
        topology_zone: TopologyZone | None = None,
        source_types: Sequence[TopologySourceType | str] | None = None,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[GatewayTopologyEntry]:
        """Return cached `GatewayTopologyEntry` rows for policy-enforcing gateways."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._topology_service.get_gateway_topology(
            mgmt_name=mgmt_name,
            domain=domain,
            gateway=gateway,
            topology_zone=topology_zone,
            source_types=source_types,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def find_affected_gateways(
        self,
        sources: Sequence[str] | str,
        destinations: Sequence[str] | str,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        min_confidence: float = 0.0,
        include_standby: bool = True,
        include_policy_inferred: bool = True,
        source_types: Sequence[TopologySourceType | str] | None = None,
        include_annotations: bool = True,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[AffectedGatewayCandidate]:
        """Locate policy-enforcing gateways where `sources` and `destinations` resolve to distinct interfaces or via explicit installed policy rules."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._topology_service.find_affected_gateways(
            sources,
            destinations,
            mgmt_name=mgmt_name,
            domain=domain,
            min_confidence=min_confidence,
            include_standby=include_standby,
            include_policy_inferred=include_policy_inferred,
            source_types=source_types,
            include_annotations=include_annotations,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def collect_gateway_routes(
        self,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        gateways: Sequence[str] | str | None = None,
        gateway_cli: GatewayCliPort | GatewayCliCallable | None = None,
        fallback_to_cprid: bool = True,
        timeout: float = 45.0,
        concurrency: int | None = None,
    ) -> RouteCollectionOutcome:
        """Collect live OS/Clish routing tables from gateways via SSH (`GatewayCliPort`) or `cprid` `run-script` fallback."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._topology_service.collect_gateway_routes(
            mgmt_name=mgmt_name,
            domain=domain,
            domains=domains,
            include_global=include_global,
            gateways=gateways,
            gateway_cli=gateway_cli,
            fallback_to_cprid=fallback_to_cprid,
            timeout=timeout,
            concurrency=concurrency,
        )

    @traced
    async def get_topology_diagnostics(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        gateways: Sequence[str] | str | None = None,
        gateway: str | None = None,
        min_severity: TopologyDiagnosticSeverity = "info",
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[TopologyDiagnostic]:
        """Return static topology health diagnostics (`TopologyDiagnostic`) across policy-enforcing gateways."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._topology_service.get_topology_diagnostics(
            mgmt_name=mgmt_name,
            domain=domain,
            gateways=gateways,
            gateway=gateway,
            min_severity=min_severity,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def reconcile_gateway_topology(
        self,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        gateways: Sequence[str] | str | None = None,
        collect_routes: bool = False,
        collect_live_routes: bool = False,
        check_policy: bool = False,
        gateway_cli: GatewayCliPort | GatewayCliCallable | None = None,
        fallback_to_cprid: bool = True,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> TopologyReconciliationReport:
        """Reconcile SmartConsole static topology against cached/collected live routes, gateway-targeted policy rules, and administrator annotations."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._topology_service.reconcile_gateway_topology(
            mgmt_name=mgmt_name,
            domain=domain,
            gateways=gateways,
            collect_routes=collect_routes,
            collect_live_routes=collect_live_routes,
            check_policy=check_policy,
            gateway_cli=gateway_cli,
            fallback_to_cprid=fallback_to_cprid,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_topology_annotations(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        gateway: str | None = None,
        interface_name: str | None = None,
    ) -> list[TopologyAnnotation]:
        """Return persistent administrator `TopologyAnnotation` records."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._topology_service.get_topology_annotations(
            mgmt_name=mgmt_name,
            domain=domain,
            gateway=gateway,
            interface_name=interface_name,
        )

    @traced
    async def upsert_topology_annotations(
        self,
        annotations: Sequence[TopologyAnnotation | dict[str, Any]] | TopologyAnnotation | dict[str, Any],
    ) -> list[TopologyAnnotation]:
        """Persist one or more administrator `TopologyAnnotation` overrides and IPAM metadata records."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._topology_service.upsert_topology_annotations(annotations)

    @traced
    async def delete_topology_annotations(
        self,
        annotation_ids: Sequence[str] | str | None = None,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        gateway_uid: str | None = None,
    ) -> int:
        """Delete persistent administrator `TopologyAnnotation` rows matching the supplied filters."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._topology_service.delete_topology_annotations(
            annotation_ids=annotation_ids,
            mgmt_name=mgmt_name,
            domain=domain,
            gateway_uid=gateway_uid,
        )

    @traced
    async def export_topology_prefixes(
        self,
        *,
        mgmt_name: str | None = None,
        domain: str | None = None,
        gateways: Sequence[str] | str | None = None,
        gateway: str | None = None,
        include_external: bool = False,
        include_ignored: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[ExportedTopologyPrefix]:
        """Export consolidated `ExportedTopologyPrefix` records for IPAM comparison."""
        if not self._db.is_initialized:
            await self._db.initialize()
        return await self._topology_service.export_topology_prefixes(
            mgmt_name=mgmt_name,
            domain=domain,
            gateways=gateways,
            gateway=gateway,
            include_external=include_external,
            include_ignored=include_ignored,
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

        async def _warm_rulebase(m_name: str, d_name: str) -> Any:
            clean_dom = (d_name or "").strip()
            if not clean_dom or clean_dom == "System Data":
                return None
            return await self.refresh_rulebases(
                mgmt_name=m_name,
                domains=[clean_dom],
                mode="smart",
            )

        return await _collect_change_report(
            self._api,
            self._cache,
            scopes,
            options=options,
            max_uid_lookups=max_uid_lookups,
            now_fn=self._now,
            refresh_rulebase_fn=_warm_rulebase,
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

        async def _warm_rulebase(m_name: str, d_name: str) -> Any:
            clean_dom = (d_name or "").strip()
            if not clean_dom or clean_dom == "System Data":
                return None
            return await self.refresh_rulebases(
                mgmt_name=m_name,
                domains=[clean_dom],
                mode="smart",
            )

        return await _build_change_report(
            self._api,
            self._cache,
            scopes,
            formats=formats,
            options=options,
            max_uid_lookups=max_uid_lookups,
            now_fn=self._now,
            refresh_rulebase_fn=_warm_rulebase,
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
        exact_match: bool = False,
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
            exact_match=exact_match,
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
        aggregate: Literal["count", "list", "describe"] = "list",
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
        """Create a Check Point object (`add-<obj_type>`) using active `WriteSession` context, explicit `sid`, or an automatic isolated `write_session` (`C8`)."""
        clean_type = obj_type.strip().lower().removeprefix("add-")
        span_attrs(mgmt_name=mgmt_name, domain=domain, object_type=clean_type)
        dom_key = normalize_domain_key(domain) if domain is not None else None
        if sid is None and get_write_session(mgmt_name=mgmt_name, domain_name=dom_key) is None:
            async with self.write_session(mgmt_name, domain) as ws:
                return await self.api_call(
                    mgmt_name,
                    f"add-{clean_type}",
                    payload,
                    domain=domain,
                    sid=ws.sid,
                    server_ip=server_ip or ws.server_ip,
                )
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
        """Update a Check Point object (`set-<obj_type>`) using active `WriteSession` context, explicit `sid`, or an automatic isolated `write_session` (`C8`)."""
        clean_type = obj_type.strip().lower().removeprefix("set-")
        span_attrs(mgmt_name=mgmt_name, domain=domain, object_type=clean_type)
        dom_key = normalize_domain_key(domain) if domain is not None else None
        if sid is None and get_write_session(mgmt_name=mgmt_name, domain_name=dom_key) is None:
            async with self.write_session(mgmt_name, domain) as ws:
                return await self.api_call(
                    mgmt_name,
                    f"set-{clean_type}",
                    payload,
                    domain=domain,
                    sid=ws.sid,
                    server_ip=server_ip or ws.server_ip,
                )
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
        """Delete a Check Point object (`delete-<obj_type>`) by `uid` or `name` using active `WriteSession`, explicit `sid`, or automatic isolated `write_session` (`C8`)."""
        clean_type = obj_type.strip().lower().removeprefix("delete-")
        req_payload: dict[str, Any] = dict(payload or {})
        if uid is not None:
            req_payload["uid"] = uid
        if name is not None:
            req_payload["name"] = name
        span_attrs(mgmt_name=mgmt_name, domain=domain, object_type=clean_type)
        dom_key = normalize_domain_key(domain) if domain is not None else None
        if sid is None and get_write_session(mgmt_name=mgmt_name, domain_name=dom_key) is None:
            async with self.write_session(mgmt_name, domain) as ws:
                return await self.api_call(
                    mgmt_name,
                    f"delete-{clean_type}",
                    req_payload,
                    domain=domain,
                    sid=ws.sid,
                    server_ip=server_ip or ws.server_ip,
                )
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
        domain: str | None = None,
        name_or_uid: str = "",
        *,
        obj_type: str | None = None,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> CPObject | CPService | Asset | None:
        """Find a single `CPObject`, `CPService`, or `Asset` by exact `uid` or `name` in `(mgmt_name, domain)` (or across all domains when `domain` is `None`), including active `WriteSession` overlay."""
        clean_query = name_or_uid.strip() if name_or_uid else ""
        if not clean_query:
            raise ValidationError("name_or_uid must not be empty or whitespace")

        if not self._db.is_initialized:
            await self._db.initialize()

        clean_type = normalize_any_type(obj_type) if obj_type else None
        is_service_type = clean_type is not None and (
            clean_type in SERVICE_COMMAND_TYPES or clean_type.startswith("service-")
        )
        is_asset_type = clean_type is not None and clean_type in {t.lower() for t in CANONICAL_ASSET_TYPES}

        eff_domain = domain.strip() if domain and domain.strip() else None
        lookup_key = clean_query
        if eff_domain:
            composite_prefix = f"{mgmt_name}:{eff_domain}:"
            if clean_query.startswith(composite_prefix):
                lookup_key = clean_query.removeprefix(composite_prefix)
        elif clean_query.startswith(f"{mgmt_name}:"):
            parts = clean_query.split(":", 2)
            if len(parts) == 3 and parts[1].strip() and parts[2].strip():
                eff_domain = parts[1].strip()
                lookup_key = parts[2].strip()
        lookup_names = list(dict.fromkeys([clean_query, lookup_key]))

        if eff_domain is not None:
            if not is_service_type and not is_asset_type:
                by_uid = await self._object_service.get_object_by_uid(
                    mgmt_name,
                    eff_domain,
                    lookup_key,
                    cache_mode=cache_mode,
                    cache_ttl=cache_ttl,
                )
                if by_uid is not None and (clean_type is None or by_uid.type.lower() == clean_type):
                    return by_uid

                objs = await self._object_service.get_objects(
                    mgmt_name=mgmt_name,
                    domain=eff_domain,
                    types=[clean_type] if clean_type else None,
                    names=lookup_names,
                    include_global=(eff_domain == "Global"),
                    cache_mode="cache" if cache_mode != "force" else cache_mode,
                    cache_ttl=cache_ttl,
                )
                if objs:
                    return objs[0]

            if is_service_type or clean_type is None:
                svc_by_uid = await self._service_cache.get_service_by_uid(
                    mgmt_name,
                    eff_domain,
                    lookup_key,
                    cache_mode=cache_mode,
                    cache_ttl=cache_ttl,
                )
                if svc_by_uid is not None and (clean_type is None or svc_by_uid.type.lower() == clean_type):
                    return svc_by_uid

                svcs = await self._service_cache.get_services(
                    mgmt_name=mgmt_name,
                    domain=eff_domain,
                    types=[clean_type] if clean_type else None,
                    names=lookup_names,
                    include_global=(eff_domain == "Global"),
                    cache_mode="cache" if cache_mode != "force" else cache_mode,
                    cache_ttl=cache_ttl,
                )
                if svcs:
                    return svcs[0]

            if is_asset_type or clean_type is None:
                assets = await self._asset_service.get_assets(
                    mgmt_name=mgmt_name,
                    domain=eff_domain,
                    types=[clean_type] if clean_type else None,
                    include_global=(eff_domain == "Global"),
                    cache_mode=cache_mode,
                    cache_ttl=cache_ttl,
                )
                needle_lower = clean_query.lower()
                lookup_lower = lookup_key.lower()
                for asset in assets:
                    if (
                        asset.uid in (clean_query, lookup_key)
                        or asset.name in (clean_query, lookup_key)
                        or asset.asset_id == clean_query
                        or asset.id == clean_query
                    ):
                        return asset
                for asset in assets:
                    if (
                        asset.name.lower() in (needle_lower, lookup_lower)
                        or asset.asset_id.lower() == needle_lower
                        or asset.id.lower() == needle_lower
                    ):
                        return asset

            return None

        # Cross-domain lookup (eff_domain is None): refresh single-domain SMC when appropriate (`R2`),
        # query indexed exact UID/name first (`R8`), and deduplicate by UID (`R3`).
        sync_domain, eff_cross_mode = await self._search_service._resolve_implicit_domain_mode(
            mgmt_name,
            None,
            cache_mode,
        )

        async def _refresh_single_domain() -> None:
            if sync_domain is None or eff_cross_mode == "cache":
                return
            if not is_service_type and not is_asset_type:
                await self._object_service.refresh_objects(
                    mgmt_name=mgmt_name,
                    domains=[sync_domain],
                    types=[clean_type] if clean_type else None,
                    include_global=False,
                    mode=eff_cross_mode,
                    cache_ttl=cache_ttl,
                )
            if is_service_type or clean_type is None:
                await self._service_cache.refresh_services(
                    mgmt_name=mgmt_name,
                    domains=[sync_domain],
                    types=[clean_type] if clean_type else None,
                    include_global=False,
                    mode=eff_cross_mode,
                    cache_ttl=cache_ttl,
                )
            if is_asset_type or clean_type is None:
                await self._asset_service.refresh_assets(
                    mgmt_name=mgmt_name,
                    domains=[sync_domain],
                    include_global=False,
                    mode=eff_cross_mode,
                    cache_ttl=cache_ttl,
                )

        if eff_cross_mode == "force":
            await _refresh_single_domain()

        needle_lower = clean_query.lower()
        lookup_lower = lookup_key.lower()

        async def _scan_cross_domain_cache() -> list[CPObject | CPService | Asset]:
            exact_matches: list[CPObject | CPService | Asset] = []

            # Pass 1 (`R8`): Indexed exact UID / exact name queries before full-table fallback
            if not is_service_type and not is_asset_type:
                objs_by_uid = await self._object_service.get_objects(
                    mgmt_name=mgmt_name,
                    domain=None,
                    types=[clean_type] if clean_type else None,
                    uids=lookup_names,
                    include_global=True,
                    cache_mode="cache",
                    cache_ttl=cache_ttl,
                )
                objs_by_name = await self._object_service.get_objects(
                    mgmt_name=mgmt_name,
                    domain=None,
                    types=[clean_type] if clean_type else None,
                    names=lookup_names,
                    include_global=True,
                    cache_mode="cache",
                    cache_ttl=cache_ttl,
                )
                exact_matches.extend(objs_by_uid)
                exact_matches.extend(objs_by_name)

            if is_service_type or clean_type is None:
                svcs_by_uid = await self._service_cache.get_services(
                    mgmt_name=mgmt_name,
                    domain=None,
                    types=[clean_type] if clean_type else None,
                    uids=lookup_names,
                    include_global=True,
                    cache_mode="cache",
                    cache_ttl=cache_ttl,
                )
                svcs_by_name = await self._service_cache.get_services(
                    mgmt_name=mgmt_name,
                    domain=None,
                    types=[clean_type] if clean_type else None,
                    names=lookup_names,
                    include_global=True,
                    cache_mode="cache",
                    cache_ttl=cache_ttl,
                )
                exact_matches.extend(svcs_by_uid)
                exact_matches.extend(svcs_by_name)

            if is_asset_type or clean_type is None:
                assets = await self._asset_service.get_assets(
                    mgmt_name=mgmt_name,
                    domain=None,
                    types=[clean_type] if clean_type else None,
                    include_global=True,
                    cache_mode="cache",
                    cache_ttl=cache_ttl,
                )
                for asset in assets:
                    if (
                        asset.uid in (clean_query, lookup_key)
                        or asset.name in (clean_query, lookup_key)
                        or asset.asset_id == clean_query
                        or asset.id == clean_query
                    ):
                        exact_matches.append(asset)

            if exact_matches:
                return exact_matches

            # Pass 2: Case-insensitive fallback scan only when exact SQL pass found nothing
            ci_matches: list[CPObject | CPService | Asset] = []
            if not is_service_type and not is_asset_type:
                objs = await self._object_service.get_objects(
                    mgmt_name=mgmt_name,
                    domain=None,
                    types=[clean_type] if clean_type else None,
                    names=None,
                    include_global=True,
                    cache_mode="cache",
                    cache_ttl=cache_ttl,
                )
                for o in objs:
                    if (
                        o.uid.lower() in (needle_lower, lookup_lower)
                        or o.name.lower() in (needle_lower, lookup_lower)
                        or o.object_id.lower() == needle_lower
                        or o.id.lower() == needle_lower
                    ):
                        ci_matches.append(o)

            if is_service_type or clean_type is None:
                svcs = await self._service_cache.get_services(
                    mgmt_name=mgmt_name,
                    domain=None,
                    types=[clean_type] if clean_type else None,
                    names=None,
                    include_global=True,
                    cache_mode="cache",
                    cache_ttl=cache_ttl,
                )
                for s in svcs:
                    if (
                        s.uid.lower() in (needle_lower, lookup_lower)
                        or s.name.lower() in (needle_lower, lookup_lower)
                        or s.service_id.lower() == needle_lower
                        or s.id.lower() == needle_lower
                    ):
                        ci_matches.append(s)

            if is_asset_type or clean_type is None:
                assets = await self._asset_service.get_assets(
                    mgmt_name=mgmt_name,
                    domain=None,
                    types=[clean_type] if clean_type else None,
                    include_global=True,
                    cache_mode="cache",
                    cache_ttl=cache_ttl,
                )
                for asset in assets:
                    if (
                        asset.name.lower() in (needle_lower, lookup_lower)
                        or asset.asset_id.lower() == needle_lower
                        or asset.id.lower() == needle_lower
                    ):
                        ci_matches.append(asset)

            return ci_matches

        chosen_pool = await _scan_cross_domain_cache()
        if not chosen_pool and eff_cross_mode in ("smart", "smart-fast") and sync_domain is not None:
            await _refresh_single_domain()
            chosen_pool = await _scan_cross_domain_cache()

        if not chosen_pool:
            return None

        deduped = self._search_service._dedup_entities_by_uid(chosen_pool)
        distinct_domains = {(getattr(item, "original_domain", None) or item.domain_name) for item in deduped}
        if len(distinct_domains) > 1:
            raise AmbiguousObjectError(
                mgmt_name,
                clean_query,
                [item.model_dump(mode="json") for item in deduped],
            )
        return deduped[0]

    @traced
    async def get_group_members(
        self,
        mgmt_name: str,
        domain: str | None = None,
        group_name_or_uid: str = "",
        *,
        recursive: bool = True,
        max_depth: int = 5,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject | CPService | Asset]:
        """Resolve direct (and optionally recursive) member `CPObject`, `CPService`, or child `Asset` items for a group, service-group, cluster, or VSX container in `(mgmt_name, domain)`."""
        if not group_name_or_uid or not group_name_or_uid.strip():
            raise ValidationError("group_name_or_uid must not be empty or whitespace")
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

    @traced
    async def publish_staged_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        session_uid: str,
        sid: str | None = None,
        server_ip: str | None = None,
        timeout: float | None = None,
        auth: AuthContext | None = None,
        force_disconnect: bool = False,
        expected_session_name: str | None = None,
        allow_foreign: bool = False,
    ) -> ApiCallResult:
        """Adopt `session_uid`, publish it, log out, and invalidate the domain cache."""
        return await self._cpcrud.publish_staged_session(
            mgmt_name,
            domain,
            session_uid=session_uid,
            sid=sid,
            server_ip=server_ip,
            timeout=timeout,
            auth=auth,
            force_disconnect=force_disconnect,
            expected_session_name=expected_session_name,
            allow_foreign=allow_foreign,
        )

    async def stream_publish_staged_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        session_uid: str,
        sid: str | None = None,
        server_ip: str | None = None,
        timeout: float | None = None,
        auth: AuthContext | None = None,
        force_disconnect: bool = False,
        expected_session_name: str | None = None,
        allow_foreign: bool = False,
    ) -> AsyncIterator[CPCRUDEvent]:
        """Adopt `session_uid`, publish it while streaming `CPCRUDEvent` items, log out, and invalidate the domain cache."""
        async for ev in self._cpcrud.stream_publish_staged_session(
            mgmt_name,
            domain,
            session_uid=session_uid,
            sid=sid,
            server_ip=server_ip,
            timeout=timeout,
            auth=auth,
            force_disconnect=force_disconnect,
            expected_session_name=expected_session_name,
            allow_foreign=allow_foreign,
        ):
            yield ev

    @traced
    async def discard_staged_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        session_uid: str,
        sid: str | None = None,
        server_ip: str | None = None,
        auth: AuthContext | None = None,
        force_disconnect: bool = False,
        expected_session_name: str | None = None,
        allow_foreign: bool = False,
    ) -> ApiCallResult:
        """Adopt `session_uid`, discard uncommitted changes, and log out."""
        return await self._cpcrud.discard_staged_session(
            mgmt_name,
            domain,
            session_uid=session_uid,
            sid=sid,
            server_ip=server_ip,
            auth=auth,
            force_disconnect=force_disconnect,
            expected_session_name=expected_session_name,
            allow_foreign=allow_foreign,
        )

    # ------------------------------------------------------------------
    # Offline API Reference & Payload Validation (`ApiReferenceEngine`)
    # ------------------------------------------------------------------

    async def ensure_api_reference(self) -> ApiReferenceEngine:
        """Return `self.api_reference`, loading the bundled gzipped index via `asyncio.to_thread` when needed (`R9`)."""
        if self._api_reference is None:
            self._api_reference = await ApiReferenceEngine.async_default()
        return self._api_reference

    def _resolve_api_version(
        self,
        version: str | None = None,
        mgmt_name: str | None = None,
    ) -> str:
        """Resolve canonical Check Point API version (`v1.9`..`v2.2`) from explicit `version` or `mgmt_name` settings."""
        latest = (
            str(self._api_reference.meta.get("latest", DEFAULT_API_VERSION))
            if self._api_reference is not None
            else DEFAULT_API_VERSION
        )
        if version and str(version).strip():
            return normalize_api_version(version, default=latest)
        servers = self._settings.servers
        if mgmt_name and mgmt_name.strip() in servers:
            srv_ver = servers[mgmt_name.strip()].api_version
            if srv_ver:
                return normalize_api_version(srv_ver, default=latest)
        elif not mgmt_name and len(servers) == 1:
            sole_srv = next(iter(servers.values()))
            if sole_srv.api_version:
                return normalize_api_version(sole_srv.api_version, default=latest)
        if self._settings.api_version:
            return normalize_api_version(self._settings.api_version, default=latest)
        return latest

    def search_api_commands(
        self,
        query: str = "",
        *,
        category: str | None = None,
        crud_type: str | None = None,
        api_family: str | None = None,
        version: str | None = None,
        mgmt_name: str | None = None,
        limit: int = 15,
    ) -> list[dict[str, Any]]:
        """Step 1: Search Check Point API commands offline, inferring `version` from `mgmt_name` when omitted."""
        eff_version = self._resolve_api_version(version, mgmt_name=mgmt_name)
        return self.api_reference.search_commands(
            query,
            category=category,
            crud_type=crud_type,
            api_family=api_family,
            version=eff_version,
            limit=limit,
        )

    def describe_api_command(
        self,
        command: str | Sequence[str],
        *,
        version: str | None = None,
        mgmt_name: str | None = None,
        resolve_nested: bool = True,
        include_examples: bool = True,
    ) -> dict[str, Any] | None:
        """Step 2: Describe one or more Check Point API commands offline, inferring `version` from `mgmt_name`."""
        eff_version = self._resolve_api_version(version, mgmt_name=mgmt_name)
        return self.api_reference.describe_command(
            command,
            version=eff_version,
            resolve_nested=resolve_nested,
            include_examples=include_examples,
        )

    def validate_api_payload(
        self,
        command: str,
        payload: dict[str, Any] | None,
        *,
        version: str | None = None,
        mgmt_name: str | None = None,
    ) -> dict[str, Any]:
        """Step 3: Validate a candidate request payload offline against the command's schema for `version` / `mgmt_name`."""
        eff_version = self._resolve_api_version(version, mgmt_name=mgmt_name)
        return self.api_reference.validate_payload(
            command,
            payload,
            version=eff_version,
        )


__all__ = [
    "ArodonataClient",
]
