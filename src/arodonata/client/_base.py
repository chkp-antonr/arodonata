"""Composition root base class, service wiring, and properties for `ArodonataClient`."""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine

from arodonata.adapters.checkpoint import AMgmtClient
from arodonata.adapters.checkpoint.rate_limiter import LoginGate, RateLimiter
from arodonata.adapters.checkpoint.task_waiter import TaskWaiter
from arodonata.adapters.checkpoint.tls import TrustPolicy
from arodonata.adapters.checkpoint.transport import ApiTransport, VerifiedConnectionPool
from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.api_reference import ApiReferenceEngine, get_api_reference
from arodonata.client.warmup import CacheWarmupCoordinator, logger
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext, UserContext, WriteSession, normalize_domain_key
from arodonata.core.errors import TrustStoreError
from arodonata.core.models.common import utc_now
from arodonata.core.ports import ApiPort, AuthProvider, CachePort, GatewayCliCallable, GatewayCliPort, LockPort
from arodonata.core.services import (
    AssetRefreshService,
    ClusterRelationshipManager,
    DomainListRefreshTracker,
    DomainService,
    DomainSyncCoordinator,
    ObjectService,
    ScriptRepositoryService,
    SearchService,
    ServiceCacheService,
    TopologyService,
    VSXRelationshipManager,
)
from arodonata.cpcrud import CPCRUDService
from arodonata.rulebase import CachedRulebaseSource, RulebaseRefreshService


class ClientBase:
    """Base composition root wiring adapters, core services, and shared facade properties."""

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
            self._amgmt_invalidation_wired = False
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
                on_domain_invalidated=lambda m, d: self.invalidate_domain(m, d),
                monotonic_fn=monotonic_fn,
                now_fn=now_fn,
                sleep_fn=sleep_fn,
            )
            self._api = self._amgmt
            self._amgmt_invalidation_wired = True

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
        self._script_service = ScriptRepositoryService(
            api=self._api,
            settings=self._settings,
            write_session_factory=self.write_session,
            on_domain_invalidated=self.invalidate_domain,
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
            script_service=self._script_service,
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
            ensure_initialized=self._ensure_initialized,
            now_fn=now_fn,
        )
        self._warmup = CacheWarmupCoordinator(
            settings=self._settings,
            now_fn=now_fn,
            ensure_initialized=self._ensure_initialized,
        )
        self._api_reference: ApiReferenceEngine | None = None

    async def _ensure_initialized(self) -> None:
        if not self._db.is_initialized:
            await self._db.initialize()

    def write_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        user: UserContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
        publish_on_exit: bool = True,
    ) -> AbstractAsyncContextManager[WriteSession]:
        """Open a context-bound isolated `WriteSession` (implemented by `ClientLifecycleMixin`)."""
        raise NotImplementedError("write_session must be provided by ClientLifecycleMixin")

    def invalidate_domain(self, mgmt_name: str, domain: str | None = None) -> None:
        """Invalidate freshness memos for `(mgmt_name, domain)` so the next smart read re-checks published head."""
        self._sync_coordinator.invalidate_domain(mgmt_name, domain)
        if self._amgmt is not None and (mgmt_name, normalize_domain_key(domain)) not in self._amgmt.invalidated_domains:
            self._amgmt._invalidated_domains.add((mgmt_name, normalize_domain_key(domain)))

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

    @property
    def script_service(self) -> ScriptRepositoryService:
        """Core `ScriptRepositoryService`."""
        return self._script_service

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
        return self._warmup.warmup_tasks


def build_validated_trust_policy(
    core_settings: ArodonataSettings,
    *,
    environ: dict[str, str] | None = None,
) -> TrustPolicy:
    """Build and validate a `TrustPolicy` from `ArodonataSettings`, loading and checking its trust store."""
    env = environ if environ is not None else dict(os.environ)
    lab_env = env.get("ARODONATA_LAB")
    trust_policy = TrustPolicy(
        mode=core_settings.tls_trust,
        known_hosts_path=core_settings.tls_known_hosts_path,
        pinned_fingerprints=core_settings.tls_fingerprints,
        lab_env=lab_env,
    )
    entries = trust_policy.trust_store.load()
    if trust_policy.mode == "pinned" and not trust_policy.pinned_fingerprints and not entries:
        raise TrustStoreError(
            "TLS trust mode 'pinned' requires at least one certificate fingerprint in "
            f"ARODONATA_TLS_FINGERPRINTS or {core_settings.tls_known_hosts_path!r}."
        )
    return trust_policy


__all__ = ["ClientBase", "TrustPolicy", "build_validated_trust_policy", "logger"]
