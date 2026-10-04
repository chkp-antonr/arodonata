"""High-level async client for Check Point  API operations.

Applications create and inject the database engine.
The client manages all other components internally.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator, Awaitable, Callable, Collection, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from arlogi.otel.decorator import set_trace_modules, traced
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncEngine

from ..asdk import AMgmtClient, ApiTransport, LoginCoordinator, RateLimiter, ServerRegistry
from ..cache import CacheRepository, DatabaseManager
from ..config import ArodonataSettings
from ..config.constants import TASK_QUERY_COMMANDS, TASK_QUERY_MAX_PAGE_SIZE, TASK_QUERY_PAGE_SIZE
from ..core.exceptions import MissingConfigurationError
from ..logger import lazy_logger
from ..utils.background_tasks import DEFAULT_CLOSE_GRACE_SECONDS, drain_background_tasks
from .schemas import ApiCallResult, ApiQueryResult, ObjectCacheWarmUp, SSEEvent, SSEEventType

if TYPE_CHECKING:
    from ..cache.models import LastPublishedSession
    from ..cache.object_service import ObjectService
    from ..cpcrud.service import CPCRUDService
    from ..services.search_service import SearchService

if TYPE_CHECKING:
    from ..asdk.server_registry import ServerConfig

if TYPE_CHECKING:
    from ..cache import CPObject
    from ..core.cache_mode import CacheMode
    from ..models.domains import Domain, Gateway, Group, Host, Network
    from ..models.rulebases import AccessRule, HTTPSRule, NATRule, ThreatRule
    from ..reports.changes import ChangeReport, ChangeReportResult, RenderOptions, ReportFormat, Scope
    from ..rulebase.model import PackageLayout, RulebaseType
    from ..rulebase.source import CachedRulebaseSource, LayerRulebase, PackageRulebase, RuleLocations

log = lazy_logger("arodonata.api.client")


class ArodonataClient:
    """High-level async client for Check Point API operations.

    Applications create the database engine and inject it.
    The client creates and manages all other components.

    Example:
        import os
        from sqlalchemy.ext.asyncio import create_async_engine
        from arodonata import ArodonataClient, ArodonataSettings

        settings = ArodonataSettings()
        engine = create_async_engine(os.environ["DATABASE_URL"])

        client = ArodonataClient(engine=engine, settings=settings)
        async with client:
            result = await client.api_call("mgmt1", "show-hosts")
            for name in client.get_mgmt_names():
                print(name)

        # App is responsible for disposing the engine
        await engine.dispose()
    """

    def __init__(
        self,
        engine: AsyncEngine | None = None,
        settings: ArodonataSettings | None = None,
        *,
        username: str | None = None,
        password: str | None = None,
        mgmt_ip: str | None = None,
        cache_mode: str = "smart",
        cache_ttl: int = 300,
        max_incremental_changes: int = 500,
        _db: DatabaseManager | None = None,
        _cache: CacheRepository | None = None,
        _mgmt: AMgmtClient | None = None,
    ) -> None:
        """Initialize Arodonata client with dependency injection.

        Supports two authentication modes:

        1. API Key mode (existing):
            ``ArodonataClient(engine=engine, settings=settings)``

        2. Credential mode (new):
            ``ArodonataClient(username="admin", password="pass", mgmt_ip="1.2.3.4")``

        In credential mode without an explicit engine, an in-memory SQLite
        database is created automatically and owned by the client.

        Args:
            engine: SQLAlchemy AsyncEngine for database operations.
                   Optional in credential mode (auto-creates in-memory SQLite).
            settings: Configuration settings. Auto-built from constructor args
                     if credentials provided and settings is None.
            username: Username for credential-based auth (takes priority over api_key).
            password: Password for credential-based auth.
            mgmt_ip: Management server IP (required when credentials provided).
            cache_mode: Default cache refresh mode for v2 read helpers
                       ("cache", "smart", "smart-fast", "force"). Defaults to "smart".
            cache_ttl: Default cache freshness TTL (seconds) for v2 read helpers.
                      Defaults to 300.
            max_incremental_changes: Cap on show-changes entries an
                       incremental refresh (mode="incremental" or smart-fast
                       reads) will apply before falling back to a full domain
                       reload. Defaults to 500.
            _db: Optional internal DatabaseManager override (for testing).
            _cache: Optional internal CacheRepository override (for testing).
            _mgmt: Optional internal AMgmtClient override (for testing).
        """
        settings = self._resolve_settings(settings, username, password, mgmt_ip)
        self._settings = settings
        # Only apply gating rules when the operator explicitly configured
        # trace_modules. arodonata never owns telemetry policy (it doesn't own
        # the TracerProvider either) — it must not clobber a host
        # application's own gating configuration by resetting the
        # process-global registry to {} on every construction.
        if settings.trace_modules_rules:
            set_trace_modules(settings.trace_modules_rules)
        self._default_cache_mode = cache_mode
        self._default_cache_ttl = cache_ttl
        self._max_incremental_changes = max_incremental_changes

        self._build_asdk_components(engine, settings, _db, _cache, _mgmt)
        self._build_services(settings)

        self._closed = False
        self._background_tasks: set[asyncio.Task[None]] = set()
        self._close_grace_seconds = DEFAULT_CLOSE_GRACE_SECONDS
        # get_domains refreshes only the domain list (show-domains) at most once per TTL, and warms an empty object
        # cache in the background at most once per mgmt server per client.
        from ..core.domain_list_refresh import DomainListRefreshTracker

        self._domain_list_refresh = DomainListRefreshTracker()
        self._object_warm_up_started: set[str] = set()
        self._warm_up_tasks: set[asyncio.Task[None]] = set()
        self._warm_ups: dict[str, ObjectCacheWarmUp] = {}
        self._search_service_instance: SearchService | None = None
        log().trace(f"ArodonataClient initialized (auth_mode={settings.auth_mode})")

    def _resolve_settings(
        self,
        settings: ArodonataSettings | None,
        username: str | None,
        password: str | None,
        mgmt_ip: str | None,
    ) -> ArodonataSettings:
        """Resolve effective settings from constructor args.

        Builds or overrides ``ArodonataSettings`` with credential-mode args when
        ``username``/``password`` are provided, then falls back to a default
        ``ArodonataSettings()`` if none was given or built.

        Raises:
            MissingConfigurationError: If username/password given without mgmt_ip.
        """
        # Build settings from constructor args if credentials provided
        if username and password:
            if not mgmt_ip:
                raise MissingConfigurationError(
                    "mgmt_ip is required when using credential-based authentication (username/password)."
                )
            if settings is None:
                from pydantic import SecretStr

                settings = ArodonataSettings(
                    username=username,
                    password=SecretStr(password),
                    mgmt_ip=mgmt_ip,
                )
            else:
                # Override settings with constructor credential args
                from pydantic import SecretStr

                settings = settings.model_copy(
                    update={
                        "username": username,
                        "password": SecretStr(password),
                        "mgmt_ip": mgmt_ip,
                    }
                )

        if settings is None:
            settings = ArodonataSettings()

        return settings

    def _build_asdk_components(
        self,
        engine: AsyncEngine | None,
        settings: ArodonataSettings,
        _db: DatabaseManager | None,
        _cache: CacheRepository | None,
        _mgmt: AMgmtClient | None,
    ) -> None:
        """Build (or accept injected) database, cache, and ASDK components.

        Sets ``self._owns_engine`` (True only when this method auto-creates
        the engine), ``self._db``, ``self._cache``, ``self._login_coordinator``,
        and ``self._mgmt``, and registers the global database lock manager.

        Raises:
            MissingConfigurationError: If no engine is given in API-key mode.
        """
        self._owns_engine = False

        # Auto-create in-memory SQLite engine for credential mode
        if engine is None and settings.auth_mode == "credential":
            from sqlalchemy.ext.asyncio import create_async_engine

            engine = create_async_engine("sqlite+aiosqlite:///:memory:")
            self._owns_engine = True
            log().debug("Auto-created in-memory SQLite engine for credential mode")
        elif engine is None:
            raise MissingConfigurationError(
                "engine is required for API key mode. Provide an AsyncEngine or use credential-based authentication."
            )

        # Create database manager
        self._db = _db or DatabaseManager(engine)

        # Create cache repository
        self._cache = _cache or CacheRepository(self._db)

        self._login_coordinator = None  # set below when building ASDK components
        if _mgmt:
            self._mgmt = _mgmt
        else:
            # Create ASDK components
            from ..asdk.tls import TrustPolicy

            transport = ApiTransport(
                tls_policy=TrustPolicy.from_settings(settings),
                connect_timeout=settings.connect_timeout,
                default_read_timeout=settings.default_read_timeout,
            )
            rate_limiter = RateLimiter(settings.concurrent_limit, slot_timeout=settings.rate_limit_slot_timeout)
            server_registry = ServerRegistry(settings)

            from ..asdk.session_cleaner import SessionCleaner

            session_cleaner = SessionCleaner(
                transport=transport,
                rate_limiter=rate_limiter,
                registry=server_registry,
            )

            login_coordinator = LoginCoordinator(
                registry=server_registry,
                transport=transport,
                rate_limiter=rate_limiter,
                cache=self._cache,
                settings=settings,
                session_cleaner=session_cleaner,
            )

            self._login_coordinator = login_coordinator
            self._mgmt = AMgmtClient(
                registry=server_registry,
                transport=transport,
                rate_limiter=rate_limiter,
                login_coordinator=login_coordinator,
            )

        # Set up global lock manager
        from ..cache import DatabaseLockManager, set_global_lock_manager

        lock_manager = DatabaseLockManager(db_manager=self._db)
        set_global_lock_manager(lock_manager)

    def _build_services(self, settings: ArodonataSettings) -> None:
        """Build the high-level services and V2 orchestration components.

        Requires ``_build_asdk_components`` to have already run: reads
        ``self._mgmt`` and ``self._cache``, which it sets.

        Sets ``self._domain_service``, ``self._asset_refresh``,
        ``self._rulebase_refresh``, ``self._cache_adapter``,
        ``self._api_adapter``, ``self._session_tracker``,
        ``self._refresh_coordinator``, ``self._rulebase_coordinator``, and
        ``self._orchestration``.
        Relationship managers and the asset-refresh service are constructed
        with ``client=self`` directly, since ``self`` already exists by the
        time this runs (called from the tail of ``__init__``). The refresh
        coordinator similarly reads ``self._object_service``, which is safe
        here since it only needs ``self._db`` (already set by
        ``_build_asdk_components``) and ``self``.
        """
        # Create high-level services
        from .cluster_relationship_manager import ClusterRelationshipManager
        from .services.asset_refresh_service import AssetRefreshService
        from .services.domain_service import DomainService
        from .vsx_relationship_manager import VSXRelationshipManager

        # Domain service for domain discovery
        self._domain_service = DomainService(
            mgmt_client=self._mgmt,
            cache=self._cache,
            api_client=self,
        )

        # Create relationship managers
        _cluster_manager = ClusterRelationshipManager(client=self)
        _vsx_manager = VSXRelationshipManager(client=self)

        # Asset refresh service
        self._asset_refresh = AssetRefreshService(
            mgmt_client=self._mgmt,
            cache=self._cache,
            domain_service=self._domain_service,
            cluster_manager=_cluster_manager,
            vsx_manager=_vsx_manager,
            settings=settings,
            api_query_method=self.api_query,
        )

        # V2: Create orchestration service with adapters
        from ..adapters.api import ASDKApiAdapter
        from ..adapters.cache import PostgresCacheAdapter
        from ..core.cache_mode import CacheMode
        from ..core.cache_refresh_coordinator import CacheRefreshCoordinator
        from ..core.orchestration import CacheOrchestrationService
        from ..core.session_tracker import SessionChangeTracker

        self._cache_adapter = PostgresCacheAdapter(self._cache)
        self._api_adapter = ASDKApiAdapter(self._mgmt)
        self._session_tracker = SessionChangeTracker()

        # self._object_service is safe to build here: it needs self._db (set by
        # _build_asdk_components, which already ran) and self (the client),
        # which exists as an object by the tail of __init__ even though
        # __init__ hasn't returned yet.
        self._refresh_coordinator = CacheRefreshCoordinator(
            cache=self._cache_adapter,
            api=self._api_adapter,
            object_service=self._object_service,
            session_tracker=self._session_tracker,
            default_mode=CacheMode(self._default_cache_mode),
            default_ttl=self._default_cache_ttl,
            max_incremental_changes=self._max_incremental_changes,
            # Domains refresh concurrently, at most concurrent_limit - 1 per MDS member per ensure call;
            # overlapping calls each get that budget, so the member-keyed RateLimiter is the real bound.
            member_of=self._login_coordinator.mds_host if self._login_coordinator is not None else None,
            domain_concurrency=max(1, self._settings.concurrent_limit - 1),
        )

        # Rulebase refresh service and its coordinator (after the object service/adapters they depend on)
        from ..core.rulebase_refresh_coordinator import RulebaseRefreshCoordinator
        from .services.rulebase_refresh_service import RulebaseRefreshService

        self._rulebase_refresh = RulebaseRefreshService(
            client=self, cache=self._cache, object_service=self._object_service
        )
        self._rulebase_coordinator = RulebaseRefreshCoordinator(
            refresh_service=self._rulebase_refresh,
            api=self._api_adapter,
            default_mode=CacheMode(self._default_cache_mode),
            default_ttl=self._default_cache_ttl,
        )
        self._orchestration = CacheOrchestrationService(
            cache=self._cache_adapter,
            api=self._api_adapter,
            session_tracker=self._session_tracker,
            coordinator=self._refresh_coordinator,
            rulebase_coordinator=self._rulebase_coordinator,
        )

    def schedule_startup_cleanup(self) -> None:
        """Fire session cleanup for all servers as a background asyncio task.

        Call once after the event loop is running and the database is initialized.
        Safe to call multiple times — each call fires an independent background task.
        No-op when no login coordinator is configured (e.g. injected _mgmt path).
        """
        if self._login_coordinator is not None:
            task = asyncio.create_task(self._login_coordinator.run_startup_cleanup())
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)

    async def __aenter__(self) -> ArodonataClient:
        """Async context manager entry - initialize database tables."""
        await self._db.initialize()
        self.schedule_startup_cleanup()
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: Any) -> None:
        """Async context manager exit with cleanup."""
        await self.close()

    async def close(self) -> None:
        """Close client and release resources.

        If the client owns the engine (auto-created for credential mode),
        it will be disposed here. App-provided engines are NOT closed.
        """
        if not self._closed:
            self._closed = True
            # An object-cache warm-up can run for hours: cancel it at once (each domain's objects are replaced
            # atomically, so a cancelled warm-up leaves whole domains) instead of letting it fail domain by domain on
            # the closed client during the grace period.
            for task in self._warm_up_tasks:
                task.cancel()
            # Let other background work (startup cleanup) finish rather than cancel it mid-query.
            await drain_background_tasks(set(self._background_tasks), self._close_grace_seconds)
            await self._mgmt.close()
            if self._owns_engine and self._db.engine:
                await self._db.engine.dispose()
                log().debug("Disposed auto-created engine")
            log().debug("ArodonataClient closed")

    @traced
    async def logout(self, mgmt_name: str, domain: str = "") -> bool:
        """Explicitly logout of a session.

        Args:
            mgmt_name: Management server name.
            domain: Domain name (empty string for system domain).

        Returns:
            True if logout was successful, False otherwise.
        """
        self._ensure_open()
        return await self._mgmt.logout(mgmt_name, domain)

    def _ensure_open(self) -> None:
        """Ensure client has not been closed."""
        if self._closed:
            raise RuntimeError("Client has been closed and cannot be used")

    @property
    def settings(self) -> ArodonataSettings:
        """Get configuration settings."""
        return self._settings

    @property
    def cache(self) -> CacheRepository:
        """Get cache repository for direct access."""
        self._ensure_open()
        return self._cache

    @property
    def _object_service(self) -> ObjectService:
        """Lazy initialization of ObjectService to avoid circular dependency.

        ObjectService needs ArodonataClient, but ArodonataClient creates ObjectService.
        Using property ensures both are fully initialized before use.
        """
        if not hasattr(self, "_object_service_instance"):
            from ..cache.object_service import ObjectService

            max_inc = getattr(self, "_max_incremental_changes", 500)
            self._object_service_instance = ObjectService(self._db, self, max_incremental_changes=max_inc)
        return self._object_service_instance

    @property
    def _search_service(self) -> SearchService:
        """Lazy SearchService initialization."""
        from ..services.search_service import SearchService

        if not getattr(self, "_object_service", None):
            from ..core.exceptions import ClientError

            raise ClientError("Object service not initialized")

        instance = getattr(self, "_search_service_instance", None)
        if instance is None:
            instance = SearchService(
                object_service=self._object_service,
                refresh_objects_fn=self.refresh_objects,
            )
            self._search_service_instance = instance
        elif instance._object_service is not self._object_service:
            instance._object_service = self._object_service
        return instance

    @property
    def cpcrud(self) -> CPCRUDService:
        """Lazy CPCRUD (idempotent object CRUD) service."""
        if not hasattr(self, "_cpcrud_instance"):
            from ..cpcrud.service import CPCRUDService

            self._cpcrud_instance = CPCRUDService(self)
        return self._cpcrud_instance

    def get_mgmt_names(self) -> list[str]:
        """Get list of all configured management server names.

        Returns:
            List of server name strings.
        """
        self._ensure_open()
        return self._mgmt.get_mgmt_names()

    async def get_server(self, name: str) -> ServerConfig | None:
        """Get server configuration by name.

        Args:
            name: Server name to lookup.

        Returns:
            Server configuration or None if not found.
        """
        self._ensure_open()
        return await self._mgmt.get_server(name)

    @traced
    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        domain: str = "",
        details_level: Literal["uid", "standard", "full"] | None = None,
        payload: dict[str, Any] | None = None,
        wait_for_task: bool = True,
        timeout: int = -1,
        cache_mode: str = "auto",
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> ApiCallResult:
        """Execute API call with automatic session management.

        Args:
            mgmt_name: Management server name.
            command: API command to execute.
            domain: Domain name (empty for system domain).
            details_level: Detail level for response.
            payload: Additional command parameters.
            wait_for_task: Wait for task completion.
            timeout: Request timeout in seconds (-1 for default).
            cache_mode: Cache behavior ("auto", "refresh", "off").
            session_name: Optional name applied when this call has to create a
                fresh session (cache miss/relogin). Ignored on a cache hit that
                reuses an already-open session. Sessions named/described with a
                recognized test marker (see session_cleaner.TEST_SESSION_MARKERS)
                get a much shorter discard grace period.
            session_description: Optional description, same caveat as session_name.

        Returns:
            Validated API call result.
        """
        self._ensure_open()

        response = await self._mgmt.api_call(
            mgmt_name=mgmt_name,
            command=command,
            domain=domain,
            details_level=details_level,
            payload=payload,
            wait_for_task=wait_for_task,
            timeout=timeout if timeout > 0 else self._settings.api_timeout,
            # A caller that named its own timeout means it as the total budget;
            # only the default path gets the separate, larger task allowance.
            task_timeout=-1 if timeout > 0 else self._settings.task_timeout,
            cache_mode=cache_mode,
            session_name=session_name,
            session_description=session_description,
        )

        # Extract data, handling cases where API returns error messages as strings
        raw_data = response.get("data")
        data: dict[str, Any] | None = None
        if isinstance(raw_data, dict):
            data = raw_data
        elif raw_data is not None:
            # data is not a dict (could be string error message, list, etc.)
            # Log it and treat as an error
            log().warning(
                f"API returned non-dict data type for {command}: {type(raw_data)}. Value: {str(raw_data)[:200]}"
            )
            # Override success to False if data is invalid
            response["success"] = False
            # Put the error data in the message field if it's a string
            if isinstance(raw_data, str):
                response["message"] = raw_data

        result = ApiCallResult(
            success=response.get("success", False),
            data=data,
            message=response.get("message", ""),
            code=response.get("code", ""),
        )
        if command == "publish" and result.success:
            # A publish on the shared session moves the domain's head: without this, a TTL memo would let smart reads
            # serve the pre-publish cache for up to cache_ttl (covers the MCP api_call tool and library callers).
            self.invalidate_domain(mgmt_name, domain)
        return result

    @traced
    async def api_call_with_sid(
        self,
        mgmt_name: str,
        sid: str,
        server_ip: str,
        command: str,
        payload: dict[str, Any] | None = None,
        wait_for_task: bool = True,
        timeout: int = -1,
        *,
        domain: str | None = None,
    ) -> ApiCallResult:
        """Execute API call with an explicit SID (no auto-session management).

        Used by write workflows (e.g. CPCRUD) that manage their own sessions
        and need to ensure a specific SID is used for publish/discard.

        Args:
            mgmt_name: Management server name.
            sid: Session ID to use.
            server_ip: Server IP address for the session.
            command: API command to execute.
            payload: Additional command parameters.
            wait_for_task: Wait for task completion.
            timeout: Request timeout in seconds (-1 for default).
            domain: The session's domain, if known: selects the RateLimiter slot of its hosting MDS member
                (LoginCoordinator.mds_host). Without it the member is looked up by server_ip
                (LoginCoordinator.mds_host_for_ip).

        Returns:
            Validated API call result.
        """
        self._ensure_open()

        response = await self._mgmt.api_call_with_sid(
            mgmt_name=mgmt_name,
            sid=sid,
            server_ip=server_ip,
            command=command,
            payload=payload,
            wait_for_task=wait_for_task,
            timeout=timeout if timeout > 0 else self._settings.api_timeout,
            # A caller that named its own timeout means it as the total budget;
            # only the default path gets the separate, larger task allowance.
            task_timeout=-1 if timeout > 0 else self._settings.task_timeout,
            domain=domain,
        )

        raw_data = response.get("data")
        if raw_data is not None and not isinstance(raw_data, dict):
            # Same guard as api_call (a list or text body is a failure, not a ValidationError), plus a code.
            log().warning(f"API returned non-dict data type for {command} (explicit SID): {type(raw_data).__name__}")
            return ApiCallResult(
                success=False,
                data=None,
                message=raw_data if isinstance(raw_data, str) else response.get("message", ""),
                code="invalid_response",
            )
        return ApiCallResult(
            success=response.get("success", False),
            data=raw_data,
            message=response.get("message", ""),
            code=response.get("code", ""),
        )

    @traced
    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str = "",
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        """Create a dedicated session bypassing the global SID cache.

        Used by write workflows (e.g. CPCRUD) that need session isolation
        from the shared pool. The returned SID is NOT stored in the cache.
        Use api_call_with_sid() to make calls, and logout_sid() when done.

        Args:
            mgmt_name: Management server name.
            domain: Domain name (empty string for system domain).
            session_name: Optional session name visible in SmartConsole.
            session_description: Optional session description.

        Returns:
            Tuple of (SID, Server IP).
        """
        self._ensure_open()
        return await self._mgmt.create_dedicated_session(
            mgmt_name,
            domain,
            session_name=session_name,
            session_description=session_description,
        )

    @traced
    async def logout_sid(
        self,
        sid: str,
        server_ip: str,
        mgmt_name: str = "",
    ) -> bool:
        """Logout a specific SID (e.g. a dedicated session).

        Args:
            sid: Session ID to logout.
            server_ip: Server IP of the session.
            mgmt_name: Optional management server name (for port lookup).

        Returns:
            True if logout was successful.
        """
        self._ensure_open()
        return await self._mgmt.logout_sid(sid, server_ip, mgmt_name)

    @traced
    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        domain: str = "",
        details_level: Literal["uid", "standard", "full"] = "standard",
        payload: dict[str, Any] | None = None,
        container_key: str = "objects",
        cache_mode: str = "auto",
    ) -> ApiQueryResult:
        """Execute paginated API query with automatic session management.

        Args:
            mgmt_name: Management server name.
            command: API query command.
            domain: Domain name.
            details_level: Detail level for response.
            payload: Additional query parameters.
            container_key: Key containing objects in response.

        Returns:
            Validated API query result.
        """
        self._ensure_open()
        if command in TASK_QUERY_COMMANDS:
            return await self._task_query(
                mgmt_name, command, domain, details_level, payload, TASK_QUERY_COMMANDS[command], cache_mode
            )
        response = await self._mgmt.api_query(
            mgmt_name=mgmt_name,
            command=command,
            domain=domain,
            details_level=details_level,
            payload=payload,
            container_key=container_key,
            cache_mode=cache_mode,
        )

        data = response.get("data", [])
        objects: Any = []
        if isinstance(data, dict):
            # Try provided container_key first
            objects = data.get(container_key, [])

            # If empty and using default 'objects', try to guess
            if not objects and container_key == "objects":
                guesses = {
                    "show-access-layers": "access-layers",
                    "show-nat-layers": "nat-layers",
                    "show-https-layers": "https-layers",
                    "show-threat-layers": "threat-layers",
                }
                if command in guesses:
                    guess_key = guesses[command]
                    objects = data.get(guess_key, [])

                # Ultimate fallback: find any list
                if not objects:
                    for key, val in data.items():
                        if isinstance(val, list) and key not in ("meta-info", "from", "to", "total"):
                            objects = val
                            break
        elif isinstance(data, list):
            objects = data

        try:
            return ApiQueryResult(
                success=response.get("success", False),
                data=data,
                objects=objects if isinstance(objects, list) else [],
                message=response.get("message", ""),
                code=response.get("code", ""),
                total=len(objects) if isinstance(objects, list) else 0,
            )
        except ValidationError:
            print(f"\n[Validation Failed] Full API response for '{command}':")
            print(json.dumps(response, indent=4, default=str))
            raise

    async def _task_query(
        self,
        mgmt_name: str,
        command: str,
        domain: str,
        details_level: Literal["uid", "standard", "full"],
        payload: dict[str, Any] | None,
        item_key: str,
        cache_mode: str,
    ) -> ApiQueryResult:
        """Page a task-based query command (see TASK_QUERY_COMMANDS) to the end.

        Each page goes through `api_call`, so arodonata's TaskWaiter awaits the
        task under the configured budgets. The caller's `limit` is the page size
        and `offset` the starting point, as with cpapi's api_query. A failed page
        fails the whole query -- never a silently partial result.
        """
        base = dict(payload or {})
        page_size = min(int(base.pop("limit", TASK_QUERY_PAGE_SIZE)), TASK_QUERY_MAX_PAGE_SIZE)
        offset = int(base.pop("offset", 0))
        items: list[dict[str, Any]] = []
        while True:
            response = await self._mgmt.api_call(
                mgmt_name=mgmt_name,
                command=command,
                domain=domain,
                details_level=details_level,
                payload={**base, "limit": page_size, "offset": offset},
                cache_mode=cache_mode,
            )
            if not response.get("success", False):
                data = response.get("data")
                return ApiQueryResult(
                    success=False,
                    data=data if isinstance(data, dict) else None,
                    message=f"{command} page at offset {offset}: {response.get('message', '')}",
                    code=response.get("code", ""),
                )
            page, to, total = _task_page(response.get("data"), item_key)
            items.extend(page)
            if not page or to >= total:
                break
            if to <= offset:
                return ApiQueryResult(
                    success=False,
                    message=f"{command} paging did not advance at offset {offset} (to={to}, total={total})",
                )
            offset = to
        return ApiQueryResult(
            success=True, data={item_key: items, "total": len(items)}, objects=items, total=len(items)
        )

    @traced
    async def collect_gateways_and_servers(
        self,
        mgmt_names: list[str] | None = None,
        domains: list[str] | None = None,
    ) -> AsyncGenerator[SSEEvent]:
        """Collect gateway/server assets with streaming progress.

        Args:
            mgmt_names: List of server names (None = all).
            domains: List of domains to scope the query to (None = system domain).

        Yields:
            SSEEvent objects for progress, results, and completion.
        """
        self._ensure_open()

        target_names = mgmt_names or self.get_mgmt_names()
        target_domains = domains or [""]
        total_servers = len(target_names)
        processed = 0

        for mgmt_name in target_names:
            for domain_name in target_domains:
                try:
                    # Progress event
                    yield SSEEvent(
                        event_type=SSEEventType.LOG,
                        mgmt_name=mgmt_name,
                        domain=domain_name,
                        data={
                            "message": f"Processing {mgmt_name}",
                            "percent": int((processed / total_servers) * 100),
                        },
                    )

                    # Query gateways
                    result = await self.api_query(
                        mgmt_name=mgmt_name,
                        command="show-gateways-and-servers",
                        domain=domain_name,
                        details_level="full",
                    )

                    if result.success and result.objects:
                        yield SSEEvent(
                            event_type=SSEEventType.RESULT,
                            mgmt_name=mgmt_name,
                            domain=domain_name,
                            data={
                                "result_type": "gateways",
                                "count": len(result.objects),
                                "objects": result.objects,
                            },
                        )
                    elif not result.success:
                        yield SSEEvent(
                            event_type=SSEEventType.ERROR,
                            mgmt_name=mgmt_name,
                            domain=domain_name,
                            data={
                                "error_message": result.message,
                                "error_code": result.code,
                            },
                        )

                except Exception as e:
                    yield SSEEvent(
                        event_type=SSEEventType.ERROR,
                        mgmt_name=mgmt_name,
                        domain=domain_name,
                        data={"error_message": str(e)},
                    )

            processed += 1

        # Complete event
        yield SSEEvent(
            event_type=SSEEventType.COMPLETE,
            data={
                "total_servers": total_servers,
                "processed": processed,
            },
        )

    @traced
    async def clear_cache(self) -> None:
        """Clear all cached sessions."""
        self._ensure_open()
        await self._cache.clear_sessions()
        log().info("Cache cleared")

    # ========== High-Level Business Functions ==========

    @traced
    async def build_refresh_assets_cache(
        self,
        mgmt_names: str | list[str] = "",
        domains: str | list[str] = "",
        cache_mode: str = "auto",
    ) -> AsyncGenerator[SSEEvent]:
        """Build and refresh the assets cache with comprehensive asset collection.

        This method delegates to the AssetRefreshService for the actual implementation.

        Args:
            mgmt_names: Server names as comma-separated string or list (empty = all).
            domains: Domains as comma-separated string or list (empty = all).

        Yields:
            SSEEvent objects for progress, results, errors, and completion.

        Example:
            ```python
            async with await factory.create_client() as client:
                async for event in client.build_refresh_assets_cache(
                    mgmt_names="mgmt1,mgmt2", domains="domain1,domain2"
                ):
                    if event.event_type == SSEEventType.LOG:
                        print(f"Progress: {event.data.get('message')}")
                    elif event.event_type == SSEEventType.COMPLETE:
                        print(f"Complete: {event.data}")
            ```
        """
        self._ensure_open()

        if self._asset_refresh is None:
            raise RuntimeError(
                "AssetRefreshService not initialized. Use ArodonataClientFactory to create properly configured client."
            )

        async for event in self._asset_refresh.build_refresh_assets_cache(
            mgmt_names=mgmt_names,
            domains=domains,
            cache_mode=cache_mode,
            client_wrapper=self,
        ):
            yield event

    @traced
    async def refresh_domain_assets(
        self,
        mgmt_name: str,
        domain_name: str,
        cache_mode: str = "auto",
    ) -> AsyncGenerator[SSEEvent]:
        """Refresh cached assets for a single domain.

        This method delegates to AssetRefreshService.refresh_domain_assets —
        a narrower alternative to build_refresh_assets_cache for callers that
        only need one domain refreshed without a full multi-domain rebuild.

        Args:
            mgmt_name: Management server name.
            domain_name: Domain name.
            cache_mode: Cache mode passed through to the underlying API query.

        Yields:
            SSEEvent objects for progress, results, and errors.
        """
        self._ensure_open()

        if self._asset_refresh is None:
            raise RuntimeError(
                "AssetRefreshService not initialized. Use ArodonataClientFactory to create properly configured client."
            )

        async for event in self._asset_refresh.refresh_domain_assets(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            cache_mode=cache_mode,
        ):
            yield event

    @traced
    async def refresh_last_published_session(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> LastPublishedSession | None:
        """Refresh the last-published-session record for a single domain.

        Makes one lightweight API call and upserts LastPublishedSession —
        does not touch the object or asset caches.

        Args:
            mgmt_name: Management server name.
            domain_name: Domain name.

        Returns:
            The upserted LastPublishedSession record, or None on failure.
        """
        self._ensure_open()

        return await self._object_service.refresh_last_published_session(mgmt_name, domain_name)

    @traced
    async def search_objects(
        self,
        search_input: str,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        refresh: Literal["skip", "check", "force", "incremental"] = "skip",
        max_depth: int = 2,
    ) -> AsyncGenerator[SSEEvent]:
        """Search for Check Point objects with cache-first queries.

        Args:
            search_input: Comma-separated search terms.
            mgmt_names: Optional management server filter.
            domain_names: Optional domain filter.
            refresh: Refresh mode - "skip", "check", "force", or "incremental".
            max_depth: Maximum depth for group membership traversal.

        Yields:
            SSEEvent with refresh progress and domain-grouped search results.
        """
        self._ensure_open()
        search_service = self._search_service
        async for event in search_service.search_objects(
            search_input=search_input,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            refresh=refresh,
            max_depth=max_depth,
        ):
            yield event

    @traced
    async def refresh_objects(
        self,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        mode: Literal["skip", "check", "force", "incremental"] = "force",
        include_global: bool = False,
    ) -> AsyncGenerator[SSEEvent]:
        """Refresh object cache from API.

        Args:
            mgmt_names: Optional management server filter.
            domain_names: Optional domain filter.
            mode: Refresh mode - "skip", "check", "force", or "incremental".
            include_global: When False (default), the "Global" domain
                is excluded from the all-domains refresh path so existing
                callers see today's behavior.

        Yields:
            SSEEvent with progress updates.
        """
        from ..core.exceptions import ClientError

        if not self._object_service:
            raise ClientError("Object service not initialized")

        yield SSEEvent(
            event_type=SSEEventType.START,
            message="Refreshing object cache",
        )

        total_count = 0

        async for progress in self._object_service.refresh_objects(
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            mode=mode,
            include_global=include_global,
        ):
            count = progress.get("count", 0)
            total_count += count

            event_type = SSEEventType.ERROR if progress.get("status") == "domain_failed" else SSEEventType.LOG

            yield SSEEvent(
                event_type=event_type,
                message=progress.get("message", ""),
                data=progress,
            )

        yield SSEEvent(
            event_type=SSEEventType.COMPLETE, message="Cache refresh complete", data={"total_results": total_count}
        )

    def invalidate_domain(self, mgmt_name: str, domain_name: str) -> None:
        """Drop the object and the rulebase freshness memos of one domain, so the next smart read re-checks it.

        Called after every publish the library sees (cpcrud, ``helpers.policy.publish_session``,
        ``CacheOrchestrationService.publish``, a successful ``api_call('publish')``). It only drops memos; the
        published-session comparison decides whether anything is refreshed.
        """
        self._refresh_coordinator.invalidate(mgmt_name, domain_name)
        self._rulebase_coordinator.invalidate(mgmt_name, domain_name)

    @traced
    async def refresh_rulebases(
        self,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        mode: Literal["skip", "check", "force"] = "force",
        include_global: bool = False,
    ) -> AsyncGenerator[SSEEvent]:
        """Refresh rulebase cache from API.

        Args:
            mgmt_names: Optional management server filter.
            domain_names: Optional domain filter.
            mode: Refresh mode - "skip", "check", or "force".
            include_global: When False (default), the "Global" domain is excluded, as in `refresh_objects`.

        Yields:
            SSEEvent with progress updates.
        """
        self._ensure_open()

        yield SSEEvent(
            event_type=SSEEventType.START,
            message="Starting rulebase cache refresh",
        )

        total_count = 0
        async for progress in self._rulebase_refresh.refresh_all(
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            mode=mode,
            include_global=include_global,
        ):
            count = progress.get("count", 0)
            total_count += count

            status = progress.get("status")
            if status in ("domain_failed", "error"):
                event_type = SSEEventType.ERROR
            elif status == "warning":
                event_type = SSEEventType.WARNING
            else:
                event_type = SSEEventType.LOG

            yield SSEEvent(
                event_type=event_type,
                data=progress,
                message=progress.get("message", ""),
            )

        yield SSEEvent(
            event_type=SSEEventType.COMPLETE, message="Rulebase refresh complete", data={"total_results": total_count}
        )

    @property
    def _rulebase_source(self) -> CachedRulebaseSource:
        """Lazy CachedRulebaseSource over the cache adapter (reads only; never calls the API)."""
        if not hasattr(self, "_rulebase_source_instance"):
            from ..rulebase.source import CachedRulebaseSource

            self._rulebase_source_instance = CachedRulebaseSource(self._cache_adapter)
        return self._rulebase_source_instance

    def _rulebase_mgmt(self, mgmt_name: str | None) -> str:
        """The named server, or the first configured one: a call without a server is a single-server app."""
        if mgmt_name:
            return mgmt_name
        names = self.get_mgmt_names()
        if not names:
            raise ValueError("no management server is configured")
        return names[0]

    async def _ensure_rulebase_domain(
        self, mgmt: str, domain: str, cache_mode: CacheMode | str | None, cache_ttl: int | None
    ) -> None:
        from ..core.cache_policy import CachePolicy, RefreshScope

        policy = CachePolicy.resolve(cache_mode, cache_ttl, self._rulebase_coordinator.default_policy)
        await self._rulebase_coordinator.ensure(RefreshScope(mgmt_names=[mgmt], domain_names=[domain]), policy)

    async def _resolve_rulebase_domain(
        self, mgmt: str, domain: str | None, name: str, candidates: Callable[[], Awaitable[list[tuple[str, str]]]]
    ) -> str:
        """The domain a domainless call reads: the one cached domain holding ``name``; else the only cached domain
        (an SMS: ``SMC User``). Several holders → AmbiguousLayerName; none on an MDS → RulebaseCacheNotReady."""
        from ..rulebase.source import AmbiguousLayerName, RulebaseCacheNotReady

        if domain:
            return domain
        found = await candidates()
        domains = sorted({d for d, _ in found})
        if len(domains) == 1:
            return domains[0]
        if domains:
            raise AmbiguousLayerName(name, tuple(found))
        cached = await self._cache_adapter.get_domains(mgmt_names=[mgmt])
        if len(cached) == 1:
            return cached[0].domain_name
        raise RulebaseCacheNotReady(
            f"{name!r} is not in any cached domain of {mgmt}; pass domain and run refresh_rulebases for it"
        )

    @traced
    async def get_policy_packages(
        self,
        mgmt_name: str | None,
        domain_name: str,
        cache_mode: CacheMode | str | None = None,
        cache_ttl: int | None = None,
    ) -> list[PackageLayout]:
        """Policy packages of a domain with their ordered layers per rulebase type (from the rulebase cache)."""
        self._ensure_open()
        if not domain_name:
            raise ValueError("domain_name is required")
        mgmt = self._rulebase_mgmt(mgmt_name)
        await self._ensure_rulebase_domain(mgmt, domain_name, cache_mode, cache_ttl)
        return await self._rulebase_source.packages(mgmt, domain_name)

    @traced
    async def get_package_rulebase(
        self,
        mgmt_name: str | None,
        domain_name: str | None,
        package: str,
        rulebase_type: RulebaseType = "access",
        cache_mode: CacheMode | str | None = None,
        cache_ttl: int | None = None,
    ) -> PackageRulebase:
        """A package's rulebase numbered exactly like SmartConsole (global layer, parent rule, ``2.x``, ``2.2.1``).

        ``domain_name`` None/'' resolves to the one cached domain holding the package (``SMC User`` on an SMS).
        Numbers reflect the cached snapshot's session (``snapshot_session_uid``).
        """
        self._ensure_open()
        mgmt = self._rulebase_mgmt(mgmt_name)
        domain = await self._resolve_rulebase_domain(
            mgmt, domain_name, package, lambda: self._rulebase_source.find_package_domains(mgmt, package)
        )
        await self._ensure_rulebase_domain(mgmt, domain, cache_mode, cache_ttl)
        return await self._rulebase_source.package_rulebase(mgmt, domain, package, rulebase_type)

    @traced
    async def get_layer_rulebase(
        self,
        mgmt_name: str | None,
        domain_name: str | None,
        layer: str,
        rulebase_type: RulebaseType = "access",
        cache_mode: CacheMode | str | None = None,
        cache_ttl: int | None = None,
    ) -> LayerRulebase:
        """One layer (uid, or unique name) numbered without package context: layer-relative numbers, sections,
        place-holders, inline layers expanded. ``domain_name`` None/'' resolves like ``get_package_rulebase``."""
        self._ensure_open()
        mgmt = self._rulebase_mgmt(mgmt_name)
        domain = await self._resolve_rulebase_domain(
            mgmt, domain_name, layer, lambda: self._rulebase_source.find_layer_domains(mgmt, layer, rulebase_type)
        )
        await self._ensure_rulebase_domain(mgmt, domain, cache_mode, cache_ttl)
        return await self._rulebase_source.layer_rulebase(mgmt, domain, layer, rulebase_type)

    @traced
    async def locate_rules(
        self,
        mgmt_name: str | None,
        domain_name: str,
        rule_uids: Collection[str] = (),
        rulebase_type: RulebaseType | None = None,
        *,
        layer_uids: Collection[str] = (),
        cache_mode: CacheMode | str | None = None,
        cache_ttl: int | None = None,
    ) -> RuleLocations:
        """Every SmartConsole position of each rule uid, and every numbering prefix of each layer uid (``""`` for an
        ordered layer, ``"2."``/``"2.2."`` for nested ones), across the domain's packages; ``[]`` for unknown uids.

        The result carries the snapshot's session uid, publish time, refresh time and sync status, so a caller can
        tell which published state the numbers describe (a deleted or unpublished rule is numbered as a layer's
        prefix plus its show-changes position).

        Raises:
            ValueError: No ``domain_name``.
            TypeError: ``rule_uids`` or ``layer_uids`` is a bare ``str`` (pass a list of uids).
        """
        from ..rulebase.source import check_uid_collections

        self._ensure_open()
        if not domain_name:
            raise ValueError("domain_name is required")
        check_uid_collections(rule_uids=rule_uids, layer_uids=layer_uids)
        mgmt = self._rulebase_mgmt(mgmt_name)
        await self._ensure_rulebase_domain(mgmt, domain_name, cache_mode, cache_ttl)
        return await self._rulebase_source.locate_rules(
            mgmt, domain_name, rule_uids, rulebase_type, layer_uids=layer_uids
        )

    @traced
    async def collect_change_report(
        self,
        scopes: Sequence[Scope],
        *,
        include_raw: bool = False,
        concurrency: int = 4,
        max_sessions: int | None = None,
    ) -> ChangeReport:
        """Collect the changes of sessions (``SessionScope``) or published ranges (``RangeScope``) into a ChangeReport.

        Reads ``show-changes`` through the shared session (read-only), member names through ``show-object``, and
        numbers rules from the rulebase cache, or live through an ``owned_session``'s SID for unpublished sessions.
        Partial failures are warnings in the report; invalid input raises ``ChangeReportInputError``. See the user
        guide "Change Report".
        """
        from ..reports.changes import collect as _collect

        self._ensure_open()
        return await _collect.collect_change_report(
            self, scopes, include_raw=include_raw, concurrency=concurrency, max_sessions=max_sessions
        )

    @traced
    async def build_change_report(
        self,
        scopes: Sequence[Scope],
        formats: Collection[ReportFormat],
        options: RenderOptions | None = None,
        *,
        include_raw: bool = False,
        concurrency: int = 4,
        max_sessions: int | None = None,
    ) -> ChangeReportResult:
        """``collect_change_report`` then ``render_change_report`` (HTML needs the ``report`` extra)."""
        from ..reports.changes.render import render_change_report

        report = await self.collect_change_report(
            scopes, include_raw=include_raw, concurrency=concurrency, max_sessions=max_sessions
        )
        return render_change_report(report, formats, options)

    # ==================== V2: Typed Helper Methods ====================
    # These methods return Pydantic models instead of raw API responses

    @traced
    async def get_domains(
        self,
        mgmt_names: list[str] | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
        include_global: bool = False,
    ) -> list[Domain]:
        """Get domains from cache as Pydantic models.

        Only the domain list itself is refreshed (one ``show-domains`` per management server), never the domains'
        objects: ``cache`` reads the table as is; ``smart``/``smart-fast`` re-read the list when the table is empty
        or the domain-list TTL has passed; ``force`` re-reads it now. Without ``mgmt_names`` every cached server is
        read and the first configured server's list is refreshed. When a server's object cache is still empty and
        ``warm_object_cache_on_first_use`` is on (the default), its objects start loading in the background; the call
        returns without waiting for them.

        Args:
            mgmt_names: Optional list of management server names to filter.
            cache_mode: Optional per-call cache refresh mode override (for the domain list).
            cache_ttl: Accepted for signature compatibility; the domain list uses its own TTL.
            include_global: When False (default), the "Global" domain
                is excluded so existing callers see today's behavior.

        Returns:
            List of Domain models.

        Example:
            domains = await client.get_domains(mgmt_names=["mgmt1"])
            for domain in domains:
                print(f"{domain.name}: {domain.active_ip}")
        """
        from ..core.cache_mode import CacheMode
        from ..core.cache_policy import CachePolicy

        self._ensure_open()
        mode = CachePolicy.resolve(cache_mode, cache_ttl, self._refresh_coordinator.default_policy).mode
        if mode != CacheMode.CACHE:
            targets = list(mgmt_names) if mgmt_names else self.get_mgmt_names()[:1]
            for mgmt in targets:
                await self._refresh_domain_list(mgmt, force=mode == CacheMode.FORCE)
                await self._maybe_warm_object_cache(mgmt)
        return await self._orchestration.get_domains(mgmt_names=mgmt_names, include_global=include_global)

    async def _refresh_domain_list(self, mgmt_name: str, *, force: bool) -> None:
        """Re-read one server's domain list unless it is cached and fresh.

        A failure keeps the cached list; with a cached list the next attempt waits for the TTL (no login retry on every
        call while the server is down), with an empty table the next call retries.
        """
        if not force and not self._domain_list_refresh.is_stale(mgmt_name):
            if await self._cache.get_domains(mgmt_names=[mgmt_name]):
                return
        try:
            await self._domain_service.populate_domain_cache(mgmt_name)
        except Exception as exc:
            log().warning(f"Domain list refresh for {mgmt_name} failed ({type(exc).__name__}); cached list used")
            if await self._cache.get_domains(mgmt_names=[mgmt_name]):
                self._domain_list_refresh.mark_checked(mgmt_name)
            return
        self._domain_list_refresh.mark_checked(mgmt_name)

    async def _maybe_warm_object_cache(self, mgmt_name: str) -> None:
        """First use: load an empty object cache in the background, once per server per client.

        Skipped while the server's domain table is empty (a failed list refresh would warm only the system domain); the
        guard is taken before the first await so concurrent first calls start one warm-up.
        """
        if not self._settings.warm_object_cache_on_first_use or mgmt_name in self._object_warm_up_started:
            return
        self._object_warm_up_started.add(mgmt_name)
        try:
            if await self._cache.get_objects_last_update(mgmt_names=[mgmt_name]) is not None:
                return  # objects already cached: no warm-up, and no need to probe again on this client
            if not await self._cache.get_domains(mgmt_names=[mgmt_name]):
                self._object_warm_up_started.discard(mgmt_name)  # no domain list yet: a later call may warm up
                return
        except BaseException:
            self._object_warm_up_started.discard(mgmt_name)
            raise
        log().info(f"Object cache of {mgmt_name} is empty; loading every domain's objects in the background")
        self._warm_ups[mgmt_name] = ObjectCacheWarmUp(state="running", started_at=datetime.now(UTC))
        task = asyncio.create_task(self._warm_object_cache(mgmt_name))
        self._warm_up_tasks.add(task)
        self._background_tasks.add(task)
        task.add_done_callback(self._warm_up_tasks.discard)
        task.add_done_callback(self._background_tasks.discard)

    def object_cache_warm_up(self, mgmt_name: str) -> ObjectCacheWarmUp | None:
        """The background object-cache load of `mgmt_name` started by this client, or None if none was started.

        `get_domains` starts one, once per server, when it finds that server's object cache empty (see
        `warm_object_cache_on_first_use`). Counts are known once it has finished.
        """
        return self._warm_ups.get(mgmt_name)

    def _end_warm_up(self, mgmt_name: str, state: Literal["finished", "failed", "cancelled"], **counts: int) -> None:
        started = self._warm_ups.get(mgmt_name)
        started_at = started.started_at if started else datetime.now(UTC)
        self._warm_ups[mgmt_name] = ObjectCacheWarmUp(
            state=state, started_at=started_at, finished_at=datetime.now(UTC), **counts
        )

    async def _warm_object_cache(self, mgmt_name: str) -> None:
        from ..core.cache_mode import CacheMode
        from ..core.cache_policy import CachePolicy, RefreshScope

        # Always a smart load, whatever the client's default mode (a "cache" default would make it a no-op).
        policy = CachePolicy(mode=CacheMode.SMART, ttl=self._refresh_coordinator.default_policy.ttl)
        try:
            outcome = await self._refresh_coordinator.ensure(RefreshScope(mgmt_names=[mgmt_name]), policy)
        except asyncio.CancelledError:
            self._end_warm_up(mgmt_name, "cancelled")
            raise
        except Exception as exc:
            self._end_warm_up(mgmt_name, "failed")
            log().warning(f"Background object cache warm-up of {mgmt_name} failed: {type(exc).__name__}")
            return
        refreshed = len(getattr(outcome, "refreshed_domains", []) or [])
        failed = len(getattr(outcome, "failed_domains", []) or [])
        self._end_warm_up(mgmt_name, "finished", refreshed_domains=refreshed, failed_domains=failed)
        log().info(
            f"Background object cache warm-up of {mgmt_name} finished: {refreshed} domains refreshed, {failed} failed"
        )

    @traced
    async def get_gateways(
        self,
        mgmt_names: list[str] | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ) -> list[Gateway]:
        """Get gateways and servers from cache as Pydantic models.

        Gateways/servers live in a separate asset cache populated by
        ``build_refresh_assets_cache()`` (not the object-cache pipeline that
        backs ``get_domains``/``get_hosts``/etc.), so this method drives that
        refresh directly instead of going through the object-cache
        coordinator: "force" always refreshes first, and an empty cache
        triggers one refresh-then-retry regardless of mode (except "cache",
        which never calls the API).

        Args:
            mgmt_names: Optional list of management server names to filter.
            cache_mode: Optional per-call cache refresh mode override
                ("cache", "smart", "smart-fast", "force"). Defaults to the
                client's configured cache mode.
            cache_ttl: Unused for gateways (asset cache has no TTL check yet);
                accepted for signature parity with the other get_* helpers.

        Returns:
            List of Gateway models.

        Example:
            gateways = await client.get_gateways(mgmt_names=["mgmt1"])
            for gw in gateways:
                print(f"{gw.name}: {gw.ip_address} ({gw.type})")
        """
        self._ensure_open()

        effective_mode = cache_mode or self._default_cache_mode

        if effective_mode == "force":
            async for _ in self.build_refresh_assets_cache(mgmt_names=mgmt_names or ""):
                pass

        gateways = await self._orchestration.get_gateways(mgmt_names=mgmt_names, cache_mode="cache")

        if not gateways and effective_mode != "cache" and effective_mode != "force":
            async for _ in self.build_refresh_assets_cache(mgmt_names=mgmt_names or ""):
                pass
            gateways = await self._orchestration.get_gateways(mgmt_names=mgmt_names, cache_mode="cache")

        return gateways

    @traced
    async def get_hosts(
        self,
        name_filter: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ) -> list[Host]:
        """Get host objects from cache as Pydantic models.

        Args:
            name_filter: Optional name filter (supports wildcards).
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.

        Returns:
            List of Host models.

        Example:
            hosts = await client.get_hosts(name_filter="web*")
            for host in hosts:
                print(f"{host.name}: {host.ip_address}")
        """
        self._ensure_open()
        return await self._orchestration.get_hosts(
            name_filter=name_filter,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_networks(
        self,
        subnet: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ) -> list[Network]:
        """Get network objects from cache as Pydantic models.

        Args:
            subnet: Optional subnet filter (CIDR notation).
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.

        Returns:
            List of Network models.

        Example:
            networks = await client.get_networks(subnet="192.168.1.0/24")
            for net in networks:
                print(f"{net.name}: {net.subnet4}/{net.subnet_mask}")
        """
        self._ensure_open()
        return await self._orchestration.get_networks(
            subnet=subnet,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_groups(
        self,
        name_filter: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ) -> list[Group]:
        """Get group objects from cache as Pydantic models.

        Args:
            name_filter: Optional name filter (supports wildcards).
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.

        Returns:
            List of Group models.

        Example:
            groups = await client.get_groups(name_filter="firewall*")
            for group in groups:
                print(f"{group.name}: {len(group.member_uids)} members")
        """
        self._ensure_open()
        return await self._orchestration.get_groups(
            name_filter=name_filter,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_object_by_uid(
        self,
        uid: str,
        mgmt_name: str,
        domain_name: str = "",
    ) -> CPObject | None:
        """Get any object by UID from cache.

        Args:
            uid: Object UID.
            mgmt_name: Management server name.
            domain_name: Domain name (default: system domain).

        Returns:
            CPObject or None if not found.

        Example:
            obj = await client.get_object_by_uid("123abc", "mgmt1")
            if obj:
                print(f"{obj.name} ({obj.type})")
        """
        self._ensure_open()
        return await self._orchestration.get_object_by_uid(
            uid=uid,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
        )

    # ==================== V2 Rulebase Helper Methods ====================

    @traced
    async def get_access_rules(
        self,
        layer_name: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        enabled_only: bool | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ) -> list[AccessRule]:
        """Get access control rules from cache.

        Args:
            layer_name: Optional layer name filter (e.g., "Network").
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            enabled_only: If True, only return enabled rules.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.

        Returns:
            List of AccessRule Pydantic models.
        """
        self._ensure_open()
        return await self._orchestration.get_access_rules(
            layer_name=layer_name,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            enabled_only=enabled_only,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_nat_rules(
        self,
        layer_name: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        enabled_only: bool | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ) -> list[NATRule]:
        """Get NAT rules from cache.

        Args:
            layer_name: Optional policy package name filter; NAT rules are keyed by package, e.g. layer_name="Standard".
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            enabled_only: If True, only return enabled rules.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.

        Returns:
            List of NATRule Pydantic models.
        """
        self._ensure_open()
        return await self._orchestration.get_nat_rules(
            layer_name=layer_name,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            enabled_only=enabled_only,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_https_rules(
        self,
        layer_name: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        enabled_only: bool | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ) -> list[HTTPSRule]:
        """Get HTTPS inspection rules from cache.

        Args:
            layer_name: Optional layer name filter (e.g., "CVD").
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            enabled_only: If True, only return enabled rules.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.

        Returns:
            List of HTTPSRule Pydantic models.
        """
        self._ensure_open()
        return await self._orchestration.get_https_rules(
            layer_name=layer_name,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            enabled_only=enabled_only,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_threat_rules(
        self,
        layer_name: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        enabled_only: bool | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ) -> list[ThreatRule]:
        """Get threat prevention rules from cache.

        Args:
            layer_name: Optional layer name filter (e.g., "Threat").
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            enabled_only: If True, only return enabled rules.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.

        Returns:
            List of ThreatRule Pydantic models.
        """
        self._ensure_open()
        return await self._orchestration.get_threat_rules(
            layer_name=layer_name,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            enabled_only=enabled_only,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )


def _task_page(data: Any, item_key: str) -> tuple[list[dict[str, Any]], int, int]:
    """(items, to, total) of one page of a task-based query.

    The finished show-task answer nests the page under `tasks[].task-details[]`;
    older servers answer flat, with the paging fields at the top level.
    """
    if not isinstance(data, dict):
        return [], 0, 0
    details = [d for t in data.get("tasks") or [] for d in t.get("task-details") or [] if isinstance(d, dict)]
    pages = details or [data]
    items = [item for d in pages for item in d.get(item_key) or []]
    to = max((int(d.get("to") or 0) for d in pages), default=0)
    total = max((int(d.get("total") or 0) for d in pages), default=0)
    return items, to, total


__all__ = ["ArodonataClient"]
