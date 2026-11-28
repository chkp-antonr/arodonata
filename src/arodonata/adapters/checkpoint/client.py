"""Low-level Check Point Management API client (`AMgmtClient`) implementing `ApiPort`.

Provides:
- `api_call` with automatic read-only `sid_cache` reuse, active `WriteSession` context routing,
  transparent single re-login on session expiration, active domain IP failover re-resolution,
  `RateLimiter` concurrency gating per MDS member, `TaskWaiter` asynchronous task polling,
  and `SessionOverlay` updates for `add-*` / `set-*` / `delete-*` mutations.
- `api_query` continuity-verified pagination releasing the `RateLimiter` slot between pages.
- `create_dedicated_session` and `write_session` isolated write context manager.
- Default in-memory SQLite engine (`sqlite+aiosqlite:///:memory:`) when `engine=None`.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine

from arodonata.adapters.checkpoint.pager import DEFAULT_PAGE_LIMIT, paginate_objects
from arodonata.adapters.checkpoint.rate_limiter import LoginGate, RateLimiter
from arodonata.adapters.checkpoint.sessions import (
    SYSTEM_DOMAIN_SENTINEL,
    LoginCoordinator,
    SessionCleaner,
    is_failover_or_unreachable_result,
    is_session_expired_result,
    normalize_domain_key,
)
from arodonata.adapters.checkpoint.target_resolver import resolve_tls_identity_host
from arodonata.adapters.checkpoint.task_waiter import TaskWaiter, extract_task_ids
from arodonata.adapters.checkpoint.tls import TrustPolicy
from arodonata.adapters.checkpoint.transport import (
    ApiTransport,
    VerifiedConnectionPool,
    derive_session_pool_scope,
)
from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import (
    NON_OVERLAY_MUTATION_TARGETS as NON_OVERLAY_MUTATION_TARGETS,
)
from arodonata.core.context import (
    SERVICE_COMMAND_TYPES as SERVICE_COMMAND_TYPES,
)
from arodonata.core.context import (
    AuthContext,
    SessionOverlay,
    UserContext,
    WriteSession,
    get_user_context,
    get_write_session,
    run_write_session_lifecycle,
    update_overlay_from_command,
)
from arodonata.core.errors import (
    ApiTimeoutError,
    RateLimitTimeoutError,
    ServerIdentityError,
    SessionStateError,
    TransportError,
)
from arodonata.core.models.common import ApiCallResult, ApiQueryResult, utc_now
from arodonata.core.ports import AuthProvider, CachePort, LockPort
from arodonata.core.primitives import (
    READONLY_EXACT_COMMANDS as READONLY_EXACT_COMMANDS,
)
from arodonata.core.primitives import (
    is_readonly_command as is_readonly_command,
)
from arodonata.core.primitives import validate_command_name
from arodonata.core.telemetry import span_attrs, traced

# Backward-compatible private alias (canonical implementation lives in `arodonata.core.context`).
_update_overlay_from_command = update_overlay_from_command


@dataclass(slots=True)
class _ResolvedCallSession:
    """Resolved session, target IP, rate-limiter MDS IP, and TLS identity state for `api_call`."""

    active_sid: str
    target_ip: str
    mds_ip: str
    port: int
    raw_target_ip: str | None
    tls_identity_host: str | None
    using_cached_sid: bool
    active_auth_identity: str | None
    active_ws: WriteSession | None
    session_scope: str | None


class AMgmtClient:
    """Low-level asynchronous Check Point Management API client implementing `ApiPort`."""

    def __init__(
        self,
        settings: ArodonataSettings | None = None,
        *,
        engine: AsyncEngine | str | None = None,
        db_manager: DatabaseManager | None = None,
        cache: CachePort | None = None,
        lock_port: LockPort | None = None,
        transport: ApiTransport | None = None,
        trust_policy: TrustPolicy | None = None,
        connection_pool: VerifiedConnectionPool | None = None,
        task_waiter: TaskWaiter | None = None,
        rate_limiter: RateLimiter | None = None,
        login_gate: LoginGate | None = None,
        auth_provider: AuthProvider | None = None,
        on_domain_invalidated: Callable[[str, str | None], None] | None = None,
        monotonic_fn: Callable[[], float] = time.monotonic,
        now_fn: Callable[[], datetime] = utc_now,
        sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
        **settings_kwargs: Any,
    ) -> None:
        self._settings = settings if settings is not None else ArodonataSettings(**settings_kwargs)
        self._settings.configure_tracing()

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

        self._trust_policy = trust_policy or TrustPolicy(
            mode=self._settings.tls_trust,
            known_hosts_path=self._settings.tls_known_hosts_path,
            pinned_fingerprints=self._settings.tls_fingerprints,
        )
        if transport is not None:
            self._transport = transport
            self._connection_pool = connection_pool or transport.connection_pool
        else:
            self._connection_pool = connection_pool or VerifiedConnectionPool(monotonic_fn=monotonic_fn)
            self._transport = ApiTransport(
                settings=self._settings,
                trust_policy=self._trust_policy,
                connection_pool=self._connection_pool,
            )
        self._task_waiter = task_waiter or TaskWaiter(
            task_timeout=self._settings.task_timeout,
            monotonic_fn=monotonic_fn,
            sleep_fn=sleep_fn,
        )
        default_lock_ttl = max(
            180.0,
            float(self._settings.connect_timeout)
            + float(max(self._settings.api_timeout, self._settings.login_timeout))
            + 60.0,
        )
        self._rate_limiter = rate_limiter or RateLimiter(
            concurrent_limit=self._settings.concurrent_limit,
            slot_timeout=self._settings.rate_limit_slot_timeout,
            lock_port=self._lock_port,
            slot_lock_ttl=default_lock_ttl,
            monotonic_fn=monotonic_fn,
            sleep_fn=sleep_fn,
        )
        self._login_gate = login_gate or LoginGate(
            lock_port=self._lock_port,
            gate_lock_ttl=default_lock_ttl,
            monotonic_fn=monotonic_fn,
            sleep_fn=sleep_fn,
        )
        self._login_coordinator = LoginCoordinator(
            settings=self._settings,
            transport=self._transport,
            cache=self._cache,
            login_gate=self._login_gate,
            rate_limiter=self._rate_limiter,
            auth_provider=auth_provider,
            monotonic_fn=monotonic_fn,
            now_fn=now_fn,
            sleep_fn=sleep_fn,
        )
        self._session_cleaner = SessionCleaner(
            settings=self._settings,
            login_coordinator=self._login_coordinator,
            transport=self._transport,
            cache=self._cache,
            rate_limiter=self._rate_limiter,
        )
        self._login_coordinator.bind_session_cleaner(self._session_cleaner)
        self._on_domain_invalidated = on_domain_invalidated
        self._invalidated_domains: set[tuple[str, str]] = set()

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
        """Return `True` if this client created and owns its SQLAlchemy `AsyncEngine`."""
        return self._owns_engine

    @property
    def cache(self) -> CachePort:
        """Underlying `CachePort` adapter."""
        return self._cache

    @property
    def lock_port(self) -> LockPort:
        """Underlying `LockPort` adapter."""
        return self._lock_port

    @property
    def transport(self) -> ApiTransport:
        """Underlying `ApiTransport`."""
        return self._transport

    @property
    def trust_policy(self) -> TrustPolicy:
        """Active `TrustPolicy`."""
        return self._trust_policy

    @property
    def connection_pool(self) -> VerifiedConnectionPool:
        """Active `VerifiedConnectionPool`."""
        return self._connection_pool

    @property
    def task_waiter(self) -> TaskWaiter:
        """Active `TaskWaiter`."""
        return self._task_waiter

    @property
    def rate_limiter(self) -> RateLimiter:
        """Active `RateLimiter`."""
        return self._rate_limiter

    @property
    def login_gate(self) -> LoginGate:
        """Active `LoginGate`."""
        return self._login_gate

    @property
    def login_coordinator(self) -> LoginCoordinator:
        """Active `LoginCoordinator`."""
        return self._login_coordinator

    @property
    def session_cleaner(self) -> SessionCleaner:
        """Active `SessionCleaner`."""
        return self._session_cleaner

    @property
    def invalidated_domains(self) -> set[tuple[str, str]]:
        """Set of `(mgmt_name, domain_key)` pairs invalidated by `publish`."""
        return set(self._invalidated_domains)

    async def initialize(self, *, run_startup_cleanup: bool = False) -> None:
        """Ensure the database schema is initialized and optionally schedule startup cleanup."""
        if not self._db.is_initialized:
            await self._db.initialize()
        if run_startup_cleanup:
            self._session_cleaner.schedule_startup_cleanup()

    async def __aenter__(self) -> AMgmtClient:
        await self.initialize(run_startup_cleanup=True)
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()

    def invalidate_domain(self, mgmt_name: str, domain: str | None = None) -> None:
        """Mark `(mgmt_name, domain)` as invalidated after `publish` and notify any facade callback."""
        dom_key = normalize_domain_key(domain)
        self._invalidated_domains.add((mgmt_name, dom_key))
        if self._on_domain_invalidated is not None:
            self._on_domain_invalidated(mgmt_name, domain)

    async def _resolve_call_session(
        self,
        mgmt_name: str,
        clean_cmd: str,
        domain: str | None,
        dom_key: str,
        *,
        sid: str | None,
        server_ip: str | None,
        is_readonly: bool,
    ) -> _ResolvedCallSession:
        """Resolve active SID, pinned target IP, rate-limiter MDS IP, and TLS identity host."""
        endpoint = self._login_coordinator.get_server_endpoint(mgmt_name)
        active_ws = get_write_session(mgmt_name=mgmt_name, domain_name=dom_key)
        using_cached_sid = False
        active_auth_identity: str | None = None

        if sid is not None:
            active_sid = sid
            raw_target_ip = server_ip
            target_ip, mds_ip, port = await self._login_coordinator.resolve_target_ips(
                mgmt_name,
                domain,
                explicit_server_ip=server_ip,
            )
        elif active_ws is not None:
            active_sid = active_ws.sid
            raw_target_ip = server_ip or active_ws.server_ip
            target_ip, mds_ip, port = await self._login_coordinator.resolve_target_ips(
                mgmt_name,
                active_ws.domain_name,
                explicit_server_ip=raw_target_ip,
            )
        else:
            if not is_readonly:
                raise SessionStateError(
                    f"Mutating command {clean_cmd!r} is forbidden on shared read-only sid_cache. "
                    "Use an isolated client.write_session(...) or pass an explicit dedicated sid."
                )
            using_cached_sid = True
            active_auth_identity = (await self._login_coordinator.resolve_credentials(mgmt_name, domain)).identity_key
            active_sid, ro_ip = await self._login_coordinator.get_readonly_session(
                mgmt_name,
                domain,
                server_ip=server_ip,
            )
            raw_target_ip = server_ip or (endpoint.host if dom_key == SYSTEM_DOMAIN_SENTINEL else ro_ip)
            target_ip, mds_ip, port = await self._login_coordinator.resolve_target_ips(
                mgmt_name,
                domain,
                explicit_server_ip=ro_ip,
            )

        tls_identity_host = resolve_tls_identity_host(raw_target_ip, target_ip)
        if tls_identity_host is None and active_sid and (server_ip is None or server_ip == target_ip):
            stored_tls_host = self._login_coordinator.get_tls_identity_host(mgmt_name, active_sid)
            if stored_tls_host is not None:
                tls_identity_host = resolve_tls_identity_host(stored_tls_host, target_ip)
        session_scope = derive_session_pool_scope(active_sid) if (not using_cached_sid and active_sid) else None
        return _ResolvedCallSession(
            active_sid=active_sid,
            target_ip=target_ip,
            mds_ip=mds_ip,
            port=port,
            raw_target_ip=raw_target_ip,
            tls_identity_host=tls_identity_host,
            using_cached_sid=using_cached_sid,
            active_auth_identity=active_auth_identity,
            active_ws=active_ws,
            session_scope=session_scope,
        )

    async def _execute_transport_call(
        self,
        clean_cmd: str,
        payload: dict[str, Any] | None,
        ctx: _ResolvedCallSession,
        call_budget: float,
    ) -> ApiCallResult:
        """Execute one transport call under the target MDS rate-limiter slot."""
        exec_kwargs: dict[str, Any] = {
            "port": ctx.port,
            "sid": ctx.active_sid,
            "timeout": call_budget,
        }
        if ctx.session_scope is not None:
            exec_kwargs["session_scope"] = ctx.session_scope
        if ctx.tls_identity_host is not None:
            exec_kwargs["tls_identity_host"] = ctx.tls_identity_host
        async with self._rate_limiter.slot(ctx.mds_ip):
            return await self._transport.execute(
                ctx.target_ip,
                clean_cmd,
                payload,
                **exec_kwargs,
            )

    async def _retry_domain_failover(
        self,
        mgmt_name: str,
        domain: str | None,
        dom_key: str,
        clean_cmd: str,
        payload: dict[str, Any] | None,
        ctx: _ResolvedCallSession,
        call_budget: float,
    ) -> tuple[bool, ApiCallResult | None]:
        """Re-resolve domain active IP from MDS and retry once if active IP changed."""
        refreshed = await self._login_coordinator.refresh_domain_active_ip(mgmt_name, dom_key)
        if refreshed is None or not refreshed.active_ip or refreshed.active_ip == ctx.target_ip:
            return False, None
        endpoint = self._login_coordinator.get_server_endpoint(mgmt_name)
        ctx.target_ip = refreshed.active_ip
        ctx.mds_ip = refreshed.active_mds_ip or endpoint.host
        ctx.raw_target_ip = refreshed.active_ip
        ctx.tls_identity_host = resolve_tls_identity_host(ctx.raw_target_ip, ctx.target_ip)
        if ctx.using_cached_sid:
            await self._cache.evict_sid(mgmt_name, dom_key, auth_identity=ctx.active_auth_identity)
            ctx.active_sid, ctx.target_ip = await self._login_coordinator.get_readonly_session(
                mgmt_name,
                domain,
                server_ip=ctx.target_ip,
                force_new=True,
            )
        return True, await self._execute_transport_call(clean_cmd, payload, ctx, call_budget)

    async def _retry_expired_readonly_session(
        self,
        mgmt_name: str,
        domain: str | None,
        dom_key: str,
        clean_cmd: str,
        payload: dict[str, Any] | None,
        server_ip: str | None,
        ctx: _ResolvedCallSession,
        call_budget: float,
    ) -> ApiCallResult:
        """Evict expired cached RO SID, re-login, re-resolve target/MDS IPs + TLS identity, and retry once."""
        endpoint = self._login_coordinator.get_server_endpoint(mgmt_name)
        await self._cache.evict_sid(mgmt_name, dom_key, auth_identity=ctx.active_auth_identity)
        new_sid, ro_ip = await self._login_coordinator.get_readonly_session(
            mgmt_name,
            domain,
            server_ip=server_ip,
            force_new=True,
        )
        raw_target_ip = server_ip or (endpoint.host if dom_key == SYSTEM_DOMAIN_SENTINEL else ro_ip)
        target_ip, mds_ip, port = await self._login_coordinator.resolve_target_ips(
            mgmt_name,
            domain,
            explicit_server_ip=ro_ip,
        )
        ctx.active_sid = new_sid
        ctx.raw_target_ip = raw_target_ip
        ctx.target_ip = target_ip
        ctx.mds_ip = mds_ip
        ctx.port = port
        tls_identity = resolve_tls_identity_host(raw_target_ip, target_ip)
        if tls_identity is None and (server_ip is None or server_ip == target_ip):
            stored_tls_host = self._login_coordinator.get_tls_identity_host(mgmt_name, new_sid)
            if stored_tls_host is not None:
                tls_identity = resolve_tls_identity_host(stored_tls_host, target_ip)
        ctx.tls_identity_host = tls_identity
        return await self._execute_transport_call(clean_cmd, payload, ctx, call_budget)

    async def _poll_task_if_needed(
        self,
        res: ApiCallResult,
        clean_cmd: str,
        wait_for_task: bool,
        timeout: float | None,
        ctx: _ResolvedCallSession,
    ) -> ApiCallResult:
        """Poll asynchronous Check Point tasks via `TaskWaiter` when `wait_for_task=True`."""
        if not (res.success and wait_for_task and clean_cmd != "show-task"):
            return res
        task_ids = extract_task_ids(res.data)
        if not task_ids:
            return res

        async def _poll_show_task(poll_payload: dict[str, Any]) -> ApiCallResult:
            poll_kwargs: dict[str, Any] = {
                "port": ctx.port,
                "sid": ctx.active_sid,
                "timeout": None,  # Uses max(api_timeout, login_timeout) + 5s socket read timeout
            }
            if ctx.session_scope is not None:
                poll_kwargs["session_scope"] = ctx.session_scope
            if ctx.tls_identity_host is not None:
                poll_kwargs["tls_identity_host"] = ctx.tls_identity_host
            async with self._rate_limiter.slot(ctx.mds_ip):
                return await self._transport.execute(
                    ctx.target_ip,
                    "show-task",
                    poll_payload,
                    **poll_kwargs,
                )

        return await self._task_waiter.wait_for_tasks(
            task_ids,
            _poll_show_task,
            timeout=timeout if timeout is not None else self._settings.task_timeout,
            initial_result=res,
            known_sids=[ctx.active_sid] if ctx.active_sid else None,
        )

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
        """Execute a single Check Point Management API command (`/web_api/<command>`).

        - Uses explicit `sid` if provided, else active `WriteSession` from `contextvars` if matching
          `(mgmt_name, domain)`, else shared read-only session from `LoginCoordinator` (`sid_cache`).
        - Transparently evicts expired cached SIDs and retries once with a fresh session.
        - Re-resolves domain `active_ip` on failover/unreachable error and retries once.
        - Polls returned `task-id` / `tasks` via `TaskWaiter` when `wait_for_task=True`.
        - Updates `WriteSession.overlay` on `add-*` / `set-*` / `delete-*` and invalidates domain on `publish`.
        """
        clean_cmd = validate_command_name(command)
        if not self._db.is_initialized:
            await self._db.initialize()

        dom_key = normalize_domain_key(domain)
        span_attrs(mgmt_name=mgmt_name, domain=dom_key, cp_command=clean_cmd, wait_for_task=wait_for_task)
        is_readonly = is_readonly_command(clean_cmd)
        call_budget = timeout if timeout is not None else self._settings.api_timeout

        ctx = await self._resolve_call_session(
            mgmt_name,
            clean_cmd,
            domain,
            dom_key,
            sid=sid,
            server_ip=server_ip,
            is_readonly=is_readonly,
        )

        try:
            res = await self._execute_transport_call(clean_cmd, payload, ctx, call_budget)
        except (ServerIdentityError, RateLimitTimeoutError):
            raise
        except (ApiTimeoutError, TransportError) as exc:
            # If a domain's cached active_ip became unreachable on connect for a read-only command,
            # attempt failover resolution once (never retry post-send or mutating commands - C8)
            can_retry_failover = (
                is_readonly
                and isinstance(exc, TransportError)
                and not exc.request_sent
                and exc.phase == "connect"
                and server_ip is None
                and dom_key != SYSTEM_DOMAIN_SENTINEL
            )
            if can_retry_failover:
                switched, retry_res = await self._retry_domain_failover(
                    mgmt_name,
                    domain,
                    dom_key,
                    clean_cmd,
                    payload,
                    ctx,
                    call_budget,
                )
                if switched and retry_res is not None:
                    res = retry_res
                else:
                    raise
            else:
                raise

        # Handle session expiration on cached read-only session -> evict SID, re-login, and retry once
        is_self_show_session = clean_cmd.lower() == "show-session" and not (payload and payload.get("uid"))
        if ctx.using_cached_sid and is_session_expired_result(
            res,
            command="show-session" if is_self_show_session else None,
        ):
            res = await self._retry_expired_readonly_session(
                mgmt_name,
                domain,
                dom_key,
                clean_cmd,
                payload,
                server_ip,
                ctx,
                call_budget,
            )

        # Handle domain failover error code returned in HTTP response (read-only commands only - C8)
        if (
            is_readonly
            and not res.success
            and server_ip is None
            and dom_key != SYSTEM_DOMAIN_SENTINEL
            and is_failover_or_unreachable_result(res)
        ):
            switched, retry_res = await self._retry_domain_failover(
                mgmt_name,
                domain,
                dom_key,
                clean_cmd,
                payload,
                ctx,
                call_budget,
            )
            if switched and retry_res is not None:
                res = retry_res

        # If keepalive returned success=False, evict immediately from sid_cache
        if clean_cmd == "keepalive" and not res.success and ctx.using_cached_sid:
            await self._cache.evict_sid(mgmt_name, dom_key, auth_identity=ctx.active_auth_identity)

        res = await self._poll_task_if_needed(res, clean_cmd, wait_for_task, timeout, ctx)

        # Update WriteSession overlay on mutation commands
        if ctx.active_ws is not None and (sid is None or sid == ctx.active_ws.sid):
            update_overlay_from_command(ctx.active_ws.overlay, clean_cmd, payload, res)

        # Invalidate domain freshness memo on successful publish
        if clean_cmd == "publish" and res.success:
            eff_domain = domain or (ctx.active_ws.domain_name if ctx.active_ws is not None else None)
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

        async def _page_caller(page_payload: dict[str, Any]) -> ApiCallResult:
            return await self.api_call(
                mgmt_name,
                command,
                page_payload,
                domain=domain,
                sid=sid,
                server_ip=server_ip,
                wait_for_task=True,
            )

        return await paginate_objects(
            command,
            _page_caller,
            details_level=details_level,
            payload=payload,
            limit=limit,
            max_pages=self._settings.max_query_pages,
            max_objects=self._settings.max_query_objects,
        )

    @traced
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
        sid, server_ip, _uid = await self._login_coordinator.create_dedicated_session(
            mgmt_name,
            domain,
            auth=auth,
            session_name=session_name,
            session_description=session_description,
        )
        return sid, server_ip

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
        """Open a context-bound isolated `WriteSession` outside `sid_cache`.

        - Authenticates under `auth` (or active `AuthContext` / `AuthProvider` / static settings).
        - Binds the `WriteSession` to `contextvars` so nested `api_call` mutations and read
          helpers automatically use its SID and `SessionOverlay`.
        - Automatically executes `publish` on clean exit (when `publish_on_exit=True`),
          invalidating the domain freshness memo and clearing the overlay.
        - Automatically executes `discard` and clears the overlay if an unhandled exception
          escapes the `async with` block.
        - Always logs out the dedicated SID in `finally`.
        """
        if not self._db.is_initialized:
            await self._db.initialize()

        dom_key = normalize_domain_key(domain)
        resolved_auth = await self._login_coordinator.resolve_credentials(mgmt_name, domain, explicit_auth=auth)
        resolved_user = user or get_user_context()
        eff_name = session_name or (resolved_user.session_name if resolved_user else None)
        eff_desc = session_description or (resolved_user.session_description if resolved_user else None)

        sid, server_ip, session_uid = await self._login_coordinator.create_dedicated_session(
            mgmt_name,
            domain,
            auth=resolved_auth,
            user=resolved_user,
            session_name=eff_name,
            session_description=eff_desc,
        )

        ws = WriteSession(
            mgmt_name=mgmt_name,
            domain_name=dom_key,
            sid=sid,
            server_ip=server_ip,
            session_uid=session_uid,
            session_name=eff_name,
            auth=resolved_auth,
            user=resolved_user,
            overlay=SessionOverlay(mgmt_name, dom_key),
        )

        async with run_write_session_lifecycle(
            ws,
            api_call_fn=self.api_call,
            logout_fn=self.logout_sid,
            domain=domain,
            publish_on_exit=publish_on_exit,
            on_domain_invalidated=self.invalidate_domain,
        ) as bound_ws:
            yield bound_ws

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> Awaitable[bool]:
        """Log out a specific session identifier."""
        return self._login_coordinator.logout_sid(mgmt_name, sid, server_ip=server_ip)

    @traced
    async def close(self, *, logout: bool | None = None) -> None:
        """Close transport connections, drain startup cleanup tasks, and dispose owned engine."""
        await self._session_cleaner.drain_startup_tasks()
        is_ephemeral_db = self._owns_engine and self._db.is_in_memory
        should_logout = is_ephemeral_db if logout is None else bool(logout)
        if self._db.is_initialized:
            await self._login_coordinator.logout_all(include_cached_readonly=should_logout)
        await self._transport.close()
        await self._db.close()


__all__ = [
    "AMgmtClient",
]
