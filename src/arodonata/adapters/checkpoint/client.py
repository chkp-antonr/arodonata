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
from contextlib import asynccontextmanager, suppress
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
from arodonata.adapters.checkpoint.task_waiter import TaskWaiter, extract_task_ids
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
from arodonata.core.errors import (
    ApiTimeoutError,
    ServerIdentityError,
    SessionError,
    SessionStateError,
    TransportError,
    is_sensitive_key,
)
from arodonata.core.models.common import ApiCallResult, ApiQueryResult, utc_now
from arodonata.core.models.objects import CPObject
from arodonata.core.models.services import CPService
from arodonata.core.ports import AuthProvider, CachePort, LockPort
from arodonata.core.telemetry import span_attrs, traced

SERVICE_COMMAND_TYPES: frozenset[str] = frozenset(
    {
        "service-tcp",
        "service-udp",
        "service-icmp",
        "service-icmp6",
        "service-other",
        "service-dce-rpc",
        "service-rpc",
        "service-sctp",
        "service-gtp",
        "service-citrix-tcp",
        "service-compound-tcp",
        "service-group",
    }
)

NON_OVERLAY_MUTATION_TARGETS: frozenset[str] = frozenset(
    {
        "access-rule",
        "access-section",
        "access-layer",
        "nat-rule",
        "nat-section",
        "https-rule",
        "https-section",
        "https-layer",
        "threat-rule",
        "threat-exception",
        "threat-layer",
        "package",
        "domain",
        "administrator",
        "session",
        "trust",
    }
)


READONLY_EXACT_COMMANDS: frozenset[str] = frozenset(
    {
        "where-used",
        "verify-policy",
        "keepalive",
    }
)


def is_readonly_command(command: str) -> bool:
    """Return `True` if `command` is a read-only Check Point Web API command (`C8`)."""
    clean = command.strip().lower().lstrip("/")
    return clean.startswith("show-") or clean in READONLY_EXACT_COMMANDS


def _update_overlay_from_command(
    overlay: SessionOverlay,
    command: str,
    payload: dict[str, Any] | None,
    result: ApiCallResult,
) -> None:
    """Update `SessionOverlay` when `add-*`, `set-*`, or `delete-*` succeeds inside a `WriteSession`."""
    if not result.success:
        return
    clean = command.strip().lower().lstrip("/")
    if not clean.startswith(("add-", "set-", "delete-")):
        return

    verb, _, target_type = clean.partition("-")
    if not target_type or target_type in NON_OVERLAY_MUTATION_TARGETS:
        return

    is_service = target_type in SERVICE_COMMAND_TYPES or target_type.startswith("service-")
    req_data = payload or {}
    resp_data = result.data if isinstance(result.data, dict) else {}

    if verb in ("add", "set"):
        merged_raw = {k: v for k, v in req_data.items() if not is_sensitive_key(k)}
        for k, v in resp_data.items():
            if not is_sensitive_key(k):
                merged_raw[k] = v
        if "type" not in merged_raw or not merged_raw.get("type"):
            merged_raw["type"] = target_type
        uid = str(merged_raw.get("uid") or "")
        name = str(merged_raw.get("name") or req_data.get("new-name") or "")
        if not uid and not name:
            return
        if not uid:
            uid = f"overlay:{target_type}:{name}"
            merged_raw["uid"] = uid

        if is_service:
            svc = CPService.from_cp_dict(overlay.mgmt_name, overlay.domain_name, merged_raw)
            overlay.record_service_upsert(svc)
        else:
            obj = CPObject.from_cp_dict(overlay.mgmt_name, overlay.domain_name, merged_raw)
            overlay.record_object_upsert(obj)
        return

    if verb == "delete":
        uid_val = req_data.get("uid") or resp_data.get("uid")
        name_val = req_data.get("name") or resp_data.get("name")
        uid_str = str(uid_val) if isinstance(uid_val, str) and uid_val else None
        name_str = str(name_val) if isinstance(name_val, str) and name_val else None
        if is_service:
            overlay.record_service_delete(uid=uid_str, name=name_str, svc_type=target_type)
        else:
            overlay.record_object_delete(uid=uid_str, name=name_str, obj_type=target_type)


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
        self._connection_pool = connection_pool or VerifiedConnectionPool(monotonic_fn=monotonic_fn)
        self._transport = transport or ApiTransport(
            settings=self._settings,
            trust_policy=self._trust_policy,
            connection_pool=self._connection_pool,
        )
        self._task_waiter = task_waiter or TaskWaiter(
            task_timeout=self._settings.task_timeout,
            monotonic_fn=monotonic_fn,
            sleep_fn=sleep_fn,
        )
        default_lock_ttl = max(180.0, float(max(self._settings.api_timeout, self._settings.login_timeout)) + 60.0)
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
        if not self._db.is_initialized:
            await self._db.initialize()

        clean_cmd = command.strip().lstrip("/")
        dom_key = normalize_domain_key(domain)
        endpoint = self._login_coordinator.get_server_endpoint(mgmt_name)
        span_attrs(mgmt_name=mgmt_name, domain=dom_key, cp_command=clean_cmd, wait_for_task=wait_for_task)

        active_ws = get_write_session(mgmt_name=mgmt_name, domain_name=dom_key if domain is not None else None)
        using_cached_sid = False
        active_auth_identity: str | None = None
        is_readonly = is_readonly_command(clean_cmd)

        if sid is not None:
            active_sid = sid
            target_ip, mds_ip, port = await self._login_coordinator.resolve_target_ips(
                mgmt_name,
                domain,
                explicit_server_ip=server_ip,
            )
        elif active_ws is not None:
            active_sid = active_ws.sid
            target_ip = server_ip or active_ws.server_ip
            _, mds_ip, port = await self._login_coordinator.resolve_target_ips(
                mgmt_name,
                active_ws.domain_name,
                explicit_server_ip=target_ip,
            )
        else:
            if not is_readonly:
                raise SessionStateError(
                    f"Mutating command {clean_cmd!r} is forbidden on shared read-only sid_cache. "
                    "Use an isolated client.write_session(...) or pass an explicit dedicated sid."
                )
            using_cached_sid = True
            active_auth_identity = (await self._login_coordinator.resolve_credentials(mgmt_name, domain)).identity_key
            active_sid, target_ip = await self._login_coordinator.get_readonly_session(
                mgmt_name,
                domain,
                server_ip=server_ip,
            )
            _, mds_ip, port = await self._login_coordinator.resolve_target_ips(
                mgmt_name,
                domain,
                explicit_server_ip=target_ip,
            )

        call_budget = timeout if timeout is not None else self._settings.api_timeout

        async def _execute_once(curr_sid: str, curr_ip: str, curr_mds_ip: str) -> ApiCallResult:
            async with self._rate_limiter.slot(curr_mds_ip):
                return await self._transport.execute(
                    curr_ip,
                    clean_cmd,
                    payload,
                    port=port,
                    sid=curr_sid,
                    timeout=call_budget,
                )

        try:
            res = await _execute_once(active_sid, target_ip, mds_ip)
        except ServerIdentityError:
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
                refreshed = await self._login_coordinator.refresh_domain_active_ip(mgmt_name, dom_key)
                if refreshed is not None and refreshed.active_ip and refreshed.active_ip != target_ip:
                    target_ip = refreshed.active_ip
                    mds_ip = refreshed.active_mds_ip or endpoint.host
                    if using_cached_sid:
                        await self._cache.evict_sid(mgmt_name, dom_key, auth_identity=active_auth_identity)
                        active_sid, target_ip = await self._login_coordinator.get_readonly_session(
                            mgmt_name,
                            domain,
                            server_ip=target_ip,
                            force_new=True,
                        )
                    res = await _execute_once(active_sid, target_ip, mds_ip)
                else:
                    raise
            else:
                raise

        # Handle session expiration on cached read-only session -> evict SID, re-login, and retry once
        is_self_show_session = clean_cmd.lower() == "show-session" and not (payload and payload.get("uid"))
        if using_cached_sid and is_session_expired_result(
            res,
            command="show-session" if is_self_show_session else None,
        ):
            await self._cache.evict_sid(mgmt_name, dom_key, auth_identity=active_auth_identity)
            active_sid, target_ip = await self._login_coordinator.get_readonly_session(
                mgmt_name,
                domain,
                server_ip=server_ip,
                force_new=True,
            )
            res = await _execute_once(active_sid, target_ip, mds_ip)

        # Handle domain failover error code returned in HTTP response (read-only commands only - C8)
        if (
            is_readonly
            and not res.success
            and server_ip is None
            and dom_key != SYSTEM_DOMAIN_SENTINEL
            and is_failover_or_unreachable_result(res)
        ):
            refreshed = await self._login_coordinator.refresh_domain_active_ip(mgmt_name, dom_key)
            if refreshed is not None and refreshed.active_ip and refreshed.active_ip != target_ip:
                target_ip = refreshed.active_ip
                mds_ip = refreshed.active_mds_ip or endpoint.host
                if using_cached_sid:
                    await self._cache.evict_sid(mgmt_name, dom_key, auth_identity=active_auth_identity)
                    active_sid, target_ip = await self._login_coordinator.get_readonly_session(
                        mgmt_name,
                        domain,
                        server_ip=target_ip,
                        force_new=True,
                    )
                res = await _execute_once(active_sid, target_ip, mds_ip)

        # If keepalive returned success=False, evict immediately from sid_cache
        if clean_cmd == "keepalive" and not res.success and using_cached_sid:
            await self._cache.evict_sid(mgmt_name, dom_key, auth_identity=active_auth_identity)

        # Poll asynchronous server tasks via TaskWaiter if requested
        if res.success and wait_for_task and clean_cmd != "show-task":
            task_ids = extract_task_ids(res.data)
            if task_ids:

                async def _poll_show_task(poll_payload: dict[str, Any]) -> ApiCallResult:
                    async with self._rate_limiter.slot(mds_ip):
                        return await self._transport.execute(
                            target_ip,
                            "show-task",
                            poll_payload,
                            port=port,
                            sid=active_sid,
                            timeout=None,  # Uses max(api_timeout, login_timeout) + 5s socket read timeout
                        )

                res = await self._task_waiter.wait_for_tasks(
                    task_ids,
                    _poll_show_task,
                    timeout=timeout if timeout is not None else self._settings.task_timeout,
                    initial_result=res,
                )

        # Update WriteSession overlay on mutation commands
        if active_ws is not None and (sid is None or sid == active_ws.sid):
            _update_overlay_from_command(active_ws.overlay, clean_cmd, payload, res)

        # Invalidate domain freshness memo on successful publish
        if clean_cmd == "publish" and res.success:
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
        is_ephemeral_db = self._owns_engine and ":memory:" in (self._settings.database_url or "")
        should_logout = is_ephemeral_db if logout is None else bool(logout)
        if self._db.is_initialized:
            await self._login_coordinator.logout_all(include_cached_readonly=should_logout)
        await self._transport.close()
        await self._db.close()


__all__ = [
    "AMgmtClient",
]
