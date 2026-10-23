"""Session lifecycle, hybrid/dynamic authentication, failover resolution, and stale session cleanup.

Implements `LoginCoordinator` and `SessionCleaner`:
- Persists shared read-only session identifiers (`sid`) in `sid_cache`, reuses unexpired
  SIDs (`age < session_expire_seconds`), and immediately evicts a SID on session expiration
  error or when `keepalive` returns `success=False`.
- Supports static (`api_key`, `credential`), hybrid, and `"dynamic"` authentication via
  `contextvars` (`AuthContext`) and `AuthProvider` (with fast-fail `InvalidCredentialsError`,
  credential eviction, and `on_auth_failed` notification).
- Serializes logins per MDS member (`active_mds_ip`) via `LoginGate`, waits
  `login_throttle_window` (`70s`) on Check Point login throttling (bounded by `login_max_wait`),
  and retries transient database revision/lock conditions (`Database revision is in progress`).
- Re-resolves domain `active_ip` and `active_mds_ip` from the MDS system domain on failover.
- Cleans up stale sessions via `SessionCleaner` and seeds the system domain SID on startup.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from typing import Any

from arodonata.adapters.checkpoint.rate_limiter import LoginGate, RateLimiter
from arodonata.adapters.checkpoint.transport import ApiTransport
from arodonata.core.config import ArodonataSettings, ServerEndpointConfig
from arodonata.core.context import AuthContext, UserContext, get_auth_context, get_user_context
from arodonata.core.errors import (
    ApiTimeoutError,
    AuthenticationError,
    ConfigurationError,
    InvalidCredentialsError,
    MissingConfigurationError,
    ServerIdentityError,
    TransportError,
)
from arodonata.core.models.common import ApiCallResult, utc_now
from arodonata.core.models.domains import DomainInfo, SIDCacheEntry
from arodonata.core.ports import AuthProvider, CachePort
from arodonata.core.telemetry import span_attrs, traced

SYSTEM_DOMAIN_SENTINEL = "System Data"


def normalize_domain_key(domain: str | None) -> str:
    """Normalize `domain=None` or `""` to `'System Data'` for `sid_cache` keys."""
    if not domain or not domain.strip():
        return SYSTEM_DOMAIN_SENTINEL
    return domain.strip()


def is_session_expired_result(result: ApiCallResult) -> bool:
    """Return `True` if `result` indicates an invalid or expired Check Point session (`sid`)."""
    if result.success:
        return False
    code = (result.error_code or "").lower()
    msg = (result.error_message or "").lower()
    if code in (
        "generic_err_invalid_session_id",
        "err_session_expired",
        "session_expired",
        "unauthorized",
    ):
        return True
    return any(
        token in msg
        for token in (
            "invalid session",
            "session expired",
            "session id is invalid",
            "wrong session id",
            "session is not valid",
            "unauthorized",
        )
    )


def is_login_throttled_result(result: ApiCallResult) -> bool:
    """Return `True` if `result` indicates Check Point per-IP login rate limiting / throttling."""
    if result.success:
        return False
    if result.status_code == 429:
        return True
    code = (result.error_code or "").lower()
    msg = (result.error_message or "").lower()
    return any(
        token in code or token in msg
        for token in (
            "too many login",
            "too many requests",
            "login rate",
            "throttl",
            "exceeded the maximum number of login",
            "try again later",
        )
    )


def is_transient_revision_lock_result(result: ApiCallResult) -> bool:
    """Return `True` if login failed transiently due to `Database revision is in progress` or lock contention."""
    if result.success:
        return False
    msg = (result.error_message or "").lower()
    code = (result.error_code or "").lower()
    return any(
        token in msg or token in code
        for token in (
            "database revision is in progress",
            "revision is in progress",
            "temporarily unavailable",
            "server is initializing",
        )
    )


def is_invalid_credentials_result(result: ApiCallResult) -> bool:
    """Return `True` if the server explicitly rejected login credentials (non-retryable)."""
    if result.success:
        return False
    if is_transient_revision_lock_result(result) or is_login_throttled_result(result):
        return False
    code = (result.error_code or "").lower()
    msg = (result.error_message or "").lower()
    return any(
        token in code or token in msg
        for token in (
            "authentication to server failed",
            "invalid credentials",
            "invalid api key",
            "invalid username or password",
            "access denied",
            "err_login_failed",
            "generic_err_login_failed",
        )
    )


def is_max_sessions_exceeded_result(result: ApiCallResult) -> bool:
    """Return `True` if login was refused because max sessions limit was reached."""
    if result.success:
        return False
    msg = (result.error_message or "").lower()
    return any(
        token in msg
        for token in (
            "maximum number of open sessions",
            "too many open sessions",
            "max sessions",
            "exceeded maximum allowed sessions",
        )
    )


def is_failover_or_unreachable_result(result: ApiCallResult) -> bool:
    """Return `True` if a domain server IP returned a standby/failover or unreachable error."""
    if result.success:
        return False
    code = (result.error_code or "").lower()
    msg = (result.error_message or "").lower()
    return any(
        token in code or token in msg
        for token in (
            "domain is not active",
            "standby domain",
            "active domain server",
            "domain server is unreachable",
            "failover",
            "err_domain_not_active",
        )
    )


def parse_domain_entry(mgmt_name: str, raw: dict[str, Any]) -> DomainInfo:
    """Parse a raw Check Point `show-domains` / `show-domain` dictionary into `DomainInfo`."""
    uid = str(raw.get("uid") or "")
    name = str(raw.get("name") or "")
    dom_type = str(raw.get("type") or raw.get("domain-type") or "domain")
    is_global = dom_type == "global" or name == "Global"

    servers_raw = raw.get("servers")
    servers_list: list[dict[str, Any]] = (
        [s for s in servers_raw if isinstance(s, dict)] if isinstance(servers_raw, list) else []
    )

    active_ip: str | None = raw.get("active_ip") or raw.get("active-ip")
    active_mds_ip: str | None = raw.get("active_mds_ip") or raw.get("active-mds-ip")
    standby_ips: list[str] = []

    for srv in servers_list:
        srv_ip = srv.get("ipv4-address") or srv.get("ipv6-address") or srv.get("ip")
        mds_obj = srv.get("multi-domain-server")
        mds_ip: str | None = None
        if isinstance(mds_obj, dict):
            mds_ip = mds_obj.get("ipv4-address") or mds_obj.get("ip")
        elif isinstance(srv.get("multi-domain-server-ip"), str):
            mds_ip = srv.get("multi-domain-server-ip")

        is_active = bool(srv.get("active"))
        if is_active:
            if isinstance(srv_ip, str) and srv_ip:
                active_ip = srv_ip
            if isinstance(mds_ip, str) and mds_ip:
                active_mds_ip = mds_ip
        elif isinstance(srv_ip, str) and srv_ip:
            standby_ips.append(srv_ip)

    if active_ip is None and servers_list:
        first_ip = servers_list[0].get("ipv4-address") or servers_list[0].get("ip")
        if isinstance(first_ip, str) and first_ip:
            active_ip = first_ip

    return DomainInfo(
        id=f"{mgmt_name}:{name}",
        mgmt_name=mgmt_name,
        uid=uid,
        name=name,
        domain_type=dom_type,
        active_ip=active_ip,
        active_mds_ip=active_mds_ip or active_ip,
        standby_ips=standby_ips,
        servers=servers_list,
        is_global=is_global,
        raw_data=dict(raw),
    )


class LoginCoordinator:
    """Coordinates read-only `sid_cache` reuse, dedicated write sessions, per-MDS-member
    login gating, throttle recovery (`70s`), dynamic credential resolution, and active
    domain failover IP re-resolution.
    """

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        transport: ApiTransport,
        cache: CachePort,
        login_gate: LoginGate,
        rate_limiter: RateLimiter,
        auth_provider: AuthProvider | None = None,
        session_cleaner: SessionCleaner | None = None,
        monotonic_fn: Callable[[], float] = time.monotonic,
        now_fn: Callable[[], datetime] = utc_now,
        sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._settings = settings
        self._transport = transport
        self._cache = cache
        self._login_gate = login_gate
        self._rate_limiter = rate_limiter
        self._auth_provider = auth_provider
        self._session_cleaner = session_cleaner
        self._monotonic = monotonic_fn
        self._now = now_fn
        self._sleep = sleep_fn

        self._domain_login_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._inflight_logins: set[str] = set()
        self._evicted_auth_identities: set[tuple[str, str]] = set()
        self._active_dedicated_sids: dict[tuple[str, str], str] = {}

    @property
    def active_dedicated_sids(self) -> dict[tuple[str, str], str]:
        """Mapping of `(mgmt_name, sid) -> server_ip` for open dedicated write sessions."""
        return dict(self._active_dedicated_sids)

    def bind_session_cleaner(self, cleaner: SessionCleaner) -> None:
        """Attach `SessionCleaner` for max-sessions recovery."""
        self._session_cleaner = cleaner

    def has_inflight_or_cached_login(self, mgmt_name: str, domain: str | None = None) -> bool:
        """Return `True` if a login is currently in flight for `(mgmt_name, domain)`."""
        dom_key = normalize_domain_key(domain)
        return f"{mgmt_name}:{dom_key}" in self._inflight_logins

    def get_server_endpoint(self, mgmt_name: str) -> ServerEndpointConfig:
        """Resolve `ServerEndpointConfig` for `mgmt_name` from `ArodonataSettings`."""
        servers = self._settings.servers
        if mgmt_name in servers:
            return servers[mgmt_name]
        if len(servers) == 1 and not mgmt_name:
            return next(iter(servers.values()))
        raise ConfigurationError(
            f"Unknown management server {mgmt_name!r}. Configured servers: {sorted(servers.keys())}."
        )

    async def resolve_target_ips(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        explicit_server_ip: str | None = None,
    ) -> tuple[str, str, int]:
        """Resolve `(server_ip, active_mds_ip, port)` for `(mgmt_name, domain)`."""
        endpoint = self.get_server_endpoint(mgmt_name)
        if explicit_server_ip:
            return explicit_server_ip, endpoint.host, endpoint.port

        dom_key = normalize_domain_key(domain)
        if dom_key != SYSTEM_DOMAIN_SENTINEL:
            cached_dom = await self._cache.get_domain(mgmt_name, dom_key)
            if cached_dom is not None:
                target_ip = cached_dom.active_ip or endpoint.host
                mds_ip = cached_dom.active_mds_ip or target_ip or endpoint.host
                return target_ip, mds_ip, endpoint.port

        return endpoint.host, endpoint.host, endpoint.port

    async def resolve_credentials(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        explicit_auth: AuthContext | None = None,
    ) -> AuthContext:
        """Resolve authentication credentials from explicit override, `contextvars`, `AuthProvider`, or static settings."""
        if explicit_auth is not None:
            if (mgmt_name, explicit_auth.identity_key) in self._evicted_auth_identities:
                raise InvalidCredentialsError(
                    f"Credentials for {explicit_auth.identity_key!r} on {mgmt_name!r} were previously rejected and evicted."
                )
            return explicit_auth

        ctx_auth = get_auth_context()
        if ctx_auth is not None:
            if (mgmt_name, ctx_auth.identity_key) in self._evicted_auth_identities:
                raise InvalidCredentialsError(
                    f"Credentials for {ctx_auth.identity_key!r} on {mgmt_name!r} were previously rejected and evicted."
                )
            return ctx_auth

        if self._auth_provider is not None:
            user_ctx = get_user_context()
            provided = await self._auth_provider.get_credentials(mgmt_name, domain, user=user_ctx)
            if (mgmt_name, provided.identity_key) in self._evicted_auth_identities:
                raise InvalidCredentialsError(
                    f"Credentials for {provided.identity_key!r} on {mgmt_name!r} were previously rejected and evicted."
                )
            return provided

        endpoint = self.get_server_endpoint(mgmt_name)
        if endpoint.api_key:
            return AuthContext(api_key=endpoint.api_key, user_id=f"static:{mgmt_name}")
        if self._settings.username and self._settings.password:
            return AuthContext(
                username=self._settings.username,
                password=self._settings.password,
                user_id=f"static:{self._settings.username}",
            )

        raise MissingConfigurationError(
            f"No credentials available for management server {mgmt_name!r} in auth_mode={self._settings.auth_mode!r}. "
            "Provide credentials via client.auth_context(...), AuthProvider, or static settings."
        )

    def has_static_credentials(self, mgmt_name: str | None = None) -> bool:
        """Return `True` if static startup credentials exist for `mgmt_name` (or all configured servers)."""
        if self._settings.auth_mode == "dynamic":
            return False
        if mgmt_name is not None:
            endpoint = self.get_server_endpoint(mgmt_name)
            return bool(endpoint.api_key or (self._settings.username and self._settings.password))
        return self._settings.auth_mode in ("api_key", "credential")

    def _is_sid_entry_fresh(self, entry: SIDCacheEntry) -> bool:
        """Return `True` if `entry` is younger than `session_expire_seconds` and not past `expires_at`."""
        now = self._now()
        if entry.expires_at is not None and now >= entry.expires_at:
            return False
        age = (now - entry.created_at).total_seconds()
        return age < float(self._settings.session_expire_seconds)

    @traced
    async def get_readonly_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        server_ip: str | None = None,
        force_new: bool = False,
    ) -> tuple[str, str]:
        """Return `(sid, server_ip)` for a shared read-only session, reusing `sid_cache` when fresh."""
        dom_key = normalize_domain_key(domain)
        lock_key = f"{mgmt_name}:{dom_key}"
        span_attrs(mgmt_name=mgmt_name, domain=dom_key, force_new=force_new)

        if not force_new:
            cached = await self._cache.get_sid(mgmt_name, dom_key)
            if cached is not None and self._is_sid_entry_fresh(cached):
                span_attrs(sid_reused=True)
                return cached.sid, (server_ip or cached.server_ip)

        async with self._domain_login_locks[lock_key]:
            if not force_new:
                cached = await self._cache.get_sid(mgmt_name, dom_key)
                if cached is not None and self._is_sid_entry_fresh(cached):
                    span_attrs(sid_reused=True)
                    return cached.sid, (server_ip or cached.server_ip)

            self._inflight_logins.add(lock_key)
            try:
                auth = await self.resolve_credentials(mgmt_name, domain)
                sid, resolved_ip, session_uid = await self._perform_gated_login(
                    mgmt_name,
                    domain,
                    auth=auth,
                    explicit_server_ip=server_ip,
                    read_only=False,
                )
                now = self._now()
                entry = SIDCacheEntry(
                    id=f"{mgmt_name}:{dom_key}",
                    mgmt_name=mgmt_name,
                    domain_name=dom_key,
                    sid=sid,
                    server_ip=resolved_ip,
                    session_uid=session_uid,
                    created_at=now,
                    last_used_at=now,
                    expires_at=now + timedelta(seconds=self._settings.session_expire_seconds),
                )
                await self._cache.upsert_sid(entry)
                span_attrs(sid_reused=False, server_ip=resolved_ip)
                return sid, resolved_ip
            finally:
                self._inflight_logins.discard(lock_key)

    @traced
    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        user: UserContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
        server_ip: str | None = None,
    ) -> tuple[str, str, str | None]:
        """Open an isolated dedicated session outside `sid_cache`, returning `(sid, server_ip, session_uid)`."""
        resolved_auth = await self.resolve_credentials(mgmt_name, domain, explicit_auth=auth)
        resolved_user = user or get_user_context()
        eff_name = session_name or (resolved_user.session_name if resolved_user else None)
        eff_desc = session_description or (resolved_user.session_description if resolved_user else None)

        sid, resolved_ip, session_uid = await self._perform_gated_login(
            mgmt_name,
            domain,
            auth=resolved_auth,
            explicit_server_ip=server_ip,
            session_name=eff_name,
            session_description=eff_desc,
            read_only=False,
        )
        self._active_dedicated_sids[(mgmt_name, sid)] = resolved_ip
        return sid, resolved_ip, session_uid

    async def _perform_gated_login(
        self,
        mgmt_name: str,
        domain: str | None,
        *,
        auth: AuthContext,
        explicit_server_ip: str | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
        read_only: bool = False,
    ) -> tuple[str, str, str | None]:
        """Authenticate against Check Point under `LoginGate` with throttle and transient retry handling."""
        dom_key = normalize_domain_key(domain)
        target_ip, mds_ip, port = await self.resolve_target_ips(
            mgmt_name,
            domain,
            explicit_server_ip=explicit_server_ip,
        )

        payload: dict[str, Any] = {
            "session-timeout": self._settings.session_timeout,
        }
        if auth.api_key:
            payload["api-key"] = auth.api_key
        else:
            payload["user"] = auth.username
            payload["password"] = auth.password

        if dom_key != SYSTEM_DOMAIN_SENTINEL:
            payload["domain"] = dom_key
        if session_name:
            payload["session-name"] = session_name
        if session_description:
            payload["session-description"] = session_description
        if read_only:
            payload["read-only"] = True

        deadline = self._monotonic() + float(self._settings.login_max_wait)
        transient_delay = 2.0
        cleaned_max_sessions = False
        failover_attempted = False

        while True:
            async with self._login_gate.acquire(mds_ip, wait_timeout=self._settings.login_max_wait):
                try:
                    res = await self._transport.execute(
                        target_ip,
                        "login",
                        payload,
                        port=port,
                        timeout=self._settings.login_timeout,
                    )
                except ServerIdentityError:
                    # Never retry TLS identity errors
                    raise
                except (ApiTimeoutError, TransportError) as exc:
                    if not failover_attempted and dom_key != SYSTEM_DOMAIN_SENTINEL and explicit_server_ip is None:
                        failover_attempted = True
                        refreshed = await self.refresh_domain_active_ip(mgmt_name, dom_key)
                        if refreshed is not None and refreshed.active_ip and refreshed.active_ip != target_ip:
                            target_ip = refreshed.active_ip
                            mds_ip = refreshed.active_mds_ip or target_ip
                            continue
                    if self._monotonic() + transient_delay >= deadline:
                        raise AuthenticationError(
                            f"Login to {mgmt_name!r} ({dom_key!r} at {target_ip}) timed out or failed: {exc}"
                        ) from exc
                    await self._sleep(transient_delay)
                    transient_delay = min(15.0, transient_delay * 2.0)
                    continue

            if res.success:
                sid = str(res.data.get("sid") or "")
                if not sid:
                    raise AuthenticationError(
                        f"Login to {mgmt_name!r} ({dom_key!r}) succeeded without returning a 'sid'."
                    )
                session_uid = res.data.get("uid")
                # Clear any previous eviction mark on success
                self._evicted_auth_identities.discard((mgmt_name, auth.identity_key))
                return sid, target_ip, (str(session_uid) if session_uid else None)

            # 1. Fast-fail on invalid credentials (never retry)
            if is_invalid_credentials_result(res):
                await self._handle_invalid_credentials(mgmt_name, dom_key, auth, res)

            # 2. Check Point per-IP login rate limit / throttling -> wait login_throttle_window (70s)
            if is_login_throttled_result(res):
                wait_sec = float(self._settings.login_throttle_window)
                if self._monotonic() + wait_sec > deadline:
                    raise AuthenticationError(
                        f"Login to {mgmt_name!r} ({dom_key!r}) throttled and exceeded login_max_wait="
                        f"{self._settings.login_max_wait}s: {res.error_message}"
                    )
                await self._sleep(wait_sec)
                continue

            # 3. Active domain server failover -> re-query MDS system domain and update active_ip
            if (
                not failover_attempted
                and dom_key != SYSTEM_DOMAIN_SENTINEL
                and explicit_server_ip is None
                and is_failover_or_unreachable_result(res)
            ):
                failover_attempted = True
                refreshed = await self.refresh_domain_active_ip(mgmt_name, dom_key)
                if refreshed is not None and refreshed.active_ip:
                    target_ip = refreshed.active_ip
                    mds_ip = refreshed.active_mds_ip or target_ip
                    continue

            # 4. Max sessions refusal -> trigger SessionCleaner once if available
            if not cleaned_max_sessions and is_max_sessions_exceeded_result(res) and self._session_cleaner is not None:
                cleaned_max_sessions = True
                await self._session_cleaner.cleanup_server_sessions(mgmt_name, domain=dom_key, auth=auth)
                continue

            # 5. Transient database revision / lock condition -> retry with backoff within login_max_wait
            if is_transient_revision_lock_result(res):
                if self._monotonic() + transient_delay > deadline:
                    raise AuthenticationError(
                        f"Login to {mgmt_name!r} ({dom_key!r}) exceeded login_max_wait="
                        f"{self._settings.login_max_wait}s waiting for database revision: {res.error_message}"
                    )
                await self._sleep(transient_delay)
                transient_delay = min(15.0, transient_delay * 2.0)
                continue

            raise AuthenticationError(
                f"Login to {mgmt_name!r} ({dom_key!r} at {target_ip}) failed: "
                f"{res.error_message or f'HTTP {res.status_code}'}"
            )

    async def _handle_invalid_credentials(
        self,
        mgmt_name: str,
        dom_key: str,
        auth: AuthContext,
        res: ApiCallResult,
    ) -> None:
        """Immediately evict cached SID and credentials, notify `AuthProvider`, and raise `InvalidCredentialsError`."""
        await self._cache.evict_sid(mgmt_name, dom_key)
        if self._settings.auth_mode == "dynamic" or get_auth_context() is not None or self._auth_provider is not None:
            self._evicted_auth_identities.add((mgmt_name, auth.identity_key))

        exc = InvalidCredentialsError(
            f"Authentication to {mgmt_name!r} ({dom_key!r}) rejected by server: "
            f"{res.error_message or 'Authentication to server failed'}"
        )
        if self._auth_provider is not None:
            await self._auth_provider.on_auth_failed(mgmt_name, auth, exc)
        raise exc

    @traced
    async def refresh_domain_active_ip(self, mgmt_name: str, domain_name: str) -> DomainInfo | None:
        """Query the MDS system domain (`show-domains` / `show-domain`) to update `active_ip` and `active_mds_ip`."""
        endpoint = self.get_server_endpoint(mgmt_name)
        span_attrs(mgmt_name=mgmt_name, domain=domain_name)

        try:
            sys_sid, sys_ip = await self.get_readonly_session(
                mgmt_name,
                None,
                server_ip=endpoint.host,
            )
            async with self._rate_limiter.slot(endpoint.host):
                res = await self._transport.execute(
                    sys_ip,
                    "show-domains",
                    {"details-level": "full", "limit": 500},
                    port=endpoint.port,
                    sid=sys_sid,
                    timeout=self._settings.api_timeout,
                )
            if is_session_expired_result(res):
                await self._cache.evict_sid(mgmt_name, SYSTEM_DOMAIN_SENTINEL)
                sys_sid, sys_ip = await self.get_readonly_session(
                    mgmt_name,
                    None,
                    server_ip=endpoint.host,
                    force_new=True,
                )
                async with self._rate_limiter.slot(endpoint.host):
                    res = await self._transport.execute(
                        sys_ip,
                        "show-domains",
                        {"details-level": "full", "limit": 500},
                        port=endpoint.port,
                        sid=sys_sid,
                        timeout=self._settings.api_timeout,
                    )
        except ServerIdentityError:
            raise
        except Exception:
            return None

        if not res.success:
            return None

        raw_domains = res.data.get("objects")
        if not isinstance(raw_domains, list):
            return None

        parsed_domains: list[DomainInfo] = []
        matched: DomainInfo | None = None
        for item in raw_domains:
            if isinstance(item, dict) and item.get("name"):
                dom_info = parse_domain_entry(mgmt_name, item)
                if not dom_info.active_mds_ip:
                    dom_info.active_mds_ip = endpoint.host
                parsed_domains.append(dom_info)
                if dom_info.name == domain_name:
                    matched = dom_info

        if parsed_domains:
            await self._cache.upsert_domains(parsed_domains)
        return matched

    @traced
    async def keepalive_sid(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        sid: str | None = None,
        server_ip: str | None = None,
    ) -> bool:
        """Send `keepalive` for a cached or explicit session; immediately evict from `sid_cache` on failure."""
        dom_key = normalize_domain_key(domain)
        cached = await self._cache.get_sid(mgmt_name, dom_key)
        target_sid = sid or (cached.sid if cached is not None else None)
        if not target_sid:
            return False

        endpoint = self.get_server_endpoint(mgmt_name)
        target_ip = server_ip or (cached.server_ip if cached is not None else endpoint.host)
        _, mds_ip, port = await self.resolve_target_ips(mgmt_name, domain, explicit_server_ip=target_ip)

        try:
            async with self._rate_limiter.slot(mds_ip):
                res = await self._transport.execute(
                    target_ip,
                    "keepalive",
                    {},
                    port=port,
                    sid=target_sid,
                    timeout=self._settings.api_timeout,
                )
        except ServerIdentityError:
            raise
        except Exception:
            if cached is not None and cached.sid == target_sid:
                await self._cache.evict_sid(mgmt_name, dom_key)
            return False

        if not res.success:
            if cached is not None and cached.sid == target_sid:
                await self._cache.evict_sid(mgmt_name, dom_key)
            return False

        if cached is not None and cached.sid == target_sid:
            now = self._now()
            updated = cached.model_copy(
                update={
                    "last_used_at": now,
                    "expires_at": now + timedelta(seconds=self._settings.session_expire_seconds),
                }
            )
            await self._cache.upsert_sid(updated)
        return True

    @traced
    async def sweep_keepalives(self, mgmt_name: str | None = None) -> dict[str, bool]:
        """Run a coalesced background keepalive sweep across cached read-only sessions."""
        sweep_key = f"keepalive:{mgmt_name or '*'}"

        async def _do_sweep() -> dict[str, bool]:
            entries = await self._cache.list_sids(mgmt_name=mgmt_name)
            outcomes: dict[str, bool] = {}
            for entry in entries:
                ok = await self.keepalive_sid(
                    entry.mgmt_name,
                    entry.domain_name,
                    sid=entry.sid,
                    server_ip=entry.server_ip,
                )
                outcomes[entry.id] = ok
            return outcomes

        return await self._rate_limiter.run_coalesced_keepalive(sweep_key, _do_sweep)

    @traced
    async def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> bool:
        """Log out a specific session identifier and remove it from `sid_cache` / dedicated tracking."""
        if not sid:
            return False
        endpoint = self.get_server_endpoint(mgmt_name)
        dedicated_ip = self._active_dedicated_sids.pop((mgmt_name, sid), None)
        target_ip = server_ip or dedicated_ip or endpoint.host

        # Also evict from sid_cache if this sid was cached there
        for entry in await self._cache.list_sids(mgmt_name=mgmt_name):
            if entry.sid == sid:
                await self._cache.evict_sid(entry.mgmt_name, entry.domain_name)

        try:
            async with self._rate_limiter.slot(endpoint.host):
                res = await self._transport.execute(
                    target_ip,
                    "logout",
                    {},
                    port=endpoint.port,
                    sid=sid,
                    timeout=self._settings.api_timeout,
                )
            return res.success
        except ServerIdentityError:
            raise
        except Exception:
            return False

    @traced
    async def logout_all(self, *, include_cached_readonly: bool = True) -> int:
        """Log out all dedicated sessions and optionally all cached read-only sessions."""
        logged_out = 0
        for (mgmt_name, sid), srv_ip in list(self._active_dedicated_sids.items()):
            if await self.logout_sid(mgmt_name, sid, server_ip=srv_ip):
                logged_out += 1

        if include_cached_readonly:
            for entry in await self._cache.list_sids():
                if await self.logout_sid(entry.mgmt_name, entry.sid, server_ip=entry.server_ip):
                    logged_out += 1
                else:
                    await self._cache.evict_sid(entry.mgmt_name, entry.domain_name)
        return logged_out


class SessionCleaner:
    """Cleans up stale or abandoned Check Point API sessions on startup and max-sessions refusal.

    Invariants:
    - When `schedule_startup_cleanup()` runs on client entry with static credentials and
      no cached SID or in-flight login exists for a server's system domain, the session
      opened by `SessionCleaner` is retained in `sid_cache` for subsequent read calls
      rather than logged out.
    - When `ArodonataClient` / `AMgmtClient` enters in `"dynamic"` auth mode before any
      administrator credentials have been supplied, startup session cleanup is skipped
      without raising an authentication error.
    """

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        login_coordinator: LoginCoordinator,
        transport: ApiTransport,
        cache: CachePort,
        rate_limiter: RateLimiter,
    ) -> None:
        self._settings = settings
        self._login_coordinator = login_coordinator
        self._transport = transport
        self._cache = cache
        self._rate_limiter = rate_limiter
        self._startup_tasks: set[asyncio.Task[Any]] = set()

    @property
    def startup_tasks(self) -> set[asyncio.Task[Any]]:
        """Currently running startup cleanup tasks."""
        return set(self._startup_tasks)

    def schedule_startup_cleanup(self) -> list[asyncio.Task[bool]]:
        """Schedule startup stale-session cleanup for all configured servers when static credentials exist."""
        if (
            self._settings.auth_mode == "dynamic"
            and get_auth_context() is None
            and self._login_coordinator._auth_provider is None
        ):
            return []

        tasks: list[asyncio.Task[bool]] = []
        for mgmt_name in self._settings.servers:
            if not self._login_coordinator.has_static_credentials(mgmt_name):
                continue
            task = asyncio.create_task(self.cleanup_server_sessions(mgmt_name, seed_system_sid=True))
            self._startup_tasks.add(task)
            task.add_done_callback(self._startup_tasks.discard)
            tasks.append(task)
        return tasks

    @traced
    async def run_startup_cleanup(self) -> dict[str, bool]:
        """Run startup session cleanup across all configured servers (skipping in cold dynamic mode)."""
        if (
            self._settings.auth_mode == "dynamic"
            and get_auth_context() is None
            and self._login_coordinator._auth_provider is None
        ):
            span_attrs(startup_cleanup_skipped=True, reason="dynamic_auth_mode")
            return {}

        outcomes: dict[str, bool] = {}
        for mgmt_name in self._settings.servers:
            if not self._login_coordinator.has_static_credentials(mgmt_name):
                continue
            outcomes[mgmt_name] = await self.cleanup_server_sessions(mgmt_name, seed_system_sid=True)
        return outcomes

    @traced
    async def cleanup_server_sessions(
        self,
        mgmt_name: str,
        *,
        domain: str | None = None,
        auth: AuthContext | None = None,
        seed_system_sid: bool = False,
    ) -> bool:
        """Inspect open Web API sessions on `mgmt_name` and discard stale/abandoned sessions."""
        if (
            self._settings.auth_mode == "dynamic"
            and auth is None
            and get_auth_context() is None
            and self._login_coordinator._auth_provider is None
        ):
            return False

        dom_key = normalize_domain_key(domain)
        endpoint = self._login_coordinator.get_server_endpoint(mgmt_name)
        span_attrs(mgmt_name=mgmt_name, domain=dom_key, seed_system_sid=seed_system_sid)

        existing_cached = await self._cache.get_sid(mgmt_name, dom_key)
        had_cached_or_inflight = existing_cached is not None or self._login_coordinator.has_inflight_or_cached_login(
            mgmt_name, domain
        )

        # Open a dedicated session to inspect/discard stale sessions
        sid, server_ip, session_uid = await self._login_coordinator.create_dedicated_session(
            mgmt_name,
            domain,
            auth=auth,
            session_name="arodonata-session-cleaner",
        )

        retain_in_cache = False
        try:
            async with self._rate_limiter.slot(endpoint.host):
                res = await self._transport.execute(
                    server_ip,
                    "show-sessions",
                    {"details-level": "standard", "limit": 100, "view-published-sessions": False},
                    port=endpoint.port,
                    sid=sid,
                    timeout=self._settings.api_timeout,
                )

            if res.success:
                sessions_list = res.data.get("objects")
                if isinstance(sessions_list, list):
                    for sess_obj in sessions_list:
                        if not isinstance(sess_obj, dict):
                            continue
                        target_uid = sess_obj.get("uid")
                        if not isinstance(target_uid, str) or not target_uid or target_uid == session_uid:
                            continue
                        is_stale = bool(
                            sess_obj.get("expired-session")
                            or (
                                sess_obj.get("application") == "WEB_API"
                                and int(sess_obj.get("changes") or 0) == 0
                                and int(sess_obj.get("locks") or 0) == 0
                                and str(sess_obj.get("session-name") or "").startswith("arodonata")
                            )
                        )
                        if is_stale:
                            async with self._rate_limiter.slot(endpoint.host):
                                await self._transport.execute(
                                    server_ip,
                                    "discard",
                                    {"uid": target_uid},
                                    port=endpoint.port,
                                    sid=sid,
                                    timeout=self._settings.api_timeout,
                                )

            # Check if we should seed `sid_cache` with this session instead of logging it out
            if seed_system_sid and dom_key == SYSTEM_DOMAIN_SENTINEL and not had_cached_or_inflight:
                current_cached = await self._cache.get_sid(mgmt_name, dom_key)
                if current_cached is None and not self._login_coordinator.has_inflight_or_cached_login(
                    mgmt_name, domain
                ):
                    now = self._login_coordinator._now()
                    entry = SIDCacheEntry(
                        id=f"{mgmt_name}:{dom_key}",
                        mgmt_name=mgmt_name,
                        domain_name=dom_key,
                        sid=sid,
                        server_ip=server_ip,
                        session_uid=session_uid,
                        created_at=now,
                        last_used_at=now,
                        expires_at=now + timedelta(seconds=self._settings.session_expire_seconds),
                    )
                    await self._cache.upsert_sid(entry)
                    self._login_coordinator._active_dedicated_sids.pop((mgmt_name, sid), None)
                    retain_in_cache = True
            return True
        finally:
            if not retain_in_cache:
                await self._login_coordinator.logout_sid(mgmt_name, sid, server_ip=server_ip)

    async def drain_startup_tasks(self, timeout: float = 5.0) -> None:
        """Wait up to `timeout` seconds for any background startup cleanup tasks to finish."""
        pending = [t for t in self._startup_tasks if not t.done()]
        if not pending:
            return
        _done, still_pending = await asyncio.wait(pending, timeout=timeout)
        for task in still_pending:
            task.cancel()
        if still_pending:
            await asyncio.gather(*still_pending, return_exceptions=True)


__all__ = [
    "SYSTEM_DOMAIN_SENTINEL",
    "LoginCoordinator",
    "SessionCleaner",
    "is_failover_or_unreachable_result",
    "is_invalid_credentials_result",
    "is_login_throttled_result",
    "is_max_sessions_exceeded_result",
    "is_session_expired_result",
    "is_transient_revision_lock_result",
    "normalize_domain_key",
    "parse_domain_entry",
]
