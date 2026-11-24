"""Session lifecycle, hybrid/dynamic authentication, failover resolution, and stale session cleanup.

Implements `LoginCoordinator` and re-exports `SessionCleaner`, domain parser,
response classifiers, and shared `logger`:
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
from contextlib import suppress
from datetime import datetime, timedelta
from typing import Protocol

from arodonata.adapters.checkpoint.rate_limiter import LoginGate, RateLimiter
from arodonata.adapters.checkpoint.response_classifiers import (
    is_failover_or_unreachable_result,
    is_invalid_credentials_result,
    is_login_throttled_result,
    is_max_sessions_exceeded_result,
    is_session_expired_result,
    is_transient_revision_lock_result,
    parse_domain_entry,
)
from arodonata.adapters.checkpoint.session_cleaner import SessionCleaner
from arodonata.adapters.checkpoint.session_credentials import (
    build_login_payload,
    handle_invalid_credentials,
    is_sid_entry_fresh,
    is_sid_entry_usable,
    resolve_auth_credentials,
)
from arodonata.adapters.checkpoint.target_resolver import (
    _canonicalize_host,
    _is_ip_literal,
    _resolve_hostname_ips,
    collect_trusted_hosts,
    fetch_domain_topology_from_mds,
    logger,
    resolve_active_mds_ip_for_target,
    resolve_failover_domain_ip,
    resolve_tls_identity_host,
    validate_explicit_server_ip,
)
from arodonata.adapters.checkpoint.transport import ApiTransport, derive_session_pool_scope
from arodonata.core.config import ArodonataSettings, ServerEndpointConfig
from arodonata.core.context import (
    SYSTEM_DOMAIN_KEY,
    AuthContext,
    UserContext,
    get_user_context,
    normalize_domain_key,
)
from arodonata.core.errors import (
    ApiTimeoutError,
    AuthenticationError,
    ConfigurationError,
    ServerIdentityError,
    TransportError,
)
from arodonata.core.models.common import ApiCallResult, utc_now
from arodonata.core.models.domains import DomainInfo, SIDCacheEntry
from arodonata.core.ports import AuthProvider, DomainCachePort, SidCachePort
from arodonata.core.telemetry import span_attrs, traced


class _LoginCachePort(DomainCachePort, SidCachePort, Protocol):
    """Combined domain + SID cache port required by `LoginCoordinator`."""


SYSTEM_DOMAIN_SENTINEL = SYSTEM_DOMAIN_KEY


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
        cache: _LoginCachePort,
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
        self._resolved_principals: dict[tuple[str, str], str] = {}
        self._active_dedicated_sids: dict[tuple[str, str], str] = {}
        self._known_mds_ips: dict[str, set[str]] = defaultdict(set)
        self._cleaning_max_sessions: set[str] = set()

    @staticmethod
    def _nonsecret_auth_fallback(auth: AuthContext) -> str:
        """Return non-secret fallback label when no username has been resolved yet."""
        if auth.user_id and auth.user_id.strip():
            uid = auth.user_id.strip()
            if not (auth.api_key and uid.startswith("static:")):
                return uid
        return "api_key"

    def _resolve_principal_label(self, mgmt_name: str, auth: AuthContext) -> str:
        """Return non-secret administrator name (or 'api_key' before first login) for logs; never returns secrets."""
        if auth.username and auth.username.strip():
            return auth.username.strip()
        cached_name = self._resolved_principals.get((mgmt_name, auth.identity_key))
        if cached_name:
            return cached_name
        return self._nonsecret_auth_fallback(auth)

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

    async def _collect_trusted_hosts(
        self,
        mgmt_name: str,
        endpoint_host: str,
    ) -> tuple[set[str], list[DomainInfo]]:
        """Collect canonicalized trusted host/IP strings and cached `DomainInfo` rows for `mgmt_name`."""
        return await collect_trusted_hosts(
            cache=self._cache,
            known_mds_ips=self._known_mds_ips.get(mgmt_name, set()),
            active_dedicated_sids=self._active_dedicated_sids,
            mgmt_name=mgmt_name,
            endpoint_host=endpoint_host,
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
            return await validate_explicit_server_ip(
                mgmt_name=mgmt_name,
                domain=domain,
                explicit_server_ip=explicit_server_ip,
                endpoint=endpoint,
                collect_hosts_fn=self._collect_trusted_hosts,
                refresh_domain_fn=self.refresh_domain_active_ip,
            )

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
        endpoint = self.get_server_endpoint(mgmt_name)
        return await resolve_auth_credentials(
            mgmt_name=mgmt_name,
            domain=domain,
            settings=self._settings,
            endpoint=endpoint,
            auth_provider=self._auth_provider,
            evicted_identities=self._evicted_auth_identities,
            explicit_auth=explicit_auth,
        )

    def has_static_credentials(self, mgmt_name: str | None = None) -> bool:
        """Return `True` if static startup credentials exist for `mgmt_name` (or all configured servers)."""
        if self._settings.auth_mode == "dynamic":
            return False
        if mgmt_name is not None:
            endpoint = self.get_server_endpoint(mgmt_name)
            return bool(endpoint.api_key or (self._settings.username and self._settings.password))
        return self._settings.auth_mode in ("api_key", "credential")

    def now(self) -> datetime:
        """Return the current UTC timestamp using the coordinator's injected clock."""
        return self._now()

    def has_dynamic_auth_provider(self) -> bool:
        """Return `True` if a fallback `AuthProvider` callback is configured."""
        return self._auth_provider is not None

    def is_sid_entry_fresh(self, entry: SIDCacheEntry) -> bool:
        """Return `True` if `entry` is still fresh.

        When `expires_at` is present it takes precedence (`now < expires_at`); otherwise the sliding window applies,
        i.e. the age since `last_used_at` (falling back to `created_at`) is below `session_expire_seconds`.
        """
        return is_sid_entry_fresh(
            entry,
            now=self._now(),
            session_expire_seconds=self._settings.session_expire_seconds,
        )

    def adopt_dedicated_sid(self, mgmt_name: str, sid: str) -> None:
        """Release `sid` from dedicated-session logout tracking after seeding it into `sid_cache`."""
        self._active_dedicated_sids.pop((mgmt_name, sid), None)

    def _is_sid_entry_usable(self, entry: SIDCacheEntry, auth: AuthContext) -> bool:
        """Return `True` if `entry` is fresh and belongs to the exact same `auth.identity_key` (`C4`)."""
        return is_sid_entry_usable(
            entry,
            auth,
            now=self._now(),
            session_expire_seconds=self._settings.session_expire_seconds,
        )

    @traced
    async def get_readonly_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        server_ip: str | None = None,
        force_new: bool = False,
    ) -> tuple[str, str]:
        """Return `(sid, server_ip)` for a shared read-only session, reusing `arodonata_sid_cache` when fresh."""
        dom_key = normalize_domain_key(domain)
        span_attrs(mgmt_name=mgmt_name, domain=dom_key, force_new=force_new)

        validated_ip: str | None = None
        if server_ip:
            validated_ip, _, _ = await self.resolve_target_ips(
                mgmt_name,
                domain,
                explicit_server_ip=server_ip,
            )

        auth = await self.resolve_credentials(mgmt_name, domain)
        identity = auth.identity_key
        lock_key = f"{mgmt_name}:{dom_key}:{identity}"

        if not force_new:
            cached = await self._cache.get_sid(mgmt_name, dom_key, auth_identity=identity)
            if cached is not None and self._is_sid_entry_usable(cached, auth):
                span_attrs(sid_reused=True)
                return cached.sid, (validated_ip or cached.server_ip)

        async with self._domain_login_locks[lock_key]:
            if not force_new:
                cached = await self._cache.get_sid(mgmt_name, dom_key, auth_identity=identity)
                if cached is not None and self._is_sid_entry_usable(cached, auth):
                    span_attrs(sid_reused=True)
                    return cached.sid, (validated_ip or cached.server_ip)

            self._inflight_logins.add(f"{mgmt_name}:{dom_key}")
            try:
                sid, resolved_ip, session_uid = await self._perform_gated_login(
                    mgmt_name,
                    domain,
                    auth=auth,
                    explicit_server_ip=server_ip,
                    read_only=True,
                )
                now = self._now()
                entry = SIDCacheEntry(
                    id=f"{mgmt_name}:{dom_key}:{identity}",
                    mgmt_name=mgmt_name,
                    domain_name=dom_key,
                    sid=sid,
                    server_ip=resolved_ip,
                    session_uid=session_uid,
                    auth_identity=identity,
                    created_at=now,
                    last_used_at=now,
                    expires_at=now + timedelta(seconds=self._settings.session_expire_seconds),
                )
                await self._cache.upsert_sid(entry)
                span_attrs(sid_reused=False, server_ip=resolved_ip)
                return sid, resolved_ip
            finally:
                self._inflight_logins.discard(f"{mgmt_name}:{dom_key}")

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
        allow_max_sessions_cleanup: bool = True,
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
            allow_max_sessions_cleanup=allow_max_sessions_cleanup,
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
        allow_max_sessions_cleanup: bool = True,
    ) -> tuple[str, str, str | None]:
        """Authenticate against Check Point under `LoginGate` with throttle and transient retry handling."""
        dom_key = normalize_domain_key(domain)
        target_ip, mds_ip, port = await self.resolve_target_ips(
            mgmt_name,
            domain,
            explicit_server_ip=explicit_server_ip,
        )
        tls_identity_host = resolve_tls_identity_host(explicit_server_ip, target_ip)

        payload = build_login_payload(
            session_timeout=self._settings.session_timeout,
            auth=auth,
            dom_key=dom_key,
            session_name=session_name,
            session_description=session_description,
            read_only=read_only,
        )

        deadline = self._monotonic() + float(self._settings.login_max_wait)
        transient_delay = 2.0
        cleaned_max_sessions = False
        failover_attempted = False
        transport_retries = 0
        max_transport_retries = 1

        while True:
            rem_wait = max(0.1, deadline - self._monotonic())
            transport_exc: Exception | None = None
            res: ApiCallResult | None = None

            async with self._login_gate.acquire(mds_ip, wait_timeout=rem_wait):
                try:
                    res = await self._transport.execute(
                        target_ip,
                        "login",
                        payload,
                        port=port,
                        timeout=self._settings.login_timeout,
                        tls_identity_host=tls_identity_host,
                    )
                except ServerIdentityError:
                    raise
                except (ApiTimeoutError, TransportError) as exc:
                    transport_exc = exc

            # Handle transport / timeout errors OUTSIDE LoginGate so refresh_domain_active_ip
            # and backoff sleep never hold or deadlock LoginGate(mds_ip) (C7, W4, W5)
            if transport_exc is not None:
                if (
                    not failover_attempted
                    and dom_key != SYSTEM_DOMAIN_SENTINEL
                    and explicit_server_ip is None
                    and target_ip != self.get_server_endpoint(mgmt_name).host
                ):
                    failover_attempted = True
                    switched = await resolve_failover_domain_ip(
                        mgmt_name=mgmt_name,
                        dom_key=dom_key,
                        target_ip=target_ip,
                        require_change=True,
                        reason="switched after transport error",
                        refresh_domain_fn=self.refresh_domain_active_ip,
                    )
                    if switched is not None:
                        target_ip, mds_ip = switched
                        transport_retries = 0
                        transient_delay = 2.0
                        continue
                if isinstance(transport_exc, ApiTimeoutError) and transport_exc.phase == "read":
                    principal = self._resolve_principal_label(mgmt_name, auth)
                    self._login_gate.record_cooldown(mds_ip, transient_delay, principal=principal)
                    logger.warning(
                        f"Login to '{mgmt_name}:{dom_key}' ({mds_ip}, user='{principal}') timed out during read phase; "
                        f"applying {transient_delay:.1f}s cooldown before retry.",
                        mgmt_name=mgmt_name,
                        domain=dom_key,
                        mds_ip=mds_ip,
                        user=principal,
                        cooldown_seconds=transient_delay,
                    )
                if transport_retries >= max_transport_retries or self._monotonic() + transient_delay >= deadline:
                    logger.warning(
                        f"Login to '{mgmt_name}:{dom_key}' ({target_ip}) failed: {transport_exc}",
                        mgmt_name=mgmt_name,
                        domain=dom_key,
                        target_ip=target_ip,
                    )
                    raise AuthenticationError(
                        f"Login to {mgmt_name!r} ({dom_key!r} at {target_ip}) timed out or failed: {transport_exc}"
                    ) from transport_exc
                transport_retries += 1
                if not (isinstance(transport_exc, ApiTimeoutError) and transport_exc.phase == "read"):
                    logger.warning(
                        f"Login to '{mgmt_name}:{dom_key}' ({target_ip}) failed ({transport_exc}); "
                        f"retrying in {transient_delay:.1f}s.",
                        mgmt_name=mgmt_name,
                        domain=dom_key,
                        target_ip=target_ip,
                    )
                await self._sleep(transient_delay)
                transient_delay = min(15.0, transient_delay * 2.0)
                continue

            assert res is not None
            if res.success:
                sid = str(res.data.get("sid") or "")
                if not sid:
                    raise AuthenticationError(
                        f"Login to {mgmt_name!r} ({dom_key!r}) succeeded without returning a 'sid'."
                    )
                resolved_user = res.data.get("user-name")
                if isinstance(resolved_user, str) and resolved_user.strip():
                    self._resolved_principals[(mgmt_name, auth.identity_key)] = resolved_user.strip()
                session_uid = res.data.get("uid")
                self._evicted_auth_identities.discard((mgmt_name, auth.identity_key))
                return sid, target_ip, (str(session_uid) if session_uid else None)

            # 1. Fast-fail on invalid credentials (never retry)
            if is_invalid_credentials_result(res):
                await self._handle_invalid_credentials(mgmt_name, dom_key, auth, res)

            # 2. Check Point per-IP login rate limit / throttling -> record shared gate cooldown & wait (W4)
            if is_login_throttled_result(res):
                wait_sec = float(self._settings.login_throttle_window)
                principal = self._resolve_principal_label(mgmt_name, auth)
                self._login_gate.record_cooldown(mds_ip, wait_sec, principal=principal)
                if self._monotonic() + wait_sec > deadline:
                    raise AuthenticationError(
                        f"Login to {mgmt_name!r} ({dom_key!r}) throttled and exceeded login_max_wait="
                        f"{self._settings.login_max_wait}s: {res.error_message}"
                    )
                logger.warning(
                    f"Login to '{mgmt_name}:{dom_key}' ({mds_ip}, user='{principal}') throttled by server; "
                    f"waiting {wait_sec:.0f}s before retry.",
                    mgmt_name=mgmt_name,
                    domain=dom_key,
                    mds_ip=mds_ip,
                    user=principal,
                    cooldown_seconds=wait_sec,
                )
                await self._sleep(wait_sec)
                continue

            # 3. Active domain server failover or cold domain IP resolution -> re-query MDS system domain
            if (
                not failover_attempted
                and dom_key != SYSTEM_DOMAIN_SENTINEL
                and explicit_server_ip is None
                and (is_failover_or_unreachable_result(res) or target_ip == self.get_server_endpoint(mgmt_name).host)
            ):
                failover_attempted = True
                switched = await resolve_failover_domain_ip(
                    mgmt_name=mgmt_name,
                    dom_key=dom_key,
                    target_ip=target_ip,
                    require_change=False,
                    reason="resolved",
                    refresh_domain_fn=self.refresh_domain_active_ip,
                )
                if switched is not None:
                    target_ip, mds_ip = switched
                    continue

            # 4. Max sessions refusal -> trigger SessionCleaner once (guarded against recursion) if available
            if (
                allow_max_sessions_cleanup
                and not cleaned_max_sessions
                and mgmt_name not in self._cleaning_max_sessions
                and is_max_sessions_exceeded_result(res)
                and self._session_cleaner is not None
            ):
                cleaned_max_sessions = True
                logger.debug(
                    f"Max open sessions reached on '{mgmt_name}:{dom_key}'; running session cleanup.",
                    mgmt_name=mgmt_name,
                    domain=dom_key,
                )
                self._cleaning_max_sessions.add(mgmt_name)
                try:
                    cleaned = await self._session_cleaner.cleanup_server_sessions(
                        mgmt_name,
                        domain=dom_key,
                        auth=auth,
                    )
                finally:
                    self._cleaning_max_sessions.discard(mgmt_name)
                if cleaned:
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
        await handle_invalid_credentials(
            mgmt_name=mgmt_name,
            dom_key=dom_key,
            auth=auth,
            res=res,
            cache=self._cache,
            settings=self._settings,
            auth_provider=self._auth_provider,
            evicted_identities=self._evicted_auth_identities,
        )

    @traced
    async def refresh_domain_active_ip(self, mgmt_name: str, domain_name: str) -> DomainInfo | None:
        """Query the MDS system domain (`show-domains` / `show-global-domain` / `show-mdss`) to update `active_ip` and `active_mds_ip`."""
        endpoint = self.get_server_endpoint(mgmt_name)
        span_attrs(mgmt_name=mgmt_name, domain=domain_name)

        async def _resolve_sys_identity() -> str | None:
            with suppress(Exception):
                return (await self.resolve_credentials(mgmt_name, None)).identity_key
            return None

        return await fetch_domain_topology_from_mds(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            endpoint=endpoint,
            transport=self._transport,
            cache=self._cache,
            rate_limiter=self._rate_limiter,
            settings=self._settings,
            known_mds_ips=self._known_mds_ips[mgmt_name],
            get_readonly_session_fn=self.get_readonly_session,
            resolve_identity_fn=_resolve_sys_identity,
        )

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
        cached: SIDCacheEntry | None = None
        if sid:
            for entry in await self._cache.list_sids(mgmt_name=mgmt_name):
                if entry.sid == sid:
                    cached = entry
                    break
        if cached is None:
            resolved_identity: str | None = None
            try:
                resolved_identity = (await self.resolve_credentials(mgmt_name, domain)).identity_key
            except Exception:
                resolved_identity = None
            cached = await self._cache.get_sid(mgmt_name, dom_key, auth_identity=resolved_identity)
        target_sid = sid or (cached.sid if cached is not None else None)
        if not target_sid:
            return False

        endpoint = self.get_server_endpoint(mgmt_name)
        raw_target_ip = server_ip or (cached.server_ip if cached is not None else endpoint.host)
        target_ip, mds_ip, port = await self.resolve_target_ips(mgmt_name, domain, explicit_server_ip=raw_target_ip)
        tls_identity_host = resolve_tls_identity_host(raw_target_ip, target_ip)

        try:
            async with self._rate_limiter.slot(mds_ip):
                res = await self._transport.execute(
                    target_ip,
                    "keepalive",
                    {},
                    port=port,
                    sid=target_sid,
                    timeout=self._settings.api_timeout,
                    tls_identity_host=tls_identity_host,
                )
        except ServerIdentityError:
            raise
        except Exception:
            if cached is not None and cached.sid == target_sid:
                await self._cache.evict_sid(mgmt_name, cached.domain_name, auth_identity=cached.auth_identity)
            return False

        if not res.success:
            if cached is not None and cached.sid == target_sid:
                await self._cache.evict_sid(mgmt_name, cached.domain_name, auth_identity=cached.auth_identity)
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
        """Log out a specific session identifier and remove it from `arodonata_sid_cache` / dedicated tracking (`W7`)."""
        if not sid:
            return False
        endpoint = self.get_server_endpoint(mgmt_name)
        dedicated_ip = self._active_dedicated_sids.get((mgmt_name, sid))
        cached_entries = await self._cache.list_sids(mgmt_name=mgmt_name)
        matching_entries = [entry for entry in cached_entries if entry.sid == sid]

        if server_ip:
            target_ip, mds_ip, port = await self.resolve_target_ips(
                mgmt_name,
                explicit_server_ip=server_ip,
            )
            tls_identity_host = resolve_tls_identity_host(server_ip, target_ip)
        else:
            cached_ip = matching_entries[0].server_ip if matching_entries else None
            target_ip = dedicated_ip or cached_ip or endpoint.host
            mds_ip = endpoint.host
            port = endpoint.port
            tls_identity_host = None
            if target_ip != endpoint.host:
                cached_domains = await self._cache.get_domains(mgmt_name, include_global=True)
                mds_ip = resolve_active_mds_ip_for_target(target_ip, endpoint.host, cached_domains)

        for entry in matching_entries:
            await self._cache.evict_sid(
                entry.mgmt_name,
                entry.domain_name,
                auth_identity=entry.auth_identity,
            )

        scope = derive_session_pool_scope(sid)
        self._transport.connection_pool.close_session_scope(scope)
        try:
            async with self._rate_limiter.slot(mds_ip):
                res = await self._transport.execute(
                    target_ip,
                    "logout",
                    {},
                    port=port,
                    sid=sid,
                    timeout=self._settings.api_timeout,
                    tls_identity_host=tls_identity_host,
                )
            if res.success:
                self._active_dedicated_sids.pop((mgmt_name, sid), None)
            return res.success
        except ServerIdentityError:
            raise
        except Exception:
            return False
        finally:
            self._transport.connection_pool.close_session_scope(scope)

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
                    await self._cache.evict_sid(
                        entry.mgmt_name,
                        entry.domain_name,
                        auth_identity=entry.auth_identity,
                    )
        return logged_out


__all__ = [
    "SYSTEM_DOMAIN_SENTINEL",
    "LoginCoordinator",
    "SessionCleaner",
    "_canonicalize_host",
    "_is_ip_literal",
    "_resolve_hostname_ips",
    "is_failover_or_unreachable_result",
    "is_invalid_credentials_result",
    "is_login_throttled_result",
    "is_max_sessions_exceeded_result",
    "is_session_expired_result",
    "is_transient_revision_lock_result",
    "logger",
    "normalize_domain_key",
    "parse_domain_entry",
]
