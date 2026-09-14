"""Login coordinator for session management with domain resolution.

Handles login orchestration with proper locking, retry logic,
and session caching.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Never

from arlogi.otel.decorator import traced

from ..cache.lock_manager import DatabaseLockManager
from ..config import (
    CREDENTIAL_REJECTION_MESSAGE,
    GLOBAL_DOMAIN_NAME,
    LOGIN_THROTTLE_WINDOW_SECONDS,
    SERVER_UNREACHABLE_MESSAGE,
    SESSION_ERROR_CODES,
    THROTTLE_ERROR_CODE,
)
from ..logger import lazy_logger
from ..telemetry import span_attrs

if TYPE_CHECKING:
    from ..cache import CacheRepository
    from ..config import ArodonataSettings
    from .rate_limiter import RateLimiter
    from .server_registry import ServerRegistry
    from .session_cleaner import SessionCleaner
    from .transport import ApiTransport

log = lazy_logger("arodonata.asdk.login_coordinator")


# How many full throttle windows to wait out before giving up on a login. The
# retry sequence holds a rate-limiter slot throughout, so waiting all
# DEFAULT_LOGIN_RETRIES attempts at LOGIN_THROTTLE_WINDOW_SECONDS each would pin
# one of three slots for ~9 minutes and outlive the login lock's TTL. If three
# consecutive windows have not cleared the lockout, the cause is systemic -- more
# login pressure on that IP than its per-minute allowance -- and failing says so
# sooner.
LOGIN_THROTTLE_MAX_WAITS = 3


def _login_failure_kind(exc: BaseException) -> str:
    """Classify a login failure as "throttle", "refusal", "timeout" or "unreachable".

    The classification decides the remedy, and the four cases want different ones:

    * **throttle** -- we exceeded Check Point's per-minute login allowance for
      this user and IP. Clears only after a wait longer than the window itself,
      so it gets LOGIN_THROTTLE_WINDOW_SECONDS rather than the ramp.
    * **refusal** -- the server answered and said no for now: Check Point's
      "Database revision is in progress" during the window after a revert, for
      instance. The address is right and the condition clears on its own, so retry
      it with backoff. This is the default for anything unrecognized.
    * **timeout** -- no answer yet, and the one failure that cannot be classified
      on the spot: a slow server and a dead one look identical until one of them
      eventually answers. Retried like any other transient failure, for the full
      budget; only once that is spent is the address itself treated as suspect.
      Calling it sooner cost three green integration buckets on 2026-09-13, when
      domain servers that were merely slow got written off.
    * **unreachable** -- conclusive: the socket was refused or unroutable, or Check
      Point itself said it cannot reach the target server. Nothing is listening,
      so re-resolve the domain's active server rather than knocking again.

    `TimeoutError` is checked first because it is an `OSError` subclass and would
    otherwise be swallowed by the socket-error branch.
    """
    from ..core.exceptions import ApiConnectionError, ThrottlingError

    if isinstance(exc, ThrottlingError) or THROTTLE_ERROR_CODE in str(exc):
        return "throttle"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, OSError | ApiConnectionError) or SERVER_UNREACHABLE_MESSAGE in str(exc):
        return "unreachable"
    return "refusal"


class LoginCoordinator:
    """Handles login operations with domain active server resolution.

    Manages distributed locks per (mgmt_name, domain) to prevent concurrent
    login attempts across multiple workers and implements proper retry logic with backoff.

    Example:
        coordinator = LoginCoordinator(
            registry=server_registry,
            transport=transport,
            rate_limiter=rate_limiter,
            cache=cache_repository,
            settings=settings,
        )
        sid, server_ip = await coordinator.login("mgmt1", "domain1")
    """

    def __init__(
        self,
        registry: ServerRegistry,
        transport: ApiTransport,
        rate_limiter: RateLimiter,
        cache: CacheRepository,
        settings: ArodonataSettings,
        lock_manager: DatabaseLockManager | None = None,
        session_cleaner: SessionCleaner | None = None,
    ) -> None:
        """Initialize login coordinator.

        Args:
            registry: Server registry instance.
            transport: API transport instance.
            rate_limiter: Rate limiter instance.
            cache: Cache repository instance.
            settings: Configuration settings.
            lock_manager: Optional DatabaseLockManager instance.
            session_cleaner: Optional SessionCleaner for max-sessions cleanup.
        """
        self._registry = registry
        self._transport = transport
        self._rate_limiter = rate_limiter
        self._cache = cache
        self._settings = settings
        self._lock_manager = lock_manager
        self._session_cleaner = session_cleaner
        self._in_process_locks: dict[str, asyncio.Lock] = {}  # For in-process synchronization
        self._lock_init_lock = asyncio.Lock()  # Protection for lock manager initialization
        self._keepalive_sweep_lock = asyncio.Lock()  # At most one keepalive sweep in flight
        self._closed = False

        # Credential-based auth support
        self._auth_mode = settings.auth_mode
        self._username: str | None = settings.username
        self._password_secret = settings.password  # SecretStr | None

        log().trace(f"LoginCoordinator initialized (auth_mode={self._auth_mode})")

    @property
    def _throttle_window(self) -> int:
        """Seconds to wait for Check Point's login rate limit to clear.

        Read from settings rather than the constant so a deployment whose server
        enforces a different limit -- or a caller that knows it will not meet a
        real throttle -- is not made to wait out a window that does not apply.
        """
        window = getattr(self._settings, "login_throttle_window", LOGIN_THROTTLE_WINDOW_SECONDS)
        return window if isinstance(window, int) else LOGIN_THROTTLE_WINDOW_SECONDS

    @property
    def _credential_username(self) -> str | None:
        """Username to scope the SID cache key in credential mode; None for api-key mode."""
        return self._username if self._auth_mode == "credential" else None

    async def close(self) -> None:
        """Clean up resources.

        Note: This method does NOT logout sessions - they remain cached in the
        database for reuse across application runs. Use logout() or logout_all()
        explicitly if you need to invalidate sessions on the server.
        """
        if not self._closed:
            self._closed = True
            if self._lock_manager:
                await self._lock_manager.close()
            self._in_process_locks.clear()
            log().debug("LoginCoordinator closed")

    async def _get_lock_manager(self) -> DatabaseLockManager:
        """Get or create lock manager instance.

        Uses the global lock manager if available to reuse database connections.

        Returns:
            DatabaseLockManager instance.
        """
        if self._lock_manager is None:
            async with self._lock_init_lock:
                if self._lock_manager is None:
                    from ..cache import _get_global_lock_manager

                    # Await _get_global_lock_manager and ensure it's not None
                    manager = await _get_global_lock_manager()
                    if manager is None:
                        raise RuntimeError("Failed to initialize DatabaseLockManager from global instance")
                    self._lock_manager = manager
                    await self._lock_manager.initialize()

        assert self._lock_manager is not None
        return self._lock_manager

    def _normalize_domain(self, mgmt_name: str, domain: str) -> str:
        """Normalize domain name, mapping aliases to the system domain.

        Maps:
          - "SMC User" -> "" (for Standalone/Smart Center)
          - "System Data" -> "" (for MDM/MDS)

        Args:
            mgmt_name: Management server name.
            domain: Domain name.

        Returns:
            Normalized domain name (empty string for system domain).
        """
        if not domain:
            return ""

        lower_domain = domain.lower()
        server = self._registry.get_server(mgmt_name)

        if not server:
            return domain

        # Check Point standard alias for Standalone server system domain
        # Also normalize when is_mdm is None (not yet detected) to avoid cache misses
        if lower_domain == "smc user" and server.is_mdm is not True:
            return ""

        # Check Point standard alias for MDM server system domain
        # Also normalize when is_mdm is None (not yet detected) to avoid cache misses
        if lower_domain == "system data" and server.is_mdm is not False:
            return ""

        return domain

    @traced
    async def _cleanup_for_max_sessions(
        self,
        mgmt_name: str,
        domain: str,
        server_ip: str,
        api_key: str,
        port: int | None,
        reason: str = "max sessions reached",
    ) -> None:
        """Acquire a temporary SID, run session cleanup, then logout temp SID.

        Called when login fails with the max-sessions error, or proactively at
        startup to discard leftover stale sessions. Uses a direct
        transport.login call to bypass coordinator logic and avoid recursion.

        Args:
            mgmt_name: Management server name (for logging and cleanup).
            domain: Domain name (for logging and cleanup).
            server_ip: Management server IP.
            api_key: API key for the temporary login.
            port: Optional port number.
            reason: Free-text reason for the cleanup (used only in the log message).
        """
        span_attrs(mgmt_name=mgmt_name, domain=domain or "system", reason=reason)
        if not self._session_cleaner:
            return

        log().info(f"Session cleanup for '{mgmt_name}:{domain}' ({reason}): acquiring temp SID...")
        async with self._rate_limiter.acquire(server_ip):
            if self._auth_mode == "credential" and self._username and self._password_secret:
                tmp_response = await self._transport.login_with_credentials(
                    server_ip=server_ip,
                    username=self._username,
                    password=self._password_secret.get_secret_value(),
                    domain=domain if domain else None,
                    port=port,
                    session_name="MMP-cleanup",
                    session_description="Temporary session for stale session cleanup",
                )
            else:
                tmp_response = await self._transport.login_with_apikey(
                    server_ip=server_ip,
                    api_key=api_key,
                    domain=domain if domain else None,
                    port=port,
                    session_name="MMP-cleanup",
                    session_description="Temporary session for stale session cleanup",
                )
        if not tmp_response.get("success") or not tmp_response.get("sid"):
            log().warning(f"Could not acquire temp SID for cleanup: {tmp_response.get('message')}")
            return

        tmp_sid = str(tmp_response["sid"])
        try:
            cleanup_result = await self._session_cleaner.cleanup_stale_sessions(
                mgmt_name=mgmt_name,
                domain=domain,
                system_sid=tmp_sid,
                server_ip=server_ip,
                port=port,
            )
            span_attrs(
                **{
                    "cleanup.discarded": cleanup_result.discarded,
                    "cleanup.skipped": cleanup_result.skipped,
                    "cleanup.errors": len(cleanup_result.errors),
                }
            )
            log().trace(
                f"Session cleanup for '{mgmt_name}:{domain}': "
                f"discarded={cleanup_result.discarded}, skipped={cleanup_result.skipped}, "
                f"errors={len(cleanup_result.errors)}"
            )
        except Exception as exc:
            log().warning(f"Session cleanup failed for '{mgmt_name}:{domain}': {exc}")
        finally:
            try:
                async with self._rate_limiter.acquire(server_ip):
                    await self._transport.logout(server_ip, tmp_sid, port=port)
            except Exception as exc:
                log().warning(f"Failed to logout cleanup temp SID [{tmp_sid[:8]}...]: {exc}")

    async def _fire_keepalive(
        self,
        mgmt_name: str,
        domain: str,
        sid: str,
        server_ip: str,
        port: int | None,
        username: str | None = None,
    ) -> None:
        """Send a keepalive ping for one session. Never propagates exceptions.

        On success, updates last_keepalive in cache.
        On failure, evicts the stale SID from cache so the next call re-authenticates.

        Args:
            mgmt_name: Management server name.
            domain: Domain name (empty string for system domain).
            sid: Session identifier to keep alive.
            server_ip: Management server IP.
            port: Optional port number.
            username: CP username when the cache key is user-scoped (credential mode).
        """
        try:
            async with self._rate_limiter.acquire(server_ip):
                await self._transport.keepalive(server_ip, sid, port)
            await self._cache.update_keepalive(mgmt_name, domain, username=username)
            log().trace(f"Keepalive sent for '{mgmt_name}:{domain}'")
        except Exception as exc:
            log().debug(f"Keepalive failed for '{mgmt_name}:{domain}': {exc} — evicting SID from cache")
            try:
                await self._cache.delete_sid(mgmt_name, domain, username=username)
            except Exception as del_exc:
                log().warning(f"Failed to evict SID for '{mgmt_name}:{domain}': {del_exc}")

    @traced
    async def run_startup_cleanup(self) -> None:
        """Run session cleanup for all configured servers at library initialization.

        Called once as a background task when ArodonataClient enters its async context.
        For each server, acquires a temporary SID, discards stale sessions, and logs out.
        Errors per-server are logged but never propagate.
        """
        if not self._session_cleaner:
            return

        # Ensure DB tables exist before acquiring distributed locks
        await self._cache._db.initialize()

        servers = self._registry.get_all_servers()
        if not servers:
            return

        span_attrs(servers=len(servers))
        log().info(f"Running startup session cleanup for {len(servers)} server(s)...")

        tasks = [
            self._cleanup_for_max_sessions(
                name,
                "",
                cfg.server_ip,
                cfg.api_key.get_secret_value(),
                cfg.port,
                reason="startup cleanup",
            )
            for name, cfg in servers.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for name, exc in zip(servers, results, strict=True):
            if isinstance(exc, Exception):
                if "does not exist" in str(exc) or "UndefinedTable" in type(exc).__name__:
                    log().debug(f"Startup cleanup skipped for '{name}': DB tables not ready yet")
                else:
                    log().warning(f"Startup cleanup failed for '{name}': {exc}")

        log().debug("Startup session cleanup complete")

    @traced
    async def maintain_keepalives(self, exclude_key: str | None = None) -> None:
        """Send keepalives for all stale cached sessions concurrently.

        Called as a background task after every API call. Skips the SID
        that was just used (it is implicitly fresh).

        Overlapping calls coalesce: if a sweep is already in flight this call
        returns immediately. A burst of API calls (e.g. rapid logout/login
        cycles) must not turn into a burst of sweeps, each holding rate-limiter
        slots for every stale session against a possibly throttled server —
        one in-flight sweep already covers the same stale set.

        Args:
            exclude_key: mgmt_dmn_key of the SID that just made an API call.
        """
        if self._keepalive_sweep_lock.locked():
            span_attrs(**{"keepalive.coalesced": True})
            log().trace("maintain_keepalives: sweep already in flight — skipping")
            return

        async with self._keepalive_sweep_lock:
            try:
                stale = await self._cache.list_stale_keepalives(threshold_seconds=600)
            except Exception as exc:
                log().warning(f"maintain_keepalives: failed to list stale SIDs: {exc}")
                return

            tasks = []
            for record in stale:
                if exclude_key and record.mgmt_dmn_key == exclude_key:
                    continue

                # Key format: 'mgmt:domain' (api-key) or 'mgmt:domain:username' (credential)
                mgmt_name, domain, username = self._split_key(record.mgmt_dmn_key)
                server_config = self._registry.get_server(mgmt_name)
                port = server_config.port if server_config else None

                tasks.append(
                    self._fire_keepalive(mgmt_name, domain, record.sid, record.server_ip, port, username=username)
                )

            if tasks:
                span_attrs(**{"keepalive.count": len(tasks)})
                log().trace(f"Firing {len(tasks)} keepalive(s) (excluding '{exclude_key}')")
                await asyncio.gather(*tasks, return_exceptions=True)

    @staticmethod
    def _split_key(mgmt_dmn_key: str) -> tuple[str, str, str | None]:
        """Split a 'mgmt:domain[:username]' cache key into its components."""
        parts = mgmt_dmn_key.split(":", 2)
        return parts[0], parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else None

    def _get_lock_key(self, mgmt_name: str, domain: str) -> str:
        """Get lock key for login coordination.

        Args:
            mgmt_name: Management server name.
            domain: Domain name (empty string for system domain).

        Returns:
            Lock key string. Matches SID cache key format.
        """
        normalized_domain = self._normalize_domain(mgmt_name, domain)
        return f"login:{mgmt_name}:{normalized_domain}"  # For system domain, this becomes "login:mgmt-server-01:"

    async def _retry_with_backoff(
        self,
        operation: Callable[..., Any],
        operation_name: str,
        max_retries: int | None = None,
        backoff: int | None = None,
    ) -> Any:
        """Execute operation with retry logic and backoff."""
        max_retries = max_retries or self._settings.login_max_retries
        backoff = backoff or self._settings.login_retry_backoff
        last_exception = None
        timeouts = 0
        throttle_waits = 0
        kind = "refusal"

        for attempt in range(max_retries):
            try:
                result = await operation()
                if result is not None:
                    return result
            except Exception as e:
                last_exception = e
                kind, timeouts = self._classify_or_raise(e, operation_name, attempt, timeouts, throttle_waits)

            if attempt < max_retries - 1:
                span_attrs(attempt=attempt)
                if kind == "throttle":
                    throttle_waits += 1
                await asyncio.sleep(self._retry_delay(kind, attempt, backoff, throttle_waits, operation_name))

        if last_exception:
            # The budget is spent and the server never answered. Now -- and only
            # now -- is a timeout worth treating as a possibly-wrong address: hand
            # it over as unreachable so `_acquire_new_sid` re-resolves the domain's
            # active server and gets one attempt there. Nothing is cut short by
            # this; it is the step after the last retry, not instead of them.
            if timeouts and _login_failure_kind(last_exception) == "timeout":
                from ..core.exceptions import ServerUnreachableError

                log().warning(
                    f"{operation_name} timed out on all {max_retries} attempts - "
                    f"treating the address as unreachable and re-resolving"
                )
                raise ServerUnreachableError(f"{operation_name} failed: {last_exception}") from last_exception
            raise last_exception
        return None

    def _classify_or_raise(
        self, exc: Exception, operation_name: str, attempt: int, timeouts: int, throttle_waits: int
    ) -> tuple[str, int]:
        """Classify a failed attempt; raise when the sequence should end here.

        Returns the failure kind and the running timeout count.
        """
        # Don't retry on developer errors (TypeError) or pure authentication
        # failures (wrong password/domain) to avoid long hangs and server lockouts.
        if isinstance(exc, TypeError) or CREDENTIAL_REJECTION_MESSAGE in str(exc):
            log().error(f"{operation_name} failed: {exc} (Fatal error - not retrying)")
            raise exc

        kind = _login_failure_kind(exc)
        if kind == "timeout":
            timeouts += 1

        if kind == "throttle" and throttle_waits >= LOGIN_THROTTLE_MAX_WAITS:  # noqa: SIM102
            log().error(
                f"{operation_name} still throttled after {throttle_waits} full "
                f"{self._throttle_window}s windows - more login pressure on this "
                f"server than Check Point's per-minute login allowance"
            )
            raise exc

        # Backoff clears lockouts, not addresses. Once the evidence says nothing is
        # listening, hand the failure up instead of spending the rest of the budget
        # on it: `_acquire_new_sid` re-resolves the domain's active server and
        # retries against what `show-domains` now reports. Only conclusive evidence
        # qualifies here; a timeout waits for the budget to run out (see below).
        if kind == "unreachable":
            from ..core.exceptions import ServerUnreachableError

            log().warning(
                f"{operation_name} attempt {attempt + 1} failed: {exc} "
                f"(server did not answer - not retrying this address)"
            )
            raise ServerUnreachableError(f"{operation_name} failed: {exc}") from exc

        log().warning(f"{operation_name} attempt {attempt + 1} failed: {exc}")
        return kind, timeouts

    def _retry_delay(self, kind: str, attempt: int, backoff: int, throttle_waits: int, operation_name: str) -> float:
        """Seconds to wait before the next attempt."""
        if kind == "throttle":
            # A throttle lockout is not cleared by ramping up to it: every step of
            # the ramp is shorter than the window, and each rejected attempt re-arms
            # it. One wait longer than the window is the only thing that works.
            # Jitter keeps concurrent callers from all coming back at the same
            # instant and re-tripping it together.
            delay = self._throttle_window + random.uniform(0, 5.0)
            log().warning(
                f"{operation_name} throttled - waiting {delay:.0f}s for the login window "
                f"to clear ({throttle_waits}/{LOGIN_THROTTLE_MAX_WAITS})"
            )
            return delay

        # Exponential backoff for everything else, capped at the throttle window: a
        # longer sleep belongs to the branch above, and a shorter cap would sit just
        # under the one lockout we know about.
        return min((backoff * (1.3**attempt)) + random.uniform(0, 2.0), float(self._throttle_window))

    @traced
    async def logout(self, mgmt_name: str, domain: str) -> bool:
        """Explicitly logout of a session.

        Args:
            mgmt_name: Management server name.
            domain: Domain name.

        Returns:
            True if logout was successful (or session didn't exist), False otherwise.
        """
        span_attrs(mgmt_name=mgmt_name, domain=domain or "system")
        domain = self._normalize_domain(mgmt_name, domain)
        cached = await self._cache.get_sid(mgmt_name, domain, username=self._credential_username)
        if not cached or not cached.sid:
            return True

        success = False
        try:
            # Get port from server configuration
            server_config = self._registry.get_server(mgmt_name)
            port = server_config.port if server_config else None

            response = await self._transport.logout(cached.server_ip, cached.sid, port=port)
            success = response.get("success", False)
        except Exception as e:
            log().warning(f"Logout failed for '{mgmt_name}:{domain}': {e}")

        # Always remove from cache regardless of server-side success
        await self._cache.delete_sid(mgmt_name, domain, username=self._credential_username)
        return success

    @traced
    async def logout_all(self) -> None:
        """Logout of all active sessions and clear cache."""
        sids = await self._cache.list_all_sids()
        for record in sids:
            mgmt, domain, _ = self._split_key(record.mgmt_dmn_key)
            await self.logout(mgmt, domain)

    async def _execute_login_request(
        self,
        mgmt_name: str,
        domain: str,
        server_ip: str,
        api_key: str,
        port: int | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
        session_timeout: int | None = None,
    ) -> dict[str, Any]:
        """Execute the actual login request to the API."""
        if self._auth_mode == "credential" and self._username and self._password_secret:
            log().trace(
                f"Attempting credential login: mgmt='{mgmt_name}', domain='{domain}', IP={server_ip}, user={self._username}"
            )
            return await self._transport.login_with_credentials(
                server_ip=server_ip,
                username=self._username,
                password=self._password_secret.get_secret_value(),
                domain=domain if domain else None,
                port=port,
                session_name=session_name,
                session_description=session_description,
                session_timeout=session_timeout,
                timeout=self._settings.login_timeout,
            )

        masked_key = f"{api_key[:4]}...{api_key[-4:]}" if api_key and len(api_key) > 8 else "****"
        log().trace(f"Attempting login: mgmt='{mgmt_name}', domain='{domain}', IP={server_ip}, API_KEY={masked_key}")
        return await self._transport.login_with_apikey(
            server_ip=server_ip,
            api_key=api_key,
            domain=domain if domain else None,
            port=port,
            session_name=session_name,
            session_description=session_description,
            session_timeout=session_timeout,
            # A login is one HTTP round trip. Without this it inherited the
            # transport's much larger default, so an unresponsive server cost
            # 120 s per attempt across every retry (int-4, 2026-09-13).
            timeout=self._settings.login_timeout,
        )

    def _raise_as_auth_error(self, exc: Exception, mgmt_name: str, domain: str) -> Never:
        """Always raises AuthenticationError wrapping exc. Never returns."""
        from ..core.exceptions import AuthenticationError

        if self._auth_mode == "credential":
            raise AuthenticationError(f"Credential authentication failed for '{mgmt_name}:{domain}': {exc}") from exc
        raise AuthenticationError(f"Login failed after {self._settings.login_max_retries} attempts: {exc}") from exc

    def _parse_login_response(
        self, response: dict[str, Any], mgmt_name: str, domain: str, server_ip: str, api_key: str
    ) -> tuple[str, str | None]:
        """Parse login API response into (sid, uid) or raise."""
        if response.get("success") and response.get("sid"):
            sid = str(response["sid"])
            uid = self._extract_uid_from_response(response)
            log().trace(f"Login successful for '{mgmt_name}:{domain}' (SID: [{sid[:8]}...], UID: {uid})")
            return sid, uid

        code = response.get("code", "")
        if code == THROTTLE_ERROR_CODE:
            from ..core.exceptions import ThrottlingError

            raise ThrottlingError(f"Login throttled: {code}")

        error_msg = response.get("message", "Unknown login error")
        log().error(
            f"AUTHENTICATION FAILURE DETAILS: "
            f"mgmt='{mgmt_name}', domain='{domain}', ip={server_ip}, "
            f"error_code='{code}', error_msg='{error_msg}', "
            f"api_key_prefix={api_key[:8] if api_key else 'None'}..., "
            f"response_data_keys={list(response.get('data', {}).keys()) if response.get('data') else 'None'}"
        )
        from ..core.exceptions import AuthenticationError, InvalidCredentialsError

        # A rejected password/key is the one login failure that never clears on
        # retry, so it gets its own subclass: callers can tell it apart from a
        # transient refusal ("Database revision is in progress", server
        # restarting, ...) by type instead of by matching on message text.
        if CREDENTIAL_REJECTION_MESSAGE in error_msg:
            raise InvalidCredentialsError(f"Login failed: {error_msg}")
        raise AuthenticationError(f"Login failed: {error_msg}")

    def _extract_uid_from_response(self, response: dict[str, Any]) -> str | None:
        """Extract user ID from login response.

        Args:
            response: Login response dictionary.

        Returns:
            User ID as string if present, None otherwise.
        """
        uid = response.get("data", {}).get("uid")
        return str(uid) if uid else None

    async def _login_operation_for(
        self,
        mgmt_name: str,
        domain: str,
        server_ip: str,
        api_key: str,
        force_relogin: bool,
        port: int | None,
        session_name: str | None,
        session_description: str | None,
    ) -> tuple[str, str | None] | None:
        """Single login attempt: cache lookup, else API call and parse.

        Used as the retryable operation passed to `_retry_with_backoff`.
        """
        if not force_relogin:
            cached = await self._cache.get_sid(
                mgmt_name, domain, self._settings.session_expire_seconds, username=self._credential_username
            )
            if cached and cached.sid:
                log().trace(f"Cache HIT: Using cached SID [{cached.sid[:8]}...] for '{mgmt_name}:{domain}'")
                return cached.sid, cached.uid
            log().trace(f"Cache MISS: No SID for '{mgmt_name}:{domain}'")
        else:
            log().trace(f"Force login for '{mgmt_name}:{domain}', skipping cache")

        response = await self._execute_login_request(
            mgmt_name,
            domain,
            server_ip,
            api_key,
            port=port,
            session_name=session_name,
            session_description=session_description,
            session_timeout=self._settings.session_timeout,
        )
        return self._parse_login_response(response, mgmt_name, domain, server_ip, api_key)

    async def _try_login_once(
        self,
        mgmt_name: str,
        domain: str,
        server_ip: str,
        api_key: str,
        force_relogin: bool,
        port: int | None,
        session_name: str | None,
        session_description: str | None,
    ) -> tuple[str, str | None]:
        """Acquire the rate limiter and run the retry-with-backoff sequence once.

        The rate limiter is held for the ENTIRE retry sequence (acquired once,
        not re-acquired per attempt), preventing concurrent logins to the same
        IP from compounding throttling issues.
        """
        from ..core.exceptions import AuthenticationError, ServerUnreachableError

        async with self._rate_limiter.acquire(server_ip):
            log().trace(f"Rate limiter acquired for '{mgmt_name}:{domain}', starting login retry sequence")

            try:
                result = await self._retry_with_backoff(
                    lambda: self._login_operation_for(
                        mgmt_name,
                        domain,
                        server_ip,
                        api_key,
                        force_relogin,
                        port,
                        session_name,
                        session_description,
                    ),
                    "Login",
                )
                if result is None:
                    raise AuthenticationError("Login failed: No session ID returned")
                sid, uid = result  # type: ignore[assignment]
                return sid, uid
            except ServerUnreachableError as e:
                # Must survive unwrapped: `_acquire_new_sid` decides, on this type,
                # whether to re-resolve the domain's active server and try there.
                e.server_ip = e.server_ip or server_ip
                raise
            except AuthenticationError:
                raise
            except Exception as e:
                self._raise_as_auth_error(e, mgmt_name, domain)

    async def _login_with_cleanup_retry(
        self,
        mgmt_name: str,
        domain: str,
        server_ip: str,
        api_key: str,
        force_relogin: bool,
        port: int | None,
        session_name: str | None,
        session_description: str | None,
    ) -> tuple[str, str | None]:
        """First login attempt; on max-sessions error, cleanup once and retry."""
        from ..core.exceptions import AuthenticationError
        from .session_cleaner import SessionCleaner

        # First attempt — on max-sessions error, cleanup once and retry
        _cleanup_attempted = False
        try:
            return await self._try_login_once(
                mgmt_name,
                domain,
                server_ip,
                api_key,
                force_relogin,
                port,
                session_name,
                session_description,
            )
        except AuthenticationError as e:
            if not _cleanup_attempted and self._session_cleaner and SessionCleaner.is_max_sessions_error(str(e)):
                _cleanup_attempted = True
                log().warning(f"Max sessions error for '{mgmt_name}:{domain}', running cleanup and retrying once...")
                await self._cleanup_for_max_sessions(
                    mgmt_name,
                    domain,
                    server_ip,
                    api_key,
                    port,
                    reason="max sessions error from API",
                )
                log().info(f"Retrying login for '{mgmt_name}:{domain}' after session cleanup")
                return await self._try_login_once(
                    mgmt_name,
                    domain,
                    server_ip,
                    api_key,
                    force_relogin,
                    port,
                    session_name,
                    session_description,
                )
            raise

    @traced
    async def _perform_login(
        self,
        mgmt_name: str,
        domain: str,
        server_ip: str,
        api_key: str,
        force_relogin: bool = False,
        port: int | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str | None]:
        """Perform actual login operation with retry logic.

        Acquires the rate limiter lock ONCE and holds it through all retry attempts.
        This prevents concurrent logins to the same IP from compounding throttling issues.

        Args:
            mgmt_name: Management server name.
            domain: Domain name.
            server_ip: Server IP address.
            api_key: API key for authentication.
            force_relogin: Force re-login even if cached SID exists.
            port: Optional port number.

        Returns:
            Tuple of (Session ID, User ID) from successful login.
        """
        # Hide this function from tracebacks to prevent leaking api_key/password
        __tracebackhide__ = True
        span_attrs(mgmt_name=mgmt_name, domain=domain or "system")
        log().trace(f"Performing login to '{mgmt_name}:{domain}' at {server_ip} (auth_mode={self._auth_mode})")
        return await self._login_with_cleanup_retry(
            mgmt_name,
            domain,
            server_ip,
            api_key,
            force_relogin,
            port,
            session_name,
            session_description,
        )

    @traced
    async def _prefetch_domain_server_ip(
        self,
        mgmt_name: str,
        domain: str,
        force: bool = False,
    ) -> str | None:
        """Prefetch domain server IP from API if not in cache.

        This is called before acquiring the domain lock to avoid deadlock.
        Returns the server IP or None if it couldn't be determined.

        Args:
            mgmt_name: Management server name.
            domain: Domain name.
            force: Whether to force refresh from API.

        Returns:
            Server IP address or None.
        """
        span_attrs(mgmt_name=mgmt_name, domain=domain or "system")
        if not force:
            cached_domain = await self._cache.get_domain(mdm_dmn=f"{mgmt_name}:{domain}")
            if cached_domain and cached_domain.active_ip:
                log().trace(f"Using cached active_ip for '{mgmt_name}:{domain}': {cached_domain.active_ip}")
                return cached_domain.active_ip

        # Cache miss or empty active_ip - fetch from API
        log().info(f"Domain cache missing/empty for '{mgmt_name}:{domain}', fetching from API...")
        server_config = self._registry.get_server(mgmt_name)
        if not server_config:
            raise ValueError(f"Unknown management server: {mgmt_name}")

        # Get system login without prefetch to avoid recursive calls.
        # Never force the system SID here — the retry loop below handles expired
        # system sessions, and forcing would bypass the cache on every domain IP
        # refresh (e.g. failover), triggering an unnecessary extra system login.
        system_sid, system_ip = await self.login(mgmt_name, "", force=False, _skip_prefetch=True)

        # Fetch domain info using system login
        # Retry once if session expired during the fetch
        max_attempts = 2
        for attempt in range(max_attempts):
            async with self._rate_limiter.acquire(system_ip):
                response = await self._transport.api_call(
                    server_ip=system_ip,
                    sid=system_sid,
                    command="show-domains",
                    payload={"details-level": "full"},
                    port=server_config.port,
                )

            # Check for session errors - retry with fresh login
            if response.get("code") in SESSION_ERROR_CODES and attempt < max_attempts - 1:
                log().debug(f"Session expired while fetching domains for '{mgmt_name}:{domain}', retrying...")
                system_sid, system_ip = await self.login(mgmt_name, "", force=True, _skip_prefetch=True)
                continue

            break

        # response always assigned due to max_attempts=2
        if not response.get("success"):  # type: ignore
            log().warning(f"API call failed for '{mgmt_name}:{domain}': {response.get('message', 'Unknown error')}")  # type: ignore
            return server_config.server_ip

        response_data = response.get("data")  # type: ignore
        if response_data is None:
            log().warning(f"No data in response for '{mgmt_name}:{domain}', using primary IP")
            return server_config.server_ip

        # show-domains returns {"objects": [...], "total": N, ...} dict
        # Handle both dict (with "objects" key) and direct list formats
        if isinstance(response_data, list):
            domains_data = response_data
        elif isinstance(response_data, dict):
            domains_data = response_data.get("objects", [])
        else:
            domains_data = []

        return await self._cache_domain_active_ip(
            mgmt_name, domain, domains_data, server_config.server_ip, server_config.is_mdm
        )

    async def _cache_domain_active_ip(
        self, mgmt_name: str, domain: str, domains_data: list[Any], default_ip: str, is_mdm: bool | None = None
    ) -> str:
        """Cache the extracted active IP for the specified domain."""
        from ..cache.models import Domain

        for d in domains_data:
            if isinstance(d, dict) and d.get("name") == domain:
                d_uid = d.get("uid", "")
                active_ip = self._extract_active_server_ip(d) or default_ip

                domain_record = Domain.build(
                    mgmt_name=mgmt_name,
                    domain_name=domain,
                    domain_uid=d_uid,
                    active_ip=active_ip,
                    is_mdm=is_mdm if is_mdm is not None else False,
                )

                await self._cache.upsert_domain(domain_record)
                log().info(f"Updated domain cache for '{mgmt_name}:{domain}' with active_ip={active_ip}")
                return active_ip

        if domain == GLOBAL_DOMAIN_NAME and is_mdm is not False:
            # The implicit Global domain is never listed by `show-domains`, so it will
            # never be "found" in domains_data above. Cache it with the MDS's own
            # primary IP rather than falling through to the "unknown domain" warning -
            # a falsy active_ip would make every subsequent Global login treat this as
            # a cache miss and re-fetch show-domains (see _prefetch_domain_server_ip).
            domain_record = Domain.build(
                mgmt_name=mgmt_name,
                domain_name=GLOBAL_DOMAIN_NAME,
                domain_uid="",
                active_ip=default_ip,
                is_mdm=is_mdm if is_mdm is not None else True,
            )
            await self._cache.upsert_domain(domain_record)
            log().info(f"Cached Global domain for '{mgmt_name}' with active_ip={default_ip}")
            return default_ip

        log().warning(
            f"Domain '{domain}' not found in API response for '{mgmt_name}', using primary IP (NOT caching unknown domain)"
        )
        # Deliberately do not cache unknown domains to prevent polluting the domains table
        # with management server names or other incorrect inputs.
        return default_ip

    def _extract_active_server_ip(self, domain_obj: dict[str, Any]) -> str:
        """Extract active server IP from domain object.

        Args:
            domain_obj: Domain object from API response.

        Returns:
            Active server IP address or empty string.
        """
        servers = domain_obj.get("servers", [])
        if not isinstance(servers, list):
            return ""

        for server in servers:
            if isinstance(server, dict) and server.get("active") is True:
                ipv4_address = server.get("ipv4-address", "")
                if isinstance(ipv4_address, str) and ipv4_address:
                    return ipv4_address

        return ""

    @traced
    async def login(
        self,
        mgmt_name: str,
        domain: str = "",
        force: bool = False,
        *,
        cache_mode: str = "auto",
        session_name: str | None = None,
        session_description: str | None = None,
        _skip_prefetch: bool = False,
        refresh_domain_ip: bool = False,
    ) -> tuple[str, str]:
        """Login to management server or domain.

        Args:
            mgmt_name: Management server name.
            domain: Domain name (empty string for system domain).
            force: Force fresh login ignoring SID cache.
            cache_mode: Cache behavior ("auto", "refresh", "off").
            _skip_prefetch: Internal use to prevent recursion.
            refresh_domain_ip: Force refresh of domain server IP (use only for failover).
                               Session-expiry retries should NOT set this — the domain IP
                               is still valid and bypassing the cache causes redundant
                               system-domain logins that trigger too_many_requests throttling.

        Returns:
            Tuple of (SID, Server IP).
        """
        # Map cache_mode to force flag
        if cache_mode == "refresh":
            force = True

        domain = self._normalize_domain(mgmt_name, domain)
        span_attrs(mgmt_name=mgmt_name, domain=domain or "system", force=force)
        entry_time = datetime.now(UTC).replace(tzinfo=None)

        # For domains, pre-fetch domain server IP before acquiring lock
        # to avoid deadlock where we hold domain lock but need system login
        # Skip prefetch when explicitly requested (internal use)
        # Use refresh_domain_ip (not force) so that session-expiry retries
        # don't bypass the domain IP cache and trigger unnecessary system logins.
        server_ip: str | None = None
        if domain and not _skip_prefetch:
            server_ip = await self._prefetch_domain_server_ip(mgmt_name, domain, force=refresh_domain_ip)

        # Pre-lock cache check (optimization)
        if not force:
            cached = await self._cache.get_sid(
                mgmt_name, domain, self._settings.session_expire_seconds, username=self._credential_username
            )
            if cached and cached.sid and cached.server_ip:
                log().trace(f"Cache HIT (pre-lock): '{mgmt_name}:{domain}' (SID: [{cached.sid[:8]}...])")
                span_attrs(sid_cache="hit-pre-lock")
                return cached.sid, cached.server_ip

        lock_key = self._get_lock_key(mgmt_name, domain)

        # In-process lock for optimization
        if lock_key not in self._in_process_locks:
            self._in_process_locks[lock_key] = asyncio.Lock()

        async with self._in_process_locks[lock_key]:
            lock_manager = await self._get_lock_manager()

            # Acquire distributed login lock with 90s TTL (accounts for throttling/retries)
            async with lock_manager.acquire(
                lock_key,
                timeout=90,
                ttl=lock_manager.DEFAULT_TTL_LOGIN,
            ):
                return await self._acquire_new_sid(
                    mgmt_name, domain, force, entry_time, server_ip, session_name, session_description
                )

    @traced
    async def _acquire_new_sid(
        self,
        mgmt_name: str,
        domain: str,
        force: bool,
        entry_time: Any,
        server_ip: str | None,
        session_name: str | None,
        session_description: str | None,
    ) -> tuple[str, str]:
        """Post-lock body: double-check cache, then login and cache the result."""
        cached = await self._cache.get_sid(
            mgmt_name, domain, self._settings.session_expire_seconds, username=self._credential_username
        )
        if cached and cached.sid and cached.server_ip:
            if not force or (cached.created_at >= entry_time):
                log().trace(f"Cache HIT (post-lock): '{mgmt_name}:{domain}' (SID: [{cached.sid[:8]}...])")
                span_attrs(sid_cache="hit-post-lock")
                return cached.sid, cached.server_ip

        log().debug(f"Cache MISS (post-lock): '{mgmt_name}:{domain}' - performing login")
        span_attrs(sid_cache="miss")

        server_config = self._registry.get_server(mgmt_name)
        if not server_config:
            raise ValueError(f"Unknown management server: {mgmt_name}")

        if server_ip is None:
            server_ip = server_config.server_ip
        api_key = server_config.api_key.get_secret_value()
        port = server_config.port

        log().debug(
            f"LOGIN ATTEMPT: mgmt='{mgmt_name}', domain='{domain}', ip={server_ip}:{port or 443}, "
            f"force={force}, entry_time={entry_time.isoformat()}, "
            f"cached_sid={cached.sid[:8] if cached and cached.sid else 'None'}..., "
            f"cached_created={cached.created_at.isoformat() if cached and cached.created_at else 'None'}"
        )

        from ..core.exceptions import ServerUnreachableError

        try:
            sid, uid = await self._perform_login(
                mgmt_name,
                domain,
                server_ip,
                api_key,
                force_relogin=force,
                port=port,
                session_name=session_name,
                session_description=session_description,
            )
        except ServerUnreachableError as exc:
            server_ip, sid, uid = await self._relogin_at_resolved_ip(
                exc,
                mgmt_name,
                domain,
                server_ip,
                api_key,
                force=force,
                port=port,
                session_name=session_name,
                session_description=session_description,
            )

        try:
            await self._cache.set_sid(mgmt_name, domain, sid, server_ip, uid, username=self._credential_username)
            log().trace(f"Cache STORE: SID for '{mgmt_name}:{domain}' (uid={uid})")
        except Exception as e:
            log().error(f"Cache store error for '{mgmt_name}:{domain}': {e}")

        return sid, server_ip

    async def _relogin_at_resolved_ip(
        self,
        exc: Exception,
        mgmt_name: str,
        domain: str,
        dead_ip: str,
        api_key: str,
        *,
        force: bool,
        port: int | None,
        session_name: str | None,
        session_description: str | None,
    ) -> tuple[str, str, str | None]:
        """Re-resolve a silent domain server and log in there; returns (ip, sid, uid).

        Only reached when the server never answered. The cached SID for this
        domain is dropped first -- it was issued by, or points at, a server we can
        no longer reach -- and then `show-domains` is asked where the domain's
        active server is now, bypassing the domain cache. A genuinely moved domain
        recovers here; a domain whose server is simply down fails immediately
        afterwards rather than spending the full retry budget knocking on it.

        The system domain has no per-domain server to re-resolve: that IS the
        management server, so there is nowhere else to look.
        """
        from ..core.exceptions import ServerUnreachableError

        await self._forget_sid(mgmt_name, domain)

        if not domain:
            log().error(f"Management server {dead_ip} did not answer for '{mgmt_name}' - no domain IP to re-resolve")
            raise self._unreachable_login_error(exc, mgmt_name, domain, dead_ip) from exc

        log().warning(
            f"Domain server {dead_ip} did not answer for '{mgmt_name}:{domain}' - "
            f"re-resolving the domain's active server before retrying"
        )
        fresh_ip = await self._prefetch_domain_server_ip(mgmt_name, domain, force=True)

        if not fresh_ip or fresh_ip == dead_ip:
            log().error(
                f"'{mgmt_name}:{domain}' still resolves to {dead_ip}, which is not answering - giving up on this login"
            )
            raise self._unreachable_login_error(exc, mgmt_name, domain, dead_ip) from exc

        log().info(f"'{mgmt_name}:{domain}' moved: {dead_ip} -> {fresh_ip}, retrying login there")
        try:
            sid, uid = await self._perform_login(
                mgmt_name,
                domain,
                fresh_ip,
                api_key,
                force_relogin=force,
                port=port,
                session_name=session_name,
                session_description=session_description,
            )
        except ServerUnreachableError as second:
            # Two addresses, no answer from either: stop rather than chase.
            log().error(f"Re-resolved address {fresh_ip} for '{mgmt_name}:{domain}' did not answer either")
            raise self._unreachable_login_error(second, mgmt_name, domain, dead_ip, fresh_ip) from second
        return fresh_ip, sid, uid

    def _unreachable_login_error(self, exc: Exception, mgmt_name: str, domain: str, *addresses: str) -> Exception:
        """An AuthenticationError naming the address(es) that went silent.

        Deliberately an `AuthenticationError` and not the `ServerUnreachableError`
        underneath it: every consumer already handles a failed login by catching
        `AuthenticationError`, and the reason a login failed should not change the
        type they have to catch. The address goes in the message, where it costs
        nothing and answers the first question anyone will ask.
        """
        from ..core.exceptions import AuthenticationError

        where = " then ".join(dict.fromkeys(a for a in addresses if a))
        return AuthenticationError(
            f"Login to '{mgmt_name}:{domain or 'system'}' failed: no answer from {where} ({exc})"
        )

    async def _forget_sid(self, mgmt_name: str, domain: str) -> None:
        """Drop the cached SID for this domain; never fatal."""
        try:
            await self._cache.delete_sid(mgmt_name, domain, username=self._credential_username)
        except Exception as e:  # noqa: BLE001 - cache hygiene must not mask the login failure
            log().warning(f"Could not clear cached SID for '{mgmt_name}:{domain}': {e}")

    @traced
    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str = "",
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        """Create a dedicated session that bypasses the global SID cache.

        Used by write-intensive workflows (e.g. CPCRUD) that need session
        isolation from the shared pool. The returned SID is NOT stored
        in the cache — the caller is responsible for using it directly
        via api_call_with_sid and for logout when done.

        Retries with the same exponential backoff as the shared login path
        (`_retry_with_backoff`) on a failed attempt -- unlike `login()`, this
        previously made a single, unretried attempt, so a routine, recoverable
        server-side throttling/lockout response (e.g. "Too many requests in a
        given amount of time") surfaced as a hard failure to the caller instead
        of being absorbed the way every other login path in this module already
        handles it.

        Args:
            mgmt_name: Management server name.
            domain: Domain name (empty string for system domain).
            session_name: Optional session name visible in SmartConsole.
            session_description: Optional session description.

        Returns:
            Tuple of (SID, Server IP).

        Raises:
            ValueError: If management server is unknown.
            AuthenticationError: If login fails after all retries.
        """
        span_attrs(mgmt_name=mgmt_name, domain=domain or "system")
        from ..core.exceptions import AuthenticationError

        server_config = self._registry.get_server(mgmt_name)
        if not server_config:
            raise ValueError(f"Unknown management server: {mgmt_name}")

        # Resolve domain server IP (for MDM setups)
        server_ip: str | None = None
        if domain:
            server_ip = await self._prefetch_domain_server_ip(mgmt_name, domain)
        if server_ip is None:
            server_ip = server_config.server_ip

        api_key = server_config.api_key.get_secret_value()
        port = server_config.port

        domain_display = domain or "system"
        log().info(
            f"Creating dedicated session for '{mgmt_name}:{domain_display}'"
            + (f" (name={session_name})" if session_name else "")
        )

        async def _attempt() -> tuple[str, str | None]:
            response = await self._execute_login_request(
                mgmt_name,
                domain,
                server_ip,
                api_key,
                port=port,
                session_name=session_name,
                session_description=session_description,
                session_timeout=self._settings.session_timeout,
            )
            if not (response.get("success") and response.get("sid")):
                error_msg = response.get("message", "Unknown login error")
                raise AuthenticationError(f"Dedicated session login failed for '{mgmt_name}:{domain}': {error_msg}")
            return str(response["sid"]), response.get("data", {}).get("uid")

        # Rate limiter held for the ENTIRE retry sequence (acquired once, not
        # re-acquired per attempt), matching _try_login_once's pattern -- prevents
        # concurrent dedicated-session logins to the same IP from compounding
        # throttling issues.
        async with self._rate_limiter.acquire(server_ip):
            result = await self._retry_with_backoff(_attempt, "Dedicated session login")

        if result is None:
            raise AuthenticationError(
                f"Dedicated session login failed for '{mgmt_name}:{domain}': No session ID returned"
            )
        sid, uid = result
        if uid:
            uid = str(uid)
        log().info(f"Dedicated session created for '{mgmt_name}:{domain}': SID=[{sid[:8]}...], UID={uid}")
        return sid, server_ip


__all__ = ["LoginCoordinator"]
