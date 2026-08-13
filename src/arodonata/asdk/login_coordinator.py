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
from ..config import SESSION_ERROR_CODES, THROTTLE_ERROR_CODE
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
        self._closed = False

        # Credential-based auth support
        self._auth_mode = settings.auth_mode
        self._username: str | None = settings.username
        self._password_secret = settings.password  # SecretStr | None

        log().trace(f"LoginCoordinator initialized (auth_mode={self._auth_mode})")

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

        Args:
            exclude_key: mgmt_dmn_key of the SID that just made an API call.
        """
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

            tasks.append(self._fire_keepalive(mgmt_name, domain, record.sid, record.server_ip, port, username=username))

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

        # Check if this is a server connection error (e.g., domain doesn't exist)
        # These errors should stop after 2 retries instead of full max_retries
        server_connection_error = False

        for attempt in range(max_retries):
            try:
                result = await operation()
                if result is not None:
                    return result
            except Exception as e:
                last_exception = e
                error_str = str(e)

                # Don't retry on developer errors (TypeError) or pure authentication
                # failures (wrong password/domain) to avoid long hangs and server lockouts.
                if isinstance(e, TypeError) or "Authentication to server failed" in error_str:
                    log().error(f"{operation_name} failed: {e} (Fatal error - not retrying)")
                    raise e

                # Detect server connection errors (e.g., "Unable to connect to server...")
                # These indicate permanent issues like missing domains and should stop early
                if (
                    "Unable to connect to server. Please make sure that all processes of the server are up and running."
                    in error_str
                ):
                    server_connection_error = True
                    log().warning(
                        f"{operation_name} attempt {attempt + 1} failed: {e} (Server connection error - limiting retries)"
                    )

                log().warning(f"{operation_name} attempt {attempt + 1} failed: {e}")

            # For server connection errors, stop after 2 attempts instead of max_retries
            if server_connection_error and attempt >= 1:
                log().error(f"{operation_name} failed after {attempt + 1} attempts due to server connection error")
                if last_exception:
                    raise last_exception
                return None

            if attempt < max_retries - 1:
                span_attrs(attempt=attempt)
                # Use exponential backoff to handle and clear server-side lockouts/throttling.
                # 1.3^6 is ~4.8, reaching >60s total wait after 6-7 attempts (with base 5s).
                # This ensures we clear 60s lockouts accurately even if some attempts reset the timer.
                current_backoff = (backoff * (1.3**attempt)) + random.uniform(0, 2.0)
                # Cap backoff at 60s to definitely clear standard lockouts
                current_backoff = min(current_backoff, 60.0)
                await asyncio.sleep(current_backoff)

        if last_exception:
            raise last_exception
        return None

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
        from ..core.exceptions import AuthenticationError

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
        from ..core.exceptions import AuthenticationError

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

        try:
            await self._cache.set_sid(mgmt_name, domain, sid, server_ip, uid, username=self._credential_username)
            log().trace(f"Cache STORE: SID for '{mgmt_name}:{domain}' (uid={uid})")
        except Exception as e:
            log().error(f"Cache store error for '{mgmt_name}:{domain}': {e}")

        return sid, server_ip

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
