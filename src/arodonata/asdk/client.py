"""AMgmtClient facade - main entry point for ASDK operations.

Orchestrates all async client functionality including session management,
rate limiting, and error handling.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Literal

from ..config import FAILOVER_ERROR_CODES, SESSION_ERROR_CODES
from ..logger import lazy_logger
from .transport import RawApiResponse

if TYPE_CHECKING:
    from .login_coordinator import LoginCoordinator
    from .rate_limiter import RateLimiter
    from .server_registry import ServerConfig, ServerRegistry
    from .transport import ApiTransport

log = lazy_logger("arodonata.asdk.client")


class AMgmtClient:
    """Facade orchestrating all async client functionality.

    Main entry point for Check Point API operations with automatic
    session management, rate limiting, and error handling.

    Example:
        client = AMgmtClient(
            registry=server_registry,
            transport=transport,
            rate_limiter=rate_limiter,
            login_coordinator=login_coordinator,
        )
        async with client:
            result = await client.api_call("mgmt1", "show-hosts")
    """

    def __init__(
        self,
        registry: ServerRegistry,
        transport: ApiTransport,
        rate_limiter: RateLimiter,
        login_coordinator: LoginCoordinator,
    ) -> None:
        self._registry = registry
        self._transport = transport
        self._rate_limiter = rate_limiter
        self._login_coordinator = login_coordinator
        self._closed = False
        self._background_tasks: set[asyncio.Task[None]] = set()
        log().trace("AMgmtClient initialized")

    async def __aenter__(self) -> AMgmtClient:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: Any) -> None:
        """Async context manager exit with cleanup."""
        await self.close()

    async def close(self) -> None:
        """Close client and clean up resources."""
        if not self._closed:
            self._closed = True
            if self._background_tasks:
                pending = list(self._background_tasks)
                for t in pending:
                    t.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
            await self._login_coordinator.close()
            log().debug("AMgmtClient closed")

    async def logout(self, mgmt_name: str, domain: str = "") -> bool:
        """Explicitly logout of a session.

        Args:
            mgmt_name: Management server name.
            domain: Domain name (empty string for system domain).

        Returns:
            True if logout was successful, False otherwise.
        """
        self._ensure_not_closed()
        return await self._login_coordinator.logout(mgmt_name, domain)

    def _ensure_not_closed(self) -> None:
        """Ensure client has not been closed."""
        if self._closed:
            raise RuntimeError("AMgmtClient has been closed and cannot be used")

    def get_mgmt_names(self) -> list[str]:
        """Get list of all management server names."""
        self._ensure_not_closed()
        return self._registry.get_names()

    async def get_server(self, name: str) -> ServerConfig | None:
        """Get server configuration by name, fetching metadata if missing.

        Args:
            name: Server name to lookup.

        Returns:
            Server configuration with populated metadata or None.
        """
        self._ensure_not_closed()
        server = self._registry.get_server(name)

        if not server:
            return None

        # Check if metadata needs update
        if server.is_mdm is None or server.version is None:
            log().debug(f"Fetching metadata for '{name}'")

            # 1. Fetch API version
            version_res = await self.api_call(name, "show-api-versions")
            version = None
            if version_res.get("success"):
                data = version_res.get("data", {})
                if isinstance(data, dict):
                    version = data.get("current-version")

            # 2. Determine MDM status
            is_mdm = None
            domains_res = await self.api_call(name, "show-domains", details_level="uid")
            if domains_res.get("success"):
                # Check if there are actual domains (not just empty response)
                data = domains_res.get("data", {})
                if isinstance(data, list) and len(data) > 0:
                    is_mdm = True
                elif isinstance(data, dict) and data.get("objects"):
                    objects = data.get("objects", [])
                    if isinstance(objects, list) and len(objects) > 0:
                        is_mdm = True
                    else:
                        is_mdm = False
                else:
                    # Empty response suggests SMS, not MDM
                    is_mdm = False
            elif domains_res.get("code") == "generic_err_command_not_found":
                is_mdm = False

            # Update registry
            await self._registry.update_metadata(name, is_mdm=is_mdm, version=version)

            # Fetch updated config
            server = self._registry.get_server(name)

        return server

    async def _execute_with_retry(
        self,
        mgmt_name: str,
        domain: str,
        cache_mode: str,
        transport_fn: Callable[..., Awaitable[RawApiResponse]],
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> RawApiResponse:
        """Run transport_fn with session management, retrying on session expiry or failover."""
        max_attempts = 2
        _refresh_ip_on_retry = False
        response: RawApiResponse | None = None
        for attempt in range(max_attempts):
            sid, server_ip = await self._login_coordinator.login(
                mgmt_name,
                domain,
                force=(attempt > 0),
                refresh_domain_ip=(attempt > 0 and _refresh_ip_on_retry),
                cache_mode=cache_mode,
                session_name=session_name,
                session_description=session_description,
            )
            if attempt > 0:
                log().trace(f"Retrying with SID [{sid[:8]}...] for '{mgmt_name}:{domain}'")
            else:
                log().trace(f"Using SID [{sid[:8]}...] for '{mgmt_name}:{domain}'")

            server_config = self._registry.get_server(mgmt_name)
            port = server_config.port if server_config else None

            async with self._rate_limiter.acquire(server_ip):
                response = await transport_fn(server_ip=server_ip, sid=sid, port=port)

            if response.get("code") in SESSION_ERROR_CODES and attempt < max_attempts - 1:
                log().debug(
                    f"Session expired for '{mgmt_name}:{domain}', refreshing and retrying (attempt {attempt + 1}/{max_attempts})..."
                )
                continue

            if domain and response.get("code") in FAILOVER_ERROR_CODES and attempt < max_attempts - 1:
                log().info(
                    f"Domain failover detected for '{mgmt_name}:{domain}' (code: {response.get('code')}), refreshing cache and retrying..."
                )
                _refresh_ip_on_retry = True
                continue

            break

        username = self._login_coordinator._credential_username if self._login_coordinator else None
        exclude_key = f"{mgmt_name}:{domain}:{username}" if username else f"{mgmt_name}:{domain}"
        task = asyncio.create_task(self._login_coordinator.maintain_keepalives(exclude_key=exclude_key))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        return response  # type: ignore[return-value]

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
    ) -> RawApiResponse:
        """Execute API call with automatic session management and retry.

        Args:
            mgmt_name: Management server name.
            command: API command to execute.
            domain: Domain name (empty string for system domain).
            details_level: Level of detail in response.
            payload: Additional command parameters.
            wait_for_task: Wait for task completion.
            timeout: Request timeout in seconds.

        Returns:
            API response dictionary.
        """
        self._ensure_not_closed()

        if payload is None:
            payload = {}
        if details_level:
            payload["details-level"] = details_level

        async def _call(*, server_ip: str, sid: str, port: int | None) -> RawApiResponse:
            return await self._transport.api_call(
                server_ip=server_ip,
                sid=sid,
                command=command,
                payload=payload,
                wait_for_task=wait_for_task,
                timeout=timeout,
                port=port,
            )

        return await self._execute_with_retry(
            mgmt_name,
            domain,
            cache_mode,
            _call,
            session_name=session_name,
            session_description=session_description,
        )

    async def api_call_with_sid(
        self,
        mgmt_name: str,
        sid: str,
        server_ip: str,
        command: str,
        payload: dict[str, Any] | None = None,
        wait_for_task: bool = True,
        timeout: int = -1,
    ) -> RawApiResponse:
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
            timeout: Request timeout in seconds.

        Returns:
            API response dictionary.
        """
        self._ensure_not_closed()

        if payload is None:
            payload = {}

        log().trace(f"Using explicit SID [{sid[:8]}...] for '{mgmt_name}' command '{command}'")

        server_config = self._registry.get_server(mgmt_name)
        port = server_config.port if server_config else None

        async with self._rate_limiter.acquire(server_ip):
            response = await self._transport.api_call(
                server_ip=server_ip,
                sid=sid,
                command=command,
                payload=payload,
                wait_for_task=wait_for_task,
                timeout=timeout,
                port=port,
            )

        return response

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str = "",
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        """Create a dedicated session bypassing the global SID cache.

        Args:
            mgmt_name: Management server name.
            domain: Domain name (empty string for system domain).
            session_name: Optional session name visible in SmartConsole.
            session_description: Optional session description.

        Returns:
            Tuple of (SID, Server IP).
        """
        self._ensure_not_closed()
        return await self._login_coordinator.create_dedicated_session(
            mgmt_name,
            domain,
            session_name=session_name,
            session_description=session_description,
        )

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
        self._ensure_not_closed()
        try:
            server_config = self._registry.get_server(mgmt_name) if mgmt_name else None
            port = server_config.port if server_config else None
            response = await self._transport.logout(server_ip, sid, port=port)
            return response.get("success", False)
        except Exception as e:
            log().warning(f"Logout SID [{sid[:8]}...] failed: {e}")
            return False

    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        domain: str = "",
        details_level: Literal["uid", "standard", "full"] = "standard",
        payload: dict[str, Any] | None = None,
        container_key: str = "objects",
        cache_mode: str = "auto",
    ) -> RawApiResponse:
        """Execute API query with automatic session management."""
        self._ensure_not_closed()

        if payload is None:
            payload = {}

        async def _call(*, server_ip: str, sid: str, port: int | None) -> RawApiResponse:
            return await self._transport.api_query(
                server_ip=server_ip,
                sid=sid,
                command=command,
                details_level=details_level,
                payload=payload,
                container_key=container_key,
                port=port,
            )

        return await self._execute_with_retry(mgmt_name, domain, cache_mode, _call)


__all__ = ["AMgmtClient"]
