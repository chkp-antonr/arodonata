"""Server registry for management server configuration lookup.

Manages the in-memory configuration map built from settings,
providing lookup and enumeration capabilities.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pydantic import SecretStr

from ..logger import lazy_logger

if TYPE_CHECKING:
    from ..config import ArodonataSettings

log = lazy_logger("arodonata.asdk.server_registry")


@dataclass
class ServerConfig:
    """Configuration for a management server."""

    name: str
    server_ip: str  # Keep for backward compatibility, use host instead
    api_key: SecretStr
    port: int | None = None  # API port (None = default 443)
    is_mdm: bool | None = None
    version: str | None = None

    @property
    def host(self) -> str:
        """Extract host from server_ip (handles host:port format).

        Returns:
            Host part of server_ip (without port)
        """
        if ":" in self.server_ip:
            # IPv6 addresses use brackets, but for this case we have IPv4:port
            return self.server_ip.rsplit(":", 1)[0]
        return self.server_ip


class ServerRegistry:
    """Immutable view over configuration → in-memory server mapping.

    Provides lookup and enumeration capabilities for management servers.

    Example:
        registry = ServerRegistry(settings)
        names = registry.get_names()
        server = registry.get_server("my-server")
    """

    def __init__(self, settings: ArodonataSettings) -> None:
        """Initialize server registry from configuration settings.

        Args:
            settings: Configuration settings instance.
        """
        self._servers: dict[str, ServerConfig] = {}
        self._lock = asyncio.Lock()
        self._build_server_map(settings)
        log().trace(f"ServerRegistry initialized with {len(self._servers)} servers")

    def _build_server_map(self, settings: ArodonataSettings) -> None:
        """Build in-memory server map from configuration settings."""
        # Credential mode: single server from mgmt_ip (no API key — credential auth only)
        if settings.auth_mode == "credential" and settings.mgmt_ip:
            host, port = self._parse_server_address(settings.mgmt_ip)
            server_config = ServerConfig(
                name=settings.mgmt_ip,
                server_ip=host,  # Store host without port
                api_key=SecretStr(""),
                port=port,
                is_mdm=None,
                version=None,
            )
            self._servers[settings.mgmt_ip] = server_config
            log().trace(f"Registered credential-mode server '{settings.mgmt_ip}' -> {host}:{port or 443}")
            return

        # API key mode: build from comma-separated lists
        mgmt_names = settings.mgmt_names_list
        mgmt_servers = settings.mgmt_servers_list
        api_keys = settings.api_keys_list

        # Validate all lists have same length
        if not mgmt_names:
            log().debug("No management servers configured")
            return

        if not (len(mgmt_names) == len(mgmt_servers) == len(api_keys)):
            raise ValueError(
                f"Configuration mismatch: {len(mgmt_names)} names, {len(mgmt_servers)} servers, {len(api_keys)} keys"
            )

        for name, server_ip, api_key in zip(mgmt_names, mgmt_servers, api_keys, strict=True):
            host, port = self._parse_server_address(server_ip)
            server_config = ServerConfig(
                name=name,
                server_ip=host,  # Store host without port
                api_key=SecretStr(api_key),
                port=port,
                is_mdm=None,
                version=None,
            )
            self._servers[name] = server_config
            log().trace(f"Registered server '{name}' -> {host}:{port or 443}")

    def _parse_server_address(self, server_address: str) -> tuple[str, int | None]:
        """Parse server address into host and port.

        Args:
            server_address: Server address in format "host" or "host:port"

        Returns:
            Tuple of (host, port) where port is None if not specified
        """
        if ":" in server_address:
            # Handle host:port format
            parts = server_address.rsplit(":", 1)
            host = parts[0]
            try:
                port = int(parts[1])
                return host, port
            except ValueError:
                # Port is not a valid integer, treat entire address as host
                return server_address, None
        # No port specified
        return server_address, None

    def get_server(self, name: str) -> ServerConfig | None:
        """Get server configuration by name.

        Args:
            name: Server name to lookup.

        Returns:
            Server configuration or None if not found.
        """
        return self._servers.get(name)

    def get_names(self) -> list[str]:
        """Get list of all management server names.

        Returns:
            List of server name strings.
        """
        return list(self._servers.keys())

    def get_all_servers(self) -> dict[str, ServerConfig]:
        """Get all server configurations.

        Returns:
            Dictionary mapping server names to ServerConfig objects.
        """
        return self._servers.copy()

    def has_server(self, name: str) -> bool:
        """Check if server exists in registry.

        Args:
            name: Server name to check.

        Returns:
            True if server exists.
        """
        return name in self._servers

    async def update_metadata(
        self,
        name: str,
        is_mdm: bool | None = None,
        version: str | None = None,
    ) -> None:
        """Update server metadata (MDM status, version).

        Args:
            name: Server name to update.
            is_mdm: Multi-Domain Management status.
            version: API version.
        """
        async with self._lock:
            server = self._servers.get(name)
            if server:
                if is_mdm is not None:
                    server.is_mdm = is_mdm
                if version is not None:
                    server.version = version
                log().trace(f"Updated metadata for '{name}': is_mdm={is_mdm}, version={version}")


__all__ = ["ServerRegistry", "ServerConfig"]
