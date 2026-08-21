"""Core protocols (interfaces) for Arodonata library.

Defines abstract interfaces using Python Protocols for proper dependency
inversion and testability. All major components implement these protocols.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..cache.models import Asset, SIDCache


# Type aliases
RawApiResponse = dict[str, Any]


class RefreshMode(StrEnum):
    """Cache refresh mode for object operations.

    Attributes:
        SKIP: Use cache as-is without refresh.
        CHECK: Refresh stale domains only (based on LastPublishedSession);
            stale domains get a full atomic reload.
        FORCE: Refresh all domains unconditionally (full atomic reload).
        INCREMENTAL: Refresh stale domains only (same staleness probe as
            CHECK); stale domains get a show-changes incremental apply with
            fallback to a full atomic reload on any unsafe condition.
    """

    SKIP = "skip"
    CHECK = "check"
    FORCE = "force"
    INCREMENTAL = "incremental"


@runtime_checkable
class ICacheRepository(Protocol):
    """Interface for cache operations.

    All database access goes through this protocol.
    """

    async def get_sid(
        self, mgmt_name: str, domain: str, max_age_seconds: int | None = None, *, username: str | None = None
    ) -> SIDCache | None:
        """Retrieve cached session ID."""
        ...

    async def set_sid(
        self,
        mgmt_name: str,
        domain: str,
        sid: str,
        server_ip: str,
        uid: str | None = None,
        session: Any | None = None,
        *,
        username: str | None = None,
    ) -> None:
        """Store session ID in cache."""
        ...

    async def delete_sid(self, mgmt_name: str, domain: str, *, username: str | None = None) -> None:
        """Delete specific session from cache."""
        ...

    async def clear_sessions(self, older_than_seconds: int | None = None) -> int:
        """Clear session entries from cache."""
        ...

    async def get_assets(
        self,
        asset_ids: list[str] | None = None,
        asset_types: list[str] | None = None,
        mgmt_names: list[str] | None = None,
    ) -> list[Asset]:
        """Retrieve assets with optional filters."""
        ...

    async def upsert_asset(self, asset: Asset) -> None:
        """Insert or update a single asset."""
        ...

    async def upsert_assets(self, assets: list[Asset]) -> int:
        """Bulk insert or update assets."""
        ...

    async def initialize(self) -> None:
        """Initialize the cache (creates tables if needed)."""
        ...

    async def close(self) -> None:
        """Close database connections."""
        ...


@runtime_checkable
class IApiTransport(Protocol):
    """Interface for API communication layer."""

    async def api_call(
        self,
        server_ip: str,
        sid: str,
        command: str,
        payload: dict[str, Any] | None = None,
        timeout: int = -1,
        wait_for_task: bool = True,
    ) -> RawApiResponse:
        """Execute API call."""
        ...

    async def api_query(
        self,
        server_ip: str,
        sid: str,
        command: str,
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        container_key: str = "objects",
    ) -> RawApiResponse:
        """Execute API query."""
        ...


@runtime_checkable
class IServerRegistry(Protocol):
    """Interface for server configuration lookup."""

    def get_server(self, name: str) -> ServerConfig | None:
        """Get server configuration by name."""
        ...

    def get_names(self) -> list[str]:
        """Get list of all server names."""
        ...

    def update_metadata(self, name: str, is_mdm: bool | None = None, version: str | None = None) -> None:
        """Update server metadata."""
        ...


@runtime_checkable
class IRateLimiter(Protocol):
    """Interface for rate limiting per server."""

    @asynccontextmanager
    async def acquire(self, server_ip: str) -> AsyncGenerator[None]:
        """Acquire rate limit slot for server."""
        yield


@runtime_checkable
class ILoginCoordinator(Protocol):
    """Interface for login orchestration."""

    async def login(self, mgmt_name: str, domain: str, force: bool = False) -> tuple[str, str]:
        """Login and return (sid, server_ip)."""
        ...


# Data classes for protocol return types
class ServerConfig:
    """Server configuration data."""

    name: str
    server_ip: str
    is_mdm: bool | None
    version: str | None


class SIDRecord:
    """Cached SID record data."""

    sid: str
    server_ip: str
    created_at: datetime


__all__ = [
    "ICacheRepository",
    "IApiTransport",
    "IServerRegistry",
    "IRateLimiter",
    "ILoginCoordinator",
    "RawApiResponse",
    "ServerConfig",
    "SIDRecord",
    "RefreshMode",
]
