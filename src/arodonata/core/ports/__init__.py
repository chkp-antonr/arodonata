"""Hexagonal architectural ports (`ApiPort`, `CachePort`, `LockPort`, `AuthProvider`, `GatewayCliPort`).

Pure typing protocols with zero transport or ORM dependencies.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol, runtime_checkable

from arodonata.core.context import AuthContext, UserContext
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import ApiCallResult, ApiQueryResult, SyncScope
from arodonata.core.models.domains import DomainInfo, DomainSyncState, SIDCacheEntry
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import DomainRulebaseSnapshot
from arodonata.core.models.services import CPService
from arodonata.core.models.topology import (
    GatewayCliResult,
    GatewayCliTarget,
    GatewayTopologyEntry,
    TopologyAnnotation,
)


@runtime_checkable
class AuthProvider(Protocol):
    """Protocol for resolving dynamic credentials and receiving auth failure callbacks."""

    async def get_credentials(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        user: UserContext | None = None,
    ) -> AuthContext:
        """Resolve runtime `AuthContext` for `(mgmt_name, domain)`."""
        ...

    async def on_auth_failed(
        self,
        mgmt_name: str,
        auth: AuthContext,
        exc: Exception,
    ) -> None:
        """Notify provider that `auth` was rejected with `InvalidCredentialsError`."""
        ...


@runtime_checkable
class GatewayCliPort(Protocol):
    """Protocol for executing CLI scripts/commands on Check Point gateways (e.g., via SSH in bash/expert mode)."""

    async def execute_command(
        self,
        target: GatewayCliTarget,
        command: str,
        *,
        timeout: float = 30.0,
    ) -> GatewayCliResult | str:
        """Execute `command` on `target` and return `GatewayCliResult` or raw stdout string."""
        ...


GatewayCliCallable = Callable[[GatewayCliTarget, str], Awaitable[GatewayCliResult | str]]


@runtime_checkable
class LockPort(Protocol):
    """Protocol for distributed cross-process lock coordination."""

    async def acquire(
        self,
        lock_key: str,
        *,
        ttl_seconds: float = 60.0,
        owner_id: str | None = None,
        wait_timeout: float | None = None,
        poll_interval: float = 0.05,
    ) -> bool:
        """Attempt to acquire `lock_key`, reclaiming any expired lock row."""
        ...

    async def renew(
        self,
        lock_key: str,
        *,
        ttl_seconds: float = 60.0,
        owner_id: str | None = None,
    ) -> bool:
        """Extend `expires_at` for an active lock held by `owner_id`."""
        ...

    async def release(
        self,
        lock_key: str,
        *,
        owner_id: str | None = None,
    ) -> bool:
        """Release `lock_key` if owned by `owner_id`."""
        ...

    def lock(
        self,
        lock_key: str,
        *,
        ttl_seconds: float = 60.0,
        owner_id: str | None = None,
        wait_timeout: float | None = None,
        poll_interval: float = 0.05,
    ) -> AbstractAsyncContextManager[str]:
        """Async context manager acquiring `lock_key` on entry and releasing it on exit."""
        ...


@runtime_checkable
class CachePort(Protocol):
    """Protocol for persistent cache operations across domains, sessions, objects, services, assets, and rulebases."""

    async def get_domains(
        self,
        mgmt_name: str | None = None,
        *,
        include_global: bool = False,
    ) -> list[DomainInfo]:
        """Return cached domains, excluding `Global` domains unless `include_global=True`."""
        ...

    async def get_domain(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> DomainInfo | None:
        """Return a single cached domain by `(mgmt_name, domain_name)`."""
        ...

    async def upsert_domains(self, domains: Sequence[DomainInfo]) -> None:
        """Insert or update domain rows in `arodonata_domains`."""
        ...

    async def get_sid(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        auth_identity: str | None = None,
    ) -> SIDCacheEntry | None:
        """Fetch a cached shared read-only session entry for `(mgmt_name, domain_name, auth_identity)`."""
        ...

    async def upsert_sid(self, entry: SIDCacheEntry) -> None:
        """Insert or update a shared read-only session entry in `arodonata_sid_cache`."""
        ...

    async def evict_sid(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        auth_identity: str | None = None,
    ) -> bool:
        """Remove the cached SID for `(mgmt_name, domain_name)` (and optional `auth_identity`) immediately."""
        ...

    async def list_sids(self, mgmt_name: str | None = None) -> list[SIDCacheEntry]:
        """List cached shared read-only SIDs, optionally filtered by `mgmt_name`."""
        ...

    async def get_sync_state(
        self,
        mgmt_name: str,
        domain_name: str,
        scope: SyncScope,
        item_type: str = "*",
    ) -> DomainSyncState | None:
        """Fetch synchronization state for `(mgmt_name, domain_name, scope, item_type)`."""
        ...

    async def list_sync_states(
        self,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        scope: SyncScope | None = None,
    ) -> list[DomainSyncState]:
        """List synchronization states matching optional filters."""
        ...

    async def upsert_sync_state(self, state: DomainSyncState) -> None:
        """Insert or update a `DomainSyncState` row in `arodonata_domain_sync_state`."""
        ...

    async def get_objects(
        self,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        *,
        types: Sequence[str] | None = None,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
    ) -> list[CPObject]:
        """Query cached network objects from `arodonata_objects`."""
        ...

    async def get_object_by_uid(
        self,
        mgmt_name: str,
        domain_name: str,
        uid: str,
    ) -> CPObject | None:
        """Fetch a single cached `CPObject` by `(mgmt_name, domain_name, uid)`."""
        ...

    async def replace_domain_objects(
        self,
        mgmt_name: str,
        domain_name: str,
        objects: Sequence[CPObject],
        *,
        types: Sequence[str],
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Atomically replace objects of `types` for `(mgmt_name, domain_name)` without deleting other types."""
        ...

    async def upsert_objects(
        self,
        objects: Sequence[CPObject],
        *,
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Insert or update `CPObject` rows in `arodonata_objects` (incremental sync)."""
        ...

    async def delete_objects_by_uids(
        self,
        mgmt_name: str,
        domain_name: str,
        uids: Sequence[str],
    ) -> int:
        """Delete `CPObject` rows matching `uids` in `(mgmt_name, domain_name)`."""
        ...

    async def get_services(
        self,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        *,
        types: Sequence[str] | None = None,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
    ) -> list[CPService]:
        """Query cached service objects from `arodonata_services`."""
        ...

    async def get_service_by_uid(
        self,
        mgmt_name: str,
        domain_name: str,
        uid: str,
    ) -> CPService | None:
        """Fetch a single cached `CPService` by `(mgmt_name, domain_name, uid)`."""
        ...

    async def replace_domain_services(
        self,
        mgmt_name: str,
        domain_name: str,
        services: Sequence[CPService],
        *,
        types: Sequence[str],
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Atomically replace services of `types` for `(mgmt_name, domain_name)` without deleting other types."""
        ...

    async def upsert_services(
        self,
        services: Sequence[CPService],
        *,
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Insert or update `CPService` rows in `arodonata_services`."""
        ...

    async def delete_services_by_uids(
        self,
        mgmt_name: str,
        domain_name: str,
        uids: Sequence[str],
    ) -> int:
        """Delete `CPService` rows matching `uids` in `(mgmt_name, domain_name)`."""
        ...

    async def get_assets(
        self,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        *,
        types: Sequence[str] | None = None,
    ) -> list[Asset]:
        """Query cached gateway/cluster/VSX/server assets from `arodonata_assets`."""
        ...

    async def replace_domain_assets(
        self,
        mgmt_name: str,
        domain_name: str,
        assets: Sequence[Asset],
        *,
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Atomically replace all cached assets for `(mgmt_name, domain_name)`."""
        ...

    async def upsert_assets(
        self,
        assets: Sequence[Asset],
    ) -> int:
        """Insert or update `Asset` rows in `arodonata_assets`."""
        ...

    async def get_gateway_topology(
        self,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        *,
        gateway_uids: Sequence[str] | None = None,
        gateway_names: Sequence[str] | None = None,
        topology_zone: str | None = None,
        source_types: Sequence[str] | None = None,
    ) -> list[GatewayTopologyEntry]:
        """Query cached gateway interface topology intervals from `arodonata_gateway_topology`."""
        ...

    async def replace_domain_topology(
        self,
        mgmt_name: str,
        domain_name: str,
        entries: Sequence[GatewayTopologyEntry],
        *,
        gateway_uids: Sequence[str] | None = None,
        source_types: Sequence[str] | None = None,
        active_gateway_uids: Sequence[str] | None = None,
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Atomically replace cached gateway topology entries for `(mgmt_name, domain_name)` (optionally scoped by `gateway_uids` and `source_types`)."""
        ...

    async def upsert_gateway_topology(
        self,
        entries: Sequence[GatewayTopologyEntry],
        *,
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Insert or update `GatewayTopologyEntry` rows in `arodonata_gateway_topology`."""
        ...

    async def get_topology_annotations(
        self,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        *,
        gateway_uids: Sequence[str] | None = None,
        interface_name: str | None = None,
    ) -> list[TopologyAnnotation]:
        """Query persistent administrator topology annotations from `arodonata_topology_annotations`."""
        ...

    async def upsert_topology_annotations(
        self,
        annotations: Sequence[TopologyAnnotation],
    ) -> int:
        """Insert or update `TopologyAnnotation` rows in `arodonata_topology_annotations`."""
        ...

    async def delete_topology_annotations(
        self,
        annotation_ids: Sequence[str],
    ) -> int:
        """Delete `TopologyAnnotation` rows matching `annotation_ids`."""
        ...

    async def replace_domain_rulebase(
        self,
        snapshot: DomainRulebaseSnapshot,
        *,
        sync_state: DomainSyncState | None = None,
    ) -> None:
        """Atomically replace all `arodonata_rulebase_*` snapshot tables for `(snapshot.mgmt_name, snapshot.domain_name)`."""
        ...

    async def get_domain_rulebase(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> DomainRulebaseSnapshot:
        """Load the cached `DomainRulebaseSnapshot` for `(mgmt_name, domain_name)`."""
        ...

    async def get_domain_rulebase_packages(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> DomainRulebaseSnapshot:
        """Load lightweight `package_layers` and NAT package metadata for `(mgmt_name, domain_name)` without loading rule rows."""
        ...


@runtime_checkable
class ApiPort(Protocol):
    """Protocol for Check Point Management Web API transport and session operations."""

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
        """Execute a single Check Point Management API command."""
        ...

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
        limit: int = 300,
    ) -> ApiQueryResult:
        """Execute a continuity-verified paginated Check Point object listing query."""
        ...

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
        ...

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> Awaitable[bool]:
        """Log out a specific session identifier."""
        ...

    async def close(self, *, logout: bool | None = None) -> None:
        """Close transport connections and optionally log out active sessions."""
        ...


__all__ = [
    "ApiPort",
    "AuthProvider",
    "CachePort",
    "GatewayCliCallable",
    "GatewayCliPort",
    "LockPort",
]
