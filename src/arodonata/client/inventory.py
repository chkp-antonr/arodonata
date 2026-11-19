"""Inventory read, search, query, refresh, mutation, and warmup facade methods for `ArodonataClient`."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from typing import Any, Literal

from arodonata.client.lifecycle import ClientLifecycleMixin
from arodonata.core.context import get_write_session, normalize_domain_key
from arodonata.core.errors import ValidationError
from arodonata.core.events import SyncProgressEvent
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import ApiCallResult, CacheMode, SyncScope
from arodonata.core.models.domains import DomainInfo, RefreshOutcome, WarmupStatusEntry
from arodonata.core.models.objects import CPObject, SearchResult
from arodonata.core.models.services import CPService
from arodonata.core.telemetry import span_attrs, traced


class ClientInventoryMixin(ClientLifecycleMixin):
    """Provides domain, object, service, asset, search, warmup, and mutation facade methods."""

    # ------------------------------------------------------------------
    # Explicit Background Cache Warm-Up
    # ------------------------------------------------------------------

    def get_warmup_status(self, mgmt_name: str | None = None) -> list[WarmupStatusEntry]:
        """Return structured status entries for active and recent background warm-up flights."""
        return self._warmup.get_warmup_status(mgmt_name=mgmt_name)

    def start_object_cache_warmup(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        include_services: bool = False,
        mode: CacheMode = "smart",
    ) -> asyncio.Task[RefreshOutcome]:
        """Explicitly schedule single-flight deduplicated background object (and optional service) cache warm-up."""
        return self._warmup.start_object_cache_warmup(
            mgmt_name=mgmt_name,
            domains=domains,
            types=types,
            include_global=include_global,
            include_services=include_services,
            mode=mode,
            refresh_objects_fn=self.refresh_objects,
            refresh_services_fn=self.refresh_services,
        )

    # ------------------------------------------------------------------
    # Paired Refresh & Streaming Methods
    # ------------------------------------------------------------------

    @traced
    async def refresh_objects(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Synchronize network objects across target domains and return `RefreshOutcome`."""
        await self._ensure_initialized()
        return await self._object_service.refresh_objects(
            mgmt_name=mgmt_name,
            domains=domains,
            types=types,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    async def stream_refresh_objects(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while synchronizing network objects."""
        await self._ensure_initialized()
        async for ev in self._object_service.stream_refresh_objects(
            mgmt_name=mgmt_name,
            domains=domains,
            types=types,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield ev

    @traced
    async def refresh_services(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Synchronize service objects across target domains and return `RefreshOutcome`."""
        await self._ensure_initialized()
        return await self._service_cache.refresh_services(
            mgmt_name=mgmt_name,
            domains=domains,
            types=types,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    async def stream_refresh_services(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while synchronizing service objects."""
        await self._ensure_initialized()
        async for ev in self._service_cache.stream_refresh_services(
            mgmt_name=mgmt_name,
            domains=domains,
            types=types,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield ev

    @traced
    async def refresh_assets(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Synchronize gateway, cluster, VSX, and server assets across domains and return `RefreshOutcome`."""
        await self._ensure_initialized()
        return await self._asset_service.refresh_assets(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    async def stream_refresh_assets(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while synchronizing gateway, cluster, VSX, and server assets."""
        await self._ensure_initialized()
        async for ev in self._asset_service.stream_refresh_assets(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield ev

    # ------------------------------------------------------------------
    # Typed Read Facade
    # ------------------------------------------------------------------

    @traced
    async def get_domains(
        self,
        mgmt_name: str | None = None,
        *,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[DomainInfo]:
        """Return discovered domains, excluding `Global` unless `include_global=True`.

        Never triggers implicit background object-cache warm-up.
        """
        await self._ensure_initialized()
        return await self._domain_service.get_domains(
            mgmt_name=mgmt_name,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_gateways(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[Asset]:
        """Return cached gateway, cluster, VSX, and server `Asset` models."""
        await self._ensure_initialized()
        return await self._asset_service.get_assets(
            mgmt_name=mgmt_name,
            domain=domain,
            types=types,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_hosts(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject]:
        """Return cached `host` `CPObject` models, merging any active `WriteSession` overlay."""
        await self._ensure_initialized()
        return await self._object_service.get_objects(
            mgmt_name=mgmt_name,
            domain=domain,
            types=["host"],
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_networks(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject]:
        """Return cached `network` `CPObject` models, merging any active `WriteSession` overlay."""
        await self._ensure_initialized()
        return await self._object_service.get_objects(
            mgmt_name=mgmt_name,
            domain=domain,
            types=["network"],
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_address_ranges(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject]:
        """Return cached `address-range` `CPObject` models, merging any active `WriteSession` overlay."""
        await self._ensure_initialized()
        return await self._object_service.get_objects(
            mgmt_name=mgmt_name,
            domain=domain,
            types=["address-range"],
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_dns_domains(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject]:
        """Return cached `dns-domain` `CPObject` models, merging any active `WriteSession` overlay."""
        await self._ensure_initialized()
        return await self._object_service.get_objects(
            mgmt_name=mgmt_name,
            domain=domain,
            types=["dns-domain"],
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_groups(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject]:
        """Return cached `group` `CPObject` models, merging any active `WriteSession` overlay."""
        await self._ensure_initialized()
        return await self._object_service.get_objects(
            mgmt_name=mgmt_name,
            domain=domain,
            types=["group"],
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_objects(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        types: Sequence[str] | None = None,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject]:
        """Return cached network `CPObject` models across `types`, merging any active `WriteSession` overlay."""
        await self._ensure_initialized()
        return await self._object_service.get_objects(
            mgmt_name=mgmt_name,
            domain=domain,
            types=types,
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_services(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        types: Sequence[str] | None = None,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPService]:
        """Return cached `CPService` models, merging any active `WriteSession` overlay."""
        await self._ensure_initialized()
        return await self._service_cache.get_services(
            mgmt_name=mgmt_name,
            domain=domain,
            types=types,
            names=names,
            uids=uids,
            include_global=include_global,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_object_by_uid(
        self,
        mgmt_name: str,
        domain: str,
        uid: str,
        *,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> CPObject | None:
        """Return a single `CPObject` by `(mgmt_name, domain, uid)`, respecting any active `WriteSession` overlay."""
        await self._ensure_initialized()
        return await self._object_service.get_object_by_uid(
            mgmt_name,
            domain,
            uid,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    # ------------------------------------------------------------------
    # Search, Structured Aggregation, & Object Mutation Helpers
    # ------------------------------------------------------------------

    @traced
    async def search_objects(
        self,
        query: str,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        max_depth: int = 2,
        exact_match: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> SearchResult:
        """Search cached objects across comma-separated terms and resolve parent groups up to `max_depth`."""
        await self._ensure_initialized()
        return await self._search_service.search_objects(
            query,
            mgmt_name=mgmt_name,
            domains=domains,
            types=types,
            include_global=include_global,
            max_depth=max_depth,
            exact_match=exact_match,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def describe_objects(
        self,
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        include_global: bool = True,
    ) -> dict[str, Any]:
        """Return progressive-disclosure schema and summary counts for cached objects and services."""
        await self._ensure_initialized()
        return await self._search_service.describe_objects(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            include_global=include_global,
        )

    @traced
    async def query_objects(
        self,
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        domains: Sequence[str] | None = None,
        types: Sequence[str] | None = None,
        scope_origin: Literal["all", "local", "global"] = "all",
        name_pattern: str | None = None,
        ip_subnet: str | None = None,
        port: str | None = None,
        protocol: str | None = None,
        tags: Sequence[str] | None = None,
        parent_id: str | None = None,
        parent_asset_id: str | None = None,
        include_global: bool = False,
        group_by: Sequence[str] | None = None,
        aggregate: Literal["count", "list", "describe"] = "list",
        limit: int = 100,
        offset: int = 0,
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> dict[str, Any]:
        """Execute structured cross-domain filtering, grouping, and counting over cached objects and services."""
        await self._ensure_initialized()
        return await self._search_service.query_objects(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            domains=domains,
            types=types,
            scope_origin=scope_origin,
            name_pattern=name_pattern,
            ip_subnet=ip_subnet,
            port=port,
            protocol=protocol,
            tags=tags,
            parent_id=parent_id,
            parent_asset_id=parent_asset_id,
            include_global=include_global,
            group_by=group_by,
            aggregate=aggregate,
            limit=limit,
            offset=offset,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_cache_status(
        self,
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        scope: SyncScope | None = None,
    ) -> dict[str, Any]:
        """Inspect `domain_sync_state` across scopes and return per-domain/per-type freshness and `cache_age_seconds`."""
        await self._ensure_initialized()
        return await self._search_service.get_cache_status(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            scope=scope,
        )

    async def _mutate_object(
        self,
        mgmt_name: str,
        verb: str,
        obj_type: str,
        payload: dict[str, Any],
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
    ) -> ApiCallResult:
        """Execute `add-/set-/delete-<obj_type>` using active `WriteSession`, explicit `sid`, or isolated `write_session`."""
        clean_type = obj_type.strip().lower().removeprefix(f"{verb}-")
        span_attrs(mgmt_name=mgmt_name, domain=domain, object_type=clean_type)
        dom_key = normalize_domain_key(domain) if domain is not None else None
        if sid is None and get_write_session(mgmt_name=mgmt_name, domain_name=dom_key) is None:
            async with self.write_session(mgmt_name, domain) as ws:
                return await self.api_call(
                    mgmt_name,
                    f"{verb}-{clean_type}",
                    payload,
                    domain=domain,
                    sid=ws.sid,
                    server_ip=server_ip or ws.server_ip,
                )
        return await self.api_call(
            mgmt_name,
            f"{verb}-{clean_type}",
            payload,
            domain=domain,
            sid=sid,
            server_ip=server_ip,
        )

    @traced
    async def add_object(
        self,
        mgmt_name: str,
        obj_type: str,
        payload: dict[str, Any],
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
    ) -> ApiCallResult:
        """Create a Check Point object (`add-<obj_type>`) using active `WriteSession` context, explicit `sid`, or an automatic isolated `write_session` (`C8`)."""
        return await self._mutate_object(
            mgmt_name,
            "add",
            obj_type,
            payload,
            domain=domain,
            sid=sid,
            server_ip=server_ip,
        )

    @traced
    async def set_object(
        self,
        mgmt_name: str,
        obj_type: str,
        payload: dict[str, Any],
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
    ) -> ApiCallResult:
        """Update a Check Point object (`set-<obj_type>`) using active `WriteSession` context, explicit `sid`, or an automatic isolated `write_session` (`C8`)."""
        return await self._mutate_object(
            mgmt_name,
            "set",
            obj_type,
            payload,
            domain=domain,
            sid=sid,
            server_ip=server_ip,
        )

    @traced
    async def delete_object(
        self,
        mgmt_name: str,
        obj_type: str,
        *,
        uid: str | None = None,
        name: str | None = None,
        payload: dict[str, Any] | None = None,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
    ) -> ApiCallResult:
        """Delete a Check Point object (`delete-<obj_type>`) by `uid` or `name` using active `WriteSession`, explicit `sid`, or automatic isolated `write_session` (`C8`)."""
        req_payload: dict[str, Any] = dict(payload or {})
        if uid is not None:
            req_payload["uid"] = uid
        if name is not None:
            req_payload["name"] = name
        return await self._mutate_object(
            mgmt_name,
            "delete",
            obj_type,
            req_payload,
            domain=domain,
            sid=sid,
            server_ip=server_ip,
        )

    @traced
    async def find_object(
        self,
        mgmt_name: str,
        domain: str | None = None,
        name_or_uid: str = "",
        *,
        obj_type: str | None = None,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> CPObject | CPService | Asset | None:
        """Find a single `CPObject`, `CPService`, or `Asset` by exact `uid` or `name` in `(mgmt_name, domain)` (or across all domains when `domain` is `None`), including active `WriteSession` overlay."""
        await self._ensure_initialized()
        return await self._search_service.find_object(
            mgmt_name,
            domain,
            name_or_uid,
            obj_type=obj_type,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_group_members(
        self,
        mgmt_name: str,
        domain: str | None = None,
        group_name_or_uid: str = "",
        *,
        recursive: bool = True,
        max_depth: int = 5,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject | CPService | Asset]:
        """Resolve direct (and optionally recursive) member `CPObject`, `CPService`, or child `Asset` items for a group, service-group, cluster, or VSX container in `(mgmt_name, domain)`."""
        if not group_name_or_uid or not group_name_or_uid.strip():
            raise ValidationError("group_name_or_uid must not be empty or whitespace")
        await self._ensure_initialized()
        return await self._search_service.get_group_members(
            mgmt_name,
            domain,
            group_name_or_uid,
            recursive=recursive,
            max_depth=max_depth,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )
