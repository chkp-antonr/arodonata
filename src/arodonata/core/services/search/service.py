"""`SearchService` facade class preserving `@traced` telemetry and public SDK surface."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any, Literal, Protocol

from arodonata.core.context import get_write_session
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CacheMode, SyncScope, to_naive_utc, utc_now
from arodonata.core.models.objects import CPObject, GroupMembershipNode, SearchResult
from arodonata.core.models.services import CPService
from arodonata.core.ports import (
    AssetCachePort,
    DomainCachePort,
    ObjectCachePort,
    ServiceCachePort,
    SyncStatePort,
)
from arodonata.core.primitives import normalize_str_sequence
from arodonata.core.services.asset_service import AssetRefreshService
from arodonata.core.services.object_service import ObjectService
from arodonata.core.services.search.finder import find_object_impl, match_assets
from arodonata.core.services.search.query import describe_objects_impl, get_cache_status_impl, query_objects_impl
from arodonata.core.services.search.resolver import (
    dedup_entities_by_uid,
    resolve_group_with_members_impl,
    resolve_implicit_domain_mode_impl,
)
from arodonata.core.services.search.terms import (
    classify_search_term,
    resolve_group_memberships,
    search_objects_impl,
)
from arodonata.core.services.service_cache import ServiceCacheService
from arodonata.core.telemetry import span_attrs, traced

_SEARCH_TRACE_MODULE = "arodonata.core.services.search_service"


class _SearchServiceCachePort(
    DomainCachePort,
    ObjectCachePort,
    ServiceCachePort,
    AssetCachePort,
    SyncStatePort,
    Protocol,
):
    """Cache capabilities required by `SearchService`."""


class SearchService:
    """Cache-first object search, recursive group membership resolution, and structured queries."""

    __module__ = _SEARCH_TRACE_MODULE

    def __init__(
        self,
        *,
        cache: _SearchServiceCachePort,
        object_service: ObjectService,
        service_cache: ServiceCacheService | None = None,
        asset_service: AssetRefreshService | None = None,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._cache = cache
        self._object_service = object_service
        self._service_cache = service_cache
        self._asset_service = asset_service
        self._now: Callable[[], datetime] = lambda: to_naive_utc(now_fn())

    @traced(module=_SEARCH_TRACE_MODULE)
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
        """Search cached objects across comma-separated terms and resolve parent group memberships up to `max_depth`."""
        raw_terms = normalize_str_sequence(query)
        classified_terms = [classify_search_term(t) for t in raw_terms]
        span_attrs(
            query=query,
            mgmt_name=mgmt_name,
            max_depth=max_depth,
            exact_match=exact_match,
            cache_mode=cache_mode,
            term_count=len(classified_terms),
        )
        return await search_objects_impl(
            self,
            query,
            classified_terms=classified_terms,
            mgmt_name=mgmt_name,
            domains=domains,
            types=types,
            include_global=include_global,
            max_depth=max_depth,
            exact_match=exact_match,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    def _resolve_group_memberships(
        self,
        matches: Sequence[CPObject],
        all_objects: Sequence[CPObject],
        *,
        max_depth: int,
    ) -> dict[str, list[GroupMembershipNode]]:
        """Build reverse member-to-group index per `(mgmt_name, domain_name)` and traverse BFS up to `max_depth`."""
        return resolve_group_memberships(matches, all_objects, max_depth=max_depth)

    async def resolve_implicit_domain_mode(
        self,
        mgmt_name: str,
        eff_domain: str | None,
        cache_mode: CacheMode,
    ) -> tuple[str | None, CacheMode]:
        """Resolve `(single_domain_or_none, effective_cache_mode)` when `domain` is omitted."""
        return await resolve_implicit_domain_mode_impl(self, mgmt_name, eff_domain, cache_mode)

    async def _resolve_implicit_domain_mode(
        self,
        mgmt_name: str,
        eff_domain: str | None,
        cache_mode: CacheMode,
    ) -> tuple[str | None, CacheMode]:
        """Forwarding wrapper preserving `_resolve_implicit_domain_mode` compatibility."""
        return await self.resolve_implicit_domain_mode(mgmt_name, eff_domain, cache_mode)

    @staticmethod
    def _dedup_entities_by_uid(
        items: Sequence[CPObject | CPService | Asset],
    ) -> list[CPObject | CPService | Asset]:
        """Deduplicate cross-domain entities by `uid`, preferring the owning (`original_domain` / `Global`) copy."""
        return dedup_entities_by_uid(items)

    @staticmethod
    def _match_assets(
        assets: Sequence[Asset],
        clean_query: str,
        lookup_key: str,
        *,
        case_insensitive: bool = False,
    ) -> list[Asset]:
        """Match assets by `uid`, `name`, `asset_id`, or `id` (exact or case-insensitive)."""
        return match_assets(assets, clean_query, lookup_key, case_insensitive=case_insensitive)

    async def _get_services_for_find(
        self,
        *,
        mgmt_name: str,
        domain: str | None,
        types: Sequence[str] | None,
        names: Sequence[str] | None = None,
        uids: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPService]:
        """Fetch services via `ServiceCacheService` or fall back directly to `ServiceCachePort` + overlay."""
        if self._service_cache is not None:
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
        cached = await self._cache.get_services(
            mgmt_name=mgmt_name,
            domain_name=domain,
            types=types,
            names=names,
            uids=uids,
        )
        if not include_global and domain is None:
            cached = [s for s in cached if s.domain_name != "Global"]
        return ServiceCacheService.apply_context_overlay(
            cached,
            mgmt_name=mgmt_name,
            domain_name=domain,
            include_global=include_global,
            types=types,
            names=names,
            uids=uids,
        )

    async def _get_service_by_uid_for_find(
        self,
        mgmt_name: str,
        domain: str,
        uid: str,
        *,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> CPService | None:
        """Fetch a single service by UID via `ServiceCacheService` or `ServiceCachePort` + overlay."""
        if self._service_cache is not None:
            return await self._service_cache.get_service_by_uid(
                mgmt_name,
                domain,
                uid,
                cache_mode=cache_mode,
                cache_ttl=cache_ttl,
            )
        ws = get_write_session(mgmt_name=mgmt_name, domain_name=domain)
        if ws is not None:
            touched, overlaid = ws.overlay.lookup_service_by_uid(uid)
            if touched:
                return overlaid
        svc = await self._cache.get_service_by_uid(mgmt_name, domain, uid)
        if svc is not None and ws is not None:
            return ws.overlay.apply_to_single_service(svc)
        return svc

    async def _get_assets_for_find(
        self,
        *,
        mgmt_name: str,
        domain: str | None,
        types: Sequence[str] | None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[Asset]:
        """Fetch assets via `AssetRefreshService` or fall back directly to `AssetCachePort`."""
        if self._asset_service is not None:
            return await self._asset_service.get_assets(
                mgmt_name=mgmt_name,
                domain=domain,
                types=types,
                include_global=include_global,
                cache_mode=cache_mode,
                cache_ttl=cache_ttl,
            )
        cached_assets = await self._cache.get_assets(
            mgmt_name=mgmt_name,
            domain_name=domain,
            types=types,
        )
        if not include_global and domain is None:
            cached_assets = [a for a in cached_assets if a.domain_name != "Global"]
        return cached_assets

    @traced(module=_SEARCH_TRACE_MODULE)
    async def resolve_group_with_members(
        self,
        mgmt_name: str,
        domain: str | None = None,
        group_name_or_uid: str = "",
        *,
        recursive: bool = True,
        max_depth: int = 5,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> tuple[CPObject | CPService | Asset | None, list[CPObject | CPService | Asset]]:
        """Resolve `(target_group_entity, members)` for `group_name_or_uid` in `(mgmt_name, domain)`."""
        return await resolve_group_with_members_impl(
            self,
            mgmt_name,
            domain,
            group_name_or_uid,
            recursive=recursive,
            max_depth=max_depth,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced(module=_SEARCH_TRACE_MODULE)
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
        """Return direct (and optionally recursive) member `CPObject`, `CPService`, or child `Asset` items."""
        _, members = await self.resolve_group_with_members(
            mgmt_name,
            domain,
            group_name_or_uid,
            recursive=recursive,
            max_depth=max_depth,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )
        return members

    @traced(module=_SEARCH_TRACE_MODULE)
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
        """Find a single `CPObject`, `CPService`, or `Asset` by exact `uid`, `name`, or composite ID."""
        return await find_object_impl(
            self,
            mgmt_name,
            domain,
            name_or_uid,
            obj_type=obj_type,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced(module=_SEARCH_TRACE_MODULE)
    async def describe_objects(
        self,
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        include_global: bool = True,
    ) -> dict[str, Any]:
        """Return progressive-disclosure schema and summary counts for cached objects, services, and assets."""
        return await describe_objects_impl(
            self,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            include_global=include_global,
        )

    @traced(module=_SEARCH_TRACE_MODULE)
    async def query_objects(
        self,
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        domains: Sequence[str] | None = None,
        types: Sequence[str] | None = None,
        roles: Sequence[str] | None = None,
        platforms: Sequence[str] | None = None,
        is_policy_target: bool | None = None,
        is_execution_target: bool | None = None,
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
        """Execute structured cross-domain filtering, grouping, counting, or schema description."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, aggregate=aggregate, cache_mode=cache_mode)
        return await query_objects_impl(
            self,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            domains=domains,
            types=types,
            roles=roles,
            platforms=platforms,
            is_policy_target=is_policy_target,
            is_execution_target=is_execution_target,
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

    @traced(module=_SEARCH_TRACE_MODULE)
    async def get_cache_status(
        self,
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        scope: SyncScope | None = None,
    ) -> dict[str, Any]:
        """Inspect `domain_sync_state` across scopes and return per-domain/per-type freshness."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, scope=scope)
        return await get_cache_status_impl(
            self,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            scope=scope,
        )
