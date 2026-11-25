"""Exact/case-insensitive cross-entity object lookup helpers for `SearchService`."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, cast

from arodonata.core.context import SERVICE_COMMAND_TYPES, get_write_session
from arodonata.core.errors import AmbiguousObjectError, ValidationError
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CANONICAL_ASSET_TYPES, CacheMode, normalize_any_type
from arodonata.core.models.objects import CPObject
from arodonata.core.models.services import CPService

_ASSET_TYPES_LOWER: frozenset[str] = frozenset(t.lower() for t in CANONICAL_ASSET_TYPES)


@dataclass(frozen=True, slots=True)
class _ParsedFindTarget:
    clean_query: str
    lookup_key: str
    lookup_names: list[str]
    eff_domain: str | None
    clean_type: str | None
    is_service_type: bool
    is_asset_type: bool


def match_assets(
    assets: Sequence[Asset],
    clean_query: str,
    lookup_key: str,
    *,
    case_insensitive: bool = False,
) -> list[Asset]:
    """Match assets by `uid`, `name`, `asset_id`, or `id` (exact or case-insensitive)."""
    if not case_insensitive:
        return [
            asset
            for asset in assets
            if (
                asset.uid in (clean_query, lookup_key)
                or asset.name in (clean_query, lookup_key)
                or asset.asset_id == clean_query
                or asset.id == clean_query
            )
        ]
    needle_lower = clean_query.lower()
    lookup_lower = lookup_key.lower()
    return [
        asset
        for asset in assets
        if (
            asset.uid.lower() in (needle_lower, lookup_lower)
            or asset.name.lower() in (needle_lower, lookup_lower)
            or asset.asset_id.lower() == needle_lower
            or asset.id.lower() == needle_lower
        )
    ]


def _parse_find_target(
    mgmt_name: str,
    domain: str | None,
    name_or_uid: str,
    obj_type: str | None,
) -> _ParsedFindTarget:
    """Validate and parse target identifiers, type hint, and optional composite domain prefix."""
    clean_query = name_or_uid.strip() if name_or_uid else ""
    if not clean_query:
        raise ValidationError("name_or_uid must not be empty or whitespace")

    clean_type = normalize_any_type(obj_type) if obj_type else None
    is_service_type = clean_type is not None and (
        clean_type in SERVICE_COMMAND_TYPES or clean_type.startswith("service-")
    )
    is_asset_type = clean_type is not None and clean_type in _ASSET_TYPES_LOWER

    eff_domain = domain.strip() if domain and domain.strip() else None
    lookup_key = clean_query
    if eff_domain:
        composite_prefix = f"{mgmt_name}:{eff_domain}:"
        if clean_query.startswith(composite_prefix):
            lookup_key = clean_query.removeprefix(composite_prefix)
    elif clean_query.startswith(f"{mgmt_name}:"):
        parts = clean_query.split(":", 2)
        if len(parts) == 3 and parts[1].strip() and parts[2].strip():
            eff_domain = parts[1].strip()
            lookup_key = parts[2].strip()
    lookup_names = list(dict.fromkeys([clean_query, lookup_key]))
    return _ParsedFindTarget(
        clean_query=clean_query,
        lookup_key=lookup_key,
        lookup_names=lookup_names,
        eff_domain=eff_domain,
        clean_type=clean_type,
        is_service_type=is_service_type,
        is_asset_type=is_asset_type,
    )


async def _find_in_explicit_domain(
    svc: Any,
    mgmt_name: str,
    eff_domain: str,
    target: _ParsedFindTarget,
    *,
    cache_mode: CacheMode,
    cache_ttl: float | None,
) -> CPObject | CPService | Asset | None:
    """Resolve an object, service, or asset within an explicitly known `eff_domain`."""
    ws = get_write_session(mgmt_name=mgmt_name, domain_name=eff_domain)
    clean_type = target.clean_type

    if not target.is_service_type and not target.is_asset_type:
        if ws is not None:
            touched, overlaid = ws.overlay.lookup_object_by_uid(target.lookup_key)
            if touched and overlaid is not None and (clean_type is None or overlaid.type.lower() == clean_type):
                return overlaid

        if cache_mode != "cache":
            await svc._object_service.refresh_objects(
                mgmt_name=mgmt_name,
                domains=[eff_domain],
                types=[clean_type] if clean_type else None,
                include_global=(eff_domain == "Global"),
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        by_uid = await svc._object_service.get_object_by_uid(
            mgmt_name,
            eff_domain,
            target.lookup_key,
            cache_mode="cache",
            cache_ttl=cache_ttl,
        )
        if by_uid is not None and (clean_type is None or by_uid.type.lower() == clean_type):
            return cast(CPObject, by_uid)

        objs = await svc._object_service.get_objects(
            mgmt_name=mgmt_name,
            domain=eff_domain,
            types=[clean_type] if clean_type else None,
            names=target.lookup_names,
            include_global=(eff_domain == "Global"),
            cache_mode="cache",
            cache_ttl=cache_ttl,
        )
        if objs:
            return cast(CPObject, objs[0])

    if target.is_service_type or clean_type is None:
        if ws is not None:
            touched_svc, overlaid_svc = ws.overlay.lookup_service_by_uid(target.lookup_key)
            if (
                touched_svc
                and overlaid_svc is not None
                and (clean_type is None or overlaid_svc.type.lower() == clean_type)
            ):
                return overlaid_svc

        if cache_mode != "cache" and svc._service_cache is not None:
            await svc._service_cache.refresh_services(
                mgmt_name=mgmt_name,
                domains=[eff_domain],
                types=[clean_type] if target.is_service_type and clean_type else None,
                include_global=(eff_domain == "Global"),
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        svc_by_uid = await svc._get_service_by_uid_for_find(
            mgmt_name,
            eff_domain,
            target.lookup_key,
            cache_mode="cache",
            cache_ttl=cache_ttl,
        )
        if svc_by_uid is not None and (clean_type is None or svc_by_uid.type.lower() == clean_type):
            return cast(CPService, svc_by_uid)

        svcs = await svc._get_services_for_find(
            mgmt_name=mgmt_name,
            domain=eff_domain,
            types=[clean_type] if clean_type else None,
            names=target.lookup_names,
            include_global=(eff_domain == "Global"),
            cache_mode="cache",
            cache_ttl=cache_ttl,
        )
        if svcs:
            return cast(CPService, svcs[0])

    if target.is_asset_type or clean_type is None:
        assets = await svc._get_assets_for_find(
            mgmt_name=mgmt_name,
            domain=eff_domain,
            types=[clean_type] if clean_type else None,
            include_global=(eff_domain == "Global"),
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )
        exact_assets = svc._match_assets(assets, target.clean_query, target.lookup_key, case_insensitive=False)
        if exact_assets:
            return cast(Asset, exact_assets[0])
        ci_assets = svc._match_assets(assets, target.clean_query, target.lookup_key, case_insensitive=True)
        if ci_assets:
            return cast(Asset, ci_assets[0])

    return None


def _select_unique_cross_domain_match(
    svc: Any,
    mgmt_name: str,
    clean_query: str,
    chosen_pool: Sequence[CPObject | CPService | Asset],
) -> CPObject | CPService | Asset | None:
    """Deduplicate by UID and raise `AmbiguousObjectError` if multiple domains match."""
    if not chosen_pool:
        return None
    deduped = svc._dedup_entities_by_uid(chosen_pool)
    distinct_domains = {(getattr(item, "original_domain", None) or item.domain_name) for item in deduped}
    if len(distinct_domains) > 1:
        raise AmbiguousObjectError(
            mgmt_name,
            clean_query,
            [item.model_dump(mode="json") for item in deduped],
        )
    return cast(CPObject | CPService | Asset | None, deduped[0])


async def _find_across_domains(
    svc: Any,
    mgmt_name: str,
    target: _ParsedFindTarget,
    *,
    cache_mode: CacheMode,
    cache_ttl: float | None,
) -> CPObject | CPService | Asset | None:
    """Resolve an object across domains, lazily checking freshness on single-domain servers."""
    sync_domain, eff_cross_mode = await svc.resolve_implicit_domain_mode(mgmt_name, None, cache_mode)
    clean_type = target.clean_type
    type_filter = [clean_type] if clean_type else None
    needle_lower = target.clean_query.lower()
    lookup_lower = target.lookup_key.lower()

    async def _fetch_exact_objects() -> list[CPObject]:
        if target.is_service_type or target.is_asset_type:
            return []
        by_uid, by_name = await asyncio.gather(
            svc._object_service.get_objects(
                mgmt_name=mgmt_name,
                domain=None,
                types=type_filter,
                uids=target.lookup_names,
                include_global=True,
                cache_mode="cache",
                cache_ttl=cache_ttl,
            ),
            svc._object_service.get_objects(
                mgmt_name=mgmt_name,
                domain=None,
                types=type_filter,
                names=target.lookup_names,
                include_global=True,
                cache_mode="cache",
                cache_ttl=cache_ttl,
            ),
        )
        return [*by_uid, *by_name]

    async def _fetch_exact_services() -> list[CPService]:
        if not (target.is_service_type or clean_type is None):
            return []
        by_uid, by_name = await asyncio.gather(
            svc._get_services_for_find(
                mgmt_name=mgmt_name,
                domain=None,
                types=type_filter,
                uids=target.lookup_names,
                include_global=True,
                cache_mode="cache",
                cache_ttl=cache_ttl,
            ),
            svc._get_services_for_find(
                mgmt_name=mgmt_name,
                domain=None,
                types=type_filter,
                names=target.lookup_names,
                include_global=True,
                cache_mode="cache",
                cache_ttl=cache_ttl,
            ),
        )
        return [*by_uid, *by_name]

    async def _fetch_all_assets() -> list[Asset]:
        if not (target.is_asset_type or clean_type is None):
            return []
        return cast(
            list[Asset],
            await svc._get_assets_for_find(
                mgmt_name=mgmt_name,
                domain=None,
                types=type_filter,
                include_global=True,
                cache_mode="cache",
                cache_ttl=cache_ttl,
            ),
        )

    async def _collect_ci_matches(pass1_assets: Sequence[Asset]) -> list[CPObject | CPService | Asset]:
        all_objects: list[CPObject] = (
            []
            if (target.is_service_type or target.is_asset_type)
            else cast(
                list[CPObject],
                await svc._object_service.get_objects(
                    mgmt_name=mgmt_name,
                    domain=None,
                    types=type_filter,
                    names=None,
                    include_global=True,
                    cache_mode="cache",
                    cache_ttl=cache_ttl,
                ),
            )
        )
        all_services: list[CPService] = (
            []
            if not (target.is_service_type or clean_type is None)
            else cast(
                list[CPService],
                await svc._get_services_for_find(
                    mgmt_name=mgmt_name,
                    domain=None,
                    types=type_filter,
                    names=None,
                    include_global=True,
                    cache_mode="cache",
                    cache_ttl=cache_ttl,
                ),
            )
        )
        ci_matches: list[CPObject | CPService | Asset] = []
        for o in all_objects:
            if (
                o.uid.lower() in (needle_lower, lookup_lower)
                or o.name.lower() in (needle_lower, lookup_lower)
                or o.object_id.lower() == needle_lower
                or o.id.lower() == needle_lower
            ):
                ci_matches.append(o)
        for s in all_services:
            if (
                s.uid.lower() in (needle_lower, lookup_lower)
                or s.name.lower() in (needle_lower, lookup_lower)
                or s.service_id.lower() == needle_lower
                or s.id.lower() == needle_lower
            ):
                ci_matches.append(s)
        ci_matches.extend(svc._match_assets(pass1_assets, target.clean_query, target.lookup_key, case_insensitive=True))
        return ci_matches

    if sync_domain is not None and eff_cross_mode != "cache":
        if not target.is_service_type and not target.is_asset_type:
            await svc._object_service.refresh_objects(
                mgmt_name=mgmt_name,
                domains=[sync_domain],
                types=[clean_type] if clean_type else None,
                include_global=False,
                mode=eff_cross_mode,
                cache_ttl=cache_ttl,
            )
            exact_objects = await _fetch_exact_objects()
            if exact_objects:
                return _select_unique_cross_domain_match(svc, mgmt_name, target.clean_query, exact_objects)

        if target.is_service_type or clean_type is None:
            if svc._service_cache is not None:
                await svc._service_cache.refresh_services(
                    mgmt_name=mgmt_name,
                    domains=[sync_domain],
                    types=[clean_type] if clean_type else None,
                    include_global=False,
                    mode=eff_cross_mode,
                    cache_ttl=cache_ttl,
                )
            exact_services = await _fetch_exact_services()
            if exact_services:
                return _select_unique_cross_domain_match(svc, mgmt_name, target.clean_query, exact_services)

        pass1_assets: list[Asset] = []
        if target.is_asset_type or clean_type is None:
            if svc._asset_service is not None:
                await svc._asset_service.refresh_assets(
                    mgmt_name=mgmt_name,
                    domains=[sync_domain],
                    include_global=False,
                    mode=eff_cross_mode,
                    cache_ttl=cache_ttl,
                )
            pass1_assets = await _fetch_all_assets()
            exact_assets = svc._match_assets(
                pass1_assets, target.clean_query, target.lookup_key, case_insensitive=False
            )
            if exact_assets:
                return _select_unique_cross_domain_match(svc, mgmt_name, target.clean_query, exact_assets)

        ci_pool = await _collect_ci_matches(pass1_assets)
        return _select_unique_cross_domain_match(svc, mgmt_name, target.clean_query, ci_pool)

    exact_objects, exact_services, pass1_assets = await asyncio.gather(
        _fetch_exact_objects(),
        _fetch_exact_services(),
        _fetch_all_assets(),
    )
    exact_matches: list[CPObject | CPService | Asset] = [
        *exact_objects,
        *exact_services,
        *svc._match_assets(pass1_assets, target.clean_query, target.lookup_key, case_insensitive=False),
    ]
    if exact_matches:
        return _select_unique_cross_domain_match(svc, mgmt_name, target.clean_query, exact_matches)

    ci_pool = await _collect_ci_matches(pass1_assets)
    return _select_unique_cross_domain_match(svc, mgmt_name, target.clean_query, ci_pool)


async def find_object_impl(
    svc: Any,
    mgmt_name: str,
    domain: str | None = None,
    name_or_uid: str = "",
    *,
    obj_type: str | None = None,
    cache_mode: CacheMode = "smart",
    cache_ttl: float | None = None,
) -> CPObject | CPService | Asset | None:
    """Find a single `CPObject`, `CPService`, or `Asset` by exact `uid`, `name`, or composite ID."""
    target = _parse_find_target(mgmt_name, domain, name_or_uid, obj_type)
    if target.eff_domain is not None:
        return await _find_in_explicit_domain(
            svc,
            mgmt_name,
            target.eff_domain,
            target,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )
    return await _find_across_domains(
        svc,
        mgmt_name,
        target,
        cache_mode=cache_mode,
        cache_ttl=cache_ttl,
    )
