"""Structured cross-domain object/service/asset filtering, aggregation, and cache-status helpers."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from fnmatch import fnmatchcase
from typing import Any, Literal, cast

from arodonata.core.errors import ValidationError
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import (
    CANONICAL_ASSET_TYPES,
    QUERY_GROUP_BY_ALIASES,
    CacheMode,
    SyncScope,
    expand_asset_type,
    normalize_any_type,
)
from arodonata.core.models.objects import CPObject
from arodonata.core.models.services import CPService
from arodonata.core.services.object_service import ObjectService
from arodonata.core.services.search.terms import classify_search_term, matches_classified_term
from arodonata.core.services.service_cache import ServiceCacheService

_CANONICAL_ASSET_TYPES_LOWER: frozenset[str] = frozenset(t.lower() for t in CANONICAL_ASSET_TYPES)

ALLOWED_QUERY_GROUP_BY_FIELDS: frozenset[str] = frozenset(
    {
        "mgmt_name",
        "domain_name",
        "original_domain",
        "type",
        "color",
        "protocol",
        "name",
        "uid",
        "id",
        "object_id",
        "service_id",
        "asset_id",
        "port",
        "ipv4_address",
        "ipv6_address",
        "subnet4",
        "mask_length4",
        "fqdn",
        "parent_id",
        "parent_uid",
        "parent_name",
        "parent_asset_id",
        "version",
        "os_name",
        "hardware",
        "sic_status",
        "is_sub_domain",
        "primary_category",
    }
)


def resolve_query_scopes(
    types: Sequence[str] | None,
    *,
    port: str | None = None,
    protocol: str | None = None,
    parent_id: str | None = None,
    parent_asset_id: str | None = None,
) -> tuple[list[str] | None, bool, bool, bool]:
    """Normalize `types` filters and compute `(requested_types, want_objects, want_services, want_assets)`."""
    requested_types: list[str] | None = None
    if types is not None:
        requested_types = []
        seen_req_types: set[str] = set()
        for raw_t in types:
            clean_t = str(raw_t or "").strip()
            if not clean_t:
                continue
            any_t = normalize_any_type(clean_t)
            candidates = (
                tuple(t.lower() for t in expand_asset_type(clean_t))
                if any_t.lower() in _CANONICAL_ASSET_TYPES_LOWER
                else (any_t,)
            )
            for candidate in candidates:
                if candidate not in seen_req_types:
                    seen_req_types.add(candidate)
                    requested_types.append(candidate)

    if requested_types is None:
        has_service_filter = port is not None or protocol is not None
        has_asset_parent_filter = parent_id is not None or parent_asset_id is not None
        if has_service_filter or has_asset_parent_filter:
            return None, False, has_service_filter, has_asset_parent_filter
        return None, True, False, False

    want_objects = any(not t.startswith("service-") and t not in _CANONICAL_ASSET_TYPES_LOWER for t in requested_types)
    want_services = any(t.startswith("service-") for t in requested_types)
    want_assets = any(t in _CANONICAL_ASSET_TYPES_LOWER for t in requested_types)
    return requested_types, want_objects, want_services, want_assets


def _parse_and_validate_group_by(group_by: Sequence[str] | None) -> list[tuple[str, list[str]]]:
    """Validate `group_by` fields against `ALLOWED_QUERY_GROUP_BY_FIELDS` and collapse aliases."""
    if group_by is None or len(group_by) == 0:
        return []
    raw_group_fields = [g.strip() for g in group_by if g and g.strip()]
    if not raw_group_fields:
        raise ValidationError("group_by must contain at least one valid field name")

    group_specs: list[tuple[str, list[str]]] = []
    canonical_idx: dict[str, int] = {}
    for req_field in raw_group_fields:
        lowered = req_field.lower()
        canonical_attr = QUERY_GROUP_BY_ALIASES.get(lowered, lowered)
        if canonical_attr not in ALLOWED_QUERY_GROUP_BY_FIELDS:
            raise ValidationError(
                f"Unsupported group_by field {req_field!r}. Allowed fields: {sorted(ALLOWED_QUERY_GROUP_BY_FIELDS)}"
            )
        if canonical_attr not in canonical_idx:
            canonical_idx[canonical_attr] = len(group_specs)
            group_specs.append((canonical_attr, [req_field]))
        elif req_field not in group_specs[canonical_idx[canonical_attr]][1]:
            group_specs[canonical_idx[canonical_attr]][1].append(req_field)
    return group_specs


def _apply_query_filters(
    items: list[CPObject | CPService | Asset],
    *,
    target_domains: Sequence[str] | None,
    want_global_dom: bool,
    requested_types: Sequence[str] | None,
    scope_origin: Literal["all", "local", "global"],
    name_pattern: str | None,
    ip_subnet: str | None,
    port: str | None,
    protocol: str | None,
    tags: Sequence[str] | None,
    parent_id: str | None,
    parent_asset_id: str | None,
) -> list[CPObject | CPService | Asset]:
    """Filter combined cached entities according to structured `query_objects` predicates."""
    combined_items = items
    if target_domains is not None:
        dom_set = set(target_domains)
        combined_items = [item for item in combined_items if item.domain_name in dom_set]
    elif not want_global_dom:
        combined_items = [item for item in combined_items if item.domain_name != "Global"]

    if requested_types is not None:
        t_set = set(requested_types)
        combined_items = [item for item in combined_items if item.type.lower() in t_set]

    if scope_origin == "local":
        combined_items = [
            item
            for item in combined_items
            if (getattr(item, "original_domain", None) or item.domain_name) == item.domain_name
            and getattr(item, "original_domain", None) != "Global"
        ]
    elif scope_origin == "global":
        combined_items = [
            item
            for item in combined_items
            if getattr(item, "original_domain", None) == "Global"
            or (
                getattr(item, "original_domain", None) is not None
                and getattr(item, "original_domain", None) != item.domain_name
            )
        ]

    if name_pattern:
        pat = name_pattern.strip().lower()
        has_wild = "*" in pat or "?" in pat

        def _matches_pattern(item: CPObject | CPService | Asset) -> bool:
            comp_id = (
                getattr(item, "object_id", None)
                or getattr(item, "service_id", None)
                or getattr(item, "asset_id", None)
                or ""
            )
            candidates = [item.name.lower(), item.id.lower()]
            if comp_id:
                candidates.append(str(comp_id).lower())
            return any(fnmatchcase(c, pat) for c in candidates) if has_wild else any(pat in c for c in candidates)

        combined_items = [item for item in combined_items if _matches_pattern(item)]

    if ip_subnet:
        ip_term = classify_search_term(ip_subnet)
        combined_items = [
            item
            for item in combined_items
            if (isinstance(item, CPObject) and matches_classified_term(item, ip_term))
            or (isinstance(item, Asset) and item.ipv4_address == ip_subnet.strip())
        ]

    if port is not None:
        p_clean = str(port).strip()
        combined_items = [item for item in combined_items if isinstance(item, CPService) and item.port == p_clean]

    if protocol is not None:
        proto_clean = str(protocol).strip().lower()
        combined_items = [
            item
            for item in combined_items
            if isinstance(item, CPService) and (item.protocol or "").lower() == proto_clean
        ]

    if tags:
        tag_set = {t.lower() for t in tags}
        combined_items = [
            item for item in combined_items if any(t.lower() in tag_set for t in getattr(item, "tags", ()))
        ]

    for attr_name, raw_filter in (("parent_id", parent_id), ("parent_asset_id", parent_asset_id)):
        if raw_filter:
            pat = raw_filter.strip().lower()
            wild = "*" in pat or "?" in pat
            combined_items = [
                item
                for item in combined_items
                if (val := getattr(item, attr_name, None)) is not None
                and (fnmatchcase(str(val).lower(), pat) if wild else str(val).lower() == pat)
            ]

    return combined_items


def _group_query_items(
    combined_items: Sequence[CPObject | CPService | Asset],
    group_specs: Sequence[tuple[str, list[str]]],
    *,
    eff_limit: int,
    eff_offset: int,
) -> dict[str, Any]:
    """Group and aggregate filtered items by validated `(canonical_attr, requested_fields)` specs."""
    grouped_counts: dict[tuple[Any, ...], int] = defaultdict(int)
    for item in combined_items:
        grouped_counts[tuple(getattr(item, ca, None) for ca, _ in group_specs)] += 1

    groups_out: list[dict[str, Any]] = []
    for key_tuple, count_val in sorted(grouped_counts.items(), key=lambda kv: [str(x) for x in kv[0]]):
        row_dict: dict[str, Any] = {}
        for idx, (canonical_attr, req_fields) in enumerate(group_specs):
            val = key_tuple[idx]
            for req_field in req_fields:
                row_dict[req_field] = val
            if canonical_attr not in row_dict:
                row_dict[canonical_attr] = val
        row_dict["count"] = count_val
        groups_out.append(row_dict)

    return {
        "total": len(combined_items),
        "total_groups": len(groups_out),
        "group_by": [ca for ca, _ in group_specs],
        "groups": groups_out[eff_offset : eff_offset + eff_limit],
    }


async def describe_objects_impl(
    svc: Any,
    *,
    mgmt_name: str | None = None,
    domain_name: str | None = None,
    include_global: bool = True,
) -> dict[str, Any]:
    """Return progressive-disclosure schema and summary counts for cached objects, services, and assets."""
    objects = await svc._cache.get_objects(mgmt_name=mgmt_name, domain_name=domain_name)
    services = await svc._cache.get_services(mgmt_name=mgmt_name, domain_name=domain_name)
    assets = await svc._cache.get_assets(mgmt_name=mgmt_name, domain_name=domain_name)
    if not include_global and domain_name is None:
        objects = [o for o in objects if o.domain_name != "Global"]
        services = [s for s in services if s.domain_name != "Global"]
        assets = [a for a in assets if a.domain_name != "Global"]

    objects = ObjectService.apply_context_overlay(
        objects,
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        include_global=include_global,
    )
    services = ServiceCacheService.apply_context_overlay(
        services,
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        include_global=include_global,
    )

    obj_type_counts: dict[str, int] = defaultdict(int)
    svc_type_counts: dict[str, int] = defaultdict(int)
    asset_type_counts: dict[str, int] = defaultdict(int)
    domains_seen: set[str] = set()
    mgmts_seen: set[str] = set()

    for o in objects:
        obj_type_counts[o.type] += 1
        domains_seen.add(o.domain_name)
        mgmts_seen.add(o.mgmt_name)
    for s in services:
        svc_type_counts[s.type] += 1
        domains_seen.add(s.domain_name)
        mgmts_seen.add(s.mgmt_name)
    for a in assets:
        asset_type_counts[a.type] += 1
        domains_seen.add(a.domain_name)
        mgmts_seen.add(a.mgmt_name)

    return {
        "total_objects": len(objects),
        "total_services": len(services),
        "total_assets": len(assets),
        "mgmt_names": sorted(mgmts_seen),
        "domains": sorted(domains_seen),
        "object_types": dict(sorted(obj_type_counts.items())),
        "service_types": dict(sorted(svc_type_counts.items())),
        "asset_types": dict(sorted(asset_type_counts.items())),
        "filterable_fields": [
            "id",
            "object_id",
            "service_id",
            "asset_id",
            "parent_id",
            "parent_asset_id",
            "mgmt_name",
            "domain_name",
            "original_domain",
            "type",
            "name",
            "uid",
            "ipv4_address",
            "subnet4",
            "fqdn",
            "port",
            "protocol",
            "tags",
        ],
        "groupable_fields": [
            "mgmt_name",
            "domain_name",
            "original_domain",
            "type",
            "color",
            "protocol",
        ],
    }


async def query_objects_impl(
    svc: Any,
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
    """Execute structured cross-domain filtering, grouping, counting, or schema description."""
    target_domains = list(domains) if domains is not None else ([domain_name] if domain_name else None)
    want_global_dom = (
        include_global or domain_name == "Global" or (target_domains is not None and "Global" in target_domains)
    )

    if aggregate == "describe":
        if (
            cache_mode != "cache"
            and not await svc._cache.list_sync_states(mgmt_name=mgmt_name, domain_name=domain_name, scope="objects")
            and (
                bool(await svc._cache.list_sync_states(mgmt_name=mgmt_name, domain_name=domain_name, scope="topology"))
                or not await svc._cache.get_objects(mgmt_name=mgmt_name, domain_name=domain_name)
            )
        ):
            await svc._object_service.refresh_objects(
                mgmt_name=mgmt_name,
                domains=target_domains,
                include_global=want_global_dom,
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )
        return cast(
            dict[str, Any],
            await svc.describe_objects(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                include_global=True if domain_name is not None else include_global,
            ),
        )

    group_specs = _parse_and_validate_group_by(group_by)
    requested_types, want_objects, want_services, want_assets = resolve_query_scopes(
        types,
        port=port,
        protocol=protocol,
        parent_id=parent_id,
        parent_asset_id=parent_asset_id,
    )

    if cache_mode != "cache":
        if want_objects:
            obj_types = (
                [t for t in requested_types if not t.startswith("service-") and t not in _CANONICAL_ASSET_TYPES_LOWER]
                if requested_types is not None
                else None
            )
            await svc._object_service.refresh_objects(
                mgmt_name=mgmt_name,
                domains=target_domains,
                types=obj_types,
                include_global=want_global_dom,
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )
        if want_services and svc._service_cache is not None:
            svc_types = (
                [t for t in requested_types if t.startswith("service-")] if requested_types is not None else None
            )
            await svc._service_cache.refresh_services(
                mgmt_name=mgmt_name,
                domains=target_domains,
                types=svc_types,
                include_global=want_global_dom,
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )
        if want_assets and svc._asset_service is not None:
            await svc._asset_service.refresh_assets(
                mgmt_name=mgmt_name,
                domains=target_domains,
                include_global=want_global_dom,
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

    combined_items: list[CPObject | CPService | Asset] = []
    if want_objects:
        objs = await svc._cache.get_objects(mgmt_name=mgmt_name, domain_name=domain_name)
        combined_items.extend(
            ObjectService.apply_context_overlay(
                objs,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                allowed_domains=target_domains,
                include_global=want_global_dom,
            )
        )
    if want_services:
        svcs = await svc._cache.get_services(mgmt_name=mgmt_name, domain_name=domain_name)
        combined_items.extend(
            ServiceCacheService.apply_context_overlay(
                svcs,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                allowed_domains=target_domains,
                include_global=want_global_dom,
            )
        )
    if want_assets:
        combined_items.extend(await svc._cache.get_assets(mgmt_name=mgmt_name, domain_name=domain_name))

    filtered_items = _apply_query_filters(
        combined_items,
        target_domains=target_domains,
        want_global_dom=want_global_dom,
        requested_types=requested_types,
        scope_origin=scope_origin,
        name_pattern=name_pattern,
        ip_subnet=ip_subnet,
        port=port,
        protocol=protocol,
        tags=tags,
        parent_id=parent_id,
        parent_asset_id=parent_asset_id,
    )

    eff_limit = max(1, min(int(limit), 1000))
    eff_offset = max(0, int(offset))

    if group_specs:
        return _group_query_items(filtered_items, group_specs, eff_limit=eff_limit, eff_offset=eff_offset)

    if aggregate == "count":
        return {"total": len(filtered_items), "count": len(filtered_items)}

    sliced = filtered_items[eff_offset : eff_offset + eff_limit]
    return {
        "total": len(filtered_items),
        "from": (eff_offset + 1) if sliced else 0,
        "to": eff_offset + len(sliced),
        "objects": [item.model_dump(mode="json") for item in sliced],
    }


async def get_cache_status_impl(
    svc: Any,
    *,
    mgmt_name: str | None = None,
    domain_name: str | None = None,
    scope: SyncScope | None = None,
) -> dict[str, Any]:
    """Inspect `domain_sync_state` across scopes and return per-domain/per-type freshness."""
    states = await svc._cache.list_sync_states(mgmt_name=mgmt_name, domain_name=domain_name, scope=scope)
    now = svc._now()
    entries: list[dict[str, Any]] = []
    by_scope: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for st in states:
        age_seconds = max(0.0, round((now - st.synced_at).total_seconds(), 3)) if st.synced_at is not None else None
        item = {
            "id": st.id,
            "mgmt_name": st.mgmt_name,
            "domain_name": st.domain_name,
            "scope": st.scope,
            "item_type": st.item_type,
            "status": st.status,
            "object_count": st.object_count,
            "last_published_at": st.last_published_at.isoformat() if st.last_published_at else None,
            "last_session_uid": st.last_session_uid,
            "synced_at": st.synced_at.isoformat() if st.synced_at else None,
            "cache_age_seconds": age_seconds,
            "last_error": st.last_error,
        }
        entries.append(item)
        by_scope[st.scope].append(item)

    return {
        "total_entries": len(entries),
        "supported_scopes": ["domains", "objects", "services", "assets", "rulebase", "topology"],
        "entries": entries,
        "by_scope": dict(by_scope),
    }
