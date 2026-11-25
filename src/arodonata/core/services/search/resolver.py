"""Group/service-group/asset membership resolution, deduplication, and implicit domain mode helpers."""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from typing import Any

from arodonata.core.errors import AmbiguousObjectError, ServerIdentityError, ValidationError
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CacheMode
from arodonata.core.models.objects import CPObject
from arodonata.core.models.services import CPService
from arodonata.core.primitives import parse_composite_id
from arodonata.core.services.service_cache import ServiceCacheService


def dedup_entities_by_uid(
    items: Sequence[CPObject | CPService | Asset],
) -> list[CPObject | CPService | Asset]:
    """Deduplicate cross-domain entities by `uid`, preferring the owning (`original_domain` / `Global`) copy."""
    by_uid: dict[str, CPObject | CPService | Asset] = {}
    order: list[str] = []
    for item in items:
        uid = item.uid
        if uid not in by_uid:
            by_uid[uid] = item
            order.append(uid)
        else:
            existing = by_uid[uid]
            orig = getattr(item, "original_domain", None) or item.domain_name
            existing_orig = getattr(existing, "original_domain", None) or existing.domain_name
            if (
                item.domain_name == orig
                and existing.domain_name != existing_orig
                or item.domain_name == "Global"
                and existing.domain_name != "Global"
            ):
                by_uid[uid] = item
    return [by_uid[u] for u in order]


def _expand_group_bfs(
    target_group: CPObject | CPService,
    all_entities: Sequence[Any],
    *,
    recursive: bool,
    max_depth: int,
) -> list[CPObject | CPService | Asset]:
    """Shared BFS expansion over `CPObject` groups and `CPService` service-groups."""
    group_domain = target_group.domain_name
    scoped = [e for e in all_entities if e.domain_name in (group_domain, "Global")]
    by_uid: dict[str, Any] = {e.uid: e for e in scoped}
    for e in all_entities:
        by_uid.setdefault(e.uid, e)
    members: list[CPObject | CPService | Asset] = []
    seen_uids: set[str] = {target_group.uid}
    queue: deque[tuple[str, int]] = deque((m_uid, 1) for m_uid in target_group.members)
    while queue:
        m_uid, depth = queue.popleft()
        if m_uid in seen_uids:
            continue
        seen_uids.add(m_uid)
        member_item = by_uid.get(m_uid)
        if member_item is None:
            continue
        members.append(member_item)
        if recursive and depth < max_depth and member_item.members:
            for child_uid in member_item.members:
                if child_uid not in seen_uids:
                    queue.append((child_uid, depth + 1))
    return members


async def resolve_implicit_domain_mode_impl(
    svc: Any,
    mgmt_name: str,
    eff_domain: str | None,
    cache_mode: CacheMode,
) -> tuple[str | None, CacheMode]:
    """Resolve `(single_domain_or_none, effective_cache_mode)` when `domain` is omitted."""
    if eff_domain is not None:
        return eff_domain, cache_mode
    if cache_mode == "cache":
        return None, "cache"

    cached_domains = await svc._cache.get_domains(mgmt_name, include_global=True)
    if not cached_domains:
        cached_objs = await svc._cache.get_objects(mgmt_name=mgmt_name)
        seeded_non_global = {o.domain_name for o in cached_objs if o.domain_name and o.domain_name != "Global"}
        if len(seeded_non_global) > 1:
            return None, "cache"
        coord = getattr(svc._object_service, "_coordinator", None)
        dom_svc = getattr(coord, "_domain_service", None) if coord is not None else None
        if dom_svc is not None:
            try:
                cached_domains = await dom_svc.get_domains(
                    mgmt_name=mgmt_name,
                    include_global=True,
                    cache_mode="smart",
                )
            except ServerIdentityError:
                raise
            except Exception:
                cached_domains = await svc._cache.get_domains(mgmt_name, include_global=True)

    non_global = [d.name for d in cached_domains if not d.is_global and d.name != "Global"]
    if len(non_global) > 1:
        return None, "cache"
    if len(non_global) == 1:
        return non_global[0], cache_mode
    return "default", cache_mode


async def _load_object_group_scope(
    svc: Any,
    mgmt_name: str,
    eff_domain: str | None,
    clean_target: str,
    *,
    sync_domain: str | None,
    eff_cache_mode: CacheMode,
    eff_include_global: bool,
    cache_ttl: float | None,
) -> tuple[list[CPObject], list[CPObject], list[CPObject]]:
    """Fetch objects and return `(all_objs, obj_containers, obj_fallbacks)`."""
    if eff_domain is None and eff_cache_mode != "cache" and sync_domain is not None:
        await svc._object_service.refresh_objects(
            mgmt_name=mgmt_name,
            domains=[sync_domain],
            include_global=False,
            mode=eff_cache_mode,
            cache_ttl=cache_ttl,
        )

    all_objs: list[CPObject] = await svc._object_service.get_objects(
        mgmt_name=mgmt_name,
        domain=eff_domain,
        include_global=eff_include_global,
        cache_mode="cache" if eff_domain is None else eff_cache_mode,
        cache_ttl=cache_ttl,
    )
    obj_containers = [
        o
        for o in all_objs
        if o.uid == clean_target and (o.type in ("group", "group-with-exclusion") or bool(o.members))
    ]
    if not obj_containers:
        obj_containers = [
            o
            for o in all_objs
            if clean_target in (o.name, o.object_id, o.id)
            and (o.type in ("group", "group-with-exclusion") or bool(o.members))
        ]
    obj_fallbacks = [o for o in all_objs if o.uid == clean_target] or [
        o for o in all_objs if clean_target in (o.name, o.object_id, o.id)
    ]
    return all_objs, obj_containers, obj_fallbacks


async def _load_service_group_scope(
    svc: Any,
    mgmt_name: str,
    eff_domain: str | None,
    clean_target: str,
    *,
    sync_domain: str | None,
    eff_cache_mode: CacheMode,
    eff_include_global: bool,
    cache_ttl: float | None,
    skip_refresh: bool,
) -> tuple[list[CPService], list[CPService], list[CPService]]:
    """Fetch services and return `(all_svcs, svc_containers, svc_fallbacks)`."""
    if svc._service_cache is not None:
        if eff_domain is None and eff_cache_mode != "cache" and sync_domain is not None and not skip_refresh:
            await svc._service_cache.refresh_services(
                mgmt_name=mgmt_name,
                domains=[sync_domain],
                include_global=False,
                mode=eff_cache_mode,
                cache_ttl=cache_ttl,
            )
        all_svcs: list[CPService] = await svc._service_cache.get_services(
            mgmt_name=mgmt_name,
            domain=eff_domain,
            include_global=eff_include_global,
            cache_mode="cache" if (eff_domain is None or skip_refresh) else eff_cache_mode,
            cache_ttl=cache_ttl,
        )
    else:
        all_svcs = await svc._cache.get_services(mgmt_name=mgmt_name, domain_name=eff_domain)
        all_svcs = ServiceCacheService.apply_context_overlay(
            all_svcs,
            mgmt_name=mgmt_name,
            domain_name=eff_domain,
            include_global=eff_include_global,
        )

    svc_containers = [s for s in all_svcs if s.uid == clean_target and (s.type == "service-group" or bool(s.members))]
    if not svc_containers:
        svc_containers = [
            s
            for s in all_svcs
            if clean_target in (s.name, s.service_id, s.id) and (s.type == "service-group" or bool(s.members))
        ]
    svc_fallbacks = [s for s in all_svcs if s.uid == clean_target] or [
        s for s in all_svcs if clean_target in (s.name, s.service_id, s.id)
    ]
    return all_svcs, svc_containers, svc_fallbacks


async def _load_asset_candidates(
    svc: Any,
    mgmt_name: str,
    eff_domain: str | None,
    clean_target: str,
    *,
    sync_domain: str | None,
    eff_cache_mode: CacheMode,
    eff_include_global: bool,
    cache_ttl: float | None,
    skip_refresh: bool,
) -> tuple[list[Asset], list[Asset]]:
    """Fetch assets and return `(all_assets, asset_candidates)`."""
    if svc._asset_service is not None:
        if eff_domain is None and eff_cache_mode != "cache" and sync_domain is not None and not skip_refresh:
            await svc._asset_service.refresh_assets(
                mgmt_name=mgmt_name,
                domains=[sync_domain],
                include_global=False,
                mode=eff_cache_mode,
                cache_ttl=cache_ttl,
            )
        all_assets: list[Asset] = await svc._asset_service.get_assets(
            mgmt_name=mgmt_name,
            domain=eff_domain,
            include_global=eff_include_global,
            cache_mode="cache" if (eff_domain is None or skip_refresh) else eff_cache_mode,
            cache_ttl=cache_ttl,
        )
    else:
        all_assets = await svc._cache.get_assets(mgmt_name=mgmt_name, domain_name=eff_domain)

    needle_lower = clean_target.lower()
    candidates = [a for a in all_assets if a.uid == clean_target]
    if not candidates:
        candidates = [
            a
            for a in all_assets
            if (
                a.name == clean_target
                or a.asset_id == clean_target
                or a.id == clean_target
                or a.name.lower() == needle_lower
                or a.asset_id.lower() == needle_lower
                or a.id.lower() == needle_lower
            )
        ]
    return all_assets, candidates


async def _expand_asset_children(
    svc: Any,
    mgmt_name: str,
    target_asset: Asset,
    all_assets: Sequence[Asset],
) -> list[CPObject | CPService | Asset]:
    """Resolve child cluster members or virtual systems for `target_asset`."""
    asset_by_uid: dict[str, Asset] = {a.uid: a for a in all_assets}
    for ma in await svc._cache.get_assets(mgmt_name=mgmt_name):
        if ma.uid not in asset_by_uid:
            asset_by_uid[ma.uid] = ma
    asset_by_asset_id: dict[str, Asset] = {a.asset_id: a for a in asset_by_uid.values()}

    child_uids: list[str] = []
    for cuid in [*target_asset.member_uids, *target_asset.virtual_system_uids]:
        if cuid and cuid not in child_uids:
            child_uids.append(cuid)
    for caid in [*target_asset.member_asset_ids, *target_asset.virtual_system_asset_ids]:
        ca_obj = asset_by_asset_id.get(caid)
        if ca_obj is not None and ca_obj.uid not in child_uids:
            child_uids.append(ca_obj.uid)
    for asset in asset_by_uid.values():
        if (
            asset.uid != target_asset.uid
            and asset.uid not in child_uids
            and (
                asset.parent_uid == target_asset.uid
                or asset.parent_id == target_asset.id
                or asset.parent_asset_id == target_asset.asset_id
                or (
                    not asset.parent_uid
                    and not asset.parent_id
                    and (not asset.parent_asset_id or asset.parent_asset_id == target_asset.asset_id)
                    and asset.mgmt_name == target_asset.mgmt_name
                    and asset.domain_name == target_asset.domain_name
                    and asset.parent_name is not None
                    and asset.parent_name.lower() == target_asset.name.lower()
                )
            )
        ):
            child_uids.append(asset.uid)

    return [asset_by_uid[cuid] for cuid in child_uids if cuid in asset_by_uid]


async def resolve_group_with_members_impl(
    svc: Any,
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
    clean_target = group_name_or_uid.strip() if group_name_or_uid else ""
    if not clean_target:
        raise ValidationError("group_name_or_uid must not be empty or whitespace")

    eff_domain = domain.strip() if domain and domain.strip() else None
    if eff_domain is None and clean_target.startswith(f"{mgmt_name}:"):
        parsed_target = parse_composite_id(clean_target, expected_parts=3)
        if parsed_target is not None and parsed_target[0] == mgmt_name:
            eff_domain = parsed_target[1]

    sync_domain, eff_cache_mode = await svc.resolve_implicit_domain_mode(mgmt_name, eff_domain, cache_mode)
    eff_include_global = True if eff_domain is None else (eff_domain == "Global")

    all_objs, obj_containers, obj_fallbacks = await _load_object_group_scope(
        svc,
        mgmt_name,
        eff_domain,
        clean_target,
        sync_domain=sync_domain,
        eff_cache_mode=eff_cache_mode,
        eff_include_global=eff_include_global,
        cache_ttl=cache_ttl,
    )
    if eff_domain is not None and obj_containers:
        deduped_groups = [c for c in svc._dedup_entities_by_uid(obj_containers) if isinstance(c, CPObject)]
        target_group = deduped_groups[0]
        return target_group, _expand_group_bfs(target_group, all_objs, recursive=recursive, max_depth=max_depth)

    all_svcs, svc_containers, svc_fallbacks = await _load_service_group_scope(
        svc,
        mgmt_name,
        eff_domain,
        clean_target,
        sync_domain=sync_domain,
        eff_cache_mode=eff_cache_mode,
        eff_include_global=eff_include_global,
        cache_ttl=cache_ttl,
        skip_refresh=bool(obj_containers),
    )
    if eff_domain is not None and svc_containers:
        deduped_svcs = [c for c in svc._dedup_entities_by_uid(svc_containers) if isinstance(c, CPService)]
        target_svc_group = deduped_svcs[0]
        return target_svc_group, _expand_group_bfs(target_svc_group, all_svcs, recursive=recursive, max_depth=max_depth)

    all_assets, asset_candidates = await _load_asset_candidates(
        svc,
        mgmt_name,
        eff_domain,
        clean_target,
        sync_domain=sync_domain,
        eff_cache_mode=eff_cache_mode,
        eff_include_global=eff_include_global,
        cache_ttl=cache_ttl,
        skip_refresh=bool(obj_containers or svc_containers),
    )

    deduped_obj_containers = (
        [c for c in svc._dedup_entities_by_uid(obj_containers) if isinstance(c, CPObject)] if obj_containers else []
    )
    deduped_svc_containers = (
        [c for c in svc._dedup_entities_by_uid(svc_containers) if isinstance(c, CPService)] if svc_containers else []
    )
    deduped_assets = (
        [c for c in svc._dedup_entities_by_uid(asset_candidates) if isinstance(c, Asset)] if asset_candidates else []
    )
    combined_containers: list[CPObject | CPService | Asset] = [
        *deduped_obj_containers,
        *deduped_svc_containers,
        *deduped_assets,
    ]
    if combined_containers:
        if eff_domain is None:
            distinct_domains = {
                (c.original_domain or c.domain_name) if isinstance(c, (CPObject, CPService)) else c.domain_name
                for c in combined_containers
            }
            if len(distinct_domains) > 1:
                raise AmbiguousObjectError(
                    mgmt_name,
                    clean_target,
                    [c.model_dump(mode="json") for c in combined_containers],
                )
        if deduped_obj_containers:
            target_group = deduped_obj_containers[0]
            return target_group, _expand_group_bfs(target_group, all_objs, recursive=recursive, max_depth=max_depth)
        if deduped_svc_containers:
            target_svc_group = deduped_svc_containers[0]
            return target_svc_group, _expand_group_bfs(
                target_svc_group, all_svcs, recursive=recursive, max_depth=max_depth
            )

        target_asset = deduped_assets[0]
        return target_asset, await _expand_asset_children(svc, mgmt_name, target_asset, all_assets)

    deduped_obj_fb = (
        [c for c in svc._dedup_entities_by_uid(obj_fallbacks) if isinstance(c, CPObject)] if obj_fallbacks else []
    )
    deduped_svc_fb = (
        [c for c in svc._dedup_entities_by_uid(svc_fallbacks) if isinstance(c, CPService)] if svc_fallbacks else []
    )
    combined_fb: list[CPObject | CPService] = [*deduped_obj_fb, *deduped_svc_fb]
    if combined_fb:
        if eff_domain is None:
            distinct_fb_domains = {(c.original_domain or c.domain_name) for c in combined_fb}
            if len(distinct_fb_domains) > 1:
                raise AmbiguousObjectError(
                    mgmt_name,
                    clean_target,
                    [c.model_dump(mode="json") for c in combined_fb],
                )
        return combined_fb[0], []

    return None, []
