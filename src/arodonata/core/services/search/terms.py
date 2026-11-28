"""Search term classification, term matching, and BFS group-membership resolution."""

from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from collections.abc import Sequence
from fnmatch import fnmatchcase
from typing import Any, Literal

from arodonata.core.models.assets import Asset
from arodonata.core.models.common import (
    DEFAULT_OBJECT_TYPES,
    CacheMode,
    partition_entity_types,
)
from arodonata.core.models.objects import CPObject, GroupMembershipNode, SearchResult
from arodonata.core.primitives import is_uuid, normalize_str_sequence, object_ipv4_bounds
from arodonata.core.services.object_service import ObjectService

SearchTermKind = Literal["ipv4", "cidr", "range", "wildcard", "uid", "name"]


class ClassifiedSearchTerm:
    """Parsed representation of a single search term."""

    def __init__(
        self,
        raw: str,
        kind: SearchTermKind,
        *,
        ip: ipaddress.IPv4Address | None = None,
        network: ipaddress.IPv4Network | None = None,
        range_bounds: tuple[int, int] | None = None,
    ) -> None:
        self.raw = raw
        self.kind = kind
        self.ip = ip
        self.network = network
        self.range_bounds = range_bounds


def classify_search_term(term: str) -> ClassifiedSearchTerm:
    """Classify a single search term into `"ipv4"`, `"cidr"`, `"range"`, `"wildcard"`, `"uid"`, or `"name"`."""
    cleaned = term.strip()
    if is_uuid(cleaned):
        return ClassifiedSearchTerm(cleaned, "uid")

    if "/" in cleaned and "*" not in cleaned and "?" not in cleaned:
        try:
            net = ipaddress.IPv4Network(cleaned, strict=False)
            return ClassifiedSearchTerm(cleaned, "cidr", network=net)
        except ValueError:
            pass

    if "-" in cleaned and cleaned.count("-") == 1 and "*" not in cleaned and "?" not in cleaned:
        left, right = cleaned.split("-", 1)
        try:
            ip_start = ipaddress.IPv4Address(left.strip())
            ip_end = ipaddress.IPv4Address(right.strip())
            lo = min(int(ip_start), int(ip_end))
            hi = max(int(ip_start), int(ip_end))
            return ClassifiedSearchTerm(cleaned, "range", range_bounds=(lo, hi))
        except ValueError:
            pass

    if "*" in cleaned or "?" in cleaned:
        return ClassifiedSearchTerm(cleaned, "wildcard")

    try:
        ip_addr = ipaddress.IPv4Address(cleaned)
        return ClassifiedSearchTerm(cleaned, "ipv4", ip=ip_addr)
    except ValueError:
        pass

    return ClassifiedSearchTerm(cleaned, "name")


def matches_classified_term(
    obj: CPObject,
    term: ClassifiedSearchTerm,
    *,
    exact_match: bool = False,
) -> bool:
    """Return `True` if `obj` matches `term`."""
    if term.kind == "uid":
        return obj.uid.lower() == term.raw.lower()

    if term.kind == "ipv4" and term.ip is not None:
        target_int = int(term.ip)
        bounds = object_ipv4_bounds(obj)
        if exact_match:
            if bounds is not None:
                lo, hi = bounds
                if lo == target_int and hi == target_int:
                    return True
            return term.raw == (obj.ipv4_address or "")
        if bounds is not None:
            lo, hi = bounds
            if lo <= target_int <= hi:
                return True
        return term.raw in (obj.ipv4_address or "", obj.name)

    if term.kind == "cidr" and term.network is not None:
        q_lo = int(term.network.network_address)
        q_hi = int(term.network.broadcast_address)
        bounds = object_ipv4_bounds(obj)
        if bounds is not None:
            o_lo, o_hi = bounds
            if exact_match:
                return o_lo >= q_lo and o_hi <= q_hi
            return not (o_hi < q_lo or o_lo > q_hi)
        return False

    if term.kind == "range" and term.range_bounds is not None:
        q_lo, q_hi = term.range_bounds
        bounds = object_ipv4_bounds(obj)
        if bounds is not None:
            o_lo, o_hi = bounds
            if exact_match:
                return o_lo >= q_lo and o_hi <= q_hi
            return not (o_hi < q_lo or o_lo > q_hi)
        return False

    if term.kind == "wildcard":
        pattern = term.raw.lower()
        candidates = [
            obj.name,
            obj.uid,
            obj.object_id,
            obj.id,
            obj.fqdn or "",
            obj.ipv4_address or "",
            obj.subnet4 or "",
            obj.comments or "",
        ]
        return any(c and fnmatchcase(c.lower(), pattern) for c in candidates)

    needle = term.raw.lower()
    if exact_match:
        exact_candidates = [
            obj.name,
            obj.uid,
            obj.object_id,
            obj.id,
            obj.fqdn or "",
            obj.ipv4_address or "",
            obj.subnet4 or "",
        ]
        return any(c.lower() == needle for c in exact_candidates if c)

    candidates = [
        obj.name,
        obj.uid,
        obj.object_id,
        obj.id,
        obj.fqdn or "",
        obj.ipv4_address or "",
        obj.subnet4 or "",
        obj.comments or "",
    ]
    return any(needle in c.lower() for c in candidates if c)


def resolve_group_memberships(
    matches: Sequence[CPObject],
    all_objects: Sequence[CPObject],
    *,
    max_depth: int,
) -> dict[str, list[GroupMembershipNode]]:
    """Build reverse member-to-group index per `(mgmt_name, domain_name)` and traverse BFS up to `max_depth`."""
    reverse_groups: dict[tuple[str, str, str], list[CPObject]] = defaultdict(list)
    for obj in all_objects:
        if obj.type in ("group", "group-with-exclusion") or obj.members:
            for member_uid in obj.members:
                reverse_groups[(obj.mgmt_name, obj.domain_name, member_uid)].append(obj)

    result: dict[str, list[GroupMembershipNode]] = {}
    for match in matches:
        direct_parents = reverse_groups.get((match.mgmt_name, match.domain_name, match.uid), [])
        if not direct_parents:
            continue

        nodes_by_id: dict[str, GroupMembershipNode] = {n.id: n for n in result.get(match.uid, [])}
        queue: deque[tuple[CPObject, int]] = deque((g, 1) for g in direct_parents)
        visited_at_depth: dict[str, int] = {}

        while queue:
            grp, depth = queue.popleft()
            if depth > max_depth or (grp.id in visited_at_depth and visited_at_depth[grp.id] <= depth):
                continue
            visited_at_depth[grp.id] = depth

            higher_groups = reverse_groups.get((grp.mgmt_name, grp.domain_name, grp.uid), [])
            candidate_node = GroupMembershipNode(
                id=grp.id,
                object_id=grp.object_id,
                uid=grp.uid,
                name=grp.name,
                mgmt_name=grp.mgmt_name,
                domain_name=grp.domain_name,
                depth=depth,
                parent_uids=[hg.uid for hg in higher_groups],
                parent_object_ids=[hg.object_id for hg in higher_groups],
            )
            existing_node = nodes_by_id.get(grp.id)
            if existing_node is None or depth < existing_node.depth:
                nodes_by_id[grp.id] = candidate_node

            if depth < max_depth:
                for hg in higher_groups:
                    if hg.uid != match.uid:
                        queue.append((hg, depth + 1))

        if nodes_by_id:
            result[match.uid] = sorted(
                nodes_by_id.values(),
                key=lambda n: (n.depth, n.mgmt_name, n.domain_name, n.name),
            )

    return result


def _asset_to_probe_object(asset: Asset) -> CPObject:
    """Convert an `Asset` to a `CPObject` projection for search-term matching and results."""
    return CPObject(
        id=asset.id,
        object_id=asset.asset_id,
        uid=asset.uid,
        name=asset.name,
        type=asset.type,
        mgmt_name=asset.mgmt_name,
        domain_name=asset.domain_name,
        ipv4_address=asset.ipv4_address,
        ipv6_address=asset.ipv6_address,
        comments=asset.comments,
        color=asset.color,
        raw_data=asset.raw_data,
        updated_at=asset.updated_at,
    )


def asset_matches_classified_term(
    asset: Asset,
    term: ClassifiedSearchTerm,
    *,
    exact_match: bool = False,
) -> bool:
    """Return `True` if `asset`'s primary attributes or interface IPv4 addresses match `term`."""
    probe = _asset_to_probe_object(asset)
    if matches_classified_term(probe, term, exact_match=exact_match):
        return True
    if asset.interfaces:
        for iface in asset.interfaces:
            iface_ip = str(iface.get("ipv4-address") or iface.get("ipv4_address") or "").strip()
            if not iface_ip:
                continue
            if matches_classified_term(
                probe.model_copy(update={"ipv4_address": iface_ip}),
                term,
                exact_match=exact_match,
            ):
                return True
    return False


async def search_objects_impl(
    svc: Any,
    query: str,
    *,
    classified_terms: list[ClassifiedSearchTerm],
    mgmt_name: str | None = None,
    domains: Sequence[str] | str | None = None,
    types: Sequence[str] | None = None,
    include_global: bool = False,
    max_depth: int = 2,
    exact_match: bool = False,
    cache_mode: CacheMode = "smart",
    cache_ttl: float | None = None,
) -> SearchResult:
    """Execute cache-first object/asset term search and parent group expansion."""
    if not classified_terms:
        return SearchResult(query=query, matches=[], memberships={})

    domain_list = normalize_str_sequence(domains) if domains is not None else None
    want_global = include_global or (domain_list is not None and "Global" in domain_list)

    part = partition_entity_types(types, expand_gateway_family=True)
    if part.is_explicit_empty:
        return SearchResult(query=query, matches=[], memberships={})

    obj_types: list[str] | None = part.object_types if types is not None else None
    asset_types_lower: set[str] = {t.lower() for t in part.asset_types}

    want_objects = types is None or bool(obj_types)
    want_assets = bool(asset_types_lower)

    all_objects: list[CPObject] = []
    matched_objects: list[CPObject] = []

    if want_objects:
        sync_types = list(obj_types) if obj_types is not None else list(DEFAULT_OBJECT_TYPES)
        if max_depth > 0 and "group" not in sync_types:
            sync_types.append("group")

        if cache_mode != "cache":
            await svc._object_service.refresh_objects(
                mgmt_name=mgmt_name,
                domains=domain_list,
                types=sync_types,
                include_global=want_global,
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        all_cached = await svc._cache.get_objects(mgmt_name=mgmt_name)
        if domain_list is not None:
            dom_set = set(domain_list)
            all_cached = [o for o in all_cached if o.domain_name in dom_set]
        elif not want_global:
            all_cached = [o for o in all_cached if o.domain_name != "Global"]

        single_dom = domain_list[0] if domain_list and len(domain_list) == 1 else None
        all_objects = ObjectService.apply_context_overlay(
            all_cached,
            mgmt_name=mgmt_name,
            domain_name=single_dom,
            allowed_domains=domain_list,
            include_global=want_global,
        )

        allowed_match_types = set(obj_types) if obj_types is not None else None
        for obj in all_objects:
            if allowed_match_types is not None and obj.type not in allowed_match_types:
                continue
            if any(matches_classified_term(obj, term, exact_match=exact_match) for term in classified_terms):
                matched_objects.append(obj)

    if want_assets:
        if cache_mode != "cache" and svc._asset_service is not None:
            await svc._asset_service.refresh_assets(
                mgmt_name=mgmt_name,
                domains=domain_list,
                include_global=want_global,
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )
        cached_assets = await svc._cache.get_assets(mgmt_name=mgmt_name)
        if domain_list is not None:
            dom_set = set(domain_list)
            cached_assets = [a for a in cached_assets if a.domain_name in dom_set]
        elif not want_global:
            cached_assets = [a for a in cached_assets if a.domain_name != "Global"]

        seen_keys = {(o.mgmt_name, o.domain_name, o.uid) for o in matched_objects}
        for asset in cached_assets:
            if asset.type.lower() not in asset_types_lower:
                continue
            key = (asset.mgmt_name, asset.domain_name, asset.uid)
            if key in seen_keys:
                continue
            if any(asset_matches_classified_term(asset, term, exact_match=exact_match) for term in classified_terms):
                seen_keys.add(key)
                matched_objects.append(_asset_to_probe_object(asset))

    memberships: dict[str, list[GroupMembershipNode]] = {}
    if max_depth > 0 and matched_objects:
        if not want_objects:
            if cache_mode != "cache":
                await svc._object_service.refresh_objects(
                    mgmt_name=mgmt_name,
                    domains=domain_list,
                    types=["group"],
                    include_global=want_global,
                    mode=cache_mode,
                    cache_ttl=cache_ttl,
                )
            cached_groups = await svc._cache.get_objects(
                mgmt_name=mgmt_name,
                types=["group", "group-with-exclusion"],
            )
            if domain_list is not None:
                dom_set = set(domain_list)
                cached_groups = [o for o in cached_groups if o.domain_name in dom_set]
            elif not want_global:
                cached_groups = [o for o in cached_groups if o.domain_name != "Global"]
            single_dom = domain_list[0] if domain_list and len(domain_list) == 1 else None
            all_objects = ObjectService.apply_context_overlay(
                cached_groups,
                mgmt_name=mgmt_name,
                domain_name=single_dom,
                allowed_domains=domain_list,
                include_global=want_global,
            )
        memberships = svc._resolve_group_memberships(matched_objects, all_objects, max_depth=max_depth)

    return SearchResult(query=query, matches=matched_objects, memberships=memberships)
