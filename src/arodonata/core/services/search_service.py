"""Cache-first object search, recursive group resolution, and structured aggregation (`SearchService`).

Provides:
- `search_objects`: classifies comma-separated search terms (`"ipv4"`, `"cidr"`, `"range"`,
  `"wildcard"`, `"uid"`, `"name"`), merges any active `WriteSession` overlay from `contextvars`,
  and traverses parent group memberships recursively up to `max_depth` (default 2).
- `describe_objects`: progressive-disclosure metadata describing cached object/service types,
  domains, servers, and filterable/groupable fields.
- `query_objects`: structured cross-domain filtering, grouping (`group_by`), and aggregation
  (`aggregate="count" | "list"`) over `arodonata_objects` and `arodonata_services` (distinguishing
  local vs Global objects via `original_domain`).
- `get_cache_status`: inspects `domain_sync_state` across `"domains"`, `"objects"`, `"services"`,
  `"assets"`, and `"rulebase"`, reporting `last_published_at`, `last_session_uid`, `synced_at`,
  and `cache_age_seconds`.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict, deque
from collections.abc import Callable, Sequence
from datetime import datetime
from fnmatch import fnmatchcase
from typing import Any, Literal

from arodonata.core.errors import AmbiguousObjectError, ValidationError
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import (
    CANONICAL_ASSET_TYPES,
    DEFAULT_OBJECT_TYPES,
    CacheMode,
    SyncScope,
    normalize_any_type,
    to_naive_utc,
    utc_now,
)
from arodonata.core.models.objects import (
    CPObject,
    GroupMembershipNode,
    SearchResult,
)
from arodonata.core.models.services import CPService
from arodonata.core.ports import CachePort
from arodonata.core.services.asset_service import AssetRefreshService
from arodonata.core.services.object_service import ObjectService
from arodonata.core.services.service_cache import ServiceCacheService
from arodonata.core.telemetry import span_attrs, traced

SearchTermKind = Literal["ipv4", "cidr", "range", "wildcard", "uid", "name"]

_UID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


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
    if _UID_RE.match(cleaned):
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


def _object_ipv4_bounds(obj: CPObject) -> tuple[int, int] | None:
    """Return `(min_ip_int, max_ip_int)` for a `host`, `network`, or `address-range` `CPObject`."""
    if obj.ipv4_address:
        try:
            val = int(ipaddress.IPv4Address(obj.ipv4_address.strip()))
            return val, val
        except ValueError:
            return None

    if obj.subnet4:
        mask_part: str | int | None = obj.mask_length4 if obj.mask_length4 is not None else obj.subnet_mask
        cidr_str = f"{obj.subnet4.strip()}/{mask_part}" if mask_part is not None else obj.subnet4.strip()
        try:
            net = ipaddress.IPv4Network(cidr_str, strict=False)
            return int(net.network_address), int(net.broadcast_address)
        except ValueError:
            return None

    if obj.ipv4_address_first and obj.ipv4_address_last:
        try:
            first_int = int(ipaddress.IPv4Address(obj.ipv4_address_first.strip()))
            last_int = int(ipaddress.IPv4Address(obj.ipv4_address_last.strip()))
            return min(first_int, last_int), max(first_int, last_int)
        except ValueError:
            return None

    return None


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
        bounds = _object_ipv4_bounds(obj)
        if bounds is not None:
            lo, hi = bounds
            if lo <= target_int <= hi:
                return True
        return term.raw in (obj.ipv4_address or "", obj.name)

    if term.kind == "cidr" and term.network is not None:
        q_lo = int(term.network.network_address)
        q_hi = int(term.network.broadcast_address)
        bounds = _object_ipv4_bounds(obj)
        if bounds is not None:
            o_lo, o_hi = bounds
            # Match if object is contained in query subnet, contains query subnet, or overlaps it
            return not (o_hi < q_lo or o_lo > q_hi)
        return False

    if term.kind == "range" and term.range_bounds is not None:
        q_lo, q_hi = term.range_bounds
        bounds = _object_ipv4_bounds(obj)
        if bounds is not None:
            o_lo, o_hi = bounds
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

    # kind == "name"
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


class SearchService:
    """Cache-first object search, recursive group membership resolution, and structured queries."""

    def __init__(
        self,
        *,
        cache: CachePort,
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
        """Search cached objects across comma-separated terms and resolve parent group memberships up to `max_depth`."""
        raw_terms = [t.strip() for t in query.split(",") if t.strip()]
        classified_terms = [classify_search_term(t) for t in raw_terms]
        span_attrs(
            query=query,
            mgmt_name=mgmt_name,
            max_depth=max_depth,
            exact_match=exact_match,
            cache_mode=cache_mode,
            term_count=len(classified_terms),
        )

        if not classified_terms:
            return SearchResult(query=query, matches=[], memberships={})

        domain_list: list[str] | None = None
        if isinstance(domains, str):
            domain_list = [d.strip() for d in domains.split(",") if d.strip()]
        elif domains is not None:
            domain_list = [str(d).strip() for d in domains if str(d).strip()]

        want_global = include_global or (domain_list is not None and "Global" in domain_list)

        # Ensure objects (including "group" for membership resolution) are refreshed when cache_mode != "cache"
        sync_types = list(types) if types is not None else list(DEFAULT_OBJECT_TYPES)
        if max_depth > 0 and "group" not in sync_types:
            sync_types.append("group")

        if cache_mode != "cache":
            await self._object_service.refresh_objects(
                mgmt_name=mgmt_name,
                domains=domain_list,
                types=sync_types,
                include_global=want_global,
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        # Load all objects in target scope (including groups for membership resolution)
        all_cached = await self._cache.get_objects(mgmt_name=mgmt_name)
        if domain_list is not None:
            dom_set = set(domain_list)
            all_cached = [o for o in all_cached if o.domain_name in dom_set]
        elif not want_global:
            all_cached = [o for o in all_cached if o.domain_name != "Global"]

        # Apply active WriteSession overlay from contextvars
        single_dom = domain_list[0] if domain_list and len(domain_list) == 1 else None
        all_objects = ObjectService.apply_context_overlay(
            all_cached,
            mgmt_name=mgmt_name,
            domain_name=single_dom,
        )

        allowed_match_types = set(types) if types is not None else None
        matched_objects: list[CPObject] = []
        for obj in all_objects:
            if allowed_match_types is not None and obj.type not in allowed_match_types:
                continue
            if any(matches_classified_term(obj, term, exact_match=exact_match) for term in classified_terms):
                matched_objects.append(obj)

        memberships: dict[str, list[GroupMembershipNode]] = {}
        if max_depth > 0 and matched_objects:
            memberships = self._resolve_group_memberships(
                matched_objects,
                all_objects,
                max_depth=max_depth,
            )

        return SearchResult(
            query=query,
            matches=matched_objects,
            memberships=memberships,
        )

    def _resolve_group_memberships(
        self,
        matches: Sequence[CPObject],
        all_objects: Sequence[CPObject],
        *,
        max_depth: int,
    ) -> dict[str, list[GroupMembershipNode]]:
        """Build reverse member-to-group index per `(mgmt_name, domain_name)` and traverse BFS up to `max_depth`."""
        # Map: (mgmt_name, domain_name, member_uid) -> list[CPObject (group)]
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

            nodes_by_uid: dict[str, GroupMembershipNode] = {}
            # BFS queue of (group_obj, depth)
            queue: deque[tuple[CPObject, int]] = deque((g, 1) for g in direct_parents)
            visited_at_depth: dict[str, int] = {}

            while queue:
                grp, depth = queue.popleft()
                if depth > max_depth:
                    continue
                if grp.uid in visited_at_depth and visited_at_depth[grp.uid] <= depth:
                    continue
                visited_at_depth[grp.uid] = depth

                higher_groups = reverse_groups.get((grp.mgmt_name, grp.domain_name, grp.uid), [])
                parent_uids = [hg.uid for hg in higher_groups]
                parent_object_ids = [hg.object_id for hg in higher_groups]

                nodes_by_uid[grp.uid] = GroupMembershipNode(
                    id=grp.id,
                    object_id=grp.object_id,
                    uid=grp.uid,
                    name=grp.name,
                    mgmt_name=grp.mgmt_name,
                    domain_name=grp.domain_name,
                    depth=depth,
                    parent_uids=parent_uids,
                    parent_object_ids=parent_object_ids,
                )

                if depth < max_depth:
                    for hg in higher_groups:
                        if hg.uid != match.uid:
                            queue.append((hg, depth + 1))

            if nodes_by_uid:
                result[match.uid] = sorted(nodes_by_uid.values(), key=lambda n: (n.depth, n.name))

        return result

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
        """Return direct (and optionally recursive) member `CPObject`, `CPService`, or child `Asset` items for a group, service-group, cluster, or VSX container in `(mgmt_name, domain)` (or across all domains when `domain` is `None`)."""
        clean_target = group_name_or_uid.strip() if group_name_or_uid else ""
        if not clean_target:
            raise ValidationError("group_name_or_uid must not be empty or whitespace")

        eff_domain = domain.strip() if domain and domain.strip() else None
        if eff_domain is None and clean_target.startswith(f"{mgmt_name}:"):
            parts = clean_target.split(":", 2)
            if len(parts) == 3 and parts[1].strip() and parts[2].strip():
                eff_domain = parts[1].strip()

        eff_cache_mode: CacheMode = "cache" if eff_domain is None else cache_mode
        eff_include_global = True if eff_domain is None else (eff_domain == "Global")

        all_objs = await self._object_service.get_objects(
            mgmt_name=mgmt_name,
            domain=eff_domain,
            include_global=eff_include_global,
            cache_mode=eff_cache_mode,
            cache_ttl=cache_ttl,
        )
        target_group: CPObject | None = None
        group_candidates: list[CPObject] = [o for o in all_objs if o.uid == clean_target]
        if not group_candidates:
            group_candidates = [
                o
                for o in all_objs
                if clean_target in (o.name, o.object_id, o.id)
                and (o.type in ("group", "group-with-exclusion") or o.members)
            ]
        if not group_candidates:
            group_candidates = [o for o in all_objs if clean_target in (o.name, o.object_id, o.id)]
        if group_candidates:
            distinct_domains = {o.domain_name for o in group_candidates}
            if eff_domain is None and len(distinct_domains) > 1:
                raise AmbiguousObjectError(
                    mgmt_name,
                    clean_target,
                    [o.model_dump(mode="json") for o in group_candidates],
                )
            target_group = group_candidates[0]

        if target_group is not None:
            group_domain = target_group.domain_name
            scoped_objs = [o for o in all_objs if o.domain_name in (group_domain, "Global")]
            by_uid: dict[str, CPObject] = {o.uid: o for o in scoped_objs}
            for o in all_objs:
                by_uid.setdefault(o.uid, o)
            members: list[CPObject | CPService | Asset] = []
            seen_uids: set[str] = {target_group.uid}
            queue: deque[tuple[str, int]] = deque((m_uid, 1) for m_uid in target_group.members)

            while queue:
                m_uid, depth = queue.popleft()
                if m_uid in seen_uids:
                    continue
                seen_uids.add(m_uid)
                member_obj = by_uid.get(m_uid)
                if member_obj is None:
                    continue
                members.append(member_obj)
                if recursive and depth < max_depth and member_obj.members:
                    for child_uid in member_obj.members:
                        if child_uid not in seen_uids:
                            queue.append((child_uid, depth + 1))

            return members

        # 2. Check arodonata_services for a matching service-group
        if self._service_cache is not None:
            all_svcs = await self._service_cache.get_services(
                mgmt_name=mgmt_name,
                domain=eff_domain,
                include_global=eff_include_global,
                cache_mode=eff_cache_mode,
                cache_ttl=cache_ttl,
            )
        else:
            all_svcs = await self._cache.get_services(mgmt_name=mgmt_name, domain_name=eff_domain)
            all_svcs = ServiceCacheService.apply_context_overlay(all_svcs, mgmt_name=mgmt_name, domain_name=eff_domain)

        target_svc_group: CPService | None = None
        svc_candidates: list[CPService] = [s for s in all_svcs if s.uid == clean_target]
        if not svc_candidates:
            svc_candidates = [
                s
                for s in all_svcs
                if clean_target in (s.name, s.service_id, s.id) and (s.type == "service-group" or s.members)
            ]
        if not svc_candidates:
            svc_candidates = [s for s in all_svcs if clean_target in (s.name, s.service_id, s.id)]
        if svc_candidates:
            distinct_svc_domains = {s.domain_name for s in svc_candidates}
            if eff_domain is None and len(distinct_svc_domains) > 1:
                raise AmbiguousObjectError(
                    mgmt_name,
                    clean_target,
                    [s.model_dump(mode="json") for s in svc_candidates],
                )
            target_svc_group = svc_candidates[0]

        if target_svc_group is not None:
            svc_domain = target_svc_group.domain_name
            scoped_svcs = [s for s in all_svcs if s.domain_name in (svc_domain, "Global")]
            svc_by_uid: dict[str, CPService] = {s.uid: s for s in scoped_svcs}
            for s in all_svcs:
                svc_by_uid.setdefault(s.uid, s)
            svc_members: list[CPObject | CPService | Asset] = []
            seen_svc_uids: set[str] = {target_svc_group.uid}
            svc_queue: deque[tuple[str, int]] = deque((m_uid, 1) for m_uid in target_svc_group.members)

            while svc_queue:
                m_uid, depth = svc_queue.popleft()
                if m_uid in seen_svc_uids:
                    continue
                seen_svc_uids.add(m_uid)
                member_svc = svc_by_uid.get(m_uid)
                if member_svc is None:
                    continue
                svc_members.append(member_svc)
                if recursive and depth < max_depth and member_svc.members:
                    for child_uid in member_svc.members:
                        if child_uid not in seen_svc_uids:
                            svc_queue.append((child_uid, depth + 1))

            return svc_members

        # 3. Check arodonata_assets for a matching cluster or VSX container
        if self._asset_service is not None:
            all_assets = await self._asset_service.get_assets(
                mgmt_name=mgmt_name,
                domain=eff_domain,
                include_global=eff_include_global,
                cache_mode=eff_cache_mode,
                cache_ttl=cache_ttl,
            )
        else:
            all_assets = await self._cache.get_assets(mgmt_name=mgmt_name, domain_name=eff_domain)

        asset_by_uid: dict[str, Asset] = {a.uid: a for a in all_assets}
        needle_lower = clean_target.lower()
        asset_candidates: list[Asset] = [a for a in all_assets if a.uid == clean_target]
        if not asset_candidates:
            asset_candidates = [
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
        target_asset: Asset | None = None
        if asset_candidates:
            distinct_asset_domains = {a.domain_name for a in asset_candidates}
            if eff_domain is None and len(distinct_asset_domains) > 1:
                raise AmbiguousObjectError(
                    mgmt_name,
                    clean_target,
                    [a.model_dump(mode="json") for a in asset_candidates],
                )
            target_asset = asset_candidates[0]

        if target_asset is not None:
            # Also load cross-domain assets on the same mgmt_name if VSX children reside in tenant domains
            mgmt_assets = await self._cache.get_assets(mgmt_name=mgmt_name)
            for ma in mgmt_assets:
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
                        or (asset.parent_name and asset.parent_name.lower() == target_asset.name.lower())
                    )
                ):
                    child_uids.append(asset.uid)

            asset_members: list[CPObject | CPService | Asset] = []
            for cuid in child_uids:
                child_asset = asset_by_uid.get(cuid)
                if child_asset is not None:
                    asset_members.append(child_asset)
            return asset_members

        return []

    @traced
    async def describe_objects(
        self,
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        include_global: bool = True,
    ) -> dict[str, Any]:
        """Return progressive-disclosure schema and summary counts for cached objects, services, and assets."""
        objects = await self._cache.get_objects(mgmt_name=mgmt_name, domain_name=domain_name)
        services = await self._cache.get_services(mgmt_name=mgmt_name, domain_name=domain_name)
        assets = await self._cache.get_assets(mgmt_name=mgmt_name, domain_name=domain_name)
        if not include_global and domain_name is None:
            objects = [o for o in objects if o.domain_name != "Global"]
            services = [s for s in services if s.domain_name != "Global"]
            assets = [a for a in assets if a.domain_name != "Global"]

        objects = ObjectService.apply_context_overlay(objects, mgmt_name=mgmt_name, domain_name=domain_name)
        services = ServiceCacheService.apply_context_overlay(services, mgmt_name=mgmt_name, domain_name=domain_name)

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
        include_global: bool = False,
        group_by: Sequence[str] | None = None,
        aggregate: Literal["count", "list", "describe"] = "list",
        limit: int = 100,
        offset: int = 0,
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> dict[str, Any]:
        """Execute structured cross-domain filtering, grouping, counting, or schema description over cached objects, services, and assets."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, aggregate=aggregate, cache_mode=cache_mode)

        target_domains = list(domains) if domains is not None else ([domain_name] if domain_name else None)
        want_global_dom = (
            include_global or domain_name == "Global" or (target_domains is not None and "Global" in target_domains)
        )

        if aggregate == "describe":
            return await self.describe_objects(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                include_global=True if domain_name is not None else include_global,
            )

        canonical_asset_types_lower = {t.lower() for t in CANONICAL_ASSET_TYPES}
        requested_types = [normalize_any_type(t) for t in types] if types is not None else None
        want_objects = requested_types is None or any(
            not t.startswith("service-") and t not in canonical_asset_types_lower for t in requested_types
        )
        want_services = requested_types is not None and any(t.startswith("service-") for t in requested_types)
        want_assets = requested_types is not None and any(t in canonical_asset_types_lower for t in requested_types)
        if requested_types is None and (port is not None or protocol is not None):
            want_services = True

        if cache_mode != "cache":
            if want_objects:
                obj_types = (
                    [
                        t
                        for t in requested_types
                        if not t.startswith("service-") and t not in canonical_asset_types_lower
                    ]
                    if requested_types is not None
                    else None
                )
                await self._object_service.refresh_objects(
                    mgmt_name=mgmt_name,
                    domains=target_domains,
                    types=obj_types,
                    include_global=want_global_dom,
                    mode=cache_mode,
                    cache_ttl=cache_ttl,
                )
            if want_services and self._service_cache is not None:
                svc_types = (
                    [t for t in requested_types if t.startswith("service-")] if requested_types is not None else None
                )
                await self._service_cache.refresh_services(
                    mgmt_name=mgmt_name,
                    domains=target_domains,
                    types=svc_types,
                    include_global=want_global_dom,
                    mode=cache_mode,
                    cache_ttl=cache_ttl,
                )
            if want_assets and self._asset_service is not None:
                await self._asset_service.refresh_assets(
                    mgmt_name=mgmt_name,
                    domains=target_domains,
                    include_global=want_global_dom,
                    mode=cache_mode,
                    cache_ttl=cache_ttl,
                )

        combined_items: list[CPObject | CPService | Asset] = []

        if want_objects:
            objs = await self._cache.get_objects(mgmt_name=mgmt_name, domain_name=domain_name)
            objs = ObjectService.apply_context_overlay(objs, mgmt_name=mgmt_name, domain_name=domain_name)
            combined_items.extend(objs)

        if want_services:
            svcs = await self._cache.get_services(mgmt_name=mgmt_name, domain_name=domain_name)
            svcs = ServiceCacheService.apply_context_overlay(svcs, mgmt_name=mgmt_name, domain_name=domain_name)
            combined_items.extend(svcs)

        if want_assets:
            assets = await self._cache.get_assets(mgmt_name=mgmt_name, domain_name=domain_name)
            combined_items.extend(assets)

        # Apply filters
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
                if has_wild:
                    return any(fnmatchcase(c, pat) for c in candidates)
                return any(pat in c for c in candidates)

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

        # Grouping
        if group_by:
            group_fields = [g.strip() for g in group_by if g.strip()]
            grouped_counts: dict[tuple[Any, ...], int] = defaultdict(int)
            for item in combined_items:
                key_tuple = tuple(getattr(item, f, None) for f in group_fields)
                grouped_counts[key_tuple] += 1

            groups_out: list[dict[str, Any]] = []
            for key_tuple, count_val in sorted(grouped_counts.items(), key=lambda kv: [str(x) for x in kv[0]]):
                row_dict: dict[str, Any] = {field: key_tuple[idx] for idx, field in enumerate(group_fields)}
                row_dict["count"] = count_val
                groups_out.append(row_dict)

            return {
                "total": len(combined_items),
                "group_by": group_fields,
                "groups": groups_out,
            }

        if aggregate == "count":
            return {
                "total": len(combined_items),
                "count": len(combined_items),
            }

        sliced = combined_items[offset : offset + max(1, limit)]
        return {
            "total": len(combined_items),
            "from": (offset + 1) if sliced else 0,
            "to": offset + len(sliced),
            "objects": [item.model_dump(mode="json") for item in sliced],
        }

    @traced
    async def get_cache_status(
        self,
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        scope: SyncScope | None = None,
    ) -> dict[str, Any]:
        """Inspect `domain_sync_state` across scopes and return per-domain/per-type freshness and `cache_age_seconds`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, scope=scope)
        states = await self._cache.list_sync_states(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            scope=scope,
        )
        now = self._now()
        entries: list[dict[str, Any]] = []
        by_scope: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for st in states:
            age_seconds: float | None = None
            if st.synced_at is not None:
                age_seconds = max(0.0, round((now - st.synced_at).total_seconds(), 3))

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
            "entries": entries,
            "by_scope": dict(by_scope),
        }


__all__ = [
    "ClassifiedSearchTerm",
    "SearchService",
    "SearchTermKind",
    "classify_search_term",
    "matches_classified_term",
]
