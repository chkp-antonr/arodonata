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

from arodonata.core.models.common import (
    DEFAULT_OBJECT_TYPES,
    CacheMode,
    SyncScope,
    utc_now,
)
from arodonata.core.models.objects import (
    CPObject,
    GroupMembershipNode,
    SearchResult,
)
from arodonata.core.models.services import CPService
from arodonata.core.ports import CachePort
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


def matches_classified_term(obj: CPObject, term: ClassifiedSearchTerm) -> bool:
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
            obj.fqdn or "",
            obj.ipv4_address or "",
            obj.subnet4 or "",
            obj.comments or "",
        ]
        return any(c and fnmatchcase(c.lower(), pattern) for c in candidates)

    # kind == "name"
    needle = term.raw.lower()
    candidates = [
        obj.name,
        obj.uid,
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
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._cache = cache
        self._object_service = object_service
        self._service_cache = service_cache
        self._now = now_fn

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
            if any(matches_classified_term(obj, term) for term in classified_terms):
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

                nodes_by_uid[grp.uid] = GroupMembershipNode(
                    uid=grp.uid,
                    name=grp.name,
                    mgmt_name=grp.mgmt_name,
                    domain_name=grp.domain_name,
                    depth=depth,
                    parent_uids=parent_uids,
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
        domain: str,
        group_name_or_uid: str,
        *,
        recursive: bool = True,
        max_depth: int = 5,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[CPObject]:
        """Return direct (and optionally recursive) member `CPObject` items for a group in `(mgmt_name, domain)`."""
        all_objs = await self._object_service.get_objects(
            mgmt_name=mgmt_name,
            domain=domain,
            include_global=(domain == "Global"),
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )
        by_uid: dict[str, CPObject] = {o.uid: o for o in all_objs}
        target_group: CPObject | None = by_uid.get(group_name_or_uid)
        if target_group is None:
            for obj in all_objs:
                if obj.name == group_name_or_uid and (obj.type in ("group", "group-with-exclusion") or obj.members):
                    target_group = obj
                    break
            if target_group is None:
                for obj in all_objs:
                    if obj.name == group_name_or_uid:
                        target_group = obj
                        break

        if target_group is None:
            return []

        members: list[CPObject] = []
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

    @traced
    async def describe_objects(
        self,
        *,
        mgmt_name: str | None = None,
        domain_name: str | None = None,
        include_global: bool = True,
    ) -> dict[str, Any]:
        """Return progressive-disclosure schema and summary counts for cached objects and services."""
        objects = await self._cache.get_objects(mgmt_name=mgmt_name, domain_name=domain_name)
        services = await self._cache.get_services(mgmt_name=mgmt_name, domain_name=domain_name)
        if not include_global and domain_name is None:
            objects = [o for o in objects if o.domain_name != "Global"]
            services = [s for s in services if s.domain_name != "Global"]

        objects = ObjectService.apply_context_overlay(objects, mgmt_name=mgmt_name, domain_name=domain_name)
        services = ServiceCacheService.apply_context_overlay(services, mgmt_name=mgmt_name, domain_name=domain_name)

        obj_type_counts: dict[str, int] = defaultdict(int)
        svc_type_counts: dict[str, int] = defaultdict(int)
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

        return {
            "total_objects": len(objects),
            "total_services": len(services),
            "mgmt_names": sorted(mgmts_seen),
            "domains": sorted(domains_seen),
            "object_types": dict(sorted(obj_type_counts.items())),
            "service_types": dict(sorted(svc_type_counts.items())),
            "filterable_fields": [
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
        aggregate: Literal["count", "list"] = "list",
        limit: int = 100,
        offset: int = 0,
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> dict[str, Any]:
        """Execute structured cross-domain filtering, grouping, and counting over cached objects and services."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, aggregate=aggregate, cache_mode=cache_mode)

        requested_types = [t.strip().lower() for t in types] if types is not None else None
        want_objects = requested_types is None or any(not t.startswith("service-") for t in requested_types)
        want_services = requested_types is not None and any(t.startswith("service-") for t in requested_types)
        if requested_types is None and (port is not None or protocol is not None):
            want_services = True

        target_domains = list(domains) if domains is not None else ([domain_name] if domain_name else None)
        want_global_dom = (
            include_global or domain_name == "Global" or (target_domains is not None and "Global" in target_domains)
        )

        if cache_mode != "cache":
            if want_objects:
                obj_types = (
                    [t for t in requested_types if not t.startswith("service-")]
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

        combined_items: list[CPObject | CPService] = []

        if want_objects:
            objs = await self._cache.get_objects(mgmt_name=mgmt_name, domain_name=domain_name)
            objs = ObjectService.apply_context_overlay(objs, mgmt_name=mgmt_name, domain_name=domain_name)
            combined_items.extend(objs)

        if want_services:
            svcs = await self._cache.get_services(mgmt_name=mgmt_name, domain_name=domain_name)
            svcs = ServiceCacheService.apply_context_overlay(svcs, mgmt_name=mgmt_name, domain_name=domain_name)
            combined_items.extend(svcs)

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
                if (item.original_domain or item.domain_name) == item.domain_name and item.original_domain != "Global"
            ]
        elif scope_origin == "global":
            combined_items = [
                item
                for item in combined_items
                if item.original_domain == "Global"
                or (item.original_domain is not None and item.original_domain != item.domain_name)
            ]

        if name_pattern:
            pat = name_pattern.strip().lower()
            has_wild = "*" in pat or "?" in pat
            combined_items = [
                item
                for item in combined_items
                if (fnmatchcase(item.name.lower(), pat) if has_wild else pat in item.name.lower())
            ]

        if ip_subnet:
            ip_term = classify_search_term(ip_subnet)
            combined_items = [
                item for item in combined_items if isinstance(item, CPObject) and matches_classified_term(item, ip_term)
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
            combined_items = [item for item in combined_items if any(t.lower() in tag_set for t in item.tags)]

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
