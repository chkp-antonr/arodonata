"""Domain-scoped object loading, on-demand asset/group/object fetching, indexing, and expansion."""

from __future__ import annotations

import asyncio
import ipaddress
from collections import deque
from collections.abc import Sequence
from typing import Any

from arodonata.core.errors import ServerIdentityError
from arodonata.core.models.assets import Asset
from arodonata.core.models.objects import CPObject
from arodonata.core.ports import ApiPort, ObjectCachePort
from arodonata.core.primitives import effective_range_prefix_len, is_uuid, mask_to_prefix_len
from arodonata.core.services._asset_linking import _extract_interfaces_from_generic
from arodonata.core.services.object_service import ObjectService
from arodonata.core.services.topology._shared import TOPOLOGY_OBJECT_LOOKUP_CONCURRENCY
from arodonata.core.services.topology.normalizer import _extract_raw_routes


async def _load_domain_scoped_objects(
    cache: ObjectCachePort,
    mgmt_name: str,
    domain_name: str,
    *,
    global_cache: dict[str, list[CPObject]] | None = None,
    global_lock: asyncio.Lock | None = None,
) -> list[CPObject]:
    """Load cached objects for `(mgmt_name, domain_name)` plus `Global` with write-session overlay."""
    raw_dom_objs = await cache.get_objects(mgmt_name=mgmt_name, domain_name=domain_name)
    dom_objs = ObjectService.apply_context_overlay(
        raw_dom_objs,
        mgmt_name=mgmt_name,
        domain_name=domain_name,
    )
    if domain_name == "Global":
        return dom_objs

    if global_cache is not None and mgmt_name in global_cache:
        global_objs = global_cache[mgmt_name]
    elif global_cache is not None and global_lock is not None:
        async with global_lock:
            if mgmt_name in global_cache:
                global_objs = global_cache[mgmt_name]
            else:
                raw_global = await cache.get_objects(mgmt_name=mgmt_name, domain_name="Global")
                global_objs = ObjectService.apply_context_overlay(
                    raw_global,
                    mgmt_name=mgmt_name,
                    domain_name="Global",
                )
                global_cache[mgmt_name] = global_objs
    else:
        raw_global = await cache.get_objects(mgmt_name=mgmt_name, domain_name="Global")
        global_objs = ObjectService.apply_context_overlay(
            raw_global,
            mgmt_name=mgmt_name,
            domain_name="Global",
        )
        if global_cache is not None:
            global_cache[mgmt_name] = global_objs

    return [*global_objs, *dom_objs]


async def _fetch_asset_detail_on_demand(
    api: ApiPort,
    mgmt_name: str,
    domain_name: str,
    asset: Asset,
) -> Asset | None:
    """Query `show-simple-gateway`, `show-simple-cluster`, or `show-generic-object` when summary lacks interfaces."""
    a_type = asset.type
    commands: list[str] = []
    if a_type in ("simple-cluster", "cluster", "CpmiGatewayCluster"):
        commands = ["show-simple-cluster", "show-generic-object"]
    elif a_type in ("simple-gateway", "gateway", "CpmiGatewayPlain", "CpmiHostCkp"):
        commands = ["show-simple-gateway", "show-generic-object"]
    else:
        commands = ["show-generic-object"]

    for cmd in commands:
        try:
            res = await api.api_call(
                mgmt_name,
                cmd,
                {"uid": asset.uid, "details-level": "full"},
                domain=domain_name,
            )
        except ServerIdentityError:
            raise
        except Exception:
            continue

        if not res.success or not isinstance(res.data, dict) or not res.data:
            continue

        detail_ifs = _extract_interfaces_from_generic(res.data)
        detail_routes = _extract_raw_routes(res.data)
        if not detail_ifs and not detail_routes:
            continue

        merged_raw = dict(asset.raw_data)
        merged_raw.update(res.data)
        new_ifs = detail_ifs if detail_ifs else list(asset.interfaces)
        if detail_ifs:
            merged_raw["interfaces"] = detail_ifs
        return asset.model_copy(update={"interfaces": new_ifs, "raw_data": merged_raw})

    return None


async def _enrich_group_raw_if_needed(
    api: ApiPort,
    mgmt_name: str,
    search_dom: str,
    raw_item: dict[str, Any],
) -> dict[str, Any]:
    """Ensure a `group` or `group-with-exclusion` dict includes `members` / `include`."""
    enriched = dict(raw_item)
    uid_val = str(enriched.get("uid") or "")
    if not uid_val:
        return enriched
    o_type = str(enriched.get("type") or "")
    if o_type == "group" and "members" not in enriched:
        try:
            g_res = await api.api_call(
                mgmt_name,
                "show-group",
                {"uid": uid_val, "details-level": "full"},
                domain=search_dom,
            )
            if g_res.success and isinstance(g_res.data, dict) and g_res.data.get("uid"):
                enriched.update(g_res.data)
        except ServerIdentityError:
            raise
        except Exception:
            pass
    elif o_type == "group-with-exclusion" and "include" not in enriched:
        try:
            ge_res = await api.api_call(
                mgmt_name,
                "show-group-with-exclusion",
                {"uid": uid_val, "details-level": "full"},
                domain=search_dom,
            )
            if ge_res.success and isinstance(ge_res.data, dict) and ge_res.data.get("uid"):
                enriched.update(ge_res.data)
        except ServerIdentityError:
            raise
        except Exception:
            pass
    return enriched


async def _fetch_single_topology_object_raw(
    api: ApiPort,
    mgmt_name: str,
    search_dom: str,
    ref_uid: str | None,
    ref_name: str | None,
) -> tuple[str, dict[str, Any]] | None:
    """Fetch a single network/group object dictionary from `search_dom` by UID or name."""
    uid_target = ref_uid or (ref_name if ref_name and is_uuid(ref_name) else None)
    if uid_target:
        try:
            res = await api.api_call(
                mgmt_name,
                "show-object",
                {"uid": uid_target, "details-level": "full"},
                domain=search_dom,
            )
        except ServerIdentityError:
            raise
        except Exception:
            res = None
        if res is not None and res.success and isinstance(res.data, dict):
            raw_obj = res.data.get("object") if isinstance(res.data.get("object"), dict) else res.data
            if isinstance(raw_obj, dict) and raw_obj.get("uid"):
                enriched_uid_obj = await _enrich_group_raw_if_needed(api, mgmt_name, search_dom, raw_obj)
                return search_dom, enriched_uid_obj

    name_target = ref_name or (ref_uid if ref_uid and not is_uuid(ref_uid) else None)
    if not name_target:
        return None

    try:
        q_res = await api.api_query(
            mgmt_name,
            "show-objects",
            domain=search_dom,
            details_level="full",
            payload={"filter": name_target},
        )
    except ServerIdentityError:
        raise
    except Exception:
        q_res = None

    if q_res is not None and q_res.success:
        if q_res.objects:
            matched_item: dict[str, Any] | None = None
            for item in q_res.objects:
                if isinstance(item, dict) and str(item.get("name") or "") == name_target:
                    matched_item = dict(item)
                    break
            if matched_item is None:
                lower_target = name_target.lower()
                for item in q_res.objects:
                    if isinstance(item, dict) and str(item.get("name") or "").lower() == lower_target:
                        matched_item = dict(item)
                        break
            if matched_item is not None and matched_item.get("uid"):
                enriched_match = await _enrich_group_raw_if_needed(api, mgmt_name, search_dom, matched_item)
                return search_dom, enriched_match
        return None

    for cmd in ("show-group", "show-network", "show-address-range", "show-host", "show-group-with-exclusion"):
        try:
            res = await api.api_call(
                mgmt_name,
                cmd,
                {"name": name_target, "details-level": "full"},
                domain=search_dom,
            )
        except ServerIdentityError:
            raise
        except Exception:
            continue
        if res.success and isinstance(res.data, dict) and res.data.get("uid"):
            return search_dom, dict(res.data)

    return None


def _unpack_topology_raw_object(
    mgmt_name: str,
    fallback_dom: str,
    raw_obj: dict[str, Any],
) -> tuple[list[CPObject], list[tuple[str | None, str | None]]]:
    """Hydrate `CPObject` plus any complete inline member dicts, returning `(objects, incomplete_child_refs)`."""
    hydrated: list[CPObject] = []
    incomplete_refs: list[tuple[str | None, str | None]] = []
    seen_raw_uids: set[str] = set()
    raw_queue: deque[tuple[str, dict[str, Any]]] = deque([(fallback_dom, raw_obj)])

    while raw_queue:
        cur_dom_hint, cur_raw = raw_queue.popleft()
        cur_uid = str(cur_raw.get("uid") or "")
        if not cur_uid or cur_uid in seen_raw_uids:
            continue
        seen_raw_uids.add(cur_uid)

        eff_dom = cur_dom_hint
        dom_meta = cur_raw.get("domain")
        if isinstance(dom_meta, dict):
            d_name = str(dom_meta.get("name") or "")
            d_type = str(dom_meta.get("domain-type") or dom_meta.get("type") or "").lower()
            if d_name == "Global" or "global" in d_type:
                eff_dom = "Global"

        cp_obj = CPObject.from_cp_dict(mgmt_name, eff_dom, cur_raw)
        if cp_obj.type == "group-with-exclusion":
            inc = cur_raw.get("include")
            if isinstance(inc, dict) and isinstance(inc.get("uid"), str) and inc["uid"]:
                if inc["uid"] not in cp_obj.members:
                    cp_obj = cp_obj.model_copy(update={"members": [*cp_obj.members, inc["uid"]]})
            elif isinstance(inc, str) and inc and inc not in cp_obj.members:
                cp_obj = cp_obj.model_copy(update={"members": [*cp_obj.members, inc]})
        hydrated.append(cp_obj)

        child_items: list[Any] = []
        raw_members = cur_raw.get("members")
        if isinstance(raw_members, list):
            child_items.extend(raw_members)
        if cp_obj.type == "group-with-exclusion" and cur_raw.get("include") is not None:
            child_items.append(cur_raw.get("include"))

        for item in child_items:
            if isinstance(item, str) and item:
                incomplete_refs.append((item, None))
            elif isinstance(item, dict):
                m_uid = str(item.get("uid") or "") or None
                m_name = str(item.get("name") or "") or None
                m_type = str(item.get("type") or "")
                has_host_ip = bool(item.get("ipv4-address") or item.get("ipv4_address") or item.get("ipv6-address"))
                has_net = bool(
                    item.get("subnet4")
                    and (item.get("mask-length4") is not None or item.get("subnet-mask") is not None)
                )
                has_range = bool(item.get("ipv4-address-first") and item.get("ipv4-address-last"))
                has_inline_group = m_type == "group" and isinstance(item.get("members"), list)
                if m_uid and (has_host_ip or has_net or has_range or has_inline_group):
                    raw_queue.append((eff_dom, item))
                elif m_uid or m_name:
                    incomplete_refs.append((m_uid, m_name))

    return hydrated, incomplete_refs


def _index_objects_into(
    by_uid: dict[str, CPObject],
    by_name: dict[str, CPObject],
    objects: Sequence[CPObject],
    *,
    domain_name: str | None = None,
) -> None:
    """Incrementally insert `objects` into `(by_uid, by_name)` while preserving local-over-Global precedence."""
    for obj in objects:
        if domain_name is not None and obj.domain_name not in (domain_name, "Global"):
            continue
        is_local = bool(domain_name and obj.domain_name == domain_name)
        for u_key in (obj.uid, obj.uid.lower()):
            existing_u = by_uid.get(u_key)
            if is_local or existing_u is None or not (domain_name and existing_u.domain_name == domain_name):
                by_uid[u_key] = obj
        for n_key in (
            obj.name,
            obj.name.lower(),
            obj.object_id,
            obj.object_id.lower(),
            obj.id,
            obj.id.lower(),
        ):
            existing_n = by_name.get(n_key)
            if is_local or existing_n is None or not (domain_name and existing_n.domain_name == domain_name):
                by_name[n_key] = obj


def _index_objects(
    objects: Sequence[CPObject],
    *,
    domain_name: str | None = None,
) -> tuple[dict[str, CPObject], dict[str, CPObject]]:
    """Index `CPObject` records by `uid` and `name`, restricted to `domain_name` and `"Global"` (local winning over Global)."""
    by_uid: dict[str, CPObject] = {}
    by_name: dict[str, CPObject] = {}
    _index_objects_into(by_uid, by_name, objects, domain_name=domain_name)
    return by_uid, by_name


async def _resolve_topology_objects_on_demand(
    api: ApiPort,
    cache: ObjectCachePort,
    mgmt_name: str,
    domain_name: str,
    *,
    seed_refs: Sequence[tuple[str | None, str | None]],
    existing_objects: Sequence[CPObject],
    force_refresh: bool = False,
    trusted_object_domains: set[str] | None = None,
    global_cache: dict[str, list[CPObject]] | None = None,
    global_lock: asyncio.Lock | None = None,
) -> list[CPObject]:
    """Cycle-safe bounded BFS resolution of referenced topology objects/groups across `domain_name` and `Global`."""
    merged_objects = list(existing_objects)
    obj_by_uid, obj_by_name = _index_objects(merged_objects, domain_name=domain_name)

    def _is_trusted_cached(obj: CPObject) -> bool:
        return not force_refresh and (trusted_object_domains is None or obj.domain_name in trusted_object_domains)

    pending_wave: list[tuple[str | None, str | None]] = []
    checked_cached_uids: set[str] = set()

    for r_uid, r_name in seed_refs:
        clean_uid = r_uid.strip() if isinstance(r_uid, str) and r_uid.strip() else None
        clean_name = r_name.strip() if isinstance(r_name, str) and r_name.strip() else None
        if not clean_uid and not clean_name:
            continue
        if force_refresh:
            pending_wave.append((clean_uid, clean_name))
            continue

        root = (
            (obj_by_uid.get(clean_uid) if clean_uid else None)
            or (obj_by_name.get(clean_name) if clean_name else None)
            or (obj_by_name.get(clean_uid) if clean_uid else None)
            or (obj_by_uid.get(clean_name) if clean_name else None)
        )
        if root is None or not _is_trusted_cached(root):
            pending_wave.append((clean_uid, clean_name))
            continue

        walk_q: deque[CPObject] = deque([root])
        while walk_q:
            cur_obj = walk_q.popleft()
            if cur_obj.uid in checked_cached_uids:
                continue
            checked_cached_uids.add(cur_obj.uid)
            for m_ref in cur_obj.members:
                child = obj_by_uid.get(m_ref) or obj_by_name.get(m_ref)
                if child is None:
                    pending_wave.append((m_ref, None))
                elif not _is_trusted_cached(child):
                    pending_wave.append((child.uid, child.name))
                elif child.uid not in checked_cached_uids:
                    walk_q.append(child)

    if not pending_wave:
        return merged_objects

    search_domains = [domain_name] if domain_name == "Global" else [domain_name, "Global"]
    sem = asyncio.Semaphore(TOPOLOGY_OBJECT_LOOKUP_CONCURRENCY)
    attempted_keys: set[str] = set()
    resolved_uids: set[str] = set()
    fetched_by_dom_uid: dict[tuple[str, str], CPObject] = {}

    async def _lookup_across_domains(
        q_uid: str | None,
        q_name: str | None,
    ) -> tuple[str, dict[str, Any]] | None:
        async with sem:
            for s_dom in search_domains:
                found = await _fetch_single_topology_object_raw(api, mgmt_name, s_dom, q_uid, q_name)
                if found is not None:
                    return found
            return None

    while pending_wave:
        dedup_wave: list[tuple[str | None, str | None]] = []
        for q_uid, q_name in pending_wave:
            key = f"uid:{q_uid.lower()}" if q_uid else f"name:{(q_name or '').lower()}"
            if key in attempted_keys:
                continue
            if not force_refresh:
                already = (
                    (obj_by_uid.get(q_uid) if q_uid else None)
                    or (obj_by_name.get(q_name) if q_name else None)
                    or (obj_by_name.get(q_uid) if q_uid else None)
                )
                if (
                    already is not None
                    and not already.members
                    and (_is_trusted_cached(already) or already.uid in resolved_uids)
                ):
                    continue
            if q_uid and q_uid in resolved_uids:
                continue
            attempted_keys.add(key)
            dedup_wave.append((q_uid, q_name))

        if not dedup_wave:
            break

        wave_results = await asyncio.gather(*(_lookup_across_domains(u, n) for u, n in dedup_wave))
        next_wave: list[tuple[str | None, str | None]] = []

        for item_res in wave_results:
            if item_res is None:
                continue
            found_dom, raw_dict = item_res
            unpacked_objs, child_refs = _unpack_topology_raw_object(mgmt_name, found_dom, raw_dict)
            for cp_obj in unpacked_objs:
                resolved_uids.add(cp_obj.uid)
                fetched_by_dom_uid[(cp_obj.domain_name, cp_obj.uid)] = cp_obj
            if unpacked_objs:
                merged_objects.extend(unpacked_objs)
                _index_objects_into(obj_by_uid, obj_by_name, unpacked_objs, domain_name=domain_name)

            for c_uid, c_name in child_refs:
                if force_refresh:
                    if not (c_uid and c_uid in resolved_uids):
                        next_wave.append((c_uid, c_name))
                else:
                    cached_child = (
                        (obj_by_uid.get(c_uid) if c_uid else None)
                        or (obj_by_name.get(c_name) if c_name else None)
                        or (obj_by_name.get(c_uid) if c_uid else None)
                    )
                    if cached_child is None or (
                        not _is_trusted_cached(cached_child) and cached_child.uid not in resolved_uids
                    ):
                        next_wave.append((c_uid, c_name))
                    else:
                        # Walk any already-cached child group to catch deeper missing or untrusted members
                        walk_q2: deque[CPObject] = deque([cached_child])
                        while walk_q2:
                            cur2 = walk_q2.popleft()
                            if cur2.uid in checked_cached_uids:
                                continue
                            checked_cached_uids.add(cur2.uid)
                            for m_ref2 in cur2.members:
                                ch2 = obj_by_uid.get(m_ref2) or obj_by_name.get(m_ref2)
                                if ch2 is None:
                                    next_wave.append((m_ref2, None))
                                elif not _is_trusted_cached(ch2) and ch2.uid not in resolved_uids:
                                    next_wave.append((ch2.uid, ch2.name))
                                elif ch2.uid not in checked_cached_uids:
                                    walk_q2.append(ch2)

        pending_wave = next_wave

    if not fetched_by_dom_uid:
        return merged_objects

    newly_fetched = list(fetched_by_dom_uid.values())
    await cache.upsert_objects(newly_fetched, sync_states=None)

    new_global = [o for o in newly_fetched if o.domain_name == "Global"]
    if new_global and global_cache is not None:
        if global_lock is not None:
            async with global_lock:
                cur_glob = {o.uid: o for o in global_cache.get(mgmt_name, [])}
                for g_obj in new_global:
                    cur_glob[g_obj.uid] = g_obj
                global_cache[mgmt_name] = ObjectService.apply_context_overlay(
                    list(cur_glob.values()),
                    mgmt_name=mgmt_name,
                    domain_name="Global",
                )
        else:
            cur_glob = {o.uid: o for o in global_cache.get(mgmt_name, [])}
            for g_obj in new_global:
                cur_glob[g_obj.uid] = g_obj
            global_cache[mgmt_name] = ObjectService.apply_context_overlay(
                list(cur_glob.values()),
                mgmt_name=mgmt_name,
                domain_name="Global",
            )

    # Deduplicate merged_objects by (domain_name, uid) with newly fetched objects applied, then write-session overlay
    by_dom_uid: dict[tuple[str, str], CPObject] = {(o.domain_name, o.uid): o for o in existing_objects}
    by_dom_uid.update(fetched_by_dom_uid)
    dom_list = ObjectService.apply_context_overlay(
        [o for o in by_dom_uid.values() if o.domain_name == domain_name],
        mgmt_name=mgmt_name,
        domain_name=domain_name,
    )
    if domain_name == "Global":
        return dom_list
    glob_list = ObjectService.apply_context_overlay(
        [o for o in by_dom_uid.values() if o.domain_name == "Global"],
        mgmt_name=mgmt_name,
        domain_name="Global",
    )
    return [*glob_list, *dom_list]


def _expand_cp_object(
    root_obj: CPObject,
    *,
    obj_by_uid: dict[str, CPObject],
    obj_by_name: dict[str, CPObject],
) -> list[tuple[str, int, int, int, str]]:
    """Cycle-safe BFS expansion of a `CPObject` (`host`, `network`, `address-range`, or nested `group`)."""
    results: list[tuple[str, int, int, int, str]] = []
    seen_intervals: set[str] = set()
    visited_uids: set[str] = set()
    queue: deque[CPObject] = deque([root_obj])
    root_ref = root_obj.name

    while queue:
        curr = queue.popleft()
        if curr.uid in visited_uids:
            continue
        visited_uids.add(curr.uid)

        if curr.ipv4_address:
            try:
                ip_obj = ipaddress.IPv4Address(curr.ipv4_address.strip())
                ip_int = int(ip_obj)
                cidr_str = f"{ip_obj}/32"
                if cidr_str not in seen_intervals:
                    seen_intervals.add(cidr_str)
                    results.append((cidr_str, ip_int, ip_int, 32, root_ref))
            except ValueError:
                pass
        elif curr.subnet4:
            plen = mask_to_prefix_len(curr.mask_length4 if curr.mask_length4 is not None else curr.subnet_mask)
            if plen is not None:
                try:
                    net = ipaddress.IPv4Network(f"{curr.subnet4.strip()}/{plen}", strict=False)
                    cidr_str = str(net)
                    if cidr_str not in seen_intervals:
                        seen_intervals.add(cidr_str)
                        results.append(
                            (
                                cidr_str,
                                int(net.network_address),
                                int(net.broadcast_address),
                                net.prefixlen,
                                root_ref,
                            )
                        )
                except ValueError:
                    pass
        elif curr.ipv4_address_first and curr.ipv4_address_last:
            try:
                ip1 = ipaddress.IPv4Address(curr.ipv4_address_first.strip())
                ip2 = ipaddress.IPv4Address(curr.ipv4_address_last.strip())
                lo = min(int(ip1), int(ip2))
                hi = max(int(ip1), int(ip2))
                range_str = f"{ipaddress.IPv4Address(lo)}-{ipaddress.IPv4Address(hi)}"
                if range_str not in seen_intervals:
                    seen_intervals.add(range_str)
                    results.append((range_str, lo, hi, effective_range_prefix_len(lo, hi), root_ref))
            except ValueError:
                pass

        if curr.members:
            for m_ref in curr.members:
                child = obj_by_uid.get(m_ref) or obj_by_name.get(m_ref)
                if child is not None and child.uid not in visited_uids:
                    queue.append(child)

    return results


def _expand_specific_reference(
    *,
    ref_uid: str | None,
    ref_name: str | None,
    obj_by_uid: dict[str, CPObject],
    obj_by_name: dict[str, CPObject],
) -> list[tuple[str, int, int, int, str]]:
    """Recursively expand a Check Point network object or group into `(cidr_or_range, lo, hi, prefix_len, source_ref)` tuples."""
    root_obj: CPObject | None = None
    if ref_uid and ref_uid in obj_by_uid:
        root_obj = obj_by_uid[ref_uid]
    elif ref_name and ref_name in obj_by_name:
        root_obj = obj_by_name[ref_name]
    elif ref_uid and ref_uid in obj_by_name:
        root_obj = obj_by_name[ref_uid]

    if root_obj is None:
        return []

    return _expand_cp_object(root_obj, obj_by_uid=obj_by_uid, obj_by_name=obj_by_name)
