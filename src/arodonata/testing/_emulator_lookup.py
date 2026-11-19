"""Domain lookup, `show-objects` filtering, referential integrity, and unused-object helpers."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from typing import Any

from arodonata.core.models.common import ApiCallResult

from ._emulator_models import (
    ACTION_NAME_TO_UID,
    BUILTIN_SENTINELS,
    ENTITY_SPECS,
    SENTINEL_NAME_TO_UID,
    TRACK_NAME_TO_UID,
    EntitySpec,
    cp_error,
)
from ._emulator_projection import (
    ACCESS_REF_COLS,
    EXTRA_OBJECT_BUCKETS,
    GATEWAY_SHOW_CMD,
    HTTPS_CELL_LIST_FIELDS,
    NAT_REF_COLS,
    THREAT_CELL_LIST_FIELDS,
    extract_ref_uids,
    iter_flat_rule_entries,
)


def as_list(val: Any) -> list[Any]:
    """Coerce a scalar or None value into a list while returning list inputs as-is."""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


def ref_uid(item: Any) -> str:
    """Extract the `uid` or `name` identifier string from a reference value."""
    if isinstance(item, Mapping):
        return str(item.get("uid") or item.get("name") or "")
    return str(item or "")


def ensure_entity_bucket(dom_files: dict[str, Any], spec: EntitySpec) -> list[dict[str, Any]]:
    """Ensure a domain's plural entity bucket exists and return its mutable `objects` list."""
    bucket = dom_files.setdefault(spec.plural_show, {"objects": [], "from": 0, "to": 0, "total": 0})
    objs = bucket.setdefault("objects", [])
    if not isinstance(objs, list):
        objs = []
        bucket["objects"] = objs
    return objs


def refresh_entity_bucket_counts(dom_files: dict[str, Any], spec: EntitySpec) -> None:
    """Recompute `total`, `from`, and `to` metadata on an entity bucket after mutation."""
    bucket = dom_files.get(spec.plural_show)
    if isinstance(bucket, dict) and isinstance(bucket.get("objects"), list):
        count = len(bucket["objects"])
        bucket["total"] = count
        bucket["from"] = 1 if count > 0 else 0
        bucket["to"] = count


def is_global_owned(obj: Mapping[str, Any], owning_dom: str, caller_dom: str) -> bool:
    """Return True when `obj` belongs to Global and `caller_dom` is a local domain."""
    if caller_dom == "Global":
        return False
    if owning_dom == "Global":
        return True
    dom_meta = obj.get("domain")
    return isinstance(dom_meta, Mapping) and str(dom_meta.get("name") or "") == "Global"


def global_read_only_error(target_ref: str, caller_dom: str) -> ApiCallResult:
    """Build a Check Point read-only ownership error for Global objects accessed locally."""
    return cp_error(
        "generic_err_object_read_only",
        f"Cannot modify or delete Global object [{target_ref}] from local domain [{caller_dom}]",
        status_code=400,
        blocking_errors=[
            {
                "message": (
                    f"Object [{target_ref}] belongs to the Global domain and is read-only in domain [{caller_dom}]"
                )
            }
        ],
    )


def find_in_scope(
    scope_files: Mapping[str, Any],
    lookup: str,
    *,
    preferred_spec: EntitySpec | None = None,
    include_extras: bool = True,
) -> tuple[dict[str, Any], EntitySpec | None] | None:
    """Locate a mutable object dict by `uid` or `name` inside a single domain map."""
    if not lookup:
        return None
    specs_to_search: list[EntitySpec] = []
    if preferred_spec is not None:
        specs_to_search.append(preferred_spec)
    for spec in ENTITY_SPECS:
        if preferred_spec is None or spec.obj_type != preferred_spec.obj_type:
            specs_to_search.append(spec)

    for match_field in ("uid", "name"):
        for spec in specs_to_search:
            bucket = scope_files.get(spec.plural_show)
            items = bucket.get("objects", []) if isinstance(bucket, Mapping) else []
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, dict) and item.get(match_field) == lookup:
                    return item, spec

        if include_extras:
            for cmd, col_key in EXTRA_OBJECT_BUCKETS:
                bucket = scope_files.get(cmd)
                items = bucket.get(col_key, []) if isinstance(bucket, Mapping) else []
                if not isinstance(items, list):
                    continue
                for item in items:
                    if isinstance(item, dict) and item.get(match_field) == lookup:
                        return item, None
    return None


def find_effective_object(
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    lookup: str,
    *,
    preferred_spec: EntitySpec | None = None,
    local_only: bool = False,
    allow_sentinels: bool = False,
    include_extras: bool = True,
) -> tuple[dict[str, Any], str, EntitySpec | None] | None:
    """Resolve an object by `uid` or `name` in `dom_name` (and `Global` when inherited)."""
    if not lookup:
        return None
    if allow_sentinels:
        if lookup in BUILTIN_SENTINELS:
            return copy.deepcopy(BUILTIN_SENTINELS[lookup]), "System", None
        lowered = lookup.strip().lower()
        if lowered in SENTINEL_NAME_TO_UID:
            return copy.deepcopy(BUILTIN_SENTINELS[SENTINEL_NAME_TO_UID[lowered]]), "System", None
        if lowered in ACTION_NAME_TO_UID:
            return copy.deepcopy(BUILTIN_SENTINELS[ACTION_NAME_TO_UID[lowered]]), "System", None
        if lowered in TRACK_NAME_TO_UID:
            return copy.deepcopy(BUILTIN_SENTINELS[TRACK_NAME_TO_UID[lowered]]), "System", None

    local_hit = find_in_scope(
        dom_files,
        lookup,
        preferred_spec=preferred_spec,
        include_extras=include_extras,
    )
    if local_hit is not None:
        obj, spec = local_hit
        owner = (
            str(obj.get("domain", {}).get("name") or dom_name) if isinstance(obj.get("domain"), Mapping) else dom_name
        )
        return obj, owner, spec

    if dom_name != "Global" and not local_only and global_files:
        glob_hit = find_in_scope(
            global_files,
            lookup,
            preferred_spec=preferred_spec,
            include_extras=include_extras,
        )
        if glob_hit is not None:
            obj, spec = glob_hit
            return obj, "Global", spec
    return None


def filter_show_objects(
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    req: Mapping[str, Any],
    type_to_cmd: Mapping[str, str],
    match_fn: Callable[[dict[str, Any]], bool],
) -> list[dict[str, Any]]:
    """Gather matching `show-objects` candidates honoring local-first Global shadowing and domain filters."""
    req_type = str(req.get("type") or "object").strip()
    show_only_local = bool(req.get("show-only-local-domain", False))
    raw_domains = req.get("domains-to-process")
    dom_filters = [str(d) for d in raw_domains] if isinstance(raw_domains, list) else []

    include_local = True
    include_global = dom_name != "Global" and not show_only_local
    explicit_global = False
    if dom_filters:
        has_cur = any(d in ("CURRENT_DOMAIN", dom_name) for d in dom_filters)
        explicit_global = "Global" in dom_filters
        include_local = has_cur or not explicit_global
        include_global = explicit_global and dom_name != "Global" and not show_only_local
        if dom_filters == ["CURRENT_DOMAIN"]:
            include_local = True
            include_global = False

    def _collect_scope(scope_files: Mapping[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if req_type in type_to_cmd:
            plural_payload = scope_files.get(type_to_cmd[req_type], {})
            raw_items = plural_payload.get("objects", []) if isinstance(plural_payload, Mapping) else []
            for item in raw_items:
                if not isinstance(item, dict):
                    continue
                item_type = item.get("type")
                if item_type is not None and str(item_type) != req_type:
                    continue
                out.append(item)
        elif req_type == "object":
            for plural_cmd in type_to_cmd.values():
                plural_payload = scope_files.get(plural_cmd, {})
                raw_items = plural_payload.get("objects", []) if isinstance(plural_payload, Mapping) else []
                for item in raw_items:
                    if isinstance(item, dict):
                        out.append(item)
        else:
            for file_val in scope_files.values():
                if not isinstance(file_val, Mapping):
                    continue
                raw_items = file_val.get("objects", [])
                if not isinstance(raw_items, list):
                    continue
                for item in raw_items:
                    if isinstance(item, dict) and str(item.get("type") or "") == req_type:
                        out.append(item)
        return out

    candidates: list[dict[str, Any]] = []
    seen_uids: set[str] = set()
    local_type_names: set[tuple[str, str]] = set()

    if include_local:
        for item in _collect_scope(dom_files):
            uid_key = str(item.get("uid") or "")
            if uid_key and uid_key in seen_uids:
                continue
            if uid_key:
                seen_uids.add(uid_key)
            item_t = str(item.get("type") or req_type)
            item_n = str(item.get("name") or "").lower()
            if item_n:
                local_type_names.add((item_t, item_n))
            candidates.append(item)

    if include_global and global_files:
        for item in _collect_scope(global_files):
            uid_key = str(item.get("uid") or "")
            if uid_key and uid_key in seen_uids:
                continue
            if not explicit_global:
                item_t = str(item.get("type") or req_type)
                item_n = str(item.get("name") or "").lower()
                if item_n and (item_t, item_n) in local_type_names:
                    continue
            if uid_key:
                seen_uids.add(uid_key)
            candidates.append(item)

    return [item for item in candidates if match_fn(item)]


def collect_blocking_references(
    target_uid: str,
    *,
    dom_name: str,
    dom_files: Mapping[str, Any],
    all_domains_effective: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    """Return human-readable descriptions of groups and rules directly referencing `target_uid`."""
    scopes: list[tuple[str, Mapping[str, Any]]] = [(dom_name, dom_files)]
    if dom_name == "Global":
        for other_dom, other_files in all_domains_effective.items():
            if other_dom != "Global":
                scopes.append((other_dom, other_files))

    refs: list[str] = []
    for scope_dom, scope_files in scopes:
        for cmd in ("show-groups", "show-groups-with-exclusion", "show-service-groups"):
            items = scope_files.get(cmd, {}).get("objects", [])
            if not isinstance(items, list):
                continue
            for grp in items:
                if not isinstance(grp, Mapping):
                    continue
                m_uids = (
                    extract_ref_uids(grp.get("members"))
                    | extract_ref_uids(grp.get("include"))
                    | extract_ref_uids(grp.get("except"))
                )
                if target_uid in m_uids:
                    refs.append(f"Group '{grp.get('name', grp.get('uid'))}' in domain '{scope_dom}'")

        for rb_cmd, ref_cols, rb_label in (
            ("show-access-rulebase", ACCESS_REF_COLS, "Access"),
            ("show-https-rulebase", HTTPS_CELL_LIST_FIELDS, "HTTPS"),
            ("show-threat-rulebase", THREAT_CELL_LIST_FIELDS, "Threat"),
        ):
            rb_store = scope_files.get(rb_cmd, {})
            if isinstance(rb_store, Mapping):
                for layer_key, layer_val in rb_store.items():
                    if not isinstance(layer_val, Mapping):
                        continue
                    layer_name = str(layer_val.get("name") or layer_key)
                    for idx, (_, rule) in enumerate(iter_flat_rule_entries(layer_val.get("rulebase")), start=1):
                        used: set[str] = set()
                        for col in ref_cols:
                            used.update(extract_ref_uids(rule.get(col)))
                        if target_uid in used:
                            r_label = rule.get("name") or f"#{rule.get('rule-number') or idx}"
                            refs.append(f"{rb_label} rule {r_label!r} in layer '{layer_name}' (domain '{scope_dom}')")

        nat_store = scope_files.get("show-nat-rulebase", {})
        if isinstance(nat_store, Mapping):
            for pkg_key, nat_val in nat_store.items():
                if not isinstance(nat_val, Mapping):
                    continue
                pkg_name = str(nat_val.get("package") or pkg_key)
                for idx, (_, rule) in enumerate(iter_flat_rule_entries(nat_val.get("rulebase")), start=1):
                    used = set()
                    for col in NAT_REF_COLS:
                        used.update(extract_ref_uids(rule.get(col)))
                    if target_uid in used:
                        refs.append(
                            f"NAT rule #{rule.get('rule-number') or idx} in package '{pkg_name}' (domain '{scope_dom}')"
                        )

        for gw_cmd in (GATEWAY_SHOW_CMD, "show-simple-gateways", "show-simple-clusters"):
            gws = scope_files.get(gw_cmd, {}).get("objects", [])
            if not isinstance(gws, list):
                continue
            for gw in gws:
                if not isinstance(gw, Mapping):
                    continue
                gw_label = str(gw.get("name") or gw.get("uid") or "gateway")
                vpn_refs = extract_ref_uids(gw.get("vpn-domain"))
                vpn_settings = gw.get("vpn-settings")
                if isinstance(vpn_settings, Mapping):
                    vpn_refs |= extract_ref_uids(vpn_settings.get("vpn-domain"))
                if target_uid in vpn_refs:
                    refs.append(f"Gateway '{gw_label}' VPN domain in domain '{scope_dom}'")

                raw_ifaces = gw.get("interfaces")
                iface_items = raw_ifaces.get("objects", []) if isinstance(raw_ifaces, Mapping) else raw_ifaces
                if isinstance(iface_items, list):
                    for iface in iface_items:
                        if not isinstance(iface, Mapping):
                            continue
                        topo_refs = extract_ref_uids(iface.get("specific-network"))
                        topo_settings = iface.get("topology-settings")
                        if isinstance(topo_settings, Mapping):
                            topo_refs |= extract_ref_uids(topo_settings.get("specific-network"))
                        if target_uid in topo_refs:
                            iface_name = str(iface.get("name") or "interface")
                            refs.append(
                                f"Gateway '{gw_label}' interface '{iface_name}' topology in domain '{scope_dom}'"
                            )
    return refs


def _build_unused_filter_predicate(
    dom_files: Mapping[str, Any],
    req: Mapping[str, Any] | None,
) -> Callable[[dict[str, Any]], bool]:
    """Build an optional predicate for `show-unused-objects` and `delete-unused-objects` filters."""
    if not req:
        return lambda _obj: True

    def _to_str_list(val: Any) -> list[str]:
        if isinstance(val, str) and val.strip():
            return [val.strip()]
        if isinstance(val, (list, tuple, set)):
            return [str(x).strip() for x in val if str(x).strip()]
        return []

    req_types = {t.lower() for t in (*_to_str_list(req.get("type")), *_to_str_list(req.get("types")))}
    req_objects = {o.lower() for o in (*_to_str_list(req.get("object")), *_to_str_list(req.get("objects")))}
    req_groups = {g.lower() for g in (*_to_str_list(req.get("group")), *_to_str_list(req.get("groups")))}
    raw_filter = req.get("filter")
    filter_needle = str(raw_filter).strip().lower() if raw_filter is not None else ""

    allowed_group_member_uids: set[str] | None = None
    if req_groups:
        allowed_group_member_uids = set()
        group_by_uid: dict[str, set[str]] = {}
        seed_uids: list[str] = []
        for cmd in ("show-groups", "show-groups-with-exclusion", "show-service-groups"):
            for grp in dom_files.get(cmd, {}).get("objects", []):
                if not isinstance(grp, Mapping) or not grp.get("uid"):
                    continue
                g_uid = str(grp["uid"])
                g_name = str(grp.get("name") or "")
                members = (
                    extract_ref_uids(grp.get("members"))
                    | extract_ref_uids(grp.get("include"))
                    | extract_ref_uids(grp.get("except"))
                )
                group_by_uid[g_uid] = members
                if g_uid.lower() in req_groups or g_name.lower() in req_groups:
                    seed_uids.append(g_uid)
        visited: set[str] = set()
        stack = list(seed_uids)
        while stack:
            curr = stack.pop()
            if curr in visited:
                continue
            visited.add(curr)
            for member_uid in group_by_uid.get(curr, ()):
                allowed_group_member_uids.add(member_uid)
                if member_uid in group_by_uid and member_uid not in visited:
                    stack.append(member_uid)

    def _matches(obj: dict[str, Any]) -> bool:
        obj_uid = str(obj.get("uid") or "")
        obj_name = str(obj.get("name") or "")
        obj_type = str(obj.get("type") or "").lower()
        if req_types and obj_type not in req_types:
            return False
        if req_objects and obj_uid.lower() not in req_objects and obj_name.lower() not in req_objects:
            return False
        if allowed_group_member_uids is not None and obj_uid not in allowed_group_member_uids:
            return False
        if filter_needle:
            haystacks = (
                obj_name.lower(),
                str(obj.get("ipv4-address") or "").lower(),
                str(obj.get("subnet4") or "").lower(),
                str(obj.get("fqdn") or "").lower(),
                str(obj.get("comments") or "").lower(),
            )
            if not any(filter_needle in h for h in haystacks):
                return False
        return True

    return _matches


def find_unused_objects(
    dom_files: Mapping[str, Any],
    *,
    dom_name: str,
    all_domains_effective: Mapping[str, Mapping[str, Any]],
    req: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return all local `ENTITY_SPECS` objects with zero incoming group, rule, or gateway references."""
    matches_filter = _build_unused_filter_predicate(dom_files, req)
    unused: list[dict[str, Any]] = []
    for spec in ENTITY_SPECS:
        items = dom_files.get(spec.plural_show, {}).get("objects", [])
        if not isinstance(items, list):
            continue
        for obj in items:
            if not isinstance(obj, dict) or not obj.get("uid"):
                continue
            if not matches_filter(obj):
                continue
            refs = collect_blocking_references(
                str(obj["uid"]),
                dom_name=dom_name,
                dom_files=dom_files,
                all_domains_effective=all_domains_effective,
            )
            if not refs:
                unused.append(obj)
    return unused


def delete_unused_objects(
    dom_files: dict[str, Any],
    *,
    dom_name: str,
    all_domains_effective: Mapping[str, Mapping[str, Any]],
    locked_uids_out: set[str],
    req: Mapping[str, Any] | None = None,
) -> int:
    """Iteratively delete unreferenced local objects matching optional filters and return the number removed."""
    matches_filter = _build_unused_filter_predicate(dom_files, req)
    removed_total = 0
    while True:
        removed_pass = 0
        for spec in ENTITY_SPECS:
            items = dom_files.get(spec.plural_show, {}).get("objects", [])
            if not isinstance(items, list):
                continue
            kept: list[dict[str, Any]] = []
            for obj in items:
                if not isinstance(obj, dict) or not obj.get("uid"):
                    kept.append(obj)
                    continue
                if not matches_filter(obj):
                    kept.append(obj)
                    continue
                uid = str(obj["uid"])
                refs = collect_blocking_references(
                    uid,
                    dom_name=dom_name,
                    dom_files=dom_files,
                    all_domains_effective=all_domains_effective,
                )
                if not refs:
                    locked_uids_out.add(uid)
                    removed_pass += 1
                else:
                    kept.append(obj)
            if len(kept) != len(items):
                dom_files[spec.plural_show]["objects"] = kept
                refresh_entity_bucket_counts(dom_files, spec)
        removed_total += removed_pass
        if removed_pass == 0:
            break
    return removed_total
