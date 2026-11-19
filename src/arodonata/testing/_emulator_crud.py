"""Stateful CRUD, referential integrity, rulebase slicing, and Global guards for the replay emulator."""

from __future__ import annotations

import copy
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from arodonata.core.models.common import ApiCallResult

from ._emulator_models import (
    ACTION_NAME_TO_UID,
    ANY_UID,
    BUILTIN_SENTINELS,
    CMD_TO_ENTITY_ACTION,
    ENTITY_SPECS,
    LOG_TRACK_UID,
    NONE_TRACK_UID,
    OBJ_TYPE_TO_SPEC,
    ORIGINAL_UID,
    SENTINEL_NAME_TO_UID,
    TRACK_NAME_TO_UID,
    EntitySpec,
    cp_error,
    cp_ok,
    format_domain_meta,
    format_timestamp,
)

_GATEWAY_SHOW_CMD = "show-gateways-and-servers"
_EXTRA_OBJECT_BUCKETS: tuple[tuple[str, str], ...] = (
    ("show-groups-with-exclusion", "objects"),
    ("show-gateways-and-servers", "objects"),
    ("show-packages", "packages"),
    ("show-access-layers", "access-layers"),
    ("show-https-layers", "https-layers"),
    ("show-threat-layers", "threat-layers"),
)
_NETWORK_NAMESPACE_TYPES: frozenset[str] = frozenset(
    {
        "host",
        "network",
        "address-range",
        "dns-domain",
        "application-site",
        "group",
    }
)
_SERVICE_NAMESPACE_TYPES: frozenset[str] = frozenset(
    {
        "service-tcp",
        "service-udp",
        "service-icmp",
        "service-icmp6",
        "service-other",
        "service-group",
    }
)
_ACCESS_CELL_LIST_FIELDS: tuple[str, ...] = ("source", "destination", "service", "install-on", "vpn", "content", "time")
_HTTPS_CELL_LIST_FIELDS: tuple[str, ...] = ("source", "destination", "service", "site-category", "install-on")
_THREAT_CELL_LIST_FIELDS: tuple[str, ...] = ("protected-scope", "source", "destination", "service", "install-on")
_NAT_CELL_SCALAR_FIELDS: tuple[str, ...] = (
    "original-source",
    "original-destination",
    "original-service",
    "translated-source",
    "translated-destination",
    "translated-service",
)
_RULE_DICT_LIST_FIELDS: tuple[str, ...] = (
    "source",
    "destination",
    "service",
    "install-on",
    "vpn",
    "content",
    "time",
    "protected-scope",
    "site-category",
)
_RULE_DICT_SCALAR_FIELDS: tuple[str, ...] = (
    "action",
    "inline-layer",
    "original-source",
    "original-destination",
    "original-service",
    "translated-source",
    "translated-destination",
    "translated-service",
)
_ACCESS_REF_COLS: tuple[str, ...] = ("source", "destination", "service", "install-on", "vpn", "content", "time")
_NAT_REF_COLS: tuple[str, ...] = (
    "original-source",
    "original-destination",
    "original-service",
    "translated-source",
    "translated-destination",
    "translated-service",
    "install-on",
)
_RULE_KIND_CONFIGS: dict[str, dict[str, Any]] = {
    "access": {
        "store_key": "show-access-rulebase",
        "layer_store": "show-access-layers",
        "layer_key": "access-layers",
        "layer_type": "access-layer",
        "rule_type": "access-rule",
        "section_type": "access-section",
        "label": "Access",
        "list_fields": _ACCESS_CELL_LIST_FIELDS,
    },
    "nat": {
        "store_key": "show-nat-rulebase",
        "layer_store": "show-packages",
        "layer_key": "packages",
        "layer_type": "nat-package",
        "rule_type": "nat-rule",
        "section_type": "nat-section",
        "label": "NAT",
        "list_fields": (),
    },
    "https": {
        "store_key": "show-https-rulebase",
        "layer_store": "show-https-layers",
        "layer_key": "https-layers",
        "layer_type": "https-layer",
        "rule_type": "https-rule",
        "section_type": "https-section",
        "label": "HTTPS",
        "list_fields": _HTTPS_CELL_LIST_FIELDS,
    },
    "threat": {
        "store_key": "show-threat-rulebase",
        "layer_store": "show-threat-layers",
        "layer_key": "threat-layers",
        "layer_type": "threat-layer",
        "rule_type": "threat-rule",
        "section_type": "threat-section",
        "label": "Threat",
        "list_fields": _THREAT_CELL_LIST_FIELDS,
    },
}


def extract_ref_uids(value: Any) -> set[str]:
    """Extract referenced UIDs from a rule column or group member container."""
    if isinstance(value, str):
        return {value} if value else set()
    if isinstance(value, Mapping):
        uid = value.get("uid")
        return {str(uid)} if uid else set()
    if isinstance(value, list):
        out: set[str] = set()
        for elem in value:
            out.update(extract_ref_uids(elem))
        return out
    return set()


def project_details_level(obj: Mapping[str, Any], details_level: str) -> dict[str, Any]:
    """Apply Check Point `details-level` (`uid`, `standard`, `full`) projection to an object."""
    level = details_level.strip().lower()
    if level == "uid":
        return {"uid": obj.get("uid")}
    copied = copy.deepcopy(dict(obj))
    if level == "standard" and len(copied) > 24:
        keep = (
            "uid",
            "name",
            "type",
            "domain",
            "color",
            "comments",
            "ipv4-address",
            "ipv6-address",
            "subnet4",
            "mask-length4",
            "subnet-mask",
            "ipv4-address-first",
            "ipv4-address-last",
            "port",
            "protocol",
            "members",
            "groups",
            "tags",
            "url-list",
            "primary-category",
            "urls-defined-as-regular-expression",
            "is-sub-domain",
            "icmp-type",
            "icmp-code",
            "ip-protocol",
            "meta-info",
        )
        slim = {k: copied[k] for k in keep if k in copied}
        if slim:
            return slim
    return copied


def paginate_items(
    items: list[dict[str, Any]],
    req: Mapping[str, Any],
    *,
    collection_key: str = "objects",
    details_level: str | None = None,
) -> dict[str, Any]:
    """Paginate a list using Check Point `limit` / `offset` conventions."""
    total = len(items)
    offset = max(0, int(req.get("offset", 0)))
    limit = max(1, int(req.get("limit", 100)))
    page_items = items[offset : offset + limit]
    eff_level = str(details_level or req.get("details-level") or "").strip().lower()
    sliced = [project_details_level(item, eff_level) for item in page_items] if eff_level else copy.deepcopy(page_items)
    from_idx = (offset + 1) if sliced else 0
    to_idx = (offset + len(sliced)) if sliced else 0
    return {
        collection_key: sliced,
        "from": from_idx,
        "to": to_idx,
        "total": total,
    }


def make_object_summary(obj: Mapping[str, Any], *, default_domain: str | None = None) -> dict[str, Any]:
    """Build a compact Check Point summary reference dict `{uid, name, type, domain}`."""
    summary: dict[str, Any] = {
        "uid": str(obj.get("uid") or ""),
        "name": str(obj.get("name") or obj.get("uid") or ""),
        "type": str(obj.get("type") or "object"),
    }
    dom = obj.get("domain")
    if isinstance(dom, Mapping):
        summary["domain"] = copy.deepcopy(dict(dom))
    elif default_domain:
        summary["domain"] = format_domain_meta(default_domain)
    return summary


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
            for cmd, col_key in _EXTRA_OBJECT_BUCKETS:
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


def _is_global_owned(obj: Mapping[str, Any], owning_dom: str, caller_dom: str) -> bool:
    if caller_dom == "Global":
        return False
    if owning_dom == "Global":
        return True
    dom_meta = obj.get("domain")
    return isinstance(dom_meta, Mapping) and str(dom_meta.get("name") or "") == "Global"


def _global_read_only_error(target_ref: str, caller_dom: str) -> ApiCallResult:
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


def _iter_flat_rule_entries(nodes: Any) -> list[tuple[dict[str, Any] | None, dict[str, Any]]]:
    """Flatten top-level and section-nested rules into `(section_meta, rule_dict)` pairs."""
    if not isinstance(nodes, list):
        return []
    out: list[tuple[dict[str, Any] | None, dict[str, Any]]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_type = str(node.get("type") or "")
        if node_type.endswith("-section") or (isinstance(node.get("rulebase"), list) and "rule-number" not in node):
            children = node.get("rulebase")
            if isinstance(children, list):
                for child in children:
                    if isinstance(child, dict):
                        out.append((node, child))
        else:
            out.append((None, node))
    return out


def build_objects_dictionary(
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    nodes: Any,
    existing_dict: Iterable[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    """Reconstruct `objects-dictionary` from all live UIDs referenced in `nodes`."""
    referenced: list[str] = []
    seen_order: set[str] = set()

    def _record(uid: str) -> None:
        if uid and uid not in seen_order:
            seen_order.add(uid)
            referenced.append(uid)

    for _, rule in _iter_flat_rule_entries(nodes):
        for field in _RULE_DICT_LIST_FIELDS:
            for uid in extract_ref_uids(rule.get(field)):
                _record(uid)
        for field in _RULE_DICT_SCALAR_FIELDS:
            for uid in extract_ref_uids(rule.get(field)):
                _record(uid)
        track = rule.get("track")
        if isinstance(track, Mapping):
            for uid in extract_ref_uids(track.get("type")):
                _record(uid)

    existing_by_uid = {
        str(entry["uid"]): copy.deepcopy(dict(entry))
        for entry in existing_dict
        if isinstance(entry, Mapping) and entry.get("uid")
    }

    live_by_uid: dict[str, dict[str, Any]] = {uid: copy.deepcopy(val) for uid, val in BUILTIN_SENTINELS.items()}
    for scope_dom, scope_files in (("Global", global_files), (dom_name, dom_files)):
        if not isinstance(scope_files, Mapping):
            continue
        for spec in ENTITY_SPECS:
            items = scope_files.get(spec.plural_show, {}).get("objects", [])
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, Mapping) and item.get("uid"):
                    uid = str(item["uid"])
                    copy_obj = copy.deepcopy(dict(item))
                    copy_obj.setdefault("domain", format_domain_meta(scope_dom))
                    live_by_uid[uid] = copy_obj
        for cmd, col_key in _EXTRA_OBJECT_BUCKETS:
            items = scope_files.get(cmd, {}).get(col_key, [])
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, Mapping) and item.get("uid") and str(item["uid"]) not in live_by_uid:
                    live_by_uid[str(item["uid"])] = make_object_summary(item, default_domain=scope_dom)

    dictionary: list[dict[str, Any]] = []
    for uid in referenced:
        if uid in live_by_uid:
            dictionary.append(live_by_uid[uid])
        elif uid in existing_by_uid:
            dictionary.append(existing_by_uid[uid])
    return dictionary


def _inline_rule_objects(rule: dict[str, Any], obj_map: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Replace UID references in a copied rule with full objects from `objects-dictionary`."""
    for field in _RULE_DICT_LIST_FIELDS:
        raw_list = rule.get(field)
        if not isinstance(raw_list, list):
            continue
        rule[field] = [
            copy.deepcopy(dict(obj_map[elem])) if isinstance(elem, str) and elem in obj_map else elem
            for elem in raw_list
        ]

    for field in _RULE_DICT_SCALAR_FIELDS:
        raw_val = rule.get(field)
        if isinstance(raw_val, str) and raw_val in obj_map:
            rule[field] = copy.deepcopy(dict(obj_map[raw_val]))

    track_val = rule.get("track")
    if isinstance(track_val, dict):
        t_type = track_val.get("type")
        if isinstance(t_type, str) and t_type in obj_map:
            resolved_track = copy.deepcopy(dict(obj_map[t_type]))
            track_val["type"] = resolved_track
            if isinstance(resolved_track.get("name"), str):
                track_val.setdefault("name", resolved_track["name"])
    return rule


def slice_rulebase_with_sections(
    layer_payload: Mapping[str, Any],
    *,
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    offset: int,
    limit: int,
    use_object_dictionary: bool = True,
) -> dict[str, Any]:
    """Slice an access/NAT rulebase by rule `offset`/`limit`, preserving live objects and empty sections."""
    raw_nodes = layer_payload.get("rulebase")
    nodes = raw_nodes if isinstance(raw_nodes, list) else []

    existing_dict_raw = layer_payload.get("objects-dictionary", [])
    existing_dict = existing_dict_raw if isinstance(existing_dict_raw, list) else []
    live_obj_dict = build_objects_dictionary(
        dom_files,
        global_files,
        dom_name,
        nodes,
        existing_dict=existing_dict,
    )
    obj_map: dict[str, dict[str, Any]] = {
        str(entry["uid"]): entry for entry in live_obj_dict if isinstance(entry, dict) and entry.get("uid")
    }

    flat_rules: list[tuple[dict[str, Any] | None, dict[str, Any]]] = []
    empty_sections_by_anchor: dict[int, list[dict[str, Any]]] = {}

    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_type = str(node.get("type") or "")
        is_sec = node_type.endswith("-section") or (
            isinstance(node.get("rulebase"), list) and "rule-number" not in node
        )
        if is_sec:
            children = [c for c in node.get("rulebase", []) if isinstance(c, dict)]
            if not children:
                empty_sections_by_anchor.setdefault(len(flat_rules), []).append(node)
            else:
                for child in children:
                    flat_rules.append((node, child))
        else:
            flat_rules.append((None, node))

    total = len(flat_rules)
    eff_offset = max(0, int(offset))
    eff_limit = max(1, int(limit))
    end_idx = min(total, eff_offset + eff_limit)
    sliced = flat_rules[eff_offset:end_idx]

    def _serialize_empty_sec(sec: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "uid": sec.get("uid"),
            "name": sec.get("name"),
            "type": sec.get("type", "access-section"),
            "rulebase": [],
        }

    page_nodes: list[dict[str, Any]] = []
    current_sec_uid: str | None = None
    current_sec_dict: dict[str, Any] | None = None

    if total == 0 and eff_offset == 0:
        for sec in empty_sections_by_anchor.get(0, []):
            page_nodes.append(_serialize_empty_sec(sec))
    elif eff_offset == total and total > 0:
        for sec in empty_sections_by_anchor.get(total, []):
            page_nodes.append(_serialize_empty_sec(sec))
    else:
        for idx_in_slice, (sec_meta, rule_dict) in enumerate(sliced):
            zero_idx = eff_offset + idx_in_slice
            abs_rule_num = zero_idx + 1

            for emp_sec in empty_sections_by_anchor.get(zero_idx, []):
                current_sec_uid = None
                current_sec_dict = None
                page_nodes.append(_serialize_empty_sec(emp_sec))

            copied_rule = copy.deepcopy(rule_dict)
            copied_rule["rule-number"] = abs_rule_num
            if not use_object_dictionary and obj_map:
                copied_rule = _inline_rule_objects(copied_rule, obj_map)

            if sec_meta is None:
                current_sec_uid = None
                current_sec_dict = None
                page_nodes.append(copied_rule)
            else:
                sec_uid = str(sec_meta.get("uid") or sec_meta.get("name") or "sec")
                if sec_uid != current_sec_uid or current_sec_dict is None:
                    current_sec_uid = sec_uid
                    current_sec_dict = {
                        "uid": sec_meta.get("uid"),
                        "name": sec_meta.get("name"),
                        "type": sec_meta.get("type", "access-section"),
                        "from": abs_rule_num,
                        "to": abs_rule_num,
                        "rulebase": [copied_rule],
                    }
                    page_nodes.append(current_sec_dict)
                else:
                    current_sec_dict["to"] = abs_rule_num
                    current_sec_dict["rulebase"].append(copied_rule)

        if end_idx == total and len(sliced) < eff_limit:
            for emp_sec in empty_sections_by_anchor.get(total, []):
                page_nodes.append(_serialize_empty_sec(emp_sec))

    from_idx = (eff_offset + 1) if sliced else 0
    to_idx = (eff_offset + len(sliced)) if sliced else 0
    result: dict[str, Any] = {
        "uid": layer_payload.get("uid", ""),
        "name": layer_payload.get("name", ""),
        "rulebase": page_nodes,
        "objects-dictionary": live_obj_dict if use_object_dictionary else [],
        "from": from_idx,
        "to": to_idx,
        "total": total,
    }
    if "package" in layer_payload:
        result["package"] = layer_payload["package"]
    return result


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
            ("show-access-rulebase", _ACCESS_REF_COLS, "Access"),
            ("show-https-rulebase", _HTTPS_CELL_LIST_FIELDS, "HTTPS"),
            ("show-threat-rulebase", _THREAT_CELL_LIST_FIELDS, "Threat"),
        ):
            rb_store = scope_files.get(rb_cmd, {})
            if isinstance(rb_store, Mapping):
                for layer_key, layer_val in rb_store.items():
                    if not isinstance(layer_val, Mapping):
                        continue
                    layer_name = str(layer_val.get("name") or layer_key)
                    for idx, (_, rule) in enumerate(_iter_flat_rule_entries(layer_val.get("rulebase")), start=1):
                        used = set()
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
                for idx, (_, rule) in enumerate(_iter_flat_rule_entries(nat_val.get("rulebase")), start=1):
                    used = set()
                    for col in _NAT_REF_COLS:
                        used.update(extract_ref_uids(rule.get(col)))
                    if target_uid in used:
                        refs.append(
                            f"NAT rule #{rule.get('rule-number') or idx} in package '{pkg_name}' (domain '{scope_dom}')"
                        )

        for gw_cmd in (_GATEWAY_SHOW_CMD, "show-simple-gateways", "show-simple-clusters"):
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


def _mask_to_length(subnet_mask: str) -> int | None:
    parts = subnet_mask.strip().split(".")
    if len(parts) != 4:
        return None
    try:
        bits = "".join(f"{int(p):08b}" for p in parts)
    except ValueError:
        return None
    if "01" in bits:
        return None
    return bits.count("1")


def _length_to_mask(prefix_len: int) -> str | None:
    if prefix_len < 0 or prefix_len > 32:
        return None
    mask_int = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF if prefix_len else 0
    return ".".join(str((mask_int >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def _ensure_entity_bucket(dom_files: dict[str, Any], spec: EntitySpec) -> list[dict[str, Any]]:
    bucket = dom_files.setdefault(spec.plural_show, {"objects": [], "from": 0, "to": 0, "total": 0})
    objs = bucket.setdefault("objects", [])
    if not isinstance(objs, list):
        objs = []
        bucket["objects"] = objs
    return objs


def _refresh_entity_bucket_counts(dom_files: dict[str, Any], spec: EntitySpec) -> None:
    bucket = dom_files.get(spec.plural_show)
    if isinstance(bucket, dict) and isinstance(bucket.get("objects"), list):
        count = len(bucket["objects"])
        bucket["total"] = count
        bucket["from"] = 1 if count > 0 else 0
        bucket["to"] = count


def _check_name_conflict(
    dom_files: Mapping[str, Any],
    name: str,
    spec: EntitySpec,
    *,
    exclude_uid: str | None = None,
) -> dict[str, Any] | None:
    """Return an existing object sharing `name` inside the same Check Point namespace."""
    namespace = _SERVICE_NAMESPACE_TYPES if spec.is_service else _NETWORK_NAMESPACE_TYPES
    for cand_spec in ENTITY_SPECS:
        if cand_spec.obj_type not in namespace:
            continue
        items = dom_files.get(cand_spec.plural_show, {}).get("objects", [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            if exclude_uid and item.get("uid") == exclude_uid:
                continue
            if item.get("name") == name:
                return item
    return None


def _sync_member_refs_on_group_list(
    group_obj: dict[str, Any],
    member_refs: list[Any],
    *,
    dom_files: dict[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    spec: EntitySpec,
) -> ApiCallResult | None:
    resolved_members: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ref in member_refs:
        lookup = str(ref.get("uid") or ref.get("name") or "") if isinstance(ref, Mapping) else str(ref)
        found = find_effective_object(dom_files, global_files, dom_name, lookup, include_extras=False)
        if found is None:
            return cp_error(
                "generic_err_object_not_found",
                f"Member object [{lookup}] not found in {dom_name}",
                status_code=404,
            )
        m_obj, m_owner, _ = found
        m_uid = str(m_obj["uid"])
        if spec.obj_type == "group" and m_uid == group_obj.get("uid"):
            return cp_error("err_validation_failed", "Group cannot contain itself", status_code=400)
        if m_uid not in seen:
            seen.add(m_uid)
            resolved_members.append(make_object_summary(m_obj, default_domain=m_owner))

    old_uids = extract_ref_uids(group_obj.get("members"))
    new_uids = {str(m["uid"]) for m in resolved_members}
    group_obj["members"] = resolved_members

    # Keep reverse `groups` field consistent on local domain objects
    grp_summary = make_object_summary(group_obj, default_domain=dom_name)
    g_uid = str(group_obj["uid"])
    for cand_spec in ENTITY_SPECS:
        items = dom_files.get(cand_spec.plural_show, {}).get("objects", [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            i_uid = str(item.get("uid") or "")
            if i_uid in (old_uids - new_uids):
                cur_groups = [g for g in item.get("groups", []) if _ref_uid(g) != g_uid]
                item["groups"] = cur_groups
            elif i_uid in new_uids:
                cur_groups = list(item.get("groups", []))
                if all(_ref_uid(g) != g_uid for g in cur_groups):
                    cur_groups.append(copy.deepcopy(grp_summary))
                    item["groups"] = cur_groups
    return None


def _ref_uid(item: Any) -> str:
    if isinstance(item, Mapping):
        return str(item.get("uid") or item.get("name") or "")
    return str(item or "")


def _sync_object_groups_field(
    obj: dict[str, Any],
    groups_spec: Any,
    *,
    dom_files: dict[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    target_group_spec: EntitySpec,
) -> ApiCallResult | None:
    """Apply `groups` list or `{add, remove}` onto local group objects."""
    cur_uids = [_ref_uid(g) for g in obj.get("groups", []) if _ref_uid(g)]
    if isinstance(groups_spec, Mapping) and ("add" in groups_spec or "remove" in groups_spec):
        to_remove = set()
        for rem_ref in _as_list(groups_spec.get("remove")):
            hit = find_in_scope(dom_files, _ref_uid(rem_ref), preferred_spec=target_group_spec, include_extras=False)
            if hit:
                to_remove.add(str(hit[0]["uid"]))
            else:
                to_remove.add(_ref_uid(rem_ref))
        desired = [u for u in cur_uids if u not in to_remove]
        for add_ref in _as_list(groups_spec.get("add")):
            eff_hit = find_effective_object(
                dom_files, global_files, dom_name, _ref_uid(add_ref), preferred_spec=target_group_spec
            )
            if eff_hit is None:
                return cp_error(
                    "generic_err_object_not_found",
                    f"Group [{_ref_uid(add_ref)}] not found",
                    status_code=404,
                )
            g_obj, g_owner, _ = eff_hit
            if _is_global_owned(g_obj, g_owner, dom_name):
                return _global_read_only_error(_ref_uid(add_ref), dom_name)
            g_uid = str(g_obj["uid"])
            if g_uid not in desired:
                desired.append(g_uid)
    else:
        desired = []
        for g_ref in _as_list(groups_spec):
            eff_hit = find_effective_object(
                dom_files, global_files, dom_name, _ref_uid(g_ref), preferred_spec=target_group_spec
            )
            if eff_hit is None:
                return cp_error(
                    "generic_err_object_not_found",
                    f"Group [{_ref_uid(g_ref)}] not found",
                    status_code=404,
                )
            g_obj, g_owner, _ = eff_hit
            if _is_global_owned(g_obj, g_owner, dom_name):
                return _global_read_only_error(_ref_uid(g_ref), dom_name)
            g_uid = str(g_obj["uid"])
            if g_uid not in desired:
                desired.append(g_uid)

    obj_uid = str(obj["uid"])
    new_groups_list: list[dict[str, Any]] = []
    for g_obj in _ensure_entity_bucket(dom_files, target_group_spec):
        g_uid = str(g_obj.get("uid") or "")
        members = [m for m in g_obj.get("members", []) if isinstance(m, Mapping)]
        if g_uid in desired:
            if all(_ref_uid(m) != obj_uid for m in members):
                members.append(make_object_summary(obj, default_domain=dom_name))
                g_obj["members"] = members
            new_groups_list.append(make_object_summary(g_obj, default_domain=dom_name))
        else:
            filtered_m = [m for m in members if _ref_uid(m) != obj_uid]
            if len(filtered_m) != len(members):
                g_obj["members"] = filtered_m
    obj["groups"] = new_groups_list
    return None


def _as_list(val: Any) -> list[Any]:
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


def _propagate_object_rename(dom_files: dict[str, Any], renamed_obj: Mapping[str, Any]) -> None:
    """Propagate an object's updated `name` into local group `members`, reverse `groups`, and `objects-dictionary`."""
    obj_uid = str(renamed_obj["uid"])
    new_name = str(renamed_obj["name"])

    for cand_spec in ENTITY_SPECS:
        items = dom_files.get(cand_spec.plural_show, {}).get("objects", [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            for field in ("members", "groups", "include", "except"):
                ref_list = item.get(field)
                if not isinstance(ref_list, list):
                    continue
                for entry in ref_list:
                    if isinstance(entry, dict) and entry.get("uid") == obj_uid:
                        entry["name"] = new_name

    for rb_cmd in ("show-access-rulebase", "show-nat-rulebase", "show-https-rulebase", "show-threat-rulebase"):
        rb_store = dom_files.get(rb_cmd, {})
        if not isinstance(rb_store, dict):
            continue
        for layer_val in rb_store.values():
            if not isinstance(layer_val, dict):
                continue
            for dict_entry in layer_val.get("objects-dictionary", []):
                if isinstance(dict_entry, dict) and dict_entry.get("uid") == obj_uid:
                    dict_entry["name"] = new_name


def _normalize_subnet_fields(target: dict[str, Any], updates: Mapping[str, Any]) -> None:
    """Keep `subnet4` / `mask-length4` / `subnet-mask` synchronized for network objects."""
    if "subnet4" in updates:
        target["subnet4"] = str(updates["subnet4"])
    if "subnet-mask" in updates and updates["subnet-mask"]:
        mask_str = str(updates["subnet-mask"])
        target["subnet-mask"] = mask_str
        prefix = _mask_to_length(mask_str)
        if prefix is not None:
            target["mask-length4"] = prefix
    if "mask-length4" in updates and updates["mask-length4"] is not None:
        plen = int(updates["mask-length4"])
        target["mask-length4"] = plen
        computed_mask = _length_to_mask(plen)
        if computed_mask is not None and "subnet-mask" not in updates:
            target["subnet-mask"] = computed_mask


def _apply_entity_fields(
    obj: dict[str, Any],
    req: Mapping[str, Any],
    spec: EntitySpec,
    *,
    dom_files: dict[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
) -> ApiCallResult | None:
    ignored = {
        "uid",
        "domain",
        "details-level",
        "set-if-exists",
        "ignore-warnings",
        "ignore-errors",
        "new-name",
        "name",
        "members",
        "groups",
        "tags",
        "url-list",
    }
    if spec.obj_type == "network":
        _normalize_subnet_fields(obj, req)
        ignored |= {"subnet4", "subnet-mask", "mask-length4"}

    for key, val in req.items():
        if key in ignored:
            continue
        obj[key] = copy.deepcopy(val)

    if "tags" in req:
        raw_tags = req["tags"]
        if isinstance(raw_tags, Mapping) and ("add" in raw_tags or "remove" in raw_tags):
            cur_tags = list(obj.get("tags", []))
            rem = {str(t) for t in _as_list(raw_tags.get("remove"))}
            cur_tags = [t for t in cur_tags if _ref_uid(t) not in rem]
            for add_t in _as_list(raw_tags.get("add")):
                if add_t not in cur_tags:
                    cur_tags.append(copy.deepcopy(add_t))
            obj["tags"] = cur_tags
        else:
            obj["tags"] = copy.deepcopy(_as_list(raw_tags))

    if spec.obj_type == "application-site" and "url-list" in req:
        raw_urls = req["url-list"]
        eff_is_regex = bool(
            req["urls-defined-as-regular-expression"]
            if "urls-defined-as-regular-expression" in req
            else obj.get("urls-defined-as-regular-expression", False)
        )

        def _url_key(raw_u: str) -> str:
            return raw_u if eff_is_regex else raw_u.lower()

        if isinstance(raw_urls, Mapping) and ("add" in raw_urls or "remove" in raw_urls):
            cur_urls = [str(u).strip() for u in _as_list(obj.get("url-list")) if str(u).strip()]
            rem_keys = {_url_key(str(u).strip()) for u in _as_list(raw_urls.get("remove")) if str(u).strip()}
            kept_urls = [u for u in cur_urls if _url_key(u) not in rem_keys]
            adds = [str(u).strip() for u in _as_list(raw_urls.get("add")) if str(u).strip()]
            candidates = [*kept_urls, *adds]
        else:
            candidates = [str(u).strip() for u in _as_list(raw_urls) if str(u).strip()]

        seen_url_keys: set[str] = set()
        new_urls: list[str] = []
        for cand in candidates:
            u_key = _url_key(cand)
            if u_key not in seen_url_keys:
                seen_url_keys.add(u_key)
                new_urls.append(cand)
        has_sig = bool(str(req.get("application-signature") or obj.get("application-signature") or "").strip())
        if not new_urls and not has_sig:
            return cp_error(
                "err_validation_failed",
                "application-site url-list cannot be empty without application-signature",
                status_code=400,
            )
        obj["url-list"] = new_urls

    if spec.is_group and "members" in req:
        raw_members = req["members"]
        if isinstance(raw_members, Mapping) and ("add" in raw_members or "remove" in raw_members):
            cur_refs = [copy.deepcopy(m) for m in obj.get("members", [])]
            rem_refs = {_ref_uid(r) for r in _as_list(raw_members.get("remove"))}
            rem_uids: set[str] = set()
            for r_ref in rem_refs:
                found_rem = find_effective_object(dom_files, global_files, dom_name, r_ref, include_extras=False)
                rem_uids.add(str(found_rem[0]["uid"]) if found_rem else r_ref)
            kept: list[Any] = [m for m in cur_refs if _ref_uid(m) not in rem_uids and _ref_uid(m) not in rem_refs]
            for add_r in _as_list(raw_members.get("add")):
                kept.append(add_r)
            err = _sync_member_refs_on_group_list(
                obj, kept, dom_files=dom_files, global_files=global_files, dom_name=dom_name, spec=spec
            )
            if err is not None:
                return err
        else:
            err = _sync_member_refs_on_group_list(
                obj,
                _as_list(raw_members),
                dom_files=dom_files,
                global_files=global_files,
                dom_name=dom_name,
                spec=spec,
            )
            if err is not None:
                return err

    if "groups" in req:
        grp_spec = OBJ_TYPE_TO_SPEC["service-group" if spec.is_service else "group"]
        err = _sync_object_groups_field(
            obj,
            req["groups"],
            dom_files=dom_files,
            global_files=global_files,
            dom_name=dom_name,
            target_group_spec=grp_spec,
        )
        if err is not None:
            return err

    return None


def handle_entity_crud(
    command: str,
    req: Mapping[str, Any],
    *,
    dom_name: str,
    dom_files: dict[str, Any],
    global_files: Mapping[str, Any],
    all_domains_effective: Mapping[str, Mapping[str, Any]],
    uid_allocator: Callable[[str], str],
    now_ms: int,
    user_name: str,
    locked_uids_out: set[str],
) -> tuple[ApiCallResult, str | None] | None:
    """Execute `show-*`, `add-*`, `set-*`, `delete-*` for all 12 `ENTITY_SPECS` types."""
    mapping = CMD_TO_ENTITY_ACTION.get(command)
    if mapping is None:
        return None
    spec, action = mapping
    details_level = str(req.get("details-level") or "standard")

    if action == "show":
        lookup = str(req.get("uid") or req.get("name") or "")
        found = find_effective_object(
            dom_files,
            global_files,
            dom_name,
            lookup,
            preferred_spec=spec,
            include_extras=False,
        )
        if found is None:
            return (
                cp_error(
                    "generic_err_object_not_found",
                    f"Requested object [{lookup}] not found",
                    status_code=404,
                ),
                None,
            )
        obj, _, found_spec = found
        if found_spec is not None and found_spec.obj_type != spec.obj_type:
            return (
                cp_error(
                    "generic_err_object_not_found",
                    f"Requested {spec.obj_type} [{lookup}] not found",
                    status_code=404,
                ),
                None,
            )
        return cp_ok(project_details_level(obj, details_level)), None

    if action == "add":
        name = str(req.get("name") or "").strip()
        if not name:
            return cp_error("err_validation_failed", f"{command}: 'name' is required", status_code=400), None

        conflict = _check_name_conflict(dom_files, name, spec)
        if conflict is not None:
            if bool(req.get("set-if-exists", False)):
                set_req = dict(req)
                set_req["uid"] = conflict["uid"]
                return handle_entity_crud(
                    spec.set_cmd,
                    set_req,
                    dom_name=dom_name,
                    dom_files=dom_files,
                    global_files=global_files,
                    all_domains_effective=all_domains_effective,
                    uid_allocator=uid_allocator,
                    now_ms=now_ms,
                    user_name=user_name,
                    locked_uids_out=locked_uids_out,
                )
            return (
                cp_error(
                    "err_validation_failed",
                    f"More than one object named [{name}] exists",
                    status_code=400,
                ),
                None,
            )

        assigned_uid = str(req.get("uid") or "").strip() or uid_allocator(spec.obj_type)
        ts = format_timestamp(now_ms)
        new_obj: dict[str, Any] = {
            "uid": assigned_uid,
            "name": name,
            "type": spec.obj_type,
            "domain": format_domain_meta(dom_name),
            "color": str(req.get("color") or "black"),
            "comments": str(req.get("comments") or ""),
            "tags": [],
            "groups": [],
            "meta-info": {
                "lock": "unlocked",
                "validation-state": "ok",
                "creator": user_name,
                "creation-time": dict(ts),
                "last-modifier": user_name,
                "last-modify-time": dict(ts),
            },
        }
        for k, default_v in spec.default_fields:
            new_obj[k] = copy.deepcopy(default_v)
        if spec.is_group:
            new_obj["members"] = []

        bucket = _ensure_entity_bucket(dom_files, spec)
        bucket.append(new_obj)
        err = _apply_entity_fields(
            new_obj,
            req,
            spec,
            dom_files=dom_files,
            global_files=global_files,
            dom_name=dom_name,
        )
        if err is not None:
            bucket.remove(new_obj)
            return err, None
        _refresh_entity_bucket_counts(dom_files, spec)
        locked_uids_out.add(assigned_uid)
        return cp_ok(project_details_level(new_obj, details_level)), assigned_uid

    if action == "set":
        lookup = str(req.get("uid") or req.get("name") or "")
        found = find_effective_object(
            dom_files,
            global_files,
            dom_name,
            lookup,
            preferred_spec=spec,
            include_extras=False,
        )
        if found is None:
            return (
                cp_error(
                    "generic_err_object_not_found",
                    f"Requested object [{lookup}] not found",
                    status_code=404,
                ),
                None,
            )
        obj, owning_dom, found_spec = found
        if _is_global_owned(obj, owning_dom, dom_name):
            return _global_read_only_error(lookup, dom_name), None
        if found_spec is not None and found_spec.obj_type != spec.obj_type:
            return (
                cp_error(
                    "generic_err_object_not_found",
                    f"Requested {spec.obj_type} [{lookup}] not found",
                    status_code=404,
                ),
                None,
            )

        obj_uid = str(obj["uid"])
        locked_uids_out.add(obj_uid)
        new_name = str(req.get("new-name") or "").strip()
        if new_name and new_name != obj.get("name"):
            conflict = _check_name_conflict(dom_files, new_name, spec, exclude_uid=obj_uid)
            if conflict is not None:
                return (
                    cp_error(
                        "err_validation_failed",
                        f"More than one object named [{new_name}] exists",
                        status_code=400,
                    ),
                    None,
                )
            obj["name"] = new_name
            _propagate_object_rename(dom_files, obj)

        err = _apply_entity_fields(
            obj,
            req,
            spec,
            dom_files=dom_files,
            global_files=global_files,
            dom_name=dom_name,
        )
        if err is not None:
            return err, None

        meta = obj.setdefault("meta-info", {})
        if isinstance(meta, dict):
            meta["last-modifier"] = user_name
            meta["last-modify-time"] = format_timestamp(now_ms)
        return cp_ok(project_details_level(obj, details_level)), obj_uid

    if action == "delete":
        lookup = str(req.get("uid") or req.get("name") or "")
        found = find_effective_object(
            dom_files,
            global_files,
            dom_name,
            lookup,
            preferred_spec=spec,
            include_extras=False,
        )
        if found is None:
            return (
                cp_error(
                    "generic_err_object_not_found",
                    f"Requested object [{lookup}] not found",
                    status_code=404,
                ),
                None,
            )
        obj, owning_dom, found_spec = found
        if _is_global_owned(obj, owning_dom, dom_name):
            return _global_read_only_error(lookup, dom_name), None
        if found_spec is not None and found_spec.obj_type != spec.obj_type:
            return (
                cp_error(
                    "generic_err_object_not_found",
                    f"Requested {spec.obj_type} [{lookup}] not found",
                    status_code=404,
                ),
                None,
            )

        obj_uid = str(obj["uid"])
        blocking = collect_blocking_references(
            obj_uid,
            dom_name=dom_name,
            dom_files=dom_files,
            all_domains_effective=all_domains_effective,
        )
        if blocking:
            return (
                cp_error(
                    "generic_err_object_cannot_be_deleted",
                    f"Object [{obj.get('name', obj_uid)}] cannot be deleted because it is still referenced",
                    status_code=400,
                    blocking_errors=[{"message": msg} for msg in blocking],
                ),
                None,
            )

        locked_uids_out.add(obj_uid)
        bucket_list = _ensure_entity_bucket(dom_files, spec)
        bucket_list[:] = [o for o in bucket_list if o.get("uid") != obj_uid]
        _refresh_entity_bucket_counts(dom_files, spec)
        return cp_ok({"message": "OK"}), obj_uid

    return None


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
                _refresh_entity_bucket_counts(dom_files, spec)
        removed_total += removed_pass
        if removed_pass == 0:
            break
    return removed_total


# ----------------------------------------------------------------------
# Access & NAT Rulebase CRUD
# ----------------------------------------------------------------------


def _resolve_rulebase_container(
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    req: Mapping[str, Any],
    *,
    rule_kind: str = "access",
) -> tuple[dict[str, Any], str] | None:
    cfg = _RULE_KIND_CONFIGS[rule_kind]
    store_key = cfg["store_key"]
    is_nat = rule_kind == "nat"
    lookup_ref = str(req.get("package") or "" if is_nat else req.get("layer") or "")

    scopes: list[tuple[str, Mapping[str, Any]]] = [(dom_name, dom_files)]
    if dom_name != "Global" and global_files:
        scopes.append(("Global", global_files))

    for scope_dom, scope_files in scopes:
        store = scope_files.get(store_key, {})
        if not isinstance(store, Mapping):
            continue
        if lookup_ref:
            direct = store.get(lookup_ref)
            if isinstance(direct, dict):
                return direct, scope_dom
            if is_nat:
                for pkg in scope_files.get("show-packages", {}).get("packages", []):
                    if isinstance(pkg, Mapping) and (pkg.get("uid") == lookup_ref or pkg.get("name") == lookup_ref):
                        for k in (pkg.get("name"), pkg.get("uid")):
                            if k and isinstance(store.get(str(k)), dict):
                                return store[str(k)], scope_dom
            else:
                layer_list = scope_files.get(cfg["layer_store"], {}).get(cfg["layer_key"], [])
                for lyr in layer_list if isinstance(layer_list, list) else []:
                    if isinstance(lyr, Mapping) and (lyr.get("uid") == lookup_ref or lyr.get("name") == lookup_ref):
                        for k in (lyr.get("name"), lyr.get("uid")):
                            if k and isinstance(store.get(str(k)), dict):
                                return store[str(k)], scope_dom
            for cand in store.values():
                if not isinstance(cand, dict):
                    continue
                if (
                    cand.get("uid") == lookup_ref
                    or cand.get("name") == lookup_ref
                    or (is_nat and cand.get("package") == lookup_ref)
                ):
                    return cand, scope_dom
        else:
            item_uid = str(req.get("uid") or req.get("name") or "")
            if item_uid:
                for cand in store.values():
                    if not isinstance(cand, dict):
                        continue
                    for _, rule in _iter_flat_rule_entries(cand.get("rulebase")):
                        if rule.get("uid") == item_uid or rule.get("name") == item_uid:
                            return cand, scope_dom
                    for node in cand.get("rulebase", []):
                        if isinstance(node, Mapping) and (node.get("uid") == item_uid or node.get("name") == item_uid):
                            return cand, scope_dom
    return None


def parse_rule_number(raw: Any) -> tuple[int | None, bool]:
    """Parse a Check Point `rule-number` value safely, returning `(parsed_int, is_valid)`."""
    if raw is None:
        return None, True
    if isinstance(raw, bool):
        return None, False
    if isinstance(raw, int):
        return raw, True
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return None, False
        try:
            return int(stripped), True
        except ValueError:
            return None, False
    return None, False


def _locate_rule_in_tree(
    nodes: list[Any],
    req: Mapping[str, Any],
) -> tuple[list[Any], int, dict[str, Any], dict[str, Any] | None] | None:
    """Return `(parent_list, index_in_parent, rule_dict, enclosing_section_or_None)`."""
    req_uid = str(req.get("uid") or "").strip()
    req_name = str(req.get("name") or "").strip()
    req_num, valid_num = parse_rule_number(req.get("rule-number"))
    if not valid_num:
        return None

    flat_counter = 0
    for idx, node in enumerate(nodes):
        if not isinstance(node, dict):
            continue
        node_type = str(node.get("type") or "")
        is_sec = node_type.endswith("-section") or (
            isinstance(node.get("rulebase"), list) and "rule-number" not in node
        )
        if is_sec:
            children = node.get("rulebase", [])
            if isinstance(children, list):
                for c_idx, child in enumerate(children):
                    if not isinstance(child, dict):
                        continue
                    flat_counter += 1
                    if _rule_matches(child, req_uid=req_uid, req_name=req_name, req_num=req_num, pos=flat_counter):
                        return children, c_idx, child, node
        else:
            flat_counter += 1
            if _rule_matches(node, req_uid=req_uid, req_name=req_name, req_num=req_num, pos=flat_counter):
                return nodes, idx, node, None
    return None


def _rule_matches(
    rule: Mapping[str, Any],
    *,
    req_uid: str,
    req_name: str,
    req_num: int | None,
    pos: int,
) -> bool:
    if req_uid:
        return str(rule.get("uid") or "") == req_uid
    if req_num is not None:
        rule_num_val, ok = parse_rule_number(rule.get("rule-number"))
        return (rule_num_val if ok and rule_num_val is not None else pos) == req_num
    if req_name:
        return str(rule.get("name") or "") == req_name
    return False


def _locate_section_in_tree(nodes: list[Any], req: Mapping[str, Any]) -> tuple[int, dict[str, Any]] | None:
    req_uid = str(req.get("uid") or "").strip()
    req_name = str(req.get("name") or "").strip()
    for idx, node in enumerate(nodes):
        if not isinstance(node, dict):
            continue
        node_type = str(node.get("type") or "")
        if not (
            node_type.endswith("-section") or (isinstance(node.get("rulebase"), list) and "rule-number" not in node)
        ):
            continue
        if req_uid and node.get("uid") == req_uid:
            return idx, node
        if req_name and node.get("name") == req_name:
            return idx, node
    return None


def _insert_rule_into_tree(nodes: list[Any], rule: dict[str, Any], pos_spec: Any) -> ApiCallResult | None:
    """Insert `rule` into `nodes` according to Check Point `position` / `new-position` semantics."""
    if pos_spec is None or pos_spec == "bottom" or pos_spec == "last":
        nodes.append(rule)
        return None
    if pos_spec == "top" or pos_spec == "first":
        nodes.insert(0, rule)
        return None

    if isinstance(pos_spec, int) or (isinstance(pos_spec, str) and pos_spec.strip().isdigit()):
        target_num = int(pos_spec)
        flat_slots: list[tuple[list[Any], int]] = []
        for idx, node in enumerate(nodes):
            if not isinstance(node, dict):
                continue
            node_type = str(node.get("type") or "")
            if node_type.endswith("-section") or (isinstance(node.get("rulebase"), list) and "rule-number" not in node):
                children = node.setdefault("rulebase", [])
                for c_idx in range(len(children)):
                    flat_slots.append((children, c_idx))
            else:
                flat_slots.append((nodes, idx))
        if target_num <= 1 or not flat_slots:
            if flat_slots:
                parent, ins_idx = flat_slots[0]
                parent.insert(ins_idx, rule)
            else:
                nodes.insert(0, rule)
            return None
        if target_num > len(flat_slots):
            nodes.append(rule)
            return None
        parent, ins_idx = flat_slots[target_num - 1]
        parent.insert(ins_idx, rule)
        return None

    if isinstance(pos_spec, Mapping):
        if "top" in pos_spec:
            sec_ref = str(pos_spec["top"])
            sec_hit = _locate_section_in_tree(nodes, {"uid": sec_ref}) or _locate_section_in_tree(
                nodes, {"name": sec_ref}
            )
            if sec_hit is None:
                return cp_error("generic_err_object_not_found", f"Section [{sec_ref}] not found", status_code=404)
            sec_hit[1].setdefault("rulebase", []).insert(0, rule)
            return None

        if "bottom" in pos_spec:
            sec_ref = str(pos_spec["bottom"])
            sec_hit = _locate_section_in_tree(nodes, {"uid": sec_ref}) or _locate_section_in_tree(
                nodes, {"name": sec_ref}
            )
            if sec_hit is None:
                return cp_error("generic_err_object_not_found", f"Section [{sec_ref}] not found", status_code=404)
            sec_hit[1].setdefault("rulebase", []).append(rule)
            return None

        for rel_key in ("above", "below"):
            if rel_key in pos_spec:
                ref_val = pos_spec[rel_key]
                ref_str = str(ref_val)
                rule_req: dict[str, Any] = (
                    {"rule-number": int(ref_val)} if isinstance(ref_val, int) or ref_str.isdigit() else {"uid": ref_str}
                )
                hit = _locate_rule_in_tree(nodes, rule_req)
                if hit is None and not (isinstance(ref_val, int) or ref_str.isdigit()):
                    hit = _locate_rule_in_tree(nodes, {"name": ref_str})
                if hit is not None:
                    parent, r_idx, _, _ = hit
                    parent.insert(r_idx if rel_key == "above" else r_idx + 1, rule)
                    return None
                sec_hit = _locate_section_in_tree(nodes, {"uid": ref_str}) or _locate_section_in_tree(
                    nodes, {"name": ref_str}
                )
                if sec_hit is not None:
                    s_idx, _ = sec_hit
                    nodes.insert(s_idx if rel_key == "above" else s_idx + 1, rule)
                    return None
                return cp_error(
                    "generic_err_object_not_found",
                    f"Target position reference [{ref_str}] not found",
                    status_code=404,
                )

    return cp_error("err_validation_failed", f"Invalid rule position specifier: {pos_spec!r}", status_code=400)


def _insert_section_into_tree(nodes: list[Any], sec: dict[str, Any], pos_spec: Any) -> ApiCallResult | None:
    if pos_spec is None or pos_spec == "bottom" or pos_spec == "last":
        nodes.append(sec)
        return None
    if pos_spec == "top" or pos_spec == "first":
        nodes.insert(0, sec)
        return None
    if isinstance(pos_spec, int) or (isinstance(pos_spec, str) and pos_spec.strip().isdigit()):
        target_num = int(pos_spec)
        if target_num <= 1:
            nodes.insert(0, sec)
            return None
        flat_count = 0
        for idx, node in enumerate(list(nodes)):
            if not isinstance(node, dict):
                continue
            node_type = str(node.get("type") or "")
            if node_type.endswith("-section") or (isinstance(node.get("rulebase"), list) and "rule-number" not in node):
                flat_count += len([c for c in node.get("rulebase", []) if isinstance(c, dict)])
            else:
                flat_count += 1
            if flat_count >= target_num:
                nodes.insert(idx, sec)
                return None
        nodes.append(sec)
        return None
    if isinstance(pos_spec, Mapping):
        for rel_key in ("above", "below"):
            if rel_key in pos_spec:
                ref_str = str(pos_spec[rel_key])
                sec_hit = _locate_section_in_tree(nodes, {"uid": ref_str}) or _locate_section_in_tree(
                    nodes, {"name": ref_str}
                )
                if sec_hit is not None:
                    nodes.insert(sec_hit[0] if rel_key == "above" else sec_hit[0] + 1, sec)
                    return None
                for idx, node in enumerate(nodes):
                    if isinstance(node, dict) and (node.get("uid") == ref_str or node.get("name") == ref_str):
                        nodes.insert(idx if rel_key == "above" else idx + 1, sec)
                        return None
                return cp_error(
                    "generic_err_object_not_found",
                    f"Section position target [{ref_str}] not found",
                    status_code=404,
                )
    return cp_error("err_validation_failed", f"Invalid section position specifier: {pos_spec!r}", status_code=400)


def _renumber_layer(
    layer_payload: dict[str, Any],
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
) -> None:
    """Recompute sequential 1-based `rule-number`s, section `from`/`to` bounds, `total`, and `objects-dictionary`."""
    nodes = layer_payload.setdefault("rulebase", [])
    rule_num = 0
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_type = str(node.get("type") or "")
        if node_type.endswith("-section") or (isinstance(node.get("rulebase"), list) and "rule-number" not in node):
            children = [c for c in node.get("rulebase", []) if isinstance(c, dict)]
            node["rulebase"] = children
            if children:
                first_n = rule_num + 1
                for child in children:
                    rule_num += 1
                    child["rule-number"] = rule_num
                node["from"] = first_n
                node["to"] = rule_num
            else:
                node.pop("from", None)
                node.pop("to", None)
        else:
            rule_num += 1
            node["rule-number"] = rule_num
    layer_payload["total"] = rule_num
    layer_payload["objects-dictionary"] = build_objects_dictionary(
        dom_files,
        global_files,
        dom_name,
        nodes,
        existing_dict=layer_payload.get("objects-dictionary", []),
    )


def _resolve_rule_cell_ref(
    ref: Any,
    *,
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    existing_dict_map: Mapping[str, Mapping[str, Any]],
) -> tuple[str | None, str | None]:
    """Resolve a rule object reference (`uid`, `name`, or dict) to a UID or `(None, error_ref)`."""
    if ref is None:
        return ANY_UID, None
    lookup = _ref_uid(ref) if isinstance(ref, Mapping) else str(ref).strip()
    if not lookup:
        return ANY_UID, None
    if lookup in BUILTIN_SENTINELS:
        return lookup, None
    lowered = lookup.lower()
    if lowered in SENTINEL_NAME_TO_UID:
        return SENTINEL_NAME_TO_UID[lowered], None

    found = find_effective_object(
        dom_files,
        global_files,
        dom_name,
        lookup,
        allow_sentinels=True,
        include_extras=True,
    )
    if found is not None:
        return str(found[0]["uid"]), None
    if lookup in existing_dict_map:
        return lookup, None
    for uid, entry in existing_dict_map.items():
        if entry.get("name") == lookup:
            return uid, None
    return None, lookup


def _apply_cell_list_update(
    current_uids: list[str],
    spec_val: Any,
    *,
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    existing_dict_map: Mapping[str, Mapping[str, Any]],
    revert_empty_to_any: bool = True,
    allow_literal_strings: bool = False,
) -> tuple[list[str], ApiCallResult | None]:
    if isinstance(spec_val, Mapping) and ("add" in spec_val or "remove" in spec_val):
        rem_uids: set[str] = set()
        rem_names: set[str] = set()
        for rem in _as_list(spec_val.get("remove")):
            r_uid, _ = _resolve_rule_cell_ref(
                rem,
                dom_files=dom_files,
                global_files=global_files,
                dom_name=dom_name,
                existing_dict_map=existing_dict_map,
            )
            raw_ref = _ref_uid(rem)
            if r_uid:
                rem_uids.add(r_uid)
            if raw_ref:
                rem_names.add(raw_ref)
        kept = [u for u in current_uids if u not in rem_uids and u not in rem_names]
        for add_item in _as_list(spec_val.get("add")):
            a_uid, missing = _resolve_rule_cell_ref(
                add_item,
                dom_files=dom_files,
                global_files=global_files,
                dom_name=dom_name,
                existing_dict_map=existing_dict_map,
            )
            if a_uid is None:
                if allow_literal_strings and missing:
                    a_uid = missing
                else:
                    return current_uids, cp_error(
                        "generic_err_object_not_found",
                        f"Referenced object [{missing}] not found in {dom_name}",
                        status_code=404,
                    )
            if a_uid != ANY_UID and kept == [ANY_UID]:
                kept = []
            if a_uid not in kept:
                kept.append(a_uid)
        if not kept and revert_empty_to_any:
            kept = [ANY_UID]
        return kept, None

    replaced: list[str] = []
    for elem in _as_list(spec_val):
        r_uid, missing = _resolve_rule_cell_ref(
            elem,
            dom_files=dom_files,
            global_files=global_files,
            dom_name=dom_name,
            existing_dict_map=existing_dict_map,
        )
        if r_uid is None:
            if allow_literal_strings and missing:
                r_uid = missing
            else:
                return current_uids, cp_error(
                    "generic_err_object_not_found",
                    f"Referenced object [{missing}] not found in {dom_name}",
                    status_code=404,
                )
        if r_uid not in replaced:
            replaced.append(r_uid)
    if not replaced and revert_empty_to_any:
        replaced = [ANY_UID]
    return replaced, None


def _normalize_action(val: Any, *, rule_kind: str = "access") -> str | ApiCallResult:
    default_by_kind = {"access": "Drop", "https": "Inspect", "threat": "Optimized"}
    default_action = default_by_kind.get(rule_kind, "Drop")
    if isinstance(val, Mapping):
        lookup = str(val.get("uid") or val.get("name") or default_action).strip()
    else:
        lookup = str(val if val is not None else default_action).strip() or default_action

    if rule_kind == "access":
        if lookup in BUILTIN_SENTINELS:
            return lookup
        lowered = lookup.lower()
        if lowered in ACTION_NAME_TO_UID:
            return ACTION_NAME_TO_UID[lowered]
        return cp_error("err_validation_failed", f"Invalid rule action [{lookup}]", status_code=400)

    if rule_kind == "https":
        https_canonical = {"inspect": "Inspect", "bypass": "Bypass", "hold": "Hold", "ask": "Ask"}
        return https_canonical.get(lookup.lower(), lookup)

    if rule_kind == "threat":
        threat_canonical = {
            "optimized": "Optimized",
            "basic": "Basic",
            "strict": "Strict",
            "detect": "Detect",
            "prevent": "Prevent",
            "inactive": "Inactive",
        }
        return threat_canonical.get(lookup.lower(), lookup)

    return lookup


def _normalize_track(val: Any) -> dict[str, Any]:
    if isinstance(val, Mapping):
        raw_t = _ref_uid(val.get("type") or val.get("name") or LOG_TRACK_UID)
    else:
        raw_t = str(val or LOG_TRACK_UID).strip()
    lowered = raw_t.lower()
    t_uid = TRACK_NAME_TO_UID.get(lowered, raw_t if raw_t in BUILTIN_SENTINELS else LOG_TRACK_UID)
    return {"type": t_uid}


def _normalize_inline_layer(
    val: Any,
    *,
    rule_kind: str,
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    existing_dict_map: Mapping[str, Mapping[str, Any]],
) -> tuple[str | None, ApiCallResult | None]:
    """Resolve an `inline-layer` UID or layer name within domain/Global layer stores."""
    if val is None:
        return None, None
    lookup = str(val.get("uid") or val.get("name") or "").strip() if isinstance(val, Mapping) else str(val).strip()
    if not lookup:
        return None, None

    cfg = _RULE_KIND_CONFIGS.get(rule_kind, _RULE_KIND_CONFIGS["access"])
    scopes: tuple[Mapping[str, Any], ...] = (dom_files, global_files) if dom_name != "Global" else (dom_files,)
    for scope_files in scopes:
        layers = scope_files.get(cfg["layer_store"], {}).get(cfg["layer_key"], [])
        if isinstance(layers, list):
            for lyr in layers:
                if isinstance(lyr, Mapping) and (lyr.get("uid") == lookup or lyr.get("name") == lookup):
                    return str(lyr.get("uid") or lookup), None
        rb_store = scope_files.get(cfg["store_key"], {})
        if isinstance(rb_store, Mapping):
            direct = rb_store.get(lookup)
            if isinstance(direct, Mapping):
                return str(direct.get("uid") or lookup), None
            for cand in rb_store.values():
                if isinstance(cand, Mapping) and (cand.get("uid") == lookup or cand.get("name") == lookup):
                    return str(cand.get("uid") or lookup), None

    if lookup in existing_dict_map:
        return lookup, None
    for uid, entry in existing_dict_map.items():
        if entry.get("name") == lookup:
            return uid, None

    return None, cp_error(
        "generic_err_object_not_found",
        f"Requested inline layer [{lookup}] not found in {dom_name}",
        status_code=404,
    )


def _format_rule_response(
    rule: Mapping[str, Any],
    *,
    layer_payload: Mapping[str, Any],
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    rule_kind: str = "access",
) -> dict[str, Any]:
    """Return a single Check Point rule response with resolved object summary dicts."""
    dict_list = build_objects_dictionary(
        dom_files,
        global_files,
        dom_name,
        [copy.deepcopy(dict(rule))],
        existing_dict=layer_payload.get("objects-dictionary", []),
    )
    obj_map = {str(entry["uid"]): entry for entry in dict_list if isinstance(entry, dict) and entry.get("uid")}
    inlined = _inline_rule_objects(copy.deepcopy(dict(rule)), obj_map)
    inlined.setdefault("domain", format_domain_meta(dom_name))
    if rule_kind == "nat":
        inlined.setdefault("package", layer_payload.get("package") or layer_payload.get("name") or "")
    else:
        layer_type = _RULE_KIND_CONFIGS.get(rule_kind, _RULE_KIND_CONFIGS["access"])["layer_type"]
        inlined.setdefault(
            "layer",
            {
                "uid": layer_payload.get("uid", ""),
                "name": layer_payload.get("name", ""),
                "type": layer_type,
            },
        )
    return inlined


def _normalize_nat_scalar_field(
    val: Any,
    *,
    is_translated: bool,
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    existing_dict_map: Mapping[str, Mapping[str, Any]],
) -> tuple[str | None, ApiCallResult | None]:
    if val is None or (isinstance(val, str) and not val.strip()):
        return (ORIGINAL_UID if is_translated else ANY_UID), None
    lookup = _ref_uid(val) if isinstance(val, Mapping) else str(val).strip()
    if lookup.lower() == "original":
        return ORIGINAL_UID, None
    if lookup.lower() == "any":
        return ANY_UID, None
    r_uid, missing = _resolve_rule_cell_ref(
        val,
        dom_files=dom_files,
        global_files=global_files,
        dom_name=dom_name,
        existing_dict_map=existing_dict_map,
    )
    if r_uid is None:
        return None, cp_error(
            "generic_err_object_not_found",
            f"Referenced object [{missing}] not found in {dom_name}",
            status_code=404,
        )
    return r_uid, None


def _detect_rule_kind(command: str) -> str | None:
    for kind in ("access", "nat", "https", "threat"):
        if command.endswith(f"-{kind}-rule") or command.endswith(f"-{kind}-section"):
            return kind
    return None


def handle_rulebase_crud(
    command: str,
    req: Mapping[str, Any],
    *,
    dom_name: str,
    dom_files: dict[str, Any],
    global_files: Mapping[str, Any],
    uid_allocator: Callable[[str], str],
    now_ms: int,
    user_name: str,
    locked_uids_out: set[str],
) -> tuple[ApiCallResult, str | None] | None:
    """Execute Access, NAT, HTTPS, & Threat rule and section CRUD commands against live domain state."""
    rule_kind = _detect_rule_kind(command)
    if rule_kind is None:
        return None

    cfg = _RULE_KIND_CONFIGS[rule_kind]
    is_nat = rule_kind == "nat"
    is_section = command.endswith("-section")
    action = command.split("-", 1)[0]
    container = _resolve_rulebase_container(dom_files, global_files, dom_name, req, rule_kind=rule_kind)
    if container is None:
        ref = req.get("package") if is_nat else (req.get("layer") or req.get("uid") or req.get("name") or "")
        kind_label = "NAT package" if is_nat else f"{cfg['label']} layer"
        return cp_error(
            "generic_err_object_not_found", f"Requested {kind_label} [{ref}] not found", status_code=404
        ), None

    layer_payload, owning_dom = container
    if action in ("add", "set", "delete") and owning_dom == "Global" and dom_name != "Global":
        return _global_read_only_error(str(layer_payload.get("name") or layer_payload.get("uid")), dom_name), None

    nodes = layer_payload.setdefault("rulebase", [])
    existing_dict_map = {
        str(entry["uid"]): entry
        for entry in layer_payload.get("objects-dictionary", [])
        if isinstance(entry, Mapping) and entry.get("uid")
    }

    if is_section:
        if action == "show":
            hit = _locate_section_in_tree(nodes, req)
            if hit is None:
                return cp_error("generic_err_object_not_found", "Section not found", status_code=404), None
            _, sec = hit
            return cp_ok(copy.deepcopy(sec)), None

        if action == "add":
            sec_name = str(req.get("name") or "").strip()
            if not sec_name:
                return cp_error("err_validation_failed", f"{command}: 'name' is required", status_code=400), None
            sec_uid = str(req.get("uid") or "").strip() or uid_allocator("section")
            new_sec: dict[str, Any] = {
                "uid": sec_uid,
                "name": sec_name,
                "type": cfg["section_type"],
                "domain": format_domain_meta(dom_name),
                "rulebase": [],
            }
            pos_err = _insert_section_into_tree(nodes, new_sec, req.get("position"))
            if pos_err is not None:
                return pos_err, None
            _renumber_layer(layer_payload, dom_files, global_files, dom_name)
            locked_uids_out.add(sec_uid)
            return cp_ok(copy.deepcopy(new_sec)), sec_uid

        if action == "set":
            hit = _locate_section_in_tree(nodes, req)
            if hit is None:
                return cp_error("generic_err_object_not_found", "Section not found", status_code=404), None
            _, sec = hit
            if req.get("new-name"):
                sec["name"] = str(req["new-name"])
            if "new-position" in req:
                nodes.remove(sec)
                pos_err = _insert_section_into_tree(nodes, sec, req.get("new-position"))
                if pos_err is not None:
                    nodes.append(sec)
                    return pos_err, None
            _renumber_layer(layer_payload, dom_files, global_files, dom_name)
            sec_uid = str(sec["uid"])
            locked_uids_out.add(sec_uid)
            return cp_ok(copy.deepcopy(sec)), sec_uid

        if action == "delete":
            hit = _locate_section_in_tree(nodes, req)
            if hit is None:
                return cp_error("generic_err_object_not_found", "Section not found", status_code=404), None
            idx, sec = hit
            sec_uid = str(sec["uid"])
            locked_uids_out.add(sec_uid)
            for child in sec.get("rulebase", []):
                if isinstance(child, Mapping) and child.get("uid"):
                    locked_uids_out.add(str(child["uid"]))
            nodes.pop(idx)
            _renumber_layer(layer_payload, dom_files, global_files, dom_name)
            return cp_ok({"message": "OK"}), sec_uid

    # Rule operations
    if action in ("show", "set", "delete") and "rule-number" in req and req.get("rule-number") is not None:
        _, valid_num = parse_rule_number(req.get("rule-number"))
        if not valid_num:
            return (
                cp_error(
                    "err_validation_failed",
                    f"Invalid rule-number: {req.get('rule-number')!r}",
                    status_code=400,
                ),
                None,
            )

    if action == "show":
        rule_hit = _locate_rule_in_tree(nodes, req)
        if rule_hit is None:
            return cp_error("generic_err_object_not_found", "Rule not found", status_code=404), None
        _, _, rule, _ = rule_hit
        return (
            cp_ok(
                _format_rule_response(
                    rule,
                    layer_payload=layer_payload,
                    dom_files=dom_files,
                    global_files=global_files,
                    dom_name=dom_name,
                    rule_kind=rule_kind,
                )
            ),
            None,
        )

    if action == "add":
        assigned_uid = str(req.get("uid") or "").strip() or uid_allocator(cfg["rule_type"])
        ts = format_timestamp(now_ms)
        meta = {
            "lock": "unlocked",
            "validation-state": "ok",
            "creator": user_name,
            "creation-time": dict(ts),
            "last-modifier": user_name,
            "last-modify-time": dict(ts),
        }
        if not is_nat:
            req_cols = (
                ("protected-scope", "source", "destination", "service", "install-on")
                if rule_kind == "threat"
                else ("source", "destination", "service", "install-on")
            )
            opt_cols = (
                ("vpn", "content", "time")
                if rule_kind == "access"
                else (("site-category",) if rule_kind == "https" else ())
            )
            act = _normalize_action(req.get("action"), rule_kind=rule_kind)
            if isinstance(act, ApiCallResult):
                return act, None
            default_track = NONE_TRACK_UID if act == "Drop" else LOG_TRACK_UID
            new_rule = {
                "uid": assigned_uid,
                "name": str(req.get("name") or ""),
                "type": cfg["rule_type"],
                "domain": format_domain_meta(dom_name),
                "enabled": bool(req.get("enabled", True)),
                "action": act,
                "track": _normalize_track(req.get("track", default_track)),
                "comments": str(req.get("comments") or ""),
                "meta-info": meta,
            }
            for col in req_cols:
                vals, err = _apply_cell_list_update(
                    [ANY_UID],
                    req.get(col, [ANY_UID]),
                    dom_files=dom_files,
                    global_files=global_files,
                    dom_name=dom_name,
                    existing_dict_map=existing_dict_map,
                )
                if err is not None:
                    return err, None
                new_rule[col] = vals
            for opt_col in opt_cols:
                if opt_col in req:
                    vals, col_err = _apply_cell_list_update(
                        [ANY_UID],
                        req[opt_col],
                        dom_files=dom_files,
                        global_files=global_files,
                        dom_name=dom_name,
                        existing_dict_map=existing_dict_map,
                        allow_literal_strings=(opt_col == "site-category"),
                    )
                    if col_err is not None:
                        return col_err, None
                    new_rule[opt_col] = vals
            if rule_kind == "access":
                new_rule["source-negate"] = bool(req.get("source-negate", False))
                new_rule["destination-negate"] = bool(req.get("destination-negate", False))
                new_rule["service-negate"] = bool(req.get("service-negate", False))
            if rule_kind in ("access", "https") and "inline-layer" in req and req.get("inline-layer") is not None:
                inline_uid, il_err = _normalize_inline_layer(
                    req.get("inline-layer"),
                    rule_kind=rule_kind,
                    dom_files=dom_files,
                    global_files=global_files,
                    dom_name=dom_name,
                    existing_dict_map=existing_dict_map,
                )
                if il_err is not None:
                    return il_err, None
                if inline_uid:
                    new_rule["inline-layer"] = inline_uid
            if rule_kind == "https":
                if "certificate" in req and req["certificate"] is not None:
                    new_rule["certificate"] = copy.deepcopy(req["certificate"])
                if "blade" in req and req["blade"] is not None:
                    new_rule["blade"] = copy.deepcopy(req["blade"])
            if rule_kind == "threat" and "exceptions" in req:
                new_rule["exceptions"] = copy.deepcopy(req["exceptions"])
        else:
            nat_fields: dict[str, str] = {}
            for nat_col in _NAT_CELL_SCALAR_FIELDS:
                is_trans = nat_col.startswith("translated-")
                val_uid, err = _normalize_nat_scalar_field(
                    req.get(nat_col),
                    is_translated=is_trans,
                    dom_files=dom_files,
                    global_files=global_files,
                    dom_name=dom_name,
                    existing_dict_map=existing_dict_map,
                )
                if err is not None:
                    return err, None
                assert val_uid is not None
                nat_fields[nat_col] = val_uid
            inst, err = _apply_cell_list_update(
                [ANY_UID],
                req.get("install-on", [ANY_UID]),
                dom_files=dom_files,
                global_files=global_files,
                dom_name=dom_name,
                existing_dict_map=existing_dict_map,
            )
            if err is not None:
                return err, None
            new_rule = {
                "uid": assigned_uid,
                "name": str(req.get("name") or ""),
                "type": "nat-rule",
                "domain": format_domain_meta(dom_name),
                "enabled": bool(req.get("enabled", True)),
                "method": str(req.get("method") or "static"),
                **nat_fields,
                "install-on": inst,
                "comments": str(req.get("comments") or ""),
                "meta-info": meta,
            }

        pos_err = _insert_rule_into_tree(nodes, new_rule, req.get("position"))
        if pos_err is not None:
            return pos_err, None
        _renumber_layer(layer_payload, dom_files, global_files, dom_name)
        locked_uids_out.add(assigned_uid)
        return (
            cp_ok(
                _format_rule_response(
                    new_rule,
                    layer_payload=layer_payload,
                    dom_files=dom_files,
                    global_files=global_files,
                    dom_name=dom_name,
                    rule_kind=rule_kind,
                )
            ),
            assigned_uid,
        )

    if action == "set":
        rule_hit = _locate_rule_in_tree(nodes, req)
        if rule_hit is None:
            return cp_error("generic_err_object_not_found", "Rule not found", status_code=404), None
        parent_list, parent_idx, rule, _ = rule_hit
        rule_uid = str(rule["uid"])
        locked_uids_out.add(rule_uid)
        snapshot_rule = copy.deepcopy(rule)

        if "new-name" in req:
            rule["name"] = str(req["new-name"])
        if "enabled" in req:
            rule["enabled"] = bool(req["enabled"])
        if "comments" in req:
            rule["comments"] = str(req["comments"])

        if not is_nat:
            for col in cfg["list_fields"]:
                if col in req:
                    cur = (
                        list(extract_ref_uids(rule.get(col)))
                        if col not in rule
                        else [str(x["uid"]) if isinstance(x, Mapping) else str(x) for x in _as_list(rule.get(col))]
                    )
                    updated, err = _apply_cell_list_update(
                        cur,
                        req[col],
                        dom_files=dom_files,
                        global_files=global_files,
                        dom_name=dom_name,
                        existing_dict_map=existing_dict_map,
                        allow_literal_strings=(col == "site-category"),
                    )
                    if err is not None:
                        parent_list[parent_idx] = snapshot_rule
                        return err, None
                    rule[col] = updated
            if "action" in req:
                act = _normalize_action(req["action"], rule_kind=rule_kind)
                if isinstance(act, ApiCallResult):
                    parent_list[parent_idx] = snapshot_rule
                    return act, None
                rule["action"] = act
            if "track" in req:
                rule["track"] = _normalize_track(req["track"])
            if rule_kind == "access":
                for neg_key in ("source-negate", "destination-negate", "service-negate"):
                    if neg_key in req:
                        rule[neg_key] = bool(req[neg_key])
            if rule_kind in ("access", "https") and "inline-layer" in req:
                inline_uid, il_err = _normalize_inline_layer(
                    req["inline-layer"],
                    rule_kind=rule_kind,
                    dom_files=dom_files,
                    global_files=global_files,
                    dom_name=dom_name,
                    existing_dict_map=existing_dict_map,
                )
                if il_err is not None:
                    parent_list[parent_idx] = snapshot_rule
                    return il_err, None
                if inline_uid:
                    rule["inline-layer"] = inline_uid
                else:
                    rule.pop("inline-layer", None)
            if rule_kind == "https":
                for opt_h in ("certificate", "blade"):
                    if opt_h in req:
                        if req[opt_h] is None:
                            rule.pop(opt_h, None)
                        else:
                            rule[opt_h] = copy.deepcopy(req[opt_h])
            if rule_kind == "threat" and "exceptions" in req:
                rule["exceptions"] = copy.deepcopy(req["exceptions"])
        else:
            if "method" in req:
                rule["method"] = str(req["method"])
            for nat_col in _NAT_CELL_SCALAR_FIELDS:
                if nat_col in req:
                    val_uid, err = _normalize_nat_scalar_field(
                        req[nat_col],
                        is_translated=nat_col.startswith("translated-"),
                        dom_files=dom_files,
                        global_files=global_files,
                        dom_name=dom_name,
                        existing_dict_map=existing_dict_map,
                    )
                    if err is not None:
                        parent_list[parent_idx] = snapshot_rule
                        return err, None
                    assert val_uid is not None
                    rule[nat_col] = val_uid
            if "install-on" in req:
                cur_inst = [
                    str(x["uid"]) if isinstance(x, Mapping) else str(x) for x in _as_list(rule.get("install-on"))
                ]
                updated, err = _apply_cell_list_update(
                    cur_inst,
                    req["install-on"],
                    dom_files=dom_files,
                    global_files=global_files,
                    dom_name=dom_name,
                    existing_dict_map=existing_dict_map,
                )
                if err is not None:
                    parent_list[parent_idx] = snapshot_rule
                    return err, None
                rule["install-on"] = updated

        if "new-position" in req:
            parent_list.pop(parent_idx)
            pos_err = _insert_rule_into_tree(nodes, rule, req["new-position"])
            if pos_err is not None:
                parent_list.insert(parent_idx, snapshot_rule)
                return pos_err, None

        meta = rule.setdefault("meta-info", {})
        if isinstance(meta, dict):
            meta["last-modifier"] = user_name
            meta["last-modify-time"] = format_timestamp(now_ms)

        _renumber_layer(layer_payload, dom_files, global_files, dom_name)
        return (
            cp_ok(
                _format_rule_response(
                    rule,
                    layer_payload=layer_payload,
                    dom_files=dom_files,
                    global_files=global_files,
                    dom_name=dom_name,
                    rule_kind=rule_kind,
                )
            ),
            rule_uid,
        )

    if action == "delete":
        rule_hit = _locate_rule_in_tree(nodes, req)
        if rule_hit is None:
            return cp_error("generic_err_object_not_found", "Rule not found", status_code=404), None
        parent_list, parent_idx, rule, _ = rule_hit
        rule_uid = str(rule["uid"])
        locked_uids_out.add(rule_uid)
        parent_list.pop(parent_idx)
        _renumber_layer(layer_payload, dom_files, global_files, dom_name)
        return cp_ok({"message": "OK"}), rule_uid

    return None
