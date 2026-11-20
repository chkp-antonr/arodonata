"""Shared projection, pagination, object-dictionary, and rulebase-slicing helpers for the replay emulator."""

from __future__ import annotations

import copy
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from ._emulator_models import BUILTIN_SENTINELS, ENTITY_SPECS, format_domain_meta

GATEWAY_SHOW_CMD = "show-gateways-and-servers"
EXTRA_OBJECT_BUCKETS: tuple[tuple[str, str], ...] = (
    ("show-groups-with-exclusion", "objects"),
    ("show-gateways-and-servers", "objects"),
    ("show-packages", "packages"),
    ("show-access-layers", "access-layers"),
    ("show-https-layers", "https-layers"),
    ("show-threat-layers", "threat-layers"),
)
NETWORK_NAMESPACE_TYPES: frozenset[str] = frozenset(
    {
        "host",
        "network",
        "address-range",
        "dns-domain",
        "application-site",
        "group",
    }
)
SERVICE_NAMESPACE_TYPES: frozenset[str] = frozenset(
    {
        "service-tcp",
        "service-udp",
        "service-icmp",
        "service-icmp6",
        "service-other",
        "service-group",
    }
)
ACCESS_CELL_LIST_FIELDS: tuple[str, ...] = ("source", "destination", "service", "install-on", "vpn", "content", "time")
HTTPS_CELL_LIST_FIELDS: tuple[str, ...] = ("source", "destination", "service", "site-category", "install-on")
THREAT_CELL_LIST_FIELDS: tuple[str, ...] = ("protected-scope", "source", "destination", "service", "install-on")
NAT_CELL_SCALAR_FIELDS: tuple[str, ...] = (
    "original-source",
    "original-destination",
    "original-service",
    "translated-source",
    "translated-destination",
    "translated-service",
)
RULE_DICT_LIST_FIELDS: tuple[str, ...] = (
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
RULE_DICT_SCALAR_FIELDS: tuple[str, ...] = (
    "action",
    "inline-layer",
    "original-source",
    "original-destination",
    "original-service",
    "translated-source",
    "translated-destination",
    "translated-service",
)
ACCESS_REF_COLS: tuple[str, ...] = ("source", "destination", "service", "install-on", "vpn", "content", "time")
NAT_REF_COLS: tuple[str, ...] = (
    "original-source",
    "original-destination",
    "original-service",
    "translated-source",
    "translated-destination",
    "translated-service",
    "install-on",
)
RULE_KIND_CONFIGS: dict[str, dict[str, Any]] = {
    "access": {
        "store_key": "show-access-rulebase",
        "layer_store": "show-access-layers",
        "layer_key": "access-layers",
        "layer_type": "access-layer",
        "rule_type": "access-rule",
        "section_type": "access-section",
        "label": "Access",
        "list_fields": ACCESS_CELL_LIST_FIELDS,
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
        "list_fields": HTTPS_CELL_LIST_FIELDS,
    },
    "threat": {
        "store_key": "show-threat-rulebase",
        "layer_store": "show-threat-layers",
        "layer_key": "threat-layers",
        "layer_type": "threat-layer",
        "rule_type": "threat-rule",
        "section_type": "threat-section",
        "label": "Threat",
        "list_fields": THREAT_CELL_LIST_FIELDS,
    },
}

REPLAY_STANDARD_SUMMARY_KEYS: frozenset[str] = frozenset(
    {
        "uid",
        "name",
        "type",
        "domain",
        "ipv4-address",
        "ipv6-address",
        "ipv4-address-first",
        "ipv4-address-last",
        "ipv6-address-first",
        "ipv6-address-last",
        "subnet4",
        "subnet6",
        "mask-length4",
        "mask-length6",
        "subnet-mask",
        "port",
        "protocol",
        "icmp-type",
        "icmp-code",
        "ip-protocol",
        "fqdn",
        "is-sub-domain",
        "url-list",
        "urls-defined-as-regular-expression",
        "primary-category",
        "members",
        "color",
        "comments",
        "meta-info",
        "icon",
        "tags",
        "class-name",
    }
)
CRUD_STANDARD_KEEP_KEYS: tuple[str, ...] = (
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


def is_section_node(node: Mapping[str, Any]) -> bool:
    """Return True if a rulebase node represents a rule section container."""
    node_type = str(node.get("type") or "")
    return node_type.endswith("-section") or (isinstance(node.get("rulebase"), list) and "rule-number" not in node)


def extract_ref_uids(value: Any) -> set[str]:
    """Extract referenced UIDs from a string, mapping, or nested list of references."""
    if isinstance(value, str):
        clean = value.strip()
        return {clean} if clean else set()
    if isinstance(value, Mapping):
        uid = value.get("uid")
        return {str(uid)} if uid else set()
    if isinstance(value, list):
        out: set[str] = set()
        for elem in value:
            out.update(extract_ref_uids(elem))
        return out
    return set()


def iter_flat_rule_entries(nodes: Any) -> list[tuple[dict[str, Any] | None, dict[str, Any]]]:
    """Flatten top-level and section-nested rules into `(section_meta, rule_dict)` pairs."""
    if not isinstance(nodes, list):
        return []
    out: list[tuple[dict[str, Any] | None, dict[str, Any]]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if is_section_node(node):
            children = node.get("rulebase")
            if isinstance(children, list):
                for child in children:
                    if isinstance(child, dict):
                        out.append((node, child))
        else:
            out.append((None, node))
    return out


def project_replay_details_level(obj: Mapping[str, Any], details_level: str) -> dict[str, Any]:
    """Apply strict Check Point `details-level` (`uid`, `standard`, `full`) projection for replay reads."""
    level = (details_level or "standard").strip().lower()
    if level == "uid":
        uid = obj.get("uid")
        return {"uid": uid} if uid is not None else copy.deepcopy(dict(obj))
    if level == "standard":
        return {k: copy.deepcopy(v) for k, v in obj.items() if k in REPLAY_STANDARD_SUMMARY_KEYS}
    return copy.deepcopy(dict(obj))


def project_details_level(obj: Mapping[str, Any], details_level: str) -> dict[str, Any]:
    """Apply Check Point `details-level` (`uid`, `standard`, `full`) projection to a CRUD object."""
    level = (details_level or "").strip().lower()
    if level == "uid":
        return {"uid": obj.get("uid")}
    copied = copy.deepcopy(dict(obj))
    if level == "standard" and len(copied) > 24:
        slim = {k: copied[k] for k in CRUD_STANDARD_KEEP_KEYS if k in copied}
        if slim:
            return slim
    return copied


def paginate_items(
    items: list[dict[str, Any]],
    req: Mapping[str, Any],
    *,
    collection_key: str = "objects",
    details_level: str | None = None,
    default_limit: int = 100,
    default_details_level: str | None = None,
    min_limit: int = 1,
    projector: Callable[[Mapping[str, Any], str], dict[str, Any]] = project_details_level,
) -> dict[str, Any]:
    """Paginate a list using Check Point `limit` / `offset` conventions."""
    total = len(items)
    offset = max(0, int(req.get("offset", 0)))
    limit = max(min_limit, int(req.get("limit", default_limit)))
    page_items = items[offset : offset + limit]
    eff_level = str(details_level or req.get("details-level") or default_details_level or "").strip().lower()
    sliced = [projector(item, eff_level) for item in page_items] if eff_level else copy.deepcopy(page_items)
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

    for _, rule in iter_flat_rule_entries(nodes):
        for field in RULE_DICT_LIST_FIELDS:
            for uid in extract_ref_uids(rule.get(field)):
                _record(uid)
        for field in RULE_DICT_SCALAR_FIELDS:
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
        for cmd, col_key in EXTRA_OBJECT_BUCKETS:
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


def inline_rule_objects(rule: dict[str, Any], obj_map: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Replace UID references in a copied rule with full objects from `objects-dictionary`."""
    for field in RULE_DICT_LIST_FIELDS:
        raw_list = rule.get(field)
        if not isinstance(raw_list, list):
            continue
        rule[field] = [
            copy.deepcopy(dict(obj_map[elem])) if isinstance(elem, str) and elem in obj_map else elem
            for elem in raw_list
        ]

    for field in RULE_DICT_SCALAR_FIELDS:
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
        if is_section_node(node):
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
                copied_rule = inline_rule_objects(copied_rule, obj_map)

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
