"""Query, layer/NAT resolution, `show-objects` filter, and `where-used` builders for `FileReplayApiMock`."""

from __future__ import annotations

import copy
from collections import deque
from typing import Any

from ._emulator_projection import extract_ref_uids, iter_flat_rule_entries

SHOW_OBJECTS_TYPE_TO_CMD: dict[str, str] = {
    "host": "show-hosts",
    "network": "show-networks",
    "address-range": "show-address-ranges",
    "multicast-address-range": "show-multicast-address-ranges",
    "group": "show-groups",
    "group-with-exclusion": "show-groups-with-exclusion",
    "dns-domain": "show-dns-domains",
    "application-site": "show-application-sites",
    "security-zone": "show-security-zones",
    "dynamic-object": "show-dynamic-objects",
    "service-tcp": "show-services-tcp",
    "service-udp": "show-services-udp",
    "service-icmp": "show-services-icmp",
    "service-icmp6": "show-services-icmp6",
    "service-other": "show-services-other",
    "service-sctp": "show-services-sctp",
    "service-dce-rpc": "show-services-dce-rpc",
    "service-rpc": "show-services-rpc",
    "service-gtp": "show-services-gtp",
    "service-citrix-tcp": "show-services-citrix-tcp",
    "service-compound-tcp": "show-services-compound-tcp",
    "service-group": "show-service-groups",
}

SHOW_OBJECTS_IP_FIELDS: tuple[str, ...] = (
    "ipv4-address",
    "ipv6-address",
    "subnet4",
    "subnet6",
    "ipv4-address-first",
    "ipv4-address-last",
    "ipv6-address-first",
    "ipv6-address-last",
)

SHOW_OBJECTS_TEXT_FIELDS: tuple[str, ...] = (
    "name",
    "comments",
    *SHOW_OBJECTS_IP_FIELDS,
    "port",
    "protocol",
    "ip-protocol",
    "fqdn",
)

ACCESS_WHERE_USED_COLS: tuple[str, ...] = ("source", "destination", "service", "vpn", "time", "install-on")
HTTPS_WHERE_USED_COLS: tuple[str, ...] = ("source", "destination", "service", "site-category", "install-on")
THREAT_WHERE_USED_COLS: tuple[str, ...] = ("protected-scope", "source", "destination", "service", "install-on")
NAT_WHERE_USED_COLS: tuple[str, ...] = (
    "original-source",
    "original-destination",
    "original-service",
    "translated-source",
    "translated-destination",
    "translated-service",
    "install-on",
)


def matches_show_objects_filter(item: dict[str, Any], *, filter_needle: str, ip_only: bool) -> bool:
    """Evaluate Check Point `show-objects` substring filtering (`filter` and `ip-only`)."""
    if not filter_needle:
        if not ip_only:
            return True
        return any(item.get(field) not in (None, "") for field in SHOW_OBJECTS_IP_FIELDS)

    candidate_fields = SHOW_OBJECTS_IP_FIELDS if ip_only else SHOW_OBJECTS_TEXT_FIELDS
    for field in candidate_fields:
        val = item.get(field)
        if val is not None and filter_needle in str(val).lower():
            return True
    if not ip_only:
        url_list = item.get("url-list")
        if isinstance(url_list, list):
            for entry in url_list:
                if entry is not None and filter_needle in str(entry).lower():
                    return True
    return False


def empty_where_used_bucket() -> dict[str, Any]:
    """Return an empty Check Point `where-used` usage bucket."""
    return {
        "total": 0,
        "objects": [],
        "access-control-rules": [],
        "nat-rules": [],
        "threat-prevention-rules": [],
        "https-rules": [],
    }


def find_domain_object_by_ref(dom_files: dict[str, Any], lookup: str) -> dict[str, Any] | None:
    """Resolve an object by `uid` or `name` across a domain's fixture payloads."""
    if not lookup:
        return None
    for file_key, file_val in dom_files.items():
        if not isinstance(file_val, dict):
            continue
        items = file_val.get("objects")
        if isinstance(items, list):
            for obj in items:
                if isinstance(obj, dict) and (obj.get("uid") == lookup or obj.get("name") == lookup):
                    return obj
        if file_key in ("show-access-rulebase", "show-nat-rulebase"):
            for layer_val in file_val.values():
                if not isinstance(layer_val, dict):
                    continue
                for entry in layer_val.get("objects-dictionary", []):
                    if isinstance(entry, dict) and (entry.get("uid") == lookup or entry.get("name") == lookup):
                        return entry
        direct_match = file_val.get(lookup)
        if isinstance(direct_match, dict):
            return direct_match
        for sub_val in file_val.values():
            if isinstance(sub_val, dict) and (sub_val.get("uid") == lookup or sub_val.get("name") == lookup):
                return sub_val
            if isinstance(sub_val, list):
                for entry in sub_val:
                    if isinstance(entry, dict) and (entry.get("uid") == lookup or entry.get("name") == lookup):
                        return entry
    return None


def resolve_layer_payload(
    dom_files: dict[str, Any],
    global_files: dict[str, Any],
    lookup: str,
    *,
    store_key: str = "show-access-rulebase",
    layer_store_key: str = "show-access-layers",
    layer_list_key: str = "access-layers",
) -> dict[str, Any] | None:
    """Resolve an access/https/threat rulebase layer payload by key, layer UID, or layer name."""
    for scope_files in (dom_files, global_files):
        rb_store = scope_files.get(store_key, {})
        if not isinstance(rb_store, dict):
            continue
        direct = rb_store.get(lookup)
        if isinstance(direct, dict):
            return direct
        for lyr in scope_files.get(layer_store_key, {}).get(layer_list_key, []):
            if isinstance(lyr, dict) and (lyr.get("uid") == lookup or lyr.get("name") == lookup):
                for key in (lyr.get("name"), lyr.get("uid")):
                    if key:
                        nested = rb_store.get(str(key))
                        if isinstance(nested, dict):
                            return nested
        for candidate in rb_store.values():
            if isinstance(candidate, dict) and (candidate.get("uid") == lookup or candidate.get("name") == lookup):
                return candidate
    return None


def resolve_access_layer_payload(
    dom_files: dict[str, Any],
    global_files: dict[str, Any],
    lookup: str,
) -> dict[str, Any] | None:
    """Resolve an access rulebase layer payload by store key, layer UID, or layer name."""
    return resolve_layer_payload(dom_files, global_files, lookup)


def resolve_nat_package_payload(dom_files: dict[str, Any], pkg_lookup: str) -> dict[str, Any] | None:
    """Resolve a NAT rulebase payload by package name, package UID, or rulebase UID."""
    nat_store = dom_files.get("show-nat-rulebase", {})
    if not isinstance(nat_store, dict):
        return None
    direct = nat_store.get(pkg_lookup)
    if isinstance(direct, dict):
        return direct

    for pkg in dom_files.get("show-packages", {}).get("packages", []):
        if not isinstance(pkg, dict):
            continue
        if pkg.get("uid") == pkg_lookup or pkg.get("name") == pkg_lookup:
            for key in (pkg.get("name"), pkg.get("uid")):
                if key:
                    candidate_by_key = nat_store.get(key)
                    if isinstance(candidate_by_key, dict):
                        return candidate_by_key

    for candidate in nat_store.values():
        if isinstance(candidate, dict) and (
            candidate.get("package") == pkg_lookup or candidate.get("uid") == pkg_lookup
        ):
            return candidate
    return None


def collect_group_parents(
    dom_files: dict[str, Any],
    global_files: dict[str, Any],
    dom_name: str,
) -> dict[str, list[tuple[dict[str, Any], str]]]:
    """Build `member_uid -> [(group_dict, owning_domain)]` across groups in domain and Global."""
    parents: dict[str, list[tuple[dict[str, Any], str]]] = {}
    group_cmds = ("show-groups", "show-groups-with-exclusion", "show-service-groups")
    scopes: list[tuple[str, dict[str, Any]]] = [(dom_name, dom_files)]
    if dom_name != "Global" and global_files:
        scopes.append(("Global", global_files))

    for scope_dom, scope_files in scopes:
        for cmd in group_cmds:
            items = scope_files.get(cmd, {}).get("objects", [])
            if not isinstance(items, list):
                continue
            for grp in items:
                if not isinstance(grp, dict) or not grp.get("uid"):
                    continue
                member_uids = extract_ref_uids(grp.get("members"))
                member_uids.update(extract_ref_uids(grp.get("include")))
                member_uids.update(extract_ref_uids(grp.get("except")))
                for m_uid in member_uids:
                    parents.setdefault(m_uid, []).append((grp, scope_dom))
    return parents


def build_where_used_response(
    dom_files: dict[str, Any],
    global_files: dict[str, Any],
    dom_name: str,
    target_uid: str,
    *,
    indirect: bool,
    max_depth: int,
) -> dict[str, Any]:
    """Compute Check Point `where-used` payload for `target_uid` from domain fixtures."""
    used_directly = empty_where_used_bucket()
    used_indirectly = empty_where_used_bucket()

    parents_by_member = collect_group_parents(dom_files, global_files, dom_name)
    direct_seen: set[str] = set()
    indirect_seen: set[str] = set()
    ancestor_group_uids: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(target_uid, 0)])
    visited_nodes: set[str] = {target_uid}

    while queue:
        curr_uid, curr_depth = queue.popleft()
        next_depth = curr_depth + 1
        if curr_depth >= 1 and (not indirect or next_depth > max_depth):
            continue
        for grp, scope_dom in parents_by_member.get(curr_uid, []):
            g_uid = str(grp.get("uid") or "")
            if not g_uid:
                continue
            ancestor_group_uids.add(g_uid)
            grp_ref = {
                "uid": g_uid,
                "name": str(grp.get("name") or g_uid),
                "type": str(grp.get("type") or "group"),
                "domain": copy.deepcopy(grp.get("domain") or {"name": scope_dom}),
            }
            if next_depth == 1 and g_uid not in direct_seen:
                direct_seen.add(g_uid)
                used_directly["objects"].append(grp_ref)
            elif next_depth >= 2 and indirect and g_uid not in indirect_seen:
                indirect_seen.add(g_uid)
                used_indirectly["objects"].append(grp_ref)

            if indirect and next_depth < max_depth and g_uid not in visited_nodes:
                visited_nodes.add(g_uid)
                queue.append((g_uid, next_depth))

    layer_to_pkg: dict[str, dict[str, str]] = {}
    pkg_lookup_map: dict[str, dict[str, str]] = {}
    for pkg in dom_files.get("show-packages", {}).get("packages", []):
        if not isinstance(pkg, dict):
            continue
        pkg_uid = str(pkg.get("uid") or "")
        pkg_name = str(pkg.get("name") or pkg_uid)
        pkg_ref = {"uid": pkg_uid, "name": pkg_name}
        if pkg_uid:
            pkg_lookup_map[pkg_uid] = pkg_ref
        if pkg_name:
            pkg_lookup_map[pkg_name] = pkg_ref
        for layer_key in ("access-layers", "https-layers", "threat-layers"):
            for lyr in pkg.get(layer_key, []):
                if not isinstance(lyr, dict):
                    continue
                if lyr.get("uid"):
                    layer_to_pkg[str(lyr["uid"])] = pkg_ref
                if lyr.get("name"):
                    layer_to_pkg[str(lyr["name"])] = pkg_ref

    layer_scans = (
        ("show-access-rulebase", ACCESS_WHERE_USED_COLS, "access-rule", "access-layer", "access-control-rules"),
        ("show-https-rulebase", HTTPS_WHERE_USED_COLS, "https-rule", "https-layer", "https-rules"),
        (
            "show-threat-rulebase",
            THREAT_WHERE_USED_COLS,
            "threat-rule",
            "threat-layer",
            "threat-prevention-rules",
        ),
    )
    for rb_cmd, cols, default_rule_type, layer_type, out_bucket_key in layer_scans:
        rb_store = dom_files.get(rb_cmd, {})
        if not isinstance(rb_store, dict):
            continue
        for layer_key, layer_payload in rb_store.items():
            if not isinstance(layer_payload, dict):
                continue
            layer_uid = str(layer_payload.get("uid") or layer_key)
            layer_name = str(layer_payload.get("name") or layer_uid)
            pkg_ref = (
                layer_to_pkg.get(layer_uid)
                or layer_to_pkg.get(layer_name)
                or {
                    "uid": layer_uid,
                    "name": layer_name,
                }
            )
            raw_rb = layer_payload.get("rulebase")
            flat_rules = iter_flat_rule_entries(raw_rb if isinstance(raw_rb, list) else [])
            for idx, (_, rule) in enumerate(flat_rules, start=1):
                col_uids = {col: extract_ref_uids(rule.get(col)) for col in cols}
                direct_cols = [col for col, uids in col_uids.items() if target_uid in uids]
                indirect_cols = (
                    [col for col, uids in col_uids.items() if ancestor_group_uids & uids] if indirect else []
                )
                if not direct_cols and not indirect_cols:
                    continue
                entry = {
                    "rule": {
                        "uid": str(rule.get("uid") or ""),
                        "name": str(rule.get("name") or ""),
                        "type": str(rule.get("type") or default_rule_type),
                    },
                    "rule-columns": direct_cols if direct_cols else indirect_cols,
                    "package": dict(pkg_ref),
                    "layer": {"uid": layer_uid, "name": layer_name, "type": layer_type},
                    "position": str(rule.get("rule-number") or idx),
                }
                if direct_cols:
                    used_directly[out_bucket_key].append(entry)
                elif indirect_cols:
                    used_indirectly[out_bucket_key].append(entry)

    nat_store = dom_files.get("show-nat-rulebase", {})
    if isinstance(nat_store, dict):
        for nat_key, nat_payload in nat_store.items():
            if not isinstance(nat_payload, dict):
                continue
            pkg_name = str(nat_payload.get("package") or nat_key)
            pkg_ref = (
                pkg_lookup_map.get(pkg_name)
                or pkg_lookup_map.get(str(nat_payload.get("uid") or ""))
                or {
                    "uid": str(nat_payload.get("uid") or nat_key),
                    "name": pkg_name,
                }
            )
            raw_nat_rb = nat_payload.get("rulebase")
            flat_rules = iter_flat_rule_entries(raw_nat_rb if isinstance(raw_nat_rb, list) else [])
            for idx, (_, rule) in enumerate(flat_rules, start=1):
                col_uids = {col: extract_ref_uids(rule.get(col)) for col in NAT_WHERE_USED_COLS}
                direct_cols = [col for col, uids in col_uids.items() if target_uid in uids]
                indirect_cols = (
                    [col for col, uids in col_uids.items() if ancestor_group_uids & uids] if indirect else []
                )
                if not direct_cols and not indirect_cols:
                    continue
                entry = {
                    "rule": {
                        "uid": str(rule.get("uid") or ""),
                        "name": str(rule.get("name") or ""),
                        "type": str(rule.get("type") or "nat-rule"),
                    },
                    "rule-columns": direct_cols if direct_cols else indirect_cols,
                    "package": dict(pkg_ref),
                    "position": str(rule.get("rule-number") or idx),
                }
                if direct_cols:
                    used_directly["nat-rules"].append(entry)
                elif indirect_cols:
                    used_indirectly["nat-rules"].append(entry)

    for bucket in (used_directly, used_indirectly):
        bucket["total"] = (
            len(bucket["objects"])
            + len(bucket["access-control-rules"])
            + len(bucket["nat-rules"])
            + len(bucket["threat-prevention-rules"])
            + len(bucket["https-rules"])
        )

    resp: dict[str, Any] = {"used-directly": used_directly}
    if indirect:
        resp["used-indirectly"] = used_indirectly
    return resp
