"""File-backed Check Point Management API and Gateway CLI replay adapters (`replay_mock.py`).

Provides:
- `FileReplayApiMock` (`ApiPort`): serves raw Check Point Management API JSON fixtures from
  `tests/fixtures/enterprise_raw_dataset/` with pagination (`limit`, `offset` -> `from`, `to`, `total`),
  `details-level` (`uid`, `standard`, `full`), `uid`/`name` and `class-name` filtering, rulebase section
  slicing (`show-access-rulebase`, `show-nat-rulebase`), `run-script` + `show-task` Base64 task execution,
  in-memory mutation helpers for targeted refresh tests, and per-domain/per-command call counters.
- `FileReplayCliMock` (`GatewayCliPort`): parses bash scripts produced by `build_route_collection_script`,
  verifies `vsenv "$vsid"` / `vsx stat -l` and `CTX%05d` `$FWDIR` checks, returns raw stdout/stderr from
  `cli/`, supports per-node SSH failure injection to trigger `cprid` `run-script` fallback, and records
  CLI execution counters.
"""

from __future__ import annotations

import base64
import copy
import json
import re
from collections import Counter, deque
from collections.abc import Awaitable, Iterable, Mapping
from pathlib import Path
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from arodonata.adapters.checkpoint.pager import DEFAULT_PAGE_LIMIT, paginate_objects
from arodonata.core.context import AuthContext
from arodonata.core.errors import REDACTED_PLACEHOLDER, SessionError
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.topology import GatewayCliResult, GatewayCliTarget
from arodonata.core.ports import ApiPort, GatewayCliPort
from arodonata.core.telemetry import span_attrs, traced
from arodonata.testing._emulator_changes import (
    build_show_changes_task,
    compute_session_delta,
    count_delta_items,
    parse_checkpoint_date_ms,
)
from arodonata.testing._emulator_crud import (
    delete_unused_objects,
    filter_show_objects,
    find_effective_object,
    find_unused_objects,
    handle_entity_crud,
    handle_rulebase_crud,
    paginate_items,
    parse_rule_number,
    slice_rulebase_with_sections,
)
from arodonata.testing._emulator_models import (
    CMD_TO_ENTITY_ACTION,
    MutationRecord,
    PublishedDelta,
    ReplayStateSnapshot,
    SidBinding,
    WorkSession,
    cp_error,
    cp_ok,
    format_domain_meta,
    format_timestamp,
    is_mutating_command,
    sanitize_call_payload,
    summarize_payload,
)
from arodonata.testing.dataset_generator import (
    ALL_DOMAINS,
    DEFAULT_DATASET_DIR,
    USER_DOMAINS,
    ensure_enterprise_raw_dataset,
)

_VSID_SCRIPT_RE = re.compile(r"(?:^|\n)vsid=(\d+)\b")
_VS_NAME_SCRIPT_RE = re.compile(r"(?:^|\n)vs_name=([^\n]+)")

_SHOW_OBJECTS_TYPE_TO_CMD: dict[str, str] = {
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

_SHOW_OBJECTS_IP_FIELDS: tuple[str, ...] = (
    "ipv4-address",
    "ipv6-address",
    "subnet4",
    "subnet6",
    "ipv4-address-first",
    "ipv4-address-last",
    "ipv6-address-first",
    "ipv6-address-last",
)

_SHOW_OBJECTS_TEXT_FIELDS: tuple[str, ...] = (
    "name",
    "comments",
    *_SHOW_OBJECTS_IP_FIELDS,
    "port",
    "protocol",
    "ip-protocol",
    "fqdn",
)


def _matches_show_objects_filter(item: dict[str, Any], *, filter_needle: str, ip_only: bool) -> bool:
    """Evaluate Check Point `show-objects` substring filtering (`filter` and `ip-only`)."""
    if not filter_needle:
        if not ip_only:
            return True
        return any(item.get(field) not in (None, "") for field in _SHOW_OBJECTS_IP_FIELDS)

    candidate_fields = _SHOW_OBJECTS_IP_FIELDS if ip_only else _SHOW_OBJECTS_TEXT_FIELDS
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


def _project_details_level(item: dict[str, Any], details_level: str) -> dict[str, Any]:
    """Project an object dictionary according to Check Point `details-level` (`uid`, `standard`, `full`)."""
    lvl = (details_level or "standard").strip().lower()
    if lvl == "uid":
        uid = item.get("uid")
        return {"uid": uid} if uid is not None else dict(item)
    if lvl == "standard":
        # Keep core summary fields while still preserving enough metadata for standard listings
        summary_keys = {
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
        return {k: copy.deepcopy(v) for k, v in item.items() if k in summary_keys}
    return copy.deepcopy(item)


_INLINE_LIST_RULE_FIELDS: tuple[str, ...] = (
    "source",
    "destination",
    "service",
    "install-on",
    "time",
    "vpn",
    "content",
    "protected-scope",
    "site-category",
)
_INLINE_SCALAR_RULE_FIELDS: tuple[str, ...] = (
    "action",
    "inline-layer",
    "original-source",
    "original-destination",
    "original-service",
    "translated-source",
    "translated-destination",
    "translated-service",
)
_ACCESS_WHERE_USED_COLS: tuple[str, ...] = ("source", "destination", "service", "vpn", "time", "install-on")
_HTTPS_WHERE_USED_COLS: tuple[str, ...] = ("source", "destination", "service", "site-category", "install-on")
_THREAT_WHERE_USED_COLS: tuple[str, ...] = ("protected-scope", "source", "destination", "service", "install-on")
_NAT_WHERE_USED_COLS: tuple[str, ...] = (
    "original-source",
    "original-destination",
    "original-service",
    "translated-source",
    "translated-destination",
    "translated-service",
    "install-on",
)


def _extract_ref_uids(value: Any) -> set[str]:
    """Extract UID strings from a string, object dict, or list of references."""
    if isinstance(value, str):
        clean = value.strip()
        return {clean} if clean else set()
    if isinstance(value, dict):
        uid_val = value.get("uid")
        return {str(uid_val)} if uid_val else set()
    if isinstance(value, list):
        out: set[str] = set()
        for entry in value:
            out.update(_extract_ref_uids(entry))
        return out
    return set()


def _iter_flat_rulebase_nodes(nodes: list[Any]) -> list[tuple[dict[str, Any] | None, dict[str, Any]]]:
    """Flatten top-level and section-nested rulebase entries into `(section_meta, rule_dict)` pairs."""
    flat: list[tuple[dict[str, Any] | None, dict[str, Any]]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_type = str(node.get("type") or "")
        if node_type.endswith("-section") or (isinstance(node.get("rulebase"), list) and "rule-number" not in node):
            child_list = node.get("rulebase")
            children = child_list if isinstance(child_list, list) else []
            for child in children:
                if isinstance(child, dict):
                    flat.append((node, child))
        else:
            flat.append((None, node))
    return flat


def _inline_rule_objects(rule: dict[str, Any], obj_map: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Replace UID references in a copied rule with full objects from `objects-dictionary`."""
    for field in _INLINE_LIST_RULE_FIELDS:
        raw_list = rule.get(field)
        if not isinstance(raw_list, list):
            continue
        rule[field] = [
            copy.deepcopy(obj_map[elem]) if isinstance(elem, str) and elem in obj_map else elem for elem in raw_list
        ]

    for field in _INLINE_SCALAR_RULE_FIELDS:
        raw_val = rule.get(field)
        if isinstance(raw_val, str) and raw_val in obj_map:
            rule[field] = copy.deepcopy(obj_map[raw_val])

    track_val = rule.get("track")
    if isinstance(track_val, dict):
        t_type = track_val.get("type")
        if isinstance(t_type, str) and t_type in obj_map:
            resolved_track = copy.deepcopy(obj_map[t_type])
            track_val["type"] = resolved_track
            if isinstance(resolved_track.get("name"), str):
                track_val.setdefault("name", resolved_track["name"])
    return rule


def _slice_rulebase_nodes(
    layer_payload: dict[str, Any],
    *,
    offset: int,
    limit: int,
    use_object_dictionary: bool = True,
) -> dict[str, Any]:
    """Slice a Check Point `show-access-rulebase` or `show-nat-rulebase` payload by rule `offset` and `limit`."""
    raw_nodes = layer_payload.get("rulebase")
    nodes = raw_nodes if isinstance(raw_nodes, list) else []
    flat_rules = _iter_flat_rulebase_nodes(nodes)

    obj_dict_raw = layer_payload.get("objects-dictionary", [])
    obj_map: dict[str, dict[str, Any]] = {}
    if not use_object_dictionary and isinstance(obj_dict_raw, list):
        for entry in obj_dict_raw:
            if isinstance(entry, dict) and entry.get("uid"):
                obj_map[str(entry["uid"])] = entry

    total = len(flat_rules)
    eff_offset = max(0, int(offset))
    eff_limit = max(1, int(limit))
    sliced = flat_rules[eff_offset : eff_offset + eff_limit]

    page_nodes: list[dict[str, Any]] = []
    current_sec_uid: str | None = None
    current_sec_dict: dict[str, Any] | None = None

    for idx_in_slice, (sec_meta, rule_dict) in enumerate(sliced):
        abs_rule_num = eff_offset + idx_in_slice + 1
        copied_rule = copy.deepcopy(rule_dict)
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

    from_idx = (eff_offset + 1) if sliced else 0
    to_idx = (eff_offset + len(sliced)) if sliced else 0

    result: dict[str, Any] = {
        "uid": layer_payload.get("uid", ""),
        "name": layer_payload.get("name", ""),
        "rulebase": page_nodes,
        "objects-dictionary": copy.deepcopy(obj_dict_raw) if use_object_dictionary else [],
        "from": from_idx,
        "to": to_idx,
        "total": total,
    }
    if "package" in layer_payload:
        result["package"] = layer_payload["package"]
    return result


def _empty_where_used_bucket() -> dict[str, Any]:
    """Return an empty Check Point `where-used` usage bucket."""
    return {
        "total": 0,
        "objects": [],
        "access-control-rules": [],
        "nat-rules": [],
        "threat-prevention-rules": [],
        "https-rules": [],
    }


def _find_domain_object_by_ref(dom_files: dict[str, Any], lookup: str) -> dict[str, Any] | None:
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


def _resolve_layer_payload(
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


def _resolve_access_layer_payload(
    dom_files: dict[str, Any],
    global_files: dict[str, Any],
    lookup: str,
) -> dict[str, Any] | None:
    """Resolve an access rulebase layer payload by store key, layer UID, or layer name."""
    return _resolve_layer_payload(dom_files, global_files, lookup)


def _resolve_nat_package_payload(dom_files: dict[str, Any], pkg_lookup: str) -> dict[str, Any] | None:
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


def _collect_group_parents(
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
                member_uids = _extract_ref_uids(grp.get("members"))
                member_uids.update(_extract_ref_uids(grp.get("include")))
                member_uids.update(_extract_ref_uids(grp.get("except")))
                for m_uid in member_uids:
                    parents.setdefault(m_uid, []).append((grp, scope_dom))
    return parents


def _build_where_used_response(
    dom_files: dict[str, Any],
    global_files: dict[str, Any],
    dom_name: str,
    target_uid: str,
    *,
    indirect: bool,
    max_depth: int,
) -> dict[str, Any]:
    """Compute Check Point `where-used` payload for `target_uid` from domain fixtures."""
    used_directly = _empty_where_used_bucket()
    used_indirectly = _empty_where_used_bucket()

    # 1. Upward group membership traversal
    parents_by_member = _collect_group_parents(dom_files, global_files, dom_name)
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

    # 2. Package / access-layer mapping
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

    # 3. Access, HTTPS, and Threat Prevention rules scan
    layer_scans = (
        ("show-access-rulebase", _ACCESS_WHERE_USED_COLS, "access-rule", "access-layer", "access-control-rules"),
        ("show-https-rulebase", _HTTPS_WHERE_USED_COLS, "https-rule", "https-layer", "https-rules"),
        (
            "show-threat-rulebase",
            _THREAT_WHERE_USED_COLS,
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
            flat_rules = _iter_flat_rulebase_nodes(raw_rb if isinstance(raw_rb, list) else [])
            for idx, (_, rule) in enumerate(flat_rules, start=1):
                col_uids = {col: _extract_ref_uids(rule.get(col)) for col in cols}
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

    # 4. NAT rules scan
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
            flat_rules = _iter_flat_rulebase_nodes(raw_nat_rb if isinstance(raw_nat_rb, list) else [])
            for idx, (_, rule) in enumerate(flat_rules, start=1):
                col_uids = {col: _extract_ref_uids(rule.get(col)) for col in _NAT_WHERE_USED_COLS}
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


class FileReplayCliMock(GatewayCliPort):
    """File-backed `GatewayCliPort` replay adapter for gateway SSH route collection."""

    def __init__(
        self,
        dataset_dir: Path | str = DEFAULT_DATASET_DIR,
        *,
        fail_ssh_nodes: set[str] | None = None,
    ) -> None:
        self._dataset_dir = ensure_enterprise_raw_dataset(dataset_dir)
        self._cli_dir = self._dataset_dir / "cli"
        # Default branch gateways that fail SSH so cprid `run-script` fallback is exercised
        self.fail_ssh_nodes: set[str] = (
            set(fail_ssh_nodes) if fail_ssh_nodes is not None else {"br-reg-gw-138", "br-reg-gw-139", "br-reg-gw-140"}
        )
        self._cli_overrides: dict[tuple[str, int], str] = {}
        self.cli_call_counts: Counter[tuple[str, int]] = Counter()
        self.node_call_counts: Counter[str] = Counter()
        self.cli_call_log: list[dict[str, Any]] = []

    def reset_counters(self) -> None:
        """Clear all CLI execution counters and logs."""
        self.cli_call_counts.clear()
        self.node_call_counts.clear()
        self.cli_call_log.clear()

    def set_cli_stdout(self, node_name: str, vsid: int, stdout: str) -> None:
        """Override the raw CLI stdout returned for `(node_name, vsid)` in memory."""
        self._cli_overrides[(node_name, int(vsid))] = stdout

    def get_raw_cli_stdout(self, node_name: str, vsid: int | None = 0) -> str | None:
        """Return the raw CLI stdout for `(node_name, vsid)` from memory override or disk fixture."""
        eff_vsid = int(vsid) if vsid is not None else 0
        key = (node_name, eff_vsid)
        if key in self._cli_overrides:
            return self._cli_overrides[key]
        candidates = [self._cli_dir / f"{node_name}__vs_{eff_vsid}.txt"]
        if eff_vsid == 0:
            candidates.append(self._cli_dir / f"{node_name}__vs_none.txt")
        for cli_path in candidates:
            if cli_path.is_file():
                return cli_path.read_text(encoding="utf-8")
        return None

    def resolve_vsid_from_stat(self, node_name: str, vs_name: str) -> int | None:
        """Emulate `vsx stat -l` awk resolution of `vs_name` -> `vsid` on `node_name` (`VS0`)."""
        stat_path = self._cli_dir / f"{node_name}__vsx_stat_l.txt"
        if not stat_path.is_file():
            return None
        current_id: int | None = None
        clean_target = vs_name.strip().strip("'\"")
        for raw_line in stat_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line.startswith("VSID:"):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        current_id = int(parts[1])
                    except ValueError:
                        current_id = None
            elif line.startswith("Name:"):
                parts = line.split(None, 1)
                if len(parts) >= 2 and parts[1].strip() == clean_target and current_id is not None:
                    return current_id
        return None

    async def execute_command(
        self,
        target: GatewayCliTarget,
        command: str,
        *,
        timeout: float = 30.0,
    ) -> GatewayCliResult:
        """Validate the incoming route-collection bash script and return raw CLI output from `cli/`."""
        _ = timeout
        node_name = target.node_name
        self.node_call_counts[node_name] += 1

        if node_name in self.fail_ssh_nodes or target.gateway_name in self.fail_ssh_nodes:
            self.cli_call_log.append(
                {
                    "node_name": node_name,
                    "gateway_name": target.gateway_name,
                    "vsid": target.vsid,
                    "vs_name": target.vs_name,
                    "status": "ssh_failed",
                }
            )
            return GatewayCliResult(
                success=False,
                stdout="",
                stderr=f"ssh: connect to host {target.node_ipv4 or node_name} port 22: Connection timed out",
                exit_code=255,
                executor="ssh",
                error_message=f"SSH connection timed out to {node_name}",
            )

        # Parse and validate VS context switching in the bash script
        resolved_vsid = 0
        prepend_resolved_marker = False
        m_vsid = _VSID_SCRIPT_RE.search(command)
        m_vs_name = _VS_NAME_SCRIPT_RE.search(command)

        if m_vsid is not None:
            resolved_vsid = int(m_vsid.group(1))
            if 'vsenv "$vsid"' not in command or "CTX%05d" not in command:
                return GatewayCliResult(
                    success=False,
                    stdout="_vs_error=missing vsenv or CTX%05d check in script\n",
                    stderr="Invalid VSX script structure",
                    exit_code=1,
                    executor="ssh",
                    error_message="_vs_error=missing vsenv or CTX%05d check in script",
                )
        elif m_vs_name is not None:
            raw_vs_name = m_vs_name.group(1).strip()
            if "vsx stat -l" not in command or 'vsenv "$vsid"' not in command or "CTX%05d" not in command:
                return GatewayCliResult(
                    success=False,
                    stdout="_vs_error=missing vsx stat -l or vsenv check in script\n",
                    stderr="Invalid VSX stat script structure",
                    exit_code=1,
                    executor="ssh",
                    error_message="_vs_error=missing vsx stat -l or vsenv check in script",
                )
            vsid_lookup = self.resolve_vsid_from_stat(node_name, raw_vs_name)
            if vsid_lookup is None or vsid_lookup <= 0:
                clean_vs = raw_vs_name.strip("'\"")
                err_out = f"_vs_error=unable to resolve vsid for {clean_vs}\n"
                return GatewayCliResult(
                    success=False,
                    stdout=err_out,
                    stderr=err_out.strip(),
                    exit_code=1,
                    executor="ssh",
                    error_message=err_out.strip(),
                )
            resolved_vsid = vsid_lookup
            prepend_resolved_marker = True

        self.cli_call_counts[(node_name, resolved_vsid)] += 1
        self.cli_call_log.append(
            {
                "node_name": node_name,
                "gateway_name": target.gateway_name,
                "vsid": resolved_vsid,
                "vs_name": target.vs_name,
                "status": "ok",
            }
        )

        stdout = self.get_raw_cli_stdout(node_name, resolved_vsid)
        if stdout is None:
            err_msg = f"_vs_error=vsenv {resolved_vsid} failed\n" if resolved_vsid > 0 else "No CLI fixture found"
            return GatewayCliResult(
                success=False,
                stdout=err_msg if resolved_vsid > 0 else "",
                stderr=err_msg,
                exit_code=1,
                executor="ssh",
                error_message=err_msg.strip(),
            )

        if prepend_resolved_marker and f"===ARODONATA_VSID_RESOLVED={resolved_vsid}===" not in stdout:
            stdout = f"===ARODONATA_VSID_RESOLVED={resolved_vsid}===\n{stdout}"

        return GatewayCliResult(
            success=True,
            stdout=stdout,
            stderr="",
            exit_code=0,
            executor="ssh",
        )


class FileReplayApiMock(ApiPort):
    """File-backed `ApiPort` replay adapter emulating Check Point MDSM and CMA domains from disk fixtures."""

    def __init__(
        self,
        dataset_dir: Path | str = DEFAULT_DATASET_DIR,
        *,
        cli_mock: FileReplayCliMock | None = None,
    ) -> None:
        self._dataset_dir = ensure_enterprise_raw_dataset(dataset_dir)
        self._cli_mock = cli_mock or FileReplayCliMock(self._dataset_dir)

        self._manifest: dict[str, Any] = json.loads((self._dataset_dir / "manifest.json").read_text(encoding="utf-8"))
        self._show_domains: dict[str, Any] = json.loads(
            (self._dataset_dir / "mds" / "show-domains.json").read_text(encoding="utf-8")
        )
        self._show_global_domain: dict[str, Any] = json.loads(
            (self._dataset_dir / "mds" / "show-global-domain.json").read_text(encoding="utf-8")
        )
        self._show_mdss: dict[str, Any] = json.loads(
            (self._dataset_dir / "mds" / "show-mdss.json").read_text(encoding="utf-8")
        )

        # Load domain JSON payloads into memory so tests can mutate single gateways without modifying disk files
        self._domain_data: dict[str, dict[str, Any]] = {
            dom_name: self._load_domain_files(dom_name) for dom_name in ALL_DOMAINS
        }

        # Index node_uid -> node_name across all domains for `run-script` target resolution
        self._node_uid_to_name: dict[str, str] = {}
        for dom_files in self._domain_data.values():
            gw_and_srv = dom_files.get("show-gateways-and-servers", {}).get("objects", [])
            for obj in gw_and_srv:
                if isinstance(obj, dict) and obj.get("uid") and obj.get("name"):
                    self._node_uid_to_name[str(obj["uid"])] = str(obj["name"])
                    members = obj.get("cluster-member-names")
                    if isinstance(members, list):
                        for m in members:
                            if isinstance(m, dict) and m.get("uid") and m.get("name"):
                                self._node_uid_to_name[str(m["uid"])] = str(m["name"])

        ga_path = self._dataset_dir / "mds" / "show-global-assignments.json"
        raw_ga = json.loads(ga_path.read_text(encoding="utf-8")) if ga_path.is_file() else {"objects": []}
        self._show_global_assignments: list[dict[str, Any]] = list(raw_ga.get("objects", []))

        # Baselines are loaded lazily per domain on first restore/reset of a dirty domain.
        self._initial_domain_data: dict[str, dict[str, Any]] = {}
        self._initial_global_assignments: list[dict[str, Any]] = copy.deepcopy(self._show_global_assignments)
        self._dirty_domains: set[str] = set()
        self._domain_generation: Counter[str] = Counter()

        self._tasks: dict[str, dict[str, Any]] = {}
        self._sid_bindings: dict[str, SidBinding] = {}
        self._work_sessions: dict[str, WorkSession] = {}
        self._published_session_by_domain: dict[str, str] = {}
        for dom_n, d_files in self._domain_data.items():
            last_pub = d_files.get("show-last-published-session", {})
            if isinstance(last_pub, dict) and last_pub.get("uid"):
                self._published_session_by_domain[dom_n] = str(last_pub["uid"])
        self._published_deltas: dict[str, list[PublishedDelta]] = {}

        self._sid_seq = 0
        self._task_seq = 0
        self._session_seq = 0
        self._uid_seq = 0
        self._ts_seq = 1794300000000

        # Call counters and call logs for test assertions
        self.api_call_counts: Counter[tuple[str, str]] = Counter()
        self.api_query_counts: Counter[tuple[str, str]] = Counter()
        self.command_counts: Counter[str] = Counter()
        self.gateway_detail_queries: list[tuple[str, str, str]] = []
        self.call_log: list[dict[str, Any]] = []

    def __repr__(self) -> str:
        return (
            f"FileReplayApiMock(dataset_dir={self._dataset_dir!s}, "
            f"domains={len(self._domain_data)}, active_sessions={sum(1 for b in self._sid_bindings.values() if b.active)})"
        )

    @property
    def dataset_dir(self) -> Path:
        """Path to the backing `enterprise_raw_dataset` fixture directory."""
        return self._dataset_dir

    @property
    def cli_mock(self) -> FileReplayCliMock:
        """Associated `FileReplayCliMock` instance."""
        return self._cli_mock

    @property
    def manifest(self) -> dict[str, Any]:
        """Loaded `manifest.json` metadata dictionary."""
        return self._manifest

    def reset_counters(self) -> None:
        """Reset all API and CLI call counters and logs."""
        self.api_call_counts.clear()
        self.api_query_counts.clear()
        self.command_counts.clear()
        self.gateway_detail_queries.clear()
        self.call_log.clear()
        self._cli_mock.reset_counters()

    # ------------------------------------------------------------------
    # State Snapshots, Reset, Session Inspection & Call-Log Assertions
    # ------------------------------------------------------------------

    def get_active_sid_binding(self, sid: str | None) -> SidBinding | None:
        """Return the active `SidBinding` for `sid`, or `None` if unknown or logged out."""
        if not sid:
            return None
        binding = self._sid_bindings.get(sid)
        if binding is None or not binding.active:
            return None
        return binding

    def _load_domain_files(self, dom_name: str) -> dict[str, Any]:
        dom_dir = self._dataset_dir / "domains" / dom_name
        dom_files: dict[str, Any] = {}
        if dom_dir.is_dir():
            for json_file in sorted(dom_dir.glob("*.json")):
                dom_files[json_file.stem] = json.loads(json_file.read_text(encoding="utf-8"))
        return dom_files

    def _get_clean_domain_baseline(self, dom_name: str) -> dict[str, Any]:
        baseline = self._initial_domain_data.get(dom_name)
        if baseline is None:
            baseline = self._load_domain_files(dom_name)
            self._initial_domain_data[dom_name] = baseline
        return baseline

    def _mark_domain_mutated(self, dom_name: str) -> None:
        self._dirty_domains.add(dom_name)
        self._domain_generation[dom_name] += 1

    def snapshot_state(self) -> ReplayStateSnapshot:
        """Capture an in-memory snapshot of modified domains, sessions, locks, tasks, and CLI overrides."""
        domain_copies = {
            dom_name: copy.deepcopy(self._domain_data[dom_name])
            for dom_name in self._dirty_domains
            if dom_name in self._domain_data
        }
        return ReplayStateSnapshot(
            domain_copies=domain_copies,
            dirty_domains=set(domain_copies.keys()),
            work_sessions=copy.deepcopy(self._work_sessions),
            sid_bindings=copy.deepcopy(self._sid_bindings),
            published_session_by_domain=dict(self._published_session_by_domain),
            published_deltas=copy.deepcopy(self._published_deltas),
            tasks=copy.deepcopy(self._tasks),
            show_global_assignments=copy.deepcopy(self._show_global_assignments),
            counters={
                "sid_seq": self._sid_seq,
                "task_seq": self._task_seq,
                "session_seq": self._session_seq,
                "uid_seq": self._uid_seq,
                "ts_seq": self._ts_seq,
            },
            cli_overrides=copy.deepcopy(self._cli_mock._cli_overrides),
            fail_ssh_nodes=set(self._cli_mock.fail_ssh_nodes),
            call_log=copy.deepcopy(self.call_log),
            domain_generations=dict(self._domain_generation),
        )

    def restore_state(self, snapshot: ReplayStateSnapshot) -> None:
        """Restore emulator state rapidly from a previously captured `ReplayStateSnapshot`."""
        for dom_name in snapshot.dirty_domains | self._dirty_domains:
            if dom_name in snapshot.domain_copies:
                self._domain_data[dom_name] = copy.deepcopy(snapshot.domain_copies[dom_name])
            elif dom_name in self._domain_data:
                self._domain_data[dom_name] = copy.deepcopy(self._get_clean_domain_baseline(dom_name))

        self._dirty_domains = set(snapshot.dirty_domains)
        self._domain_generation = Counter(snapshot.domain_generations)
        self._work_sessions = copy.deepcopy(snapshot.work_sessions)
        self._sid_bindings = copy.deepcopy(snapshot.sid_bindings)
        self._published_session_by_domain = dict(snapshot.published_session_by_domain)
        self._published_deltas = copy.deepcopy(snapshot.published_deltas)
        self._tasks = copy.deepcopy(snapshot.tasks)
        self._show_global_assignments = copy.deepcopy(snapshot.show_global_assignments)

        self._sid_seq = snapshot.counters.get("sid_seq", self._sid_seq)
        self._task_seq = snapshot.counters.get("task_seq", self._task_seq)
        self._session_seq = snapshot.counters.get("session_seq", self._session_seq)
        self._uid_seq = snapshot.counters.get("uid_seq", self._uid_seq)
        self._ts_seq = snapshot.counters.get("ts_seq", self._ts_seq)

        self._cli_mock._cli_overrides = copy.deepcopy(snapshot.cli_overrides)
        self._cli_mock.fail_ssh_nodes = set(snapshot.fail_ssh_nodes)
        self.call_log = copy.deepcopy(snapshot.call_log)
        self.api_call_counts.clear()
        self.command_counts.clear()
        self.api_query_counts.clear()
        self.gateway_detail_queries.clear()
        for entry in self.call_log:
            if not isinstance(entry, dict):
                continue
            cmd = str(entry.get("command") or "")
            dom = str(entry.get("domain") or "")
            if cmd:
                self.api_call_counts[(dom, cmd)] += 1
                self.command_counts[cmd] += 1

    def reset(self) -> None:
        """Reset all in-memory domain data, sessions, locks, tasks, counters, and CLI overrides to baseline."""
        for dom_name in list(self._dirty_domains):
            if dom_name in self._domain_data:
                self._domain_data[dom_name] = copy.deepcopy(self._get_clean_domain_baseline(dom_name))
        self._dirty_domains.clear()
        self._domain_generation.clear()
        self._show_global_assignments = copy.deepcopy(self._initial_global_assignments)
        self._work_sessions.clear()
        self._sid_bindings.clear()
        self._published_deltas.clear()
        self._tasks.clear()
        self._published_session_by_domain.clear()
        for dom_n, d_files in self._domain_data.items():
            last_pub = d_files.get("show-last-published-session", {})
            if isinstance(last_pub, dict) and last_pub.get("uid"):
                self._published_session_by_domain[dom_n] = str(last_pub["uid"])
        self._sid_seq = 0
        self._task_seq = 0
        self._session_seq = 0
        self._uid_seq = 0
        self._ts_seq = 1794300000000
        self._cli_mock._cli_overrides.clear()
        self._cli_mock.fail_ssh_nodes.clear()
        self.reset_counters()

    def get_calls(
        self,
        *,
        domain: str | None = None,
        command: str | None = None,
        mutating_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Return recorded `call_log` entries matching optional `domain`, `command`, and `mutating_only` filters."""
        norm_dom = self._normalize_domain(domain) if domain is not None else None
        out: list[dict[str, Any]] = []
        for entry in self.call_log:
            if norm_dom is not None and entry.get("domain") != norm_dom:
                continue
            if command is not None and entry.get("command") != command:
                continue
            if mutating_only and not entry.get("is_mutating", entry.get("mutating")):
                continue
            out.append(entry)
        return out

    def assert_no_global_mutations(self) -> None:
        """Fail if any mutating API command targeted the `Global` domain."""
        global_writes = [
            f"{e.get('command')} ({e.get('payload_summary')})"
            for e in self.call_log
            if e.get("domain") == "Global" and e.get("is_mutating", e.get("mutating"))
        ]
        if global_writes:
            raise AssertionError(f"Unexpected mutating commands in Global domain: {', '.join(global_writes)}")

    def assert_no_full_object_scans(
        self,
        commands: Iterable[str] = ("show-hosts", "show-networks", "show-address-ranges", "show-groups"),
    ) -> None:
        """Fail if any command in `commands` was invoked (e.g., to guard against uncached full-table scans)."""
        target_cmds = set(commands)
        hits = [f"{e.get('domain')}:{e.get('command')}" for e in self.call_log if e.get("command") in target_cmds]
        if hits:
            raise AssertionError(f"Unexpected full-object scan commands invoked: {', '.join(hits)}")

    def assert_command_called(
        self,
        command: str,
        *,
        domain: str | None = None,
        times: int | None = None,
    ) -> None:
        """Assert that `command` was called (optionally within `domain` and exact `times` count)."""
        matches = self.get_calls(domain=domain, command=command)
        if times is None:
            if not matches:
                scope = f" in domain {domain!r}" if domain else ""
                raise AssertionError(f"Expected command {command!r}{scope} to be called at least once, got 0")
        elif len(matches) != times:
            scope = f" in domain {domain!r}" if domain else ""
            raise AssertionError(f"Expected command {command!r}{scope} {times} time(s), got {len(matches)}")

    def assert_command_not_called(self, command: str, *, domain: str | None = None) -> None:
        """Assert that `command` was never called (optionally restricted to `domain`)."""
        matches = self.get_calls(domain=domain, command=command)
        if matches:
            scope = f" in domain {domain!r}" if domain else ""
            raise AssertionError(f"Expected command {command!r}{scope} not to be called, got {len(matches)}")

    # ------------------------------------------------------------------
    # Internal Session, Timestamp & Overlay Helpers
    # ------------------------------------------------------------------

    def _next_timestamp_ms(self) -> int:
        self._ts_seq += 1000
        return self._ts_seq

    def _allocate_uid(self, prefix: str) -> str:
        self._uid_seq += 1
        clean = prefix.replace("-", "_")
        return f"uid-{clean}-{self._uid_seq:06d}"

    def _known_sids(self, extra_sid: str | None = None) -> set[str]:
        sids = set(self._sid_bindings.keys())
        if extra_sid:
            sids.add(extra_sid)
        return sids

    def _create_work_session(
        self,
        domain: str,
        *,
        user_name: str = "admin",
        name: str = "",
        description: str = "",
        application: str = "WEB_API",
        read_only: bool = False,
    ) -> WorkSession:
        self._session_seq += 1
        ts_ms = self._next_timestamp_ms()
        dom_meta = format_domain_meta(domain)
        ws = WorkSession(
            uid=f"sess-{domain.lower().replace(' ', '-')}-{self._session_seq:06d}",
            domain=domain,
            user_name=user_name,
            name=name,
            description=description,
            application=application,
            read_only=read_only,
            state="open",
            base_published_uid=self._published_session_by_domain.get(domain, ""),
            created_time_posix=ts_ms,
            last_modify_posix=ts_ms,
            base_domain_gen=self._domain_generation[domain],
            domain_meta=dom_meta,
        )
        self._work_sessions[ws.uid] = ws
        return ws

    def _effective_domain_files(self, dom_name: str, binding: SidBinding | None) -> dict[str, Any] | None:
        if binding is not None and binding.active and binding.domain == dom_name:
            ws = self._work_sessions.get(binding.session_uid)
            if ws is not None and ws.state == "open" and ws.overlay_data is not None:
                return ws.overlay_data
        return self._domain_data.get(dom_name)

    def _ensure_overlay(self, ws: WorkSession) -> dict[str, Any]:
        if ws.overlay_data is None:
            published = self._domain_data.get(ws.domain, {})
            ws.base_snapshot = copy.deepcopy(published)
            ws.overlay_data = copy.deepcopy(published)
            ws.base_published_uid = self._published_session_by_domain.get(ws.domain, "")
            ws.base_domain_gen = self._domain_generation[ws.domain]
        return ws.overlay_data

    def _effective_all_domains(self, binding: SidBinding | None) -> dict[str, Mapping[str, Any]]:
        out: dict[str, Mapping[str, Any]] = {}
        for dom_n in self._domain_data:
            eff = self._effective_domain_files(dom_n, binding)
            if eff is not None:
                out[dom_n] = eff
        return out

    @staticmethod
    def _candidate_preflight_layers(
        store: Any,
        *,
        dom_files: Mapping[str, Any],
        pkg_or_lyr: str,
        rule_kind: str,
        allow_multi: bool,
    ) -> list[Mapping[str, Any]]:
        if not isinstance(store, Mapping):
            return []
        if pkg_or_lyr:
            if rule_kind == "nat":
                resolved_layer = _resolve_nat_package_payload(dict(dom_files), pkg_or_lyr)
            else:
                rb_meta = {
                    "access": ("show-access-rulebase", "show-access-layers", "access-layers"),
                    "https": ("show-https-rulebase", "show-https-layers", "https-layers"),
                    "threat": ("show-threat-rulebase", "show-threat-layers", "threat-layers"),
                }[rule_kind]
                resolved_layer = _resolve_layer_payload(
                    dict(dom_files),
                    {},
                    pkg_or_lyr,
                    store_key=rb_meta[0],
                    layer_store_key=rb_meta[1],
                    layer_list_key=rb_meta[2],
                )
            return [resolved_layer] if isinstance(resolved_layer, Mapping) else []
        layers = [v for v in store.values() if isinstance(v, Mapping)]
        if not allow_multi and len(layers) != 1:
            return []
        return layers

    def _preflight_target_uids(
        self,
        command: str,
        req: Mapping[str, Any],
        dom_files: Mapping[str, Any],
        global_files: Mapping[str, Any],
        dom_name: str,
    ) -> set[str]:
        targets: set[str] = set()
        entity_map = CMD_TO_ENTITY_ACTION.get(command)
        if entity_map is not None:
            spec, action = entity_map
            if action in ("set", "delete"):
                lookup = str(req.get("uid") or req.get("name") or "")
                found = find_effective_object(
                    dom_files, global_files, dom_name, lookup, preferred_spec=spec, include_extras=False
                )
                if found is not None and found[0].get("uid"):
                    targets.add(str(found[0]["uid"]))
            elif action == "add" and bool(req.get("set-if-exists", False)):
                name = str(req.get("name") or "").strip()
                if name:
                    found = find_effective_object(
                        dom_files,
                        global_files,
                        dom_name,
                        name,
                        preferred_spec=spec,
                        local_only=True,
                        include_extras=False,
                    )
                    if found is not None and found[0].get("uid"):
                        targets.add(str(found[0]["uid"]))
            return targets

        matched_kind = next(
            (
                k
                for k in ("access", "nat", "https", "threat")
                if command in (f"set-{k}-rule", f"delete-{k}-rule", f"set-{k}-section", f"delete-{k}-section")
            ),
            None,
        )
        if matched_kind is not None:
            is_nat = matched_kind == "nat"
            is_section = command.endswith("-section")
            rb_cmd = f"show-{matched_kind}-rulebase"
            store = dom_files.get(rb_cmd, {})
            pkg_or_lyr = str(req.get("package") if is_nat else (req.get("layer") or ""))

            if not is_section:
                uid = str(req.get("uid") or "").strip()
                if uid:
                    targets.add(uid)
                    return targets
                req_num, valid_num = parse_rule_number(req.get("rule-number"))
                if not valid_num:
                    return targets
                req_name = str(req.get("name") or "")
                candidate_layers = self._candidate_preflight_layers(
                    store,
                    dom_files=dom_files,
                    pkg_or_lyr=pkg_or_lyr,
                    rule_kind=matched_kind,
                    allow_multi=not (req_num is not None and not req_name),
                )
                for layer_data in candidate_layers:
                    idx = 0
                    for node in layer_data.get("rulebase", []):
                        if not isinstance(node, Mapping):
                            continue
                        raw_children = node.get("rulebase")
                        children: list[Any] = raw_children if isinstance(raw_children, list) else [node]
                        for child in children:
                            if not isinstance(child, Mapping):
                                continue
                            idx += 1
                            child_num, num_ok = parse_rule_number(child.get("rule-number"))
                            eff_num = child_num if (num_ok and child_num is not None) else idx
                            if (
                                (req_num is not None and eff_num == req_num)
                                or (req_name and child.get("name") == req_name)
                            ) and child.get("uid"):
                                targets.add(str(child["uid"]))
            else:
                sec_uid = str(req.get("uid") or "").strip()
                sec_name = str(req.get("name") or "").strip()
                if sec_uid:
                    targets.add(sec_uid)
                candidate_layers = self._candidate_preflight_layers(
                    store,
                    dom_files=dom_files,
                    pkg_or_lyr=pkg_or_lyr,
                    rule_kind=matched_kind,
                    allow_multi=True,
                )
                for layer_data in candidate_layers:
                    for node in layer_data.get("rulebase", []):
                        if not isinstance(node, Mapping):
                            continue
                        node_type = str(node.get("type") or "")
                        if not (node_type.endswith("-section") or isinstance(node.get("rulebase"), list)):
                            continue
                        if (sec_uid and node.get("uid") == sec_uid) or (sec_name and node.get("name") == sec_name):
                            if node.get("uid"):
                                targets.add(str(node["uid"]))
                            if command.startswith("delete-"):
                                for child in node.get("rulebase", []):
                                    if isinstance(child, Mapping) and child.get("uid"):
                                        targets.add(str(child["uid"]))
        return targets

    def _check_cross_session_locks(self, ws: WorkSession, candidate_uids: set[str]) -> ApiCallResult | None:
        if not candidate_uids:
            return None
        for other_ws in self._work_sessions.values():
            if other_ws.domain != ws.domain or other_ws.uid == ws.uid:
                continue
            if other_ws.state not in ("open", "disconnected"):
                continue
            overlap = sorted(candidate_uids & other_ws.locked_uids)
            if overlap:
                holder = other_ws.name or other_ws.uid
                return cp_error(
                    "generic_err_object_locked",
                    f"Object [{overlap[0]}] is locked by another session [{other_ws.uid}]",
                    status_code=400,
                    blocking_errors=[{"message": f"Object [{overlap[0]}] is locked by session {holder}"}],
                )
        return None

    # ------------------------------------------------------------------
    # In-Memory Mutation Helpers for Step 6 Targeted Gateway Refresh
    # ------------------------------------------------------------------

    def update_gateway_interfaces(
        self,
        domain: str,
        gateway_name_or_uid: str,
        interfaces: list[dict[str, Any]],
    ) -> None:
        """Update the raw `interfaces` list for a single gateway across summary and detail payloads in memory."""
        self._mark_domain_mutated(domain)
        dom_files = self._domain_data[domain]
        target_uid: str | None = None
        target_name: str | None = None

        for obj in dom_files.get("show-gateways-and-servers", {}).get("objects", []):
            if obj.get("uid") == gateway_name_or_uid or obj.get("name") == gateway_name_or_uid:
                target_uid = str(obj["uid"])
                target_name = str(obj["name"])
                obj["interfaces"] = copy.deepcopy(interfaces)
                break

        for detail_cmd in ("show-simple-gateway", "show-simple-cluster", "show-generic-object"):
            store = dom_files.get(detail_cmd, {})
            for key in (gateway_name_or_uid, target_uid, target_name):
                if key and key in store:
                    store[key]["interfaces"] = copy.deepcopy(interfaces)

    def update_gateway_cli_stdout(
        self,
        node_name: str,
        stdout: str,
        *,
        vsid: int = 0,
    ) -> None:
        """Update the raw CLI routing stdout for `(node_name, vsid)` in the associated `FileReplayCliMock`."""
        self._cli_mock.set_cli_stdout(node_name, vsid, stdout)

    def bump_published_session(
        self,
        domain: str,
        *,
        new_session_uid: str,
        new_iso_time: str = "2026-11-09T12:00:00Z",
        new_posix_time: int = 1794225600000,
    ) -> None:
        """Simulate a new `publish` in `domain` by updating `show-last-published-session` and `show-sessions`."""
        self._mark_domain_mutated(domain)
        self._published_session_by_domain[domain] = new_session_uid
        dom_files = self._domain_data[domain]
        new_sess = {
            "uid": new_session_uid,
            "name": f"session-{domain.lower()}-updated",
            "type": "session",
            "state": "published",
            "locks": 0,
            "published-changes": 1,
            "number-of-published-changes": 0,
            "publish-time": {"posix": new_posix_time, "iso-8601": new_iso_time},
            "last-login-was-at": {"posix": new_posix_time - 5000, "iso-8601": new_iso_time},
        }
        dom_files["show-last-published-session"] = copy.deepcopy(new_sess)
        sessions_list = dom_files.setdefault("show-sessions", {}).setdefault("objects", [])
        sessions_list.insert(0, copy.deepcopy(new_sess))
        dom_files["show-sessions"]["total"] = len(sessions_list)
        dom_files["show-sessions"]["to"] = len(sessions_list)

    # ------------------------------------------------------------------
    # Internal Command Dispatch
    # ------------------------------------------------------------------

    def _normalize_domain(self, domain: str | None) -> str:
        if not domain or not domain.strip() or domain.strip() == "System Data":
            return "System Data"
        clean = domain.strip()
        if clean in self._domain_data:
            return clean
        # Check by domain UID or case-insensitive name
        for d_obj in self._show_domains.get("objects", []):
            if d_obj.get("uid") == clean or str(d_obj.get("name", "")).lower() == clean.lower():
                return str(d_obj["name"])
        if clean.lower() == "global" or self._show_global_domain.get("uid") == clean:
            return "Global"
        return clean

    @staticmethod
    def _paginate_list(
        items: list[dict[str, Any]],
        payload: dict[str, Any],
        *,
        collection_key: str = "objects",
    ) -> dict[str, Any]:
        details_level = str(payload.get("details-level") or "standard")
        limit = int(payload.get("limit", DEFAULT_PAGE_LIMIT))
        offset = int(payload.get("offset", 0))
        total = len(items)
        sliced = items[offset : offset + limit]
        projected = [_project_details_level(item, details_level) for item in sliced]
        from_val = (offset + 1) if projected else 0
        to_val = (offset + len(projected)) if projected else 0
        return {
            collection_key: projected,
            "from": from_val,
            "to": to_val,
            "total": total,
        }

    def _handle_run_script(
        self,
        dom_name: str,
        payload: dict[str, Any],
        *,
        wait_for_task: bool,
    ) -> ApiCallResult:
        targets = payload.get("targets") or []
        if isinstance(targets, str):
            targets = [targets]
        target_ref = str(targets[0]) if targets else "unknown-target"
        node_name = self._node_uid_to_name.get(target_ref, target_ref)
        script = str(payload.get("script") or "")

        vsid = 0
        m_vsid = _VSID_SCRIPT_RE.search(script)
        m_vs_name = _VS_NAME_SCRIPT_RE.search(script)
        prepend_resolved = False
        script_error: str | None = None
        if m_vsid is not None:
            vsid = int(m_vsid.group(1))
            if 'vsenv "$vsid"' not in script or "CTX%05d" not in script:
                script_error = f"_vs_error=vsenv_{vsid}_missing_guard"
        elif m_vs_name is not None:
            vs_name_val = m_vs_name.group(1)
            if "vsx stat -l" not in script or 'vsenv "$vsid"' not in script or "CTX%05d" not in script:
                script_error = f"_vs_error=vsx_stat_missing_guard:{vs_name_val}"
            else:
                resolved = self._cli_mock.resolve_vsid_from_stat(node_name, vs_name_val)
                if resolved is None:
                    script_error = f"_vs_error=vs_not_found:{vs_name_val}"
                else:
                    vsid = resolved
                    prepend_resolved = True

        self._task_seq += 1
        task_id = f"12345678-8888-4888-8888-{self._task_seq:012d}"

        if script_error is not None:
            b64_err = base64.b64encode((script_error + "\n").encode("utf-8")).decode("ascii")
            task_obj = {
                "uid": task_id,
                "task-id": task_id,
                "task-name": str(payload.get("script-name") or f"arodonata-route-collect-{node_name}"),
                "status": "failed",
                "progress-percentage": 100,
                "suppressed": False,
                "task-details": [
                    {
                        "uid": f"td-{task_id}",
                        "gatewayId": target_ref,
                        "gatewayName": node_name,
                        "statusCode": "failed",
                        "statusDescription": "Failed",
                        "responseMessage": b64_err,
                        "responseError": b64_err,
                    }
                ],
            }
            self._tasks[task_id] = task_obj
            if wait_for_task:
                return ApiCallResult(
                    success=False,
                    status_code=200,
                    error_code="generic_err_task_failed",
                    error_message=script_error,
                    data={"tasks": [copy.deepcopy(task_obj)]},
                )
            return ApiCallResult(
                success=True,
                status_code=200,
                data={"tasks": [{"target": target_ref, "task-id": task_id}]},
            )

        # Load pre-generated task file if present and not overridden in memory
        task_file = self._dataset_dir / "tasks" / f"{node_name}__vs_{vsid}.json"
        if not task_file.is_file() and vsid == 0:
            alt_task_file = self._dataset_dir / "tasks" / f"{node_name}__vs_none.json"
            if alt_task_file.is_file():
                task_file = alt_task_file
        override_stdout = self._cli_mock.get_raw_cli_stdout(node_name, vsid)

        if task_file.is_file() and (node_name, vsid) not in self._cli_mock._cli_overrides and not prepend_resolved:
            task_payload = json.loads(task_file.read_text(encoding="utf-8"))
            tasks_list = task_payload.get("tasks", [])
            if tasks_list:
                task_obj = copy.deepcopy(tasks_list[0])
                task_obj["task-id"] = task_id
            else:
                task_obj = {"task-id": task_id, "status": "succeeded", "task-details": []}
        else:
            stdout_str = override_stdout or ""
            if prepend_resolved and stdout_str and f"===ARODONATA_VSID_RESOLVED={vsid}===" not in stdout_str:
                stdout_str = f"===ARODONATA_VSID_RESOLVED={vsid}===\n{stdout_str}"
            b64_msg = base64.b64encode(stdout_str.encode("utf-8")).decode("ascii")
            task_obj = {
                "uid": task_id,
                "task-id": task_id,
                "task-name": str(payload.get("script-name") or f"arodonata-route-collect-{node_name}"),
                "status": "succeeded" if stdout_str else "failed",
                "progress-percentage": 100,
                "suppressed": False,
                "task-details": [
                    {
                        "uid": f"td-{task_id}",
                        "gatewayId": target_ref,
                        "gatewayName": node_name,
                        "statusCode": "succeeded" if stdout_str else "failed",
                        "statusDescription": "Succeeded" if stdout_str else "Failed",
                        "responseMessage": b64_msg,
                        "responseError": "",
                    }
                ],
            }

        self._tasks[task_id] = task_obj

        if wait_for_task:
            # Also record the show-task poll so tests can verify run-script + show-task interaction
            self.api_call_counts[(dom_name, "show-task")] += 1
            self.command_counts["show-task"] += 1
            show_task_payload = {"task-id": task_id, "details-level": "full"}
            self.call_log.append(
                {
                    "mgmt_name": "mds",
                    "domain": dom_name,
                    "command": "show-task",
                    "payload": show_task_payload,
                    "payload_summary": summarize_payload("show-task", show_task_payload),
                    "sid_ref": None,
                    "session_uid": None,
                    "mutating": False,
                    "success": True,
                    "error_code": None,
                }
            )
            return ApiCallResult(
                success=True,
                status_code=200,
                data={"tasks": [copy.deepcopy(task_obj)]},
            )

        return ApiCallResult(
            success=True,
            status_code=200,
            data={
                "tasks": [
                    {
                        "target": target_ref,
                        "task-id": task_id,
                        "task-name": task_obj.get("task-name", "run-script"),
                    }
                ]
            },
        )

    # ------------------------------------------------------------------
    # ApiPort Implementation & Stateful Dispatch
    # ------------------------------------------------------------------

    def _next_task_id(self) -> str:
        self._task_seq += 1
        return f"12345678-9999-4999-8999-{self._task_seq:012d}"

    def _apply_domain_mutation(
        self,
        clean_cmd: str,
        req: Mapping[str, Any],
        *,
        dom_name: str,
        target_files: dict[str, Any],
        global_files: Mapping[str, Any],
        all_domains: Mapping[str, Mapping[str, Any]],
        user_name: str,
        locked_uids_out: set[str],
        override_now_ms: int | None = None,
    ) -> tuple[ApiCallResult, str | None] | None:
        now_ms = override_now_ms if override_now_ms is not None else self._next_timestamp_ms()
        entity_hit = handle_entity_crud(
            clean_cmd,
            req,
            dom_name=dom_name,
            dom_files=target_files,
            global_files=global_files,
            all_domains_effective=all_domains,
            uid_allocator=self._allocate_uid,
            now_ms=now_ms,
            user_name=user_name,
            locked_uids_out=locked_uids_out,
        )
        if entity_hit is not None:
            return entity_hit

        rb_hit = handle_rulebase_crud(
            clean_cmd,
            req,
            dom_name=dom_name,
            dom_files=target_files,
            global_files=global_files,
            uid_allocator=self._allocate_uid,
            now_ms=now_ms,
            user_name=user_name,
            locked_uids_out=locked_uids_out,
        )
        if rb_hit is not None:
            return rb_hit

        if clean_cmd == "delete-unused-objects":
            removed = delete_unused_objects(
                target_files,
                dom_name=dom_name,
                all_domains_effective=all_domains,
                locked_uids_out=locked_uids_out,
            )
            return cp_ok({"deleted-count": removed, "message": f"Deleted {removed} unused objects"}), None

        return None

    def _handle_global_assignments_cmd(
        self,
        clean_cmd: str,
        req: Mapping[str, Any],
        *,
        binding: SidBinding | None,
        dom_name: str,
        wait_for_task: bool,
    ) -> ApiCallResult:
        if clean_cmd == "show-global-assignments":
            return cp_ok(paginate_items(self._show_global_assignments, req, collection_key="objects"))

        def _domain_ref_matches(val: Any, target: str) -> bool:
            if not target:
                return True
            if isinstance(val, Mapping):
                return target in (str(val.get("name") or ""), str(val.get("uid") or ""))
            return str(val or "") == target

        if clean_cmd == "show-global-assignment":
            lookup_uid = str(req.get("uid") or "").strip()
            dep_dom = str(req.get("dependent-domain") or "").strip()
            glob_dom = str(req.get("global-domain") or "").strip()
            for entry in self._show_global_assignments:
                if lookup_uid and entry.get("uid") == lookup_uid:
                    return cp_ok(copy.deepcopy(entry))
                if (
                    dep_dom
                    and _domain_ref_matches(entry.get("dependent-domain"), dep_dom)
                    and _domain_ref_matches(entry.get("global-domain"), glob_dom)
                ):
                    return cp_ok(copy.deepcopy(entry))
            return cp_error(
                "generic_err_object_not_found",
                f"Global assignment [{lookup_uid or dep_dom}] not found",
                status_code=404,
            )

        if clean_cmd in ("assign-global-assignment", "assign-global-policy"):
            if binding is not None and self._work_sessions[binding.session_uid].read_only:
                return cp_error("err_validation_failed", "Cannot modify database in read-only session", status_code=400)
            if binding is not None and binding.domain not in ("System Data", "Global") and dom_name == "Global":
                return cp_error(
                    "generic_err_object_read_only",
                    f"Cannot assign Global policy from local domain [{binding.domain}]",
                    status_code=400,
                )

            raw_globs = req.get("global-domains") or req.get("global-domain") or ["Global"]
            global_list = [str(g) for g in (raw_globs if isinstance(raw_globs, list) else [raw_globs])]
            raw_deps = req.get("dependent-domains") or req.get("dependent-domain")
            if raw_deps is None:
                dep_list = [d for d in USER_DOMAINS if d in self._domain_data]
            else:
                dep_list = [str(d) for d in (raw_deps if isinstance(raw_deps, list) else [raw_deps])]

            for dep in dep_list:
                if dep not in self._domain_data or dep in ("Global", "System Data"):
                    return cp_error(
                        "generic_err_object_not_found",
                        f"Dependent domain [{dep}] not found",
                        status_code=404,
                    )

            ts_ms = self._next_timestamp_ms()
            ts_obj = format_timestamp(ts_ms)
            details: list[dict[str, Any]] = []
            for dep in dep_list:
                for g_dom in global_list:
                    matched_entry: dict[str, Any] | None = None
                    for entry in self._show_global_assignments:
                        if _domain_ref_matches(entry.get("dependent-domain"), dep) and _domain_ref_matches(
                            entry.get("global-domain"), g_dom
                        ):
                            matched_entry = entry
                            break
                    if matched_entry is None:
                        matched_entry = {
                            "uid": self._allocate_uid("ga"),
                            "type": "global-assignment",
                            "global-domain": format_domain_meta(g_dom),
                            "dependent-domain": format_domain_meta(dep),
                            "global-access-policy": str(req.get("global-access-policy") or "Global_Standard_Pkg"),
                            "global-threat-prevention-policy": str(req.get("global-threat-prevention-policy") or ""),
                        }
                        self._show_global_assignments.append(matched_entry)
                    matched_entry["assignment-status"] = "assigned"
                    matched_entry["assignment-up-to-date"] = dict(ts_obj)
                    matched_entry["last-modify-time"] = dict(ts_obj)

                # Update dependent domain package metadata so downstream readers observe assignment
                self._mark_domain_mutated(dep)
                for pkg in self._domain_data[dep].get("show-packages", {}).get("packages", []):
                    if isinstance(pkg, dict):
                        pkg["global-policy-assigned-at"] = dict(ts_obj)
                        pkg["global-domains"] = list(global_list)

                details.append(
                    {
                        "uid": self._allocate_uid("td"),
                        "domainName": dep,
                        "statusCode": "succeeded",
                        "statusDescription": f"Global policy assigned to {dep}",
                    }
                )

            tid = self._next_task_id()
            t_obj = {
                "uid": tid,
                "task-id": tid,
                "task-name": "Assign Global Policy",
                "status": "succeeded",
                "progress-percentage": 100,
                "suppressed": False,
                "task-details": details,
            }
            self._tasks[tid] = t_obj
            if wait_for_task:
                return cp_ok({"tasks": [copy.deepcopy(t_obj)]}, task_id=tid)
            return cp_ok({"task-id": tid}, task_id=tid)

        return cp_error("generic_err_command_not_recognized", f"Unsupported command {clean_cmd!r}")

    def _resolve_session_by_uid(self, uid: str, dom_name: str) -> dict[str, Any] | None:
        ws = self._work_sessions.get(uid)
        if ws is not None:
            return ws.to_checkpoint_dict()
        search_domains = [dom_name] if dom_name in self._domain_data else list(self._domain_data.keys())
        for d_name in search_domains:
            d_files = self._domain_data[d_name]
            for s in d_files.get("show-sessions", {}).get("objects", []):
                if isinstance(s, dict) and s.get("uid") == uid:
                    return copy.deepcopy(s)
            last_pub = d_files.get("show-last-published-session", {})
            if isinstance(last_pub, dict) and last_pub.get("uid") == uid:
                return copy.deepcopy(last_pub)
        return None

    def _handle_show_changes(
        self,
        dom_name: str,
        req: Mapping[str, Any],
        *,
        binding: SidBinding | None,
        wait_for_task: bool,
    ) -> ApiCallResult:
        to_uid = str(req.get("to-session") or "").strip()
        from_uid = str(req.get("from-session") or "").strip()
        from_ms = parse_checkpoint_date_ms(req.get("from-date"))
        to_ms = parse_checkpoint_date_ms(req.get("to-date"))
        global_dom = self._effective_domain_files("Global", binding)

        change_entries: list[dict[str, Any]] = []
        if to_uid and to_uid in self._work_sessions and self._work_sessions[to_uid].state in ("open", "disconnected"):
            ws = self._work_sessions[to_uid]
            before_dom = self._domain_data.get(ws.domain, {})
            after_dom = ws.overlay_data if ws.overlay_data is not None else before_dom
            delta = compute_session_delta(
                before_dom,
                after_dom,
                global_before=self._domain_data.get("Global", {}),
                global_after=global_dom,
                session_meta=ws.to_checkpoint_dict(),
            )
            if count_delta_items(delta) > 0:
                change_entries.append(delta)
        elif to_uid:
            matched_deltas = [d for d in self._published_deltas.get(dom_name, []) if d.session_uid == to_uid]
            if matched_deltas:
                change_entries.extend(copy.deepcopy(d.changes) for d in matched_deltas)
            else:
                sess_meta = self._resolve_session_by_uid(to_uid, dom_name)
                if sess_meta is None:
                    return cp_error(
                        "generic_err_object_not_found",
                        f"Session [{to_uid}] not found in {dom_name}",
                        status_code=404,
                    )
        else:
            pub_list = self._published_deltas.get(dom_name, [])
            in_range = not bool(from_uid)
            for p_delta in pub_list:
                if from_uid and p_delta.session_uid == from_uid:
                    in_range = True
                    continue
                if not in_range:
                    continue
                if from_ms is not None and p_delta.publish_time_posix < from_ms:
                    continue
                if to_ms is not None and p_delta.publish_time_posix > to_ms:
                    continue
                change_entries.append(copy.deepcopy(p_delta.changes))

        tid = self._next_task_id()
        task_obj = build_show_changes_task(tid, change_entries)
        self._tasks[tid] = task_obj
        if wait_for_task:
            return cp_ok({"tasks": [copy.deepcopy(task_obj)]}, task_id=tid)
        return cp_ok({"task-id": tid}, task_id=tid)

    def _rotate_sid_bindings_for_session(self, ws: WorkSession) -> None:
        """Rebind active SIDs attached to `ws.uid` onto fresh open sessions (`OwnedSession` invariant)."""
        for act_binding in self._sid_bindings.values():
            if act_binding.active and act_binding.session_uid == ws.uid:
                fresh_ws = self._create_work_session(
                    ws.domain,
                    user_name=act_binding.user_name,
                    name="",
                    description="",
                    application=ws.application,
                    read_only=act_binding.read_only,
                )
                act_binding.session_uid = fresh_ws.uid

    def _record_publish_task(
        self,
        session_uid: str | None,
        n_changes: int,
        *,
        wait_for_task: bool,
    ) -> ApiCallResult:
        tid = self._next_task_id()
        detail: dict[str, Any] = {
            "uid": f"td-{tid}",
            "statusDescription": "Publish completed successfully",
        }
        if session_uid:
            detail["revision"] = session_uid
            detail["publishResponse"] = {
                "uid": session_uid,
                "mode": "async",
                "number-of-published-changes": n_changes,
            }
            detail["publish-Response"] = {
                "uid": session_uid,
                "number-of-published-changes": n_changes,
            }
        t_obj: dict[str, Any] = {
            "uid": tid,
            "task-id": tid,
            "task-name": "Publish operation",
            "status": "succeeded",
            "progress-percentage": 100,
            "suppressed": False,
            "task-details": [detail],
        }
        self._tasks[tid] = t_obj
        if wait_for_task:
            payload: dict[str, Any] = {"tasks": [copy.deepcopy(t_obj)]}
            if session_uid:
                payload["uid"] = session_uid
            return cp_ok(payload, task_id=tid)
        return cp_ok({"task-id": tid}, task_id=tid)

    def _handle_publish(
        self,
        req: Mapping[str, Any],
        *,
        binding: SidBinding | None,
        wait_for_task: bool,
    ) -> ApiCallResult:
        req_uid = str(req.get("uid") or "").strip()
        ws: WorkSession | None = None
        if req_uid:
            ws = self._work_sessions.get(req_uid)
            if ws is None:
                return cp_error("generic_err_object_not_found", f"Session [{req_uid}] not found", status_code=404)
            if binding is not None:
                if binding.read_only:
                    return cp_error("err_validation_failed", "Cannot publish from a read-only session", status_code=400)
                if binding.domain not in ("System Data", ws.domain):
                    return cp_error(
                        "err_validation_failed",
                        f"Session bound to domain [{binding.domain}] cannot publish session in [{ws.domain}]",
                        status_code=400,
                    )
        elif binding is not None:
            ws = self._work_sessions.get(binding.session_uid)

        if ws is None:
            return self._record_publish_task(None, 0, wait_for_task=wait_for_task)

        if ws.read_only:
            return cp_error("err_validation_failed", "Cannot publish from a read-only session", status_code=400)
        if ws.state in ("published", "discarded"):
            return cp_error("err_validation_failed", f"Session [{ws.uid}] is already {ws.state}", status_code=400)

        target_dom = ws.domain
        if target_dom not in self._domain_data:
            pub_ts = self._next_timestamp_ms()
            ws.state = "published"
            ws.published_time_posix = pub_ts
            ws.last_modify_posix = pub_ts
            ws.published_changes = 0
            ws.changes_count = 0
            ws.locked_uids.clear()
            ws.overlay_data = None
            ws.base_snapshot = None
            self._rotate_sid_bindings_for_session(ws)
            return self._record_publish_task(ws.uid, 0, wait_for_task=wait_for_task)

        before_dom = copy.deepcopy(self._domain_data[target_dom])
        current_pub_uid = self._published_session_by_domain.get(target_dom, "")

        if ws.overlay_data is not None:
            if ws.base_published_uid == current_pub_uid and ws.base_domain_gen == self._domain_generation[target_dom]:
                candidate_after = copy.deepcopy(ws.overlay_data)
            else:
                candidate_after = copy.deepcopy(before_dom)
                global_files = self._domain_data.get("Global", {})
                for rec in ws.mutation_records:
                    outcome = self._apply_domain_mutation(
                        rec.command,
                        rec.payload,
                        dom_name=rec.domain,
                        target_files=candidate_after,
                        global_files=global_files,
                        all_domains=self._domain_data,
                        user_name=ws.user_name,
                        locked_uids_out=set(),
                    )
                    if outcome is not None and not outcome[0].success:
                        return outcome[0]
        else:
            candidate_after = copy.deepcopy(before_dom)

        pub_ts = self._next_timestamp_ms()
        ws.state = "published"
        ws.published_time_posix = pub_ts
        ws.last_modify_posix = pub_ts

        delta = compute_session_delta(
            before_dom,
            candidate_after,
            global_before=before_dom if target_dom == "Global" else self._domain_data.get("Global", {}),
            global_after=candidate_after if target_dom == "Global" else self._domain_data.get("Global", {}),
            session_meta=ws.to_checkpoint_dict(),
        )
        n_changes = count_delta_items(delta)
        ws.published_changes = n_changes
        ws.changes_count = 0
        ws.locked_uids.clear()
        ws.overlay_data = None
        ws.base_snapshot = None

        self._domain_data[target_dom] = candidate_after
        self._mark_domain_mutated(target_dom)
        self._published_session_by_domain[target_dom] = ws.uid

        pub_dict = ws.to_checkpoint_dict()
        pub_dict["published-changes"] = n_changes
        pub_dict["number-of-published-changes"] = n_changes
        delta["session"] = copy.deepcopy(pub_dict)

        dom_files = self._domain_data[target_dom]
        dom_files["show-last-published-session"] = copy.deepcopy(pub_dict)
        sessions_list = dom_files.setdefault("show-sessions", {}).setdefault("objects", [])
        sessions_list.insert(0, copy.deepcopy(pub_dict))
        dom_files["show-sessions"]["total"] = len(sessions_list)
        dom_files["show-sessions"]["to"] = len(sessions_list)
        dom_files["show-sessions"]["from"] = 1 if sessions_list else 0

        self._published_deltas.setdefault(target_dom, []).append(
            PublishedDelta(
                session_uid=ws.uid,
                session_name=ws.name,
                domain=target_dom,
                user_name=ws.user_name,
                publish_time_posix=pub_ts,
                publish_time_iso=pub_dict["publish-time"]["iso-8601"],
                changes=delta,
            )
        )

        self._rotate_sid_bindings_for_session(ws)
        return self._record_publish_task(ws.uid, n_changes, wait_for_task=wait_for_task)

    def _dispatch_api_call(
        self,
        mgmt_name: str,
        clean_cmd: str,
        req: dict[str, Any],
        *,
        dom_name: str,
        sid: str | None,
        binding: SidBinding | None,
        wait_for_task: bool,
    ) -> ApiCallResult:
        # 1. Login lifecycle
        if clean_cmd == "login":
            login_dom = self._normalize_domain(req.get("domain") or dom_name)
            if login_dom != "System Data" and login_dom not in self._domain_data:
                return cp_error(
                    "generic_err_object_not_found",
                    f"Domain [{login_dom}] not found in dataset",
                    status_code=404,
                )
            self._sid_seq += 1
            new_sid = f"mock-sid-{login_dom}-{self._sid_seq}"
            sid_ref = f"sid#{self._sid_seq:04d}"
            user_name = str(req.get("user") or "admin")
            read_only = bool(req.get("read-only", False))
            sess_name = str(req.get("session-name") or "")
            sess_desc = str(req.get("session-description") or "")
            app_name = str(req.get("application") or "WEB_API")

            ws: WorkSession | None = None
            if bool(req.get("continue-last-session", False)) and not read_only:
                for cand_ws in reversed(list(self._work_sessions.values())):
                    if (
                        cand_ws.domain == login_dom
                        and cand_ws.user_name == user_name
                        and cand_ws.state == "disconnected"
                        and not cand_ws.read_only
                    ):
                        cand_ws.state = "open"
                        cand_ws.last_modify_posix = self._next_timestamp_ms()
                        ws = cand_ws
                        break
            if ws is None:
                ws = self._create_work_session(
                    login_dom,
                    user_name=user_name,
                    name=sess_name,
                    description=sess_desc,
                    application=app_name,
                    read_only=read_only,
                )

            self._sid_bindings[new_sid] = SidBinding(
                sid=new_sid,
                sid_ref=sid_ref,
                mgmt_name=mgmt_name,
                domain=login_dom,
                user_name=user_name,
                session_uid=ws.uid,
                read_only=ws.read_only,
                active=True,
            )
            return cp_ok(
                {
                    "sid": new_sid,
                    "uid": ws.uid,
                    "session-timeout": 600,
                    "api-server-version": "1.9.1",
                    "disk-space-message": "OK",
                    "read-only": ws.read_only,
                }
            )

        # Validate active SID when provided
        active_ws: WorkSession | None = None
        if sid is not None:
            if binding is None or not binding.active:
                return cp_error("generic_err_invalid_session_id", "Session ID is invalid or expired", status_code=401)
            active_ws = self._work_sessions.get(binding.session_uid)
            if active_ws is None:
                return cp_error(
                    "generic_err_invalid_session_id",
                    "Attached work session is invalid or expired",
                    status_code=401,
                )

        if clean_cmd == "logout":
            if binding is not None:
                binding.active = False
            if active_ws is not None and active_ws.state == "open":
                has_uncommitted = bool(
                    active_ws.changes_count > 0 or active_ws.locked_uids or active_ws.mutation_records
                )
                if has_uncommitted or bool(req.get("continue-session-in-smartconsole", False)):
                    active_ws.state = "disconnected"
                else:
                    active_ws.overlay_data = None
                    active_ws.base_snapshot = None
                    active_ws.locked_uids.clear()
                    active_ws.mutation_records.clear()
                    active_ws.changes_count = 0
                    active_ws.state = "discarded"
            return cp_ok({"message": "OK"})

        if clean_cmd in ("disconnect", "continue-session-in-smartconsole"):
            target_uid = str(req.get("uid") or "").strip()
            if target_uid:
                target_ws = self._work_sessions.get(target_uid)
                if target_ws is None:
                    return cp_error(
                        "generic_err_object_not_found", f"Session [{target_uid}] not found", status_code=404
                    )
                if binding is not None and binding.domain not in ("System Data", target_ws.domain):
                    return cp_error(
                        "err_validation_failed",
                        f"Session bound to domain [{binding.domain}] cannot disconnect session in [{target_ws.domain}]",
                        status_code=400,
                    )
            else:
                target_ws = active_ws

            if target_ws is not None:
                for b in self._sid_bindings.values():
                    if b.session_uid == target_ws.uid and b.active:
                        b.active = False
                if target_ws.state == "open":
                    target_ws.state = "disconnected"
                    target_ws.last_modify_posix = self._next_timestamp_ms()
                return cp_ok(target_ws.to_checkpoint_dict())
            if binding is not None:
                binding.active = False
            return cp_ok({"message": "OK"})

        if clean_cmd == "keepalive":
            return cp_ok({"message": "OK"})

        if clean_cmd == "set-session":
            if active_ws is None:
                return cp_error("generic_err_wrong_session_id", "Active session is required", status_code=400)
            if active_ws.read_only:
                return cp_error("err_validation_failed", "Cannot modify a read-only session", status_code=400)
            if req.get("new-name") is not None:
                active_ws.name = str(req["new-name"])
            elif req.get("name") is not None:
                active_ws.name = str(req["name"])
            if req.get("description") is not None:
                active_ws.description = str(req["description"])
            if req.get("comments") is not None:
                active_ws.comments = str(req["comments"])
            if req.get("color") is not None:
                active_ws.color = str(req["color"])
            if req.get("tags") is not None:
                raw_tags = req["tags"]
                active_ws.tags = list(raw_tags) if isinstance(raw_tags, list) else [raw_tags]
            active_ws.last_modify_posix = self._next_timestamp_ms()
            return cp_ok(active_ws.to_checkpoint_dict())

        if clean_cmd == "take-over-session":
            if binding is None or active_ws is None:
                return cp_error("generic_err_wrong_session_id", "Active session is required", status_code=400)
            if binding.read_only:
                return cp_error(
                    "err_validation_failed", "Cannot take over a session from a read-only session", status_code=400
                )
            target_uid = str(req.get("uid") or "").strip()
            target_ws = self._work_sessions.get(target_uid)
            if target_ws is None:
                return cp_error("generic_err_object_not_found", f"Session [{target_uid}] not found", status_code=404)
            if binding.domain not in ("System Data", target_ws.domain):
                return cp_error(
                    "err_validation_failed",
                    f"Session bound to domain [{binding.domain}] cannot take over session in [{target_ws.domain}]",
                    status_code=400,
                )
            if target_ws.read_only:
                return cp_error("err_validation_failed", "Cannot take over a read-only session", status_code=400)
            if target_ws.state in ("published", "discarded"):
                return cp_error(
                    "err_validation_failed",
                    f"Cannot take over session [{target_uid}] in state {target_ws.state!r}",
                    status_code=400,
                )
            disconnect_active = bool(req.get("disconnect-active-session", False))
            other_active = [
                other_b
                for other_b in self._sid_bindings.values()
                if other_b.sid != binding.sid and other_b.session_uid == target_ws.uid and other_b.active
            ]
            if other_active:
                if disconnect_active:
                    for other_b in other_active:
                        other_b.active = False
                elif target_ws.application != "WEB_API" or target_ws.user_name != binding.user_name:
                    return cp_error(
                        "err_validation_failed",
                        (
                            f"Session [{target_uid}] is currently active; "
                            "pass disconnect-active-session=true to take over"
                        ),
                        status_code=400,
                    )
                else:
                    for other_b in other_active:
                        fresh_other_ws = self._create_work_session(
                            other_b.domain,
                            user_name=other_b.user_name,
                            name="",
                            description="",
                            application="WEB_API",
                            read_only=other_b.read_only,
                        )
                        other_b.session_uid = fresh_other_ws.uid
            if active_ws.uid != target_ws.uid:
                active_ws.state = "disconnected"
            target_ws.state = "open"
            target_ws.last_modify_posix = self._next_timestamp_ms()
            binding.session_uid = target_ws.uid
            binding.domain = target_ws.domain
            return cp_ok(target_ws.to_checkpoint_dict())

        if clean_cmd == "switch-session":
            if binding is None or active_ws is None:
                return cp_error("generic_err_wrong_session_id", "Active session is required", status_code=400)
            target_uid = str(req.get("uid") or "").strip()
            target_ws = self._work_sessions.get(target_uid)
            if target_ws is None:
                return cp_error("generic_err_object_not_found", f"Session [{target_uid}] not found", status_code=404)
            if binding.domain not in ("System Data", target_ws.domain):
                return cp_error(
                    "err_validation_failed",
                    f"Session bound to domain [{binding.domain}] cannot switch to session in [{target_ws.domain}]",
                    status_code=400,
                )
            if target_ws.state not in ("open", "disconnected"):
                return cp_error(
                    "err_validation_failed",
                    f"Cannot switch to session [{target_uid}] in state {target_ws.state!r}",
                    status_code=400,
                )
            if active_ws.uid != target_ws.uid:
                active_ws.state = "disconnected"
            target_ws.state = "open"
            target_ws.last_modify_posix = self._next_timestamp_ms()
            binding.session_uid = target_ws.uid
            binding.domain = target_ws.domain
            return cp_ok(target_ws.to_checkpoint_dict())

        if clean_cmd == "discard":
            if active_ws is not None and active_ws.read_only:
                return cp_error("err_validation_failed", "Cannot discard from a read-only session", status_code=400)
            target_uid = str(req.get("uid") or "").strip()
            if target_uid:
                target_ws = self._work_sessions.get(target_uid)
                if target_ws is None:
                    return cp_error(
                        "generic_err_object_not_found", f"Session [{target_uid}] not found", status_code=404
                    )
                if binding is not None and binding.domain not in ("System Data", target_ws.domain):
                    return cp_error(
                        "err_validation_failed",
                        f"Session bound to domain [{binding.domain}] cannot discard session in [{target_ws.domain}]",
                        status_code=400,
                    )
                if target_ws.state in ("published", "discarded"):
                    return cp_error(
                        "err_validation_failed",
                        f"Session [{target_uid}] is already {target_ws.state}",
                        status_code=400,
                    )
            elif active_ws is not None:
                target_ws = active_ws
            else:
                return cp_ok({"message": "OK"})

            discarded_changes = target_ws.changes_count
            target_ws.overlay_data = None
            target_ws.base_snapshot = None
            target_ws.locked_uids.clear()
            target_ws.mutation_records.clear()
            target_ws.changes_count = 0
            target_ws.state = "discarded"
            target_ws.last_modify_posix = self._next_timestamp_ms()

            if binding is not None and active_ws is not None and target_ws.uid == active_ws.uid:
                fresh_ws = self._create_work_session(
                    active_ws.domain,
                    user_name=active_ws.user_name,
                    name="",
                    description="",
                    application=active_ws.application,
                    read_only=active_ws.read_only,
                )
                binding.session_uid = fresh_ws.uid
            return cp_ok({"message": "OK", "number-of-discarded-changes": discarded_changes})

        if clean_cmd == "publish":
            return self._handle_publish(req, binding=binding, wait_for_task=wait_for_task)

        if clean_cmd == "show-api-versions":
            return cp_ok({"current-version": "1.9.1", "supported-versions": ["1.8", "1.9", "1.9.1"]})

        # 2. MDS domain & global assignment commands
        if clean_cmd == "show-domains":
            items = self._show_domains.get("objects", [])
            return cp_ok(self._paginate_list(items, req, collection_key="objects"))

        if clean_cmd == "show-global-domain":
            return cp_ok(copy.deepcopy(self._show_global_domain))

        if clean_cmd in (
            "show-global-assignments",
            "show-global-assignment",
            "assign-global-assignment",
            "assign-global-policy",
        ):
            return self._handle_global_assignments_cmd(
                clean_cmd, req, binding=binding, dom_name=dom_name, wait_for_task=wait_for_task
            )

        if clean_cmd == "show-domain":
            lookup = str(req.get("name") or req.get("uid") or dom_name)
            if lookup.lower() == "global" or lookup == self._show_global_domain.get("uid"):
                return cp_ok(copy.deepcopy(self._show_global_domain))
            for d_obj in self._show_domains.get("objects", []):
                if d_obj.get("name") == lookup or d_obj.get("uid") == lookup:
                    return cp_ok(copy.deepcopy(d_obj))
            return cp_error("generic_err_object_not_found", f"Requested domain [{lookup}] not found", status_code=404)

        if clean_cmd == "show-mdss":
            items = self._show_mdss.get("objects", [])
            return cp_ok(self._paginate_list(items, req, collection_key="objects"))

        # 3. Task polling & cprid `run-script`
        if clean_cmd == "run-script":
            return self._handle_run_script(dom_name, req, wait_for_task=wait_for_task)

        if clean_cmd == "show-task":
            raw_tid = req.get("task-id")
            tids = [raw_tid] if isinstance(raw_tid, str) else (list(raw_tid) if isinstance(raw_tid, list) else [])
            found_tasks: list[dict[str, Any]] = []
            for tid in tids:
                if str(tid) in self._tasks:
                    found_tasks.append(copy.deepcopy(self._tasks[str(tid)]))
            if not found_tasks:
                return cp_error("generic_err_object_not_found", f"Requested task {tids} not found", status_code=404)
            return cp_ok({"tasks": found_tasks})

        # Cross-domain session inspection commands
        if clean_cmd == "show-session":
            req_uid = str(req.get("uid") or "").strip()
            if req_uid:
                resolved = self._resolve_session_by_uid(req_uid, dom_name)
                if resolved is None:
                    return cp_error(
                        "generic_err_object_not_found",
                        f"Session [{req_uid}] not found",
                        status_code=404,
                    )
                return cp_ok(resolved)
            if active_ws is not None:
                return cp_ok(active_ws.to_checkpoint_dict())
            if dom_name == "System Data":
                return cp_ok(
                    {
                        "uid": "sess-system-data-0001",
                        "name": "system-session",
                        "type": "session",
                        "state": "published",
                        "locks": 0,
                        "published-changes": 0,
                        "number-of-published-changes": 0,
                        "publish-time": {"posix": 1794139200000, "iso-8601": "2026-11-08T12:00:00Z"},
                    }
                )

        if clean_cmd == "show-sessions":
            if req.get("view-published-sessions") is False:
                open_sessions = [
                    ws.to_checkpoint_dict()
                    for ws in self._work_sessions.values()
                    if ws.state in ("open", "disconnected") and (dom_name == "System Data" or ws.domain == dom_name)
                ]
                return cp_ok(self._paginate_list(open_sessions, req, collection_key="objects"))
            if dom_name == "System Data":
                return cp_ok({"objects": [], "from": 0, "to": 0, "total": 0})

        if clean_cmd == "show-changes":
            return self._handle_show_changes(dom_name, req, binding=binding, wait_for_task=wait_for_task)

        if clean_cmd == "show-checkpoint-host":
            lookup = str(req.get("name") or req.get("uid") or "").strip()
            details_level = str(req.get("details-level") or "full")
            candidate_scopes: list[dict[str, Any]] = []
            eff_dom = self._effective_domain_files(dom_name, binding)
            if isinstance(eff_dom, dict):
                candidate_scopes.append(eff_dom)
            for extra_dom in ("System Data", "SMC User", "Global"):
                if extra_dom != dom_name and isinstance(self._domain_data.get(extra_dom), dict):
                    candidate_scopes.append(self._domain_data[extra_dom])
            for d_name, d_files in self._domain_data.items():
                if d_name not in (dom_name, "System Data", "SMC User", "Global") and isinstance(d_files, dict):
                    candidate_scopes.append(d_files)
            for scope_files in candidate_scopes:
                for bucket_cmd in ("show-checkpoint-hosts", "show-gateways-and-servers"):
                    for obj in scope_files.get(bucket_cmd, {}).get("objects", []):
                        if isinstance(obj, dict) and (
                            not lookup or obj.get("uid") == lookup or obj.get("name") == lookup
                        ):
                            return cp_ok(_project_details_level(obj, details_level))
            for mds_obj in self._show_mdss.get("objects", []):
                if isinstance(mds_obj, dict) and (mds_obj.get("uid") == lookup or mds_obj.get("name") == lookup):
                    return cp_ok(_project_details_level(mds_obj, details_level))
            if lookup == mgmt_name and "SMC User" in self._domain_data:
                return cp_ok(
                    {
                        "uid": f"uid-chost-{mgmt_name}",
                        "name": mgmt_name,
                        "type": "checkpoint-host",
                        "domain": {"uid": "uid-dom-smc-user", "name": "SMC User", "domain-type": "domain"},
                    }
                )
            return cp_error(
                "generic_err_object_not_found",
                f"Requested Check Point host [{lookup}] not found",
                status_code=404,
            )

        # 4. System Data fallback commands
        if dom_name == "System Data":
            if clean_cmd == "show-last-published-session":
                return cp_ok(
                    {
                        "uid": "sess-system-data-0001",
                        "name": "system-session",
                        "type": "session",
                        "state": "published",
                        "locks": 0,
                        "published-changes": 0,
                        "number-of-published-changes": 0,
                        "publish-time": {"posix": 1794139200000, "iso-8601": "2026-11-08T12:00:00Z"},
                    }
                )
            if clean_cmd == "where-used":
                lookup_ref = str(req.get("uid") or req.get("name") or "")
                sys_items = [*self._show_mdss.get("objects", []), *self._show_domains.get("objects", [])]
                if lookup_ref and any(
                    isinstance(o, dict) and (o.get("uid") == lookup_ref or o.get("name") == lookup_ref)
                    for o in sys_items
                ):
                    data_out: dict[str, Any] = {"used-directly": _empty_where_used_bucket()}
                    if bool(req.get("indirect", False)):
                        data_out["used-indirectly"] = _empty_where_used_bucket()
                    return cp_ok(data_out)
                return cp_error(
                    "generic_err_object_not_found",
                    f"Requested object [{lookup_ref}] not found in {dom_name}",
                    status_code=404,
                )

        mutating = is_mutating_command(clean_cmd)
        if mutating and dom_name == "System Data":
            return cp_error(
                "err_validation_failed",
                f"Cannot execute domain object/rule mutation {clean_cmd!r} in System Data domain",
                status_code=400,
            )

        dom_files = self._effective_domain_files(dom_name, binding)
        if dom_files is None:
            return cp_error(
                "generic_err_object_not_found", f"Domain [{dom_name}] not found in dataset", status_code=404
            )
        global_files = self._effective_domain_files("Global", binding) or {}

        # 5. Stateful mutations & CRUD commands
        if mutating and active_ws is not None:
            if active_ws.read_only:
                return cp_error("err_validation_failed", "Cannot modify database in read-only session", status_code=400)
            if binding is not None and binding.domain != dom_name:
                if dom_name == "Global" and binding.domain != "System Data":
                    return cp_error(
                        "generic_err_object_read_only",
                        f"Cannot mutate Global domain from local domain session [{binding.domain}]",
                        status_code=400,
                    )
                return cp_error(
                    "err_validation_failed",
                    f"Session bound to domain [{binding.domain}] cannot mutate domain [{dom_name}]",
                    status_code=400,
                )

        if (
            mutating
            or clean_cmd in CMD_TO_ENTITY_ACTION
            or (
                clean_cmd.startswith("show-")
                and not clean_cmd.endswith("-rulebase")
                and any(
                    clean_cmd.endswith(f"-{rk}-{sfx}")
                    for rk in ("access", "nat", "https", "threat")
                    for sfx in ("rule", "section")
                )
            )
        ):
            is_write = mutating
            if is_write and active_ws is not None:
                candidate_uids = self._preflight_target_uids(clean_cmd, req, dom_files, global_files, dom_name)
                lock_err = self._check_cross_session_locks(active_ws, candidate_uids)
                if lock_err is not None:
                    return lock_err
                target_files = self._ensure_overlay(active_ws)
                user_name = active_ws.user_name
            elif is_write:
                target_files = self._domain_data[dom_name]
                user_name = "admin"
            else:
                target_files = dom_files
                user_name = active_ws.user_name if active_ws is not None else "admin"

            locked_out: set[str] = set()
            all_eff = self._effective_all_domains(binding)
            outcome = self._apply_domain_mutation(
                clean_cmd,
                req,
                dom_name=dom_name,
                target_files=target_files,
                global_files=global_files,
                all_domains=all_eff,
                user_name=user_name,
                locked_uids_out=locked_out,
            )
            if outcome is not None:
                res, assigned_uid = outcome
                if res.success and is_write:
                    if active_ws is not None:
                        active_ws.locked_uids.update(locked_out)
                        replay_payload = copy.deepcopy(req)
                        if assigned_uid and "uid" not in replay_payload:
                            replay_payload["uid"] = assigned_uid
                        active_ws.mutation_records.append(
                            MutationRecord(
                                command=clean_cmd,
                                domain=dom_name,
                                payload=replay_payload,
                                assigned_uid=assigned_uid,
                            )
                        )
                        active_ws.last_modify_posix = self._next_timestamp_ms()
                        active_ws.changes_count = len(active_ws.mutation_records)
                    else:
                        self._mark_domain_mutated(dom_name)
                return res

        if clean_cmd == "show-unused-objects":
            unused = find_unused_objects(
                dom_files,
                dom_name=dom_name,
                all_domains_effective=self._effective_all_domains(binding),
            )
            return cp_ok(paginate_items(unused, req, collection_key="objects"))

        if clean_cmd in ("show-last-published-session", "show-session"):
            sess_data = dom_files.get(clean_cmd) or dom_files.get("show-last-published-session") or {}
            return cp_ok(copy.deepcopy(sess_data))

        if clean_cmd in ("show-simple-gateway", "show-simple-cluster", "show-generic-object"):
            lookup_key = str(req.get("uid") or req.get("name") or "")
            self.gateway_detail_queries.append((dom_name, clean_cmd, lookup_key))
            store = dom_files.get(clean_cmd, {})
            if lookup_key in store:
                return cp_ok(_project_details_level(store[lookup_key], str(req.get("details-level") or "full")))
            for item_val in store.values():
                if isinstance(item_val, dict) and item_val.get("name") == lookup_key:
                    return cp_ok(_project_details_level(item_val, str(req.get("details-level") or "full")))
            if clean_cmd == "show-generic-object":
                raw_gen = dom_files.get("show-generic-objects", {})
                gen_lists = (
                    [raw_gen["objects"]]
                    if isinstance(raw_gen.get("objects"), list)
                    else [v for v in raw_gen.values() if isinstance(v, list)]
                )
                for g_list in gen_lists:
                    for g_obj in g_list:
                        if isinstance(g_obj, dict) and (
                            g_obj.get("uid") == lookup_key or g_obj.get("name") == lookup_key
                        ):
                            return cp_ok(_project_details_level(g_obj, str(req.get("details-level") or "full")))
            return cp_error(
                "generic_err_object_not_found", f"Requested object [{lookup_key}] not found", status_code=404
            )

        if clean_cmd == "show-generic-objects":
            raw_gen = dom_files.get("show-generic-objects", {})
            cls_filter = req.get("class-name")
            name_filter = req.get("name")
            if isinstance(raw_gen.get("objects"), list):
                all_generic = [g for g in raw_gen["objects"] if not cls_filter or g.get("class-name") == cls_filter]
            elif cls_filter:
                all_generic = list(raw_gen.get(str(cls_filter), []))
            else:
                all_generic = [g for v in raw_gen.values() if isinstance(v, list) for g in v if isinstance(g, dict)]
            filtered = [g for g in all_generic if not name_filter or g.get("name") == name_filter]
            return cp_ok(self._paginate_list(filtered, req, collection_key="objects"))

        if clean_cmd in ("show-access-rulebase", "show-https-rulebase", "show-threat-rulebase"):
            rb_specs = {
                "show-access-rulebase": ("show-access-layers", "access-layers", "access"),
                "show-https-rulebase": ("show-https-layers", "https-layers", "HTTPS"),
                "show-threat-rulebase": ("show-threat-layers", "threat-layers", "Threat"),
            }
            lyr_store, lyr_key, label = rb_specs[clean_cmd]
            lookup = str(req.get("uid") or req.get("name") or "")
            layer_payload = _resolve_layer_payload(
                dom_files,
                global_files,
                lookup,
                store_key=clean_cmd,
                layer_store_key=lyr_store,
                layer_list_key=lyr_key,
            )
            if layer_payload is None:
                return cp_error(
                    "generic_err_object_not_found",
                    f"Requested {label} layer [{lookup}] not found in {dom_name}",
                    status_code=404,
                )
            sliced_rb = slice_rulebase_with_sections(
                layer_payload,
                dom_files=dom_files,
                global_files=global_files,
                dom_name=dom_name,
                offset=int(req.get("offset", 0)),
                limit=int(req.get("limit", 100)),
                use_object_dictionary=bool(req.get("use-object-dictionary", True)),
            )
            return cp_ok(sliced_rb)

        if clean_cmd == "show-nat-rulebase":
            pkg_lookup = str(req.get("package") or req.get("uid") or req.get("name") or "")
            nat_payload = _resolve_nat_package_payload(dom_files, pkg_lookup)
            if nat_payload is None and dom_name != "Global":
                nat_payload = _resolve_nat_package_payload(global_files, pkg_lookup)
            if nat_payload is None:
                return cp_error(
                    "generic_err_object_not_found",
                    f"Requested NAT package [{pkg_lookup}] not found in {dom_name}",
                    status_code=404,
                )
            sliced_nat = slice_rulebase_with_sections(
                nat_payload,
                dom_files=dom_files,
                global_files=global_files,
                dom_name=dom_name,
                offset=int(req.get("offset", 0)),
                limit=int(req.get("limit", 100)),
                use_object_dictionary=bool(req.get("use-object-dictionary", True)),
            )
            return cp_ok(sliced_nat)

        if clean_cmd == "where-used":
            lookup_ref = str(req.get("uid") or req.get("name") or "")
            target_obj = _find_domain_object_by_ref(dom_files, lookup_ref)
            if target_obj is None and dom_name != "Global":
                target_obj = _find_domain_object_by_ref(global_files, lookup_ref)
            if target_obj is None:
                return cp_error(
                    "generic_err_object_not_found",
                    f"Requested object [{lookup_ref}] not found in {dom_name}",
                    status_code=404,
                )
            target_uid = str(target_obj.get("uid") or lookup_ref)
            indirect_flag = bool(req.get("indirect", False))
            max_depth = max(1, int(req.get("indirect-max-depth", 5)))
            wu_data = _build_where_used_response(
                dom_files,
                global_files,
                dom_name,
                target_uid,
                indirect=indirect_flag,
                max_depth=max_depth,
            )
            return cp_ok(wu_data)

        if clean_cmd == "show-package":
            pkg_lookup = str(req.get("name") or req.get("uid") or "")
            for scope_files in (dom_files, global_files if dom_name != "Global" else {}):
                for pkg in scope_files.get("show-packages", {}).get("packages", []):
                    if pkg.get("name") == pkg_lookup or pkg.get("uid") == pkg_lookup:
                        return cp_ok(copy.deepcopy(pkg))
            return cp_error("generic_err_object_not_found", f"Package [{pkg_lookup}] not found", status_code=404)

        if clean_cmd in ("show-access-layer", "show-https-layer", "show-threat-layer"):
            layer_cmd_meta = {
                "show-access-layer": ("show-access-layers", "access-layers", "Access"),
                "show-https-layer": ("show-https-layers", "https-layers", "HTTPS"),
                "show-threat-layer": ("show-threat-layers", "threat-layers", "Threat"),
            }
            lyr_store, lyr_key, lyr_label = layer_cmd_meta[clean_cmd]
            layer_lookup = str(req.get("name") or req.get("uid") or "")
            for scope_files in (dom_files, global_files if dom_name != "Global" else {}):
                for lyr in scope_files.get(lyr_store, {}).get(lyr_key, []):
                    if lyr.get("name") == layer_lookup or lyr.get("uid") == layer_lookup:
                        return cp_ok(copy.deepcopy(lyr))
            return cp_error(
                "generic_err_object_not_found", f"{lyr_label} layer [{layer_lookup}] not found", status_code=404
            )

        if clean_cmd == "show-object":
            lookup_uid = str(req.get("uid") or req.get("name") or "")
            found_eff = find_effective_object(
                dom_files, global_files, dom_name, lookup_uid, allow_sentinels=False, include_extras=True
            )
            if found_eff is not None:
                return cp_ok({"object": copy.deepcopy(found_eff[0])})
            for scope_files in (dom_files, global_files if dom_name != "Global" else {}):
                for file_val in scope_files.values():
                    if not isinstance(file_val, dict):
                        continue
                    items = file_val.get("objects")
                    if isinstance(items, list):
                        for obj in items:
                            if isinstance(obj, dict) and (
                                obj.get("uid") == lookup_uid or obj.get("name") == lookup_uid
                            ):
                                return cp_ok({"object": copy.deepcopy(obj)})
                    elif lookup_uid in file_val and isinstance(file_val[lookup_uid], dict):
                        return cp_ok({"object": copy.deepcopy(file_val[lookup_uid])})
            return cp_error("generic_err_object_not_found", f"Object [{lookup_uid}] not found", status_code=404)

        if clean_cmd == "show-objects":
            filter_raw = req.get("filter")
            filter_needle = str(filter_raw).strip().lower() if filter_raw is not None else ""
            ip_only = bool(req.get("ip-only", False))
            matched = filter_show_objects(
                dom_files,
                global_files,
                dom_name,
                req,
                _SHOW_OBJECTS_TYPE_TO_CMD,
                lambda item: _matches_show_objects_filter(item, filter_needle=filter_needle, ip_only=ip_only),
            )
            return cp_ok(self._paginate_list(matched, req, collection_key="objects"))

        if clean_cmd in ("verify-policy", "install-policy"):
            pkg_lookup = str(req.get("policy-package") or req.get("package") or "").strip()
            all_pkgs = [
                pkg
                for scope_files in (dom_files, global_files if dom_name != "Global" else {})
                for pkg in scope_files.get("show-packages", {}).get("packages", [])
                if isinstance(pkg, dict)
            ]
            if pkg_lookup:
                matched_pkg = next(
                    (p for p in all_pkgs if p.get("name") == pkg_lookup or p.get("uid") == pkg_lookup),
                    None,
                )
                if matched_pkg is None:
                    return cp_error(
                        "generic_err_object_not_found",
                        f"Requested policy package [{pkg_lookup}] not found in {dom_name}",
                        status_code=404,
                    )
                eff_pkg = str(matched_pkg.get("name") or pkg_lookup)
            else:
                eff_pkg = str(all_pkgs[0].get("name")) if all_pkgs else "Standard"

            if clean_cmd == "verify-policy":
                tid = self._next_task_id()
                t_obj = {
                    "uid": tid,
                    "task-id": tid,
                    "task-name": f"Verify Policy ({eff_pkg})",
                    "status": "succeeded",
                    "progress-percentage": 100,
                    "suppressed": False,
                    "comments": f"Package '{eff_pkg}' verified with 0 errors.",
                    "task-details": [
                        {
                            "uid": self._allocate_uid("td"),
                            "statusCode": "succeeded",
                            "statusDescription": "Succeeded",
                            "errors": [],
                            "warnings": [],
                        }
                    ],
                }
                self._tasks[tid] = t_obj
                if wait_for_task:
                    return cp_ok({"tasks": [copy.deepcopy(t_obj)]}, task_id=tid)
                return cp_ok({"task-id": tid}, task_id=tid)

            raw_targets = req.get("targets")
            req_targets = (
                [str(raw_targets).strip()]
                if isinstance(raw_targets, str)
                else ([str(t).strip() for t in raw_targets if str(t).strip()] if isinstance(raw_targets, list) else [])
            )
            if not req_targets:
                return cp_error("err_validation_failed", "install-policy: 'targets' is required", status_code=400)

            all_gws = [
                gw
                for scope_files in (dom_files, global_files if dom_name != "Global" else {})
                for gw in scope_files.get("show-gateways-and-servers", {}).get("objects", [])
                if isinstance(gw, dict)
            ]
            resolved_targets: list[str] = []
            for tgt in req_targets:
                if tgt.lower() == "all":
                    for gw in all_gws:
                        gw_name = str(gw.get("name") or gw.get("uid") or "")
                        if gw_name and gw_name not in resolved_targets:
                            resolved_targets.append(gw_name)
                    continue
                matched_gw = next(
                    (gw for gw in all_gws if gw.get("name") == tgt or gw.get("uid") == tgt),
                    None,
                )
                if matched_gw is None:
                    return cp_error(
                        "generic_err_object_not_found",
                        f"Requested install target [{tgt}] not found in {dom_name}",
                        status_code=404,
                    )
                resolved_targets.append(str(matched_gw.get("name") or tgt))

            tid = self._next_task_id()
            t_obj = {
                "uid": tid,
                "task-id": tid,
                "task-name": f"Install Policy ({eff_pkg})",
                "status": "succeeded",
                "progress-percentage": 100,
                "suppressed": False,
                "installed-targets": list(resolved_targets),
                "task-details": [
                    {
                        "uid": self._allocate_uid("td"),
                        "gatewayName": tgt_name,
                        "statusCode": "succeeded",
                        "statusDescription": "Succeeded",
                        "errors": [],
                        "warnings": [],
                    }
                    for tgt_name in resolved_targets
                ],
            }
            self._tasks[tid] = t_obj
            if wait_for_task:
                return cp_ok({"tasks": [copy.deepcopy(t_obj)]}, task_id=tid)
            return cp_ok({"task-id": tid}, task_id=tid)

        # Standard paginated listing commands (`show-gateways-and-servers`, `show-hosts`, `show-networks`, etc.)
        if clean_cmd in dom_files and isinstance(dom_files[clean_cmd], dict):
            file_payload = dom_files[clean_cmd]
            col_key = "objects"
            for candidate_key in (
                "objects",
                "packages",
                "access-layers",
                "https-layers",
                "threat-layers",
                "nat-rules",
                "sessions",
            ):
                if isinstance(file_payload.get(candidate_key), list):
                    col_key = candidate_key
                    break
            items = file_payload.get(col_key, [])
            return cp_ok(self._paginate_list(items, req, collection_key=col_key))

        if clean_cmd == "show-https-layers":
            return cp_ok({"https-layers": [], "from": 0, "to": 0, "total": 0})
        if clean_cmd == "show-threat-layers":
            return cp_ok({"threat-layers": [], "from": 0, "to": 0, "total": 0})

        # Empty paginated response for optional plural object/service/layer types not populated in fixture
        if clean_cmd.startswith(
            ("show-services-", "show-groups-with-", "show-threat-", "show-https-")
        ) or clean_cmd in {
            "show-multicast-address-ranges",
            "show-security-zones",
            "show-dynamic-objects",
            "show-tags",
            "show-time-groups",
            "show-times",
            "show-wildcard",
            "show-wildcards",
            "show-gsn-handover-groups",
        }:
            return cp_ok({"objects": [], "from": 0, "to": 0, "total": 0})

        return cp_error(
            "generic_err_command_not_recognized",
            f"Unsupported command {clean_cmd!r} in FileReplayApiMock",
            status_code=400,
        )

    @traced
    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ) -> ApiCallResult:
        """Execute a single Check Point Management API command with stateful sessions, overlays, and OTEL spans."""
        _ = (server_ip, timeout)
        clean_cmd = command.strip().lstrip("/")
        if clean_cmd.startswith("web_api/"):
            clean_cmd = clean_cmd.removeprefix("web_api/")
        req = dict(payload) if payload else {}
        binding = self._sid_bindings.get(sid) if sid is not None else None

        if clean_cmd == "login":
            dom_name = self._normalize_domain(req.get("domain") or domain)
        elif domain is not None:
            dom_name = self._normalize_domain(domain)
        elif req.get("domain") is not None:
            dom_name = self._normalize_domain(req.get("domain"))
        elif binding is not None:
            dom_name = binding.domain
        else:
            dom_name = self._normalize_domain(None)

        sid_ref: str | None = binding.sid_ref if binding is not None else ("invalid-sid" if sid is not None else None)
        known_sids = self._known_sids(sid)

        is_mut = is_mutating_command(clean_cmd)
        self.api_call_counts[(dom_name, clean_cmd)] += 1
        self.command_counts[clean_cmd] += 1
        log_entry: dict[str, Any] = {
            "mgmt_name": mgmt_name,
            "domain": dom_name,
            "command": clean_cmd,
            "is_mutating": is_mut,
            "mutating": is_mut,
            "sid_ref": sid_ref,
            "session_uid": binding.session_uid if binding is not None else None,
            "read_only_session": binding.read_only if binding is not None else None,
            "payload": sanitize_call_payload(req, known_sids=known_sids),
            "payload_summary": summarize_payload(clean_cmd, req, known_sids=known_sids),
            "status_code": 200,
            "success": True,
            "error_code": None,
        }
        self.call_log.append(log_entry)

        span_attrs(
            mgmt_name=mgmt_name,
            domain=dom_name,
            command=clean_cmd,
            sid_ref=sid_ref or "",
            session_uid=binding.session_uid if binding is not None else "",
            mutating=is_mut,
        )

        res = self._dispatch_api_call(
            mgmt_name,
            clean_cmd,
            req,
            dom_name=dom_name,
            sid=sid,
            binding=binding,
            wait_for_task=wait_for_task,
        )

        log_entry["status_code"] = res.status_code
        log_entry["success"] = res.success
        log_entry["error_code"] = res.error_code
        if clean_cmd == "login" and res.success and isinstance(res.data, dict):
            new_sid = str(res.data.get("sid") or "")
            new_binding = self._sid_bindings.get(new_sid)
            if new_binding is not None:
                log_entry["sid_ref"] = new_binding.sid_ref
                log_entry["session_uid"] = new_binding.session_uid
                log_entry["read_only_session"] = new_binding.read_only
                span_attrs(sid_ref=new_binding.sid_ref, session_uid=new_binding.session_uid)

        span_attrs(status_code=res.status_code, success=res.success, error_code=res.error_code or "")
        if not res.success:
            span = trace.get_current_span()
            span.set_status(Status(StatusCode.ERROR, res.error_code or "api_error"))
        return res

    @traced
    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        *,
        domain: str | None = None,
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        limit: int = DEFAULT_PAGE_LIMIT,
    ) -> ApiQueryResult:
        """Execute a continuity-verified paginated listing query via `paginate_objects`."""
        clean_cmd = command.strip().lstrip("/")
        binding = self._sid_bindings.get(sid) if sid is not None else None
        dom_name = self._normalize_domain(domain if domain is not None else (binding.domain if binding else None))
        self.api_query_counts[(dom_name, clean_cmd)] += 1
        span_attrs(
            mgmt_name=mgmt_name,
            domain=dom_name,
            command=clean_cmd,
            details_level=details_level,
            limit=limit,
        )

        async def _call_page(page_payload: dict[str, Any]) -> ApiCallResult:
            return await self.api_call(
                mgmt_name,
                clean_cmd,
                page_payload,
                domain=domain,
                sid=sid,
                server_ip=server_ip,
            )

        return await paginate_objects(
            clean_cmd,
            _call_page,
            details_level=details_level,
            payload=payload,
            limit=limit,
        )

    @traced
    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        """Open a registered stateful mock session and return `(sid, server_ip)`."""
        dom_name = self._normalize_domain(domain)
        user_name = "admin"
        if auth is not None and getattr(auth, "username", None):
            user_name = str(auth.username)
        login_payload: dict[str, Any] = {"domain": dom_name, "user": user_name}
        if session_name:
            login_payload["session-name"] = session_name
        if session_description:
            login_payload["session-description"] = session_description
        if domain == "Global":
            login_payload["domain"] = "Global"
        res = await self.api_call(mgmt_name, "login", login_payload, domain=dom_name)
        new_sid = str(res.data.get("sid") or "") if isinstance(res.data, dict) else ""
        if not res.success or not new_sid:
            err_detail = res.error_message or res.error_code or f"HTTP {res.status_code}"
            raise SessionError(
                f"Failed to create dedicated session for domain {dom_name!r}: {err_detail}",
                known_sids=[new_sid] if new_sid else None,
            )
        span_attrs(mgmt_name=mgmt_name, domain=dom_name, sid_ref=REDACTED_PLACEHOLDER)
        return new_sid, "127.0.0.1"

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> Awaitable[bool]:
        """Log out a registered mock session identifier and clean up uncommitted work."""
        _ = server_ip

        async def _do_logout() -> bool:
            binding = self.get_active_sid_binding(sid)
            if binding is None:
                return False
            res = await self.api_call(mgmt_name, "logout", {}, domain=binding.domain, sid=sid)
            return res.success

        return _do_logout()

    async def close(self, *, logout: bool | None = None) -> None:
        """Close the mock adapter, optionally logging out all active sessions."""
        if logout:
            for sid in [s for s, b in self._sid_bindings.items() if b.active]:
                await self.logout_sid("mds", sid)
        return None


__all__ = [
    "FileReplayApiMock",
    "FileReplayCliMock",
    "ReplayStateSnapshot",
]
