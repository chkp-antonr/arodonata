"""Lock preflight, MDSM global assignments, and policy verify/install handlers."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from arodonata.core.models.common import ApiCallResult

from ._emulator_lookup import as_list, find_effective_object, preview_delete_unused_uids, ref_uid
from ._emulator_models import (
    CMD_TO_ENTITY_ACTION,
    OBJ_TYPE_TO_SPEC,
    SidBinding,
    WorkSession,
    cp_error,
    cp_ok,
    format_domain_meta,
    format_timestamp,
)
from ._emulator_projection import paginate_items
from ._emulator_rulebase_tree import parse_rule_number
from ._replay_queries import resolve_layer_payload, resolve_nat_package_payload
from .dataset_generator import USER_DOMAINS

if TYPE_CHECKING:
    from .replay_mock import FileReplayApiMock


def candidate_preflight_layers(
    store: Any,
    *,
    dom_files: Mapping[str, Any],
    pkg_or_lyr: str,
    rule_kind: str,
    allow_multi: bool,
) -> list[Mapping[str, Any]]:
    """Return rulebase layers/packages targeted by a rule or section preflight lock scan."""
    if not isinstance(store, Mapping):
        return []
    if pkg_or_lyr:
        if rule_kind == "nat":
            resolved_layer = resolve_nat_package_payload(dict(dom_files), pkg_or_lyr)
        else:
            rb_meta = {
                "access": ("show-access-rulebase", "show-access-layers", "access-layers"),
                "https": ("show-https-rulebase", "show-https-layers", "https-layers"),
                "threat": ("show-threat-rulebase", "show-threat-layers", "threat-layers"),
            }[rule_kind]
            resolved_layer = resolve_layer_payload(
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


def preflight_target_uids(
    command: str,
    req: Mapping[str, Any],
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    *,
    all_domains_effective: Mapping[str, Mapping[str, Any]] | None = None,
) -> set[str]:
    """Identify object, script, rule, or section UIDs affected by a write command for lock checking."""
    targets: set[str] = set()
    if command == "delete-unused-objects":
        return preview_delete_unused_uids(
            dom_files,
            dom_name=dom_name,
            all_domains_effective=all_domains_effective or {dom_name: dom_files, "Global": global_files},
            req=req,
        )
    if command in ("set-repository-script", "delete-repository-script") or (
        command == "add-repository-script" and bool(req.get("set-if-exists", False))
    ):
        lookup = (
            str(req.get("name") or "")
            if command == "add-repository-script"
            else str(req.get("uid") or req.get("name") or "")
        )
        if lookup:
            for item in dom_files.get("show-repository-scripts", {}).get("objects", []):
                if isinstance(item, Mapping) and (item.get("uid") == lookup or item.get("name") == lookup):
                    if item.get("uid"):
                        targets.add(str(item["uid"]))
                    break
        return targets

    entity_map = CMD_TO_ENTITY_ACTION.get(command)
    if entity_map is not None:
        spec, action = entity_map
        grp_spec = OBJ_TYPE_TO_SPEC["service-group" if spec.is_service else "group"]
        existing_obj: Mapping[str, Any] | None = None
        if action in ("set", "delete"):
            lookup = str(req.get("uid") or req.get("name") or "")
            found = find_effective_object(
                dom_files, global_files, dom_name, lookup, preferred_spec=spec, include_extras=False
            )
            if found is not None and found[0].get("uid"):
                existing_obj = found[0]
                targets.add(str(existing_obj["uid"]))
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
                    existing_obj = found[0]
                    targets.add(str(existing_obj["uid"]))
        if action in ("add", "set") and "groups" in req:
            raw_groups = req["groups"]
            group_refs = (
                [*as_list(raw_groups.get("add")), *as_list(raw_groups.get("remove"))]
                if isinstance(raw_groups, Mapping) and ("add" in raw_groups or "remove" in raw_groups)
                else as_list(raw_groups)
            )
            for g_ref in group_refs:
                g_hit = find_effective_object(
                    dom_files, global_files, dom_name, ref_uid(g_ref), preferred_spec=grp_spec
                )
                if g_hit is not None and g_hit[0].get("uid"):
                    targets.add(str(g_hit[0]["uid"]))
            if existing_obj is not None and not (
                isinstance(raw_groups, Mapping) and ("add" in raw_groups or "remove" in raw_groups)
            ):
                for cur_g in existing_obj.get("groups", []):
                    cur_g_uid = ref_uid(cur_g)
                    if cur_g_uid:
                        targets.add(cur_g_uid)
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
        pkg_or_lyr = str((req.get("package") or "") if is_nat else (req.get("layer") or ""))

        if not is_section:
            uid = str(req.get("uid") or "").strip()
            if uid:
                targets.add(uid)
                return targets
            req_num, valid_num = parse_rule_number(req.get("rule-number"))
            if not valid_num:
                return targets
            req_name = str(req.get("name") or "")
            candidate_layers = candidate_preflight_layers(
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
                            (req_num is not None and eff_num == req_num) or (req_name and child.get("name") == req_name)
                        ) and child.get("uid"):
                            targets.add(str(child["uid"]))
        else:
            sec_uid = str(req.get("uid") or "").strip()
            sec_name = str(req.get("name") or "").strip()
            if sec_uid:
                targets.add(sec_uid)
            candidate_layers = candidate_preflight_layers(
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


def check_cross_session_locks(
    mock: FileReplayApiMock,
    ws: WorkSession,
    candidate_uids: set[str],
) -> ApiCallResult | None:
    """Reject mutations targeting UIDs locked by another open or disconnected session."""
    if not candidate_uids:
        return None
    for other_ws in mock._work_sessions.values():
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


def handle_global_assignments_cmd(
    mock: FileReplayApiMock,
    clean_cmd: str,
    req: Mapping[str, Any],
    *,
    binding: SidBinding | None,
    wait_for_task: bool,
) -> ApiCallResult:
    """Handle `show-global-assignments`, `show-global-assignment`, and `assign-global-*` commands."""
    if clean_cmd == "show-global-assignments":
        return cp_ok(paginate_items(mock._show_global_assignments, req, collection_key="objects"))

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
        for entry in mock._show_global_assignments:
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
        if binding is not None and mock._work_sessions[binding.session_uid].read_only:
            return cp_error("err_validation_failed", "Cannot modify database in read-only session", status_code=400)
        if binding is not None and binding.domain not in ("System Data", "Global"):
            return cp_error(
                "generic_err_object_read_only",
                f"Cannot assign Global policy from local domain [{binding.domain}]",
                status_code=400,
            )

        raw_globs = req.get("global-domains") or req.get("global-domain") or ["Global"]
        global_list = [str(g) for g in (raw_globs if isinstance(raw_globs, list) else [raw_globs])]
        raw_deps = req.get("dependent-domains") or req.get("dependent-domain")
        if raw_deps is None:
            dep_list = [d for d in USER_DOMAINS if d in mock._domain_data]
        else:
            dep_list = [str(d) for d in (raw_deps if isinstance(raw_deps, list) else [raw_deps])]

        for dep in dep_list:
            if dep not in mock._domain_data or dep in ("Global", "System Data"):
                return cp_error(
                    "generic_err_object_not_found",
                    f"Dependent domain [{dep}] not found",
                    status_code=404,
                )

        ts_ms = mock._next_timestamp_ms()
        ts_obj = format_timestamp(ts_ms)
        details: list[dict[str, Any]] = []
        for dep in dep_list:
            for g_dom in global_list:
                matched_entry: dict[str, Any] | None = None
                for entry in mock._show_global_assignments:
                    if _domain_ref_matches(entry.get("dependent-domain"), dep) and _domain_ref_matches(
                        entry.get("global-domain"), g_dom
                    ):
                        matched_entry = entry
                        break
                if matched_entry is None:
                    matched_entry = {
                        "uid": mock._allocate_uid("ga"),
                        "type": "global-assignment",
                        "global-domain": format_domain_meta(g_dom),
                        "dependent-domain": format_domain_meta(dep),
                        "global-access-policy": str(req.get("global-access-policy") or "Global_Standard_Pkg"),
                        "global-threat-prevention-policy": str(req.get("global-threat-prevention-policy") or ""),
                    }
                    mock._show_global_assignments.append(matched_entry)
                matched_entry["assignment-status"] = "assigned"
                matched_entry["assignment-up-to-date"] = dict(ts_obj)
                matched_entry["last-modify-time"] = dict(ts_obj)

            mock._mark_domain_mutated(dep)
            for pkg in mock._domain_data[dep].get("show-packages", {}).get("packages", []):
                if isinstance(pkg, dict):
                    pkg["global-policy-assigned-at"] = dict(ts_obj)
                    pkg["global-domains"] = list(global_list)

            details.append(
                {
                    "uid": mock._allocate_uid("td"),
                    "domainName": dep,
                    "statusCode": "succeeded",
                    "statusDescription": f"Global policy assigned to {dep}",
                }
            )

        tid = mock._next_task_id()
        t_obj = {
            "uid": tid,
            "task-id": tid,
            "task-name": "Assign Global Policy",
            "status": "succeeded",
            "progress-percentage": 100,
            "suppressed": False,
            "task-details": details,
        }
        mock._tasks[tid] = t_obj
        if wait_for_task:
            return cp_ok({"tasks": [copy.deepcopy(t_obj)]}, task_id=tid)
        return cp_ok({"task-id": tid}, task_id=tid)

    return cp_error("generic_err_command_not_recognized", f"Unsupported command {clean_cmd!r}")


def handle_verify_or_install_policy(
    mock: FileReplayApiMock,
    clean_cmd: str,
    req: Mapping[str, Any],
    *,
    dom_name: str,
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    wait_for_task: bool,
    binding: SidBinding | None = None,
    active_ws: WorkSession | None = None,
) -> ApiCallResult:
    """Handle `verify-policy` and `install-policy` session/domain guards and async task synthesis."""
    if binding is not None or active_ws is not None:
        if active_ws is None or active_ws.state != "open":
            return cp_error(
                "err_validation_failed",
                f"{clean_cmd} requires an open session",
                status_code=400,
            )
        if active_ws.read_only or (binding is not None and binding.read_only):
            return cp_error(
                "generic_err_operation_failed",
                f"Cannot execute {clean_cmd} in read-only session [{active_ws.uid}]",
                status_code=403,
            )
        if binding is not None and binding.domain != dom_name:
            return cp_error(
                "err_validation_failed",
                f"Session bound to domain [{binding.domain}] cannot execute {clean_cmd} on domain [{dom_name}]",
                status_code=400,
            )
        if active_ws.changes_count > 0 or active_ws.locked_uids:
            return cp_error(
                "generic_err_invalid_parameter",
                f"{clean_cmd} requires a clean session with zero uncommitted changes",
                status_code=400,
            )
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
        tid = mock._next_task_id()
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
                    "uid": mock._allocate_uid("td"),
                    "statusCode": "succeeded",
                    "statusDescription": "Succeeded",
                    "errors": [],
                    "warnings": [],
                }
            ],
        }
        mock._tasks[tid] = t_obj
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

    tid = mock._next_task_id()
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
                "uid": mock._allocate_uid("td"),
                "gatewayName": tgt_name,
                "statusCode": "succeeded",
                "statusDescription": "Succeeded",
                "errors": [],
                "warnings": [],
            }
            for tgt_name in resolved_targets
        ],
    }
    mock._tasks[tid] = t_obj
    if wait_for_task:
        return cp_ok({"tasks": [copy.deepcopy(t_obj)]}, task_id=tid)
    return cp_ok({"task-id": tid}, task_id=tid)
