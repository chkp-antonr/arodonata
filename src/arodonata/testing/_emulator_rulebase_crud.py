"""Access, NAT, HTTPS, and Threat rulebase CRUD handlers for the stateful replay emulator."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from typing import Any

from arodonata.core.models.common import ApiCallResult

from ._emulator_lookup import as_list, global_read_only_error
from ._emulator_models import (
    ANY_UID,
    LOG_TRACK_UID,
    NONE_TRACK_UID,
    cp_error,
    cp_ok,
    format_domain_meta,
    format_timestamp,
)
from ._emulator_projection import NAT_CELL_SCALAR_FIELDS, RULE_KIND_CONFIGS, extract_ref_uids
from ._emulator_rulebase_fields import (
    apply_cell_list_update,
    detect_rule_kind,
    format_rule_response,
    normalize_action,
    normalize_inline_layer,
    normalize_nat_scalar_field,
    normalize_track,
)
from ._emulator_rulebase_tree import (
    insert_rule_into_tree,
    insert_section_into_tree,
    locate_rule_in_tree,
    locate_section_in_tree,
    parse_rule_number,
    renumber_layer,
    resolve_rulebase_container,
)


def _handle_section_crud(
    command: str,
    action: str,
    req: Mapping[str, Any],
    *,
    cfg: Mapping[str, Any],
    dom_name: str,
    dom_files: dict[str, Any],
    global_files: Mapping[str, Any],
    layer_payload: dict[str, Any],
    nodes: list[Any],
    uid_allocator: Callable[[str], str],
    locked_uids_out: set[str],
) -> tuple[ApiCallResult, str | None] | None:
    if action == "show":
        hit = locate_section_in_tree(nodes, req)
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
        pos_err = insert_section_into_tree(nodes, new_sec, req.get("position"))
        if pos_err is not None:
            return pos_err, None
        renumber_layer(layer_payload, dom_files, global_files, dom_name)
        locked_uids_out.add(sec_uid)
        return cp_ok(copy.deepcopy(new_sec)), sec_uid

    if action == "set":
        hit = locate_section_in_tree(nodes, req)
        if hit is None:
            return cp_error("generic_err_object_not_found", "Section not found", status_code=404), None
        _, sec = hit
        if req.get("new-name"):
            sec["name"] = str(req["new-name"])
        if "new-position" in req:
            nodes.remove(sec)
            pos_err = insert_section_into_tree(nodes, sec, req.get("new-position"))
            if pos_err is not None:
                nodes.append(sec)
                return pos_err, None
        renumber_layer(layer_payload, dom_files, global_files, dom_name)
        sec_uid = str(sec["uid"])
        locked_uids_out.add(sec_uid)
        return cp_ok(copy.deepcopy(sec)), sec_uid

    if action == "delete":
        hit = locate_section_in_tree(nodes, req)
        if hit is None:
            return cp_error("generic_err_object_not_found", "Section not found", status_code=404), None
        idx, sec = hit
        sec_uid = str(sec["uid"])
        locked_uids_out.add(sec_uid)
        for child in sec.get("rulebase", []):
            if isinstance(child, Mapping) and child.get("uid"):
                locked_uids_out.add(str(child["uid"]))
        nodes.pop(idx)
        renumber_layer(layer_payload, dom_files, global_files, dom_name)
        return cp_ok({"message": "OK"}), sec_uid

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
    rule_kind = detect_rule_kind(command)
    if rule_kind is None:
        return None

    cfg = RULE_KIND_CONFIGS[rule_kind]
    is_nat = rule_kind == "nat"
    is_section = command.endswith("-section")
    action = command.split("-", 1)[0]
    container = resolve_rulebase_container(dom_files, global_files, dom_name, req, rule_kind=rule_kind)
    if container is None:
        ref = req.get("package") if is_nat else (req.get("layer") or req.get("uid") or req.get("name") or "")
        kind_label = "NAT package" if is_nat else f"{cfg['label']} layer"
        return cp_error(
            "generic_err_object_not_found", f"Requested {kind_label} [{ref}] not found", status_code=404
        ), None

    layer_payload, owning_dom = container
    if action in ("add", "set", "delete") and owning_dom == "Global" and dom_name != "Global":
        return global_read_only_error(str(layer_payload.get("name") or layer_payload.get("uid")), dom_name), None

    nodes = layer_payload.setdefault("rulebase", [])
    existing_dict_map = {
        str(entry["uid"]): entry
        for entry in layer_payload.get("objects-dictionary", [])
        if isinstance(entry, Mapping) and entry.get("uid")
    }

    if is_section:
        return _handle_section_crud(
            command,
            action,
            req,
            cfg=cfg,
            dom_name=dom_name,
            dom_files=dom_files,
            global_files=global_files,
            layer_payload=layer_payload,
            nodes=nodes,
            uid_allocator=uid_allocator,
            locked_uids_out=locked_uids_out,
        )

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
        rule_hit = locate_rule_in_tree(nodes, req)
        if rule_hit is None:
            return cp_error("generic_err_object_not_found", "Rule not found", status_code=404), None
        _, _, rule, _ = rule_hit
        return (
            cp_ok(
                format_rule_response(
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
            act = normalize_action(req.get("action"), rule_kind=rule_kind)
            if isinstance(act, ApiCallResult):
                return act, None
            default_track = NONE_TRACK_UID if act == "Drop" else LOG_TRACK_UID
            new_rule: dict[str, Any] = {
                "uid": assigned_uid,
                "name": str(req.get("name") or ""),
                "type": cfg["rule_type"],
                "domain": format_domain_meta(dom_name),
                "enabled": bool(req.get("enabled", True)),
                "action": act,
                "track": normalize_track(req.get("track", default_track)),
                "comments": str(req.get("comments") or ""),
                "meta-info": meta,
            }
            for col in req_cols:
                vals, err = apply_cell_list_update(
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
                    vals, col_err = apply_cell_list_update(
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
                inline_uid, il_err = normalize_inline_layer(
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
            for nat_col in NAT_CELL_SCALAR_FIELDS:
                is_trans = nat_col.startswith("translated-")
                val_uid, err = normalize_nat_scalar_field(
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
            inst, err = apply_cell_list_update(
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

        pos_err = insert_rule_into_tree(nodes, new_rule, req.get("position"))
        if pos_err is not None:
            return pos_err, None
        renumber_layer(layer_payload, dom_files, global_files, dom_name)
        locked_uids_out.add(assigned_uid)
        return (
            cp_ok(
                format_rule_response(
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
        rule_hit = locate_rule_in_tree(nodes, req)
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
                        else [str(x["uid"]) if isinstance(x, Mapping) else str(x) for x in as_list(rule.get(col))]
                    )
                    updated, err = apply_cell_list_update(
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
                act = normalize_action(req["action"], rule_kind=rule_kind)
                if isinstance(act, ApiCallResult):
                    parent_list[parent_idx] = snapshot_rule
                    return act, None
                rule["action"] = act
            if "track" in req:
                rule["track"] = normalize_track(req["track"])
            if rule_kind == "access":
                for neg_key in ("source-negate", "destination-negate", "service-negate"):
                    if neg_key in req:
                        rule[neg_key] = bool(req[neg_key])
            if rule_kind in ("access", "https") and "inline-layer" in req:
                inline_uid, il_err = normalize_inline_layer(
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
            for nat_col in NAT_CELL_SCALAR_FIELDS:
                if nat_col in req:
                    val_uid, err = normalize_nat_scalar_field(
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
                    str(x["uid"]) if isinstance(x, Mapping) else str(x) for x in as_list(rule.get("install-on"))
                ]
                updated, err = apply_cell_list_update(
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
            pos_err = insert_rule_into_tree(nodes, rule, req["new-position"])
            if pos_err is not None:
                parent_list.insert(parent_idx, snapshot_rule)
                return pos_err, None

        meta = rule.setdefault("meta-info", {})
        if isinstance(meta, dict):
            meta["last-modifier"] = user_name
            meta["last-modify-time"] = format_timestamp(now_ms)

        renumber_layer(layer_payload, dom_files, global_files, dom_name)
        return (
            cp_ok(
                format_rule_response(
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
        rule_hit = locate_rule_in_tree(nodes, req)
        if rule_hit is None:
            return cp_error("generic_err_object_not_found", "Rule not found", status_code=404), None
        parent_list, parent_idx, rule, _ = rule_hit
        rule_uid = str(rule["uid"])
        locked_uids_out.add(rule_uid)
        parent_list.pop(parent_idx)
        renumber_layer(layer_payload, dom_files, global_files, dom_name)
        return cp_ok({"message": "OK"}), rule_uid

    return None
