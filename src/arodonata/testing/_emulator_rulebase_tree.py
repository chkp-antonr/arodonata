"""Rulebase container resolution, tree lookup, rule/section insertion, and renumbering helpers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from arodonata.core.models.common import ApiCallResult

from ._emulator_models import cp_error
from ._emulator_projection import (
    RULE_KIND_CONFIGS,
    build_objects_dictionary,
    is_section_node,
    iter_flat_rule_entries,
)


def resolve_rulebase_container(
    dom_files: Mapping[str, Any],
    global_files: Mapping[str, Any],
    dom_name: str,
    req: Mapping[str, Any],
    *,
    rule_kind: str = "access",
) -> tuple[dict[str, Any], str] | None:
    """Resolve the mutable layer/NAT package rulebase container and its owning domain."""
    cfg = RULE_KIND_CONFIGS[rule_kind]
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
                    for _, rule in iter_flat_rule_entries(cand.get("rulebase")):
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


def locate_rule_in_tree(
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
        if is_section_node(node):
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


def locate_section_in_tree(nodes: list[Any], req: Mapping[str, Any]) -> tuple[int, dict[str, Any]] | None:
    """Locate a section dict inside top-level rulebase `nodes` by `uid` or `name`."""
    req_uid = str(req.get("uid") or "").strip()
    req_name = str(req.get("name") or "").strip()
    for idx, node in enumerate(nodes):
        if not isinstance(node, dict) or not is_section_node(node):
            continue
        if req_uid and node.get("uid") == req_uid:
            return idx, node
        if req_name and node.get("name") == req_name:
            return idx, node
    return None


def insert_rule_into_tree(nodes: list[Any], rule: dict[str, Any], pos_spec: Any) -> ApiCallResult | None:
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
            if is_section_node(node):
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
            sec_hit = locate_section_in_tree(nodes, {"uid": sec_ref}) or locate_section_in_tree(
                nodes, {"name": sec_ref}
            )
            if sec_hit is None:
                return cp_error("generic_err_object_not_found", f"Section [{sec_ref}] not found", status_code=404)
            sec_hit[1].setdefault("rulebase", []).insert(0, rule)
            return None

        if "bottom" in pos_spec:
            sec_ref = str(pos_spec["bottom"])
            sec_hit = locate_section_in_tree(nodes, {"uid": sec_ref}) or locate_section_in_tree(
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
                hit = locate_rule_in_tree(nodes, rule_req)
                if hit is None and not (isinstance(ref_val, int) or ref_str.isdigit()):
                    hit = locate_rule_in_tree(nodes, {"name": ref_str})
                if hit is not None:
                    parent, r_idx, _, _ = hit
                    parent.insert(r_idx if rel_key == "above" else r_idx + 1, rule)
                    return None
                sec_hit = locate_section_in_tree(nodes, {"uid": ref_str}) or locate_section_in_tree(
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


def insert_section_into_tree(nodes: list[Any], sec: dict[str, Any], pos_spec: Any) -> ApiCallResult | None:
    """Insert `sec` into top-level rulebase `nodes` according to `position` / `new-position`."""
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
            if is_section_node(node):
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
                sec_hit = locate_section_in_tree(nodes, {"uid": ref_str}) or locate_section_in_tree(
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


def renumber_layer(
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
        if is_section_node(node):
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
