"""Change delta computation and `show-changes` synthesis for the stateful replay emulator."""

from __future__ import annotations

import copy
from bisect import bisect_left
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from ._emulator_models import BUILTIN_SENTINELS, ENTITY_SPECS

_IGNORED_DIFF_FIELDS: frozenset[str] = frozenset({"meta-info", "last-modify-time", "layer-uid"})
_RULE_LIST_REF_FIELDS: tuple[str, ...] = ("source", "destination", "service", "install-on", "vpn", "content", "time")
_RULE_SCALAR_REF_FIELDS: tuple[str, ...] = (
    "action",
    "original-source",
    "original-destination",
    "original-service",
    "translated-source",
    "translated-destination",
    "translated-service",
)


def _iter_flat_rules(nodes: Any) -> list[tuple[dict[str, Any] | None, dict[str, Any]]]:
    """Flatten a rulebase `rulebase` node list into `(section_meta, rule_dict)` pairs."""
    if not isinstance(nodes, list):
        return []
    flat: list[tuple[dict[str, Any] | None, dict[str, Any]]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_type = str(node.get("type") or "")
        if node_type.endswith("-section") or (isinstance(node.get("rulebase"), list) and "rule-number" not in node):
            children = node.get("rulebase")
            if isinstance(children, list):
                for child in children:
                    if isinstance(child, dict):
                        flat.append((node, child))
        else:
            flat.append((None, node))
    return flat


def _build_uid_summary_index(*domain_maps: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Build `uid -> {uid, name, type, ...}` lookup across snapshots, sentinels, and Global."""
    index: dict[str, dict[str, Any]] = {uid: copy.deepcopy(meta) for uid, meta in BUILTIN_SENTINELS.items()}
    for dom_map in domain_maps:
        if not isinstance(dom_map, Mapping):
            continue
        for spec in ENTITY_SPECS:
            raw_bucket = dom_map.get(spec.plural_show)
            items = raw_bucket.get("objects", []) if isinstance(raw_bucket, Mapping) else []
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, Mapping) and item.get("uid"):
                    uid = str(item["uid"])
                    summary: dict[str, Any] = {
                        "uid": uid,
                        "name": str(item.get("name") or uid),
                        "type": str(item.get("type") or spec.obj_type),
                    }
                    if isinstance(item.get("domain"), Mapping):
                        summary["domain"] = copy.deepcopy(dict(item["domain"]))
                    index.setdefault(uid, summary)
        for rb_cmd in ("show-access-rulebase", "show-nat-rulebase"):
            rb_store = dom_map.get(rb_cmd)
            if not isinstance(rb_store, Mapping):
                continue
            for layer_val in rb_store.values():
                if not isinstance(layer_val, Mapping):
                    continue
                for entry in layer_val.get("objects-dictionary", []):
                    if isinstance(entry, Mapping) and entry.get("uid"):
                        uid = str(entry["uid"])
                        index.setdefault(
                            uid,
                            {
                                "uid": uid,
                                "name": str(entry.get("name") or uid),
                                "type": str(entry.get("type") or "object"),
                            },
                        )
    return index


def _inline_ref_item(val: Any, uid_index: Mapping[str, dict[str, Any]]) -> Any:
    """Resolve a rule column reference to an object summary dict when possible."""
    if isinstance(val, Mapping):
        copied = copy.deepcopy(dict(val))
        uid = str(copied.get("uid") or "")
        if uid and uid in uid_index and not copied.get("name"):
            copied["name"] = uid_index[uid]["name"]
            copied.setdefault("type", uid_index[uid].get("type"))
        return copied
    if isinstance(val, str) and val in uid_index:
        return copy.deepcopy(uid_index[val])
    return copy.deepcopy(val)


def _inline_rule_snapshot(
    rule: Mapping[str, Any],
    uid_index: Mapping[str, dict[str, Any]],
    *,
    rule_number: int,
    layer_name: str | None = None,
    package_name: str | None = None,
    section_name: str | None = None,
) -> dict[str, Any]:
    """Return a rule copy with resolved object summary dicts and placement context."""
    snap = copy.deepcopy(dict(rule))
    snap["rule-number"] = rule_number
    if layer_name:
        snap["layer"] = layer_name
    if package_name:
        snap["package"] = package_name
    if section_name:
        snap["section-name"] = section_name

    for field in _RULE_LIST_REF_FIELDS:
        raw_list = snap.get(field)
        if isinstance(raw_list, list):
            snap[field] = [_inline_ref_item(elem, uid_index) for elem in raw_list]

    for field in _RULE_SCALAR_REF_FIELDS:
        if field in snap:
            snap[field] = _inline_ref_item(snap[field], uid_index)

    track_val = snap.get("track")
    if isinstance(track_val, dict):
        t_type = track_val.get("type")
        if isinstance(t_type, str) and t_type in uid_index:
            resolved = copy.deepcopy(uid_index[t_type])
            track_val["type"] = resolved
            if isinstance(resolved.get("name"), str):
                track_val.setdefault("name", resolved["name"])
    return snap


def _compute_field_changes(
    old_obj: Mapping[str, Any],
    new_obj: Mapping[str, Any],
    *,
    ignore_keys: frozenset[str] = _IGNORED_DIFF_FIELDS,
) -> list[dict[str, Any]]:
    """Compute sorted Check Point `field-changes` entries between two snapshots."""
    diffs: list[dict[str, Any]] = []
    all_keys = sorted((set(old_obj.keys()) | set(new_obj.keys())) - ignore_keys)
    for key in all_keys:
        old_val = old_obj.get(key)
        new_val = new_obj.get(key)
        if old_val != new_val:
            diffs.append(
                {
                    "field-name": key,
                    "old-value": copy.deepcopy(old_val),
                    "new-value": copy.deepcopy(new_val),
                }
            )
    return diffs


def _lis_values(seq: list[int]) -> set[int]:
    """Return the set of values participating in a longest increasing subsequence of `seq`."""
    if not seq:
        return set()
    tails: list[int] = []
    parent: dict[int, int] = {}
    tail_vals: list[int] = []
    for val in seq:
        pos = bisect_left(tails, val)
        if pos == len(tails):
            tails.append(val)
            tail_vals.append(val)
        else:
            tails[pos] = val
            tail_vals[pos] = val
        if pos > 0:
            parent[val] = tail_vals[pos - 1]
    if not tail_vals:
        return set()
    keep: set[int] = set()
    curr: int | None = tail_vals[-1]
    while curr is not None:
        keep.add(curr)
        curr = parent.get(curr)
    return keep


def _layer_to_package_map(dom_map: Mapping[str, Any]) -> dict[str, str]:
    """Build `layer_uid/name -> package_name` map from `show-packages`."""
    out: dict[str, str] = {}
    raw_pkgs = dom_map.get("show-packages")
    packages = raw_pkgs.get("packages", []) if isinstance(raw_pkgs, Mapping) else []
    if not isinstance(packages, list):
        return out
    for pkg in packages:
        if not isinstance(pkg, Mapping):
            continue
        pkg_name = str(pkg.get("name") or "")
        if not pkg_name:
            continue
        for lyr in pkg.get("access-layers", []):
            if not isinstance(lyr, Mapping):
                continue
            if lyr.get("uid"):
                out[str(lyr["uid"])] = pkg_name
            if lyr.get("name"):
                out[str(lyr["name"])] = pkg_name
    return out


def compute_session_delta(
    before_dom: Mapping[str, Any],
    after_dom: Mapping[str, Any],
    *,
    global_before: Mapping[str, Any] | None = None,
    global_after: Mapping[str, Any] | None = None,
    session_meta: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute a Check Point `show-changes` delta dict between two domain snapshots."""
    uid_index = _build_uid_summary_index(after_dom, before_dom, global_after, global_before)

    added_objects: list[dict[str, Any]] = []
    modified_objects: list[dict[str, Any]] = []
    deleted_objects: list[dict[str, Any]] = []

    for spec in ENTITY_SPECS:
        before_raw = before_dom.get(spec.plural_show)
        after_raw = after_dom.get(spec.plural_show)
        before_items = before_raw.get("objects", []) if isinstance(before_raw, Mapping) else []
        after_items = after_raw.get("objects", []) if isinstance(after_raw, Mapping) else []

        before_by_uid = {str(o["uid"]): o for o in before_items if isinstance(o, Mapping) and o.get("uid")}
        after_by_uid = {str(o["uid"]): o for o in after_items if isinstance(o, Mapping) and o.get("uid")}

        for uid, new_obj in after_by_uid.items():
            if uid not in before_by_uid:
                added_objects.append(copy.deepcopy(dict(new_obj)))
            else:
                old_obj = before_by_uid[uid]
                field_changes = _compute_field_changes(old_obj, new_obj)
                if field_changes:
                    modified_objects.append(
                        {
                            "uid": uid,
                            "name": str(new_obj.get("name") or uid),
                            "type": str(new_obj.get("type") or spec.obj_type),
                            "old-object": copy.deepcopy(dict(old_obj)),
                            "new-object": copy.deepcopy(dict(new_obj)),
                            "field-changes": field_changes,
                        }
                    )

        for uid, old_obj in before_by_uid.items():
            if uid not in after_by_uid:
                deleted_objects.append(copy.deepcopy(dict(old_obj)))

    added_rules: list[dict[str, Any]] = []
    modified_rules: list[dict[str, Any]] = []
    deleted_rules: list[dict[str, Any]] = []

    layer_pkg_map = _layer_to_package_map(after_dom)
    layer_pkg_map.update(_layer_to_package_map(before_dom))

    def _diff_rulebase_bucket(rb_cmd: str, *, is_nat: bool) -> None:
        before_store = before_dom.get(rb_cmd)
        after_store = after_dom.get(rb_cmd)
        before_map = before_store if isinstance(before_store, Mapping) else {}
        after_map = after_store if isinstance(after_store, Mapping) else {}
        all_keys = list(dict.fromkeys([*before_map.keys(), *after_map.keys()]))

        for store_key in all_keys:
            raw_b = before_map.get(store_key)
            raw_a = after_map.get(store_key)
            b_layer: Mapping[str, Any] = raw_b if isinstance(raw_b, Mapping) else {}
            a_layer: Mapping[str, Any] = raw_a if isinstance(raw_a, Mapping) else {}

            layer_uid = str(a_layer.get("uid") or b_layer.get("uid") or store_key)
            layer_name = str(a_layer.get("name") or b_layer.get("name") or store_key)
            pkg_name = str(
                a_layer.get("package")
                or b_layer.get("package")
                or layer_pkg_map.get(layer_uid)
                or layer_pkg_map.get(layer_name)
                or ""
            )

            b_flat = _iter_flat_rules(b_layer.get("rulebase"))
            a_flat = _iter_flat_rules(a_layer.get("rulebase"))

            b_by_uid: dict[str, tuple[int, str | None, dict[str, Any]]] = {}
            for idx, (sec, r) in enumerate(b_flat, start=1):
                if r.get("uid"):
                    sec_name = str(sec.get("name")) if isinstance(sec, Mapping) and sec.get("name") else None
                    b_by_uid[str(r["uid"])] = (idx, sec_name, r)

            a_by_uid: dict[str, tuple[int, str | None, dict[str, Any]]] = {}
            a_common_b_positions: list[int] = []
            for idx, (sec, r) in enumerate(a_flat, start=1):
                if r.get("uid"):
                    r_uid = str(r["uid"])
                    sec_name = str(sec.get("name")) if isinstance(sec, Mapping) and sec.get("name") else None
                    a_by_uid[r_uid] = (idx, sec_name, r)
                    if r_uid in b_by_uid:
                        a_common_b_positions.append(b_by_uid[r_uid][0])

            lis_keep = _lis_values(a_common_b_positions)

            for r_uid, (new_num, new_sec, new_rule) in a_by_uid.items():
                eff_layer = None if is_nat else layer_name
                eff_pkg = pkg_name or (layer_name if is_nat else "")
                new_snap = _inline_rule_snapshot(
                    new_rule,
                    uid_index,
                    rule_number=new_num,
                    layer_name=eff_layer,
                    package_name=eff_pkg or None,
                    section_name=new_sec,
                )
                if r_uid not in b_by_uid:
                    added_rules.append(new_snap)
                    continue

                old_num, old_sec, old_rule = b_by_uid[r_uid]
                old_snap = _inline_rule_snapshot(
                    old_rule,
                    uid_index,
                    rule_number=old_num,
                    layer_name=eff_layer,
                    package_name=eff_pkg or None,
                    section_name=old_sec,
                )
                explicitly_reordered = old_num not in lis_keep or old_sec != new_sec
                content_ignore = _IGNORED_DIFF_FIELDS | frozenset({"rule-number"})
                field_changes = _compute_field_changes(old_snap, new_snap, ignore_keys=content_ignore)
                if explicitly_reordered and old_num != new_num:
                    field_changes.append(
                        {
                            "field-name": "rule-number",
                            "old-value": old_num,
                            "new-value": new_num,
                        }
                    )
                if field_changes or explicitly_reordered:
                    mod_entry: dict[str, Any] = {
                        "uid": r_uid,
                        "name": str(new_rule.get("name") or old_rule.get("name") or ""),
                        "type": str(new_rule.get("type") or ("nat-rule" if is_nat else "access-rule")),
                        "old-object": old_snap,
                        "new-object": new_snap,
                        "field-changes": field_changes,
                        "rule-number": new_num,
                        "old-rule-number": old_num,
                        "moved": old_num != new_num and explicitly_reordered,
                    }
                    if eff_layer:
                        mod_entry["layer"] = eff_layer
                    if eff_pkg:
                        mod_entry["package"] = eff_pkg
                    modified_rules.append(mod_entry)

            for r_uid, (old_num, old_sec, old_rule) in b_by_uid.items():
                if r_uid not in a_by_uid:
                    eff_layer = None if is_nat else layer_name
                    eff_pkg = pkg_name or (layer_name if is_nat else "")
                    deleted_rules.append(
                        _inline_rule_snapshot(
                            old_rule,
                            uid_index,
                            rule_number=old_num,
                            layer_name=eff_layer,
                            package_name=eff_pkg or None,
                            section_name=old_sec,
                        )
                    )

    _diff_rulebase_bucket("show-access-rulebase", is_nat=False)
    _diff_rulebase_bucket("show-nat-rulebase", is_nat=True)

    container: dict[str, Any] = {
        "added-objects": added_objects,
        "modified-objects": modified_objects,
        "deleted-objects": deleted_objects,
        "added-rules": added_rules,
        "modified-rules": modified_rules,
        "deleted-rules": deleted_rules,
    }
    if session_meta is not None:
        container["session"] = copy.deepcopy(dict(session_meta))
    return container


def count_delta_items(delta: Mapping[str, Any]) -> int:
    """Count total object and rule change items inside a `show-changes` delta container."""
    keys = (
        "added-objects",
        "modified-objects",
        "deleted-objects",
        "added-rules",
        "modified-rules",
        "deleted-rules",
    )
    return sum(len(delta.get(k, [])) for k in keys if isinstance(delta.get(k), list))


def parse_checkpoint_date_ms(value: Any) -> int | None:
    """Parse an ISO-8601 date string or posix int/dict into epoch milliseconds."""
    if value is None:
        return None
    if isinstance(value, Mapping):
        if "posix" in value:
            return int(value["posix"])
        if "iso-8601" in value:
            value = value["iso-8601"]
    if isinstance(value, (int, float)):
        raw = int(value)
        return raw * 1000 if raw < 10_000_000_000 else raw
    text = str(value).strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    if len(normalized) >= 5 and normalized[-5] in ("+", "-") and ":" not in normalized[-5:]:
        normalized = f"{normalized[:-2]}:{normalized[-2:]}"
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    return int(dt.timestamp() * 1000)


def build_show_changes_task(task_id: str, change_entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a Check Point `show-changes` task object matching `ChangeReportCollector`."""
    return {
        "uid": task_id,
        "task-id": task_id,
        "task-name": "show-changes",
        "status": "succeeded",
        "progress-percentage": 100,
        "suppressed": False,
        "task-details": [
            {
                "uid": f"td-{task_id}",
                "statusDescription": "Succeeded",
                "changes": copy.deepcopy(change_entries),
            }
        ],
    }
