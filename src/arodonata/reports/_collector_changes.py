"""Change-container parsing, UID substitution, and range filtering (`arodonata.reports._collector_changes`)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from arodonata.core.errors import sanitize_mapping
from arodonata.core.models.common import parse_cp_publish_timestamp, to_naive_utc
from arodonata.reports._collector_diffs import (
    RULE_OBJECT_TYPES,
    _build_object_summary_fields,
    _collect_known_names_from_operations,
    _extract_field_diffs,
    _extract_ref_list,
    _extract_ref_str_or_uid,
    _extract_track_str,
    _format_object_summary_from_fields,
    _is_system_maintenance_object,
    _rulebase_type_from_obj_type,
    _synthesize_object_snapshot_diffs,
    _synthesize_rule_snapshot_diffs,
    is_bare_uid,
)
from arodonata.reports.models import (
    ChangeOperation,
    ObjectChangeEntry,
    RangeScope,
    RuleChangeEntry,
    SessionChangeReport,
)


def _extract_session_user_from_changes(
    data: dict[str, Any],
    *,
    session_uid: str | None = None,
) -> str:
    """Extract `user-name` from a `show-changes` response's `changes[].session` block if present."""
    containers: list[dict[str, Any]] = []
    if isinstance(data.get("tasks"), list):
        for task in data["tasks"]:
            if isinstance(task, dict) and isinstance(task.get("task-details"), list):
                for detail in task["task-details"]:
                    if isinstance(detail, dict) and isinstance(detail.get("changes"), list):
                        for ch in detail["changes"]:
                            if isinstance(ch, dict):
                                containers.append(ch)
    if isinstance(data.get("changes"), list):
        for ch in data["changes"]:
            if isinstance(ch, dict):
                containers.append(ch)
    for c in containers:
        sess_dict = c.get("session")
        if isinstance(sess_dict, dict):
            c_uid = str(sess_dict.get("session-uid") or sess_dict.get("uid") or "")
            if session_uid and c_uid and c_uid != session_uid:
                continue
            u_name = str(sess_dict.get("user-name") or sess_dict.get("user") or "").strip()
            if u_name:
                return u_name
    return ""


def _parse_change_containers(
    data: dict[str, Any],
    *,
    session_uid: str | None = None,
) -> list[dict[str, Any]]:
    """Extract normalized operation containers from a `show-changes` response payload."""
    containers: list[dict[str, Any]] = []
    if isinstance(data.get("tasks"), list):
        for task in data["tasks"]:
            if isinstance(task, dict) and isinstance(task.get("task-details"), list):
                for detail in task["task-details"]:
                    if isinstance(detail, dict):
                        if isinstance(detail.get("changes"), list):
                            for ch in detail["changes"]:
                                if isinstance(ch, dict):
                                    containers.append(ch)
                        else:
                            containers.append(detail)
    if isinstance(data.get("changes"), list):
        for ch in data["changes"]:
            if isinstance(ch, dict):
                containers.append(ch)
    if isinstance(data.get("operations"), dict) or any(
        k in data
        for k in (
            "added-objects",
            "modified-objects",
            "deleted-objects",
            "added-rules",
            "modified-rules",
            "deleted-rules",
        )
    ):
        containers.append(data)

    ops_list: list[dict[str, Any]] = []
    for c in containers:
        if session_uid:
            sess_dict = c.get("session")
            if isinstance(sess_dict, dict):
                c_uid = str(sess_dict.get("session-uid") or sess_dict.get("uid") or "")
                if c_uid and c_uid != session_uid:
                    continue
        ops = c.get("operations")
        ops_list.append(ops if isinstance(ops, dict) else c)
    return ops_list


def _parse_rule_and_object_changes(
    ops_list: list[dict[str, Any]],
    known_names: dict[str, str],
    bare_uids_out: set[str],
    *,
    session_user_name: str = "",
    include_system_objects: bool = False,
) -> tuple[list[RuleChangeEntry], list[ObjectChangeEntry], int]:
    """Parse `RuleChangeEntry` and `ObjectChangeEntry` models from `show-changes` operation buckets."""
    _collect_known_names_from_operations(ops_list, known_names)

    rules: list[RuleChangeEntry] = []
    objects: list[ObjectChangeEntry] = []
    filtered_system_count = 0

    bucket_specs: list[tuple[str, ChangeOperation, bool]] = [
        ("added-rules", "added", True),
        ("added_rules", "added", True),
        ("modified-rules", "modified", True),
        ("modified_rules", "modified", True),
        ("deleted-rules", "deleted", True),
        ("deleted_rules", "deleted", True),
        ("added-objects", "added", False),
        ("added_objects", "added", False),
        ("modified-objects", "modified", False),
        ("modified_objects", "modified", False),
        ("deleted-objects", "deleted", False),
        ("deleted_objects", "deleted", False),
    ]

    for ops in ops_list:
        for bucket_key, bucket_op, force_rule in bucket_specs:
            items = ops.get(bucket_key)
            if not isinstance(items, list):
                continue
            for raw in items:
                if not isinstance(raw, dict):
                    continue
                old_core = raw.get("old-object") if isinstance(raw.get("old-object"), dict) else {}
                if isinstance(raw.get("new-object"), dict):
                    core = raw["new-object"]
                elif bucket_op == "deleted" and old_core:
                    core = old_core
                else:
                    core = raw
                assert isinstance(core, dict)
                assert isinstance(old_core, dict)
                op: ChangeOperation = (
                    "added"
                    if (bucket_op == "modified" and isinstance(raw.get("new-object"), dict) and not old_core)
                    else bucket_op
                )

                uid = str(core.get("uid") or raw.get("uid") or old_core.get("uid") or "")
                name = str(core.get("name") or raw.get("name") or old_core.get("name") or "")
                obj_type = str(core.get("type") or raw.get("type") or old_core.get("type") or "object")

                is_rule = force_rule or obj_type.lower() in RULE_OBJECT_TYPES or obj_type.lower().endswith("-rule")
                if (
                    not is_rule
                    and not include_system_objects
                    and _is_system_maintenance_object(raw, core, old_core, op=op, session_user_name=session_user_name)
                ):
                    filtered_system_count += 1
                    continue

                f_diffs = _extract_field_diffs(raw, known_names, bare_uids_out)
                existing_diff_fields = {d.field_name.strip().lower() for d in f_diffs}

                if is_rule:
                    if op == "modified" and old_core:
                        f_diffs.extend(
                            _synthesize_rule_snapshot_diffs(
                                old_core, core, existing_diff_fields, known_names, bare_uids_out
                            )
                        )
                    rb_type = _rulebase_type_from_obj_type(obj_type)
                    layer_raw = core.get("layer") or raw.get("layer") or old_core.get("layer")
                    layer_uid = ""
                    layer_name = ""
                    if isinstance(layer_raw, dict):
                        layer_uid = str(layer_raw.get("uid") or "")
                        layer_name = str(layer_raw.get("name") or "")
                    elif isinstance(layer_raw, str):
                        if is_bare_uid(layer_raw):
                            layer_uid = layer_raw
                            layer_name = known_names.get(layer_raw, "")
                        else:
                            layer_name = layer_raw
                            layer_uid = layer_raw
                    if not layer_uid and isinstance(core.get("layer-uid") or raw.get("layer_uid"), str):
                        layer_uid = str(core.get("layer-uid") or raw.get("layer_uid"))
                    if not layer_name and isinstance(core.get("layer-name") or raw.get("layer_name"), str):
                        layer_name = str(core.get("layer-name") or raw.get("layer_name"))
                    if not layer_name and is_bare_uid(layer_uid):
                        if layer_uid in known_names:
                            layer_name = known_names[layer_uid]
                        else:
                            bare_uids_out.add(layer_uid)

                    pkg_raw = core.get("package") or raw.get("package") or old_core.get("package")
                    pkg_uid: str | None = None
                    pkg_name: str | None = None
                    if isinstance(pkg_raw, dict):
                        pkg_uid = str(pkg_raw.get("uid") or "") or None
                        pkg_name = str(pkg_raw.get("name") or "") or None
                    elif isinstance(pkg_raw, str) and pkg_raw:
                        pkg_name = pkg_raw
                        pkg_uid = pkg_raw

                    rule_num_raw = core.get("rule-number") or raw.get("rule-number") or raw.get("rule_number")
                    old_num_raw = (
                        old_core.get("rule-number") or raw.get("old-rule-number") or raw.get("old_rule_number")
                    )
                    rule_num = str(rule_num_raw) if rule_num_raw is not None else None
                    old_rule_num = str(old_num_raw) if old_num_raw is not None else None
                    moved = bool(
                        raw.get("moved", False)
                        or (rule_num and old_rule_num and rule_num != old_rule_num)
                        or any(d.field_name in ("rule-number", "position") for d in f_diffs)
                    )
                    non_move_diffs = [d for d in f_diffs if d.field_name.lower() not in ("rule-number", "position")]
                    eff_op: ChangeOperation = "moved" if (op == "modified" and moved and not non_move_diffs) else op

                    rules.append(
                        RuleChangeEntry(
                            uid=uid or f"rule:{len(rules) + 1}",
                            name=name,
                            operation=eff_op,
                            rulebase_type=rb_type,
                            package_uid=pkg_uid,
                            package_name=pkg_name,
                            layer_uid=layer_uid,
                            layer_name=layer_name,
                            section_uid=str(core["section-uid"]) if core.get("section-uid") else None,
                            section_name=str(core["section-name"]) if core.get("section-name") else None,
                            rule_number=rule_num,
                            old_rule_number=old_rule_num,
                            moved=moved,
                            enabled=bool(core.get("enabled", True)),
                            action=_extract_ref_str_or_uid(core.get("action"), known_names, bare_uids_out),
                            method=str(core["method"]) if core.get("method") is not None else None,
                            source=_extract_ref_list(core.get("source"), known_names, bare_uids_out),
                            destination=_extract_ref_list(core.get("destination"), known_names, bare_uids_out),
                            service=_extract_ref_list(core.get("service"), known_names, bare_uids_out),
                            source_negate=bool(core.get("source-negate", False)),
                            destination_negate=bool(core.get("destination-negate", False)),
                            service_negate=bool(core.get("service-negate", False)),
                            original_source=_extract_ref_str_or_uid(
                                core.get("original-source"), known_names, bare_uids_out
                            ),
                            original_destination=_extract_ref_str_or_uid(
                                core.get("original-destination"), known_names, bare_uids_out
                            ),
                            original_service=_extract_ref_str_or_uid(
                                core.get("original-service"), known_names, bare_uids_out
                            ),
                            translated_source=_extract_ref_str_or_uid(
                                core.get("translated-source"), known_names, bare_uids_out
                            ),
                            translated_destination=_extract_ref_str_or_uid(
                                core.get("translated-destination"), known_names, bare_uids_out
                            ),
                            translated_service=_extract_ref_str_or_uid(
                                core.get("translated-service"), known_names, bare_uids_out
                            ),
                            track=_extract_track_str(core.get("track"), known_names, bare_uids_out),
                            install_on=_extract_ref_list(core.get("install-on"), known_names, bare_uids_out),
                            comments=str(core.get("comments") or ""),
                            field_diffs=f_diffs,
                            raw_data=sanitize_mapping(dict(raw)),
                        )
                    )
                else:
                    if op == "modified" and old_core:
                        f_diffs.extend(
                            _synthesize_object_snapshot_diffs(
                                old_core, core, existing_diff_fields, known_names, bare_uids_out
                            )
                        )
                    members = _extract_ref_list(core.get("members"), known_names, bare_uids_out)
                    nat_settings = core.get("nat-settings") or core.get("nat_settings")
                    if isinstance(nat_settings, dict):
                        for nk in ("ipv4-address", "install-on", "hide-behind-ip"):
                            if nk in nat_settings:
                                _extract_ref_str_or_uid(nat_settings[nk], known_names, bare_uids_out)

                    summary_fields = _build_object_summary_fields(core, members)
                    objects.append(
                        ObjectChangeEntry(
                            uid=uid or f"obj:{len(objects) + 1}",
                            name=name,
                            object_type=obj_type,
                            operation=op,
                            summary=_format_object_summary_from_fields(summary_fields),
                            summary_fields=summary_fields,
                            field_diffs=f_diffs,
                            raw_data=sanitize_mapping(dict(raw)),
                        )
                    )

    return rules, objects, filtered_system_count


def _replace_resolved_uids_in_session(
    session_report: SessionChangeReport,
    resolved: dict[str, str],
) -> None:
    """Substitute resolved UID->name mappings into rule and object change fields and diffs."""
    if not resolved:
        return

    def _sub(val: str | None) -> str | None:
        return resolved[val] if (val is not None and val in resolved) else val

    def _sub_list(items: list[str]) -> list[str]:
        return [resolved.get(x, x) for x in items]

    def _sub_any(val: Any) -> Any:
        if isinstance(val, str):
            return resolved.get(val, val)
        if isinstance(val, list):
            return [_sub_any(x) for x in val]
        return val

    for rc in session_report.rule_changes:
        if not rc.layer_name and rc.layer_uid in resolved:
            rc.layer_name = resolved[rc.layer_uid]
        rc.action = _sub(rc.action)
        rc.track = _sub(rc.track)
        rc.source = _sub_list(rc.source)
        rc.destination = _sub_list(rc.destination)
        rc.service = _sub_list(rc.service)
        rc.original_source = _sub(rc.original_source)
        rc.original_destination = _sub(rc.original_destination)
        rc.original_service = _sub(rc.original_service)
        rc.translated_source = _sub(rc.translated_source)
        rc.translated_destination = _sub(rc.translated_destination)
        rc.translated_service = _sub(rc.translated_service)
        rc.install_on = _sub_list(rc.install_on)
        for fd in rc.field_diffs:
            fd.old_value = _sub_any(fd.old_value)
            fd.new_value = _sub_any(fd.new_value)
            fd.added_items = _sub_list(fd.added_items)
            fd.removed_items = _sub_list(fd.removed_items)

    for oc in session_report.object_changes:
        if oc.summary_fields:
            for k, v in list(oc.summary_fields.items()):
                oc.summary_fields[k] = _sub_any(v)
            oc.summary = _format_object_summary_from_fields(oc.summary_fields)
        else:
            for uid, name in resolved.items():
                if uid in oc.summary:
                    oc.summary = oc.summary.replace(uid, name)
        for fd in oc.field_diffs:
            fd.old_value = _sub_any(fd.old_value)
            fd.new_value = _sub_any(fd.new_value)
            fd.added_items = _sub_list(fd.added_items)
            fd.removed_items = _sub_list(fd.removed_items)


def _filter_range_sessions(
    sessions: list[dict[str, Any]],
    scope: RangeScope,
) -> list[dict[str, Any]]:
    """Filter `show-sessions` objects by exact UTC publish timestamp and optional `from_session` / `to_session`."""
    with_ts: list[tuple[datetime | None, int, dict[str, Any]]] = []
    for idx, s in enumerate(sessions):
        pub_dt = parse_cp_publish_timestamp(s.get("publish-time") or s.get("last-modify-time"))
        with_ts.append((pub_dt, idx, s))

    uid_to_dt: dict[str, datetime] = {str(s.get("uid")): dt for dt, _, s in with_ts if dt is not None and s.get("uid")}
    from_bound_dt = to_naive_utc(scope.from_date)
    to_bound_dt = to_naive_utc(scope.to_date)

    if scope.from_session and scope.from_session in uid_to_dt:
        s_dt = uid_to_dt[scope.from_session]
        from_bound_dt = max(from_bound_dt, s_dt) if from_bound_dt is not None else s_dt
    if scope.to_session and scope.to_session in uid_to_dt:
        s_dt = uid_to_dt[scope.to_session]
        to_bound_dt = min(to_bound_dt, s_dt) if to_bound_dt is not None else s_dt

    uids_in_order = [str(s.get("uid") or "") for _, _, s in with_ts]
    allowed_uids: set[str] | None = None
    if (scope.from_session and scope.from_session not in uid_to_dt) or (
        scope.to_session and scope.to_session not in uid_to_dt
    ):
        start_idx = 0
        end_idx = len(uids_in_order) - 1
        if scope.from_session and scope.from_session in uids_in_order:
            start_idx = uids_in_order.index(scope.from_session)
        if scope.to_session and scope.to_session in uids_in_order:
            end_idx = uids_in_order.index(scope.to_session)
        lo, hi = min(start_idx, end_idx), max(start_idx, end_idx)
        allowed_uids = set(uids_in_order[lo : hi + 1])

    filtered: list[dict[str, Any]] = []
    for pub_dt, _idx, s in with_ts:
        s_uid = str(s.get("uid") or "")
        if allowed_uids is not None and s_uid not in allowed_uids:
            continue
        if from_bound_dt is not None and (pub_dt is None or pub_dt < from_bound_dt):
            continue
        if to_bound_dt is not None and (pub_dt is None or pub_dt > to_bound_dt):
            continue
        filtered.append(s)

    return filtered
