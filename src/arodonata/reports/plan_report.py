"""Offline Dry-Run `ChangeReport` synthesis from a CPCRUD `Plan` (`arodonata.reports.plan_report`)."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from arodonata.core.errors import redact_sid, sanitize_mapping
from arodonata.core.models.rulebase import RulebaseType
from arodonata.core.telemetry import span_attrs, traced
from arodonata.cpcrud.models import FieldChange, Outcome, Plan, PlannedAction
from arodonata.reports.models import (
    ChangeOperation,
    ChangeReport,
    FieldDiff,
    ObjectChangeEntry,
    ReportWarning,
    RuleChangeEntry,
    SessionChangeReport,
)


def _compute_post_delta_list(
    old_items: list[str],
    added_items: list[str],
    removed_items: list[str],
) -> list[str]:
    rem_set = set(removed_items)
    kept = [x for x in old_items if x not in rem_set]
    return list(dict.fromkeys([*kept, *added_items]))


def _convert_field_change(fc: FieldChange) -> FieldDiff:
    old_val = fc.old_value
    new_val = fc.new_value
    added = list(fc.added_items)
    removed = list(fc.removed_items)

    if isinstance(old_val, list) and isinstance(new_val, Mapping) and ("add" in new_val or "remove" in new_val):
        old_list = [str(x) for x in old_val]
        if not added and isinstance(new_val.get("add"), list):
            added = [str(x) for x in new_val["add"]]
        if not removed and isinstance(new_val.get("remove"), list):
            removed = [str(x) for x in new_val["remove"]]
        post_list = _compute_post_delta_list(old_list, added, removed)
        return FieldDiff(
            field_name=fc.field,
            old_value=old_list,
            new_value=post_list,
            added_items=added,
            removed_items=removed,
        )

    if isinstance(old_val, list) and isinstance(new_val, list):
        old_list = [str(x) for x in old_val]
        new_list = [str(x) for x in new_val]
        if not added and not removed:
            old_set = set(old_list)
            new_set = set(new_list)
            added = list(dict.fromkeys(x for x in new_list if x not in old_set))
            removed = list(dict.fromkeys(x for x in old_list if x not in new_set))
        return FieldDiff(
            field_name=fc.field,
            old_value=old_list,
            new_value=new_list,
            added_items=added,
            removed_items=removed,
        )

    return FieldDiff(
        field_name=fc.field,
        old_value=old_val,
        new_value=new_val,
        added_items=added,
        removed_items=removed,
    )


def _map_outcome_to_op(outcome: Outcome) -> ChangeOperation:
    if outcome == Outcome.CREATE:
        return "added"
    if outcome == Outcome.DELETE:
        return "deleted"
    return "modified"


def _is_rule_action(act: PlannedAction) -> bool:
    low = act.object_type.strip().lower()
    return low.endswith("-rule") or low in ("access", "nat", "https", "threat")


def _rulebase_type_from_action(act: PlannedAction) -> RulebaseType:
    low = act.object_type.strip().lower()
    if "nat" in low:
        return "nat"
    if "https" in low:
        return "https"
    if "threat" in low:
        return "threat"
    return "access"


def _as_str_list(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x) for x in val if x is not None and str(x) != ""]
    if isinstance(val, Mapping):
        adds = val.get("add")
        if isinstance(adds, list):
            return [str(x) for x in adds if x is not None and str(x) != ""]
        return []
    return [str(val)] if str(val) else []


def _format_plan_object_summary(fields: Mapping[str, Any]) -> str:
    parts: list[str] = []
    if fields.get("ipv4-address") is not None:
        parts.append(f"ipv4-address={fields['ipv4-address']}")
    if fields.get("ipv6-address") is not None:
        parts.append(f"ipv6-address={fields['ipv6-address']}")
    if fields.get("subnet4") is not None:
        if fields.get("mask-length4") is not None:
            parts.append(f"subnet4={fields['subnet4']}/{fields['mask-length4']}")
        elif fields.get("subnet-mask") is not None:
            parts.append(f"subnet4={fields['subnet4']}/{fields['subnet-mask']}")
        else:
            parts.append(f"subnet4={fields['subnet4']}")
    if fields.get("ipv4-address-first") is not None or fields.get("ipv4-address-last") is not None:
        parts.append(f"range={fields.get('ipv4-address-first', '')}-{fields.get('ipv4-address-last', '')}")
    for key in ("port", "protocol", "fqdn", "primary-category"):
        if fields.get(key) is not None:
            parts.append(f"{key}={fields[key]}")
    for list_key in ("url-list", "members"):
        vals = fields.get(list_key)
        if isinstance(vals, list) and vals:
            parts.append(f"{list_key}=[{', '.join(str(v) for v in vals)}]")
    comments = str(fields.get("comments") or "").strip()
    if comments:
        parts.append(f"comments={comments}")
    return ", ".join(parts)


def _canonical_list_field_key(raw_key: str) -> str:
    dashed = raw_key.replace("_", "-")
    if dashed in ("url-list", "install-on", "protected-scope", "site-category"):
        return dashed
    return raw_key


def _lookup_list_value(mapping: Mapping[str, Any], canon_key: str, raw_key: str) -> Any:
    for candidate in (canon_key, raw_key, canon_key.replace("-", "_")):
        if candidate in mapping:
            return mapping[candidate]
    return None


def _merge_action_state(act: PlannedAction, diff_by_name: Mapping[str, FieldDiff]) -> dict[str, Any]:
    prior: dict[str, Any] = dict(act.prior_state or {})
    merged: dict[str, Any] = dict(prior)
    for layer_map in (act.desired_spec or {}, act.payload or {}):
        for raw_key, val in layer_map.items():
            if isinstance(val, Mapping) and ("add" in val or "remove" in val):
                canon_key = _canonical_list_field_key(raw_key)
                raw_prior = _lookup_list_value(prior, canon_key, raw_key)
                prior_items = [str(x) for x in raw_prior] if isinstance(raw_prior, list) else []
                adds = [str(x) for x in (val.get("add") or []) if x is not None and str(x) != ""]
                rems = [str(x) for x in (val.get("remove") or []) if x is not None and str(x) != ""]
                if [x.lower() for x in prior_items] == ["any"] and any(x.lower() != "any" for x in adds):
                    prior_items = []
                merged[canon_key] = _compute_post_delta_list(prior_items, adds, rems)
                if raw_key != canon_key:
                    merged.pop(raw_key, None)
            else:
                merged[raw_key] = val
    for f_key, f_diff in diff_by_name.items():
        merged[f_key] = f_diff.new_value
    return merged


def _action_to_object_entry(act: PlannedAction, field_diffs: list[FieldDiff]) -> ObjectChangeEntry:
    diff_by_name = {d.field_name.lower(): d for d in field_diffs}
    merged = _merge_action_state(act, diff_by_name)

    summary_fields: dict[str, Any] = {}
    for scalar_key in (
        "ipv4-address",
        "ipv6-address",
        "subnet4",
        "mask-length4",
        "subnet-mask",
        "ipv4-address-first",
        "ipv4-address-last",
        "port",
        "protocol",
        "fqdn",
        "primary-category",
    ):
        val = merged.get(scalar_key)
        if val is None:
            val = merged.get(scalar_key.replace("-", "_"))
        if val is not None:
            summary_fields[scalar_key] = val

    for list_key in ("url-list", "members"):
        if list_key in diff_by_name and isinstance(diff_by_name[list_key].new_value, list):
            summary_fields[list_key] = list(diff_by_name[list_key].new_value)
        else:
            raw_l = merged.get(list_key) if list_key in merged else merged.get(list_key.replace("-", "_"))
            str_l = _as_str_list(raw_l)
            if str_l:
                summary_fields[list_key] = str_l

    comments_val = str(merged.get("comments") or "").strip()
    if comments_val:
        summary_fields["comments"] = redact_sid(comments_val)

    summary_text = redact_sid(_format_plan_object_summary(summary_fields))
    raw_data = sanitize_mapping(
        {
            "action_id": act.action_id,
            "outcome": act.outcome.value,
            "command": act.command,
            "payload": act.payload,
            "desired_spec": act.desired_spec,
        }
    )

    return ObjectChangeEntry(
        uid=act.target_uid or act.action_id,
        name=redact_sid(act.resolved_name or act.name),
        object_type=act.object_type,
        operation=_map_outcome_to_op(act.outcome),
        summary=summary_text,
        summary_fields=sanitize_mapping(summary_fields),
        field_diffs=field_diffs,
        raw_data=raw_data,
    )


def _extract_track_display(track_val: Any) -> str | None:
    if track_val is None:
        return None
    if isinstance(track_val, Mapping):
        t = track_val.get("type") or track_val.get("name")
        return str(t) if t is not None else None
    return str(track_val)


def _action_to_rule_entry(act: PlannedAction, field_diffs: list[FieldDiff]) -> RuleChangeEntry:
    diff_by_name = {d.field_name.lower(): d for d in field_diffs}
    merged = _merge_action_state(act, diff_by_name)

    rb_type = _rulebase_type_from_action(act)
    layer_name = str(act.layer or merged.get("layer") or "")
    package_name = str(act.package or merged.get("package") or "") or None

    raw_rule_num = merged.get("rule_number") if "rule_number" in merged else merged.get("rule-number")
    rule_number: str | None = None
    if isinstance(raw_rule_num, int) and not isinstance(raw_rule_num, bool):
        rule_number = str(raw_rule_num)
    elif isinstance(raw_rule_num, str) and re.fullmatch(r"\d+(?:\.\d+)*", raw_rule_num.strip()):
        rule_number = raw_rule_num.strip()
    else:
        raw_pos = merged.get("position")
        if isinstance(raw_pos, int) and not isinstance(raw_pos, bool):
            rule_number = str(raw_pos)

    raw_act = merged.get("rule_action") or merged.get("action")
    if isinstance(raw_act, str) and raw_act.lower() in ("present", "absent", "add", "set", "update", "delete"):
        raw_act = (act.prior_state or {}).get("rule_action") or merged.get("rule_action")

    def _cell_list(field_key: str, *, default_any: bool = False) -> list[str]:
        if field_key in diff_by_name and isinstance(diff_by_name[field_key].new_value, list):
            return [str(x) for x in diff_by_name[field_key].new_value]
        val = merged.get(field_key) if field_key in merged else merged.get(field_key.replace("-", "_"))
        items = _as_str_list(val)
        if not items and default_any:
            return ["Any"]
        return items

    raw_data = sanitize_mapping(
        {
            "action_id": act.action_id,
            "outcome": act.outcome.value,
            "command": act.command,
            "payload": act.payload,
            "desired_spec": act.desired_spec,
        }
    )

    return RuleChangeEntry(
        uid=act.target_uid or act.action_id,
        name=redact_sid(str(merged.get("new-name") or act.resolved_name or act.name)),
        operation=_map_outcome_to_op(act.outcome),
        rulebase_type=rb_type,
        package_name=package_name,
        layer_name=layer_name,
        rule_number=rule_number,
        enabled=bool(merged.get("enabled", True)),
        action=str(raw_act) if raw_act is not None else None,
        method=str(merged["method"]) if merged.get("method") is not None else None,
        source=_cell_list("source", default_any=(rb_type != "nat")),
        destination=_cell_list("destination", default_any=(rb_type != "nat")),
        service=_cell_list("service", default_any=(rb_type != "nat")),
        source_negate=bool(merged.get("source-negate", merged.get("source_negate", False))),
        destination_negate=bool(merged.get("destination-negate", merged.get("destination_negate", False))),
        service_negate=bool(merged.get("service-negate", merged.get("service_negate", False))),
        original_source=str(merged["original-source"]) if merged.get("original-source") is not None else None,
        original_destination=(
            str(merged["original-destination"]) if merged.get("original-destination") is not None else None
        ),
        original_service=str(merged["original-service"]) if merged.get("original-service") is not None else None,
        translated_source=str(merged["translated-source"]) if merged.get("translated-source") is not None else None,
        translated_destination=(
            str(merged["translated-destination"]) if merged.get("translated-destination") is not None else None
        ),
        translated_service=(
            str(merged["translated-service"]) if merged.get("translated-service") is not None else None
        ),
        track=_extract_track_display(merged.get("track")),
        install_on=_cell_list("install-on"),
        comments=redact_sid(str(merged.get("comments") or "")),
        field_diffs=field_diffs,
        raw_data=raw_data,
    )


@traced
def build_change_report_from_plan(
    plan: Plan,
    *,
    title: str | None = None,
    header_fields: Mapping[str, str] | None = None,
    include_unchanged: bool = False,
) -> ChangeReport:
    """Synthesize an offline `ChangeReport` directly from a CPCRUD `Plan` for dry-run previews."""
    span_attrs(action_count=len(plan.actions), include_unchanged=include_unchanged)
    eff_title = redact_sid(title) if title is not None else "Check Point Dry-Run Policy Change Plan"
    eff_headers = sanitize_mapping({str(k): redact_sid(str(v)) for k, v in (header_fields or {}).items()})

    domain_order: list[tuple[str, str]] = []
    actions_by_domain: dict[tuple[str, str], list[PlannedAction]] = defaultdict(list)
    for act in plan.actions:
        key = (act.mgmt_name, act.domain_name)
        if key not in actions_by_domain:
            domain_order.append(key)
        actions_by_domain[key].append(act)

    sessions: list[SessionChangeReport] = []
    warnings: list[ReportWarning] = []

    for mgmt_name, dom_name in domain_order:
        dom_actions = actions_by_domain[(mgmt_name, dom_name)]
        rule_changes: list[RuleChangeEntry] = []
        object_changes: list[ObjectChangeEntry] = []

        for act in dom_actions:
            if act.outcome in (Outcome.ERROR, Outcome.SKIPPED_DEPENDENCY, Outcome.PLAN_STALE):
                warn_msg = redact_sid(
                    str(act.error or act.message or f"Planned action {act.action_id} ended in {act.outcome.value}")
                )
                warnings.append(
                    ReportWarning(
                        code="partial_failure",
                        message=warn_msg,
                        mgmt_name=mgmt_name or None,
                        domain=dom_name or None,
                        details=sanitize_mapping(
                            {
                                "action_id": act.action_id,
                                "object_type": act.object_type,
                                "name": redact_sid(act.name),
                                "outcome": act.outcome.value,
                            }
                        ),
                    )
                )
                continue

            if act.outcome in (Outcome.UNCHANGED, Outcome.REUSE, Outcome.SKIPPED) and not include_unchanged:
                continue

            field_diffs = [_convert_field_change(fc) for fc in act.diffs.values()]
            if _is_rule_action(act):
                rule_changes.append(_action_to_rule_entry(act, field_diffs))
            else:
                object_changes.append(_action_to_object_entry(act, field_diffs))

        if rule_changes or object_changes or include_unchanged:
            sessions.append(
                SessionChangeReport(
                    mgmt_name=mgmt_name or "default",
                    domain_name=dom_name,
                    session_uid="dry-run-plan",
                    session_name="Dry-Run Plan Preview",
                    state="dry-run",
                    changes_count=len(rule_changes) + len(object_changes),
                    numbering_source="not_applicable",
                    numbering_basis="Dry-run preview synthesized offline from CPCRUD Plan (no Check Point write session opened)",
                    rule_changes=rule_changes,
                    object_changes=object_changes,
                    resolved_names=dict(plan.name_resolutions),
                )
            )

    return ChangeReport(
        generated_at=plan.created_at,
        title=eff_title,
        header_fields=eff_headers,
        sessions=sessions,
        warnings=warnings,
    )


__all__ = [
    "build_change_report_from_plan",
]
