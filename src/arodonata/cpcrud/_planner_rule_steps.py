"""Rulebase step planning helper (`arodonata.cpcrud._planner_rule_steps`)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from arodonata.core.errors import redact_sid
from arodonata.cpcrud._planner_helpers import (
    LOOKUP_ERROR_PREFIX,
    _build_add_rule_payload,
    _build_prior_rule_state,
    _make_error_action,
    _normalize_verb,
    _resolve_rulebase_type,
)
from arodonata.cpcrud.differ import DiffSafetyError, compute_rule_diff
from arodonata.cpcrud.models import ConflictPolicy, Outcome, PlannedAction
from arodonata.cpcrud.position_helper import resolve_rule_position
from arodonata.cpcrud.rule_identity import RuleEntryUnion, match_rule, rule_spec_has_delta_mapping
from arodonata.cpcrud.state_reader import HybridStateReader, StateLookupError


async def plan_rule_step(
    *,
    action_id: str,
    mgmt_name: str,
    domain_name: str,
    spec: Mapping[str, Any],
    policy: ConflictPolicy,
    reader: HybridStateReader,
    res_map: dict[str, str],
    collect_known_sids: Callable[[str], Awaitable[list[str]]],
) -> PlannedAction:
    """Plan an `access-rule`, `nat-rule`, `https-rule`, or `threat-rule` operation."""
    rb_type, rule_type = _resolve_rulebase_type(spec)
    verb = _normalize_verb(spec, is_rule=True)
    layer = str(spec.get("layer") or "").strip() or None
    package = str(spec.get("package") or "").strip() or None
    req_name = str(spec.get("name") or "").strip()
    req_uid = str(spec.get("uid") or "").strip()
    display_name = req_name or req_uid or f"{rule_type}@{layer or package}"

    try:
        paged = await reader.get_rulebase(
            mgmt_name,
            domain_name,
            rulebase_type=rb_type,
            layer=layer,
            package=package,
        )

        rules_list: list[RuleEntryUnion]
        if rb_type == "nat":
            rules_list = list(paged.nat_rules)
        elif rb_type == "https":
            rules_list = list(paged.https_rules)
        elif rb_type == "threat":
            rules_list = list(paged.threat_rules)
        else:
            rules_list = list(paged.access_rules)

        existing = match_rule(
            spec,
            rules_list,
            rulebase_type=rb_type,
            obj_dict=paged.objects_dictionary,
            name_resolutions=res_map,
            strict_name=(verb == "set"),
        )

        if verb == "delete":
            if existing is None:
                return PlannedAction(
                    action_id=action_id,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    operation="delete",
                    object_type=rule_type,
                    name=display_name,
                    layer=layer,
                    package=package,
                    outcome=Outcome.UNCHANGED,
                    desired_spec=dict(spec),
                    message=f"{rule_type} {display_name!r} is already absent.",
                )
            del_payload: dict[str, Any] = {"uid": existing.uid}
            if rb_type == "nat":
                del_payload["package"] = package or paged.package_name or paged.layer_name
            else:
                del_payload["layer"] = layer or paged.layer_name
            return PlannedAction(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                operation="delete",
                object_type=rule_type,
                name=existing.name or display_name,
                target_uid=existing.uid,
                layer=layer,
                package=package,
                outcome=Outcome.DELETE,
                command=f"delete-{rule_type}",
                payload=del_payload,
                prior_state=_build_prior_rule_state(
                    existing,
                    rulebase_type=rb_type,
                    layer=layer,
                    package=package,
                    obj_dict=paged.objects_dictionary,
                ),
                desired_spec=dict(spec),
                message=f"Delete {rule_type} {existing.name or existing.uid!r}.",
            )

        if existing is not None:
            prior_state = _build_prior_rule_state(
                existing,
                rulebase_type=rb_type,
                layer=layer,
                package=package,
                obj_dict=paged.objects_dictionary,
            )
            try:
                diffs, update_payload = compute_rule_diff(
                    spec,
                    existing,
                    rulebase_type=rb_type,
                    obj_dict=paged.objects_dictionary,
                    name_resolutions=res_map,
                )
            except DiffSafetyError as exc:
                return _make_error_action(
                    action_id=action_id,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    operation=verb,
                    object_type=rule_type,
                    name=existing.name or display_name,
                    requested_name=display_name,
                    resolved_name=existing.name or display_name,
                    target_uid=existing.uid,
                    layer=layer,
                    package=package,
                    prior_state=prior_state,
                    desired_spec=spec,
                    error=str(exc),
                )
            if not diffs:
                return PlannedAction(
                    action_id=action_id,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    operation=verb,
                    object_type=rule_type,
                    name=existing.name or display_name,
                    target_uid=existing.uid,
                    layer=layer,
                    package=package,
                    outcome=Outcome.UNCHANGED,
                    prior_state=prior_state,
                    desired_spec=dict(spec),
                    message=f"{rule_type} {existing.name or existing.uid!r} is unchanged.",
                )
            if policy.on_name_conflict == "error":
                err_msg = (
                    f"Rule conflict on {rule_type} {existing.name or existing.uid!r}: "
                    f"differs on [{', '.join(sorted(diffs.keys()))}] and on_name_conflict='error'."
                )
                return PlannedAction(
                    action_id=action_id,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    operation=verb,
                    object_type=rule_type,
                    name=existing.name or display_name,
                    target_uid=existing.uid,
                    layer=layer,
                    package=package,
                    outcome=Outcome.ERROR,
                    diffs=diffs,
                    prior_state=prior_state,
                    desired_spec=dict(spec),
                    message=err_msg,
                    error=err_msg,
                )

            update_payload["uid"] = existing.uid
            if rb_type == "nat":
                update_payload["package"] = package or paged.package_name or paged.layer_name
            else:
                update_payload["layer"] = layer or paged.layer_name

            return PlannedAction(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                operation="set",
                object_type=rule_type,
                name=existing.name or display_name,
                target_uid=existing.uid,
                layer=layer,
                package=package,
                outcome=Outcome.UPDATE,
                command=f"set-{rule_type}",
                payload=update_payload,
                diffs=diffs,
                prior_state=prior_state,
                desired_spec=dict(spec),
                message=f"Update {rule_type} {existing.name or existing.uid!r} ({', '.join(sorted(diffs.keys()))}).",
            )

        if verb == "set":
            return _make_error_action(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                operation="set",
                object_type=rule_type,
                name=display_name,
                layer=layer,
                package=package,
                desired_spec=spec,
                error=f"{rule_type} {display_name!r} not found for update.",
            )

        if rule_spec_has_delta_mapping(spec):
            return _make_error_action(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                operation=verb,
                object_type=rule_type,
                name=display_name,
                layer=layer,
                package=package,
                desired_spec=spec,
                error=(
                    f"Cannot create {rule_type} {display_name!r} from incremental {{add, remove}} rule cell patch; "
                    "target rule was not found."
                ),
            )

        # Create new rule with cleanup-rule-aware position resolution
        resolved_pos = resolve_rule_position(
            spec.get("position", "bottom"),
            rules_list,
            sections=paged.sections,
            obj_dict=paged.objects_dictionary,
        )
        add_payload = _build_add_rule_payload(
            rb_type=rb_type,
            spec=spec,
            layer=layer or paged.layer_name,
            package=package or paged.package_name or paged.layer_name,
            position=resolved_pos,
            name_resolutions=res_map,
        )
        return PlannedAction(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            operation="add",
            object_type=rule_type,
            name=req_name or display_name,
            layer=layer,
            package=package,
            outcome=Outcome.CREATE,
            command=f"add-{rule_type}",
            payload=add_payload,
            desired_spec=dict(spec),
            message=f"Create {rule_type} {req_name or display_name!r}.",
        )

    except StateLookupError as exc:
        known_sids = await collect_known_sids(mgmt_name)
        err_msg = redact_sid(f"{LOOKUP_ERROR_PREFIX}{exc}", known_sids=known_sids)
        return PlannedAction(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            operation=verb,
            object_type=rule_type,
            name=display_name,
            layer=layer,
            package=package,
            outcome=Outcome.ERROR,
            status="error",
            desired_spec=dict(spec),
            message=err_msg,
            error=err_msg,
        )
