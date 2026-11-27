"""Rulebase step planning helper (`arodonata.cpcrud._planner_rule_steps`)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from arodonata.core.errors import redact_sid
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    HttpsRuleEntry,
    NatRuleEntry,
    RulebaseType,
    ThreatRuleEntry,
)
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


def _build_virtual_rule_from_payload(
    *,
    mgmt_name: str,
    domain_name: str,
    rb_type: RulebaseType,
    rule_type: str,
    uid: str,
    payload: Mapping[str, Any],
    position: int,
) -> RuleEntryUnion:
    """Synthesize a rulebase entry model representing a planned rule creation for intra-plan reads."""
    name = str(payload.get("name") or "")
    comments = str(payload.get("comments") or "")
    enabled = bool(payload["enabled"]) if "enabled" in payload else True
    if rb_type == "nat":
        return NatRuleEntry(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            package_uid="",
            package_name=str(payload.get("package") or ""),
            uid=uid,
            name=name,
            position=position,
            rule_number=str(position),
            enabled=enabled,
            method=str(payload.get("method") or "static"),
            original_source=str(payload.get("original-source") or "Any"),
            original_destination=str(payload.get("original-destination") or "Any"),
            original_service=str(payload.get("original-service") or "Any"),
            translated_source=str(payload.get("translated-source") or "Original"),
            translated_destination=str(payload.get("translated-destination") or "Original"),
            translated_service=str(payload.get("translated-service") or "Original"),
            install_on=list(payload.get("install-on") or []),
            comments=comments,
            raw_data=dict(payload),
        )
    layer_name = str(payload.get("layer") or "")
    common: dict[str, Any] = {
        "mgmt_name": mgmt_name,
        "domain_name": domain_name,
        "layer_uid": "",
        "layer_name": layer_name,
        "uid": uid,
        "name": name,
        "rule_type": rule_type,
        "position": position,
        "rule_number": str(position),
        "enabled": enabled,
        "action": str(payload.get("action") or "Accept"),
        "source": list(payload.get("source") or []),
        "destination": list(payload.get("destination") or []),
        "service": list(payload.get("service") or []),
        "install_on": list(payload.get("install-on") or []),
        "comments": comments,
        "raw_data": dict(payload),
    }
    if rb_type == "https":
        return HttpsRuleEntry(
            **common,
            site_category=list(payload.get("site-category") or []),
            certificate=str(payload["certificate"]) if payload.get("certificate") else None,
        )
    if rb_type == "threat":
        return ThreatRuleEntry(
            **common,
            protected_scope=list(payload.get("protected-scope") or []),
        )
    return AccessRuleEntry(
        **common,
        source_negate=bool(payload.get("source-negate", False)),
        destination_negate=bool(payload.get("destination-negate", False)),
        service_negate=bool(payload.get("service-negate", False)),
        inline_layer_name=str(payload["inline-layer"]) if payload.get("inline-layer") else None,
    )


def _apply_update_to_virtual_rule(existing: RuleEntryUnion, update_payload: Mapping[str, Any]) -> RuleEntryUnion:
    """Apply `set-*-rule` payload fields onto a rule entry copy for intra-plan virtual state."""
    upd: dict[str, Any] = {}
    if "new-name" in update_payload:
        upd["name"] = str(update_payload["new-name"])
    if "comments" in update_payload:
        upd["comments"] = str(update_payload["comments"])
    if "enabled" in update_payload:
        upd["enabled"] = bool(update_payload["enabled"])
    if "action" in update_payload:
        upd["action"] = str(update_payload["action"])
    for cell in ("source", "destination", "service"):
        val = update_payload.get(cell)
        if isinstance(val, list):
            upd[cell] = list(val)
    if "install-on" in update_payload and isinstance(update_payload["install-on"], list):
        upd["install_on"] = list(update_payload["install-on"])
    if isinstance(existing, AccessRuleEntry):
        for sk, kk in (
            ("source_negate", "source-negate"),
            ("destination_negate", "destination-negate"),
            ("service_negate", "service-negate"),
        ):
            if kk in update_payload:
                upd[sk] = bool(update_payload[kk])
        if "inline-layer" in update_payload:
            upd["inline_layer_name"] = str(update_payload["inline-layer"]) or None
    elif isinstance(existing, HttpsRuleEntry) and "certificate" in update_payload:
        upd["certificate"] = str(update_payload["certificate"]) or None
    return existing.model_copy(update=upd)


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
    target_key = layer or package or ""
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
            is_planned_rule = str(existing.uid).startswith("planned:")
            del_payload: dict[str, Any] = (
                {"name": existing.name} if (is_planned_rule and existing.name) else {"uid": existing.uid}
            )
            if rb_type == "nat":
                del_payload["package"] = package or paged.package_name or paged.layer_name
            else:
                del_payload["layer"] = layer or paged.layer_name
            reader.record_virtual_rule_delete(
                mgmt_name,
                domain_name,
                rb_type,
                target_key,
                uid=existing.uid,
                name=existing.name,
            )
            return PlannedAction(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                operation="delete",
                object_type=rule_type,
                name=existing.name or display_name,
                target_uid=None if is_planned_rule else existing.uid,
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

            is_planned_rule = str(existing.uid).startswith("planned:")
            if is_planned_rule and existing.name:
                update_payload["name"] = existing.name
            else:
                update_payload["uid"] = existing.uid
            if rb_type == "nat":
                update_payload["package"] = package or paged.package_name or paged.layer_name
            else:
                update_payload["layer"] = layer or paged.layer_name

            updated_virtual = _apply_update_to_virtual_rule(existing, update_payload)
            reader.record_virtual_rule(
                mgmt_name,
                domain_name,
                rb_type,
                target_key,
                updated_virtual,
                previous_name=existing.name,
            )

            return PlannedAction(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                operation="set",
                object_type=rule_type,
                name=existing.name or display_name,
                target_uid=None if is_planned_rule else existing.uid,
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
        try:
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
        except DiffSafetyError as exc:
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
                error=str(exc),
            )
        virtual_uid = f"planned:{rule_type}:{req_name or action_id}"
        virtual_rule = _build_virtual_rule_from_payload(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            rb_type=rb_type,
            rule_type=rule_type,
            uid=virtual_uid,
            payload=add_payload,
            position=len(rules_list) + 1,
        )
        reader.record_virtual_rule(mgmt_name, domain_name, rb_type, target_key, virtual_rule)
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
