"""Existing-entity diff planning and virtual overlay model mutation (`arodonata.cpcrud._planner_diff`)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any

from arodonata.core.errors import redact_sid
from arodonata.core.models.objects import CPObject
from arodonata.core.models.services import CPService
from arodonata.core.primitives import format_composite_id
from arodonata.cpcrud._planner_helpers import (
    LOOKUP_ERROR_PREFIX,
    _build_prior_object_state,
    _build_prior_service_state,
    _entity_wire_identity,
    _make_error_action,
)
from arodonata.cpcrud.differ import (
    DiffSafetyError,
    compute_object_diff,
    compute_service_diff,
    parse_existing_member_entries,
)
from arodonata.cpcrud.models import ConflictPolicy, FieldChange, Outcome, PlannedAction
from arodonata.cpcrud.state_reader import HybridStateReader, StateLookupError


async def _lookup_error_action(
    *,
    action_id: str,
    mgmt_name: str,
    domain_name: str,
    verb: str,
    entity_type: str,
    display_name: str,
    spec: Mapping[str, Any],
    exc: StateLookupError,
    collect_known_sids: Callable[[str], Awaitable[list[str]]],
) -> PlannedAction:
    known_sids = await collect_known_sids(mgmt_name)
    err_msg = redact_sid(f"{LOOKUP_ERROR_PREFIX}{exc}", known_sids=known_sids)
    return _make_error_action(
        action_id=action_id,
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        operation=verb,
        object_type=entity_type,
        name=display_name,
        requested_name=display_name,
        resolved_name=display_name,
        desired_spec=spec,
        error=err_msg,
    )


def _plan_entity_delete(
    *,
    action_id: str,
    mgmt_name: str,
    domain_name: str,
    entity_type: str,
    display_name: str,
    spec: Mapping[str, Any],
    existing: CPObject | CPService | None,
    reader: HybridStateReader,
) -> PlannedAction:
    if existing is None:
        return PlannedAction(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            operation="delete",
            object_type=entity_type,
            name=display_name,
            outcome=Outcome.UNCHANGED,
            desired_spec=dict(spec),
            message=f"{entity_type} {display_name!r} is already absent.",
        )
    del_payload = _entity_wire_identity(existing)
    if isinstance(existing, CPService):
        reader.record_virtual_service_delete(
            mgmt_name, domain_name, svc_type=entity_type, name=existing.name, uid=existing.uid
        )
        prior = _build_prior_service_state(existing)
    else:
        reader.record_virtual_object_delete(
            mgmt_name, domain_name, obj_type=entity_type, name=existing.name, uid=existing.uid
        )
        prior = _build_prior_object_state(existing)
    return PlannedAction(
        action_id=action_id,
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        operation="delete",
        object_type=entity_type,
        name=existing.name,
        requested_name=display_name,
        resolved_name=existing.name,
        target_uid=existing.uid,
        outcome=Outcome.DELETE,
        command=f"delete-{entity_type}",
        payload=del_payload,
        prior_state=prior,
        desired_spec=dict(spec),
        message=f"Delete {entity_type} {existing.name!r}.",
    )


def _plan_missing_set_action(
    *,
    action_id: str,
    mgmt_name: str,
    domain_name: str,
    entity_type: str,
    display_name: str,
    spec: Mapping[str, Any],
) -> PlannedAction:
    return _make_error_action(
        action_id=action_id,
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        operation="set",
        object_type=entity_type,
        name=display_name,
        desired_spec=spec,
        error=f"{entity_type} {display_name!r} not found for update.",
    )


def _plan_value_conflict_action(
    *,
    action_id: str,
    mgmt_name: str,
    domain_name: str,
    verb: str,
    entity_type: str,
    req_name: str,
    matched: CPObject | CPService,
    conflict_label: str,
    policy: ConflictPolicy,
    spec: Mapping[str, Any],
    res_map: dict[str, str],
) -> PlannedAction | None:
    if policy.on_ip_conflict == "error":
        err_msg = (
            f"{conflict_label} conflict for {entity_type} {req_name!r}: "
            f"already exists as {matched.name!r} ({matched.uid}) and on_ip_conflict='error'."
        )
        return PlannedAction(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            operation=verb,
            object_type=entity_type,
            name=req_name,
            requested_name=req_name,
            resolved_name=req_name,
            target_uid=matched.uid,
            outcome=Outcome.ERROR,
            desired_spec=dict(spec),
            message=err_msg,
            error=err_msg,
        )
    if policy.on_ip_conflict == "reuse":
        res_map[req_name] = matched.name
        prior = (
            _build_prior_object_state(matched) if isinstance(matched, CPObject) else _build_prior_service_state(matched)
        )
        return PlannedAction(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            operation=verb,
            object_type=entity_type,
            name=matched.name,
            requested_name=req_name,
            resolved_name=matched.name,
            target_uid=matched.uid,
            outcome=Outcome.REUSE,
            prior_state=prior,
            desired_spec=dict(spec),
            message=f"Reuse existing {entity_type} {matched.name!r} for requested {req_name!r}.",
        )
    return None


def _plan_create_entity(
    *,
    action_id: str,
    mgmt_name: str,
    domain_name: str,
    entity_type: str,
    target_create_name: str,
    req_name: str,
    add_payload: dict[str, Any],
    spec: Mapping[str, Any],
    reader: HybridStateReader,
    res_map: dict[str, str],
    is_service: bool,
) -> PlannedAction:
    virt_data = {
        **add_payload,
        "uid": f"planned:{entity_type}:{target_create_name}",
        "type": entity_type,
        "name": target_create_name,
    }
    if is_service:
        reader.record_virtual_service(CPService.from_cp_dict(mgmt_name, domain_name, virt_data))
    else:
        reader.record_virtual_object(CPObject.from_cp_dict(mgmt_name, domain_name, virt_data))
    if target_create_name:
        res_map.pop(target_create_name, None)
    if req_name and target_create_name != req_name:
        res_map[req_name] = target_create_name
    elif req_name:
        res_map.pop(req_name, None)
    return PlannedAction(
        action_id=action_id,
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        operation="add",
        object_type=entity_type,
        name=target_create_name,
        requested_name=req_name or target_create_name,
        resolved_name=target_create_name,
        outcome=Outcome.CREATE,
        command=f"add-{entity_type}",
        payload=add_payload,
        desired_spec=dict(spec),
        message=f"Create {entity_type} {target_create_name!r}.",
    )


def _compute_post_update_members(
    existing_members: Sequence[str],
    raw_data: Mapping[str, Any] | None,
    diffs: Mapping[str, FieldChange],
    update_payload: Mapping[str, Any],
) -> tuple[list[str], list[dict[str, Any]]]:
    """Compute post-update `(members, raw_data_members)` for `group` and `service-group` overlays."""
    existing_dicts = parse_existing_member_entries(existing_members, raw_data)
    by_token: dict[str, dict[str, Any]] = {}
    for entry in existing_dicts:
        u = str(entry.get("uid") or "").strip()
        n = str(entry.get("name") or "").strip()
        if u:
            by_token[u] = entry
        if n:
            by_token[n] = entry

    if "members" in update_payload:
        member_spec = update_payload["members"]
        new_members: list[str] = []
        new_raw_members: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        if isinstance(member_spec, list):
            for raw_m in member_spec:
                tok = str(raw_m).strip()
                if not tok:
                    continue
                matched = by_token.get(tok)
                if matched is not None:
                    entry = dict(matched)
                    member_id = str(entry.get("uid") or entry.get("name") or tok)
                else:
                    entry = {"name": tok}
                    member_id = tok
                if member_id not in seen_ids:
                    seen_ids.add(member_id)
                    new_members.append(member_id)
                    new_raw_members.append(entry)
            return new_members, new_raw_members

        if isinstance(member_spec, Mapping):
            diff_entry = diffs.get("members")
            removed_raw = diff_entry.removed_items if diff_entry is not None else (member_spec.get("remove") or [])
            added_raw = diff_entry.added_items if diff_entry is not None else (member_spec.get("add") or [])
            removed_tokens = {str(x).strip() for x in removed_raw if str(x).strip()}

            surviving_tokens: set[str] = set()
            for entry in existing_dicts:
                u = str(entry.get("uid") or "").strip()
                n = str(entry.get("name") or "").strip()
                if (u and u in removed_tokens) or (n and n in removed_tokens):
                    continue
                member_id = u or n
                if member_id and member_id not in seen_ids:
                    seen_ids.add(member_id)
                    new_members.append(member_id)
                    new_raw_members.append(dict(entry))
                    if u:
                        surviving_tokens.add(u)
                    if n:
                        surviving_tokens.add(n)

            for raw_add in added_raw:
                tok = str(raw_add).strip()
                if not tok or tok in surviving_tokens or tok in seen_ids:
                    continue
                seen_ids.add(tok)
                surviving_tokens.add(tok)
                new_members.append(tok)
                new_raw_members.append({"name": tok})
            return new_members, new_raw_members

    surviving_ids = [str(d.get("uid") or d.get("name") or "") for d in existing_dicts if d.get("uid") or d.get("name")]
    return surviving_ids, existing_dicts


def _apply_object_update_to_model(
    existing: CPObject,
    diffs: Mapping[str, FieldChange],
    update_payload: Mapping[str, Any],
) -> CPObject:
    """Build an updated `CPObject` reflecting all `set-<type>` changes for the virtual overlay."""
    new_target_name = str(update_payload.get("new-name") or existing.name)
    new_raw = dict(existing.raw_data) if isinstance(existing.raw_data, Mapping) else {}
    new_raw["name"] = new_target_name

    updates: dict[str, Any] = {
        "name": new_target_name,
        "object_id": format_composite_id(existing.mgmt_name, existing.domain_name, new_target_name),
    }

    for payload_key, model_attr in (
        ("ipv4-address", "ipv4_address"),
        ("ipv6-address", "ipv6_address"),
        ("subnet4", "subnet4"),
        ("ipv4-address-first", "ipv4_address_first"),
        ("ipv4-address-last", "ipv4_address_last"),
        ("is-sub-domain", "is_sub_domain"),
        ("primary-category", "primary_category"),
        ("url-list", "url_list"),
        ("urls-defined-as-regular-expression", "urls_defined_as_regular_expression"),
        ("description", "description"),
        ("comments", "comments"),
        ("color", "color"),
        ("tags", "tags"),
        ("nat-settings", "nat_settings"),
    ):
        if payload_key in update_payload:
            val = update_payload[payload_key]
            copied = list(val) if isinstance(val, list) else (dict(val) if isinstance(val, dict) else val)
            updates[model_attr] = copied
            new_raw[payload_key] = copied

    if "mask-length4" in update_payload:
        updates["mask_length4"] = update_payload["mask-length4"]
        updates["subnet_mask"] = None
        new_raw["mask-length4"] = update_payload["mask-length4"]
        new_raw.pop("subnet-mask", None)
        new_raw.pop("subnet_mask", None)

    for raw_only_key in ("application-signature", "additional-categories"):
        if raw_only_key in update_payload:
            val = update_payload[raw_only_key]
            new_raw[raw_only_key] = list(val) if isinstance(val, list) else val

    if existing.type == "group" and "members" in update_payload:
        new_members, new_raw_members = _compute_post_update_members(
            existing.members,
            existing.raw_data,
            diffs,
            update_payload,
        )
        updates["members"] = new_members
        new_raw["members"] = new_raw_members

    updates["raw_data"] = new_raw
    return existing.model_copy(update=updates)


def _apply_service_update_to_model(
    existing: CPService,
    diffs: Mapping[str, FieldChange],
    update_payload: Mapping[str, Any],
) -> CPService:
    """Build an updated `CPService` reflecting all `set-<service-type>` changes for the virtual overlay."""
    new_target_name = str(update_payload.get("new-name") or existing.name)
    new_raw = dict(existing.raw_data) if isinstance(existing.raw_data, Mapping) else {}
    new_raw["name"] = new_target_name

    updates: dict[str, Any] = {
        "name": new_target_name,
        "service_id": format_composite_id(existing.mgmt_name, existing.domain_name, new_target_name),
    }

    if "port" in update_payload:
        port_str = str(update_payload["port"])
        updates["port"] = port_str
        new_raw["port"] = port_str

    for proto_key in ("protocol", "ip-protocol"):
        if proto_key in update_payload:
            proto_str = str(update_payload[proto_key])
            updates["protocol"] = proto_str
            new_raw[proto_key] = proto_str

    for payload_key, model_attr in (
        ("icmp-type", "icmp_type"),
        ("icmp-code", "icmp_code"),
        ("session-timeout", "session_timeout"),
        ("match-for-any", "match_for_any"),
        ("comments", "comments"),
        ("color", "color"),
        ("tags", "tags"),
    ):
        if payload_key in update_payload:
            val = update_payload[payload_key]
            copied = list(val) if isinstance(val, list) else val
            updates[model_attr] = copied
            new_raw[payload_key] = copied

    if existing.type == "service-group" and "members" in update_payload:
        new_members, new_raw_members = _compute_post_update_members(
            existing.members,
            existing.raw_data,
            diffs,
            update_payload,
        )
        updates["members"] = new_members
        new_raw["members"] = new_raw_members

    updates["raw_data"] = new_raw
    return existing.model_copy(update=updates)


def _plan_existing_object_diff(
    *,
    action_id: str,
    mgmt_name: str,
    domain_name: str,
    verb: str,
    obj_type: str,
    display_name: str,
    spec: Mapping[str, Any],
    existing: CPObject,
    policy: ConflictPolicy,
    reader: HybridStateReader,
    res_map: dict[str, str],
) -> PlannedAction:
    """Compute field diffs, enforce `on_name_conflict`, and update virtual overlay for an existing `CPObject`."""
    try:
        diffs, update_payload = compute_object_diff(spec, existing, name_resolutions=res_map)
    except DiffSafetyError as exc:
        return _make_error_action(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            operation=verb,
            object_type=obj_type,
            name=existing.name,
            requested_name=display_name,
            resolved_name=existing.name,
            target_uid=existing.uid,
            prior_state=_build_prior_object_state(existing),
            desired_spec=spec,
            error=str(exc),
        )
    if not diffs:
        return PlannedAction(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            operation=verb,
            object_type=obj_type,
            name=existing.name,
            requested_name=display_name,
            resolved_name=existing.name,
            target_uid=existing.uid,
            outcome=Outcome.UNCHANGED,
            prior_state=_build_prior_object_state(existing),
            desired_spec=dict(spec),
            message=f"{obj_type} {existing.name!r} is unchanged.",
        )
    if policy.on_name_conflict == "error":
        diff_keys = ", ".join(sorted(diffs.keys()))
        err_msg = (
            f"Name conflict on {obj_type} {existing.name!r}: differs on [{diff_keys}] and on_name_conflict='error'."
        )
        return PlannedAction(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            operation=verb,
            object_type=obj_type,
            name=existing.name,
            requested_name=display_name,
            resolved_name=existing.name,
            target_uid=existing.uid,
            outcome=Outcome.ERROR,
            diffs=diffs,
            prior_state=_build_prior_object_state(existing),
            desired_spec=dict(spec),
            message=err_msg,
            error=err_msg,
        )

    update_payload.update(_entity_wire_identity(existing))
    new_target_name = str(update_payload.get("new-name") or existing.name)
    updated_model = _apply_object_update_to_model(existing, diffs, update_payload)
    reader.record_virtual_object(updated_model, previous_name=existing.name)

    return PlannedAction(
        action_id=action_id,
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        operation="set",
        object_type=obj_type,
        name=existing.name,
        requested_name=display_name,
        resolved_name=new_target_name,
        target_uid=existing.uid,
        outcome=Outcome.UPDATE,
        command=f"set-{obj_type}",
        payload=update_payload,
        diffs=diffs,
        prior_state=_build_prior_object_state(existing),
        desired_spec=dict(spec),
        message=f"Update {obj_type} {existing.name!r} ({', '.join(sorted(diffs.keys()))}).",
    )


def _plan_existing_service_diff(
    *,
    action_id: str,
    mgmt_name: str,
    domain_name: str,
    verb: str,
    svc_type: str,
    display_name: str,
    spec: Mapping[str, Any],
    existing: CPService,
    policy: ConflictPolicy,
    reader: HybridStateReader,
    res_map: dict[str, str],
) -> PlannedAction:
    """Compute field diffs, enforce `on_name_conflict`, and update virtual overlay for an existing `CPService`."""
    try:
        diffs, update_payload = compute_service_diff(spec, existing, name_resolutions=res_map)
    except DiffSafetyError as exc:
        return _make_error_action(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            operation=verb,
            object_type=svc_type,
            name=existing.name,
            requested_name=display_name,
            resolved_name=existing.name,
            target_uid=existing.uid,
            prior_state=_build_prior_service_state(existing),
            desired_spec=spec,
            error=str(exc),
        )
    if not diffs:
        return PlannedAction(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            operation=verb,
            object_type=svc_type,
            name=existing.name,
            requested_name=display_name,
            resolved_name=existing.name,
            target_uid=existing.uid,
            outcome=Outcome.UNCHANGED,
            prior_state=_build_prior_service_state(existing),
            desired_spec=dict(spec),
            message=f"{svc_type} {existing.name!r} is unchanged.",
        )
    if policy.on_name_conflict == "error":
        diff_keys = ", ".join(sorted(diffs.keys()))
        err_msg = (
            f"Name conflict on {svc_type} {existing.name!r}: differs on [{diff_keys}] and on_name_conflict='error'."
        )
        return PlannedAction(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            operation=verb,
            object_type=svc_type,
            name=existing.name,
            requested_name=display_name,
            resolved_name=existing.name,
            target_uid=existing.uid,
            outcome=Outcome.ERROR,
            diffs=diffs,
            prior_state=_build_prior_service_state(existing),
            desired_spec=dict(spec),
            message=err_msg,
            error=err_msg,
        )

    update_payload.update(_entity_wire_identity(existing))
    new_target_name = str(update_payload.get("new-name") or existing.name)
    updated_svc = _apply_service_update_to_model(existing, diffs, update_payload)
    reader.record_virtual_service(updated_svc, previous_name=existing.name)

    return PlannedAction(
        action_id=action_id,
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        operation="set",
        object_type=svc_type,
        name=existing.name,
        requested_name=display_name,
        resolved_name=new_target_name,
        target_uid=existing.uid,
        outcome=Outcome.UPDATE,
        command=f"set-{svc_type}",
        payload=update_payload,
        diffs=diffs,
        prior_state=_build_prior_service_state(existing),
        desired_spec=dict(spec),
        message=f"Update {svc_type} {existing.name!r} ({', '.join(sorted(diffs.keys()))}).",
    )
