"""Compensating rollback template generator (`src/arodonata/cpcrud/inverse.py`).

Implements `build_inverse_template` (`CPCRUDService.inverse(plan, report)`):
- Builds a dictionary valid against `checkpoint_ops_schema.json` that reverses applied
  `CREATE`, `UPDATE`, and `DELETE` actions using captured `PlannedAction.prior_state`.
- Reverses execution order so dependent rules and groups are rolled back before the
  objects/services they reference.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from arodonata.cpcrud.models import ActionResult, ApplyReport, Outcome, Plan, PlannedAction
from arodonata.cpcrud.state_reader import OBJECT_ITEM_TYPES, SERVICE_ITEM_TYPES

_OBJECT_INVERSE_FIELDS: tuple[str, ...] = (
    "ipv4-address",
    "ipv6-address",
    "subnet4",
    "mask-length4",
    "ipv4-address-first",
    "ipv4-address-last",
    "is-sub-domain",
    "primary-category",
    "url-list",
    "urls-defined-as-regular-expression",
    "description",
    "application-signature",
    "additional-categories",
    "comments",
    "color",
    "tags",
    "groups",
    "nat-settings",
    "ignore-warnings",
    "set-if-exists",
)

_SERVICE_INVERSE_FIELDS: tuple[str, ...] = (
    "port",
    "protocol",
    "icmp-type",
    "icmp-code",
    "session-timeout",
    "match-for-any",
    "comments",
    "color",
    "tags",
    "groups",
    "ignore-warnings",
    "set-if-exists",
)

_GROUP_INVERSE_FIELDS: tuple[str, ...] = ("comments", "color", "tags", "groups")

_RULE_INVERSE_FIELDS: tuple[str, ...] = (
    "enabled",
    "comments",
    "source",
    "destination",
    "service",
    "source-negate",
    "destination-negate",
    "service-negate",
    "rule_action",
    "track",
    "install-on",
    "inline-layer",
    "protected-scope",
    "site-category",
    "certificate",
    "method",
    "original-source",
    "original-destination",
    "original-service",
    "translated-source",
    "translated-destination",
    "translated-service",
)


def _copy_prior_fields(
    op: dict[str, Any],
    prior: Mapping[str, Any],
    field_keys: tuple[str, ...],
) -> None:
    """Copy non-None keys listed in `field_keys` from `prior` into rollback payload `op`."""
    for field_key in field_keys:
        if field_key in prior and prior[field_key] is not None:
            op[field_key] = prior[field_key]


def _real_uid(*candidates: Any) -> str | None:
    """Return the first non-empty candidate UID that is not a synthetic `'planned:...'` placeholder."""
    for cand in candidates:
        if cand is None:
            continue
        s = str(cand).strip()
        if s and not s.startswith("planned:"):
            return s
    return None


def _restore_empty_groups_tags(op: dict[str, Any], action: PlannedAction, *, is_update: bool = True) -> None:
    """Explicitly emit empty defaults (`[]`/`""`) when mutated from empty prior state on rollback."""
    for field_key in ("groups", "tags"):
        if (field_key in action.diffs or field_key in action.payload) and field_key not in op:
            op[field_key] = []
    if is_update:
        if (
            "additional-categories" in action.diffs
            or "additional_categories" in action.diffs
            or "additional-categories" in action.payload
            or "additional_categories" in action.payload
        ) and "additional-categories" not in op:
            op["additional-categories"] = []
        if ("description" in action.diffs or "description" in action.payload) and "description" not in op:
            op["description"] = ""


def _invert_single_action(
    action: PlannedAction,
    result: ActionResult | None = None,
    *,
    report_supplied: bool = False,
) -> tuple[str, dict[str, Any]] | None:
    """Invert a single `PlannedAction` into `(bucket_name, op_dict)` or `None` if no-op."""
    effective_outcome = result.outcome if result is not None else action.outcome
    if result is not None and not result.success:
        return None
    if effective_outcome not in (Outcome.CREATE, Outcome.UPDATE, Outcome.DELETE):
        return None

    obj_type = action.object_type
    prior = dict(action.prior_state or {})
    created_uid = (result.target_uid if result is not None else None) or action.target_uid
    if created_uid and created_uid.startswith("planned:"):
        created_uid = None
    # When a report is supplied for a CREATE action, refuse unsafe delete-by-name if no concrete UID was created
    if effective_outcome == Outcome.CREATE and report_supplied and not created_uid:
        return None

    if obj_type.endswith("-rule") or obj_type in ("access", "nat", "https", "threat"):
        rule_op = _invert_rule_action(action, effective_outcome, prior, created_uid)
        return ("rules", rule_op) if rule_op is not None else None

    if obj_type in ("group", "service-group"):
        grp_op = _invert_entity_action(
            action,
            effective_outcome,
            prior,
            created_uid,
            fields=_GROUP_INVERSE_FIELDS,
            include_members=True,
            restore_empty_on_delete=True,
        )
        return ("groups", grp_op) if grp_op is not None else None

    if obj_type in SERVICE_ITEM_TYPES:
        svc_op = _invert_entity_action(
            action,
            effective_outcome,
            prior,
            created_uid,
            fields=_SERVICE_INVERSE_FIELDS,
            restore_empty_on_delete=True,
        )
        return ("services", svc_op) if svc_op is not None else None

    if obj_type in OBJECT_ITEM_TYPES:
        obj_op = _invert_entity_action(
            action,
            effective_outcome,
            prior,
            created_uid,
            fields=_OBJECT_INVERSE_FIELDS,
        )
        return ("objects", obj_op) if obj_op is not None else None

    return None


def _invert_entity_action(
    action: PlannedAction,
    outcome: Outcome,
    prior: dict[str, Any],
    target_uid: str | None,
    *,
    fields: tuple[str, ...],
    include_members: bool = False,
    restore_empty_on_delete: bool = False,
) -> dict[str, Any] | None:
    """Invert a `CREATE`, `UPDATE`, or `DELETE` action for an object, service, or group entity."""
    entity_type = action.object_type
    if outcome == Outcome.CREATE:
        op: dict[str, Any] = {
            "operation": "delete",
            "type": entity_type,
            "name": action.resolved_name or action.name,
        }
        uid_val = _real_uid(target_uid)
        if uid_val:
            op["uid"] = uid_val
        return op

    if outcome == Outcome.UPDATE:
        if not prior:
            return None
        current_name = action.resolved_name or action.name
        prior_name = str(prior.get("name") or action.name)
        op = {
            "operation": "set",
            "type": entity_type,
            "name": current_name,
        }
        uid_val = _real_uid(target_uid, prior.get("uid"))
        if uid_val:
            op["uid"] = uid_val
        if prior_name != current_name:
            op["new-name"] = prior_name
        if include_members and "members" in prior and isinstance(prior["members"], list):
            op["members"] = [str(m) for m in prior["members"]]
        _copy_prior_fields(op, prior, fields)
        _restore_empty_groups_tags(op, action, is_update=True)
        return op

    if outcome == Outcome.DELETE:
        if not prior:
            return None
        op = {
            "operation": "add",
            "type": entity_type,
            "name": str(prior.get("name") or action.name),
        }
        if include_members and "members" in prior and isinstance(prior["members"], list):
            op["members"] = [str(m) for m in prior["members"]]
        _copy_prior_fields(op, prior, fields)
        if restore_empty_on_delete:
            _restore_empty_groups_tags(op, action, is_update=False)
        return op

    return None


def _invert_rule_action(
    action: PlannedAction,
    outcome: Outcome,
    prior: dict[str, Any],
    target_uid: str | None,
) -> dict[str, Any] | None:
    rule_type = action.object_type
    layer = action.layer or prior.get("layer") or action.desired_spec.get("layer")
    package = action.package or prior.get("package") or action.desired_spec.get("package")

    if outcome == Outcome.CREATE:
        op: dict[str, Any] = {
            "operation": "delete",
            "type": rule_type,
        }
        if layer:
            op["layer"] = str(layer)
        if package:
            op["package"] = str(package)
        if target_uid and not target_uid.startswith("planned:"):
            op["uid"] = target_uid
        if action.name:
            op["name"] = action.name
        return op

    if outcome == Outcome.UPDATE:
        if not prior:
            return None
        op = {
            "operation": "set",
            "type": rule_type,
        }
        if layer:
            op["layer"] = str(layer)
        if package:
            op["package"] = str(package)
        uid_val = _real_uid(target_uid, prior.get("uid"))
        if uid_val:
            op["uid"] = uid_val
        prior_name = str(prior.get("name") or "")
        current_name = str((action.payload or {}).get("new-name") or action.resolved_name or action.name or "")
        if current_name and prior_name and current_name != prior_name:
            op["name"] = current_name
            op["new-name"] = prior_name
        elif prior.get("name") is not None:
            op["name"] = str(prior["name"])

        _copy_prior_fields(op, prior, _RULE_INVERSE_FIELDS)
        return op

    if outcome == Outcome.DELETE:
        if not prior:
            return None
        op = {
            "operation": "add",
            "type": rule_type,
        }
        if layer:
            op["layer"] = str(layer)
        if package:
            op["package"] = str(package)
        if prior.get("name"):
            op["name"] = str(prior["name"])

        pos_val = prior.get("position", "bottom")
        if (isinstance(pos_val, int) and pos_val >= 1) or (isinstance(pos_val, str) and pos_val in ("top", "bottom")):
            op["position"] = pos_val
        else:
            op["position"] = "bottom"

        _copy_prior_fields(op, prior, _RULE_INVERSE_FIELDS)
        return op

    return None


def build_inverse_template(
    plan: Plan,
    report: ApplyReport | None = None,
) -> dict[str, Any]:
    """Generate a schema-valid compensating template from `plan` (and optional `report`).

    - `CREATE` actions become `delete` operations.
    - `UPDATE` actions become `set` operations restoring prior attribute values from `prior_state`.
    - `DELETE` actions become `add` operations populated from `prior_state`.
    - Actions within each target domain are emitted in reverse execution order so rules/groups
      are removed or restored in safe dependency order.
    """
    result_by_id: dict[str, ActionResult] = {}
    if report is not None:
        for res in report.results:
            result_by_id[res.action_id] = res

    # Group actions by (mgmt_name, domain_name)
    domain_order: list[tuple[str, str]] = []
    domain_actions: dict[tuple[str, str], list[PlannedAction]] = defaultdict(list)
    for act in plan.actions:
        key = (act.mgmt_name, act.domain_name)
        if key not in domain_actions:
            domain_order.append(key)
        domain_actions[key].append(act)

    targets: list[dict[str, Any]] = []

    for mgmt_name, dom_name in domain_order:
        acts = domain_actions[(mgmt_name, dom_name)]
        ops: list[dict[str, Any]] = []
        objects_bucket: list[dict[str, Any]] = []
        services_bucket: list[dict[str, Any]] = []
        groups_bucket: list[dict[str, Any]] = []
        rules_bucket: list[dict[str, Any]] = []

        # Process in reverse order so rules/groups created last are deleted first
        for act in reversed(acts):
            res_item = result_by_id.get(act.action_id) if report is not None else None
            if report is not None and res_item is None:
                continue
            inverted = _invert_single_action(act, res_item, report_supplied=(report is not None))
            if inverted is None:
                continue
            bucket_name, op_dict = inverted
            ops.append(op_dict)
            if bucket_name == "objects":
                objects_bucket.append(op_dict)
            elif bucket_name == "services":
                services_bucket.append(op_dict)
            elif bucket_name == "groups":
                groups_bucket.append(op_dict)
            elif bucket_name == "rules":
                rules_bucket.append(op_dict)

        target_entry: dict[str, Any] = {
            "mgmt_name": mgmt_name or "default",
            "domain": dom_name or None,
            "operations": ops,
        }
        if objects_bucket:
            target_entry["objects"] = objects_bucket
        if services_bucket:
            target_entry["services"] = services_bucket
        if groups_bucket:
            target_entry["groups"] = groups_bucket
        if rules_bucket:
            target_entry["rules"] = rules_bucket
        targets.append(target_entry)

    if len(targets) == 1:
        single = targets[0]
        flat: dict[str, Any] = {
            "version": 1,
            "mgmt_name": single["mgmt_name"],
            "domain": single["domain"],
            "operations": single["operations"],
        }
        for bucket_key in ("objects", "services", "groups", "rules"):
            if bucket_key in single:
                flat[bucket_key] = single[bucket_key]
        return flat

    if not targets:
        root_mgmt = str(plan.template.get("mgmt_name") or "default")
        root_dom = plan.template.get("domain")
        return {
            "version": 1,
            "mgmt_name": root_mgmt,
            "domain": root_dom,
            "operations": [],
        }

    return {
        "version": 1,
        "targets": targets,
    }


__all__ = [
    "build_inverse_template",
]
