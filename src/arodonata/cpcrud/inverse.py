"""Compensating rollback template generator (`src/arodonata/cpcrud/inverse.py`).

Implements `build_inverse_template` (`CPCRUDService.inverse(plan, report)`):
- Builds a dictionary valid against `checkpoint_ops_schema.json` that reverses applied
  `CREATE`, `UPDATE`, and `DELETE` actions using captured `PlannedAction.prior_state`.
- Reverses execution order so dependent rules and groups are rolled back before the
  objects/services they reference.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from arodonata.cpcrud.models import ActionResult, ApplyReport, Outcome, Plan, PlannedAction
from arodonata.cpcrud.state_reader import OBJECT_ITEM_TYPES, SERVICE_ITEM_TYPES


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
        grp_op = _invert_group_action(action, effective_outcome, prior, created_uid)
        return ("groups", grp_op) if grp_op is not None else None

    if obj_type in SERVICE_ITEM_TYPES:
        svc_op = _invert_service_action(action, effective_outcome, prior, created_uid)
        return ("services", svc_op) if svc_op is not None else None

    if obj_type in OBJECT_ITEM_TYPES:
        obj_op = _invert_object_action(action, effective_outcome, prior, created_uid)
        return ("objects", obj_op) if obj_op is not None else None

    return None


def _invert_object_action(
    action: PlannedAction,
    outcome: Outcome,
    prior: dict[str, Any],
    target_uid: str | None,
) -> dict[str, Any] | None:
    obj_type = action.object_type
    if outcome == Outcome.CREATE:
        op: dict[str, Any] = {
            "operation": "delete",
            "type": obj_type,
            "name": action.resolved_name or action.name,
        }
        if target_uid and not target_uid.startswith("planned:"):
            op["uid"] = target_uid
        return op

    if outcome == Outcome.UPDATE:
        if not prior:
            return None
        current_name = action.resolved_name or action.name
        prior_name = str(prior.get("name") or action.name)
        op = {
            "operation": "set",
            "type": obj_type,
            "name": current_name,
        }
        if target_uid:
            op["uid"] = target_uid
        elif prior.get("uid"):
            op["uid"] = str(prior["uid"])
        if prior_name != current_name:
            op["new-name"] = prior_name

        # Restore prior field values
        for field_key in (
            "ipv4-address",
            "ipv6-address",
            "subnet4",
            "mask-length4",
            "ipv4-address-first",
            "ipv4-address-last",
            "is-sub-domain",
            "comments",
            "color",
            "tags",
            "groups",
            "nat-settings",
            "ignore-warnings",
            "set-if-exists",
        ):
            if field_key in prior and prior[field_key] is not None:
                op[field_key] = prior[field_key]
        return op

    if outcome == Outcome.DELETE:
        if not prior:
            return None
        op = {
            "operation": "add",
            "type": obj_type,
            "name": str(prior.get("name") or action.name),
        }
        for field_key in (
            "ipv4-address",
            "ipv6-address",
            "subnet4",
            "mask-length4",
            "ipv4-address-first",
            "ipv4-address-last",
            "is-sub-domain",
            "comments",
            "color",
            "tags",
            "groups",
            "nat-settings",
            "ignore-warnings",
            "set-if-exists",
        ):
            if field_key in prior and prior[field_key] is not None:
                op[field_key] = prior[field_key]
        return op

    return None


def _invert_service_action(
    action: PlannedAction,
    outcome: Outcome,
    prior: dict[str, Any],
    target_uid: str | None,
) -> dict[str, Any] | None:
    svc_type = action.object_type
    if outcome == Outcome.CREATE:
        op: dict[str, Any] = {
            "operation": "delete",
            "type": svc_type,
            "name": action.resolved_name or action.name,
        }
        if target_uid and not target_uid.startswith("planned:"):
            op["uid"] = target_uid
        return op

    if outcome == Outcome.UPDATE:
        if not prior:
            return None
        current_name = action.resolved_name or action.name
        prior_name = str(prior.get("name") or action.name)
        op = {
            "operation": "set",
            "type": svc_type,
            "name": current_name,
        }
        if target_uid:
            op["uid"] = target_uid
        elif prior.get("uid"):
            op["uid"] = str(prior["uid"])
        if prior_name != current_name:
            op["new-name"] = prior_name

        for field_key in (
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
        ):
            if field_key in prior and prior[field_key] is not None:
                op[field_key] = prior[field_key]
        return op

    if outcome == Outcome.DELETE:
        if not prior:
            return None
        op = {
            "operation": "add",
            "type": svc_type,
            "name": str(prior.get("name") or action.name),
        }
        for field_key in (
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
        ):
            if field_key in prior and prior[field_key] is not None:
                op[field_key] = prior[field_key]
        return op

    return None


def _invert_group_action(
    action: PlannedAction,
    outcome: Outcome,
    prior: dict[str, Any],
    target_uid: str | None,
) -> dict[str, Any] | None:
    grp_type = action.object_type
    if outcome == Outcome.CREATE:
        op: dict[str, Any] = {
            "operation": "delete",
            "type": grp_type,
            "name": action.resolved_name or action.name,
        }
        if target_uid and not target_uid.startswith("planned:"):
            op["uid"] = target_uid
        return op

    if outcome == Outcome.UPDATE:
        if not prior:
            return None
        current_name = action.resolved_name or action.name
        prior_name = str(prior.get("name") or action.name)
        op = {
            "operation": "set",
            "type": grp_type,
            "name": current_name,
        }
        if target_uid:
            op["uid"] = target_uid
        elif prior.get("uid"):
            op["uid"] = str(prior["uid"])
        if prior_name != current_name:
            op["new-name"] = prior_name
        if "members" in prior and isinstance(prior["members"], list):
            op["members"] = [str(m) for m in prior["members"]]
        for field_key in ("comments", "color", "tags"):
            if field_key in prior and prior[field_key] is not None:
                op[field_key] = prior[field_key]
        return op

    if outcome == Outcome.DELETE:
        if not prior:
            return None
        op = {
            "operation": "add",
            "type": grp_type,
            "name": str(prior.get("name") or action.name),
        }
        if "members" in prior and isinstance(prior["members"], list):
            op["members"] = [str(m) for m in prior["members"]]
        for field_key in ("comments", "color", "tags"):
            if field_key in prior and prior[field_key] is not None:
                op[field_key] = prior[field_key]
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
        uid_val = target_uid or prior.get("uid")
        if uid_val:
            op["uid"] = str(uid_val)
        if prior.get("name") is not None:
            op["name"] = str(prior["name"])

        for k in (
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
        ):
            if k in prior and prior[k] is not None:
                op[k] = prior[k]
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

        for k in (
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
        ):
            if k in prior and prior[k] is not None:
                op[k] = prior[k]
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
