"""Inverse templates: compensate an applied Plan via a normal schema-valid template."""

from __future__ import annotations

from typing import Any

from ..logger import get_logger
from .models import ApplyReport, Outcome, Plan, PlannedAction

logger = get_logger(__name__)

# Apply-time outcomes proving the action executed and changed state.
_EXECUTED = {Outcome.CREATE, Outcome.UPDATE, Outcome.DELETE}

# prior_state fields that are read-only/meta -> never replayed into an add.
_STRIP_FIELDS = {
    "uid",
    "meta-info",
    "domain",
    "type",
    "read-only",
    "available-actions",
    "creation-time",
    "last-modify-time",
    "creator",
    "last-modifier",
    "tags-meta",
    "icon",
    "_rule_number",
}

# existing (API) field name -> template field name (reverse of differ._FIELD_ALIASES)
_API_TO_TEMPLATE = {
    "ipv4-address": "ip-address",
    "ipv6-address": "ip-address",
    "subnet4": "subnet",
    "mask-length4": "mask-length",
    "subnet-mask": "mask-length",
    "ipv4-address-first": "ip-address-first",
    "ipv4-address-last": "ip-address-last",
}

_RULE_TYPES = {"access-rule", "nat-rule", "threat-prevention-rule", "https-rule"}


def _prior_to_add_data(prior: dict[str, Any]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for field, value in prior.items():
        if field in _STRIP_FIELDS or value is None:
            continue
        data[_API_TO_TEMPLATE.get(field, field)] = value
    return data


def _invert_create(action: PlannedAction, uid_by_id: dict[str, str]) -> dict[str, Any] | None:
    uid = uid_by_id.get(action.id)
    if not uid and not action.resolved_name:
        logger.warning("inverse: cannot key nameless created %s (%s); skipped", action.type, action.id)
        return None
    return {"operation": "delete", "key": {"uid": uid} if uid else {"name": action.resolved_name}}


def _invert_update(action: PlannedAction) -> dict[str, Any] | None:
    before = {f: c.get("before") for f, c in (action.changes or {}).items() if c.get("before") is not None}
    if not before:
        logger.warning("inverse: update %s has no restorable before-values; skipped", action.id)
        return None
    return {"operation": "update", "key": action.key or {"name": action.resolved_name}, "data": before}


def _invert_delete(action: PlannedAction) -> dict[str, Any] | None:
    if action.prior_state is None:
        return None  # was already absent -- nothing was deleted
    data = _prior_to_add_data(action.prior_state)
    if len(data) <= 1:  # only "name" (or nothing) survived stripping -- e.g. a stub cache row
        logger.warning(
            "inverse: prior_state for deleted %s (%s) has no restorable fields; skipped", action.type, action.id
        )
        return None
    op: dict[str, Any] = {"operation": "add", "data": data}
    if action.type in _RULE_TYPES:
        op["position"] = action.prior_state.get("_rule_number", "top")
    return op


def _invert_action(action: PlannedAction, uid_by_id: dict[str, str]) -> dict[str, Any] | None:
    if action.outcome == Outcome.CREATE:
        op = _invert_create(action, uid_by_id)
    elif action.outcome == Outcome.UPDATE:
        op = _invert_update(action)
    elif action.outcome == Outcome.DELETE:
        op = _invert_delete(action)
    else:
        op = None  # REUSE / UNCHANGED / CONFLICT / ERROR / show -> nothing to compensate
    if op is None:
        return None
    op["type"] = action.type
    if action.type in _RULE_TYPES:
        if action.layer:
            op["layer"] = action.layer
        if action.package:
            op["package"] = action.package
    return op


def build_inverse_template(plan: Plan, report: ApplyReport | None = None) -> dict[str, Any]:
    """Build a schema-valid template that compensates `plan`.

    With `report`, only actions that actually executed (per ActionResult) are inverted, and
    created-object uids from the report are used as precise delete keys. Apply the result via
    the normal plan()/apply() pipeline -- it re-resolves, re-orders, re-stamps and re-guards.
    """
    executed_ids: set[str] | None = None
    uid_by_id: dict[str, str] = {}
    if report is not None:
        executed_ids = {r.action_id for r in report.results if r.outcome in _EXECUTED}
        uid_by_id = {r.action_id: r.uid for r in report.results if r.uid}

    # Preserve the plan's original (mgmt, domain) appearance order for the output grouping,
    # even though operations within a domain are inverted in reverse action order below.
    domain_priority = {pair: i for i, pair in enumerate(plan.domains())}

    by_domain: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for action in reversed(plan.actions):  # reverse original order; planner re-sorts on re-plan anyway
        if executed_ids is not None and action.id not in executed_ids:
            continue
        op = _invert_action(action, uid_by_id)
        if op is None:
            continue
        by_domain.setdefault((action.mgmt_name, action.domain_name), []).append(op)

    servers: dict[str, dict[str, Any]] = {}
    for mgmt, domain in sorted(by_domain, key=lambda pair: domain_priority.get(pair, 0)):
        server = servers.setdefault(mgmt, {"mgmt_name": mgmt, "domains": []})
        server["domains"].append({"name": domain, "operations": by_domain[(mgmt, domain)]})
    return {"management_servers": list(servers.values())}
