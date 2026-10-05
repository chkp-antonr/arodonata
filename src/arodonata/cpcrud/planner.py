"""Decide phase: normalized template + StateReader + policy -> single Plan."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import ValidationError

from ..logger import get_logger
from .models import DomainStamp, IpConflictPolicy, NameConflictPolicy, Outcome, Plan, PlannedAction
from .naming import DEFAULT_PREFIXES, NamingPrefixes
from .resolver import (
    StateReader,
    StateReadError,
    _resolved_name_from_key,
    resolve_add,
    resolve_delete,
    resolve_nat_rule,
    resolve_nat_rule_by_key,
    resolve_rule,
    resolve_rule_by_key,
    resolve_show,
    resolve_update,
)
from .schema import normalize_operations, validate_template

logger = get_logger(__name__)

_TYPE_ORDER = {
    "host": 0,
    "network": 0,
    "address-range": 0,
    "network-group": 1,
    "tcp-service": 2,
    "udp-service": 2,
    "icmp-service": 2,
    "service-group": 3,
    "access-rule": 4,
    "nat-rule": 4,
    "threat-prevention-rule": 4,
    "https-rule": 4,
}
_MAX_ORDER = 4  # rules -- final tier, no further plans extend this

_LAYER_RULE_TYPES = ("access-rule", "threat-prevention-rule", "https-rule")


def template_hash(normalized_doc: dict[str, Any]) -> str:
    canonical = json.dumps(normalized_doc, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _sort_key(op: dict[str, Any]) -> tuple[int, int]:
    """adds/updates ascend (objects before groups); deletes descend (groups before objects); shows last-neutral."""
    order = _TYPE_ORDER.get(op.get("type", ""), 0)
    verb = op.get("operation", "add")
    if verb in ("add", "update"):
        return (0, order)
    if verb == "show":
        return (1, order)
    return (2, _MAX_ORDER - order)  # delete: reverse type order


def _topo_sort(actions: list[PlannedAction]) -> list[PlannedAction]:
    """Stable Kahn topological sort by depends_on; original order breaks ties.

    Unknown/missing dependency ids are ignored (they can't be satisfied by reordering)."""
    by_id = {a.id: a for a in actions}
    indeg = {a.id: sum(1 for d in a.depends_on if d in by_id) for a in actions}
    ready = [a for a in actions if indeg[a.id] == 0]
    out: list[PlannedAction] = []
    while ready:
        current = ready.pop(0)
        out.append(current)
        for a in actions:
            if current.id in a.depends_on and a.id in indeg:
                indeg[a.id] -= 1
                if indeg[a.id] == 0 and a not in ready and a not in out:
                    ready.append(a)
        ready.sort(key=lambda a: actions.index(a))
    if len(out) != len(actions):  # cycle -> keep original order for the rest
        out.extend(a for a in actions if a not in out)
    return out


def _dedupe_reuse(actions: list[PlannedAction]) -> list[PlannedAction]:
    """Collapse duplicate auto-created REUSE actions by (type, resolved_name); remap depends_on.

    Rule-resolver dependency synthesis runs per-rule (`resolve_rule`/`resolve_nat_rule` in
    `resolver.py`), so the same already-existing object referenced by two different rules
    produces two separate REUSE `PlannedAction`s with distinct plan-internal ids but identical
    `(type, resolved_name)`. Keep only the first and remap any `depends_on` edge pointing at a
    dropped duplicate onto the surviving action's id, so downstream cascade-skip logic still
    resolves correctly.
    """
    keep: dict[tuple[str, str], PlannedAction] = {}
    remap: dict[str, str] = {}
    out: list[PlannedAction] = []
    for a in actions:
        if a.auto_created and a.outcome == Outcome.REUSE:
            k = (a.type, a.resolved_name)
            if k in keep:
                remap[a.id] = keep[k].id
                continue
            keep[k] = a
        out.append(a)
    for a in out:
        a.depends_on = list(dict.fromkeys(remap.get(d, d) for d in a.depends_on))
    return out


def _lookup_failed_action(
    op: dict[str, Any], exc: StateReadError, *, mgmt: str, domain: str, action_id: str
) -> PlannedAction:
    data = op.get("data") or {}
    key = op.get("key") or {}
    return PlannedAction(
        id=action_id,
        operation=op["operation"],
        type=op["type"],
        mgmt_name=mgmt,
        domain_name=domain,
        desired=data,
        key=op.get("key"),
        resolved_name=data.get("name") or _resolved_name_from_key(key),
        layer=op.get("layer"),
        package=op.get("package"),
        outcome=Outcome.ERROR,
        message=f"lookup failed, nothing planned (re-plan to retry): {exc}",
    )


def _mark_lookup_failed(action: PlannedAction, detail: str) -> None:
    """Turn an already planned action into an ERROR that writes nothing."""
    action.outcome = Outcome.ERROR
    action.command = None
    action.payload = None
    action.message = f"lookup failed, nothing planned (re-plan to retry): {detail}"


class Planner:
    def __init__(self, reader: StateReader, settings: Any | None = None) -> None:
        self._reader = reader
        self._settings = settings
        self._prefixes = DEFAULT_PREFIXES
        if settings:
            try:
                self._prefixes = NamingPrefixes.from_settings(settings)
            except ValidationError:
                # Settings-like stand-ins (e.g. AsyncMock in unit tests) auto-generate
                # non-string attributes -- fall back to defaults rather than raising, exactly
                # like the "no settings" branch above.
                logger.warning("Planner: settings-like object had invalid naming-prefix fields; using defaults")

    def _policy(
        self,
        op: dict[str, Any],
        on_name: NameConflictPolicy | None,
        on_ip: IpConflictPolicy | None,
    ) -> tuple[NameConflictPolicy, IpConflictPolicy]:
        s = self._settings
        name_default = (
            (on_name.value if on_name else None)
            or (getattr(s, "cpcrud_on_name_conflict", None) if s else None)
            or "update"
        )
        ip_default = (
            (on_ip.value if on_ip else None) or (getattr(s, "cpcrud_on_ip_conflict", None) if s else None) or "reuse"
        )
        return (
            NameConflictPolicy(op.get("on_name_conflict", name_default)),
            IpConflictPolicy(op.get("on_ip_conflict", ip_default)),
        )

    async def decide(
        self,
        doc: dict[str, Any],
        on_name: NameConflictPolicy | None = None,
        on_ip: IpConflictPolicy | None = None,
    ) -> Plan:
        errors = validate_template(doc)
        if errors:
            from ..core.exceptions import ConfigurationError

            raise ConfigurationError("Invalid CPCRUD template: " + "; ".join(errors))
        normalized = normalize_operations(doc)

        actions: list[PlannedAction] = []
        stamps: list[DomainStamp] = []
        counter = 0
        for ms in normalized.get("management_servers", []):
            mgmt = ms["mgmt_name"]
            for domain in ms.get("domains", []):
                domain_name = domain["name"]
                ops = sorted(domain.get("operations", []), key=_sort_key)
                # The stamp is read BEFORE the lookups, so a publish while the domain is planned leaves the plan
                # stale at apply instead of being stamped as seen (as the object cache does, Backlog #36).
                try:
                    head = await self._reader.get_last_publish_session(mgmt=mgmt, domain=domain_name)
                except StateReadError as exc:
                    # Without a stamp the plan cannot be checked for staleness: plan nothing here (Backlog #39).
                    for op in ops:
                        counter += 1
                        actions.append(
                            _lookup_failed_action(
                                op, exc, mgmt=mgmt, domain=domain_name, action_id=f"act-{counter:04d}"
                            )
                        )
                    continue
                stamps.append(DomainStamp(mgmt_name=mgmt, domain_name=domain_name, last_publish_session=head))
                domain_actions, counter = await self._plan_domain(
                    ops, mgmt=mgmt, domain_name=domain_name, counter=counter, on_name=on_name, on_ip=on_ip
                )
                actions.extend(domain_actions)
        return Plan(actions=actions, stamps=stamps, template_hash=template_hash(normalized))

    async def _plan_domain(
        self,
        ops: list[dict[str, Any]],
        *,
        mgmt: str,
        domain_name: str,
        counter: int,
        on_name: NameConflictPolicy | None,
        on_ip: IpConflictPolicy | None,
    ) -> tuple[list[PlannedAction], int]:
        """Resolve one domain's sorted operations into its ordered actions and the updated counter."""
        domain_actions: list[PlannedAction] = []
        for op in ops:
            counter += 1
            action_id = f"act-{counter:04d}"
            try:
                new_actions, counter = await self._resolve_op(
                    op,
                    mgmt=mgmt,
                    domain_name=domain_name,
                    action_id=action_id,
                    counter=counter,
                    on_name=on_name,
                    on_ip=on_ip,
                )
            except StateReadError as exc:
                # A lookup that did not happen is not "not found": plan nothing for this operation (its
                # auto-created dependencies included) rather than create a duplicate (Backlog #37).
                new_actions = [_lookup_failed_action(op, exc, mgmt=mgmt, domain=domain_name, action_id=action_id)]
            domain_actions.extend(new_actions)
        domain_actions, counter = await self._ensure_group_dependencies(domain_actions, mgmt, domain_name, counter)
        return _topo_sort(_dedupe_reuse(domain_actions)), counter

    async def _resolve_op(
        self,
        op: dict[str, Any],
        *,
        mgmt: str,
        domain_name: str,
        action_id: str,
        counter: int,
        on_name: NameConflictPolicy | None,
        on_ip: IpConflictPolicy | None,
    ) -> tuple[list[PlannedAction], int]:
        """Resolve a single normalized operation into its ordered new actions and the updated counter.

        Rule types are dispatched on `type` first, ahead of the generic operation-based dispatch
        below: rule identity is fundamentally different (traffic-tuple for `add`, key-based for
        update/delete/show), never name-based like plain objects/services.
        """
        operation = op["operation"]
        otype = op["type"]
        if otype in _LAYER_RULE_TYPES and operation == "add":
            action, deps, counter = await resolve_rule(
                self._reader,
                otype,
                op,
                mgmt=mgmt,
                domain=domain_name,
                action_id=action_id,
                counter=counter,
                prefixes=self._prefixes,
            )
            return [*deps, action], counter
        if otype == "nat-rule" and operation == "add":
            action, deps, counter = await resolve_nat_rule(
                self._reader,
                op,
                mgmt=mgmt,
                domain=domain_name,
                action_id=action_id,
                counter=counter,
                prefixes=self._prefixes,
            )
            return [*deps, action], counter
        if otype in _LAYER_RULE_TYPES and operation in ("update", "delete", "show"):
            action, deps, counter = await resolve_rule_by_key(
                self._reader,
                otype,
                operation,
                op,
                mgmt=mgmt,
                domain=domain_name,
                action_id=action_id,
                counter=counter,
                prefixes=self._prefixes,
            )
            return [*deps, action], counter
        if otype == "nat-rule" and operation in ("update", "delete", "show"):
            action, deps, counter = await resolve_nat_rule_by_key(
                self._reader,
                operation,
                op,
                mgmt=mgmt,
                domain=domain_name,
                action_id=action_id,
                counter=counter,
                prefixes=self._prefixes,
            )
            return [*deps, action], counter
        if operation == "add":
            pol_name, pol_ip = self._policy(op, on_name, on_ip)
            action = await resolve_add(
                self._reader,
                otype,
                op.get("data", {}),
                on_name=pol_name,
                on_ip=pol_ip,
                mgmt=mgmt,
                domain=domain_name,
                action_id=action_id,
            )
            return [action], counter
        if operation == "update":
            action = await resolve_update(
                self._reader,
                otype,
                op.get("key", {}),
                op.get("data", {}),
                mgmt=mgmt,
                domain=domain_name,
                action_id=action_id,
            )
            return [action], counter
        if operation == "delete":
            action = await resolve_delete(
                self._reader,
                otype,
                op.get("key", {}),
                mgmt=mgmt,
                domain=domain_name,
                action_id=action_id,
            )
            return [action], counter
        if operation == "show":
            action = await resolve_show(
                self._reader,
                otype,
                op.get("key", {}),
                mgmt=mgmt,
                domain=domain_name,
                action_id=action_id,
            )
            return [action], counter
        return [], counter

    async def _ensure_group_dependencies(
        self,
        domain_actions: list[PlannedAction],
        mgmt: str,
        domain: str,
        counter: int,
    ) -> tuple[list[PlannedAction], int]:
        explicit_groups = {
            a.desired.get("name"): a for a in domain_actions if a.type == "network-group" and a.operation == "add"
        }
        synthesized: dict[str, PlannedAction] = {}
        for action in domain_actions:
            if action.operation not in ("add", "update") or action.type == "network-group":
                continue
            if action.outcome == Outcome.ERROR:
                continue  # nothing is written for it, so neither are the groups it names (Backlog #37)
            planned: dict[str, PlannedAction] = {}  # this action's new group actions, kept only if all resolve
            deps: list[PlannedAction] = []
            try:
                for group in action.desired.get("groups", []) or []:
                    dep = explicit_groups.get(group) or synthesized.get(group) or planned.get(group)
                    if dep is None:
                        dep, counter = await self._group_dependency(group, mgmt, domain, counter)
                        planned[group] = dep
                    deps.append(dep)
            except StateReadError as exc:
                # The object cannot be written without knowing whether its group exists (Backlog #37).
                _mark_lookup_failed(action, f"group {group!r}: {exc}")
                continue
            synthesized.update(planned)
            for dep in deps:
                if dep.id not in action.depends_on:
                    action.depends_on.append(dep.id)
        return list(synthesized.values()) + domain_actions, counter

    async def _group_dependency(self, group: str, mgmt: str, domain: str, counter: int) -> tuple[PlannedAction, int]:
        """Reuse or auto-create one group named in an object's `groups`; raises StateReadError if its lookup fails."""
        existing = await self._reader.get_by_name("network-group", group, mgmt=mgmt, domain=domain)
        counter += 1
        if existing is not None:
            return PlannedAction(
                id=f"act-{counter:04d}",
                operation="add",
                type="network-group",
                mgmt_name=mgmt,
                domain_name=domain,
                desired={"name": group},
                resolved_name=group,
                resolved_uid=existing.uid,
                outcome=Outcome.REUSE,
                auto_created=True,
                message="reused existing (referenced in groups)",
            ), counter
        return PlannedAction(
            id=f"act-{counter:04d}",
            operation="add",
            type="network-group",
            mgmt_name=mgmt,
            domain_name=domain,
            desired={"name": group},
            resolved_name=group,
            outcome=Outcome.CREATE,
            command="add-group",
            payload={"name": group},
            auto_created=True,
            message="auto-created (referenced in groups)",
        ), counter
