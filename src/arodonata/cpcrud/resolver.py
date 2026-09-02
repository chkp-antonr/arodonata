"""Kind-generic create-or-reuse resolver (Decide phase, no writes)."""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from .differ import _equal, diff_object
from .models import (
    ConflictInfo,
    IpConflictPolicy,
    NameConflictPolicy,
    ObjectMatch,
    ObjectState,
    Outcome,
    PlannedAction,
)
from .naming import DEFAULT_PREFIXES, NamingPrefixes, matches_convention
from .nat import transform_nat_settings
from .position_helper import resolve_nat_position, resolve_position
from .rule_identity import nat_tuple, pick_tie_break
from .services import resolve_service as _resolve_service_spec

if TYPE_CHECKING:
    from .models import LayerInfo, RuleMatch, SectionInfo
    from .services import ServiceSpec

# template type -> API command suffix
_TYPE_CMD: dict[str, str] = {
    "host": "host",
    "network": "network",
    "address-range": "address-range",
    "network-group": "group",
    "tcp-service": "service-tcp",
    "udp-service": "service-udp",
    "icmp-service": "service-icmp",
    "service-group": "service-group",
}


@runtime_checkable
class StateReader(Protocol):
    async def get_by_name(self, type: str, name: str, *, mgmt: str, domain: str) -> ObjectState | None: ...
    async def find_by_ip(self, *, type: str, ip_value: dict[str, Any], mgmt: str, domain: str) -> list[ObjectState]: ...
    async def where_used(self, uid: str, *, mgmt: str, domain: str) -> int: ...
    async def get_last_publish_session(self, *, mgmt: str, domain: str) -> str: ...
    async def get_service(
        self, spec: ServiceSpec, original_text: str, *, mgmt: str, domain: str
    ) -> ObjectState | None: ...
    async def get_layer(self, layer_ref: str, layer_type: str, *, mgmt: str, domain: str) -> LayerInfo | None: ...
    async def get_section(
        self, section_ref: str, layer_uid: str, layer_type: str, *, mgmt: str, domain: str
    ) -> SectionInfo | None: ...
    async def get_last_rule(self, scope_uid: str, layer_type: str, *, mgmt: str, domain: str) -> RuleMatch | None: ...
    async def find_rules_by_traffic(
        self,
        scope_uid: str,
        layer_type: str,
        source_uids: list[str],
        dest_uids: list[str],
        service_uids: list[str],
        *,
        mgmt: str,
        domain: str,
    ) -> list[RuleMatch]: ...
    async def find_nat_rules_by_tuple(
        self, package: str, tup: tuple[str, str, str, str, str, str], *, mgmt: str, domain: str
    ) -> list[RuleMatch]: ...
    async def get_last_nat_rule(self, package: str, *, mgmt: str, domain: str) -> RuleMatch | None: ...
    async def get_rule_by_key(
        self, scope_uid: str, layer_type: str, key: dict[str, Any], *, mgmt: str, domain: str
    ) -> RuleMatch | None: ...
    async def get_nat_rule_by_key(
        self, package: str, key: dict[str, Any], *, mgmt: str, domain: str
    ) -> RuleMatch | None: ...


def _ip_value(object_type: str, desired: dict[str, Any]) -> dict[str, Any] | None:
    if object_type == "host" and desired.get("ip-address"):
        return {"ip-address": desired["ip-address"]}
    if object_type == "network" and desired.get("subnet"):
        return {"subnet": desired["subnet"], "mask-length": desired.get("mask-length")}
    if object_type == "address-range" and desired.get("ip-address-first"):
        return {"ip-address-first": desired["ip-address-first"], "ip-address-last": desired.get("ip-address-last")}
    return None


def _to_match(state: ObjectState, where_used_total: int = 0) -> ObjectMatch:
    return ObjectMatch(name=state.name, uid=state.uid, where_used_total=where_used_total)


def _build_payload(object_type: str, fields: dict[str, Any]) -> dict[str, Any]:
    payload = dict(fields)
    nat = transform_nat_settings(object_type, payload.pop("nat-settings", None))
    if nat is not None:
        payload["nat-settings"] = nat
    return payload


def _lock_warning(base: PlannedAction, existing: ObjectState) -> None:
    lock = existing.lock
    if lock and "other session" in lock:
        base.warnings.append(f"object '{existing.name}' is {lock} (advisory; may fail as LOCKED at apply)")


async def resolve_add(
    reader: StateReader,
    object_type: str,
    desired: dict[str, Any],
    *,
    on_name: NameConflictPolicy,
    on_ip: IpConflictPolicy,
    mgmt: str,
    domain: str,
    action_id: str,
) -> PlannedAction:
    name = desired.get("name", "")
    suffix = _TYPE_CMD.get(object_type, object_type)
    base = PlannedAction(
        id=action_id,
        operation="add",
        type=object_type,
        desired=desired,
        resolved_name=name,
        mgmt_name=mgmt,
        domain_name=domain,
    )

    existing = await reader.get_by_name(object_type, name, mgmt=mgmt, domain=domain)
    if existing is not None:
        diff = diff_object(object_type, desired, existing)
        if not diff.has_changes:
            base.outcome = Outcome.UNCHANGED
            base.resolved_uid = existing.uid
            base.matches = [_to_match(existing)]
            base.message = "already in desired state"
            return base
        # name exists with differences
        if on_name is NameConflictPolicy.ERROR:
            base.outcome = Outcome.CONFLICT
            base.conflict = ConflictInfo(
                axis="name", policy=on_name.value, requested=desired, candidates=[_to_match(existing)]
            )
            base.message = "name conflict; policy=error"
            return base
        base.outcome = Outcome.UPDATE
        base.resolved_uid = existing.uid
        _lock_warning(base, existing)
        base.matches = [_to_match(existing)]
        base.changes = diff.changes
        base.command = f"set-{suffix}"
        base.payload = {
            "uid": existing.uid,
            **_build_payload(object_type, {k: v for k, v in desired.items() if k != "name"}),
        }
        return base

    # not present by name -> check IP collision
    ip_value = _ip_value(object_type, desired)
    if ip_value is not None:
        candidates = await reader.find_by_ip(type=object_type, ip_value=ip_value, mgmt=mgmt, domain=domain)
        if candidates:
            if on_ip is IpConflictPolicy.ERROR:
                base.outcome = Outcome.CONFLICT
                base.conflict = ConflictInfo(
                    axis="ip", policy=on_ip.value, requested=ip_value, candidates=[_to_match(c) for c in candidates]
                )
                base.message = "ip conflict; policy=error"
                return base
            if on_ip is IpConflictPolicy.REUSE:
                scored = [
                    (
                        c,
                        matches_convention(object_type, c.name),
                        await reader.where_used(c.uid, mgmt=mgmt, domain=domain),
                    )
                    for c in candidates
                ]
                scored.sort(key=lambda t: (t[1], t[2]), reverse=True)  # convention first, then usage
                base.outcome = Outcome.REUSE
                base.matches = [
                    ObjectMatch(
                        name=c.name, uid=c.uid, type=object_type, where_used_total=total, matches_convention=conv
                    )
                    for c, conv, total in scored
                ]
                base.resolved_uid = scored[0][0].uid
                base.resolved_name = scored[0][0].name
                base.message = f"reused existing {scored[0][0].name}"
                return base
            # CREATE_NEW falls through to create, recording the conflict
            base.conflict = ConflictInfo(
                axis="ip", policy=on_ip.value, requested=ip_value, candidates=[_to_match(c) for c in candidates]
            )

    base.outcome = Outcome.CREATE
    base.command = f"add-{suffix}"
    base.payload = _build_payload(object_type, desired)
    base.matches = []  # executor fills [self] after create
    return base


async def resolve_update(
    reader: StateReader,
    object_type: str,
    key: dict[str, Any],
    data: dict[str, Any],
    *,
    mgmt: str,
    domain: str,
    action_id: str,
) -> PlannedAction:
    suffix = _TYPE_CMD.get(object_type, object_type)
    name = key.get("name") or key.get("uid") or ""
    existing = await reader.get_by_name(object_type, name, mgmt=mgmt, domain=domain)
    base = PlannedAction(
        id=action_id,
        operation="update",
        type=object_type,
        key=key,
        desired=data,
        resolved_name=data.get("name", name),
        mgmt_name=mgmt,
        domain_name=domain,
    )
    if existing is None:
        base.outcome = Outcome.ERROR
        base.message = "object not found for update"
        return base
    diff = diff_object(object_type, data, existing)
    base.resolved_uid = existing.uid
    _lock_warning(base, existing)
    if not diff.has_changes:
        base.outcome = Outcome.UNCHANGED
        base.matches = [_to_match(existing)]
        return base
    base.outcome = Outcome.UPDATE
    base.changes = diff.changes
    base.command = f"set-{suffix}"
    base.payload = {"uid": existing.uid, **_build_payload(object_type, data)}
    return base


async def resolve_delete(
    reader: StateReader, object_type: str, key: dict[str, Any], *, mgmt: str, domain: str, action_id: str
) -> PlannedAction:
    suffix = _TYPE_CMD.get(object_type, object_type)
    name = key.get("name") or key.get("uid") or ""
    existing = await reader.get_by_name(object_type, name, mgmt=mgmt, domain=domain)
    base = PlannedAction(
        id=action_id,
        operation="delete",
        type=object_type,
        key=key,
        resolved_name=name,
        mgmt_name=mgmt,
        domain_name=domain,
    )
    if existing is None:
        base.outcome = Outcome.DELETE
        base.message = "already absent"
        return base
    base.outcome = Outcome.DELETE
    base.resolved_uid = existing.uid
    base.prior_state = dict(existing.raw)
    _lock_warning(base, existing)
    base.command = f"delete-{suffix}"
    base.payload = {"uid": existing.uid}
    return base


async def resolve_show(
    reader: StateReader, object_type: str, key: dict[str, Any], *, mgmt: str, domain: str, action_id: str
) -> PlannedAction:
    name = key.get("name") or key.get("uid") or ""
    existing = await reader.get_by_name(object_type, name, mgmt=mgmt, domain=domain)
    base = PlannedAction(
        id=action_id,
        operation="show",
        type=object_type,
        key=key,
        resolved_name=name,
        mgmt_name=mgmt,
        domain_name=domain,
    )
    if existing is None:
        base.outcome = Outcome.ERROR
        base.message = "not found"
    else:
        base.outcome = Outcome.UNCHANGED
        base.resolved_uid = existing.uid
        base.matches = [_to_match(existing)]
    return base


_BARE_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_CIDR = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
_RANGE = re.compile(r"^(\d{1,3}(\.\d{1,3}){3})-(\d{1,3}(\.\d{1,3}){3})$")


def _classify_reference(text: str) -> str | None:
    """Return 'host' | 'network' | 'address-range' | None (not an IP-shaped string)."""
    if _BARE_IP.match(text):
        return "host"
    if _CIDR.match(text):
        return "network"
    if _RANGE.match(text):
        return "address-range"
    return None


async def resolve_ip_reference(
    reader: StateReader,
    text: str,
    *,
    mgmt: str,
    domain: str,
    action_id: str,
    prefixes: NamingPrefixes | None = None,
) -> tuple[str, PlannedAction | None]:
    """Resolve a bare IP/CIDR/range string in a rule's source/destination to a reference or a synthesized CREATE.

    Returns the object's NAME, not its uid, for an existing match -- confirmed against the live
    lab (Task 14) that `find_rules_by_traffic`'s traffic-tuple comparison works against the live
    rulebase's *dereferenced* (uid->name) fields (see statereader.py's `_dereference_rule`), so
    this side of the comparison must speak names too, matching the "Any"/auto-created-dependency
    cases below (which were already name-based) instead of mixing uid and name representations.
    CP's add/set-*-rule commands accept either form for these fields, so this is payload-safe.
    """
    if text.strip().lower() == "any":
        return "Any", None

    kind = _classify_reference(text)
    if kind is None:
        return text, None  # plain object name -- pass through, no resolution needed here

    p = prefixes or DEFAULT_PREFIXES
    prefix = "global_" if domain == "Global" else ""

    if kind == "network":
        addr, mask = text.split("/")
        try:
            ipaddress.ip_network(text, strict=True)
        except ValueError:
            canonical = ipaddress.ip_network(text, strict=False)
            raise ValueError(f"{text!r} has host bits set; did you mean the canonical network {canonical}?") from None
        name = f"{prefix}{p.network}{addr}_{mask}"
        ip_value = {"subnet": addr, "mask-length": int(mask)}
        candidates = await reader.find_by_ip(type="network", ip_value=ip_value, mgmt=mgmt, domain=domain)
        if candidates:
            c = candidates[0]
            return c.name, PlannedAction(
                id=action_id,
                operation="add",
                type="network",
                mgmt_name=mgmt,
                domain_name=domain,
                desired={"name": c.name, **ip_value},
                resolved_name=c.name,
                resolved_uid=c.uid,
                outcome=Outcome.REUSE,
                auto_created=True,
                message="reused existing (referenced in rule)",
            )
        return action_id, PlannedAction(
            id=action_id,
            operation="add",
            type="network",
            mgmt_name=mgmt,
            domain_name=domain,
            desired={"name": name, **ip_value},
            resolved_name=name,
            outcome=Outcome.CREATE,
            command="add-network",
            payload={"name": name, **ip_value},
            auto_created=True,
            message="auto-created (bare CIDR referenced in rule)",
        )

    if kind == "host":
        name = f"{prefix}{p.host}{text}"
        ip_value = {"ip-address": text}
        candidates = await reader.find_by_ip(type="host", ip_value=ip_value, mgmt=mgmt, domain=domain)
        if candidates:
            c = candidates[0]
            return c.name, PlannedAction(
                id=action_id,
                operation="add",
                type="host",
                mgmt_name=mgmt,
                domain_name=domain,
                desired={"name": c.name, **ip_value},
                resolved_name=c.name,
                resolved_uid=c.uid,
                outcome=Outcome.REUSE,
                auto_created=True,
                message="reused existing (referenced in rule)",
            )
        return action_id, PlannedAction(
            id=action_id,
            operation="add",
            type="host",
            mgmt_name=mgmt,
            domain_name=domain,
            desired={"name": name, **ip_value},
            resolved_name=name,
            outcome=Outcome.CREATE,
            command="add-host",
            payload={"name": name, **ip_value},
            auto_created=True,
            message="auto-created (bare IP referenced in rule)",
        )

    # address-range
    first, last = text.split("-")
    name = f"{prefix}{p.range}{first}-{last}"
    ip_value = {"ip-address-first": first, "ip-address-last": last}
    candidates = await reader.find_by_ip(type="address-range", ip_value=ip_value, mgmt=mgmt, domain=domain)
    if candidates:
        c = candidates[0]
        return c.name, PlannedAction(
            id=action_id,
            operation="add",
            type="address-range",
            mgmt_name=mgmt,
            domain_name=domain,
            desired={"name": c.name, **ip_value},
            resolved_name=c.name,
            resolved_uid=c.uid,
            outcome=Outcome.REUSE,
            auto_created=True,
            message="reused existing (referenced in rule)",
        )
    return action_id, PlannedAction(
        id=action_id,
        operation="add",
        type="address-range",
        mgmt_name=mgmt,
        domain_name=domain,
        desired={"name": name, **ip_value},
        resolved_name=name,
        outcome=Outcome.CREATE,
        command="add-address-range",
        payload={"name": name, **ip_value},
        auto_created=True,
        message="auto-created (bare range referenced in rule)",
    )


async def resolve_service_reference(
    reader: StateReader,
    text: str,
    *,
    mgmt: str,
    domain: str,
    action_id: str,
    prefixes: NamingPrefixes | None = None,
) -> tuple[str, PlannedAction | None]:
    """Find-or-create resolve one rule-service entry, using Plan B's resolve_service.

    Returns the service's NAME (not uid) for an existing match -- see `resolve_ip_reference`'s
    docstring for why: the live rulebase comparison speaks names (Task 14's dereferencing fix),
    so this side must too.
    """
    resolution = await _resolve_service_spec(reader, text, mgmt=mgmt, domain=domain, prefixes=prefixes)
    if resolution.outcome == "any":
        return "Any", None
    if resolution.outcome == "error":
        raise ValueError(resolution.message)
    if resolution.outcome == "match":
        return resolution.name, PlannedAction(
            id=action_id,
            operation="add",
            type=resolution.type,
            mgmt_name=mgmt,
            domain_name=domain,
            desired={"name": resolution.name},
            resolved_name=resolution.name,
            resolved_uid=resolution.uid,
            outcome=Outcome.REUSE,
            auto_created=True,
            message="reused existing (referenced in rule service field)",
        )
    # create
    return action_id, PlannedAction(
        id=action_id,
        operation="add",
        type=resolution.type,
        mgmt_name=mgmt,
        domain_name=domain,
        desired={"name": resolution.name, **resolution.payload},
        resolved_name=resolution.name,
        outcome=Outcome.CREATE,
        command=resolution.command,
        payload=resolution.payload,
        auto_created=True,
        message="auto-created (referenced in rule service field)",
    )


# rule_type -> layer type used by StateReader.get_layer/find_rules_by_traffic
_RULE_LAYER_TYPE: dict[str, str] = {
    "access-rule": "access",
    "threat-prevention-rule": "threat-prevention",
    "https-rule": "https",
}
# rule_type -> API command suffix (add-<x>/set-<x>)
_RULE_CMD: dict[str, str] = {
    "access-rule": "access-rule",
    "threat-prevention-rule": "threat-rule",
    "https-rule": "https-rule",
}
# rule_type -> non-traffic data fields considered for the UNCHANGED/UPDATE decision.
# source/destination/service are deliberately excluded here -- their identity is decided by
# the traffic-tuple match (find_rules_by_traffic), never by direct field comparison.
_RULE_DATA_FIELDS: dict[str, tuple[str, ...]] = {
    "access-rule": ("enabled", "comments", "action", "track", "install-on", "time", "vpn"),
    "threat-prevention-rule": ("enabled", "comments", "protected-scope", "action", "track", "install-on"),
    "https-rule": ("enabled", "comments", "site-category", "action", "track", "blade", "certificate", "install-on"),
}
# NAT counterpart to _RULE_DATA_FIELDS -- original-source/original-destination/original-service/
# translated-* are deliberately excluded, same reasoning (identity decided by the tuple match).
_NAT_DATA_FIELDS: tuple[str, ...] = ("name", "method", "enabled", "comments", "install-on")


async def _resolve_reference_list(
    reader: StateReader,
    texts: list[str],
    resolver_fn,
    mgmt: str,
    domain: str,
    counter: int,
    prefixes: NamingPrefixes | None = None,
) -> tuple[list[str], list[PlannedAction], int]:
    """Resolve each source/destination/service entry to a payload reference.

    Auto-created dependencies contribute their `resolved_name` (never their plan-internal
    `id`) to the payload -- rules' source/destination/service fields accept object names
    directly, exactly like Plan A/B's existing group-auto-create pattern. `depends_on`
    edges (added by the caller) still use the plan-internal id, for cascade-skip purposes.
    """
    resolved: list[str] = []
    deps: list[PlannedAction] = []
    for text in texts:
        counter += 1
        ref, dep = await resolver_fn(
            reader, text, mgmt=mgmt, domain=domain, action_id=f"act-{counter:04d}", prefixes=prefixes
        )
        if dep is not None:
            resolved.append(dep.resolved_name)
            deps.append(dep)
        else:
            resolved.append(ref)
    return resolved, deps, counter


def _with_new_name(fields: dict[str, Any]) -> dict[str, Any]:
    """CP's set-*-rule commands treat `name` purely as an ALTERNATE IDENTIFIER (like `uid` or
    `rule-number`), never as a settable field -- sending `uid` and `name` together is rejected
    outright ("need only one of uid/rule-number/name"), confirmed against the live lab in Task
    14 (the rename-updates-not-duplicates scenario failed with exactly this error). Renaming an
    existing rule requires `new-name` instead (confirmed via Check Point's own set-access-rule
    API reference). `add-*-rule`/`add-nat-rule` are unaffected -- there's no uid yet to collide
    with on create, so plain `name` is correct there and left alone.
    """
    if "name" not in fields:
        return fields
    out = dict(fields)
    out["new-name"] = out.pop("name")
    return out


def _rule_field_equal(field: str, desired_val: Any, existing_val: Any) -> bool:
    """Idempotency comparison for one rule data field.

    Reuses differ.py's `_equal` for scalars and lists -- this gives rule fields the same
    int-as-string coercion and list-of-dicts-vs-names normalization already proven for plain
    objects (e.g. `install-on`/`time` commonly come back from the live API as
    `[{"name": ..., "uid": ...}, ...]` even though the template declares plain names).

    For nested dict fields (e.g. `track`), `_equal` falls through to plain `dict == dict`,
    which is unsafe: the live API routinely expands a dict field with extra default keys
    (e.g. `track: {"type": "Log"}` in the template vs. the live `track: {"type": "Log",
    "name": "Log", "settings": {...}}`). A naive full-equality check would spuriously report
    a change for every rule that merely has a track object, breaking idempotency the same
    way the pre-Plan-B icmp-type coercion bug and Plan A's differ.py groups bug did. Instead,
    recurse and compare only the keys the template actually declared (declared-subset
    comparison), matching the same "only compare what desired declares" philosophy
    `diff_object` already uses at the top level.
    """
    if isinstance(desired_val, dict):
        if not isinstance(existing_val, dict):
            return False
        return all(_rule_field_equal(k, v, existing_val.get(k)) for k, v in desired_val.items())
    if field == "action" and isinstance(desired_val, str) and isinstance(existing_val, str):
        # CP's action names are a fixed canonical enum (dereferenced from the live rulebase's
        # action uid via statereader.py's use-object-dictionary fix -- e.g. "Accept"/"Drop"),
        # but templates commonly declare them lowercase (confirmed by this plan's own given
        # live tests, which use action="accept"). Case carries no semantic meaning here, so
        # folding it avoids a spurious UPDATE on every re-apply.
        return desired_val.lower() == existing_val.lower()
    return _equal(field, desired_val, existing_val)


async def resolve_rule(
    reader: StateReader,
    rule_type: str,
    op: dict[str, Any],
    *,
    mgmt: str,
    domain: str,
    action_id: str,
    counter: int,
    prefixes: NamingPrefixes | None = None,
) -> tuple[PlannedAction, list[PlannedAction], int]:
    """Create-or-reuse decision for one access/threat-prevention/https rule.

    Unlike plain objects (identity = name), a rule's identity is its traffic tuple
    (source, destination, service) -- see rule_identity.py. Renaming a rule in the template
    is therefore never a CREATE: if the traffic tuple already matches an existing rule, that
    rule is the target of an UPDATE (or UNCHANGED), regardless of name differences.
    """
    data = op.get("data", {})
    layer_ref = op["layer"]
    layer_type = _RULE_LAYER_TYPE[rule_type]
    rule_cmd = _RULE_CMD[rule_type]

    layer = await reader.get_layer(layer_ref, layer_type, mgmt=mgmt, domain=domain)
    if layer is None:
        from ..core.exceptions import ConfigurationError

        raise ConfigurationError(f"Layer {layer_ref!r} not found ({layer_type})")

    # source/destination/service are optional per the ops schema (only `name` is required in
    # `data`) -- default to "any" when the template omits them, matching CP's own semantics.
    src_texts = data.get("source", ["any"]) or ["any"]
    dst_texts = data.get("destination", ["any"]) or ["any"]
    svc_texts = data.get("service", ["any"]) or ["any"]

    src_refs, src_deps, counter = await _resolve_reference_list(
        reader, src_texts, resolve_ip_reference, mgmt, domain, counter, prefixes
    )
    dst_refs, dst_deps, counter = await _resolve_reference_list(
        reader, dst_texts, resolve_ip_reference, mgmt, domain, counter, prefixes
    )
    svc_refs, svc_deps, counter = await _resolve_reference_list(
        reader, svc_texts, resolve_service_reference, mgmt, domain, counter, prefixes
    )
    all_deps = src_deps + dst_deps + svc_deps

    base = PlannedAction(
        id=action_id,
        operation="add",
        type=rule_type,
        mgmt_name=mgmt,
        domain_name=domain,
        layer=layer_ref,
        position=op.get("position"),
        desired=data,
        depends_on=[d.id for d in all_deps],
        resolved_name=data.get("name", ""),
    )

    # Traffic-tuple matching uses the UID/name form resolved above; for auto-created deps
    # (name-only, not yet a real object) the traffic tuple naturally won't match anything
    # existing -- correct, since a rule referencing a brand-new object cannot already exist.
    existing_rules = await reader.find_rules_by_traffic(
        layer.uid, layer_type, src_refs, dst_refs, svc_refs, mgmt=mgmt, domain=domain
    )

    payload_fields = {k: data[k] for k in _RULE_DATA_FIELDS[rule_type] if k in data}
    payload = {
        "name": data.get("name", ""),
        "source": src_refs,
        "destination": dst_refs,
        "service": svc_refs,
        **payload_fields,
    }

    if not existing_rules:
        base.outcome = Outcome.CREATE
        base.command = f"add-{rule_cmd}"
        # Task 8's resolve_position was built specifically to be consumed here (Task 11's own
        # "Consumes" line names it) but the original sketch never actually called it -- CP's
        # add-*-rule commands require `position` in the payload (confirmed missing-parameter
        # error against the live lab in Task 14), so this was a genuine gap, not a shape guess.
        position_fragment = await resolve_position(
            reader, op["position"], layer.uid, layer_type, mgmt=mgmt, domain=domain
        )
        base.payload = {"layer": layer_ref, **position_fragment, **payload}
        return base, all_deps, counter

    winner = pick_tie_break(existing_rules, declared_name=data.get("name"))
    base.resolved_uid = winner.uid
    base.resolved_name = winner.name

    other_fields_match = all(
        _rule_field_equal(k, data[k], winner.raw.get(k)) for k in ("name", *_RULE_DATA_FIELDS[rule_type]) if k in data
    )
    if other_fields_match:
        base.outcome = Outcome.UNCHANGED
        return base, all_deps, counter

    base.outcome = Outcome.UPDATE
    base.command = f"set-{rule_cmd}"
    # Only include a field in the UPDATE payload if the template's `data` actually declared
    # it -- iterate `data.keys()` directly rather than reconstructing which of `payload`'s
    # pre-built keys came from `data` vs. defaults. `layer` is required by CP's set-*-rule
    # commands alongside `uid` (rule uids are only unique within their owning layer).
    update_fields = _with_new_name({k: payload[k] for k in data if k in payload})
    base.payload = {"uid": winner.uid, "layer": layer_ref, **update_fields}
    return base, all_deps, counter


# Check Point's special "Any" object is referenced by its actual, platform-fixed system UID on
# NAT writes -- unlike access/threat/https rules, `add-nat-rule`/`set-nat-rule` reject the
# literal name "Any" outright ("Requested object [Any] not found", confirmed against the live
# lab in Task 14 with a raw API call that bypassed cpcrud entirely). This UID is NOT
# domain-specific: it's cross-verified identical on two independent Check Point installations --
# this lab's own live server AND Check Point's own official add-nat-rule/show-access-rulebase
# API doc examples, both showing uid "97aeb369-9aea-11d5-bd16-0090272ccb30" / name "Any" / type
# "CpmiAnyObject". This only applies to `original-*` fields and only in the OUTGOING PAYLOAD --
# `translated-*` fields never use "Any" at all, see `_NAT_NO_TRANSLATION` below.
#
# Exported as a public name (see `arodonata/__init__.py`) so other in-org consumers that build
# their own `set-nat-rule`/`add-nat-rule` payloads (e.g. MMP's decom removal engine) can reuse
# the verified UID instead of copy-pasting the magic string.
NAT_ANY_OBJECT_UID = "97aeb369-9aea-11d5-bd16-0090272ccb30"
_NAT_ORIGINAL_ANY_FIELDS = ("original-source", "original-destination", "original-service")
_NAT_TRANSLATED_FIELDS = ("translated-source", "translated-destination", "translated-service")

# Check Point has no concept of "translate to Any" -- `publish` rejects "Any" as a translated-*
# value outright ("Field Translated Source/Destination/Services references invalid objects",
# confirmed live even though `add-nat-rule` itself accepts the uid). The real equivalent of "no
# translation on this side" is what Check Point itself calls it when dereferencing a live rule's
# translated-* fields (see statereader.py's `_dereference_nat_rule` / `_uid_to_name_map`,
# confirmed live): the string "Original", not "Any". `resolve_nat_rule` below maps an "any"
# translated-* value (explicit or this module's own default) to this sentinel up front so the
# NAT-tuple identity comparison matches what a live, already-published rule actually looks like
# -- using "Any" there previously meant a freshly-created rule could never be found again by
# `find_nat_rules_by_tuple` on a later re-apply, permanently breaking idempotency.
_NAT_NO_TRANSLATION = "Original"


def _nat_payload_any_fix(payload: dict[str, Any]) -> dict[str, Any]:
    """Fix up "Any"/"Original" in NAT payload fields for `add-nat-rule`/`set-nat-rule`.

    `original-*` fields accept "Any" traffic matches, but only via the object's uid (see
    module docstring above) -- substitute it in. `translated-*` fields resolved to
    `_NAT_NO_TRANSLATION` ("Original") are dropped from the payload entirely -- omitting the
    field is how the API expresses "no translation on this side", there is no value to send.
    """
    fixed: dict[str, Any] = {}
    for k, v in payload.items():
        if k in _NAT_TRANSLATED_FIELDS and v in (_NAT_NO_TRANSLATION, "Any"):
            continue
        if k in _NAT_ORIGINAL_ANY_FIELDS and v == "Any":
            v = NAT_ANY_OBJECT_UID
        fixed[k] = v
    return fixed


async def _resolve_nat_translated_field(
    reader: StateReader,
    text: str,
    resolver_fn: Any,
    *,
    mgmt: str,
    domain: str,
    action_id: str,
    prefixes: NamingPrefixes | None,
) -> tuple[str, PlannedAction | None]:
    """Resolve one NAT translated-side field, short-circuiting CP's "no translation" sentinel
    for a bare "any" instead of routing it through the (ip/service) reference resolver.
    """
    if text.strip().lower() == "any":
        return _NAT_NO_TRANSLATION, None
    return await resolver_fn(reader, text, mgmt=mgmt, domain=domain, action_id=action_id, prefixes=prefixes)


def _add_optional_nat_fields(payload: dict[str, Any], data: dict[str, Any]) -> None:
    """Copy the optional straight-through nat-rule fields (name/install-on/enabled/comments)
    from the template's `data` onto the outgoing wire `payload`, if the template declared them.
    """
    for field in ("name", "install-on", "enabled", "comments"):
        if field in data:
            payload[field] = data[field]


async def resolve_nat_rule(
    reader: StateReader,
    op: dict[str, Any],
    *,
    mgmt: str,
    domain: str,
    action_id: str,
    counter: int,
    prefixes: NamingPrefixes | None = None,
) -> tuple[PlannedAction, list[PlannedAction], int]:
    """Create-or-reuse decision for one nat-rule.

    NAT has no layer concept -- identity is package-scoped (see `StateReader.find_nat_rules_by_tuple`)
    and the tuple itself is positional, not order-independent like access/threat-prevention/https
    rules' traffic tuple (see rule_identity.nat_tuple): original and translated sides are never
    interchangeable, and each side is a single value, not a set.
    """
    data = op.get("data", {})
    package = op["package"]

    orig_src_texts = data.get("source", ["any"]) or ["any"]
    orig_dst_texts = data.get("destination", ["any"]) or ["any"]
    orig_svc_texts = data.get("service", ["any"]) or ["any"]
    xlate_src_text = data.get("translated-source", "any")
    xlate_dst_text = data.get("translated-destination", "any")
    xlate_svc_text = data.get("translated-service", "any")

    # NAT's 6-tuple is positional (single value per side), not a set -- resolve the first/only
    # entry of each original-side list; templates should declare exactly one value per NAT side
    # (this mirrors the design spec's "original/translated 6-tuple" framing, singular per side).
    counter += 1
    orig_src, src_dep = await resolve_ip_reference(
        reader, orig_src_texts[0], mgmt=mgmt, domain=domain, action_id=f"act-{counter:04d}", prefixes=prefixes
    )
    counter += 1
    orig_dst, dst_dep = await resolve_ip_reference(
        reader, orig_dst_texts[0], mgmt=mgmt, domain=domain, action_id=f"act-{counter:04d}", prefixes=prefixes
    )
    counter += 1
    orig_svc, svc_dep = await resolve_service_reference(
        reader, orig_svc_texts[0], mgmt=mgmt, domain=domain, action_id=f"act-{counter:04d}", prefixes=prefixes
    )
    counter += 1
    xlate_src, xsrc_dep = await _resolve_nat_translated_field(
        reader,
        xlate_src_text,
        resolve_ip_reference,
        mgmt=mgmt,
        domain=domain,
        action_id=f"act-{counter:04d}",
        prefixes=prefixes,
    )
    counter += 1
    xlate_dst, xdst_dep = await _resolve_nat_translated_field(
        reader,
        xlate_dst_text,
        resolve_ip_reference,
        mgmt=mgmt,
        domain=domain,
        action_id=f"act-{counter:04d}",
        prefixes=prefixes,
    )
    counter += 1
    xlate_svc, xsvc_dep = await _resolve_nat_translated_field(
        reader,
        xlate_svc_text,
        resolve_service_reference,
        mgmt=mgmt,
        domain=domain,
        action_id=f"act-{counter:04d}",
        prefixes=prefixes,
    )

    all_deps = [d for d in (src_dep, dst_dep, svc_dep, xsrc_dep, xdst_dep, xsvc_dep) if d is not None]
    orig_src_ref = src_dep.resolved_name if src_dep else orig_src
    orig_dst_ref = dst_dep.resolved_name if dst_dep else orig_dst
    orig_svc_ref = svc_dep.resolved_name if svc_dep else orig_svc
    xlate_src_ref = xsrc_dep.resolved_name if xsrc_dep else xlate_src
    xlate_dst_ref = xdst_dep.resolved_name if xdst_dep else xlate_dst
    xlate_svc_ref = xsvc_dep.resolved_name if xsvc_dep else xlate_svc

    base = PlannedAction(
        id=action_id,
        operation="add",
        type="nat-rule",
        mgmt_name=mgmt,
        domain_name=domain,
        package=package,
        position=op.get("position"),
        desired=data,
        depends_on=[d.id for d in all_deps],
        resolved_name=data.get("name", ""),
    )

    tup = nat_tuple(orig_src_ref, orig_dst_ref, orig_svc_ref, xlate_src_ref, xlate_dst_ref, xlate_svc_ref)
    existing = await reader.find_nat_rules_by_tuple(package, tup, mgmt=mgmt, domain=domain)

    # `add-nat-rule`/`set-nat-rule` use `original-source`/`original-destination`/`original-service`
    # as SINGULAR string fields -- not "source"/"destination"/"service" (that's the access-rule
    # shape) and not list-wrapped. Confirmed both via the live lab ("Unrecognized parameter
    # [source]") and Check Point's own add-nat-rule/set-nat-rule API docs; the original sketch's
    # field names were simply wrong, not a shape guess that turned out to be close.
    payload = {
        "original-source": orig_src_ref,
        "original-destination": orig_dst_ref,
        "original-service": orig_svc_ref,
        "method": data.get("method", ""),
        "translated-source": xlate_src_ref,
        "translated-destination": xlate_dst_ref,
        "translated-service": xlate_svc_ref,
    }
    _add_optional_nat_fields(payload, data)

    if not existing:
        base.outcome = Outcome.CREATE
        base.command = "add-nat-rule"
        # Same genuine gap as resolve_rule's CREATE branch (Task 12's own "Consumes" line names
        # Task 8's resolve_position, package-scoped for NAT) -- add-nat-rule requires `position`
        # in the payload too, confirmed missing-parameter error against the live lab in Task 14.
        position_fragment = resolve_nat_position(op["position"])
        base.payload = {"package": package, **position_fragment, **_nat_payload_any_fix(payload)}
        return base, all_deps, counter

    winner = existing[
        0
    ]  # NAT rules have no declared "name" identity for tie-break in the same sense -- topmost by rule_number
    if len(existing) > 1:
        winner = min(existing, key=lambda r: r.rule_number)
    base.resolved_uid = winner.uid

    # Compare every declared field in _NAT_DATA_FIELDS the template actually set, matching
    # resolve_rule's other_fields_match pattern exactly (Task 11: only compare what the template
    # declared, skip the rest) -- source/destination/service/translated-* are excluded, their
    # identity already decided by the tuple match above. This replaces an earlier version that
    # only checked method/enabled: comments/install-on/name are legitimate nat-rule data fields
    # already included in the outgoing payload below, so silently excluding them from the
    # UNCHANGED/UPDATE decision meant a template that changed only one of them was permanently
    # misreported as UNCHANGED -- the set-nat-rule call that would actually converge that field
    # was never issued.
    other_fields_match = all(_rule_field_equal(k, data[k], winner.raw.get(k)) for k in _NAT_DATA_FIELDS if k in data)
    if other_fields_match:
        base.outcome = Outcome.UNCHANGED
        return base, all_deps, counter

    base.outcome = Outcome.UPDATE
    base.command = "set-nat-rule"
    # `package` is required by `set-nat-rule` alongside `uid` -- confirmed via Check Point's API
    # reference (set-nat-rule.j.md): both are `required: true`, because NAT rule uids are only
    # unique within their owning package's NAT rulebase (exactly analogous to access-rule's
    # `layer` requirement on `set-*-rule`, Task 11's identical bug class). Must not be dropped.
    # `name` must become `new-name` on SET, same identifier-collision bug class as resolve_rule.
    base.payload = {"uid": winner.uid, "package": package, **_with_new_name(_nat_payload_any_fix(payload))}
    return base, all_deps, counter


_NAT_ORIGINAL_FIELD_MAP = {
    "source": "original-source",
    "destination": "original-destination",
    "service": "original-service",
}


def _to_nat_wire_fields(data: dict[str, Any]) -> dict[str, Any]:
    """Translate a NAT template's source/destination/service vocabulary (`resolve_nat_rule`'s
    own `data.get("source", ...)` reads use these names, matching access-rule's template
    vocabulary for familiarity) into CP's actual wire field names -- `add-nat-rule`/
    `set-nat-rule` don't accept plain source/destination/service at all ("Unrecognized parameter
    [source]", confirmed against the live lab and Check Point's own API docs in Task 14).
    `translated-source`/`translated-destination`/`translated-service` are already spelled the
    same way in both the template and the wire format, so left untouched.
    """
    return {_NAT_ORIGINAL_FIELD_MAP.get(k, k): v for k, v in data.items()}


def _resolved_name_from_key(key: dict[str, Any]) -> str:
    if key.get("name"):
        return key["name"]
    if key.get("uid"):
        return key["uid"]
    if "rule-number" in key:
        return str(key["rule-number"])
    return ""


async def _resolve_update_reference_fields(
    reader: StateReader,
    data: dict[str, Any],
    mgmt: str,
    domain: str,
    counter: int,
    prefixes: NamingPrefixes | None = None,
) -> tuple[dict[str, Any], list[PlannedAction], int]:
    """Resolve bare IP/CIDR/range and service-spec strings in an update's list-valued
    reference fields (source/destination/service), matching `resolve_rule`'s `add` pipeline
    (Tasks 9/10) -- a key-based update can change these fields too, so they need the same
    find-or-create resolution, not a verbatim pass-through of whatever text the template used.
    """
    resolved = dict(data)
    deps: list[PlannedAction] = []
    if "source" in data:
        resolved["source"], src_deps, counter = await _resolve_reference_list(
            reader, data["source"], resolve_ip_reference, mgmt, domain, counter, prefixes
        )
        deps += src_deps
    if "destination" in data:
        resolved["destination"], dst_deps, counter = await _resolve_reference_list(
            reader, data["destination"], resolve_ip_reference, mgmt, domain, counter, prefixes
        )
        deps += dst_deps
    if "service" in data:
        resolved["service"], svc_deps, counter = await _resolve_reference_list(
            reader, data["service"], resolve_service_reference, mgmt, domain, counter, prefixes
        )
        deps += svc_deps
    return resolved, deps, counter


async def _resolve_update_nat_reference_fields(
    reader: StateReader,
    data: dict[str, Any],
    mgmt: str,
    domain: str,
    counter: int,
    prefixes: NamingPrefixes | None = None,
) -> tuple[dict[str, Any], list[PlannedAction], int]:
    """NAT variant of `_resolve_update_reference_fields`: source/destination/service are still
    list-valued (resolved the same way), but translated-source/translated-destination/
    translated-service are singular strings (resolve_nat_rule's positional 6-tuple shape)."""
    resolved, deps, counter = await _resolve_update_reference_fields(reader, data, mgmt, domain, counter, prefixes)
    for field, resolver_fn in (
        ("translated-source", resolve_ip_reference),
        ("translated-destination", resolve_ip_reference),
        ("translated-service", resolve_service_reference),
    ):
        if field not in data:
            continue
        counter += 1
        ref, dep = await resolver_fn(
            reader, data[field], mgmt=mgmt, domain=domain, action_id=f"act-{counter:04d}", prefixes=prefixes
        )
        if dep is not None:
            resolved[field] = dep.resolved_name
            deps.append(dep)
        else:
            resolved[field] = ref
    return resolved, deps, counter


async def resolve_rule_by_key(
    reader: StateReader,
    rule_type: str,
    operation: str,
    op: dict[str, Any],
    *,
    mgmt: str,
    domain: str,
    action_id: str,
    counter: int,
    prefixes: NamingPrefixes | None = None,
) -> tuple[PlannedAction, list[PlannedAction], int]:
    """Key-based update/delete/show for one access/threat-prevention/https rule.

    Unlike `resolve_rule` (used for `add`), a rule addressed by `key: {name|uid|rule-number}`
    is already unambiguously identified by the user -- no traffic-tuple discovery needed, and
    (per the CP CRUD convention already established for objects) no create-on-miss either:
    the user named a specific existing rule, not a desired traffic pattern to find-or-create.
    """
    key = op.get("key", {})
    layer_ref = op["layer"]
    layer_type = _RULE_LAYER_TYPE[rule_type]
    rule_cmd = _RULE_CMD[rule_type]
    data = op.get("data", {}) if operation == "update" else {}

    all_deps: list[PlannedAction] = []
    if operation == "update":
        data, all_deps, counter = await _resolve_update_reference_fields(reader, data, mgmt, domain, counter, prefixes)

    base = PlannedAction(
        id=action_id,
        operation=operation,
        type=rule_type,
        key=key,
        desired=data,
        mgmt_name=mgmt,
        domain_name=domain,
        layer=layer_ref,
        resolved_name=_resolved_name_from_key(key),
        depends_on=[d.id for d in all_deps],
    )

    layer = await reader.get_layer(layer_ref, layer_type, mgmt=mgmt, domain=domain)
    if layer is None:
        from ..core.exceptions import ConfigurationError

        raise ConfigurationError(f"Layer {layer_ref!r} not found ({layer_type})")

    rule = await reader.get_rule_by_key(layer.uid, layer_type, key, mgmt=mgmt, domain=domain)
    if rule is None:
        if operation == "delete":
            base.outcome = Outcome.DELETE  # already absent -- idempotent success, matches resolve_delete's convention
            base.message = "already absent"
        else:
            # update/show: cannot traffic-tuple-discover-or-create when the user explicitly
            # addressed a specific rule by key -- matches resolve_update's convention for objects.
            base.outcome = Outcome.ERROR
            base.message = "rule not found"
        return base, all_deps, counter

    base.resolved_uid = rule.uid
    base.resolved_name = rule.name

    if operation == "delete":
        base.outcome = Outcome.DELETE
        base.command = f"delete-{rule_cmd}"
        # `layer` is required by CP's delete-*-rule commands alongside `uid` (rule uids are
        # only unique within their owning layer) -- same requirement as set-*-rule (Task 11).
        base.payload = {"uid": rule.uid, "layer": layer_ref}
        base.prior_state = {**rule.raw, "_rule_number": rule.rule_number}
        return base, all_deps, counter

    if operation == "show":
        base.outcome = Outcome.UNCHANGED
        base.matches = [ObjectMatch(name=rule.name, uid=rule.uid)]
        return base, all_deps, counter

    # update
    unchanged = all(_rule_field_equal(k, v, rule.raw.get(k)) for k, v in data.items())
    if unchanged:
        base.outcome = Outcome.UNCHANGED
        return base, all_deps, counter
    base.outcome = Outcome.UPDATE
    base.command = f"set-{rule_cmd}"
    # `layer` is required by `set-*-rule` alongside `uid` -- same bug class Task 11 fixed for
    # resolve_rule's UPDATE path; must not be dropped here either. `name` -> `new-name` for the
    # same identifier-collision reason (Task 14 live-verified fix, resolve_rule's UPDATE path).
    base.payload = {"uid": rule.uid, "layer": layer_ref, **_with_new_name(data)}
    return base, all_deps, counter


async def resolve_nat_rule_by_key(
    reader: StateReader,
    operation: str,
    op: dict[str, Any],
    *,
    mgmt: str,
    domain: str,
    action_id: str,
    counter: int,
    prefixes: NamingPrefixes | None = None,
) -> tuple[PlannedAction, list[PlannedAction], int]:
    """Key-based update/delete/show for one nat-rule (package-scoped, no layer concept).

    Mirrors `resolve_rule_by_key`'s reasoning exactly, substituting NAT's `package` scoping
    for access/threat/https's `layer` scoping (the same distinction `resolve_nat_rule` draws
    from `resolve_rule` for `add`).
    """
    key = op.get("key", {})
    package = op["package"]
    data = op.get("data", {}) if operation == "update" else {}

    all_deps: list[PlannedAction] = []
    if operation == "update":
        data, all_deps, counter = await _resolve_update_nat_reference_fields(
            reader, data, mgmt, domain, counter, prefixes
        )

    base = PlannedAction(
        id=action_id,
        operation=operation,
        type="nat-rule",
        key=key,
        desired=data,
        mgmt_name=mgmt,
        domain_name=domain,
        package=package,
        resolved_name=_resolved_name_from_key(key),
        depends_on=[d.id for d in all_deps],
    )

    rule = await reader.get_nat_rule_by_key(package, key, mgmt=mgmt, domain=domain)
    if rule is None:
        if operation == "delete":
            base.outcome = Outcome.DELETE
            base.message = "already absent"
        else:
            base.outcome = Outcome.ERROR
            base.message = "rule not found"
        return base, all_deps, counter

    base.resolved_uid = rule.uid
    base.resolved_name = rule.name

    if operation == "delete":
        base.outcome = Outcome.DELETE
        base.command = "delete-nat-rule"
        # `package` is required by `delete-nat-rule` alongside `uid` -- same requirement as
        # `set-nat-rule` (Task 12's bug class): NAT rule uids are only unique within their
        # owning package's NAT rulebase.
        base.payload = {"uid": rule.uid, "package": package}
        base.prior_state = {**rule.raw, "_rule_number": rule.rule_number}
        return base, all_deps, counter

    if operation == "show":
        base.outcome = Outcome.UNCHANGED
        base.matches = [ObjectMatch(name=rule.name, uid=rule.uid)]
        return base, all_deps, counter

    # update -- `rule.raw` (from get_nat_rule_by_key) and the outgoing payload both speak CP's
    # wire vocabulary (original-source/original-destination/original-service), not the
    # template's source/destination/service -- translate before comparing or sending, same
    # live-verified fix as resolve_nat_rule's CREATE payload.
    wire_data = _to_nat_wire_fields(data)
    unchanged = all(_rule_field_equal(k, v, rule.raw.get(k)) for k, v in wire_data.items())
    if unchanged:
        base.outcome = Outcome.UNCHANGED
        return base, all_deps, counter
    base.outcome = Outcome.UPDATE
    base.command = "set-nat-rule"
    # `package` required alongside `uid` -- Task 12's bug class, must not be dropped here either.
    # `name` -> `new-name` for the same identifier-collision reason (Task 14 live-verified fix).
    base.payload = {"uid": rule.uid, "package": package, **_with_new_name(_nat_payload_any_fix(wire_data))}
    return base, all_deps, counter
