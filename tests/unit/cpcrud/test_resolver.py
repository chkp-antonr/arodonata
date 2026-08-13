# tests/unit/cpcrud/test_resolver.py
import pytest

from arodonata.cpcrud.models import IpConflictPolicy, LayerInfo, NameConflictPolicy, ObjectState, Outcome, RuleMatch
from arodonata.cpcrud.naming import NamingPrefixes
from arodonata.cpcrud.resolver import (
    resolve_add,
    resolve_delete,
    resolve_ip_reference,
    resolve_nat_rule,
    resolve_nat_rule_by_key,
    resolve_rule,
    resolve_rule_by_key,
    resolve_service_reference,
    resolve_update,
)


class FakeReader:
    def __init__(self, by_name=None, by_ip=None, usage=None, where_used=None, group_names: set[str] = frozenset()):
        self._by_name = by_name or {}
        self._by_ip = by_ip or {}
        self._usage = usage or where_used or {}
        self.group_names = group_names

    async def get_by_name(self, type, name, *, mgmt, domain):
        if type == "network-group" and name in self.group_names:
            return ObjectState(uid=f"uid-{name}", name=name, type="network-group", raw={})
        if isinstance(self._by_name, ObjectState):
            return self._by_name
        return self._by_name.get((type, name))

    async def find_by_ip(self, *, type, ip_value, mgmt, domain):
        if isinstance(self._by_ip, list):
            return self._by_ip
        return self._by_ip.get((type, _key(ip_value)), [])

    async def where_used(self, uid, *, mgmt, domain):
        return self._usage.get(uid, 0)

    async def get_last_publish_session(self, *, mgmt, domain):
        return ""

    # --- rule-tier defaults (Task 13): sensible no-op stubs so any test driving a rule op
    # through FakeReader (e.g. via Planner.decide) doesn't error for lack of these methods.
    # Subclasses (RuleFakeReader/NatFakeReader below) override the ones they need to control.
    async def get_layer(self, layer_ref, layer_type, *, mgmt, domain):
        return LayerInfo(uid=f"layer-{layer_ref}", name=layer_ref, type=layer_type)

    async def find_rules_by_traffic(self, scope_uid, layer_type, source_uids, dest_uids, service_uids, *, mgmt, domain):
        return []

    async def get_last_rule(self, scope_uid, layer_type, *, mgmt, domain):
        return None

    async def find_nat_rules_by_tuple(self, package, tup, *, mgmt, domain):
        return []

    async def get_last_nat_rule(self, package, *, mgmt, domain):
        return None

    async def get_rule_by_key(self, scope_uid, layer_type, key, *, mgmt, domain):
        return None

    async def get_nat_rule_by_key(self, package, key, *, mgmt, domain):
        return None


def _key(ip_value):
    return tuple(sorted(ip_value.items()))


def _state(t, name, raw):
    return ObjectState(uid=raw.get("uid", "u"), name=name, type=t, raw=raw)


@pytest.mark.asyncio
async def test_create_when_absent():
    r = FakeReader()
    action = await resolve_add(
        r,
        "host",
        {"name": "h1", "ip-address": "10.0.0.1"},
        on_name=NameConflictPolicy.UPDATE,
        on_ip=IpConflictPolicy.REUSE,
        mgmt="m",
        domain="d",
        action_id="act-0001",
    )
    assert action.outcome == Outcome.CREATE
    assert action.command == "add-host"
    assert action.resolved_name == "h1"


@pytest.mark.asyncio
async def test_skip_when_identical():
    r = FakeReader(
        by_name={
            ("host", "h1"): _state(
                "host", "h1", {"uid": "u1", "name": "h1", "ipv4-address": "10.0.0.1", "comments": "c"}
            )
        }
    )
    action = await resolve_add(
        r,
        "host",
        {"name": "h1", "ip-address": "10.0.0.1", "comments": "c"},
        on_name=NameConflictPolicy.UPDATE,
        on_ip=IpConflictPolicy.REUSE,
        mgmt="m",
        domain="d",
        action_id="act-0001",
    )
    assert action.outcome == Outcome.UNCHANGED
    assert action.matches[0].name == "h1"


@pytest.mark.asyncio
async def test_update_on_name_conflict_with_diff():
    r = FakeReader(
        by_name={("host", "h1"): _state("host", "h1", {"uid": "u1", "name": "h1", "ipv4-address": "10.0.0.1"})}
    )
    action = await resolve_add(
        r,
        "host",
        {"name": "h1", "ip-address": "10.0.0.2"},
        on_name=NameConflictPolicy.UPDATE,
        on_ip=IpConflictPolicy.REUSE,
        mgmt="m",
        domain="d",
        action_id="act-0001",
    )
    assert action.outcome == Outcome.UPDATE
    assert action.command == "set-host"
    assert action.resolved_uid == "u1"


@pytest.mark.asyncio
async def test_error_on_name_conflict_when_policy_error():
    r = FakeReader(
        by_name={("host", "h1"): _state("host", "h1", {"uid": "u1", "name": "h1", "ipv4-address": "10.0.0.1"})}
    )
    action = await resolve_add(
        r,
        "host",
        {"name": "h1", "ip-address": "10.0.0.2"},
        on_name=NameConflictPolicy.ERROR,
        on_ip=IpConflictPolicy.REUSE,
        mgmt="m",
        domain="d",
        action_id="act-0001",
    )
    assert action.outcome == Outcome.CONFLICT
    assert action.command is None  # do nothing


@pytest.mark.asyncio
async def test_ip_conflict_reuse_most_used():
    r = FakeReader(
        by_ip={
            ("host", _key({"ip-address": "10.0.0.5"})): [
                _state("host", "less", {"uid": "u-less", "name": "less", "ipv4-address": "10.0.0.5"}),
                _state("host", "more", {"uid": "u-more", "name": "more", "ipv4-address": "10.0.0.5"}),
            ]
        },
        usage={"u-less": 2, "u-more": 9},
    )
    action = await resolve_add(
        r,
        "host",
        {"name": "h1", "ip-address": "10.0.0.5"},
        on_name=NameConflictPolicy.UPDATE,
        on_ip=IpConflictPolicy.REUSE,
        mgmt="m",
        domain="d",
        action_id="act-0001",
    )
    assert action.outcome == Outcome.REUSE
    assert action.matches[0].name == "more"  # most-used first
    assert action.matches[0].where_used_total == 9
    assert action.command is None


@pytest.mark.asyncio
async def test_ip_conflict_create_duplicate():
    r = FakeReader(
        by_ip={
            ("host", _key({"ip-address": "10.0.0.5"})): [
                _state("host", "x", {"uid": "ux", "name": "x", "ipv4-address": "10.0.0.5"})
            ]
        }
    )
    action = await resolve_add(
        r,
        "host",
        {"name": "h1", "ip-address": "10.0.0.5"},
        on_name=NameConflictPolicy.UPDATE,
        on_ip=IpConflictPolicy.CREATE_NEW,
        mgmt="m",
        domain="d",
        action_id="act-0001",
    )
    assert action.outcome == Outcome.CREATE
    assert action.command == "add-host"
    assert action.conflict is not None  # surfaces the existing same-IP object


@pytest.mark.asyncio
async def test_delete_idempotent_when_missing():
    r = FakeReader()
    action = await resolve_delete(r, "host", {"name": "gone"}, mgmt="m", domain="d", action_id="act-0001")
    assert action.outcome == Outcome.DELETE  # already absent = success
    assert action.command is None


@pytest.mark.asyncio
async def test_resolve_delete_captures_prior_state():
    raw = {"uid": "u-1", "name": "h1", "ipv4-address": "10.0.0.1", "color": "red"}
    r = FakeReader(by_name={("host", "h1"): _state("host", "h1", raw)})
    action = await resolve_delete(r, "host", {"name": "h1"}, mgmt="m", domain="d", action_id="act-0001")
    assert action.prior_state == raw


@pytest.mark.asyncio
async def test_resolve_delete_absent_has_no_prior_state():
    r = FakeReader()
    action = await resolve_delete(r, "host", {"name": "gone"}, mgmt="m", domain="d", action_id="act-0001")
    assert action.prior_state is None and action.message == "already absent"


@pytest.mark.asyncio
async def test_reuse_prefers_convention_name_over_usage():
    conventional = ObjectState(uid="u-conv", name="Host_10.0.0.5", type="host", raw={})
    popular = ObjectState(uid="u-pop", name="db-01", type="host", raw={})
    reader = FakeReader(by_name=None, by_ip=[popular, conventional], where_used={"u-pop": 50, "u-conv": 1})
    action = await resolve_add(
        reader,
        "host",
        {"name": "app-01", "ip-address": "10.0.0.5"},
        on_name=NameConflictPolicy.UPDATE,
        on_ip=IpConflictPolicy.REUSE,
        mgmt="m",
        domain="d",
        action_id="act-0001",
    )
    assert action.outcome == Outcome.REUSE
    assert action.resolved_name == "Host_10.0.0.5"  # convention wins despite lower usage
    assert action.matches[0].matches_convention is True
    assert action.matches[1].where_used_total == 50


async def test_update_on_locked_object_carries_advisory_warning():
    locked = ObjectState(
        uid="u1",
        name="h1",
        type="host",
        raw={"ipv4-address": "10.0.0.1", "meta-info": {"lock": "locked by other session"}},
    )
    reader = FakeReader(by_name=locked)
    action = await resolve_update(
        reader, "host", {"name": "h1"}, {"ip-address": "10.9.9.9"}, mgmt="m", domain="d", action_id="act-0001"
    )
    assert any("locked" in w for w in action.warnings)


@pytest.mark.asyncio
async def test_resolve_add_tcp_service_when_absent():
    reader = FakeReader()
    action = await resolve_add(
        reader,
        "tcp-service",
        {"name": "TCP_8080", "port": "8080"},
        on_name=NameConflictPolicy.UPDATE,
        on_ip=IpConflictPolicy.REUSE,
        mgmt="m",
        domain="d",
        action_id="act-0001",
    )
    assert action.outcome == Outcome.CREATE
    assert action.command == "add-service-tcp"
    assert action.payload == {"name": "TCP_8080", "port": "8080"}


@pytest.mark.asyncio
async def test_resolve_update_udp_service_by_name():
    existing = ObjectState(uid="u1", name="UDP_53", type="udp-service", raw={"port": "53"})
    reader = FakeReader(by_name=existing)
    action = await resolve_update(
        reader,
        "udp-service",
        {"name": "UDP_53"},
        {"comments": "dns"},
        mgmt="m",
        domain="d",
        action_id="act-0001",
    )
    assert action.outcome == Outcome.UPDATE
    assert action.command == "set-service-udp"
    assert action.payload == {"uid": "u1", "comments": "dns"}


@pytest.mark.asyncio
async def test_resolve_delete_icmp_service():
    existing = ObjectState(uid="u1", name="ICMP_8", type="icmp-service", raw={"icmp-type": 8})
    reader = FakeReader(by_name=existing)
    action = await resolve_delete(
        reader, "icmp-service", {"name": "ICMP_8"}, mgmt="m", domain="d", action_id="act-0001"
    )
    assert action.outcome == Outcome.DELETE
    assert action.command == "delete-service-icmp"
    assert action.payload == {"uid": "u1"}


@pytest.mark.asyncio
async def test_resolve_add_service_group_when_absent():
    reader = FakeReader()
    action = await resolve_add(
        reader,
        "service-group",
        {"name": "Web-Services", "members": ["TCP_8080"]},
        on_name=NameConflictPolicy.UPDATE,
        on_ip=IpConflictPolicy.REUSE,
        mgmt="m",
        domain="d",
        action_id="act-0001",
    )
    assert action.outcome == Outcome.CREATE
    assert action.command == "add-service-group"
    assert action.payload == {"name": "Web-Services", "members": ["TCP_8080"]}


@pytest.mark.asyncio
async def test_resolve_add_service_no_ip_conflict_branch():
    """Services have no ip-address field; the IP-conflict branch must never trigger."""
    reader = FakeReader()
    action = await resolve_add(
        reader,
        "tcp-service",
        {"name": "TCP_22", "port": "22"},
        on_name=NameConflictPolicy.UPDATE,
        on_ip=IpConflictPolicy.ERROR,  # would CONFLICT if IP branch ran
        mgmt="m",
        domain="d",
        action_id="act-0001",
    )
    assert action.outcome == Outcome.CREATE
    assert action.conflict is None


@pytest.mark.asyncio
async def test_resolve_ip_reference_any_is_literal():
    reader = FakeReader()
    resolved, create_action = await resolve_ip_reference(reader, "any", mgmt="m", domain="d", action_id="act-0001")
    assert resolved == "Any"
    assert create_action is None


@pytest.mark.asyncio
async def test_resolve_ip_reference_plain_name_passes_through():
    reader = FakeReader()
    resolved, create_action = await resolve_ip_reference(
        reader, "web-srv-01", mgmt="m", domain="d", action_id="act-0001"
    )
    assert resolved == "web-srv-01"
    assert create_action is None


@pytest.mark.asyncio
async def test_resolve_ip_reference_single_ip_reuses_existing_host():
    """Returns the existing host's NAME, not its uid -- Task 14's live run confirmed
    `find_rules_by_traffic` compares against the live rulebase's dereferenced (uid->name)
    fields, so this side of the comparison must speak names too (matching "Any"/auto-created
    dependencies, which were already name-based).

    Task 5: an already-existing match must surface as a REUSE `PlannedAction`, not `None` --
    a dependency that already exists must never silently vanish from the plan/report."""
    existing = ObjectState(uid="u1", name="web-srv-01", type="host", raw={})
    reader = FakeReader(by_ip=[existing])
    resolved, dep = await resolve_ip_reference(reader, "10.0.0.5", mgmt="m", domain="d", action_id="act-0001")
    assert resolved == "web-srv-01"
    assert dep is not None
    assert dep.outcome == Outcome.REUSE
    assert dep.command is None and dep.payload is None
    assert dep.auto_created is True
    assert dep.resolved_uid == "u1"
    assert dep.resolved_name == "web-srv-01"


@pytest.mark.asyncio
async def test_existing_ip_reference_reports_reuse():
    """Task 5 plan spec's own example: an existing host matched by bare-IP reference must
    return `(name, PlannedAction)` with outcome=REUSE, never `(name, None)`."""
    existing = ObjectState(uid="u-1", name="Host_10.1.2.3", type="host", raw={})
    reader = FakeReader(by_ip=[existing])
    ref, dep = await resolve_ip_reference(reader, "10.1.2.3", mgmt="m", domain="d", action_id="act-0001")
    assert ref == "Host_10.1.2.3"
    assert dep is not None
    assert dep.outcome == Outcome.REUSE
    assert dep.command is None and dep.payload is None
    assert dep.auto_created is True
    assert dep.resolved_uid == "u-1"


@pytest.mark.asyncio
async def test_resolve_ip_reference_single_ip_not_found_synthesizes_create():
    reader = FakeReader()  # find_by_ip returns []
    resolved, create_action = await resolve_ip_reference(reader, "10.0.0.9", mgmt="m", domain="d", action_id="act-0001")
    assert create_action is not None
    assert create_action.type == "host"
    assert create_action.resolved_name == "Host_10.0.0.9"
    assert create_action.command == "add-host"
    assert resolved == create_action.id


@pytest.mark.asyncio
async def test_resolve_ip_reference_cidr_not_found_synthesizes_network_create():
    reader = FakeReader()
    resolved, create_action = await resolve_ip_reference(
        reader, "10.0.0.0/24", mgmt="m", domain="d", action_id="act-0001"
    )
    assert create_action is not None
    assert create_action.type == "network"
    assert create_action.resolved_name == "Net_10.0.0.0_24"
    assert create_action.payload == {"name": "Net_10.0.0.0_24", "subnet": "10.0.0.0", "mask-length": 24}


@pytest.mark.asyncio
async def test_resolve_ip_reference_range_not_found_synthesizes_range_create():
    reader = FakeReader()
    resolved, create_action = await resolve_ip_reference(
        reader, "10.0.0.1-10.0.0.9", mgmt="m", domain="d", action_id="act-0001"
    )
    assert create_action is not None
    assert create_action.type == "address-range"
    assert create_action.resolved_name == "IPR_10.0.0.1-10.0.0.9"


@pytest.mark.asyncio
async def test_resolve_ip_reference_cidr_with_host_bits_set_raises_with_suggestion():
    reader = FakeReader()
    with pytest.raises(ValueError, match="10.0.0.0/24"):
        await resolve_ip_reference(reader, "10.0.0.5/24", mgmt="m", domain="d", action_id="act-0001")


@pytest.mark.asyncio
async def test_resolve_ip_reference_global_domain_prefixes_name():
    reader = FakeReader()
    resolved, create_action = await resolve_ip_reference(
        reader, "10.0.0.9", mgmt="m", domain="Global", action_id="act-0001"
    )
    assert create_action.resolved_name == "global_Host_10.0.0.9"


@pytest.mark.asyncio
async def test_resolve_service_reference_any_is_literal():
    reader = FakeReader()
    resolved, create_action = await resolve_service_reference(reader, "any", mgmt="m", domain="d", action_id="act-0001")
    assert resolved == "Any"
    assert create_action is None


@pytest.mark.asyncio
async def test_resolve_service_reference_existing_match_returns_name():
    """Returns the existing service's NAME, not its uid -- see resolve_ip_reference's analogous
    fix for why (Task 14's live-verified dereferencing of the live rulebase's comparison side).

    Task 5: an already-existing match must surface as a REUSE `PlannedAction`, not `None`."""

    class ServiceReader(FakeReader):
        async def get_service(self, spec, original_text, *, mgmt, domain):
            return ObjectState(uid="u1", name="https", type="tcp-service", raw={})

    reader = ServiceReader()
    resolved, dep = await resolve_service_reference(reader, "https", mgmt="m", domain="d", action_id="act-0001")
    assert resolved == "https"
    assert dep is not None
    assert dep.outcome == Outcome.REUSE
    assert dep.command is None and dep.payload is None
    assert dep.auto_created is True
    assert dep.resolved_uid == "u1"


@pytest.mark.asyncio
async def test_resolve_service_reference_miss_synthesizes_create():
    class ServiceReader(FakeReader):
        async def get_service(self, spec, original_text, *, mgmt, domain):
            return None

    reader = ServiceReader()
    resolved, create_action = await resolve_service_reference(
        reader, "TCP/2200", mgmt="m", domain="d", action_id="act-0001"
    )
    assert create_action is not None
    assert create_action.type == "tcp-service"
    assert create_action.resolved_name == "TCP_2200"
    assert create_action.command == "add-service-tcp"
    assert resolved == create_action.id


@pytest.mark.asyncio
async def test_resolve_service_reference_unresolved_named_raises():
    class ServiceReader(FakeReader):
        async def get_service(self, spec, original_text, *, mgmt, domain):
            return None

    reader = ServiceReader()
    with pytest.raises(ValueError, match="SmartConsole"):
        await resolve_service_reference(reader, "totally-unknown-name", mgmt="m", domain="d", action_id="act-0001")


@pytest.mark.asyncio
async def test_resolve_service_reference_invalid_range_raises():
    reader = FakeReader()
    with pytest.raises(ValueError, match="range"):
        await resolve_service_reference(reader, "2026-2000", mgmt="m", domain="d", action_id="act-0001")


# ---------------------------------------------------------------------------
# resolve_rule -- traffic-tuple identity for access/threat-prevention/https rules
# ---------------------------------------------------------------------------


class RuleFakeReader(FakeReader):
    def __init__(self, *args, layer=None, existing_rules=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._layer = layer
        self._existing_rules = existing_rules or []

    async def get_layer(self, layer_ref, layer_type, *, mgmt, domain):
        return self._layer

    async def find_rules_by_traffic(self, scope_uid, layer_type, source_uids, dest_uids, service_uids, *, mgmt, domain):
        return self._existing_rules

    async def get_last_rule(self, scope_uid, layer_type, *, mgmt, domain):
        return None


@pytest.mark.asyncio
async def test_resolve_rule_create_when_no_traffic_match():
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    reader = RuleFakeReader(layer=layer, by_ip=[])
    op = {
        "type": "access-rule",
        "layer": "Network",
        "position": "bottom",
        "data": {
            "name": "Allow-Web",
            "source": ["any"],
            "destination": ["any"],
            "service": ["any"],
            "action": "accept",
        },
    }
    action, deps, counter = await resolve_rule(
        reader, "access-rule", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.CREATE
    assert action.command == "add-access-rule"
    assert action.layer == "Network"
    assert action.payload["source"] == ["Any"]
    assert action.payload["destination"] == ["Any"]
    assert action.payload["service"] == ["Any"]
    assert action.payload["name"] == "Allow-Web"
    assert action.payload["action"] == "accept"
    # resolved_name must be set even on CREATE (no `winner` exists yet) -- otherwise
    # PlannedAction.to_result() reports an empty name for every created rule.
    assert action.resolved_name == "Allow-Web"


@pytest.mark.asyncio
async def test_resolve_rule_unchanged_when_traffic_identical_and_fields_match():
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    existing = RuleMatch(
        uid="r1",
        name="Allow-Web",
        rule_number=1,
        raw={
            "uid": "r1",
            "name": "Allow-Web",
            "source": [],
            "destination": [],
            "service": [],
            "action": "accept",
            "enabled": True,
            "comments": "",
            "track": {},
            "install-on": [],
            "time": [],
            "vpn": "",
        },
    )
    reader = RuleFakeReader(layer=layer, existing_rules=[existing])
    op = {
        "type": "access-rule",
        "layer": "Network",
        "position": "bottom",
        "data": {"name": "Allow-Web", "source": [], "destination": [], "service": [], "action": "accept"},
    }
    action, deps, counter = await resolve_rule(
        reader, "access-rule", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UNCHANGED
    assert action.resolved_uid == "r1"


@pytest.mark.asyncio
async def test_resolve_rule_update_when_traffic_identical_but_other_fields_differ():
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    existing = RuleMatch(
        uid="r1",
        name="Old-Name",
        rule_number=1,
        raw={
            "uid": "r1",
            "name": "Old-Name",
            "source": [],
            "destination": [],
            "service": [],
            "action": "accept",
            "enabled": True,
            "comments": "",
            "track": {},
            "install-on": [],
            "time": [],
            "vpn": "",
        },
    )
    reader = RuleFakeReader(layer=layer, existing_rules=[existing])
    op = {
        "type": "access-rule",
        "layer": "Network",
        "position": "bottom",
        "data": {"name": "New-Name", "source": [], "destination": [], "service": [], "action": "accept"},
    }
    action, deps, counter = await resolve_rule(
        reader, "access-rule", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UPDATE
    assert action.resolved_uid == "r1"
    assert action.command == "set-access-rule"
    # `name` is CP's alternate rule IDENTIFIER (like uid/rule-number), never a settable field on
    # set-access-rule -- sending both uid and name together is rejected outright ("need only one
    # of uid/rule-number/name"), confirmed against the live lab in Task 14. Renaming requires
    # `new-name` instead, and plain `name` must NOT appear in the UPDATE payload at all.
    assert action.payload["new-name"] == "New-Name"
    assert "name" not in action.payload
    # layer is required by CP's set-*-rule commands alongside uid (rule uids are only
    # unique within their owning layer's rulebase) -- must not be dropped on UPDATE.
    assert action.payload["layer"] == "Network"


@pytest.mark.asyncio
async def test_resolve_rule_rename_never_duplicates():
    """Renaming in the template is an UPDATE of the name field, never a new rule."""
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    existing = RuleMatch(
        uid="r1",
        name="Allow-Web-v1",
        rule_number=1,
        raw={
            "uid": "r1",
            "name": "Allow-Web-v1",
            "source": [],
            "destination": [],
            "service": [],
            "action": "accept",
            "enabled": True,
            "comments": "",
            "track": {},
            "install-on": [],
            "time": [],
            "vpn": "",
        },
    )
    reader = RuleFakeReader(layer=layer, existing_rules=[existing])
    op = {
        "type": "access-rule",
        "layer": "Network",
        "position": "bottom",
        "data": {"name": "Allow-Web-v2", "source": [], "destination": [], "service": [], "action": "accept"},
    }
    action, deps, counter = await resolve_rule(
        reader, "access-rule", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UPDATE  # not CREATE -- traffic tuple matched
    assert action.resolved_uid == "r1"


@pytest.mark.asyncio
async def test_resolve_rule_synthesizes_object_dependency_for_bare_ip():
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    reader = RuleFakeReader(layer=layer, by_ip=[])
    op = {
        "type": "access-rule",
        "layer": "Network",
        "position": "bottom",
        "data": {
            "name": "Allow-Host",
            "source": ["10.0.0.5"],
            "destination": ["any"],
            "service": ["any"],
            "action": "accept",
        },
    }
    action, deps, counter = await resolve_rule(
        reader, "access-rule", op, mgmt="m", domain="d", action_id="act-0002", counter=1
    )
    assert len(deps) == 1
    assert deps[0].type == "host" and deps[0].resolved_name == "Host_10.0.0.5"
    assert deps[0].id in action.depends_on
    # NOTE (corrected per brief lines 136-142): the rule payload references the synthesized
    # dependency's resolved_name, not its plan-internal id -- rules' source/destination/service
    # fields accept object NAMES directly (same pattern as Plan A/B's group auto-create), so no
    # new executor-side plan-internal-id substitution is needed.
    assert action.payload["source"] == ["Host_10.0.0.5"]


@pytest.mark.asyncio
async def test_resolve_rule_tie_break_prefers_declared_name():
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    a = RuleMatch(
        uid="ra",
        name="rule-a",
        rule_number=5,
        raw={"uid": "ra", "name": "rule-a", "source": [], "destination": [], "service": [], "action": "accept"},
    )
    b = RuleMatch(
        uid="rb",
        name="rule-b",
        rule_number=1,
        raw={"uid": "rb", "name": "rule-b", "source": [], "destination": [], "service": [], "action": "accept"},
    )
    reader = RuleFakeReader(layer=layer, existing_rules=[a, b])
    op = {
        "type": "access-rule",
        "layer": "Network",
        "position": "bottom",
        "data": {"name": "rule-a", "source": [], "destination": [], "service": [], "action": "accept"},
    }
    action, deps, counter = await resolve_rule(
        reader, "access-rule", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.resolved_uid == "ra"


# --- rough edge #1: field comparison must reuse differ.py's alias/coercion logic, not naive `==` ---
# These cases specifically probe shape mismatches between the live API's raw rule representation
# and the template's declared data -- the same class of bug that broke idempotency twice before
# (Plan A's differ.py groups bug, the pre-Plan-B icmp-type coercion bug).


@pytest.mark.asyncio
async def test_resolve_rule_unchanged_when_enabled_bool_matches_live_shape():
    """A plain bool field, identical on both sides, must never be treated as a change."""
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    existing = RuleMatch(
        uid="r1",
        name="Allow-Web",
        rule_number=1,
        raw={
            "uid": "r1",
            "name": "Allow-Web",
            "source": [],
            "destination": [],
            "service": [],
            "action": "accept",
            "enabled": True,
        },
    )
    reader = RuleFakeReader(layer=layer, existing_rules=[existing])
    op = {
        "type": "access-rule",
        "layer": "Network",
        "position": "bottom",
        "data": {
            "name": "Allow-Web",
            "source": [],
            "destination": [],
            "service": [],
            "action": "accept",
            "enabled": True,
        },
    }
    action, deps, counter = await resolve_rule(
        reader, "access-rule", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UNCHANGED


@pytest.mark.asyncio
async def test_resolve_rule_unchanged_when_track_live_shape_has_extra_default_keys():
    """The live API commonly expands `track` with extra default keys (name/settings) the
    template never declared. A naive dict `==` would spuriously report a change here -- the
    fix must compare only the keys the template actually declared (declared-subset comparison)."""
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    existing = RuleMatch(
        uid="r1",
        name="Allow-Web",
        rule_number=1,
        raw={
            "uid": "r1",
            "name": "Allow-Web",
            "source": [],
            "destination": [],
            "service": [],
            "action": "accept",
            "track": {"type": "Log", "name": "Log", "settings": {"enabled": True, "packet-capture": False}},
        },
    )
    reader = RuleFakeReader(layer=layer, existing_rules=[existing])
    op = {
        "type": "access-rule",
        "layer": "Network",
        "position": "bottom",
        "data": {
            "name": "Allow-Web",
            "source": [],
            "destination": [],
            "service": [],
            "action": "accept",
            "track": {"type": "Log"},
        },
    }
    action, deps, counter = await resolve_rule(
        reader, "access-rule", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UNCHANGED


@pytest.mark.asyncio
async def test_resolve_rule_update_when_track_actually_differs():
    """Guard against an overly-lenient fix: a genuine difference inside `track` must still
    surface as UPDATE, not be swallowed by the declared-subset normalization."""
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    existing = RuleMatch(
        uid="r1",
        name="Allow-Web",
        rule_number=1,
        raw={
            "uid": "r1",
            "name": "Allow-Web",
            "source": [],
            "destination": [],
            "service": [],
            "action": "accept",
            "track": {"type": "None", "name": "None"},
        },
    )
    reader = RuleFakeReader(layer=layer, existing_rules=[existing])
    op = {
        "type": "access-rule",
        "layer": "Network",
        "position": "bottom",
        "data": {
            "name": "Allow-Web",
            "source": [],
            "destination": [],
            "service": [],
            "action": "accept",
            "track": {"type": "Log"},
        },
    }
    action, deps, counter = await resolve_rule(
        reader, "access-rule", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UPDATE
    assert action.payload["track"] == {"type": "Log"}


@pytest.mark.asyncio
async def test_resolve_rule_unchanged_when_install_on_live_shape_is_list_of_dicts():
    """`install-on` (and similarly time/protected-scope/site-category/blade) may come back from
    the live API as a list of {"name": ..., "uid": ...} dicts even though the template declares
    plain names -- reuse differ.py's `_equal` list-of-dicts-vs-names normalization here too."""
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    existing = RuleMatch(
        uid="r1",
        name="Allow-Web",
        rule_number=1,
        raw={
            "uid": "r1",
            "name": "Allow-Web",
            "source": [],
            "destination": [],
            "service": [],
            "action": "accept",
            "install-on": [{"name": "Policy Targets", "uid": "u-pt"}],
        },
    )
    reader = RuleFakeReader(layer=layer, existing_rules=[existing])
    op = {
        "type": "access-rule",
        "layer": "Network",
        "position": "bottom",
        "data": {
            "name": "Allow-Web",
            "source": [],
            "destination": [],
            "service": [],
            "action": "accept",
            "install-on": ["Policy Targets"],
        },
    }
    action, deps, counter = await resolve_rule(
        reader, "access-rule", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UNCHANGED


# ---------------------------------------------------------------------------
# resolve_rule for threat-prevention-rule/https-rule -- whole-branch review finding: these two
# rule types were only ever smoke-tested for command/layer dispatch (test_resolve_rule_by_key_
# works_for_threat_and_https_types), never exercised through the full traffic-tuple UNCHANGED/
# UPDATE decision with their own rule-type-specific _RULE_DATA_FIELDS (protected-scope for
# threat-prevention-rule; site-category/blade/certificate for https-rule) actually populated.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_rule_threat_prevention_unchanged_when_protected_scope_matches_live_shape():
    """`protected-scope` may come back from the live API as a list of {"name": ..., "uid": ...}
    dicts even though the template declares plain names -- same normalization as install-on
    (Task 14's whole-branch-review fix extended _REFERENCE_LIST_FIELDS to cover this field)."""
    layer = LayerInfo(uid="layer-u1", name="Threat Layer", type="threat-prevention")
    existing = RuleMatch(
        uid="r1",
        name="Block-Bots",
        rule_number=1,
        raw={
            "uid": "r1",
            "name": "Block-Bots",
            "source": [],
            "destination": [],
            "service": [],
            "action": "Prevent",
            "protected-scope": [{"name": "Web Servers", "uid": "u-ws"}],
        },
    )
    reader = RuleFakeReader(layer=layer, existing_rules=[existing])
    op = {
        "type": "threat-prevention-rule",
        "layer": "Threat Layer",
        "position": "bottom",
        "data": {
            "name": "Block-Bots",
            "source": [],
            "destination": [],
            "service": [],
            "action": "Prevent",
            "protected-scope": ["Web Servers"],
        },
    }
    action, deps, counter = await resolve_rule(
        reader, "threat-prevention-rule", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UNCHANGED


@pytest.mark.asyncio
async def test_resolve_rule_threat_prevention_update_when_protected_scope_differs():
    layer = LayerInfo(uid="layer-u1", name="Threat Layer", type="threat-prevention")
    existing = RuleMatch(
        uid="r1",
        name="Block-Bots",
        rule_number=1,
        raw={
            "uid": "r1",
            "name": "Block-Bots",
            "source": [],
            "destination": [],
            "service": [],
            "action": "Prevent",
            "protected-scope": [{"name": "Web Servers", "uid": "u-ws"}],
        },
    )
    reader = RuleFakeReader(layer=layer, existing_rules=[existing])
    op = {
        "type": "threat-prevention-rule",
        "layer": "Threat Layer",
        "position": "bottom",
        "data": {
            "name": "Block-Bots",
            "source": [],
            "destination": [],
            "service": [],
            "action": "Prevent",
            "protected-scope": ["DB Servers"],
        },
    }
    action, deps, counter = await resolve_rule(
        reader, "threat-prevention-rule", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UPDATE
    assert action.payload["protected-scope"] == ["DB Servers"]


@pytest.mark.asyncio
async def test_resolve_rule_https_unchanged_when_site_category_blade_certificate_match():
    layer = LayerInfo(uid="layer-u1", name="HTTPS Layer", type="https")
    existing = RuleMatch(
        uid="r1",
        name="Inspect-Web",
        rule_number=1,
        raw={
            "uid": "r1",
            "name": "Inspect-Web",
            "source": [],
            "destination": [],
            "service": [],
            "action": "Inspect",
            "site-category": [{"name": "Gambling", "uid": "u-gam"}],
            "blade": [{"name": "Application Control", "uid": "u-ac"}],
            "certificate": "outbound-cert",
        },
    )
    reader = RuleFakeReader(layer=layer, existing_rules=[existing])
    op = {
        "type": "https-rule",
        "layer": "HTTPS Layer",
        "position": "bottom",
        "data": {
            "name": "Inspect-Web",
            "source": [],
            "destination": [],
            "service": [],
            "action": "Inspect",
            "site-category": ["Gambling"],
            "blade": ["Application Control"],
            "certificate": "outbound-cert",
        },
    }
    action, deps, counter = await resolve_rule(
        reader, "https-rule", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UNCHANGED


@pytest.mark.asyncio
async def test_resolve_rule_https_update_when_certificate_differs():
    layer = LayerInfo(uid="layer-u1", name="HTTPS Layer", type="https")
    existing = RuleMatch(
        uid="r1",
        name="Inspect-Web",
        rule_number=1,
        raw={
            "uid": "r1",
            "name": "Inspect-Web",
            "source": [],
            "destination": [],
            "service": [],
            "action": "Inspect",
            "site-category": [],
            "blade": [],
            "certificate": "old-cert",
        },
    )
    reader = RuleFakeReader(layer=layer, existing_rules=[existing])
    op = {
        "type": "https-rule",
        "layer": "HTTPS Layer",
        "position": "bottom",
        "data": {
            "name": "Inspect-Web",
            "source": [],
            "destination": [],
            "service": [],
            "action": "Inspect",
            "certificate": "new-cert",
        },
    }
    action, deps, counter = await resolve_rule(
        reader, "https-rule", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UPDATE
    assert action.payload["certificate"] == "new-cert"


# ---------------------------------------------------------------------------
# resolve_nat_rule -- NAT's positional 6-tuple identity (package-scoped, not layer-scoped)
# ---------------------------------------------------------------------------


class NatFakeReader(FakeReader):
    def __init__(self, *args, existing_nat_rules=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._existing_nat_rules = existing_nat_rules or []

    async def find_nat_rules_by_tuple(self, package, tup, *, mgmt, domain):
        return self._existing_nat_rules

    async def get_last_nat_rule(self, package, *, mgmt, domain):
        return None


@pytest.mark.asyncio
async def test_resolve_nat_rule_create_when_no_tuple_match():
    reader = NatFakeReader()
    op = {
        "type": "nat-rule",
        "package": "Standard",
        "position": "bottom",
        "data": {
            "name": "hide-nat",
            "source": ["any"],
            "destination": ["any"],
            "service": ["any"],
            "method": "hide",
            "translated-source": "gw-01",
            "translated-destination": "any",
            "translated-service": "any",
        },
    }
    action, deps, counter = await resolve_nat_rule(reader, op, mgmt="m", domain="d", action_id="act-0001", counter=1)
    assert action.outcome == Outcome.CREATE
    assert action.command == "add-nat-rule"
    assert action.package == "Standard"
    # resolved_name must be set even on CREATE (no `winner` exists yet) -- otherwise
    # PlannedAction.to_result() reports an empty name for every created NAT rule (Task 11 lesson).
    assert action.resolved_name == "hide-nat"


@pytest.mark.asyncio
async def test_resolve_nat_rule_create_omits_any_translated_destination_and_service():
    """Check Point rejects "Any" for translated-* fields on `publish` (not `add-nat-rule` itself,
    which accepts the uid fine) -- confirmed live: "Field Translated Destination/Services
    references invalid objects". A template that leaves translated-destination/service at their
    "any" default (or sets them explicitly to "any") means "= Original" (no translation on that
    side), which the API expresses by omitting the field, not by any uid."""
    reader = NatFakeReader()
    op = {
        "type": "nat-rule",
        "package": "Standard",
        "position": "bottom",
        "data": {
            "name": "hide-nat",
            "source": ["Host_XXX"],
            "destination": ["Host_YYY"],
            "service": ["any"],
            "method": "hide",
            "translated-source": "gw-01",
        },
    }
    action, deps, counter = await resolve_nat_rule(reader, op, mgmt="m", domain="d", action_id="act-0001", counter=1)
    assert action.outcome == Outcome.CREATE
    assert "translated-destination" not in action.payload
    assert "translated-service" not in action.payload
    assert action.payload["translated-source"] == "gw-01"
    # original-service left at its "any" default -> DOES get the uid substitution (CP accepts
    # "Any" traffic matches on original-* fields, just not by the literal name "Any").
    assert action.payload["original-service"] == "97aeb369-9aea-11d5-bd16-0090272ccb30"


class NatTupleFakeReader(FakeReader):
    """Reader whose `find_nat_rules_by_tuple` does a REAL tuple comparison, unlike
    `NatFakeReader` above (which returns its fixture list unconditionally regardless of `tup`).
    Needed to catch a bug in the computed tuple's VALUES themselves, not just the outcome --
    `NatFakeReader` can't distinguish "resolve_nat_rule computed the right tuple" from "it
    computed some other tuple that happens to not matter to this fake"."""

    def __init__(self, *args, live_tuple, live_rule, **kwargs):
        super().__init__(*args, **kwargs)
        self._live_tuple = live_tuple
        self._live_rule = live_rule

    async def find_nat_rules_by_tuple(self, package, tup, *, mgmt, domain):
        return [self._live_rule] if tup == self._live_tuple else []

    async def get_last_nat_rule(self, package, *, mgmt, domain):
        return None


@pytest.mark.asyncio
async def test_resolve_nat_rule_computes_original_not_any_for_omitted_translated_fields():
    """The regression this guards against: a live, already-published NAT rule with no real
    destination/service translation dereferences those fields to the literal string "Original"
    (confirmed against the live lab via statereader.py's `_dereference_nat_rule` +
    `objects-dictionary`), NOT "Any". Before this fix, `resolve_nat_rule` computed "Any" for an
    omitted/"any" translated-destination/service, so its tuple could never equal a live rule's
    real ("Original"-bearing) tuple -- `find_nat_rules_by_tuple` would never find a match, and
    every idempotent re-apply created a duplicate rule instead of reporting UNCHANGED. Uses
    `NatTupleFakeReader` (real tuple comparison) rather than `NatFakeReader` (ignores `tup`
    entirely) so this test actually fails against the pre-fix "Any" computation."""
    live_tuple = ("Host_XXX", "Host_YYY", "Any", "gw-01", "Original", "Original")
    live_rule = RuleMatch(
        uid="n1",
        name="hide-nat",
        rule_number=1,
        raw={
            "uid": "n1",
            "name": "hide-nat",
            "method": "hide",
            "enabled": True,
            "comments": "",
            "original-source": "Host_XXX",
            "original-destination": "Host_YYY",
            "original-service": "Any",
            "translated-source": "gw-01",
            "translated-destination": "Original",
            "translated-service": "Original",
            "install-on": [],
        },
    )
    reader = NatTupleFakeReader(live_tuple=live_tuple, live_rule=live_rule)
    op = {
        "type": "nat-rule",
        "package": "Standard",
        "position": "bottom",
        "data": {
            "name": "hide-nat",
            "source": ["Host_XXX"],
            "destination": ["Host_YYY"],
            "service": ["any"],
            "method": "hide",
            "translated-source": "gw-01",
        },
    }
    action, deps, counter = await resolve_nat_rule(reader, op, mgmt="m", domain="d", action_id="act-0001", counter=1)
    assert action.outcome == Outcome.UNCHANGED


@pytest.mark.asyncio
async def test_resolve_nat_rule_unchanged_when_tuple_and_fields_match():
    existing = RuleMatch(
        uid="n1",
        name="hide-nat",
        rule_number=1,
        raw={
            "uid": "n1",
            "name": "hide-nat",
            "method": "hide",
            "enabled": True,
            "comments": "",
            "original-source": "Any",
            "original-destination": "Any",
            "original-service": "Any",
            "translated-source": "gw-01",
            "translated-destination": "Any",
            "translated-service": "Any",
            "install-on": [],
        },
    )
    reader = NatFakeReader(existing_nat_rules=[existing])
    op = {
        "type": "nat-rule",
        "package": "Standard",
        "position": "bottom",
        "data": {
            "name": "hide-nat",
            "source": ["any"],
            "destination": ["any"],
            "service": ["any"],
            "method": "hide",
            "translated-source": "gw-01",
            "translated-destination": "any",
            "translated-service": "any",
        },
    }
    action, deps, counter = await resolve_nat_rule(reader, op, mgmt="m", domain="d", action_id="act-0001", counter=1)
    assert action.outcome == Outcome.UNCHANGED


@pytest.mark.asyncio
async def test_resolve_nat_rule_update_when_tuple_identical_but_method_differs():
    """CRITICAL: same tuple match (source/destination/service/translated-* all identical) but
    `method` differs -> UPDATE. The `set-nat-rule` payload MUST include `package` alongside
    `uid` -- confirmed via Check Point's API reference (set-nat-rule.j.md) that both are
    `required: true`, because NAT rule uids are only unique within their owning package's NAT
    rulebase (exactly analogous to access-rule's layer-scoping, Task 11's bug class)."""
    existing = RuleMatch(
        uid="n1",
        name="hide-nat",
        rule_number=1,
        raw={
            "uid": "n1",
            "name": "hide-nat",
            "method": "hide",
            "enabled": True,
            "comments": "",
            "original-source": "Any",
            "original-destination": "Any",
            "original-service": "Any",
            "translated-source": "gw-01",
            "translated-destination": "Any",
            "translated-service": "Any",
            "install-on": [],
        },
    )
    reader = NatFakeReader(existing_nat_rules=[existing])
    op = {
        "type": "nat-rule",
        "package": "Standard",
        "position": "bottom",
        "data": {
            "name": "hide-nat",
            "source": ["any"],
            "destination": ["any"],
            "service": ["any"],
            "method": "static",
            "translated-source": "gw-01",
            "translated-destination": "any",
            "translated-service": "any",
        },
    }
    action, deps, counter = await resolve_nat_rule(reader, op, mgmt="m", domain="d", action_id="act-0001", counter=1)
    assert action.outcome == Outcome.UPDATE
    assert action.resolved_uid == "n1"
    assert action.command == "set-nat-rule"
    assert action.payload["uid"] == "n1"
    assert action.payload["package"] == "Standard"  # NOT optional -- see docstring above
    assert action.payload["method"] == "static"


@pytest.mark.asyncio
async def test_resolve_nat_rule_update_when_enabled_differs_carries_enabled_in_payload():
    """`enabled` drives the UNCHANGED/UPDATE decision (method_equal/enabled_equal), so the
    resulting `set-nat-rule` payload MUST actually carry `enabled` -- otherwise the field that
    triggered the UPDATE never gets fixed on the live rule (silently-dropped-declared-field bug,
    same class the `package` fix above addressed for `uid`)."""
    existing = RuleMatch(
        uid="n1",
        name="hide-nat",
        rule_number=1,
        raw={
            "uid": "n1",
            "name": "hide-nat",
            "method": "hide",
            "enabled": True,
            "comments": "",
            "original-source": "Any",
            "original-destination": "Any",
            "original-service": "Any",
            "translated-source": "gw-01",
            "translated-destination": "Any",
            "translated-service": "Any",
            "install-on": [],
        },
    )
    reader = NatFakeReader(existing_nat_rules=[existing])
    op = {
        "type": "nat-rule",
        "package": "Standard",
        "position": "bottom",
        "data": {
            "name": "hide-nat",
            "source": ["any"],
            "destination": ["any"],
            "service": ["any"],
            "method": "hide",
            "translated-source": "gw-01",
            "translated-destination": "any",
            "translated-service": "any",
            "enabled": False,
            "comments": "disabled for maintenance",
        },
    }
    action, deps, counter = await resolve_nat_rule(reader, op, mgmt="m", domain="d", action_id="act-0001", counter=1)
    assert action.outcome == Outcome.UPDATE
    assert action.payload["enabled"] is False
    assert action.payload["comments"] == "disabled for maintenance"


@pytest.mark.asyncio
async def test_resolve_nat_rule_update_when_only_comments_differs():
    """Whole-branch review finding: the UNCHANGED/UPDATE decision must compare every declared
    NAT data field, not just method/enabled -- comments and install-on are legitimate nat-rule
    fields already included in the outgoing payload, so a template that changes ONLY comments
    (method/enabled both unchanged) must still be detected as a real UPDATE, not silently
    misreported as UNCHANGED (which would mean the comments change never actually reaches the
    live rule)."""
    existing = RuleMatch(
        uid="n1",
        name="hide-nat",
        rule_number=1,
        raw={
            "uid": "n1",
            "name": "hide-nat",
            "method": "hide",
            "enabled": True,
            "comments": "old comment",
            "original-source": "Any",
            "original-destination": "Any",
            "original-service": "Any",
            "translated-source": "gw-01",
            "translated-destination": "Any",
            "translated-service": "Any",
            "install-on": [],
        },
    )
    reader = NatFakeReader(existing_nat_rules=[existing])
    op = {
        "type": "nat-rule",
        "package": "Standard",
        "position": "bottom",
        "data": {
            "name": "hide-nat",
            "source": ["any"],
            "destination": ["any"],
            "service": ["any"],
            "method": "hide",
            "translated-source": "gw-01",
            "translated-destination": "any",
            "translated-service": "any",
            "comments": "new comment",
        },
    }
    action, deps, counter = await resolve_nat_rule(reader, op, mgmt="m", domain="d", action_id="act-0001", counter=1)
    assert action.outcome == Outcome.UPDATE
    assert action.payload["comments"] == "new comment"


class RuleKeyFakeReader(FakeReader):
    """Reader for resolve_rule_by_key tests -- key-based lookup, no traffic-tuple discovery."""

    def __init__(self, *args, layer=None, rule=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._layer = layer
        self._rule = rule

    async def get_layer(self, layer_ref, layer_type, *, mgmt, domain):
        return self._layer

    async def get_rule_by_key(self, scope_uid, layer_type, key, *, mgmt, domain):
        return self._rule


class NatKeyFakeReader(FakeReader):
    """Reader for resolve_nat_rule_by_key tests."""

    def __init__(self, *args, rule=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._rule = rule

    async def get_nat_rule_by_key(self, package, key, *, mgmt, domain):
        return self._rule


# ---------------------------------------------------------------------------
# resolve_rule_by_key -- key-based update/delete/show for access/threat/https rules
# (identity is `key: {name|uid|rule-number}`, no traffic-tuple discovery)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_rule_by_key_update_found_includes_layer_in_payload():
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    rule = RuleMatch(
        uid="r1",
        name="Allow-Web",
        rule_number=1,
        raw={
            "uid": "r1",
            "name": "Allow-Web",
            "enabled": True,
            "comments": "old",
        },
    )
    reader = RuleKeyFakeReader(layer=layer, rule=rule)
    op = {
        "type": "access-rule",
        "operation": "update",
        "layer": "Network",
        "key": {"name": "Allow-Web"},
        "data": {"comments": "new comment"},
    }
    action, deps, counter = await resolve_rule_by_key(
        reader, "access-rule", "update", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UPDATE
    assert action.command == "set-access-rule"
    assert action.payload["uid"] == "r1"
    # REQUIRED: layer must accompany uid on set-access-rule (access_rule_update requires
    # `layer` in its top-level `required` array per the ops schema) -- Task 11's bug class.
    assert action.payload["layer"] == "Network"
    assert action.payload["comments"] == "new comment"
    assert action.resolved_uid == "r1"


@pytest.mark.asyncio
async def test_resolve_rule_by_key_update_not_found_is_error():
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    reader = RuleKeyFakeReader(layer=layer, rule=None)
    op = {
        "type": "access-rule",
        "operation": "update",
        "layer": "Network",
        "key": {"name": "Missing"},
        "data": {"comments": "new comment"},
    }
    action, deps, counter = await resolve_rule_by_key(
        reader, "access-rule", "update", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.ERROR
    assert action.message == "rule not found"
    assert action.command is None


@pytest.mark.asyncio
async def test_resolve_rule_by_key_update_unchanged_when_data_matches_live():
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    rule = RuleMatch(
        uid="r1",
        name="Allow-Web",
        rule_number=1,
        raw={
            "uid": "r1",
            "name": "Allow-Web",
            "enabled": True,
            "comments": "same",
        },
    )
    reader = RuleKeyFakeReader(layer=layer, rule=rule)
    op = {
        "type": "access-rule",
        "operation": "update",
        "layer": "Network",
        "key": {"uid": "r1"},
        "data": {"comments": "same"},
    }
    action, deps, counter = await resolve_rule_by_key(
        reader, "access-rule", "update", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UNCHANGED
    assert action.command is None


@pytest.mark.asyncio
async def test_resolve_rule_by_key_delete_found_includes_layer_in_payload():
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    rule = RuleMatch(uid="r1", name="Allow-Web", rule_number=1, raw={"uid": "r1", "name": "Allow-Web"})
    reader = RuleKeyFakeReader(layer=layer, rule=rule)
    op = {"type": "access-rule", "operation": "delete", "layer": "Network", "key": {"rule-number": 1}}
    action, deps, counter = await resolve_rule_by_key(
        reader, "access-rule", "delete", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.DELETE
    assert action.command == "delete-access-rule"
    assert action.payload["uid"] == "r1"
    assert action.payload["layer"] == "Network"  # required alongside uid, same as update


@pytest.mark.asyncio
async def test_resolve_rule_by_key_delete_not_found_is_idempotent():
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    reader = RuleKeyFakeReader(layer=layer, rule=None)
    op = {"type": "access-rule", "operation": "delete", "layer": "Network", "key": {"name": "gone"}}
    action, deps, counter = await resolve_rule_by_key(
        reader, "access-rule", "delete", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.DELETE  # already absent = success, matches object resolve_delete convention
    assert action.command is None
    assert action.prior_state is None


@pytest.mark.asyncio
async def test_rule_delete_captures_prior_state_with_number():
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    rule = RuleMatch(
        uid="r-1",
        name="r",
        rule_number=7,
        raw={
            "name": "r",
            "source": ["Any"],
            "destination": ["Any"],
            "service": ["Any"],
            "action": "Drop",
        },
    )
    reader = RuleKeyFakeReader(layer=layer, rule=rule)
    op = {"key": {"name": "r"}, "layer": "Network", "type": "access-rule", "operation": "delete"}
    action, deps, counter = await resolve_rule_by_key(
        reader, "access-rule", "delete", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.prior_state["_rule_number"] == 7
    assert action.prior_state["action"] == "Drop"


@pytest.mark.asyncio
async def test_resolve_rule_by_key_show_found():
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    rule = RuleMatch(uid="r1", name="Allow-Web", rule_number=1, raw={"uid": "r1", "name": "Allow-Web"})
    reader = RuleKeyFakeReader(layer=layer, rule=rule)
    op = {"type": "access-rule", "operation": "show", "layer": "Network", "key": {"name": "Allow-Web"}}
    action, deps, counter = await resolve_rule_by_key(
        reader, "access-rule", "show", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UNCHANGED
    assert action.resolved_uid == "r1"
    assert action.matches[0].name == "Allow-Web"


@pytest.mark.asyncio
async def test_resolve_rule_by_key_show_not_found_is_error():
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    reader = RuleKeyFakeReader(layer=layer, rule=None)
    op = {"type": "access-rule", "operation": "show", "layer": "Network", "key": {"name": "gone"}}
    action, deps, counter = await resolve_rule_by_key(
        reader, "access-rule", "show", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.ERROR
    assert action.message == "rule not found"


@pytest.mark.asyncio
async def test_resolve_rule_by_key_works_for_threat_and_https_types():
    """Same helper, different rule_type -- command suffix and layer_type must map correctly."""
    layer = LayerInfo(uid="layer-u1", name="Threat Layer", type="threat-prevention")
    rule = RuleMatch(uid="r1", name="Block-Bots", rule_number=1, raw={"uid": "r1", "name": "Block-Bots"})
    reader = RuleKeyFakeReader(layer=layer, rule=rule)
    op = {
        "type": "threat-prevention-rule",
        "operation": "update",
        "layer": "Threat Layer",
        "key": {"name": "Block-Bots"},
        "data": {"enabled": False},
    }
    action, deps, counter = await resolve_rule_by_key(
        reader, "threat-prevention-rule", "update", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.command == "set-threat-rule"
    assert action.payload["layer"] == "Threat Layer"


@pytest.mark.asyncio
async def test_resolve_rule_by_key_update_resolves_bare_ip_in_destination():
    """A key-based update can change source/destination/service too -- these must be
    resolved through the same bare-IP/CIDR/range find-or-create pipeline `resolve_rule`'s
    `add` path uses (Task 9), not forwarded as a literal string CP's API won't accept."""
    layer = LayerInfo(uid="layer-u1", name="Network", type="access")
    rule = RuleMatch(
        uid="r1",
        name="Allow-Web",
        rule_number=1,
        raw={
            "uid": "r1",
            "name": "Allow-Web",
            "destination": ["Any"],
        },
    )
    reader = RuleKeyFakeReader(layer=layer, rule=rule, by_ip=[])
    op = {
        "type": "access-rule",
        "operation": "update",
        "layer": "Network",
        "key": {"name": "Allow-Web"},
        "data": {"destination": ["10.0.0.99"]},
    }
    action, deps, counter = await resolve_rule_by_key(
        reader, "access-rule", "update", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UPDATE
    assert len(deps) == 1
    assert deps[0].type == "host" and deps[0].resolved_name == "Host_10.0.0.99"
    assert deps[0].id in action.depends_on
    assert action.payload["destination"] == ["Host_10.0.0.99"]


# ---------------------------------------------------------------------------
# resolve_nat_rule_by_key -- key-based update/delete/show for nat-rule (package-scoped)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_nat_rule_by_key_update_found_includes_package_in_payload():
    rule = RuleMatch(
        uid="n1",
        name="hide-nat",
        rule_number=1,
        raw={
            "uid": "n1",
            "name": "hide-nat",
            "method": "hide",
            "enabled": True,
        },
    )
    reader = NatKeyFakeReader(rule=rule)
    op = {
        "type": "nat-rule",
        "operation": "update",
        "package": "Standard",
        "key": {"name": "hide-nat"},
        "data": {"method": "static"},
    }
    action, deps, counter = await resolve_nat_rule_by_key(
        reader, "update", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UPDATE
    assert action.command == "set-nat-rule"
    assert action.payload["uid"] == "n1"
    # REQUIRED: package must accompany uid on set-nat-rule (nat_rule_update requires
    # `package` in its top-level `required` array per the ops schema) -- Task 12's bug class.
    assert action.payload["package"] == "Standard"
    assert action.payload["method"] == "static"


@pytest.mark.asyncio
async def test_resolve_nat_rule_by_key_update_not_found_is_error():
    reader = NatKeyFakeReader(rule=None)
    op = {
        "type": "nat-rule",
        "operation": "update",
        "package": "Standard",
        "key": {"name": "missing"},
        "data": {"method": "static"},
    }
    action, deps, counter = await resolve_nat_rule_by_key(
        reader, "update", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.ERROR
    assert action.message == "rule not found"


@pytest.mark.asyncio
async def test_resolve_nat_rule_by_key_update_unchanged_when_data_matches_live():
    rule = RuleMatch(
        uid="n1",
        name="hide-nat",
        rule_number=1,
        raw={
            "uid": "n1",
            "name": "hide-nat",
            "method": "hide",
            "enabled": True,
        },
    )
    reader = NatKeyFakeReader(rule=rule)
    op = {
        "type": "nat-rule",
        "operation": "update",
        "package": "Standard",
        "key": {"uid": "n1"},
        "data": {"method": "hide"},
    }
    action, deps, counter = await resolve_nat_rule_by_key(
        reader, "update", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UNCHANGED
    assert action.command is None


@pytest.mark.asyncio
async def test_resolve_nat_rule_by_key_update_resolves_bare_ip_in_translated_source():
    """`translated-source`/`translated-destination`/`translated-service` are singular strings
    (not lists) -- must still be resolved through the bare-IP/service-spec find-or-create
    pipeline, matching `resolve_nat_rule`'s `add` path (Task 12), not forwarded verbatim."""
    rule = RuleMatch(
        uid="n1",
        name="hide-nat",
        rule_number=1,
        raw={
            "uid": "n1",
            "name": "hide-nat",
            "method": "hide",
            "translated-source": "Any",
        },
    )
    reader = NatKeyFakeReader(rule=rule, by_ip=[])
    op = {
        "type": "nat-rule",
        "operation": "update",
        "package": "Standard",
        "key": {"name": "hide-nat"},
        "data": {"translated-source": "10.0.0.50"},
    }
    action, deps, counter = await resolve_nat_rule_by_key(
        reader, "update", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UPDATE
    assert len(deps) == 1
    assert deps[0].type == "host" and deps[0].resolved_name == "Host_10.0.0.50"
    assert deps[0].id in action.depends_on
    assert action.payload["translated-source"] == "Host_10.0.0.50"


@pytest.mark.asyncio
async def test_resolve_nat_rule_by_key_delete_found_includes_package_in_payload():
    rule = RuleMatch(uid="n1", name="hide-nat", rule_number=1, raw={"uid": "n1", "name": "hide-nat"})
    reader = NatKeyFakeReader(rule=rule)
    op = {"type": "nat-rule", "operation": "delete", "package": "Standard", "key": {"rule-number": 1}}
    action, deps, counter = await resolve_nat_rule_by_key(
        reader, "delete", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.DELETE
    assert action.command == "delete-nat-rule"
    assert action.payload["uid"] == "n1"
    assert action.payload["package"] == "Standard"


@pytest.mark.asyncio
async def test_resolve_nat_rule_by_key_delete_not_found_is_idempotent():
    reader = NatKeyFakeReader(rule=None)
    op = {"type": "nat-rule", "operation": "delete", "package": "Standard", "key": {"name": "gone"}}
    action, deps, counter = await resolve_nat_rule_by_key(
        reader, "delete", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.DELETE
    assert action.command is None
    assert action.prior_state is None


@pytest.mark.asyncio
async def test_resolve_nat_rule_by_key_delete_captures_prior_state_with_number():
    rule = RuleMatch(
        uid="n-1",
        name="hide-nat",
        rule_number=3,
        raw={
            "name": "hide-nat",
            "method": "hide",
            "original-source": "Any",
        },
    )
    reader = NatKeyFakeReader(rule=rule)
    op = {"type": "nat-rule", "operation": "delete", "package": "Standard", "key": {"name": "hide-nat"}}
    action, deps, counter = await resolve_nat_rule_by_key(
        reader, "delete", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.prior_state["_rule_number"] == 3
    assert action.prior_state["method"] == "hide"


@pytest.mark.asyncio
async def test_resolve_nat_rule_by_key_show_found():
    rule = RuleMatch(uid="n1", name="hide-nat", rule_number=1, raw={"uid": "n1", "name": "hide-nat"})
    reader = NatKeyFakeReader(rule=rule)
    op = {"type": "nat-rule", "operation": "show", "package": "Standard", "key": {"name": "hide-nat"}}
    action, deps, counter = await resolve_nat_rule_by_key(
        reader, "show", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.UNCHANGED
    assert action.resolved_uid == "n1"


@pytest.mark.asyncio
async def test_resolve_nat_rule_by_key_show_not_found_is_error():
    reader = NatKeyFakeReader(rule=None)
    op = {"type": "nat-rule", "operation": "show", "package": "Standard", "key": {"name": "gone"}}
    action, deps, counter = await resolve_nat_rule_by_key(
        reader, "show", op, mgmt="m", domain="d", action_id="act-0001", counter=1
    )
    assert action.outcome == Outcome.ERROR
    assert action.message == "rule not found"


@pytest.mark.asyncio
async def test_resolve_nat_rule_synthesizes_object_dependency_for_bare_ip():
    """A bare IP in the NAT tuple's original-source position must synthesize a create
    dependency, and both the tuple computation and the payload must use the dependency's
    `resolved_name` (never its plan-internal id) -- matching resolve_rule's established
    pattern (Task 11) and Plan A/B's group auto-create precedent."""
    reader = NatFakeReader(by_ip=[])
    op = {
        "type": "nat-rule",
        "package": "Standard",
        "position": "bottom",
        "data": {
            "name": "hide-nat-host",
            "source": ["10.0.0.9"],
            "destination": ["any"],
            "service": ["any"],
            "method": "hide",
            "translated-source": "gw-01",
            "translated-destination": "any",
            "translated-service": "any",
        },
    }
    action, deps, counter = await resolve_nat_rule(reader, op, mgmt="m", domain="d", action_id="act-0001", counter=1)
    assert len(deps) == 1
    assert deps[0].type == "host" and deps[0].resolved_name == "Host_10.0.0.9"
    assert deps[0].id in action.depends_on
    # `original-source`, singular (not a list) -- CP's add-nat-rule doesn't accept plain "source"
    # at all ("Unrecognized parameter [source]", confirmed against the live lab in Task 14).
    assert action.payload["original-source"] == "Host_10.0.0.9"


# --- Task 4: configurable NamingPrefixes threaded through the resolver layer ---


@pytest.mark.asyncio
async def test_ip_reference_uses_configured_prefixes():
    p = NamingPrefixes(host="H-", network="N-", range="R-")
    reader = FakeReader()  # find_by_ip returns [] for everything -- always synthesizes a CREATE
    ref, dep = await resolve_ip_reference(reader, "10.1.2.3", mgmt="m", domain="d", action_id="act-0001", prefixes=p)
    assert dep is not None and dep.resolved_name == "H-10.1.2.3"
    ref, dep = await resolve_ip_reference(reader, "10.1.0.0/24", mgmt="m", domain="d", action_id="act-0002", prefixes=p)
    assert dep.resolved_name == "N-10.1.0.0_24"
    ref, dep = await resolve_ip_reference(
        reader, "10.1.2.3-10.1.2.9", mgmt="m", domain="d", action_id="act-0003", prefixes=p
    )
    assert dep.resolved_name == "R-10.1.2.3-10.1.2.9"


@pytest.mark.asyncio
async def test_ip_reference_default_prefixes_unchanged():
    reader = FakeReader()
    ref, dep = await resolve_ip_reference(reader, "10.1.2.3", mgmt="m", domain="Global", action_id="act-0001")
    assert dep.resolved_name == "global_Host_10.1.2.3"


@pytest.mark.asyncio
async def test_service_reference_uses_configured_prefixes():
    class ServiceReader(FakeReader):
        async def get_service(self, spec, original_text, *, mgmt, domain):
            return None

    p = NamingPrefixes(svc_tcp="Tcp-")
    reader = ServiceReader()
    resolved, dep = await resolve_service_reference(
        reader, "tcp/8080", mgmt="m", domain="d", action_id="act-0001", prefixes=p
    )
    assert dep is not None
    assert dep.resolved_name == "Tcp-8080"
    assert resolved == dep.id


@pytest.mark.asyncio
async def test_resolve_rule_forwards_prefixes_to_synthesized_dependencies():
    """resolve_rule's synthesized source/destination/service dependencies must use the
    configured prefixes, not the hardcoded defaults, proving the keyword threads all the way
    through `_resolve_reference_list`."""

    class Reader(FakeReader):
        async def get_service(self, spec, original_text, *, mgmt, domain):
            return None

    reader = Reader()  # find_by_ip/get_service both miss -> synthesizes CREATE deps
    p = NamingPrefixes(host="H-", svc_tcp="Tcp-")
    op = {
        "type": "access-rule",
        "layer": "Network",
        "position": "bottom",
        "data": {
            "name": "r1",
            "source": ["10.0.0.9"],
            "destination": ["any"],
            "service": ["tcp/8080"],
            "action": "accept",
        },
    }
    action, deps, counter = await resolve_rule(
        reader, "access-rule", op, mgmt="m", domain="d", action_id="act-0001", counter=1, prefixes=p
    )
    dep_names = {d.type: d.resolved_name for d in deps}
    assert dep_names["host"] == "H-10.0.0.9"
    assert dep_names["tcp-service"] == "Tcp-8080"


@pytest.mark.asyncio
async def test_resolve_nat_rule_forwards_prefixes_to_synthesized_dependency():
    reader = FakeReader()
    p = NamingPrefixes(host="H-")
    op = {
        "type": "nat-rule",
        "package": "Standard",
        "position": "bottom",
        "data": {
            "name": "hide-nat-host",
            "source": ["10.0.0.9"],
            "destination": ["any"],
            "service": ["any"],
            "method": "hide",
            "translated-source": "any",
            "translated-destination": "any",
            "translated-service": "any",
        },
    }
    action, deps, counter = await resolve_nat_rule(
        reader, op, mgmt="m", domain="d", action_id="act-0001", counter=1, prefixes=p
    )
    assert len(deps) == 1
    assert deps[0].resolved_name == "H-10.0.0.9"


@pytest.mark.asyncio
async def test_resolve_rule_by_key_forwards_prefixes_to_update_reference_fields():
    class Reader(FakeReader):
        async def get_layer(self, layer_ref, layer_type, *, mgmt, domain):
            return LayerInfo(uid="layer-u1", name=layer_ref, type=layer_type)

        async def get_rule_by_key(self, scope_uid, layer_type, key, *, mgmt, domain):
            return RuleMatch(uid="r1", name="Allow-Web", rule_number=1, raw={"uid": "r1", "name": "Allow-Web"})

    reader = Reader()
    p = NamingPrefixes(host="H-")
    op = {
        "type": "access-rule",
        "operation": "update",
        "layer": "Network",
        "key": {"name": "Allow-Web"},
        "data": {"source": ["10.0.0.9"]},
    }
    action, deps, counter = await resolve_rule_by_key(
        reader, "access-rule", "update", op, mgmt="m", domain="d", action_id="act-0001", counter=1, prefixes=p
    )
    assert len(deps) == 1
    assert deps[0].resolved_name == "H-10.0.0.9"
    assert action.payload["source"] == ["H-10.0.0.9"]


@pytest.mark.asyncio
async def test_resolve_nat_rule_by_key_forwards_prefixes_to_update_reference_fields():
    class NatKeyReader(FakeReader):
        async def get_nat_rule_by_key(self, package, key, *, mgmt, domain):
            return RuleMatch(
                uid="n1",
                name="hide-nat",
                rule_number=1,
                raw={
                    "uid": "n1",
                    "name": "hide-nat",
                    "method": "hide",
                    "translated-source": "Any",
                },
            )

    reader = NatKeyReader()
    p = NamingPrefixes(host="H-")
    op = {
        "type": "nat-rule",
        "operation": "update",
        "package": "Standard",
        "key": {"name": "hide-nat"},
        "data": {"translated-source": "10.0.0.50"},
    }
    action, deps, counter = await resolve_nat_rule_by_key(
        reader, "update", op, mgmt="m", domain="d", action_id="act-0001", counter=1, prefixes=p
    )
    assert len(deps) == 1
    assert deps[0].resolved_name == "H-10.0.0.50"
    assert action.payload["translated-source"] == "H-10.0.0.50"
