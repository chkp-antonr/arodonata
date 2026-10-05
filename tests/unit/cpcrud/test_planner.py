# tests/unit/cpcrud/test_planner.py
import pytest

from arodonata.cpcrud.models import DomainStamp, ObjectState, Outcome
from arodonata.cpcrud.naming import DEFAULT_PREFIXES, NamingPrefixes
from arodonata.cpcrud.planner import Planner
from arodonata.cpcrud.resolver import StateReadError
from tests.unit.cpcrud.test_resolver import FakeReader  # reuse the fake


def _doc(*ops):
    return {"management_servers": [{"mgmt_name": "m1", "domains": [{"name": "General", "operations": list(ops)}]}]}


def _actions_for(plan, mgmt, domain):
    return [a for a in plan.actions if a.mgmt_name == mgmt and a.domain_name == domain]


@pytest.mark.asyncio
async def test_decide_creates_when_absent():
    reader = FakeReader()
    planner = Planner(reader, settings=None)
    plan = await planner.decide(_doc({"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.1"}}))
    actions = _actions_for(plan, "m1", "General")
    assert actions[0].outcome == Outcome.CREATE


@pytest.mark.asyncio
async def test_decide_orders_groups_after_objects():
    reader = FakeReader()
    planner = Planner(reader, settings=None)
    doc = _doc(
        {"type": "network-group", "data": {"name": "g1", "members": ["h1"]}},
        {"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.1"}},
    )
    plan = await planner.decide(doc)
    types = [a.type for a in _actions_for(plan, "m1", "General")]
    assert types.index("host") < types.index("network-group")


@pytest.mark.asyncio
async def test_decide_per_op_policy_overrides_settings():
    reader = FakeReader()

    # settings stub with ip=error default
    class S:
        cpcrud_on_name_conflict = "update"
        cpcrud_on_ip_conflict = "error"

    planner = Planner(reader, settings=S())
    # op overrides ip to reuse; absent IP conflict -> still CREATE
    plan = await planner.decide(
        _doc({"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.1"}, "on_ip_conflict": "reuse"})
    )
    assert _actions_for(plan, "m1", "General")[0].outcome == Outcome.CREATE


@pytest.fixture
def minimal_template():
    return {
        "management_servers": [
            {
                "mgmt_name": "mgmt-a",
                "domains": [
                    {
                        "name": "dom-a",
                        "operations": [
                            {"operation": "add", "type": "host", "data": {"name": "h1", "ip-address": "10.0.0.1"}}
                        ],
                    }
                ],
            }
        ],
    }


@pytest.mark.asyncio
async def test_decide_stamps_domains(minimal_template):
    reader = FakeReader()
    reader.last_publish = "sess-uid-42"

    async def get_last_publish_session(*, mgmt, domain):
        return reader.last_publish

    reader.get_last_publish_session = get_last_publish_session

    plan = await Planner(reader).decide(minimal_template)
    assert plan.stamps == [DomainStamp(mgmt_name="mgmt-a", domain_name="dom-a", last_publish_session="sess-uid-42")]
    assert len(plan.template_hash) == 64


@pytest.mark.asyncio
async def test_missing_referenced_group_is_auto_created_before_object():
    reader = FakeReader()  # get_by_name returns None for everything
    template = {
        "management_servers": [
            {
                "mgmt_name": "m",
                "domains": [
                    {
                        "name": "d",
                        "operations": [
                            {
                                "operation": "add",
                                "type": "host",
                                "data": {"name": "h1", "ip-address": "10.0.0.1", "groups": ["WebServers"]},
                            },
                        ],
                    }
                ],
            }
        ],
    }
    plan = await Planner(reader).decide(template)
    kinds = [(a.type, a.operation, a.auto_created) for a in plan.actions]
    assert kinds[0] == ("network-group", "add", True)
    assert plan.actions[0].payload == {"name": "WebServers"}
    host = plan.actions[1]
    assert host.type == "host" and plan.actions[0].id in host.depends_on


@pytest.mark.asyncio
async def test_explicit_group_action_is_moved_before_dependent_object():
    reader = FakeReader()
    template = {
        "management_servers": [
            {
                "mgmt_name": "m",
                "domains": [
                    {
                        "name": "d",
                        "operations": [
                            {
                                "operation": "add",
                                "type": "host",
                                "data": {"name": "h1", "ip-address": "10.0.0.1", "groups": ["G1"]},
                            },
                            {"operation": "add", "type": "network-group", "data": {"name": "G1"}},
                        ],
                    }
                ],
            }
        ],
    }
    plan = await Planner(reader).decide(template)
    order = [a.type for a in plan.actions]
    assert order.index("network-group") < order.index("host")
    group_action = next(a for a in plan.actions if a.type == "network-group")
    host_action = next(a for a in plan.actions if a.type == "host")
    assert group_action.id in host_action.depends_on
    assert group_action.auto_created is False  # explicit, not synthesized


@pytest.mark.asyncio
async def test_existing_group_reported_as_reuse_with_edge():
    """Task 5: a group referenced via `data.groups` that already exists in state must no
    longer vanish silently -- it now surfaces as a REUSE action (auto_created=True), and the
    referencing host still gets a `depends_on` edge to it (previously: no action, no edge)."""
    reader = FakeReader(group_names={"Prod"})  # extend FakeReader: get_by_name("network-group","Prod") -> ObjectState
    template = {
        "management_servers": [
            {
                "mgmt_name": "m",
                "domains": [
                    {
                        "name": "d",
                        "operations": [
                            {
                                "operation": "add",
                                "type": "host",
                                "data": {"name": "h1", "ip-address": "10.0.0.1", "groups": ["Prod"]},
                            },
                        ],
                    }
                ],
            }
        ],
    }
    plan = await Planner(reader).decide(template)
    assert [a.type for a in plan.actions] == ["network-group", "host"]
    group_action, host_action = plan.actions
    assert group_action.outcome == Outcome.REUSE
    assert group_action.auto_created is True
    assert group_action.resolved_name == "Prod"
    assert group_action.resolved_uid == "uid-Prod"
    assert host_action.depends_on == [group_action.id]


@pytest.mark.asyncio
async def test_existing_group_membership_reports_reuse():
    """Plan spec's own example: a host's `data.groups` referencing an already-existing
    network-group must produce exactly one REUSE action for that group."""
    reader = FakeReader(group_names={"G1"})
    template = {
        "management_servers": [
            {
                "mgmt_name": "m",
                "domains": [
                    {
                        "name": "d",
                        "operations": [
                            {
                                "operation": "add",
                                "type": "host",
                                "data": {"name": "h1", "ip-address": "10.0.0.1", "groups": ["G1"]},
                            },
                        ],
                    }
                ],
            }
        ],
    }
    plan = await Planner(reader).decide(template)
    reuse = [a for a in plan.actions if a.outcome == Outcome.REUSE and a.type == "network-group"]
    assert len(reuse) == 1 and reuse[0].resolved_name == "G1" and reuse[0].auto_created


@pytest.mark.asyncio
async def test_reuse_actions_deduped_across_rules():
    """Two rules referencing the same already-existing IP must collapse to exactly ONE
    REUSE action for that host, not one per rule."""
    existing = ObjectState(uid="u1", name="Host_10.1.2.3", type="host", raw={})
    reader = FakeReader(by_ip=[existing])
    doc = _doc(
        {
            "type": "access-rule",
            "layer": "Network",
            "position": "bottom",
            "data": {
                "name": "r1",
                "source": ["10.1.2.3"],
                "destination": ["any"],
                "service": ["any"],
                "action": "accept",
            },
        },
        {
            "type": "access-rule",
            "layer": "Network",
            "position": "bottom",
            "data": {
                "name": "r2",
                "source": ["10.1.2.3"],
                "destination": ["any"],
                "service": ["any"],
                "action": "accept",
            },
        },
    )
    plan = await Planner(reader).decide(doc)
    reuse = [a for a in plan.actions if a.outcome == Outcome.REUSE and a.type == "host"]
    assert len(reuse) == 1


@pytest.mark.asyncio
async def test_decide_orders_services_after_groups_and_before_service_groups():
    reader = FakeReader()
    doc = _doc(
        {"type": "service-group", "data": {"name": "SG1", "members": ["TCP_80"]}},
        {"type": "network-group", "data": {"name": "G1"}},
        {"type": "tcp-service", "data": {"name": "TCP_80", "port": "80"}},
        {"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.1"}},
    )
    plan = await Planner(reader).decide(doc)
    types_in_order = [a.type for a in _actions_for(plan, "m1", "General")]
    assert types_in_order.index("host") < types_in_order.index("network-group")
    assert types_in_order.index("network-group") < types_in_order.index("tcp-service")
    assert types_in_order.index("tcp-service") < types_in_order.index("service-group")


@pytest.mark.asyncio
async def test_decide_orders_deletes_in_exact_reverse():
    reader = FakeReader()
    doc = _doc(
        {"operation": "delete", "type": "host", "key": {"name": "h1"}},
        {"operation": "delete", "type": "network-group", "key": {"name": "G1"}},
        {"operation": "delete", "type": "tcp-service", "key": {"name": "TCP_80"}},
        {"operation": "delete", "type": "service-group", "key": {"name": "SG1"}},
    )
    plan = await Planner(reader).decide(doc)
    types_in_order = [a.type for a in _actions_for(plan, "m1", "General")]
    assert types_in_order == ["service-group", "tcp-service", "network-group", "host"]


# ---------------------------------------------------------------------------
# Task 13: rule dispatch (add -> resolve_rule/resolve_nat_rule; update/delete/show -> by-key)
# and rule tier ordering (tier 4, final).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_decide_orders_rules_after_service_groups():
    reader = FakeReader()  # rule ops hit the FakeReader defaults: get_layer/find_rules_by_traffic/get_last_rule
    doc = _doc(
        {
            "type": "access-rule",
            "layer": "Network",
            "position": "bottom",
            "data": {"name": "r1", "source": ["any"], "destination": ["any"], "service": ["any"], "action": "accept"},
        },
        {"type": "service-group", "data": {"name": "SG1", "members": ["TCP_80"]}},
        {"type": "tcp-service", "data": {"name": "TCP_80", "port": "80"}},
        {"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.1"}},
    )
    plan = await Planner(reader).decide(doc)
    types_in_order = [a.type for a in _actions_for(plan, "m1", "General")]
    assert types_in_order.index("host") < types_in_order.index("tcp-service")
    assert types_in_order.index("tcp-service") < types_in_order.index("service-group")
    assert types_in_order.index("service-group") < types_in_order.index("access-rule")


@pytest.mark.asyncio
async def test_decide_dispatches_add_for_all_four_rule_types():
    reader = FakeReader()
    doc = _doc(
        {
            "type": "access-rule",
            "layer": "Network",
            "position": "bottom",
            "data": {"name": "r1", "source": ["any"], "destination": ["any"], "service": ["any"], "action": "accept"},
        },
        {
            "type": "threat-prevention-rule",
            "layer": "Threat Layer",
            "position": "bottom",
            "data": {"name": "t1", "source": ["any"], "destination": ["any"], "service": ["any"], "action": "prevent"},
        },
        {
            "type": "https-rule",
            "layer": "HTTPS Layer",
            "position": "bottom",
            "data": {
                "name": "h1rule",
                "source": ["any"],
                "destination": ["any"],
                "service": ["any"],
                "action": "inspect",
            },
        },
        {
            "type": "nat-rule",
            "package": "Standard",
            "position": "bottom",
            "data": {
                "name": "n1",
                "source": ["any"],
                "destination": ["any"],
                "service": ["any"],
                "method": "hide",
                "translated-source": "any",
                "translated-destination": "any",
                "translated-service": "any",
            },
        },
    )
    plan = await Planner(reader).decide(doc)
    actions = {a.type: a for a in _actions_for(plan, "m1", "General")}
    assert actions["access-rule"].command == "add-access-rule"
    assert actions["threat-prevention-rule"].command == "add-threat-rule"
    assert actions["https-rule"].command == "add-https-rule"
    assert actions["nat-rule"].command == "add-nat-rule"
    assert all(a.outcome == Outcome.CREATE for a in actions.values())


@pytest.mark.asyncio
async def test_decide_dispatches_rule_update_by_key_and_carries_layer():
    class Reader(FakeReader):
        async def get_layer(self, layer_ref, layer_type, *, mgmt, domain):
            from arodonata.cpcrud.models import LayerInfo

            return LayerInfo(uid="layer-u1", name=layer_ref, type=layer_type)

        async def get_rule_by_key(self, scope_uid, layer_type, key, *, mgmt, domain):
            from arodonata.cpcrud.models import RuleMatch

            return RuleMatch(
                uid="r1", name="Allow-Web", rule_number=1, raw={"uid": "r1", "name": "Allow-Web", "comments": "old"}
            )

    reader = Reader()
    doc = _doc(
        {
            "type": "access-rule",
            "operation": "update",
            "layer": "Network",
            "key": {"name": "Allow-Web"},
            "data": {"comments": "new"},
        }
    )
    plan = await Planner(reader).decide(doc)
    action = _actions_for(plan, "m1", "General")[0]
    assert action.outcome == Outcome.UPDATE
    assert action.command == "set-access-rule"
    assert action.payload["uid"] == "r1"
    assert action.payload["layer"] == "Network"
    assert action.payload["comments"] == "new"


@pytest.mark.asyncio
async def test_decide_dispatches_nat_rule_delete_by_key_and_carries_package():
    class Reader(FakeReader):
        async def get_nat_rule_by_key(self, package, key, *, mgmt, domain):
            from arodonata.cpcrud.models import RuleMatch

            return RuleMatch(uid="n1", name="hide-nat", rule_number=1, raw={"uid": "n1", "name": "hide-nat"})

    reader = Reader()
    doc = _doc({"type": "nat-rule", "operation": "delete", "package": "Standard", "key": {"name": "hide-nat"}})
    plan = await Planner(reader).decide(doc)
    action = _actions_for(plan, "m1", "General")[0]
    assert action.outcome == Outcome.DELETE
    assert action.command == "delete-nat-rule"
    assert action.payload["uid"] == "n1"
    assert action.payload["package"] == "Standard"


@pytest.mark.asyncio
async def test_decide_dispatches_rule_show_by_key_not_found_is_error():
    reader = FakeReader()  # get_rule_by_key default returns None
    doc = _doc({"type": "access-rule", "operation": "show", "layer": "Network", "key": {"name": "gone"}})
    plan = await Planner(reader).decide(doc)
    action = _actions_for(plan, "m1", "General")[0]
    assert action.outcome == Outcome.ERROR
    assert action.message == "rule not found"


@pytest.mark.asyncio
async def test_decide_orders_rule_deletes_before_service_group_deletes():
    """Rules are tier 4 (final); reverse-delete order therefore deletes them FIRST."""

    class Reader(FakeReader):
        async def get_rule_by_key(self, scope_uid, layer_type, key, *, mgmt, domain):
            return None  # idempotent delete-when-absent; order is what's under test here

    reader = Reader()
    doc = _doc(
        {"operation": "delete", "type": "service-group", "key": {"name": "SG1"}},
        {"operation": "delete", "type": "access-rule", "layer": "Network", "key": {"name": "r1"}},
    )
    plan = await Planner(reader).decide(doc)
    types_in_order = [a.type for a in _actions_for(plan, "m1", "General")]
    assert types_in_order.index("access-rule") < types_in_order.index("service-group")


# ---------------------------------------------------------------------------
# Task 4: Planner builds NamingPrefixes from settings and threads them into every
# rule-resolver call in decide().
# ---------------------------------------------------------------------------


def test_planner_init_defaults_prefixes_with_no_settings():
    planner = Planner(FakeReader(), settings=None)
    assert planner._prefixes is DEFAULT_PREFIXES


def test_planner_init_builds_prefixes_from_settings():
    class S:
        cpcrud_auto_name_prefix_host = "H-"
        cpcrud_auto_name_prefix_network = "N-"
        cpcrud_auto_name_prefix_range = "R-"
        cpcrud_auto_name_prefix_svc_tcp = "T-"
        cpcrud_auto_name_prefix_svc_udp = "U-"
        cpcrud_auto_name_prefix_svc_icmp = "I-"

    planner = Planner(FakeReader(), settings=S())
    assert planner._prefixes == NamingPrefixes(
        host="H-", network="N-", range="R-", svc_tcp="T-", svc_udp="U-", svc_icmp="I-"
    )


@pytest.mark.asyncio
async def test_decide_uses_custom_prefixes_for_rule_add_synthesized_deps():
    """A bare-IP reference inside an access-rule's source, resolved through resolve_rule via
    decide(), must be synthesized using the settings-derived prefixes -- proving Planner
    actually passes `prefixes=self._prefixes` into the resolver, not just building it."""

    class S:
        cpcrud_auto_name_prefix_host = "H-"
        cpcrud_auto_name_prefix_network = "Net_"
        cpcrud_auto_name_prefix_range = "IPR_"
        cpcrud_auto_name_prefix_svc_tcp = "TCP_"
        cpcrud_auto_name_prefix_svc_udp = "UDP_"
        cpcrud_auto_name_prefix_svc_icmp = "ICMP_"

    reader = FakeReader()
    doc = _doc(
        {
            "type": "access-rule",
            "layer": "Network",
            "position": "bottom",
            "data": {
                "name": "r1",
                "source": ["10.0.0.9"],
                "destination": ["any"],
                "service": ["any"],
                "action": "accept",
            },
        }
    )
    plan = await Planner(reader, settings=S()).decide(doc)
    host_dep = next(a for a in plan.actions if a.type == "host")
    assert host_dep.resolved_name == "H-10.0.0.9"


@pytest.mark.asyncio
async def test_decide_default_prefixes_unchanged_for_rule_add_synthesized_deps():
    reader = FakeReader()
    doc = _doc(
        {
            "type": "access-rule",
            "layer": "Network",
            "position": "bottom",
            "data": {
                "name": "r1",
                "source": ["10.0.0.9"],
                "destination": ["any"],
                "service": ["any"],
                "action": "accept",
            },
        }
    )
    plan = await Planner(reader).decide(doc)
    host_dep = next(a for a in plan.actions if a.type == "host")
    assert host_dep.resolved_name == "Host_10.0.0.9"


# ---------------------------------------------------------------------------
# Backlog #37: a failed lookup plans nothing for its operation
# ---------------------------------------------------------------------------


class _FailingReader(FakeReader):
    """find_by_ip fails for 10.0.0.1 and find_rules_by_traffic always fails, as failed listings do."""

    async def find_by_ip(self, *, type, ip_value, mgmt, domain):
        if "10.0.0.1" in ip_value.values():
            raise StateReadError("show-objects failed: generic_err: timeout")
        return await super().find_by_ip(type=type, ip_value=ip_value, mgmt=mgmt, domain=domain)

    async def find_rules_by_traffic(self, scope_uid, layer_type, source_uids, dest_uids, service_uids, *, mgmt, domain):
        raise StateReadError("show-access-rulebase failed at offset 50: generic_err: timeout")


@pytest.mark.asyncio
async def test_failed_lookup_plans_no_group_for_the_failed_object():
    plan = await Planner(_FailingReader()).decide(
        _doc({"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.1", "groups": ["g-new"]}})
    )
    actions = _actions_for(plan, "m1", "General")
    assert [(a.type, a.outcome) for a in actions] == [("host", Outcome.ERROR)]
    assert actions[0].depends_on == []


@pytest.mark.asyncio
async def test_failed_rulebase_read_drops_the_rule_dependencies_already_planned():
    plan = await Planner(_FailingReader()).decide(
        _doc(
            {
                "type": "access-rule",
                "layer": "Network",
                "position": "bottom",
                "data": {"name": "r1", "source": ["10.0.0.2"], "destination": ["any"], "service": ["any"]},
            },
            {"type": "host", "data": {"name": "h3", "ip-address": "10.0.0.3"}},
        )
    )
    actions = _actions_for(plan, "m1", "General")
    # Hosts sort before rules; the rule's auto-created host for 10.0.0.2 is not planned.
    assert sorted((a.id, a.type, a.outcome) for a in actions) == [
        ("act-0001", "host", Outcome.CREATE),
        ("act-0002", "access-rule", Outcome.ERROR),
    ]
    rule = next(a for a in actions if a.type == "access-rule")
    assert rule.message.startswith("lookup failed, nothing planned (re-plan to retry):")
    assert "offset 50" in rule.message


@pytest.mark.asyncio
async def test_failed_lookup_names_a_rule_addressed_by_rule_number():
    plan = await Planner(_FailingReader()).decide(
        _doc(
            {
                "operation": "update",
                "type": "access-rule",
                "layer": "Network",
                "key": {"rule-number": 7},
                "data": {"source": ["10.0.0.1"]},
            }
        )
    )
    (action,) = _actions_for(plan, "m1", "General")
    assert action.outcome == Outcome.ERROR
    assert action.resolved_name == "7"


class _FailingNameReader(FakeReader):
    """get_by_name fails for "h-bad" and the group "g-bad", as a failed show-<type> does."""

    async def get_by_name(self, type, name, *, mgmt, domain):
        if name in ("h-bad", "g-bad"):
            raise StateReadError(f"show-{type} failed: generic_err: timeout")
        return await super().get_by_name(type, name, mgmt=mgmt, domain=domain)


@pytest.mark.asyncio
async def test_failed_name_lookup_on_delete_is_an_error_not_already_absent():
    plan = await Planner(_FailingNameReader()).decide(
        _doc({"operation": "delete", "type": "host", "key": {"name": "h-bad"}})
    )
    (action,) = _actions_for(plan, "m1", "General")
    assert action.outcome == Outcome.ERROR
    assert action.command is None


@pytest.mark.asyncio
async def test_failed_group_lookup_stops_the_object_that_names_the_group():
    plan = await Planner(_FailingNameReader()).decide(
        _doc(
            {"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.5", "groups": ["g-bad"]}},
            {"type": "host", "data": {"name": "h2", "ip-address": "10.0.0.6"}},
        )
    )
    by_name = {a.resolved_name: a for a in _actions_for(plan, "m1", "General")}
    assert set(by_name) == {"h1", "h2"}  # no group action for g-bad
    assert by_name["h1"].outcome == Outcome.ERROR
    assert by_name["h1"].command is None and by_name["h1"].payload is None
    assert "g-bad" in by_name["h1"].message and "show-network-group failed" in by_name["h1"].message
    assert by_name["h2"].outcome == Outcome.CREATE


@pytest.mark.asyncio
async def test_failed_lookup_of_a_second_group_keeps_no_group_planned_for_the_object():
    plan = await Planner(_FailingNameReader()).decide(
        _doc({"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.5", "groups": ["g-new", "g-bad"]}})
    )
    actions = _actions_for(plan, "m1", "General")
    assert [(a.type, a.outcome) for a in actions] == [("host", Outcome.ERROR)]


@pytest.mark.asyncio
async def test_unreadable_head_plans_nothing_for_that_domain():
    """Backlog #39: a plan without a publish stamp cannot be checked for staleness at apply."""

    class Reader(FakeReader):
        async def get_last_publish_session(self, *, mgmt, domain):
            if domain == "Bad":
                raise StateReadError("could not read the last published session of m1/Bad")
            return "sess-ok"

    doc = {
        "management_servers": [
            {
                "mgmt_name": "m1",
                "domains": [
                    {"name": "Bad", "operations": [{"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.1"}}]},
                    {
                        "name": "Good",
                        "operations": [{"type": "host", "data": {"name": "h2", "ip-address": "10.0.0.2"}}],
                    },
                ],
            }
        ]
    }
    plan = await Planner(Reader()).decide(doc)

    (bad,) = _actions_for(plan, "m1", "Bad")
    assert bad.outcome == Outcome.ERROR and bad.command is None and bad.payload is None
    assert "could not read the last published session" in bad.message
    assert [a.outcome for a in _actions_for(plan, "m1", "Good")] == [Outcome.CREATE]
    assert plan.stamps == [DomainStamp(mgmt_name="m1", domain_name="Good", last_publish_session="sess-ok")]


@pytest.mark.asyncio
async def test_head_is_read_before_the_domain_lookups():
    """A publish while the domain is being planned must leave the plan stale: the stamp predates every lookup."""
    calls: list[str] = []

    class Reader(FakeReader):
        async def get_last_publish_session(self, *, mgmt, domain):
            calls.append("head")
            return "sess-1"

        async def get_by_name(self, type, name, *, mgmt, domain):
            calls.append("get_by_name")
            return await super().get_by_name(type, name, mgmt=mgmt, domain=domain)

        async def find_by_ip(self, *, type, ip_value, mgmt, domain):
            calls.append("find_by_ip")
            return await super().find_by_ip(type=type, ip_value=ip_value, mgmt=mgmt, domain=domain)

    await Planner(Reader()).decide(_doc({"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.1"}}))
    assert calls[0] == "head"
    assert calls.count("head") == 1


@pytest.mark.asyncio
async def test_unreadable_head_skips_the_domain_lookups():
    class Reader(FakeReader):
        async def get_last_publish_session(self, *, mgmt, domain):
            raise StateReadError("could not read the last published session of m1/General")

        async def get_by_name(self, type, name, *, mgmt, domain):
            raise AssertionError("no lookup may run without a stamp")

    plan = await Planner(Reader()).decide(
        _doc(
            {"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.1"}},
            {"operation": "update", "type": "host", "key": {"name": "h2"}, "data": {}},
        )
    )
    actions = _actions_for(plan, "m1", "General")
    assert sorted((a.id, a.resolved_name, a.outcome) for a in actions) == [
        ("act-0001", "h1", Outcome.ERROR),
        ("act-0002", "h2", Outcome.ERROR),
    ]
    assert all("could not read the last published session" in a.message for a in actions)
    assert plan.stamps == []


@pytest.mark.asyncio
async def test_two_rules_at_a_sections_bottom_anchor_on_its_cleanup_rule_not_its_number():
    """Backlog #40 review: a rule number planned per rule goes stale once the first add shifts it (the second rule
    would land above the first); both anchor on the cleanup rule, so they keep the template's order."""
    from arodonata.cpcrud.models import RuleMatch, SectionInfo

    cleanup = RuleMatch(
        uid="r-cleanup",
        name="Cleanup rule",
        rule_number=6,
        raw={"source": [{"name": "Any"}], "destination": [{"name": "Any"}], "service": [{"name": "Any"}]},
    )

    class Reader(FakeReader):
        async def get_section(self, section_ref, layer_uid, layer_type, *, mgmt, domain):
            return SectionInfo(uid="s-cleanup", name=section_ref, layer_uid=layer_uid)

        async def get_last_rule_in_section(self, layer_uid, section_uid, layer_type, *, mgmt, domain):
            return cleanup

    def rule(name, source):
        return {
            "type": "access-rule",
            "layer": "Network",
            "position": {"bottom": "Cleanup"},
            "data": {"name": name, "source": [source], "destination": ["any"], "service": ["any"]},
        }

    plan = await Planner(Reader()).decide(_doc(rule("r-a", "10.0.0.11"), rule("r-b", "10.0.0.12")))
    rules = [a for a in _actions_for(plan, "m1", "General") if a.type == "access-rule"]
    assert [r.payload["position"] for r in rules] == [{"above": "r-cleanup"}, {"above": "r-cleanup"}]
    assert [r.resolved_name for r in rules] == ["r-a", "r-b"]
