"""Lab-free tests for lab_build.py's planning step.

`plan()` compares the wanted lab (plain data in lab_build.py) with what the
MDS reports and returns the actions still needed. It is the only part with
real logic, so it is where "idempotent" is proven: a fully built lab plans
nothing, and nothing that exists is ever planned again.
"""

from __future__ import annotations

from tests.integration.lab_build import (
    ADMINS,
    DOMAIN_NAMES,
    EXTRAS,
    Actual,
    plan,
    wanted_domains,
)

DOMAINS = wanted_domains("mds-b", "10.0.0.181")


def _built() -> Actual:
    """The state lab_build is meant to produce."""
    return Actual(
        domains={d.name: {d.server_ip} for d in DOMAINS},
        admins={a.name for a in ADMINS} | {"admin", "AntonR", "auto"},
        objects={domain: {obj.name for obj in objs} for domain, objs in EXTRAS.items()},
    )


def test_a_fully_built_lab_plans_nothing():
    assert plan(_built(), DOMAINS) == []


def test_an_empty_mds_plans_every_domain_admin_and_extra():
    actions = plan(Actual(domains={}, admins={"admin", "AntonR", "auto"}, objects={}), DOMAINS)

    kinds = [a.command for a in actions]
    assert kinds.count("add-domain") == len(DOMAINS)
    assert kinds.count("add-administrator") == len(ADMINS)
    assert sum(len(objs) for objs in EXTRAS.values()) == len([a for a in actions if a.domain])


def test_domains_come_first_then_admins_then_extras():
    """Extras live inside domains, so a domain must exist before its objects are planned to run."""
    actions = plan(Actual(domains={}, admins=set(), objects={}), DOMAINS)

    order = [a.command for a in actions]
    last_domain = max(i for i, c in enumerate(order) if c == "add-domain")
    first_extra = min(i for i, a in enumerate(actions) if a.domain)
    assert last_domain < first_extra
    assert all(c == "add-administrator" for c in order[last_domain + 1 : first_extra])


def test_only_missing_pieces_are_planned():
    actual = _built()
    actual.domains.pop("Domain5")
    actual.objects.pop("Domain5", None)
    actual.admins.discard("eng3")
    actual.objects["General"].discard("crud-host-2")

    planned = {(a.command, a.domain, a.name) for a in plan(actual, DOMAINS)}

    assert ("add-domain", "", "Domain5") in planned
    assert ("add-administrator", "", "eng3") in planned
    assert ("add-host", "General", "crud-host-2") in planned
    assert ("add-simple-gateway", "Domain5", "fakegwD5") in planned
    assert len(planned) == 4


def test_a_domain_whose_server_is_elsewhere_is_reported_not_recreated():
    """The user may move a domain's active server to another member later; that is not ours to undo."""
    actual = _built()
    actual.domains["Domain2"] = {"10.0.0.152"}

    actions = plan(actual, DOMAINS)

    assert not [a for a in actions if a.command == "add-domain"]
    notes = [a for a in actions if a.command == "note"]
    assert notes and "Domain2" in notes[0].name


def test_domains_sit_on_the_given_member_at_consecutive_addresses():
    assert [d.server_ip for d in DOMAINS] == [f"10.0.0.{n}" for n in range(181, 186)]
    assert {d.mds for d in DOMAINS} == {"mds-b"}
    assert [d.name for d in DOMAINS] == DOMAIN_NAMES == ["General", "Domain2", "Domain3", "Domain4", "Domain5"]


def test_admin_passwords_are_referenced_by_env_var_never_stored():
    assert [a.password_env for a in ADMINS] == ["USER_Eng1", "USER_Eng2", "USER_Eng3", "USER_Eng4"]
    payload = plan(Actual(domains={}, admins=set(), objects={}), DOMAINS)
    assert all("password" not in a.payload for a in payload if a.command == "add-administrator")


def test_active_ip_is_optional_so_planning_never_depends_on_it():
    """`active_ip` only routes logins; plan() must work without it."""
    actual = _built()
    assert actual.active_ip == {}
    assert plan(actual, DOMAINS) == []
