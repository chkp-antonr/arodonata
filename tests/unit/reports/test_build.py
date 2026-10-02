from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from arodonata.reports.changes.build import build_session, classify
from arodonata.reports.changes.model import FieldChange, NamedRef
from tests.unit.reports.entries import (
    ACCEPT,
    DROP,
    access_rule,
    created,
    entry,
    group,
    host,
    https_rule,
    modified,
    nat_rule,
    ref,
    section,
    session_meta,
    threat_rule,
)
from tests.unit.reports.trim_changes import _bodies, load_changes

H1, H2, H3 = ref("h1", "web-1"), ref("h2", "web-2"), ref("h3", "web-3")


def one(*, added=(), mods=(), deleted=(), published=True):
    return build_session(entry(session_meta("s1", published=published), added=added, modified=mods, deleted=deleted))


def rule(session, uid="r1"):
    return next(r for r in session.rules if r.uid == uid)


def by_uid(items, uid):
    return next(i for i in items if i.uid == uid)


def test_unpublished_session_added_hosts_group_rule_and_deleted_host():
    s = build_session(load_changes("w_A_own_sid_0.json")[0])
    assert (s.published, s.published_at, s.name, s.user_name) == (False, None, "arod-probe-A", "admin")
    assert sorted((o.type, o.name, o.status) for o in s.objects) == [
        ("group", "arod-probe-g1", "added"),
        ("host", "arod-probe-h0", "deleted"),
        ("host", "arod-probe-h1", "added"),
        ("host", "arod-probe-h2", "added"),
    ]
    assert all(o.key_value.startswith("192.0.2.") for o in s.objects if o.type == "host")
    [r] = s.rules
    assert (r.rulebase, r.status, r.name, r.position) == ("access", "added", "arod-probe-r1", 1)
    assert [i.name for i in r.cells["source"].items or []] == ["arod-probe-h1"]
    assert r.cells["comments"].text == "edited in same session"


def test_published_session_same_changes_after_publish():
    before = build_session(load_changes("w_A_own_sid_0.json")[0])
    after = build_session(load_changes("w_A_after_publish_0.json")[0])
    assert after.uid == before.uid and after.published is True
    assert after.published_at == datetime(2026, 10, 1, 6, 19, 18, 610000, tzinfo=UTC)
    key = lambda s: sorted((x.uid, x.status) for x in [*s.rules, *s.objects])  # noqa: E731
    assert key(after) == key(before)


def test_modified_without_old_object_is_added():
    s = one(mods=[created(access_rule("r1", "new", layer="L", position=1))])
    assert rule(s).status == "added" and rule(s).changes == []
    recorded = load_changes("to_mid_full.json")[0]
    created_uids = {
        m["new-object"]["uid"]
        for m in recorded["operations"]["modified-objects"]
        if "old-object" not in m and classify(m["new-object"]["type"]) == "rule"
    }
    s = build_session(recorded)
    assert created_uids and all(rule(s, uid).status == "added" for uid in created_uids)
    assert any(r.rulebase == "threat" for r in s.rules)


def test_section_rename_old_and_new_names():
    s = one(mods=[modified(section("sec", "Old name"), section("sec", "New name"))])
    [sec] = s.sections
    assert (sec.category, sec.status, sec.name) == ("section", "modified", "New name")
    assert sec.changes == [FieldChange(field="name", old="Old name", new="New name")]
    recorded = build_session(load_changes("noparams.json")[0])
    assert len(recorded.sections) == 10 and {x.status for x in recorded.sections} == {"modified"}


def test_internal_camelcase_types_hidden_and_counted():
    s = build_session(load_changes("d4_assign_session_changes.json")[0])
    assert sorted(o.type for o in s.internal) == ["AccessPolicy"] * 5 + [
        "AccessPolicyAssignment",
        "ThreatBladeAssignment",
    ]
    assert all(o.internal and o.category == "other" for o in s.internal)
    assert all(not o.type[:1].isupper() for o in [*s.objects, *s.other])


def test_kebab_unlisted_type_goes_to_other():
    s = build_session(load_changes("d4_assign_session_changes.json")[0])
    assert [(o.type, o.status, o.internal) for o in s.other] == [("app-control-advanced-settings", "modified", False)]


def test_net_zero_session_has_no_visible_changes():
    s = one()
    assert (s.rules, s.objects, s.sections, s.other, s.internal) == ([], [], [], [], [])


def test_list_cell_compares_by_uid():
    old = access_rule("r1", "a", layer="L", source=[ref("h1", "old-name")])
    new = access_rule("r1", "a", layer="L", source=[ref("h1", "new-name"), H2])
    cell = rule(one(mods=[modified(old, new)])).cells["source"]
    assert [(i.uid, i.name, i.status) for i in cell.items or []] == [
        ("h1", "new-name", "unchanged"),
        ("h2", "web-2", "added"),
    ]
    assert cell.changed and not cell.default


def test_unchanged_item_modified_in_session_is_modified():
    r_old = access_rule("r1", "a", layer="L", source=[H1], comments="x")
    r_new = access_rule("r1", "a", layer="L", source=[H1], comments="y")
    s = one(
        mods=[modified(r_old, r_new), modified(host("h1", "web-1"), host("h1", "web-1", ip="192.0.2.99"))],
        added=[access_rule("r2", "b", layer="L", position=2, destination=[H1])],
    )
    item = (rule(s).cells["source"].items or [])[0]
    assert (item.status, item.anchor) == ("modified", "o-s1-h1")
    assert (rule(s, "r2").cells["destination"].items or [])[0].status == "modified"
    assert not rule(s).cells["source"].changed


def test_scalar_change_marks_cell_changed():
    old = access_rule("r1", "a", layer="L", action=ACCEPT, comments="x")
    new = access_rule("r1", "a", layer="L", action=DROP, comments="y")
    r = rule(one(mods=[modified(old, new)]))
    assert (r.cells["action"].text, r.cells["action"].changed) == ("Drop", True)
    assert (r.cells["comments"].text, r.cells["comments"].changed) == ("y", True)
    assert r.changes == [
        FieldChange(field="action", old="Accept", new="Drop"),
        FieldChange(field="comments", old="x", new="y"),
    ]


def test_negation_change_marks_cell():
    old = access_rule("r1", "a", layer="L", source=[H1])
    new = access_rule("r1", "a", layer="L", source=[H1], **{"source-negate": True})
    r = rule(one(mods=[modified(old, new)]))
    assert r.cells["source"].negated and r.cells["source"].changed
    assert r.changes == [FieldChange(field="source-negate", old="false", new="true")]


def test_enabled_only_change_is_modified_with_detail():
    old = access_rule("r1", "a", layer="L")
    r = rule(one(mods=[modified(old, {**old, "enabled": False})]))
    assert (r.status, r.enabled, r.enabled_changed) == ("modified", False, True)
    assert r.changes == [FieldChange(field="enabled", old="true", new="false")]
    assert not any(c.changed for c in r.cells.values())


def test_created_and_disabled_rule_is_added_disabled():
    r = rule(one(added=[access_rule("r1", "a", layer="L", position=1, enabled=False)]))
    assert (r.status, r.enabled, r.enabled_changed) == ("added", False, False)


def test_deleted_rule_keeps_pre_session_cells():
    r = rule(one(deleted=[access_rule("r1", "gone", layer="L", position=4, source=[H1], comments="pre")]))
    assert (r.status, r.name, r.old_layer_uid, r.old_position) == ("deleted", "gone", "L", 4)
    assert [(i.uid, i.status) for i in r.cells["source"].items or []] == [("h1", "unchanged")]
    assert (r.cells["comments"].text, r.cells["comments"].changed) == ("pre", False)


def _mod(
    uid: str, old_pos: int | None = None, new_pos: int | None = None, *, old_layer: str = "L", new_layer: str = "L"
) -> dict[str, Any]:
    """A modified rule as CP sends it: positions only when the session moved it (F1)."""
    return modified(
        access_rule(uid, uid, layer=old_layer, position=old_pos, comments="a"),
        access_rule(uid, uid, layer=new_layer, position=new_pos, comments="b"),
    )


def test_moved_rule_flags_layer_or_position_change():
    s = one(mods=[_mod("y", 2, 5), _mod("z", new_layer="L2"), _mod("u")])
    assert rule(s, "y").moved and rule(s, "z").moved and not rule(s, "u").moved
    assert (rule(s, "y").old_position, rule(s, "y").position) == (2, 5)


def test_section_move_with_equal_positions_is_moved():
    # R1: a rule moved from the top of one section to the top of another: old 1 -> new 1, both present
    assert rule(one(mods=[_mod("y", 1, 1)]), "y").moved


def test_insert_above_modified_rule_not_moved():
    s = one(added=[access_rule("x", "x", layer="L", position=1)], mods=[_mod("y")])
    assert not rule(s, "y").moved


def test_delete_above_modified_rule_not_moved():
    s = one(deleted=[access_rule("x", "x", layer="L", position=1)], mods=[_mod("y")])
    assert not rule(s, "y").moved


def test_intra_layer_move_of_other_rule_not_moved():
    s = one(mods=[_mod("x", 1, 5), _mod("y")])
    assert rule(s, "x").moved and not rule(s, "y").moved


def test_duplicate_modified_entries_deduped():
    # R1 (F3): a moved rule appears twice in modified-objects, byte-identical
    twice = _mod("y", 2, 1)
    s = one(mods=[twice, twice])
    assert [r.uid for r in s.rules] == ["y"]


def test_group_member_delta():
    s = one(mods=[modified(group("g1", "grp", ["h1", "h2"]), group("g1", "grp", ["h2", "h3"]))])
    [g] = s.objects
    assert g.changes == [
        FieldChange(field="members", removed=[NamedRef(uid="h1", name="h1")], added=[NamedRef(uid="h3", name="h3")])
    ]


def test_members_delta_for_other_category_type():
    old = {"uid": "t1", "name": "tg", "type": "time-group", "members": ["a"], "comments": ""}
    [o] = one(mods=[modified(old, {**old, "members": ["a", "b"]})]).other
    assert o.category == "other"
    assert o.changes == [FieldChange(field="members", added=[NamedRef(uid="b", name="b")])]
    assert o.other_fields == []


def test_object_key_values():
    s = one(
        added=[
            host("h", "h", ip="192.0.2.5"),
            {"uid": "n", "name": "n", "type": "network", "subnet4": "198.51.100.0", "mask-length4": 24},
            {
                "uid": "r",
                "name": "r",
                "type": "address-range",
                "ipv4-address-first": "192.0.2.1",
                "ipv4-address-last": "192.0.2.9",
            },
            {"uid": "t", "name": "t", "type": "service-tcp", "port": "8443"},
            {"uid": "i", "name": "i", "type": "service-icmp", "icmp-type": 8},
            group("g", "g"),
        ]
    )
    assert {o.uid: o.key_value for o in s.objects} == {
        "h": "192.0.2.5",
        "n": "198.51.100.0/24",
        "r": "192.0.2.1 - 192.0.2.9",
        "t": "8443",
        "i": "8",
        "g": "",
    }


def test_unknown_type_compares_top_level_scalars_except_ignored():
    old = {
        "uid": "u",
        "name": "n",
        "type": "foo-bar",
        "x": 1,
        "icon": "a",
        "read-only": False,
        "meta-info": {"last-modify-time": 1},
        "domain": {"uid": "d1"},
    }
    new = {**old, "x": 2, "icon": "b", "read-only": True, "meta-info": {"last-modify-time": 2}, "domain": {"uid": "d2"}}
    [o] = one(mods=[modified(old, new)]).other
    assert (o.changes, o.other_fields) == ([FieldChange(field="x", old="1", new="2")], [])


def test_modified_outside_allowlist_lists_other_fields():
    old = access_rule("r1", "a", layer="L")
    new = {
        **old,
        "custom-fields": {"field-1": "RITM1", "field-2": "", "field-3": ""},
        "tags": [ref("t1", "tag", "tag")],
    }
    r = rule(one(mods=[modified(old, new)]))
    assert r.changes == [FieldChange(field="custom-fields.field-1", old="", new="RITM1")]
    assert r.other_fields == ["tags"]


def test_host_nat_settings_change_reported():
    old = host("h4", "nat-host")
    new = {**old, "nat-settings": {"auto-rule": True, "method": "static", "ipv4-address": "192.0.2.44"}}
    [o] = one(mods=[modified(old, new)]).objects
    assert {(c.field, c.old, c.new) for c in o.changes} == {
        ("nat-settings.auto-rule", "false", "true"),
        ("nat-settings.method", "", "static"),
        ("nat-settings.ipv4-address", "", "192.0.2.44"),
    }


def test_modified_with_no_differing_field_says_so():
    old = host("h1", "web-1", **{"meta-info": {"last-modify-time": 1}})
    [o] = one(mods=[modified(old, {**old, "meta-info": {"last-modify-time": 2}})]).objects
    assert (o.status, o.changes, o.other_fields) == ("modified", [], [])


def test_threat_rule_without_name():
    r = rule(one(added=[threat_rule("t1", layer="T", position=1)]), "t1")
    assert (r.rulebase, r.name) == ("threat", "")


def test_rule_referencing_modified_object_not_reported():
    s = one(mods=[modified(host("h1", "web-1"), host("h1", "web-1", ip="192.0.2.99"))])
    assert s.rules == [] and [o.uid for o in s.objects] == ["h1"]


def test_nat_and_https_rules_classified():
    s = one(added=[nat_rule("n1", "nat", layer="N", position=1), https_rule("x1", "https", layer="H", position=1)])
    assert {r.uid: r.rulebase for r in s.rules} == {"n1": "nat", "x1": "https"}
    assert rule(s, "n1").cells["translated-source"].default


BUILDERS = {
    "access-rule": lambda: access_rule("u", "n", layer="L", position=1),
    "threat-rule": lambda: threat_rule("u", layer="L", position=1, name="n"),
    "nat-rule": lambda: nat_rule("u", "n", layer="L", position=1),
    "https-rule": lambda: https_rule("u", "n", layer="L", position=1),
}


@pytest.mark.parametrize("rule_type", sorted(BUILDERS))
def test_builder_shapes_match_r1_recordings(rule_type):
    recorded = [b for b in _bodies(json_fixture("r1_modified_rules_published.json")) if b.get("type") == rule_type]
    if not recorded:
        pytest.skip(f"R1 recorded no {rule_type} (see the Task 1 findings)")
    keys = set().union(*(set(b) for b in recorded)) - {"domain"}
    always = {k for k in keys if all(k in b for b in recorded)}
    built = set(BUILDERS[rule_type]())
    assert built <= keys | {"name"}, f"builder keys CP does not send: {built - keys}"
    assert always <= built, f"recorded keys the builder lacks: {always - built}"


def test_r1_modified_rules_carry_old_and_new_and_deleted_rules_are_bodies():
    for change in load_changes("r1_modified_rules_published.json"):
        for item in change["operations"]["modified-objects"]:
            if classify(item["new-object"]["type"]) == "rule":
                assert set(item) <= {"old-object", "new-object"}
        for item in change["operations"]["deleted-objects"]:
            assert "old-object" not in item and "uid" in item


def json_fixture(name: str) -> dict[str, Any]:
    return {"changes": load_changes(name)}


GLOBAL_LOG = {"uid": "6c488338-8eec-4103-ad21-cd461ac2c477", "name": "Log", "type": "Global"}
GLOBAL_NONE = {"uid": "6c488338-8eec-4103-ad21-cd461ac2c478", "name": "None", "type": "Global"}


def test_r1_threat_and_https_rules_show_the_track_name():
    s = build_session(load_changes("r1_modified_rules_published.json")[0])
    rules = [r for r in s.rules if r.rulebase in ("threat", "https")]
    assert {r.rulebase for r in rules} == {"threat", "https"}
    assert {r.cells["track"].text for r in rules} == {"Log"}


@pytest.mark.parametrize("builder", [threat_rule, https_rule])
def test_global_track_change_is_reported(builder):
    def make(track):
        if builder is threat_rule:
            return threat_rule("t1", layer="T", name="t", track=track)
        return https_rule("t1", "t", layer="H", track=track)

    s = one(mods=[modified(make(GLOBAL_LOG), make(GLOBAL_NONE))])
    r = rule(s, "t1")
    assert r.cells["track"].text == "None" and r.cells["track"].changed
    assert FieldChange(field="track", old="Log", new="None") in r.changes
