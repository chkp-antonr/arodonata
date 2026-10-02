from __future__ import annotations

import dataclasses

from arodonata.reports.changes.build import build_session
from arodonata.reports.changes.model import ObjectChange, RulePlacement, SectionHeader
from arodonata.reports.changes.placement import number_key, place_session
from arodonata.rulebase.source import locate_rules_in_snapshot
from tests.unit.reports.entries import (
    access_rule,
    d4_layer,
    d4_rule,
    entry,
    modified,
    nat_rule,
    ref,
    section,
    session_meta,
)
from tests.unit.rulebase.fakes import domain4_snapshot

SNAP = domain4_snapshot()
DOMAIN_LAYER = d4_layer("FPCR_UAT_Active Network")  # has sections
INLINE_LAYER = d4_layer("FPCR_UAT_Active Inline")  # no sections, prefix "2.2."
SECTIONS = {s.name: s.uid for layer in SNAP.layers for s in layer.sections}
R3, R4, R2 = (
    d4_rule("fpcr_uat_FPCR_UAT_Active_3"),
    d4_rule("fpcr_uat_FPCR_UAT_Active_4"),
    d4_rule("fpcr_uat_FPCR_UAT_Active_2"),
)
INLINE = d4_rule("fpcr_uat_inline_FPCR_UAT_Active_allow")
CLEANUP = d4_rule("fpcr_uat_inline_FPCR_UAT_Active_cleanup")


def session(*, added=(), mods=(), deleted=(), published=True):
    return build_session(entry(session_meta("s1", published=published), added=added, modified=mods, deleted=deleted))


def locations(s, snapshot=SNAP):
    rules = {r.uid for r in s.rules}
    layers = {u for r in s.rules for u in (r.layer_uid, r.old_layer_uid) if u}
    return locate_rules_in_snapshot(snapshot, rules, layer_uids=layers)


def place(s, basis="snapshot", snapshot=SNAP):
    """Unpublished sessions (basis provisional) get the cache as ``prior`` too: it holds the pre-session state."""
    located = locations(s, snapshot)
    return place_session(s, located, basis=basis, prior=located if basis == "provisional" else None)


def mod(r, *, old_pos=None, new_pos=None, uid=None, layer=None):
    """A modified rule as CP sends it: positions only for a moved rule (F1), counted within its section (F2)."""
    uid = uid or r["uid"]
    layer = layer or r["layer"]
    return modified(
        access_rule(uid, uid, layer=layer, position=old_pos, comments="a"),
        access_rule(uid, uid, layer=layer, position=new_pos, comments="b"),
    )


def rows(s, rulebase="access"):
    block = next(b for b in s.rulebases if b.rulebase == rulebase)
    return [row for p in block.packages for layer in p.layers for row in layer.rows]


def placed(s, rulebase="access"):
    return [r for r in rows(s, rulebase) if isinstance(r, RulePlacement)]


def numbers(s, rulebase="access"):
    return [(r.number, r.basis) for r in placed(s, rulebase)]


def test_published_numbers_from_rule_positions():
    s = place(session(mods=[mod(R3)]))
    block = s.rulebases[0]
    assert [p.package_name for p in block.packages] == ["FPCR_UAT_Active"]
    assert numbers(s) == [("2.3", "snapshot")]
    header, placement = rows(s)
    assert isinstance(header, SectionHeader) and (header.name, header.range) == ("FPCR_UAT_Section_3", "2.3")
    assert placement.section_uid == SECTIONS["FPCR_UAT_Section_3"]


def test_number_key_orders_2_2_1_before_2_10():
    assert sorted(["2.10", "2.2.1", "2.2", "10", None, "3"], key=number_key) == [
        "2.2",
        "2.2.1",
        "2.10",
        "3",
        "10",
        None,
    ]


def test_shared_inline_layer_rule_under_each_package():
    layout = SNAP.packages[0]
    two = dataclasses.replace(
        SNAP, packages=(layout, dataclasses.replace(layout, package_uid="p2", package_name="FPCR_UAT_Copy"))
    )
    s = place(session(mods=[mod(INLINE)]), snapshot=two)
    got = [
        (p.package_name, row.number, row.anchor)
        for p in s.rulebases[0].packages
        for layer in p.layers
        for row in layer.rows
        if isinstance(row, RulePlacement)
    ]
    assert got == [
        ("FPCR_UAT_Active", "2.2.1", f"r-s1-{INLINE['uid']}-p1"),
        ("FPCR_UAT_Copy", "2.2.1", f"r-s1-{INLINE['uid']}-p2"),
    ]


def test_unpublished_rule_not_in_cache_is_prefix_plus_position():
    s = place(
        session(added=[access_rule("new", "new", layer=INLINE_LAYER, position=3)], published=False),
        basis="provisional",
    )
    assert numbers(s) == [("2.2.3", "provisional")]


def test_rule_in_sectioned_layer_gets_section_position():
    body = access_rule("new", "new", layer=DOMAIN_LAYER, position=3)
    unpublished = place(session(added=[body], published=False), basis="provisional")
    published = place(session(added=[body]))
    for s, basis in ((unpublished, "provisional"), (published, "at-time-of-change")):
        [p] = placed(s)
        assert (p.number, p.section_position, p.basis) == (None, 3, basis)


def test_unpublished_unmoved_rule_keeps_cached_number():
    [p] = placed(place(session(mods=[mod(R3)], published=False), basis="provisional"))
    assert (p.number, p.basis, p.section_name) == ("2.3", "provisional", "FPCR_UAT_Section_3")


def test_unpublished_moved_rule_uses_new_position_not_cache_number():
    [p] = placed(place(session(mods=[mod(R3, old_pos=1, new_pos=2)], published=False), basis="provisional"))
    assert (p.number, p.section_position, p.previous_number, p.basis) == (None, 2, "2.3", "provisional")


def test_new_rule_in_new_inline_layer_uses_parent_number():
    parent = access_rule("p", "parent", layer=INLINE_LAYER, position=3, **{"inline-layer": "new-inline"})
    child = access_rule("c", "child", layer="new-inline", position=1)
    s = place(session(added=[parent, child], published=False), basis="provisional")
    assert numbers(s) == [("2.2.3", "provisional"), ("2.2.3.1", "provisional")]


def test_deleted_rule_numbered_before_deletion():
    s = place(
        session(
            deleted=[
                access_rule("gone", "gone", layer=INLINE_LAYER, position=2),
                access_rule("sec", "sec", layer=DOMAIN_LAYER, position=4),
            ]
        )
    )
    assert [(p.rule_uid, p.number, p.section_position, p.basis) for p in placed(s)] == [
        ("gone", "2.2.2", None, "before-deletion"),
        ("sec", None, 4, "before-deletion"),
    ]


def test_deleted_rule_without_position_uses_cache_number():
    body = access_rule(R3["uid"], "x", layer=DOMAIN_LAYER)
    del body["layer"]
    s = place(session(deleted=[body], published=False), basis="provisional")
    assert numbers(s) == [("2.3", "before-deletion")]


def test_unpublished_deleted_rule_uses_prior_number():
    body = access_rule(R3["uid"], "x", layer=DOMAIN_LAYER, position=1)  # section-relative position (F2)
    s = place(session(deleted=[body], published=False), basis="provisional")
    assert numbers(s) == [("2.3", "before-deletion")]


def test_deleted_rules_of_deleted_inline_layer():
    parent = access_rule("p", "parent", layer=INLINE_LAYER, position=2, **{"inline-layer": "gone-inline"})
    child = access_rule("c", "child", layer="gone-inline", position=1)
    s = place(session(deleted=[parent, child]))
    assert numbers(s) == [("2.2.2", "before-deletion"), ("2.2.2.1", "before-deletion")]


def test_published_rule_gone_from_snapshot_at_time_of_change():
    s = place(session(mods=[mod({"uid": "x", "layer": INLINE_LAYER}, old_pos=3, new_pos=4)]))
    assert numbers(s) == [("2.2.4", "at-time-of-change")]


def test_moved_rule_previous_number():
    [published] = placed(place(session(mods=[mod(CLEANUP, old_pos=1, new_pos=2)])))
    assert (published.number, published.previous_number) == ("2.2.2", "2.2.1")  # positional, section-less layer
    [unpublished] = placed(place(session(mods=[mod(R3, old_pos=1, new_pos=1)], published=False), basis="provisional"))
    assert unpublished.previous_number == "2.3"  # from prior (the cache's pre-session state)
    [sectioned] = placed(place(session(mods=[mod(R3, old_pos=1, new_pos=2)])))
    assert (sectioned.number, sectioned.previous_number) == ("2.3", None)  # old position is section-relative


def test_section_headers_only_for_sections_with_changes_and_ranges():
    s = place(session(mods=[mod(R4), mod(R2)]))
    shown = [(r.name, r.range) if isinstance(r, SectionHeader) else r.number for r in rows(s)]
    assert shown == [("FPCR_UAT_Section_4", "2.1-2.2"), "2.1", ("FPCR_UAT_Section_2", "2.4"), "2.4"]


def test_sectionless_placement_does_not_split_section_run():
    gone = mod({"uid": "x", "layer": INLINE_LAYER}, old_pos=3, new_pos=4)  # 2.2.4, at time of change, no section
    s = place(session(mods=[mod(R4), gone, mod(R3)]))
    shown = [r.name if isinstance(r, SectionHeader) else r.number for r in rows(s)]
    assert shown == ["FPCR_UAT_Section_4", "2.1", "2.2.4", "FPCR_UAT_Section_3", "2.3"]


def test_deleted_before_live_rule_with_same_number():
    s = place(session(mods=[mod(INLINE)], deleted=[access_rule("gone", "gone", layer=INLINE_LAYER, position=1)]))
    assert [(r.rule_uid, r.number) for r in placed(s)] == [("gone", "2.2.1"), (INLINE["uid"], "2.2.1")]


def test_numberless_rows_sort_after_numbered():
    s = place(session(added=[access_rule("new", "new", layer=DOMAIN_LAYER, position=1)], mods=[mod(R3)]))
    assert [(r.rule_uid, r.number) for r in placed(s)] == [(R3["uid"], "2.3"), ("new", None)]


def test_changed_section_status_on_header_row():
    uid = SECTIONS["FPCR_UAT_Section_3"]
    s = place(session(mods=[mod(R3), modified(section(uid, "Old"), section(uid, "FPCR_UAT_Section_3"))]))
    header = rows(s)[0]
    assert isinstance(header, SectionHeader) and header.status == "modified"
    assert [(c.field, c.old, c.new) for c in header.changes] == [("name", "Old", "FPCR_UAT_Section_3")]
    assert s.sections == []


def test_unplaceable_section_change_listed_separately():
    s = place(session(mods=[mod(R3), modified(section("elsewhere", "A"), section("elsewhere", "B"))]))
    assert [o.uid for o in s.sections] == ["elsewhere"] and isinstance(s.sections[0], ObjectChange)


def test_no_locations_gives_unplaced_rules():
    s = place_session(
        session(added=[access_rule("a", "a", layer=DOMAIN_LAYER, position=1, source=[ref("h1", "web-1")])]),
        None,
        basis="none",
    )
    [block] = s.rulebases
    assert block.packages == [] and [(p.number, p.basis) for p in block.unplaced] == [(None, "none")]
    assert "source" in block.columns  # a value only an unplaced rule carries keeps its column


def test_nat_rule_layer_mapped_to_cache_nat_layer():
    nat = next(layer for layer in SNAP.layers if layer.rulebase_type == "nat")
    item = nat.items[0]  # the Domain4 NAT fixture holds auto-generated rules only; the mapping is the same
    body = nat_rule(item.uid, item.name, layer="not-the-cache-key")
    s = place(session(mods=[modified(body, {**body, "comments": "x"})]))
    [r] = s.rules
    assert r.layer_uid == nat.layer_uid
    expected = locate_rules_in_snapshot(SNAP, [item.uid]).rules[item.uid][0].number
    assert numbers(s, "nat") == [(expected, "snapshot")]


def test_placement_anchors_unique():
    layout = SNAP.packages[0]
    two = dataclasses.replace(
        SNAP, packages=(layout, dataclasses.replace(layout, package_uid="p2", package_name="Copy"))
    )
    s = place(
        session(mods=[mod(INLINE), mod(R3)], deleted=[access_rule("g", "g", layer=DOMAIN_LAYER, position=3)]),
        snapshot=two,
    )
    anchors = [
        r.anchor
        for b in s.rulebases
        for p in b.packages
        for layer in p.layers
        for r in layer.rows
        if isinstance(r, RulePlacement)
    ]
    assert len(anchors) == len(set(anchors)) == 6


def test_section_position_rows_get_unknown_section_header():
    s = place(session(added=[access_rule("new", "new", layer=DOMAIN_LAYER, position=1)], mods=[mod(R3)]))
    shown = [(r.name, r.uid) if isinstance(r, SectionHeader) else r.number for r in rows(s)]
    assert shown == [
        ("FPCR_UAT_Section_3", SECTIONS["FPCR_UAT_Section_3"]),
        "2.3",
        ("Section not known (or before the first section)", None),
        None,
    ]
    unknown = rows(s)[2]
    assert (unknown.range, unknown.status, unknown.changes) == (None, None, [])


def test_section_position_rows_ordered_by_position_under_one_unknown_header():
    added = [access_rule(n, n, layer=DOMAIN_LAYER, position=p) for n, p in (("b", 2), ("a", 1))]
    s = place(session(added=added))
    kinds = [r.name if isinstance(r, SectionHeader) else r.rule_uid for r in rows(s)]
    assert kinds == ["Section not known (or before the first section)", "a", "b"]
