"""RulebaseSource: numbered packages/layers and rule positions from a snapshot; CachedRulebaseSource readiness."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from arodonata.adapters.cache.postgres_adapter import PostgresCacheAdapter
from arodonata.cache.database import DatabaseManager
from arodonata.cache.models import RulebaseSyncState
from arodonata.cache.repository import CacheRepository
from arodonata.cache.rulebase_rows import build_rulebase_rows
from arodonata.rulebase.model import LayerSnapshot, OrderedLayer, PackageLayout, RuleItem
from arodonata.rulebase.source import (
    AmbiguousLayerName,
    CachedRulebaseSource,
    RulebaseCacheNotReady,
    RulebaseNotFound,
    layer_rulebase_from_snapshot,
    locate_rules_in_snapshot,
    package_rulebase_from_snapshot,
)
from tests.unit.rulebase.fakes import domain4_snapshot, load_fixture
from tests.unit.rulebase.golden import FPCR_UAT_ACTIVE_ACCESS, summarize

NETWORK = "FPCR_UAT_Active Network"


def rule(uid, n, *, inline=None):
    return RuleItem(
        uid=uid,
        name=uid,
        kind="rule",
        rule_number=n,
        enabled=True,
        section_uid=None,
        inline_layer_uid=inline,
        domain_type="domain",
        auto_generated=False,
        raw={"uid": uid},
    )


def layer(uid, items, name=None):
    return LayerSnapshot(
        "access",
        uid,
        name or uid,
        "domain",
        len(items),
        (),
        tuple(items),
        ({"uid": uid, "name": name or uid, "type": "access-layer"},),
    )


def test_package_rulebase_matches_golden():
    result = package_rulebase_from_snapshot(domain4_snapshot(), "FPCR_UAT_Active", "access", status="ok")
    (first, entries), (second, app_entries) = result.layers
    assert (first.layer_name, second.layer_name) == ("arod-global-pkg Network", "FPCR_UAT_Active AppControl")
    assert summarize(entries) == FPCR_UAT_ACTIVE_ACCESS
    assert [e.number for e in app_entries] == ["1", "2"]
    assert (result.package_name, result.snapshot_session_uid, result.status, result.last_error) == (
        "FPCR_UAT_Active",
        "sess-1",
        "ok",
        None,
    )


def test_package_rulebase_nat_single_ordered_layer():
    result = package_rulebase_from_snapshot(domain4_snapshot(), "FPCR_UAT_Active", "nat")
    [(ordered, entries)] = result.layers
    assert ordered.rulebase_type == "nat" and [e.number for e in entries if e.kind == "rule"] == ["1", "2"]


def test_unknown_package_raises_not_found():
    with pytest.raises(RulebaseNotFound, match="Nope"):
        package_rulebase_from_snapshot(domain4_snapshot(), "Nope", "access")


def test_layer_by_uid_and_by_unique_name():
    snap = domain4_snapshot()
    uid = load_fixture("domain_layer_fpcr_uat_active_network.json")["uid"]
    by_name = layer_rulebase_from_snapshot(snap, NETWORK, "access")
    by_uid = layer_rulebase_from_snapshot(snap, uid, "access")
    assert by_name.layer_uid == by_uid.layer_uid == uid and by_name.layer_name == NETWORK
    assert [e.number for e in by_name.entries if e.kind == "rule"] == ["1", "2", "2.1", "2.2", "3", "4", "5", "6"]


def test_unknown_layer_raises_not_found():
    with pytest.raises(RulebaseNotFound):
        layer_rulebase_from_snapshot(domain4_snapshot(), "No Such Layer", "access")


def test_ambiguous_layer_name_raises():
    snap = domain4_snapshot()
    twin = replace(next(lyr for lyr in snap.layers if lyr.layer_name == NETWORK), layer_uid="twin-uid")
    snap = replace(snap, layers=(*snap.layers, twin))
    with pytest.raises(AmbiguousLayerName) as err:
        layer_rulebase_from_snapshot(snap, NETWORK, "access")
    assert err.value.name == NETWORK and len(err.value.candidates) == 2
    assert {d for d, _ in err.value.candidates} == {"Domain4"} and ("Domain4", "twin-uid") in err.value.candidates


def test_layer_rulebase_returns_dictionaries_and_layer_names_of_visited_layers():
    result = layer_rulebase_from_snapshot(domain4_snapshot(), NETWORK, "access")
    inline_uid = load_fixture("inline_layer_fpcr_uat_active_inline.json")["uid"]
    assert set(result.layer_names) == {result.layer_uid, inline_uid}
    assert result.layer_names[inline_uid] == "FPCR_UAT_Active Inline"
    assert set(result.layer_dictionaries) == set(result.layer_names)
    assert any(o["name"] == "hostA_8" for o in result.layer_dictionaries[result.layer_uid])


def test_results_expose_snapshot_published_at():
    snap = domain4_snapshot()
    assert (
        package_rulebase_from_snapshot(snap, "FPCR_UAT_Active", "access").snapshot_published_at
        == snap.session_published_time
    )
    assert layer_rulebase_from_snapshot(snap, NETWORK, "access").snapshot_published_at == snap.session_published_time


def test_locate_rules_inline_rule_under_parent_rule():
    snap = domain4_snapshot()
    allow = next(i.uid for lyr in snap.layers for i in lyr.items if i.name == "fpcr_uat_inline_FPCR_UAT_Active_allow")
    [pos] = locate_rules_in_snapshot(snap, [allow], "access").rules[allow]
    assert (pos.package_name, pos.number, pos.ordered_layer_position, pos.ordered_layer_name) == (
        "FPCR_UAT_Active",
        "2.2.1",
        0,
        "arod-global-pkg Network",
    )
    assert pos.layer_name == "FPCR_UAT_Active Inline" and pos.section_name is None


def test_locate_rules_reports_section_range():
    snap = domain4_snapshot()
    first = next(i.uid for lyr in snap.layers for i in lyr.items if i.name == "fpcr_uat_FPCR_UAT_Active_4")
    [pos] = locate_rules_in_snapshot(snap, [first]).rules[first]
    assert (pos.number, pos.section_name, pos.section_range) == ("2.1", "FPCR_UAT_Section_4", "2.1-2.2")


def test_locate_rules_result_carries_snapshot_and_status():
    snap = domain4_snapshot()
    result = locate_rules_in_snapshot(snap, ["nope"], status="failed", last_error="dirty session")
    assert (result.snapshot_session_uid, result.snapshot_published_at, result.snapshot_refreshed_at) == (
        "sess-1",
        snap.session_published_time,
        snap.refreshed_at,
    )
    assert (result.status, result.last_error, result.layers) == ("failed", "dirty session", {})


def test_layer_positions_match_fpcr_uat_active_golden():
    snap = domain4_snapshot()
    domain_layer = load_fixture("domain_layer_fpcr_uat_active_network.json")["uid"]  # f97e1159
    inline_layer = load_fixture("inline_layer_fpcr_uat_active_inline.json")["uid"]  # dbfa273a
    glb = load_fixture("global_layer_no_package.json")["uid"]
    app = next(lyr.layer_uid for lyr in snap.layers if lyr.layer_name.endswith("AppControl"))
    found = locate_rules_in_snapshot(snap, layer_uids=[domain_layer, inline_layer, glb, app]).layers
    as_tuples = {
        uid: [
            (p.package_name, p.rulebase_type, p.ordered_layer_position, p.ordered_layer_name, p.prefix)
            for p in positions
        ]
        for uid, positions in found.items()
    }
    assert as_tuples[domain_layer] == [("FPCR_UAT_Active", "access", 0, "arod-global-pkg Network", "2.")]
    assert as_tuples[inline_layer] == [("FPCR_UAT_Active", "access", 0, "arod-global-pkg Network", "2.2.")]
    assert as_tuples[glb] == [("FPCR_UAT_Active", "access", 0, "arod-global-pkg Network", "")]
    assert as_tuples[app] == [("FPCR_UAT_Active", "access", 1, "FPCR_UAT_Active AppControl", "")]


def test_layer_positions_shared_inline_layer_gives_several():
    snap = replace(
        domain4_snapshot(),
        packages=(PackageLayout("p", "P", (OrderedLayer("access", 0, "", "L", "L", "domain"),)),),
        layers=(layer("L", [rule("r1", 1, inline="X"), rule("r2", 2, inline="X")]), layer("X", [rule("x1", 1)])),
    )
    assert sorted(p.prefix for p in locate_rules_in_snapshot(snap, layer_uids=["X"]).layers["X"]) == ["1.", "2."]


def test_layer_positions_unknown_uid_returns_empty():
    assert locate_rules_in_snapshot(domain4_snapshot(), layer_uids=["nope"]).layers == {"nope": []}


def test_locate_rules_shared_layer_gives_several_positions():
    shared = layer("S", [rule("s1", 1)])
    snap = replace(
        domain4_snapshot(),
        packages=(
            PackageLayout("p1", "P1", (OrderedLayer("access", 0, "", "S", "S", "domain"),)),
            PackageLayout("p2", "P2", (OrderedLayer("access", 0, "", "S", "S", "domain"),)),
        ),
        layers=(shared,),
    )
    positions = locate_rules_in_snapshot(snap, ["s1"]).rules["s1"]
    assert sorted((p.package_name, p.number) for p in positions) == [("P1", "1"), ("P2", "1")]


def test_locate_rules_inline_layer_under_two_parents_returns_both_numbers():
    snap = replace(
        domain4_snapshot(),
        packages=(PackageLayout("p", "P", (OrderedLayer("access", 0, "", "L", "L", "domain"),)),),
        layers=(layer("L", [rule("r1", 1, inline="X"), rule("r2", 2, inline="X")]), layer("X", [rule("x1", 1)])),
    )
    assert sorted(p.number for p in locate_rules_in_snapshot(snap, ["x1"]).rules["x1"]) == ["1.1", "2.1"]


def test_locate_rules_unknown_uid_returns_empty():
    assert locate_rules_in_snapshot(domain4_snapshot(), ["nope"]).rules == {"nope": []}


@pytest.fixture
async def repo():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield CacheRepository(DatabaseManager(engine))
    await engine.dispose()


async def store(repo, domain="Domain4", **state_kw):
    snap = domain4_snapshot("m1", domain)
    state = RulebaseSyncState(
        id=f"m1:{domain}",
        mgmt_name="m1",
        domain_name=domain,
        session_uid="sess-1",
        refreshed_at=snap.refreshed_at,
        session_published_time=snap.session_published_time,
        **{"format_version": 2, "status": "ok", **state_kw},
    )
    await repo.replace_domain_rulebases("m1", domain, build_rulebase_rows(snap), state)
    return snap


def source(repo):
    return CachedRulebaseSource(PostgresCacheAdapter(repo))


async def test_cached_package_rulebase_matches_golden(repo):
    await store(repo)
    result = await source(repo).package_rulebase("m1", "Domain4", "FPCR_UAT_Active", "access")
    assert summarize(result.layers[0][1]) == FPCR_UAT_ACTIVE_ACCESS


async def test_not_ready_without_sync_state(repo):
    with pytest.raises(RulebaseCacheNotReady, match="refresh_rulebases"):
        await source(repo).layer_rulebase("m1", "Domain4", NETWORK, "access")


async def test_not_ready_when_format_version_old(repo):
    await store(repo, format_version=1)
    with pytest.raises(RulebaseCacheNotReady):
        await source(repo).packages("m1", "Domain4")


async def test_not_ready_when_only_refreshes_failed(repo):
    await repo.mark_rulebase_sync_failed("m1", "Domain4", "dirty session")
    with pytest.raises(RulebaseCacheNotReady):
        await source(repo).packages("m1", "Domain4")


async def test_failed_status_still_readable_from_last_snapshot(repo):
    await store(repo)
    await repo.mark_rulebase_sync_failed("m1", "Domain4", "dirty session")
    result = await source(repo).layer_rulebase("m1", "Domain4", NETWORK, "access")
    assert (result.status, result.last_error, result.snapshot_session_uid) == ("failed", "dirty session", "sess-1")
    assert [e.number for e in result.entries if e.kind == "rule"][:3] == ["1", "2", "2.1"]


async def test_empty_v2_snapshot_is_readable(repo):
    state = RulebaseSyncState(id="m1:Empty", mgmt_name="m1", domain_name="Empty", format_version=2, status="ok")
    await repo.replace_domain_rulebases("m1", "Empty", [], state)
    assert await source(repo).packages("m1", "Empty") == []


async def test_find_layer_domains_across_cached_domains(repo):
    await store(repo, "Domain4")
    await store(repo, "Domain5")
    await store(repo, "Old", format_version=1)
    domains = await source(repo).find_layer_domains("m1", NETWORK, "access")
    assert [d for d, _ in domains] == ["Domain4", "Domain5"]


async def test_find_package_domains_skips_unready(repo):
    await store(repo, "Domain4")
    await store(repo, "Old", format_version=1)
    assert [d for d, _ in await source(repo).find_package_domains("m1", "FPCR_UAT_Active")] == ["Domain4"]


async def test_cached_locate_rules(repo):
    snap = await store(repo)
    allow = next(i.uid for lyr in snap.layers for i in lyr.items if i.name == "fpcr_uat_inline_FPCR_UAT_Active_allow")
    domain_layer = load_fixture("domain_layer_fpcr_uat_active_network.json")["uid"]
    result = await source(repo).locate_rules("m1", "Domain4", [allow], layer_uids=[domain_layer])
    assert [p.number for p in result.rules[allow]] == ["2.2.1"]
    assert [p.prefix for p in result.layers[domain_layer]] == ["2."]
    assert (result.snapshot_session_uid, result.snapshot_published_at, result.status) == (
        "sess-1",
        snap.session_published_time,
        "ok",
    )


async def test_cached_locate_rules_reports_failed_status(repo):
    await store(repo)
    await repo.mark_rulebase_sync_failed("m1", "Domain4", "dirty session")
    result = await source(repo).locate_rules("m1", "Domain4", ["nope"])
    assert (result.status, result.last_error, result.rules) == ("failed", "dirty session", {"nope": []})


async def test_not_ready_message_carries_the_refresh_error(repo):
    await repo.mark_rulebase_sync_failed("m1", "Domain4", "dirty session")
    with pytest.raises(RulebaseCacheNotReady, match="last refresh failed: dirty session"):
        await source(repo).packages("m1", "Domain4")


async def test_cached_locate_rules_extra_arguments_are_keyword_only(repo):
    await store(repo)
    with pytest.raises(TypeError):
        await source(repo).locate_rules("m1", "Domain4", ["r"], "access", ["L"])  # type: ignore[misc]


@pytest.mark.parametrize("kwargs", [{"rule_uids": "abc"}, {"layer_uids": "abc"}])
async def test_cached_locate_rules_rejects_a_bare_string(repo, kwargs):
    await store(repo)
    with pytest.raises(TypeError, match="str"):
        await source(repo).locate_rules("m1", "Domain4", **kwargs)


class RacingCache:
    """Cache double: snapshot and state reads served from queues (a refresh landing between the two reads)."""

    def __init__(self, snapshots, states):
        self.snapshots, self.states = list(snapshots), list(states)
        self.snapshot_calls = self.state_calls = 0

    async def load_domain_rulebase_snapshot(self, mgmt_name, domain_name):
        self.snapshot_calls += 1
        return self.snapshots.pop(0)

    async def get_rulebase_sync_state(self, mgmt_name, domain_name):
        self.state_calls += 1
        return self.states.pop(0)


def sync_state(refreshed_at, status="ok", last_error=None):
    return RulebaseSyncState(
        id="m1:Domain4",
        mgmt_name="m1",
        domain_name="Domain4",
        format_version=2,
        refreshed_at=refreshed_at,
        status=status,
        last_error=last_error,
    )


async def test_status_read_again_when_a_refresh_lands_between_snapshot_and_state():
    base = domain4_snapshot()
    t1, t2 = datetime(2026, 10, 1, tzinfo=UTC), datetime(2026, 10, 2, tzinfo=UTC)
    s1, s2 = replace(base, session_uid="sess-1", refreshed_at=t1), replace(base, session_uid="sess-2", refreshed_at=t2)
    cache = RacingCache([s1, s2], [sync_state(t2), sync_state(t2, "failed", "later failure")])
    result = await CachedRulebaseSource(cache).layer_rulebase("m1", "Domain4", NETWORK, "access")
    assert (result.snapshot_session_uid, result.status, result.last_error) == ("sess-2", "failed", "later failure")
    assert (cache.snapshot_calls, cache.state_calls) == (2, 2)


async def test_failed_state_of_the_same_snapshot_is_not_read_again():
    t1 = datetime(2026, 10, 1, tzinfo=UTC)
    cache = RacingCache([replace(domain4_snapshot(), refreshed_at=t1)], [sync_state(t1, "failed", "dirty session")])
    result = await CachedRulebaseSource(cache).layer_rulebase("m1", "Domain4", NETWORK, "access")
    assert (result.status, result.last_error) == ("failed", "dirty session")
    assert (cache.snapshot_calls, cache.state_calls) == (1, 1)


async def test_cached_source_implements_both_protocols(repo):
    from arodonata.rulebase.source import RulebaseDomainIndex, RulebaseSource

    cached = source(repo)
    for proto in (RulebaseSource, RulebaseDomainIndex):
        members = [n for n in vars(proto) if not n.startswith("_")]
        assert members and all(callable(getattr(cached, n, None)) for n in members)
    assert {n for n in vars(RulebaseSource) if not n.startswith("_")} == {
        "packages",
        "package_rulebase",
        "layer_rulebase",
        "locate_rules",
    }
    assert "find_layer_domains" in vars(RulebaseDomainIndex) and "find_package_domains" in vars(RulebaseDomainIndex)


def test_locate_rules_returns_section_uid():
    snapshot = domain4_snapshot()
    sections = {s.name: s.uid for layer in snapshot.layers for s in layer.sections}
    rule = next(i for layer in snapshot.layers for i in layer.items if i.name == "fpcr_uat_FPCR_UAT_Active_3")
    [position] = locate_rules_in_snapshot(snapshot, [rule.uid]).rules[rule.uid]
    assert (position.number, position.section_name, position.section_uid) == (
        "2.3",
        "FPCR_UAT_Section_3",
        sections["FPCR_UAT_Section_3"],
    )


def test_locate_rules_reports_layer_has_sections():
    snapshot = domain4_snapshot()
    uid = {layer.layer_name: layer.layer_uid for layer in snapshot.layers}
    domain, inline = uid["FPCR_UAT_Active Network"], uid["FPCR_UAT_Active Inline"]
    located = locate_rules_in_snapshot(snapshot, layer_uids=[domain, inline])
    assert [(p.prefix, p.has_sections) for p in located.layers[domain]] == [("2.", True)]
    assert [(p.prefix, p.has_sections) for p in located.layers[inline]] == [("2.2.", False)]
