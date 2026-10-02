"""Snapshot <-> cache rows: names resolved, v2 columns filled, round trip through SQLite is lossless."""

from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from arodonata.cache.database import DatabaseManager
from arodonata.cache.models import (
    PolicyPackageLayer,
    RulebaseAccess,
    RulebaseLayer,
    RulebaseNAT,
    RulebaseSection,
    RulebaseSyncState,
    RulebaseThreat,
)
from arodonata.cache.repository import CacheRepository
from arodonata.cache.rulebase_rows import build_rulebase_rows
from arodonata.rulebase.model import DomainRulebaseSnapshot
from arodonata.rulebase.parse import parse_layer_response, parse_packages
from tests.unit.rulebase.fakes import load_fixture

LAYER_FIXTURES = [
    ("access", "global_layer_no_package.json", None, "global domain"),
    ("access", "domain_layer_fpcr_uat_active_network.json", None, "domain"),
    ("access", "inline_layer_fpcr_uat_active_inline.json", None, ""),
    ("nat", "nat_fpcr_uat_active.json", "FPCR_UAT_Active", ""),
    ("threat", "threat_ips_empty.json", None, "domain"),
    ("threat", "threat_fpcr_uat_active.json", None, "domain"),
    ("https", "https_inbound_empty.json", None, "domain"),
    ("https", "https_outbound.json", None, "domain"),
]


def make_snapshot() -> DomainRulebaseSnapshot:
    layers = [
        parse_layer_response(load_fixture(f), t, layer_name=n, layer_domain_type=dt) for t, f, n, dt in LAYER_FIXTURES
    ]
    pkg = next(p for p in load_fixture("packages_domain4_after_assign.json") if p["name"] == "FPCR_UAT_Active")
    nat_uid = next(layer.layer_uid for layer in layers if layer.rulebase_type == "nat")
    packages = parse_packages([pkg], nat_layer_uids={pkg["uid"]: nat_uid})
    return DomainRulebaseSnapshot(
        mgmt_name="m1",
        domain_name="Domain4",
        session_uid="sess-1",
        session_published_time=datetime(2026, 10, 1, 6, 53),
        refreshed_at=datetime(2026, 10, 1, 7, 0),
        packages=tuple(sorted(packages, key=lambda p: p.package_name)),
        layers=tuple(sorted(layers, key=lambda layer: (layer.rulebase_type, layer.layer_uid))),
    )


def state(**kw) -> RulebaseSyncState:
    return RulebaseSyncState(
        id="m1:Domain4",
        mgmt_name="m1",
        domain_name="Domain4",
        session_uid="sess-1",
        session_published_time=datetime(2026, 10, 1, 6, 53),
        refreshed_at=datetime(2026, 10, 1, 7, 0),
        format_version=2,
        status="ok",
        **kw,
    )


@pytest.fixture
async def repo():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield CacheRepository(DatabaseManager(engine))
    await engine.dispose()


def of(rows, model):
    return [r for r in rows if isinstance(r, model)]


def test_rule_rows_carry_v2_columns_and_names():
    rows = build_rulebase_rows(make_snapshot())
    access = {r.name: r for r in of(rows, RulebaseAccess)}
    jump = access["FPCR_UAT_Active_InlineJump"]
    assert jump.id == f"m1:Domain4:{jump.layer_uid}:{jump.uid}" and jump.layer_uid.startswith("f97e1159")
    assert jump.action == "Inner Layer" and jump.inline_layer_uid.startswith("dbfa273a") and jump.section_uid
    assert jump.layer_name == "FPCR_UAT_Active Network" and jump.domain_type == "domain"
    placeholder = access["Placeholder for domain rules"]
    assert placeholder.kind == "place-holder" and placeholder.domain_type == "global domain"
    nat = of(rows, RulebaseNAT)
    assert {r.layer_name for r in nat} == {"FPCR_UAT_Active"} and all(r.auto_generated for r in nat)


def test_threat_protections_empty_and_track_resolved_on_recorded_rule():
    [threat] = of(build_rulebase_rows(make_snapshot()), RulebaseThreat)
    assert (threat.protections, threat.track, threat.name) == ("", "Log", "")


def test_layer_section_and_package_rows():
    rows = build_rulebase_rows(make_snapshot())
    layers = {r.layer_name: r for r in of(rows, RulebaseLayer)}
    assert layers["IPS"].total == 0 and layers["Default Inbound Layer"].total == 0
    assert all(set(o) == {"uid", "name", "type"} for o in layers["FPCR_UAT_Active Network"].objects_dictionary)
    empty = next(s for s in of(rows, RulebaseSection) if s.name == "Manual Lower Rules")
    assert (empty.from_number, empty.to_number, empty.rules_before) == (None, None, 2)
    packages = of(rows, PolicyPackageLayer)
    assert {(p.rulebase_type, p.position) for p in packages} >= {("access", 0), ("nat", 0), ("https", 1)}


def _max_lengths(model) -> dict[str, int]:
    return {name: col.type.length for name, col in model.__table__.columns.items() if getattr(col.type, "length", None)}


def test_extracted_values_fit_column_lengths():
    for row in build_rulebase_rows(make_snapshot()):
        for name, length in _max_lengths(type(row)).items():
            value = getattr(row, name)
            assert not isinstance(value, str) or len(value) <= length, (type(row).__name__, name, value)


async def test_snapshot_round_trips_through_cache(repo):
    snapshot = make_snapshot()
    await repo.replace_domain_rulebases("m1", "Domain4", build_rulebase_rows(snapshot), state())
    assert await repo.load_domain_rulebase_snapshot("m1", "Domain4") == snapshot


async def test_load_without_sync_state_is_none(repo):
    assert await repo.load_domain_rulebase_snapshot("m1", "Domain4") is None
