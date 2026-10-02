"""Change report reads on the home lab (non-mutating): Domain4 published sessions, a published range, and one
Global-domain session read only (D16, D23)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from arodonata.reports.changes import RangeScope, SessionScope, render_change_report
from tests.unit.rulebase.golden import FPCR_UAT_ACTIVE_ACCESS

from ..cp_revision import last_published_session

SEED = "354446be-2f2b-4f2f-b7b3-e10603fad414"
ASSIGN = "3250a85f-9765-44ac-8355-432be83da916"
PLUS3 = timezone(timedelta(hours=3))
GOLDEN = {name: number for number, kind, name, _, _ in FPCR_UAT_ACTIVE_ACCESS if kind == "rule"}


def _sessions(report):
    return [s for m in report.servers for d in m.domains for s in d.sessions]


async def test_seed_session_numbered_from_cache_like_smartconsole(apikey_client, test_domain_a):
    client, _ = apikey_client
    assert test_domain_a == "Domain4"
    report = await client.collect_change_report([SessionScope(domain="Domain4", session_uids=[SEED])])
    [session] = _sessions(report)
    assert session.numbering.source == "cache" and session.numbering.status in ("ok", "unversioned")
    rules = {r.uid: r for r in session.rules}
    placed = [
        (rules[row.rule_uid].name, row.number)
        for b in session.rulebases
        if b.rulebase == "access"
        for p in b.packages
        if p.package_name == "FPCR_UAT_Active"
        for layer in p.layers
        for row in layer.rows
        if row.kind == "rule"
    ]
    assert placed and all(GOLDEN[name] == number for name, number in placed if name in GOLDEN)
    assert "2.2.1" in {number for _, number in placed}
    assert render_change_report(report, ["html"]).html


async def test_assignment_session_hides_internal_types(apikey_client):
    client, _ = apikey_client
    [session] = _sessions(await client.collect_change_report([SessionScope(domain="Domain4", session_uids=[ASSIGN])]))
    assert session.internal and all(o.internal for o in session.internal)
    assert [o.type for o in session.other] == ["app-control-advanced-settings"]


async def test_range_returns_exactly_the_sessions_inside_the_bounds(apikey_client):
    client, _ = apikey_client
    lo, hi = datetime(2026, 9, 28, 18, 30, tzinfo=PLUS3), datetime(2026, 9, 28, 18, 50, tzinfo=PLUS3)
    narrow = _sessions(await client.collect_change_report([RangeScope(domain="Domain4", from_date=lo, to_date=hi)]))
    wide = _sessions(
        await client.collect_change_report(
            [RangeScope(domain="Domain4", from_date=lo - timedelta(hours=2), to_date=hi + timedelta(hours=2))]
        )
    )
    expected = [s.uid for s in wide if s.published_at and lo <= s.published_at <= hi]
    assert expected and [s.uid for s in narrow] == expected


async def test_global_session_numbered_in_global_packages(apikey_client):
    client, mgmt = apikey_client
    last = await last_published_session(client, mgmt, "Global")
    assert last["uid"], "no published Global session to read"
    report = await client.collect_change_report([SessionScope(domain="Global", session_uids=[last["uid"]])])
    [session] = _sessions(report)
    if not session.rules:
        pytest.skip("last published Global session has no rules; Global packages numbering not exercised")
    assert session.numbering.global_packages is True
    assert b"(Global packages)" in (render_change_report(report, ["html"]).html or b"")
