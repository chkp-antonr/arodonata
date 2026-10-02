from __future__ import annotations

import asyncio
import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import SecretStr

from arodonata.api.schemas import ApiCallResult, ApiQueryResult
from arodonata.reports.changes import (
    ChangeReportInputError,
    OwnedSession,
    RangeScope,
    SessionScope,
    collect_change_report,
)
from arodonata.reports.changes import collect as collect_mod
from arodonata.rulebase.source import RulebaseCacheNotReady
from tests.unit.reports.entries import access_rule, d4_rule, entry, modified, session_meta
from tests.unit.reports.fakes import FakeReportClient, live_responder
from tests.unit.rulebase.fakes import ACCESS, domain4_fake, domain4_snapshot

T0 = datetime(2026, 9, 28, 15, 30, tzinfo=UTC)
MS = int(T0.timestamp() * 1000)
SID_A, SID_B = "SIDSENTINEL-A-0123456789abcdef", "SIDSENTINEL-B-0123456789abcdef"


def fake_with(domain: str = "Domain4", *entries: dict[str, Any], mgmt: str = "m1") -> FakeReportClient:
    fake = FakeReportClient()
    fake.changes[(mgmt, domain)] = list(entries)
    return fake


def owned(sid: str) -> OwnedSession:
    return OwnedSession(sid=SecretStr(sid), server_ip="192.0.2.1")


def sessions_of(report: Any, domain: str = "Domain4") -> list[Any]:
    return next(d for s in report.servers for d in s.domains if d.domain == domain).sessions


def codes(report: Any) -> list[str]:
    return [w.code for w in report.warnings]


async def collect(fake: FakeReportClient, *scopes: Any, **kw: Any) -> Any:
    kw.setdefault("now", lambda: datetime(2026, 10, 2, 9, 0, tzinfo=UTC))
    return await collect_change_report(fake, list(scopes), **kw)  # type: ignore[arg-type]


async def test_one_to_session_request_per_session_uid():
    fake = fake_with("Domain4", entry(session_meta("s1")), entry(session_meta("s2", posix_ms=MS + 1)))
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1", "s2"]))
    payloads = [c["payload"] for c in fake.query_calls]
    assert payloads == [{"to-session": "s1"}, {"to-session": "s2"}]
    assert all(c["details_level"] == "full" and c["command"] == "show-changes" for c in fake.query_calls)
    assert [s.uid for s in sessions_of(report)] == ["s2", "s1"]  # PUBLISHED_MS (s1) is later than MS + 1 (s2)


async def test_duplicate_uid_requested_once_and_first_owned_session_wins():
    fake = fake_with("Domain5", entry(session_meta("s1", published=False, domain="Domain5")))
    report = await collect(
        fake,
        SessionScope(domain="Domain5", session_uids=["s1"], owned_session=owned(SID_A)),
        SessionScope(domain="Domain5", session_uids=["s1"], owned_session=owned(SID_B)),
    )
    assert [c["payload"] for c in fake.query_calls] == [{"to-session": "s1"}]
    conflict = next(w for w in report.warnings if w.code == "owned_session_conflict")
    assert conflict.session_uid == "s1" and SID_B not in conflict.message and SID_A not in conflict.message
    assert all(sid != SID_B for sid, _, _ in fake.sid_calls)


async def test_session_not_found_warning_and_skip():
    fake = fake_with("Domain4", entry(session_meta("s1")))
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1", "missing"]))
    assert [s.uid for s in sessions_of(report)] == ["s1"]
    warning = next(w for w in report.warnings if w.code == "session_not_found")
    assert warning.session_uid == "missing" and "may be empty" in warning.message


async def test_session_uid_of_other_domain_is_session_not_found():
    # R3: another domain's uid answers success with a different session; an unknown uid answers generic_server_error
    fake = fake_with("Domain4", entry(session_meta("9d3fc19d")))
    fake.query_failures[("m1", "Domain4", "dfa38161")] = ApiQueryResult(
        success=True,
        data={"changes": [entry(session_meta("9d3fc19d"))], "total": 1},
        objects=[entry(session_meta("9d3fc19d"))],
        total=1,
    )
    fake.query_failures[("m1", "Domain4", "unknown")] = ApiQueryResult(
        success=False, code="generic_server_error", message="Management server failed to execute command"
    )
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["dfa38161", "unknown"]))
    assert codes(report) == ["session_not_found", "session_not_found"] and sessions_of(report) == []
    assert "9d3fc19d" in report.warnings[0].message


async def test_range_empty_window_is_no_sessions():
    fake = fake_with("Domain4")
    fake.query_failures[("m1", "Domain4", "*")] = ApiQueryResult(
        success=False, code="err_validation_failed", message="Only one publish made - no baseline to compare to."
    )
    report = await collect(fake, RangeScope(domain="Domain4", from_date=T0, to_date=T0.replace(hour=16)))
    d4 = report.servers[0].domains[0]
    assert (d4.unavailable, d4.sessions, report.warnings) == (None, [], [])


async def test_range_from_date_in_future_sends_nothing():
    fake = fake_with("Domain4")
    report = await collect(fake, RangeScope(domain="Domain4", from_date=datetime(2026, 10, 3, tzinfo=UTC)))
    assert fake.query_calls == [] and report.servers[0].domains[0].sessions == []


async def test_empty_session_entry_has_no_visible_changes():
    fake = fake_with("Domain5", entry(session_meta("s1", published=False, domain="Domain5")))
    [session] = sessions_of(await collect(fake, SessionScope(domain="Domain5", session_uids=["s1"])), "Domain5")
    assert (session.rules, session.objects, session.other, session.sections) == ([], [], [], [])


async def test_domain_failure_is_unavailable_block_and_others_continue():
    fake = fake_with("Domain4", entry(session_meta("s1")))
    fake.changes[("m1", "Domain5")] = [entry(session_meta("s5", domain="Domain5"))]
    fake.query_failures[("m1", "Domain4", "*")] = ApiQueryResult(success=False, code="err_login", message="denied")
    report = await collect(
        fake, SessionScope(domain="Domain4", session_uids=["s1"]), SessionScope(domain="Domain5", session_uids=["s5"])
    )
    d4 = report.servers[0].domains[0]
    assert d4.unavailable is not None and d4.unavailable.code == "err_login" and d4.sessions == []
    assert [s.uid for s in sessions_of(report, "Domain5")] == ["s5"]
    assert "domain_unavailable" in codes(report)


async def test_domain_failure_keeps_already_fetched_sessions():
    fake = fake_with("Domain4", entry(session_meta("s1")))
    fake.query_failures[("m1", "Domain4", "s2")] = ApiQueryResult(success=False, code="err_x", message="x")
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1", "s2", "s3"]))
    d4 = report.servers[0].domains[0]
    assert [s.uid for s in d4.sessions] == ["s1"] and d4.unavailable is not None
    assert [c["payload"] for c in fake.query_calls] == [{"to-session": "s1"}, {"to-session": "s2"}]


async def test_api_query_exception_is_domain_unavailable_with_class_name():
    fake = fake_with("Domain4")
    fake.query_failures[("m1", "Domain4", "*")] = TimeoutError("secret text from the transport")
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]))
    error = report.servers[0].domains[0].unavailable
    assert error is not None and error.code == "TimeoutError"
    assert error.message == "show-changes raised TimeoutError"
    assert "secret text" not in report.model_dump_json()


def _range_entries() -> list[dict[str, Any]]:
    return [
        entry(session_meta("before", posix_ms=MS - 500)),
        entry(session_meta("at_from", posix_ms=MS)),
        entry(session_meta("at_to", posix_ms=MS + 20 * 60_000)),
        entry(session_meta("after", posix_ms=MS + 20 * 60_000 + 1)),
        entry(session_meta("open", published=False)),
    ]


async def test_range_keeps_published_only_and_exact_date_bounds():
    fake = fake_with("Domain4", *_range_entries())
    report = await collect(
        fake, RangeScope(domain="Domain4", from_date=T0, to_date=datetime(2026, 9, 28, 15, 50, tzinfo=UTC))
    )
    assert [s.uid for s in sessions_of(report)] == ["at_from", "at_to"]


@pytest.mark.parametrize(
    ("style", "lo", "hi"),
    [
        ("colon", "2026-09-28T15:29:00+00:00", "2026-09-28T15:52:00+00:00"),
        ("z", "2026-09-28T15:29:00Z", "2026-09-28T15:52:00Z"),
        ("nocolon", "2026-09-28T15:29:00+0000", "2026-09-28T15:52:00+0000"),
    ],
)
async def test_range_dates_sent_with_offset_and_minute_widening(monkeypatch, style, lo, hi):
    monkeypatch.setattr(collect_mod, "_DATE_STYLE", style)
    fake = fake_with("Domain4")
    await collect(
        fake,
        RangeScope(
            domain="Domain4", from_date=T0.replace(second=20), to_date=datetime(2026, 9, 28, 15, 50, 10, tzinfo=UTC)
        ),
    )
    assert fake.query_calls[-1]["payload"] == {"from-date": lo, "to-date": hi}


async def test_range_offset_fallback_uses_server_offset_from_publish_time(monkeypatch):
    monkeypatch.setattr(collect_mod, "_DATE_STYLE", "offsetless")
    last = entry(session_meta("last"))
    last["session"]["publish-time"]["iso-8601"] = "2026-09-28T18:40+0300"
    fake = fake_with("Domain4", last)
    scope = RangeScope(
        domain="Domain4", from_date=T0.replace(second=20), to_date=datetime(2026, 9, 28, 15, 50, 10, tzinfo=UTC)
    )
    await collect(fake, scope, scope.model_copy(update={"from_date": T0}))
    offset_reads = [c for c in fake.query_calls if c["payload"] == {}]
    assert len(offset_reads) == 1  # one per mgmt
    ranged = [c["payload"] for c in fake.query_calls if c["payload"]]
    assert ranged[0] == {"from-date": "2026-09-28T17:29:00", "to-date": "2026-09-28T19:52:00"}


async def test_range_session_cap_warns():
    entries = [entry(session_meta(f"s{i}", posix_ms=MS + i)) for i in range(5)]
    fake = fake_with("Domain4", *entries)
    report = await collect(
        fake,
        RangeScope(domain="Domain4", from_date=T0),
        SessionScope(domain="Domain4", session_uids=["s4"]),
        max_sessions=2,
    )
    assert [s.uid for s in sessions_of(report)] == ["s0", "s1", "s4"]
    warning = next(w for w in report.warnings if w.code == "range_truncated")
    assert warning.message == "2 more range sessions omitted (cap 2); continue with from_session=s1"


async def test_scopes_merge_into_mgmt_domain_session_hierarchy_with_dedup():
    fake = FakeReportClient(mgmt_names=("m1", "m2"))
    fake.changes[("m1", "Domain4")] = [entry(session_meta("a")), entry(session_meta("b", posix_ms=MS))]
    fake.changes[("m2", "Domain5")] = [entry(session_meta("c", domain="Domain5"))]
    report = await collect(
        fake,
        SessionScope(domain="Domain4", session_uids=["a"]),
        SessionScope(mgmt_name="m2", domain="Domain5", session_uids=["c"]),
        RangeScope(domain="Domain4", from_date=T0),
    )
    assert [(m.mgmt_name, [d.domain for d in m.domains]) for m in report.servers] == [
        ("m1", ["Domain4"]),
        ("m2", ["Domain5"]),
    ]
    assert [s.uid for s in sessions_of(report)] == ["b", "a"]  # a once, ordered by publish time
    assert [r.kind for r in report.requested] == ["session", "session", "range"]


async def test_sessions_ordered_by_publish_time_then_unpublished():
    fake = fake_with(
        "Domain4",
        entry(session_meta("late", posix_ms=MS + 9)),
        entry(session_meta("u2", published=False)),
        entry(session_meta("early", posix_ms=MS)),
        entry(session_meta("u1", published=False)),
    )
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["u2", "late", "u1", "early"]))
    assert [s.uid for s in sessions_of(report)] == ["early", "late", "u2", "u1"]


async def test_mgmt_none_uses_first_configured_server():
    fake = FakeReportClient(mgmt_names=("first", "second"))
    fake.changes[("first", "Domain4")] = [entry(session_meta("s1"))]
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]))
    assert report.servers[0].mgmt_name == "first" and {c["mgmt_name"] for c in fake.query_calls} == {"first"}


async def test_unknown_mgmt_and_empty_scopes_raise():
    fake = FakeReportClient()
    with pytest.raises(ChangeReportInputError, match="unknown mgmt_name"):
        await collect(fake, SessionScope(mgmt_name="nope", session_uids=["s1"]))
    with pytest.raises(ChangeReportInputError, match="non-empty"):
        await collect(fake)
    with pytest.raises(ChangeReportInputError, match="SessionScope"):
        await collect(fake, {"session_uids": ["s1"]})
    with pytest.raises(ChangeReportInputError, match="no management server"):
        await collect(FakeReportClient(mgmt_names=()), SessionScope(session_uids=["s1"]))


async def test_include_raw_one_entry_per_request_per_domain():
    fake = fake_with("Domain4", entry(session_meta("s1")), entry(session_meta("s2")))
    fake.changes[("m1", "Domain5")] = [entry(session_meta("s5", domain="Domain5"))]
    report = await collect(
        fake,
        SessionScope(domain="Domain4", session_uids=["s1", "s2"]),
        SessionScope(domain="Domain5", session_uids=["s5"]),
        include_raw=True,
    )
    assert report.raw is not None
    assert [(r.domain, r.request["to-session"]) for r in report.raw] == [
        ("Domain4", "s1"),
        ("Domain4", "s2"),
        ("Domain5", "s5"),
    ]
    assert report.raw[0].response == {"changes": [fake.changes[("m1", "Domain4")][0]], "total": 1}
    assert report.raw[0].request == {"command": "show-changes", "details-level": "full", "to-session": "s1"}
    assert (await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]))).raw is None


async def test_include_raw_records_failed_request():
    fake = fake_with("Domain4")
    fake.query_failures[("m1", "Domain4", "*")] = ApiQueryResult(success=False, code="err_x", message="boom")
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]), include_raw=True)
    assert report.raw is not None
    [raw] = report.raw
    assert (raw.success, raw.code, raw.message, raw.response) == (False, "err_x", "boom", None)


async def test_domains_run_concurrently_bounded():
    fake = FakeReportClient()
    fake.delay = 0.01
    scopes = []
    for i in range(6):
        fake.changes[("m1", f"D{i}")] = [entry(session_meta(f"s{i}", domain=f"D{i}"))]
        scopes.append(SessionScope(domain=f"D{i}", session_uids=[f"s{i}"]))
    await collect(fake, *scopes, concurrency=2)
    assert fake.max_in_flight == 2


async def test_range_from_session_sends_no_dates_and_reads_no_offset():
    fake = fake_with("Domain4", entry(session_meta("s1")))
    await collect(fake, RangeScope(domain="Domain4", from_session="s0"))
    assert [c["payload"] for c in fake.query_calls] == [{"from-session": "s0"}]


async def test_range_from_session_never_combined_with_dates_but_dates_filter_client_side():
    fake = fake_with("Domain4", *_range_entries())
    report = await collect(
        fake,
        RangeScope(
            domain="Domain4", from_session="s0", from_date=T0, to_date=datetime(2026, 9, 28, 15, 50, tzinfo=UTC)
        ),
    )
    assert [c["payload"] for c in fake.query_calls] == [{"from-session": "s0"}]
    assert [s.uid for s in sessions_of(report)] == ["at_from", "at_to"]


async def test_range_from_and_to_session_payload():
    fake = fake_with("Domain4", entry(session_meta("s1")))
    await collect(fake, RangeScope(domain="Domain4", from_session="s0", to_session="s9"))
    assert [c["payload"] for c in fake.query_calls] == [{"from-session": "s0", "to-session": "s9"}]


def _two_domains_one_mgmt() -> tuple[FakeReportClient, list[RangeScope]]:
    fake = FakeReportClient()
    fake.changes[("m1", "Domain5")] = [entry(session_meta("s5", domain="Domain5"))]
    scopes = [
        RangeScope(domain=d, from_date=T0, to_date=datetime(2026, 9, 28, 15, 50, 10, tzinfo=UTC))
        for d in ("Domain4", "Domain5")
    ]
    return fake, scopes


def _ranged_payloads(fake: FakeReportClient) -> list[dict[str, Any]]:
    return [c["payload"] for c in fake.query_calls if c["payload"]]


async def test_empty_offset_read_is_not_cached_and_window_widens_15_hours():
    fake, scopes = _two_domains_one_mgmt()  # Domain4 has no session to read the offset from
    await collect(fake, *scopes, concurrency=1)
    assert [c["domain"] for c in fake.query_calls if c["payload"] == {}] == ["Domain4", "Domain5"]
    window = {"from-date": "2026-09-28T00:30:00", "to-date": "2026-09-29T06:51:00"}
    assert _ranged_payloads(fake)[0] == window


@pytest.mark.parametrize("failure", ["failed", "raises"])
async def test_failed_offset_read_is_not_cached_and_window_widens_15_hours(failure):
    fake, scopes = _two_domains_one_mgmt()
    real = fake.api_query

    async def api_query(*args, **kw):
        if kw.get("payload") == {}:
            fake.query_calls.append({"domain": kw["domain"], "payload": {}})
            if failure == "raises":
                raise TimeoutError("down")
            return ApiQueryResult(success=False, code="err_x", message="x")
        return await real(*args, **kw)

    fake.api_query = api_query  # type: ignore[method-assign]
    await collect(fake, *scopes, concurrency=1)
    assert [c["domain"] for c in fake.query_calls if c["payload"] == {}] == ["Domain4", "Domain5"]
    assert _ranged_payloads(fake)[0] == {"from-date": "2026-09-28T00:30:00", "to-date": "2026-09-29T06:51:00"}


async def test_to_date_omitted_when_widened_bound_is_in_the_future(monkeypatch):
    monkeypatch.setattr(collect_mod, "_DATE_STYLE", "colon")
    fake = fake_with("Domain4")
    await collect(
        fake, RangeScope(domain="Domain4", from_date=T0, to_date=datetime(2026, 10, 2, 8, 59, 30, tzinfo=UTC))
    )
    assert fake.query_calls[-1]["payload"] == {"from-date": "2026-09-28T15:29:00+00:00"}


async def test_member_names_resolved_across_domains_with_one_budget():
    from tests.unit.reports.entries import group, modified

    fake = FakeReportClient()
    for d in ("Domain4", "Domain5"):
        fake.changes[("m1", d)] = [
            entry(session_meta(f"s-{d}", domain=d), modified=[modified(group("g", "g", []), group("g", "g", ["x"]))])
        ]
    fake.object_names = {"x": "host-x"}
    report = await collect(
        fake,
        SessionScope(domain="Domain4", session_uids=["s-Domain4"]),
        SessionScope(domain="Domain5", session_uids=["s-Domain5"]),
    )
    assert [s.objects[0].changes[0].added[0].name for m in report.servers for d in m.domains for s in d.sessions] == [
        "host-x",
        "host-x",
    ]


R3 = d4_rule("fpcr_uat_FPCR_UAT_Active_3")
SNAP_PUBLISHED = datetime(2026, 10, 1, 6, 53, tzinfo=UTC)  # domain4_snapshot(): naive 06:53, session "sess-1"


def r3_session(uid: str, *, published: bool = True, at: datetime | None = None) -> dict[str, Any]:
    body = access_rule(R3["uid"], "r3", layer=R3["layer"], comments="a")  # unmoved: no position (F1)
    meta = session_meta(
        uid, published=published, posix_ms=int((at or SNAP_PUBLISHED - timedelta(hours=1)).timestamp() * 1000)
    )
    return entry(meta, modified=[modified(body, {**body, "comments": "b"})])


def numbered(fake_entries: list[dict[str, Any]], domain: str = "Domain4", **snapshot: Any) -> FakeReportClient:
    fake = fake_with(domain, *fake_entries)
    fake.snapshots[("m1", domain or "SMC User")] = dataclasses.replace(
        domain4_snapshot(domain_name=domain or "SMC User"), **snapshot
    )
    return fake


def number_of(report: Any, domain: str = "Domain4") -> list[tuple[str | None, str]]:
    return [
        (row.number, row.basis)
        for s in sessions_of(report, domain)
        for b in s.rulebases
        for p in b.packages
        for layer in p.layers
        for row in layer.rows
        if row.kind == "rule"
    ]


async def test_published_session_numbered_via_locate_rules_smart():
    fake = numbered([r3_session("s1")])
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]))
    assert number_of(report) == [("2.3", "snapshot")]
    assert [c["cache_mode"] for c in fake.locate_calls] == ["smart"]
    info = sessions_of(report)[0].numbering
    assert (info.source, info.snapshot_session_uid, info.status, info.provisional) == ("cache", "sess-1", "ok", False)


async def test_one_locate_rules_per_domain_for_cache_numbered_sessions():
    deleted = access_rule("gone", "gone", layer=R3["layer"], position=9)
    fake = numbered([r3_session("s1"), entry(session_meta("s2", published=False), deleted=[deleted])])
    await collect(fake, SessionScope(domain="Domain4", session_uids=["s1", "s2"]))
    [call] = fake.locate_calls
    assert call["rule_uids"] == {R3["uid"], "gone"} and call["layer_uids"] == {R3["layer"]}


async def test_domain_invalidated_before_locate():
    fake = numbered([r3_session("s1")])
    await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]))
    assert fake.events == ["invalidate:Domain4", "locate:Domain4:smart"]


async def test_no_rules_no_numbering_call():
    fake = numbered([entry(session_meta("s1"))])
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]))
    assert fake.events == [] and sessions_of(report)[0].numbering.source == "none"


async def test_stale_snapshot_relocated_with_force():
    later = SNAP_PUBLISHED + timedelta(minutes=40)
    fake = numbered([r3_session("s1", at=later)])
    fake.forced_snapshots[("m1", "Domain4")] = dataclasses.replace(
        domain4_snapshot(), session_uid="s1", session_published_time=later.replace(tzinfo=None, second=0, microsecond=0)
    )
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]))
    assert fake.events == ["invalidate:Domain4", "locate:Domain4:smart", "locate:Domain4:force"]
    assert sessions_of(report)[0].numbering.snapshot_session_uid == "s1" and "numbering_failed" not in codes(report)


async def test_stale_after_force_warns_snapshot_predates_session():
    fake = numbered([r3_session("s1", at=SNAP_PUBLISHED + timedelta(minutes=40))])
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]))
    warning = next(w for w in report.warnings if w.code == "numbering_failed")
    assert warning.severity == "info" and warning.session_uid == "s1" and "predates" in warning.message
    assert number_of(report) == [("2.3", "snapshot")]


async def test_snapshot_of_same_session_not_forced():
    at = SNAP_PUBLISHED + timedelta(seconds=41, milliseconds=7)  # same minute as the minute-truncated snapshot
    fake = numbered([r3_session("sess-1", at=at)])
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["sess-1"]))
    assert [c["cache_mode"] for c in fake.locate_calls] == ["smart"] and report.warnings == []


async def test_snapshot_newer_than_session_by_over_a_minute_not_forced():
    fake = numbered([r3_session("s1", at=SNAP_PUBLISHED - timedelta(seconds=90))])
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]))
    assert [c["cache_mode"] for c in fake.locate_calls] == ["smart"] and report.warnings == []


async def test_same_minute_different_uid_forced_once():
    at = SNAP_PUBLISHED + timedelta(seconds=20)
    fake = numbered([r3_session("s1", at=at), r3_session("s2", at=at + timedelta(seconds=5))])
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1", "s2"]))
    assert [c["cache_mode"] for c in fake.locate_calls] == ["smart", "force"]
    assert "numbering_failed" not in codes(report)


async def test_cache_datetimes_normalised_to_utc():
    fake = numbered([r3_session("s1")])
    info = sessions_of(await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"])))[0].numbering
    assert info.snapshot_published_at == SNAP_PUBLISHED and info.snapshot_published_at.tzinfo is UTC
    assert info.snapshot_refreshed_at == datetime(2026, 10, 1, 7, 0, tzinfo=UTC)


async def test_numbering_failure_warns_and_keeps_report():
    fake = numbered([r3_session("s1")])
    fake.locate_error = RulebaseCacheNotReady("no rulebase snapshot cached for m1/Domain4")
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]))
    [s] = sessions_of(report)
    assert (s.numbering.status, s.numbering.last_error) == ("failed", "RulebaseCacheNotReady")
    assert [(p.number, p.basis) for p in s.rulebases[0].unplaced] == [(None, "none")]
    assert "numbering_failed" in codes(report)


async def test_unpublished_session_numbered_provisionally_from_cache():
    fake = numbered([r3_session("u1", published=False)])
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["u1"]))
    assert number_of(report) == [("2.3", "provisional")] and sessions_of(report)[0].numbering.provisional


async def test_sms_scope_uses_smc_user_cache_domain():
    fake = numbered([r3_session("s1")], domain="")
    report = await collect(fake, SessionScope(session_uids=["s1"]))
    assert fake.locate_calls[0]["domain_name"] == "SMC User" and fake.invalidated == [("m1", "SMC User")]
    assert fake.query_calls[0]["domain"] == "" and number_of(report, "") == [("2.3", "snapshot")]


async def test_global_scope_numbers_in_global_packages():
    fake = numbered([r3_session("g1")], domain="Global")
    report = await collect(fake, SessionScope(domain="Global", session_uids=["g1"]))
    assert fake.locate_calls[0]["domain_name"] == "Global"
    assert sessions_of(report, "Global")[0].numbering.global_packages is True


async def test_forced_relocate_failure_keeps_smart_numbers_and_names_the_error():
    fake = numbered([r3_session("s1", at=SNAP_PUBLISHED + timedelta(minutes=40))])
    fake.locate_error_force = RulebaseCacheNotReady("boom")
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]))
    warning = next(w for w in report.warnings if w.code == "numbering_failed")
    assert "forced re-locate failed (RulebaseCacheNotReady)" in warning.message and "sess-1" in warning.message
    assert "predates" not in warning.message and number_of(report) == [("2.3", "snapshot")]


async def test_predates_warning_says_unknown_without_snapshot_uid():
    fake = numbered([r3_session("s1", at=SNAP_PUBLISHED + timedelta(minutes=40))], session_uid=None)
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]))
    warning = next(w for w in report.warnings if w.code == "numbering_failed")
    assert "snapshot unknown predates" in warning.message and "None" not in warning.message


async def test_invalidate_failure_is_a_numbering_failure():
    fake = numbered([r3_session("s1")])
    fake.invalidate_error = RuntimeError("memo broken")
    report = await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]))
    [s] = sessions_of(report)
    assert (s.numbering.status, s.numbering.last_error) == ("failed", "RuntimeError")
    assert codes(report).count("numbering_failed") == 1 and fake.locate_calls == []


GLOBAL_LAYER = next(
    o.layer_uid for o in domain4_snapshot().packages[0].layers if o.layer_domain_type == "global domain"
)


def owned_fake(show_session: dict[str, Any] | None, *, rulebase: Any = None) -> FakeReportClient:
    fake = numbered([r3_session("u1", published=False)])
    if show_session is not None:
        fake.sid_sessions[SID_A] = show_session
    fake.sid_responder = live_responder(rulebase or domain4_fake())
    return fake


OWNED_U1 = SessionScope(domain="Domain4", session_uids=["u1"], owned_session=owned(SID_A))


async def test_owned_session_verified_uses_live_source():
    fake = owned_fake({"uid": "u1", "type": "session", "changes": 1})
    report = await collect(fake, OWNED_U1)
    [s] = sessions_of(report)
    assert (s.numbering.source, s.numbering.status, s.numbering.snapshot_session_uid) == ("live", "live", "u1")
    assert s.numbering.snapshot_published_at is None and s.numbering.provisional is False
    assert number_of(report) == [("2.3", "live")]
    assert {c for _, c, _ in fake.sid_calls} <= {
        "show-session",
        "show-packages",
        "show-access-rulebase",
        "show-nat-rulebase",
        "show-threat-rulebase",
        "show-https-rulebase",
    }
    assert not any(c.endswith("-layers") for _, c, _ in fake.sid_calls)  # package-scoped read, no listings


async def test_owned_session_uid_mismatch_info_note_and_cache():
    report = await collect(owned_fake({"uid": "another-session"}), OWNED_U1)
    note = next(w for w in report.warnings if w.code == "owned_session_not_used")
    assert note.severity == "info" and note.session_uid == "u1"
    assert sessions_of(report)[0].numbering.source == "cache" and number_of(report) == [("2.3", "provisional")]


async def test_owned_session_error_warns_and_falls_back_provisional():
    report = await collect(owned_fake(None), OWNED_U1)  # show-session fails with the SID in its message
    error = next(w for w in report.warnings if w.code == "owned_session_error")
    assert error.message == "generic_err_wrong_session_id"
    assert number_of(report) == [("2.3", "provisional")]
    assert SID_A not in report.model_dump_json() and SID_A[:8] not in report.model_dump_json()


async def test_live_read_warning_degrades_to_provisional():
    rulebase = domain4_fake()
    rulebase.call_failures[(ACCESS, f"{GLOBAL_LAYER}@FPCR_UAT_Active")] = ApiCallResult(
        success=False, code="err_link", message=f"failed {SID_A}"
    )
    report = await collect(owned_fake({"uid": "u1"}, rulebase=rulebase), OWNED_U1)
    [s] = sessions_of(report)
    assert (s.numbering.source, s.numbering.provisional, s.numbering.last_error) == (
        "cache",
        True,
        "live_read_warning",
    )
    assert "live_numbering_degraded" in codes(report) and SID_A[:8] not in report.model_dump_json()


async def test_sid_absent_from_json_raw_warnings_and_logs(caplog):
    fake = owned_fake(None)
    with caplog.at_level(1):
        report = await collect(fake, OWNED_U1, include_raw=True)
    texts = [report.model_dump_json(), "\n".join(r.getMessage() for r in caplog.records)]
    from arodonata.reports.changes import render_change_report

    rendered = render_change_report(report, ["html", "markdown", "json"])
    texts += [
        rendered.html.decode() if rendered.html else "",
        rendered.markdown or "",
        rendered.json.decode() if rendered.json else "",
    ]
    for text in texts:
        assert SID_A not in text and SID_A[:8] not in text


T1 = datetime(2026, 9, 28, 15, 50, tzinfo=UTC)


async def test_to_session_with_from_date_sends_from_date_but_not_to_date(monkeypatch):
    monkeypatch.setattr(collect_mod, "_DATE_STYLE", "colon")
    fake = fake_with("Domain4", entry(session_meta("s1")))
    await collect(fake, RangeScope(domain="Domain4", from_date=T0, to_session="s9"))
    assert [c["payload"] for c in fake.query_calls] == [{"to-session": "s9", "from-date": "2026-09-28T15:29:00+00:00"}]


async def test_to_session_with_both_dates_keeps_to_date_client_side(monkeypatch):
    monkeypatch.setattr(collect_mod, "_DATE_STYLE", "colon")
    fake = fake_with("Domain4", entry(session_meta("s1")))
    await collect(fake, RangeScope(domain="Domain4", from_date=T0, to_date=T1, to_session="s9"))
    assert [c["payload"] for c in fake.query_calls] == [{"to-session": "s9", "from-date": "2026-09-28T15:29:00+00:00"}]


async def test_from_session_with_dates_still_sends_only_from_session_even_with_to_session():
    fake = fake_with("Domain4", entry(session_meta("s1")))
    await collect(fake, RangeScope(domain="Domain4", from_session="s0", to_session="s9", from_date=T0, to_date=T1))
    assert [c["payload"] for c in fake.query_calls] == [{"from-session": "s0", "to-session": "s9"}]


async def test_unexpected_error_in_one_domain_is_contained(monkeypatch):
    real = collect_mod.build_session

    def build_session(e):
        if e["session"]["session-uid"] == "boom":
            raise KeyError("secret-detail")
        return real(e)

    monkeypatch.setattr(collect_mod, "build_session", build_session)
    fake = FakeReportClient()
    fake.changes[("m1", "D1")] = [entry(session_meta("boom", domain="D1"))]
    fake.changes[("m1", "D2")] = [entry(session_meta("ok", domain="D2"))]
    report = await collect(
        fake, SessionScope(domain="D1", session_uids=["boom"]), SessionScope(domain="D2", session_uids=["ok"])
    )
    bad, good = sessions_of(report, "D1"), sessions_of(report, "D2")
    assert bad == [] and [s.uid for s in good] == ["ok"]
    d1 = next(d for s in report.servers for d in s.domains if d.domain == "D1")
    assert (d1.unavailable.code, d1.unavailable.message) == ("KeyError", "change report raised KeyError")
    [w] = [w for w in report.warnings if w.code == "domain_unavailable"]
    assert w.domain == "D1" and "secret-detail" not in w.message


async def test_cancellation_still_propagates(monkeypatch):
    def build_session(e):
        raise asyncio.CancelledError

    monkeypatch.setattr(collect_mod, "build_session", build_session)
    fake = fake_with("Domain4", entry(session_meta("s1")))
    with pytest.raises(asyncio.CancelledError):
        await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]))


@pytest.mark.parametrize("bad", [0, -1])
async def test_max_sessions_must_be_none_or_positive(bad):
    fake = fake_with("Domain4", entry(session_meta("s1")))
    with pytest.raises(ChangeReportInputError, match="max_sessions"):
        await collect(fake, SessionScope(domain="Domain4", session_uids=["s1"]), max_sessions=bad)


async def test_scopes_accept_any_iterable_but_not_a_single_scope_or_str():
    fake = fake_with("Domain4", entry(session_meta("s1")))
    scope = SessionScope(domain="Domain4", session_uids=["s1"])
    report = await collect_change_report(fake, (s for s in [scope]), now=lambda: T0)  # type: ignore[arg-type]
    assert [s.uid for s in sessions_of(report)] == ["s1"]
    for bad in (scope, "Domain4"):
        with pytest.raises(ChangeReportInputError, match="non-empty"):
            await collect_change_report(fake, bad, now=lambda: T0)  # type: ignore[arg-type]
