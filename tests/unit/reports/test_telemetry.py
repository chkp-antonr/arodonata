from __future__ import annotations

from arodonata.reports.changes import SessionScope, collect_change_report
from tests.unit.reports.entries import entry, session_meta
from tests.unit.reports.fakes import FakeReportClient


def _attrs(spans, suffix):
    return [dict(s.attributes or {}) for s in spans if s.name.endswith(suffix)]


async def test_collect_span_carries_session_uids_mgmt_domain(otel_spans):
    fake = FakeReportClient()
    fake.changes[("m1", "Domain4")] = [entry(session_meta("s1")), entry(session_meta("s2"))]
    await collect_change_report(fake, [SessionScope(domain="Domain4", session_uids=["s1", "s2"])])  # type: ignore[arg-type]
    spans = otel_spans.get_finished_spans()
    [top] = _attrs(spans, "collect.collect_change_report")
    assert top["arodonata.report.session_uids"] == "s1,s2"
    assert top["arodonata.report.mgmt_names"] == "m1" and top["arodonata.report.domains"] == "Domain4"
    assert top["arodonata.report.sessions"] == 2 and top["arodonata.report.include_raw"] is False
    [domain] = _attrs(spans, "collect._collect_domain")
    assert domain["arodonata.mgmt_name"] == "m1" and domain["arodonata.domain"] == "Domain4"
    assert domain["arodonata.report.session_uids"] == "s1,s2" and domain["arodonata.report.scope_kind"] == "session"


async def test_numbering_span_carries_source_snapshot_and_forced_flag(otel_spans):
    import dataclasses
    from datetime import timedelta

    from tests.unit.reports.test_collect import SNAP_PUBLISHED, numbered, r3_session

    fake = numbered([r3_session("s1", at=SNAP_PUBLISHED + timedelta(minutes=40))])
    fake.forced_snapshots[("m1", "Domain4")] = dataclasses.replace(fake.snapshots[("m1", "Domain4")], session_uid="s1")
    await collect_change_report(fake, [SessionScope(domain="Domain4", session_uids=["s1"])])  # type: ignore[arg-type]
    [span] = _attrs(otel_spans.get_finished_spans(), "collect._number_session")
    assert span["arodonata.session_uid"] == "s1" and span["arodonata.report.numbering_source"] == "cache"
    assert span["arodonata.report.snapshot_session_uid"] == "s1" and span["arodonata.report.forced_relocate"] is True
    assert span["arodonata.report.owned_session_verified"] is False
    assert span["arodonata.report.numbering_status"] == "ok"


async def test_no_span_attribute_or_log_record_contains_the_sid(otel_spans, caplog):
    from tests.unit.reports.test_collect import OWNED_U1, SID_A, owned_fake

    with caplog.at_level(1):
        await collect_change_report(owned_fake({"uid": "u1"}), [OWNED_U1])  # type: ignore[arg-type]
        await collect_change_report(owned_fake(None), [OWNED_U1])  # type: ignore[arg-type]
    values = [str(v) for s in otel_spans.get_finished_spans() for v in (s.attributes or {}).values()]
    values += [r.getMessage() for r in caplog.records]
    assert values and not any(SID_A in v or SID_A[:8] in v for v in values)


def test_sid_prefix_removed_from_asdk_log_lines():
    from pathlib import Path

    src = Path(__file__).resolve().parents[3] / "src" / "arodonata"
    client = (src / "asdk" / "client.py").read_text()
    coordinator = (src / "asdk" / "login_coordinator.py").read_text()
    assert "Using explicit SID [{sid[:8]}" not in client and "Using explicit SID for '{mgmt_name}'" in client
    assert "Logout SID [{sid[:8]}" not in client and "Logout of explicit SID for '{mgmt_name}'" in client
    assert "SID=[{sid[:8]}...], UID=" not in coordinator
