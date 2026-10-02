from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import SecretStr, ValidationError

from arodonata.reports.changes import ChangeReport, OwnedSession, SessionScope, collect_change_report
from arodonata.reports.changes.model import (
    FORMAT_VERSION,
    Cell,
    CellItem,
    DomainChanges,
    FieldChange,
    LayerBlock,
    MgmtChanges,
    NamedRef,
    NumberingInfo,
    ObjectChange,
    PackageBlock,
    RequestedScope,
    RulebaseBlock,
    RuleChange,
    RulePlacement,
    SectionHeader,
    SessionChanges,
)
from tests.unit.reports.entries import entry, session_meta
from tests.unit.reports.fakes import FakeReportClient

T0 = datetime(2026, 9, 28, 15, 30, tzinfo=UTC)


def sample_report() -> ChangeReport:
    rule = RuleChange(
        uid="r1",
        type="access-rule",
        rulebase="access",
        name="web",
        status="modified",
        enabled=True,
        layer_uid="L1",
        position=3,
        old_layer_uid="L1",
        old_position=2,
        moved=True,
        cells={
            "source": Cell(
                items=[CellItem(uid="h1", name="h1", status="removed"), CellItem(uid="h2", name="h2", status="added")],
                changed=True,
            )
        },
        changes=[
            FieldChange(field="source", removed=[NamedRef(uid="h1", name="h1")], added=[NamedRef(uid="h2", name="h2")])
        ],
        anchor_base="r-s1-r1",
    )
    block = RulebaseBlock(
        rulebase="access",
        columns=["enabled", "number", "source"],
        packages=[
            PackageBlock(
                package_name="P",
                layers=[
                    LayerBlock(
                        ordered_layer_name="Network",
                        ordered_layer_position=0,
                        rows=[
                            SectionHeader(uid="sec", name="S1", range="2.1-2.2"),
                            RulePlacement(
                                rule_uid="r1",
                                anchor="r-s1-r1-p1",
                                number="2.2",
                                previous_number="2.1",
                                basis="snapshot",
                                section_uid="sec",
                                section_name="S1",
                                section_range="2.1-2.2",
                            ),
                        ],
                    )
                ],
            )
        ],
    )
    session = SessionChanges(
        uid="s1",
        name="n",
        published=True,
        published_at=T0,
        numbering=NumberingInfo(source="cache", snapshot_session_uid="s1", snapshot_published_at=T0, status="ok"),
        rules=[rule],
        rulebases=[block],
        sections=[],
        objects=[
            ObjectChange(
                uid="h3",
                type="host",
                name="h3",
                status="added",
                category="object",
                key_value="192.0.2.3",
                anchor="o-s1-h3",
            )
        ],
        other=[],
        internal=[],
    )
    return ChangeReport(
        generated_at=T0,
        arodonata_version="1.11.0",
        requested=[
            RequestedScope(
                kind="range", mgmt_name="m1", domain="Domain4", from_date=T0, to_date=T0 + timedelta(hours=1)
            )
        ],
        servers=[
            MgmtChanges(
                mgmt_name="m1", domains=[DomainChanges(domain="Domain4", display_name="Domain4", sessions=[session])]
            )
        ],
    )


def test_json_round_trip_preserves_report():
    report = sample_report()
    assert ChangeReport.model_validate_json(report.model_dump_json()) == report


def test_format_version_written_and_newer_rejected():
    data = json.loads(sample_report().model_dump_json())
    assert data["format_version"] == FORMAT_VERSION
    data["format_version"] = FORMAT_VERSION + 1
    with pytest.raises(ValueError, match=f"format_version {FORMAT_VERSION + 1} .*{FORMAT_VERSION}"):
        ChangeReport.model_validate_json(json.dumps(data))


async def test_requested_scopes_omit_owned_session():
    sid = "SIDSENTINEL-0123456789abcdef"
    fake = FakeReportClient()
    fake.changes[("m1", "Domain5")] = [entry(session_meta("s1", published=False, domain="Domain5"))]
    scope = SessionScope(
        domain="Domain5", session_uids=["s1"], owned_session=OwnedSession(sid=SecretStr(sid), server_ip="192.0.2.1")
    )
    report = await collect_change_report(fake, [scope])  # type: ignore[arg-type]
    assert report.requested[0].owned_session_supplied is True
    assert sid not in report.model_dump_json() and sid[:8] not in report.model_dump_json()


def test_model_datetimes_are_aware_utc():
    info = NumberingInfo(
        source="cache", snapshot_published_at=datetime(2026, 10, 1, 9, 0, tzinfo=timezone(timedelta(hours=3)))
    )
    assert info.snapshot_published_at == datetime(2026, 10, 1, 6, 0, tzinfo=UTC)
    assert info.snapshot_published_at.tzinfo is UTC
    with pytest.raises(ValidationError):
        NumberingInfo(source="cache", snapshot_published_at=datetime(2026, 10, 1, 9, 0))
