"""A deterministic ChangeReport exercising every renderer feature (golden files, round trip, escaping)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from arodonata.api.schemas import ApiQueryResult
from arodonata.reports.changes import ChangeReport, SessionScope, collect_change_report
from arodonata.reports.changes.render import RenderOptions
from tests.unit.reports.entries import (
    ACCEPT,
    DROP,
    access_rule,
    d4_layer,
    d4_rule,
    entry,
    group,
    host,
    modified,
    ref,
    section,
    session_meta,
    threat_rule,
)
from tests.unit.reports.fakes import FakeReportClient
from tests.unit.rulebase.fakes import domain4_snapshot

GENERATED = datetime(2026, 10, 2, 9, 0, tzinfo=UTC)
PUBLISHED = datetime(2026, 10, 1, 5, 53, tzinfo=UTC)  # an hour before the snapshot: numbered as of the snapshot
EVIL = "<b>&\"'"
HOSTILE = "[x](javascript:alert(1)) <img src=x> **b** ~~s~~ +lead \\"
SNAP = domain4_snapshot()
DOMAIN_LAYER = d4_layer("FPCR_UAT_Active Network")
H1, H2 = ref("h1", "web-1"), ref("h2", "web-2")
OPTIONS = RenderOptions(
    title="Change evidence **RITM0012345**",
    header_fields={"RITM": "[RITM0012345](https://servicenow.example.com/ritm?id=1&x=2)", "Requester": "*J. Doe*"},
    generated_by="unit tests",
)


def _threat() -> dict[str, Any]:
    layer = next(lyr for lyr in SNAP.layers if lyr.rulebase_type == "threat" and lyr.items)
    return {"uid": layer.items[0].uid, "layer": layer.layer_uid}


def published_entry() -> dict[str, Any]:
    r3, r4 = (d4_rule(f"fpcr_uat_FPCR_UAT_Active_{n}") for n in (3, 4))
    cleanup = d4_rule("fpcr_uat_inline_FPCR_UAT_Active_cleanup")  # inline layer: no sections, prefix 2.2.
    # unmoved modified rules carry no position (lab F1); the moved one carries old/new positions
    r3_old = access_rule(r3["uid"], "fpcr_uat_FPCR_UAT_Active_3", layer=r3["layer"], source=[H1], action=ACCEPT)
    r4_old = access_rule(r4["uid"], "fpcr_uat_FPCR_UAT_Active_4", layer=r4["layer"])
    moved_old = access_rule(
        cleanup["uid"], "fpcr_uat_inline_FPCR_UAT_Active_cleanup", layer=cleanup["layer"], position=1
    )
    t = _threat()
    t_old = threat_rule(t["uid"], layer=t["layer"])
    sec3 = next(s.uid for lyr in SNAP.layers for s in lyr.sections if s.name == "FPCR_UAT_Section_3")
    acs = {
        "uid": "acs",
        "name": "Application Control Advanced Settings",
        "type": "app-control-advanced-settings",
        "x": 1,
    }
    policy = {"uid": "ap", "name": "pol", "type": "AccessPolicy"}
    return entry(
        session_meta(
            "pub-1",
            name="RITM0012345 change",
            description="Open | web access",
            posix_ms=int(PUBLISHED.timestamp() * 1000),
        ),
        added=[
            access_rule("new-top", EVIL, layer=DOMAIN_LAYER, position=1, enabled=False, source=[H1]),
            host("h2", "web-2", ip="192.0.2.12"),
        ],
        modified=[
            modified(r3_old, {**r3_old, "source": [H2], "action": DROP}),
            modified(r4_old, {**r4_old, "enabled": False}),
            modified(moved_old, {**moved_old, "position": 2}),
            modified(t_old, {**t_old, "comments": "tuned"}),
            modified(section(sec3, "Old section 3"), section(sec3, "FPCR_UAT_Section_3")),
            modified(host("h1", "web-1"), host("h1", "web-1", comments="decommission")),
            modified(group("g1", "web-servers", ["h1"]), group("g1", "web-servers", ["h1", "h2"])),
            modified(acs, {**acs, "x": 2}),
            modified(policy, {**policy, "y": 1}),
        ],
        deleted=[access_rule("gone", "old rule", layer=DOMAIN_LAYER, position=5, source=[H1])],
    )


def unpublished_entry() -> dict[str, Any]:
    return entry(
        session_meta("open-1", name="pending | change", published=False),
        added=[
            access_rule(
                "pending-rule", HOSTILE, layer=DOMAIN_LAYER, position=2, comments="see [docs](https://example.com)"
            )
        ],
    )


def sample_fake() -> FakeReportClient:
    fake = FakeReportClient()
    fake.changes[("m1", "Domain4")] = [published_entry(), unpublished_entry()]
    fake.snapshots[("m1", "Domain4")] = SNAP
    fake.query_failures[("m1", "Domain5", "*")] = ApiQueryResult(
        success=False, code="err_rpc", message="Domain5 server down"
    )
    return fake


async def sample_report(*, include_raw: bool = True, fake: FakeReportClient | None = None) -> ChangeReport:
    report = await collect_change_report(
        fake or sample_fake(),  # type: ignore[arg-type]
        [
            SessionScope(domain="Domain4", session_uids=["pub-1", "open-1"]),
            SessionScope(domain="Domain5", session_uids=["d5-1"]),
        ],
        include_raw=include_raw,
        now=lambda: GENERATED,
    )
    return report.model_copy(update={"arodonata_version": "0.0.0"})


def rule_rows(report: ChangeReport) -> int:
    """Rule rows the renderers show: one per placement, placed and unplaced."""
    return sum(
        sum(1 for p in b.packages for layer in p.layers for row in layer.rows if row.kind == "rule") + len(b.unplaced)
        for m in report.servers
        for d in m.domains
        for s in d.sessions
        for b in s.rulebases
    )


def object_rows(report: ChangeReport) -> int:
    return sum(
        len(s.objects) + len(s.sections) + len(s.other) for m in report.servers for d in m.domains for s in d.sessions
    )
