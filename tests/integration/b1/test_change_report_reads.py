"""Bucket 1 — Read-only change report collection & rendering against the live MDSM.

Covers:
1. ``collect_change_report`` with a ``SessionScope`` targeting the baseline published session
   of ``TEST_DOMAIN_A``.
2. ``render_change_report`` produces valid ``html``, ``markdown``, and ``json`` outputs.
3. ``ChangeReport`` JSON round-trip (``model_dump_json`` -> ``model_validate_json``) re-renders
   identically without any network call.
4. ``RangeScope`` over the last 7 days collects published sessions in ``TEST_DOMAIN_A``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from arodonata import (
    ArodonataClient,
    ChangeReport,
    RangeScope,
    RenderOptions,
    SessionScope,
)
from tests.integration.cp_revision import BaselineSnapshot


async def test_change_report_session_scope_and_roundtrip(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
    cp_baseline_snapshot: BaselineSnapshot,
) -> None:
    """Verify ``collect_change_report``, ``render_change_report``, and offline JSON round-trip."""
    base_uid = cp_baseline_snapshot.domains[test_domain_a].session_uid

    scope = SessionScope(
        mgmt_name=mgmt_name,
        domain=test_domain_a,
        session_uids=[base_uid],
    )
    opts = RenderOptions(
        title="B1 Integration Smoke Report",
        header_fields={"Ticket": "INT-B1"},
    )

    report = await apikey_client.collect_change_report([scope], options=opts)
    assert len(report.sessions) == 1
    assert report.sessions[0].session_uid == base_uid

    rendered = apikey_client.render_change_report(
        report,
        formats=("html", "markdown", "json"),
        options=opts,
    )
    assert isinstance(rendered["html"], bytes)
    assert b"B1 Integration Smoke Report" in rendered["html"]
    assert isinstance(rendered["markdown"], str)
    assert "INT-B1" in rendered["markdown"]
    assert isinstance(rendered["json"], str)

    # Round-trip from JSON without touching the network
    reloaded = ChangeReport.model_validate_json(rendered["json"])
    re_rendered = apikey_client.render_change_report(reloaded, formats=("markdown",), options=opts)
    assert re_rendered["markdown"] == rendered["markdown"]


async def test_change_report_range_scope(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``RangeScope`` collects published sessions within a UTC time window."""
    now = datetime.now(UTC)
    scope = RangeScope(
        mgmt_name=mgmt_name,
        domain=test_domain_a,
        from_date=now - timedelta(days=30),
        to_date=now + timedelta(minutes=5),
    )
    report = await apikey_client.collect_change_report([scope])
    assert isinstance(report.sessions, list)
