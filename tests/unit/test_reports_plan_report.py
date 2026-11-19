"""Unit tests for offline Dry-Run `ChangeReport` synthesis (`src/arodonata/reports/plan_report.py`)."""

from __future__ import annotations

from typing import Any

import pytest

from arodonata import ArodonataClient, ArodonataSettings
from arodonata.cpcrud.models import FieldChange, Outcome, Plan, PlannedAction
from arodonata.reports import ChangeReport, build_change_report_from_plan, render_change_report


class _NeverCalledApi:
    async def api_call(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("build_change_report_from_plan must not perform API calls")

    async def api_query(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("build_change_report_from_plan must not perform API queries")

    async def create_dedicated_session(self, *args: Any, **kwargs: Any) -> tuple[str, str]:
        raise AssertionError("build_change_report_from_plan must not open a session")

    async def logout_sid(self, *args: Any, **kwargs: Any) -> bool:
        raise AssertionError("build_change_report_from_plan must not call logout_sid")

    async def close(self, *, logout: bool | None = None) -> None:
        return None


@pytest.mark.spec("SCN-REPORT-004-1")
def test_build_change_report_from_plan_renders_html_markdown_and_json_offline() -> None:
    """Dry-run `Plan` synthesizes `ChangeReport` offline and renders SmartConsole HTML, Markdown, and JSON."""
    plan = Plan(
        name_resolutions={"Site__chinacloudapi.cn": "Custom_ChinaCloud"},
        actions=[
            PlannedAction(
                action_id="act-1",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="add",
                object_type="host",
                name="Host_10.1.1.1",
                outcome=Outcome.CREATE,
                command="add-host",
                payload={"name": "Host_10.1.1.1", "ipv4-address": "10.1.1.1"},
            ),
            PlannedAction(
                action_id="act-2",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="set",
                object_type="application-site",
                name="Site__chinacloudapi.cn",
                target_uid="site-1",
                outcome=Outcome.UPDATE,
                command="set-application-site",
                payload={"uid": "site-1", "url-list": [r"\.chinacloudapi\.cn", r"\.partner\.cn"]},
                diffs={
                    "url-list": FieldChange(
                        field="url-list",
                        old_value=[r"\/chinacloudapi\.cn", r"\.chinacloudapi\.cn"],
                        new_value=[r"\.chinacloudapi\.cn", r"\.partner\.cn"],
                        added_items=[r"\.partner\.cn"],
                        removed_items=[r"\/chinacloudapi\.cn"],
                    )
                },
            ),
            PlannedAction(
                action_id="act-3",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="set",
                object_type="group",
                name="AppAccess_Grp",
                target_uid="grp-1",
                outcome=Outcome.UPDATE,
                command="set-group",
                payload={"uid": "grp-1", "members": {"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]}},
                diffs={
                    "members": FieldChange(
                        field="members",
                        old_value=["Host_10.0.0.5", "Host_Existing"],
                        new_value={"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]},
                        added_items=["Host_10.1.1.1"],
                        removed_items=["Host_10.0.0.5"],
                    )
                },
            ),
            PlannedAction(
                action_id="act-4",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="set",
                object_type="access-rule",
                name="Allow App",
                target_uid="rule-1",
                layer="Network",
                outcome=Outcome.UPDATE,
                command="set-access-rule",
                payload={
                    "uid": "rule-1",
                    "layer": "Network",
                    "source": {"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]},
                    "service": {"add": ["TCP_8443"]},
                },
                diffs={
                    "source": FieldChange(
                        field="source",
                        old_value=["Host_10.0.0.5"],
                        new_value={"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]},
                        added_items=["Host_10.1.1.1"],
                        removed_items=["Host_10.0.0.5"],
                    ),
                    "service": FieldChange(
                        field="service",
                        old_value=["TCP_80"],
                        new_value={"add": ["TCP_8443"]},
                        added_items=["TCP_8443"],
                        removed_items=[],
                    ),
                },
                prior_state={
                    "uid": "rule-1",
                    "name": "Allow App",
                    "layer": "Network",
                    "position": 3,
                    "source": ["Host_10.0.0.5"],
                    "destination": ["Any"],
                    "service": ["TCP_80"],
                    "rule_action": "Accept",
                    "track": "Log",
                },
            ),
            PlannedAction(
                action_id="act-5",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="unchanged",
                object_type="host",
                name="Host_Unchanged",
                outcome=Outcome.UNCHANGED,
            ),
            PlannedAction(
                action_id="act-6",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="set",
                object_type="host",
                name="<script>alert(1)</script>",
                outcome=Outcome.ERROR,
                error="Host missing",
            ),
        ],
    )

    # Works offline without touching API
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret_api_key_value")
    client = ArodonataClient(settings, api=_NeverCalledApi())

    report = client.build_change_report_from_plan(
        plan,
        title="Dry-Run Change Preview",
        header_fields={"Ticket": "CHG-1001", "sid": "never-leak-sid"},
    )
    assert isinstance(report, ChangeReport)
    assert len(report.sessions) == 1
    assert len(report.warnings) == 1
    assert report.warnings[0].code == "partial_failure"

    sess = report.sessions[0]
    assert sess.session_uid == "dry-run-plan"
    assert sess.numbering_source == "not_applicable"
    assert sess.resolved_names == {"Site__chinacloudapi.cn": "Custom_ChinaCloud"}

    # Unchanged action omitted by default
    obj_by_name = {o.name: o for o in sess.object_changes}
    assert set(obj_by_name.keys()) == {"Host_10.1.1.1", "Site__chinacloudapi.cn", "AppAccess_Grp"}
    assert obj_by_name["Host_10.1.1.1"].operation == "added"
    assert obj_by_name["AppAccess_Grp"].field_diffs[0].added_items == ["Host_10.1.1.1"]
    assert obj_by_name["AppAccess_Grp"].field_diffs[0].removed_items == ["Host_10.0.0.5"]
    assert obj_by_name["AppAccess_Grp"].field_diffs[0].new_value == ["Host_Existing", "Host_10.1.1.1"]

    assert len(sess.rule_changes) == 1
    rc = sess.rule_changes[0]
    assert rc.operation == "modified"
    assert rc.rule_number == "3"
    assert rc.source == ["Host_10.1.1.1"]
    assert rc.service == ["TCP_80", "TCP_8443"]
    rc_diffs = {d.field_name: d for d in rc.field_diffs}
    assert rc_diffs["source"].added_items == ["Host_10.1.1.1"]
    assert rc_diffs["source"].removed_items == ["Host_10.0.0.5"]
    assert rc_diffs["service"].added_items == ["TCP_8443"]

    bundle = render_change_report(report, formats=["html", "markdown", "json"])
    assert bundle.html is not None
    assert bundle.markdown is not None
    assert bundle.json_text is not None

    html_str = bundle.html.decode("utf-8")
    assert "<script" not in html_str.lower()
    assert "secret_api_key_value" not in html_str
    assert "never-leak-sid" not in html_str
    assert "+ Host_10.1.1.1" in html_str
    assert "- Host_10.0.0.5" in html_str
    assert "+ TCP_8443" in html_str
    assert "Dry-Run Change Preview" in html_str

    assert "Host_10.1.1.1" in bundle.markdown
    assert "[+Host_10.1.1.1]" in bundle.markdown
    assert "[-Host_10.0.0.5]" in bundle.markdown

    # JSON round-trip validation
    round_tripped = ChangeReport.model_validate_json(bundle.json_text)
    assert round_tripped.sessions[0].rule_changes[0].source == ["Host_10.1.1.1"]

    # include_unchanged=True includes Outcome.UNCHANGED
    with_unchanged = build_change_report_from_plan(plan, include_unchanged=True)
    assert any(o.name == "Host_Unchanged" for o in with_unchanged.sessions[0].object_changes)


def test_build_change_report_preserves_prior_on_noop_delta_and_redacts_warnings() -> None:
    """No-op delta cells in modified actions keep full prior list items, and warnings redact SIDs."""
    plan = Plan(
        actions=[
            PlannedAction(
                action_id="act-noop-cell",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="set",
                object_type="access-rule",
                name="Partial Noop",
                target_uid="rule-2",
                layer="Network",
                outcome=Outcome.UPDATE,
                command="set-access-rule",
                payload={"uid": "rule-2", "layer": "Network", "destination": {"add": ["Net_C"]}},
                diffs={
                    "destination": FieldChange(
                        field="destination",
                        old_value=["Net_D"],
                        new_value={"add": ["Net_C"]},
                        added_items=["Net_C"],
                        removed_items=[],
                    )
                },
                desired_spec={
                    "type": "access-rule",
                    "operation": "set",
                    "layer": "Network",
                    "name": "Partial Noop",
                    "source": {"add": ["Host_A"]},
                    "destination": {"add": ["Net_C"]},
                },
                prior_state={
                    "uid": "rule-2",
                    "name": "Partial Noop",
                    "layer": "Network",
                    "position": 4,
                    "source": ["Host_A", "Host_B"],
                    "destination": ["Net_D"],
                    "service": ["TCP_80"],
                },
            ),
            PlannedAction(
                action_id="act-err-sid",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="set",
                object_type="host",
                name="Host_sid_test",
                outcome=Outcome.ERROR,
                error="Request failed with X-chkp-sid: abcdef1234567890",
            ),
        ]
    )
    report = build_change_report_from_plan(plan)
    rc = report.sessions[0].rule_changes[0]
    assert rc.source == ["Host_A", "Host_B"]
    assert rc.destination == ["Net_D", "Net_C"]
    assert len(report.warnings) == 1
    assert "abcdef1234567890" not in report.warnings[0].message
