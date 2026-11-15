"""Comprehensive end-to-end tests exercising client workflows over direct FileReplayApiMock and HTTPS server."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from arodonata import AMgmtClient, ArodonataClient, ArodonataSettings
from arodonata.adapters.checkpoint.task_waiter import TaskWaiter
from arodonata.core.telemetry import set_trace_modules
from arodonata.mcp import create_mcp_server
from arodonata.reports.models import OwnedSession, SessionScope
from arodonata.testing import (
    CheckPointReplayHttpServer,
    FileReplayApiMock,
    FileReplayCliMock,
    ensure_enterprise_raw_dataset,
)
from arodonata.testing._emulator_models import ANY_UID


def _parse_mcp_json(result: Any) -> dict[str, Any]:
    return dict(json.loads(result.content[0].text))


@pytest.mark.asyncio
async def test_e2e_in_process_mmp_decommission_cpcrud_reports_and_mcp(tmp_path: Path) -> None:
    """Exercise Decommission, CPCRUD staged/publish/inverse, Change Reports, MCP, and snapshot rollback."""
    dataset_dir = ensure_enterprise_raw_dataset()
    cli_mock = FileReplayCliMock(dataset_dir)
    api_mock = FileReplayApiMock(dataset_dir, cli_mock=cli_mock)
    baseline_snap = api_mock.snapshot_state()

    settings = ArodonataSettings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'e2e_direct.sqlite'}",
        mgmt_name="mds",
        mgmt_ip="127.0.0.1",
        mgmt_port=443,
        api_key="mock-e2e-key",
    )

    async with ArodonataClient(settings=settings, api=api_mock, gateway_cli=cli_mock) as client:
        # ------------------------------------------------------------------
        # 1. MMP Decommission workflow
        # ------------------------------------------------------------------
        decom_sid, _ = await api_mock.create_dedicated_session("mds", "Branch", session_name="mmp-decom-seed")
        h_uid = str(
            (
                await api_mock.api_call(
                    "mds",
                    "add-host",
                    {"name": "H_Decom_Target", "ipv4-address": "10.222.10.10"},
                    domain="Branch",
                    sid=decom_sid,
                )
            ).data["uid"]
        )
        g_uid = str(
            (
                await api_mock.api_call(
                    "mds",
                    "add-group",
                    {"name": "G_Decom_App", "members": [h_uid]},
                    domain="Branch",
                    sid=decom_sid,
                )
            ).data["uid"]
        )
        arule_uid = str(
            (
                await api_mock.api_call(
                    "mds",
                    "add-access-rule",
                    {
                        "layer": "Branch_Standard_Pkg Network",
                        "position": "top",
                        "name": "Decom_Sole_Rule",
                        "source": [h_uid],
                        "destination": ["Any"],
                        "service": ["Any"],
                        "action": "Accept",
                    },
                    domain="Branch",
                    sid=decom_sid,
                )
            ).data["uid"]
        )
        nrule_uid = str(
            (
                await api_mock.api_call(
                    "mds",
                    "add-nat-rule",
                    {
                        "package": "Branch_Standard_Pkg",
                        "position": "top",
                        "method": "static",
                        "original-source": h_uid,
                        "translated-source": "Original",
                        "comments": "Decom NAT rule",
                    },
                    domain="Branch",
                    sid=decom_sid,
                )
            ).data["uid"]
        )
        assert (await api_mock.api_call("mds", "publish", {}, domain="Branch", sid=decom_sid)).success

        # Verify where-used finds group + Access rule + NAT rule and delete fails until unlinked
        wu_before = await api_mock.api_call("mds", "where-used", {"uid": h_uid}, domain="Branch")
        assert wu_before.success
        assert len(wu_before.data["used-directly"]["objects"]) == 1
        assert len(wu_before.data["used-directly"]["access-control-rules"]) == 1
        assert len(wu_before.data["used-directly"]["nat-rules"]) == 1

        blocked = await api_mock.api_call("mds", "delete-host", {"uid": h_uid}, domain="Branch", sid=decom_sid)
        assert not blocked.success
        assert blocked.error_code == "generic_err_object_cannot_be_deleted"

        # Cleanup sequence: unlink group, remove sole source member & disable rule, delete NAT rule, delete host
        assert (
            await api_mock.api_call(
                "mds",
                "set-group",
                {"uid": g_uid, "members": {"remove": [h_uid]}},
                domain="Branch",
                sid=decom_sid,
            )
        ).success
        upd_rule = await api_mock.api_call(
            "mds",
            "set-access-rule",
            {
                "layer": "Branch_Standard_Pkg Network",
                "uid": arule_uid,
                "source": {"remove": [h_uid]},
                "enabled": False,
                "comments": "Decommissioned H_Decom_Target",
            },
            domain="Branch",
            sid=decom_sid,
        )
        assert upd_rule.success
        assert [s["uid"] for s in upd_rule.data["source"]] == [ANY_UID]
        assert upd_rule.data["enabled"] is False

        assert (
            await api_mock.api_call(
                "mds",
                "delete-nat-rule",
                {"package": "Branch_Standard_Pkg", "uid": nrule_uid},
                domain="Branch",
                sid=decom_sid,
            )
        ).success
        assert (await api_mock.api_call("mds", "delete-host", {"uid": h_uid}, domain="Branch", sid=decom_sid)).success
        assert (await api_mock.api_call("mds", "publish", {}, domain="Branch", sid=decom_sid)).success
        await api_mock.logout_sid("mds", decom_sid)

        assert not (await api_mock.api_call("mds", "show-host", {"uid": h_uid}, domain="Branch")).success

        # ------------------------------------------------------------------
        # 2. CPCRUD staged, discard, publish, and inverse rollback workflow
        # ------------------------------------------------------------------
        await client.get_domains(mgmt_name="mds", include_global=True, cache_mode="force")
        await client.rulebase_refresh.refresh_rulebases(mgmt_name="mds", domains=["Branch"], mode="force")

        tpl: dict[str, Any] = {
            "version": 1,
            "mgmt_name": "mds",
            "domain": "Branch",
            "objects": [{"type": "host", "name": "cpcrud-e2e-host", "ipv4-address": "10.223.1.15"}],
            "groups": [{"type": "group", "name": "cpcrud-e2e-grp", "members": ["cpcrud-e2e-host"]}],
            "rules": [
                {
                    "type": "access-rule",
                    "layer": "Branch_Standard_Pkg Network",
                    "name": "CPCRUD_E2E_Rule",
                    "position": "top",
                    "source": ["cpcrud-e2e-grp"],
                    "destination": ["Any"],
                    "service": ["Any"],
                    "rule_action": "Accept",
                }
            ],
        }
        plan = await client.cpcrud.plan(tpl)
        staged_report = await client.cpcrud.apply(
            plan,
            no_publish=True,
            keep_session=True,
            session_name="cpcrud-e2e-staged",
        )
        assert len(staged_report.staged_sessions) == 1
        staged_uid = staged_report.staged_sessions[0].session_uid
        staged_sid = staged_report.staged_sessions[0].sid
        assert staged_sid
        assert not (await api_mock.api_call("mds", "show-host", {"name": "cpcrud-e2e-host"}, domain="Branch")).success

        # Mimic MMP try_verify_draft logout_sid before staged discard: session stays disconnected & adopts without 401
        call_log_start = len(api_mock.call_log)
        assert await client.logout_sid("mds", staged_sid) is True
        disc_res = await client.cpcrud.discard_staged_session("mds", "Branch", session_uid=staged_uid)
        assert disc_res.success
        discard_slice = api_mock.call_log[call_log_start:]
        assert not any(c.get("error_code") == "generic_err_invalid_session_id" for c in discard_slice)

        pub_report = await client.cpcrud.apply(plan, no_publish=False, session_name="cpcrud-e2e-pub")
        assert list(pub_report.published_sessions.keys()) == ["mds:Branch"]
        assert (await api_mock.api_call("mds", "show-host", {"name": "cpcrud-e2e-host"}, domain="Branch")).success

        # Rollback using CPCRUD inverse()
        inv_tpl = client.cpcrud.inverse(plan, pub_report)
        inv_plan = await client.cpcrud.plan(inv_tpl)
        inv_report = await client.cpcrud.apply(inv_plan, no_publish=False)
        assert list(inv_report.published_sessions.keys()) == ["mds:Branch"]
        assert not (await api_mock.api_call("mds", "show-host", {"name": "cpcrud-e2e-host"}, domain="Branch")).success

        # ------------------------------------------------------------------
        # 3. Change Reports with OwnedSession (staged & live_published)
        # ------------------------------------------------------------------
        chg_sid, _ = await api_mock.create_dedicated_session("mds", "Branch", session_name="e2e-change-report")
        chg_sess_uid = str(
            (await api_mock.api_call("mds", "show-session", {}, domain="Branch", sid=chg_sid)).data["uid"]
        )
        assert (
            await api_mock.api_call(
                "mds",
                "add-host",
                {"name": "H_Chg_E2E", "ipv4-address": "10.223.2.20"},
                domain="Branch",
                sid=chg_sid,
            )
        ).success
        assert (
            await api_mock.api_call(
                "mds",
                "add-access-rule",
                {
                    "layer": "Branch_Standard_Pkg Network",
                    "position": "top",
                    "name": "R_Chg_E2E",
                    "source": "H_Chg_E2E",
                    "destination": "Any",
                    "service": "Any",
                    "action": "Accept",
                },
                domain="Branch",
                sid=chg_sid,
            )
        ).success

        rep_staged = await client.collect_change_report(
            [
                SessionScope(
                    mgmt_name="mds",
                    domain="Branch",
                    session_uids=[chg_sess_uid],
                    owned_sessions=OwnedSession(sid=chg_sid, session_uid=chg_sess_uid, server_ip="127.0.0.1"),
                )
            ]
        )
        assert rep_staged.sessions[0].numbering_source == "owned_session"
        assert any(o.name == "H_Chg_E2E" for o in rep_staged.sessions[0].object_changes)
        assert any(r.name == "R_Chg_E2E" and r.rule_number == "1" for r in rep_staged.sessions[0].rule_changes)

        assert (await api_mock.api_call("mds", "publish", {}, domain="Branch", sid=chg_sid)).success
        rep_pub = await client.collect_change_report(
            [
                SessionScope(
                    mgmt_name="mds",
                    domain="Branch",
                    session_uids=[chg_sess_uid],
                    owned_sessions=OwnedSession(sid=chg_sid, session_uid=chg_sess_uid, server_ip="127.0.0.1"),
                )
            ]
        )
        assert rep_pub.sessions[0].numbering_source == "live_published"
        await api_mock.logout_sid("mds", chg_sid)

        # ------------------------------------------------------------------
        # 4. MCP server E2E verification (read + CPCRUD + change_report)
        # ------------------------------------------------------------------
        mcp_server = create_mcp_server(client, auth_mode="host", cpcrud=True)
        mcp_tpl = {
            "version": 1,
            "mgmt_name": "mds",
            "domain": "Branch",
            "objects": [{"type": "host", "name": "H_MCP_E2E", "ipv4-address": "10.223.3.30"}],
        }
        mcp_plan_res = await mcp_server.call_tool("cpcrud_plan", {"template": mcp_tpl})
        assert not mcp_plan_res.is_error
        mcp_plan_data = _parse_mcp_json(mcp_plan_res)

        mcp_apply_res = await mcp_server.call_tool(
            "cpcrud_apply",
            {"plan_id": mcp_plan_data["plan_id"], "no_publish": True, "keep_session": True},
        )
        assert not mcp_apply_res.is_error
        mcp_staged_uid = _parse_mcp_json(mcp_apply_res)["staged_sessions"][0]["session_uid"]

        mcp_pub_res = await mcp_server.call_tool(
            "cpcrud_staged_session",
            {"mgmt_name": "mds", "domain": "Branch", "session_uid": mcp_staged_uid, "action": "publish"},
        )
        assert not mcp_pub_res.is_error
        assert _parse_mcp_json(mcp_pub_res)["published"] is True

        mcp_show_res = await mcp_server.call_tool(
            "show_object",
            {"mgmt_name": "mds", "domain": "Branch", "uid_or_name": "H_MCP_E2E"},
        )
        assert not mcp_show_res.is_error
        assert _parse_mcp_json(mcp_show_res)["objects"][0]["ipv4_address"] == "10.223.3.30"

        mcp_rb_res = await mcp_server.call_tool(
            "show_rulebase",
            {
                "mgmt_name": "mds",
                "domain": "Branch",
                "package": "Branch_Standard_Pkg",
                "layer": "Branch_Standard_Pkg Network",
                "limit": 5,
            },
        )
        assert not mcp_rb_res.is_error

        mcp_rep_res = await mcp_server.call_tool(
            "change_report",
            {"mgmt_name": "mds", "domain": "Branch", "session_uids": [mcp_staged_uid], "format": "json"},
        )
        assert not mcp_rep_res.is_error
        assert "H_MCP_E2E" in mcp_rep_res.content[0].text

    # Fast snapshot restore & Global mutation audit
    api_mock.assert_no_global_mutations()
    api_mock.restore_state(baseline_snap)
    assert not (await api_mock.api_call("mds", "show-host", {"name": "H_Decom_Target"}, domain="Branch")).success
    assert not (await api_mock.api_call("mds", "show-host", {"name": "H_MCP_E2E"}, domain="Branch")).success


@pytest.mark.asyncio
async def test_e2e_https_server_amgmt_cpcrud_reports_global_and_otel(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    """Exercise real `AMgmtClient` + `TaskWaiter` over loopback HTTPS `CheckPointReplayHttpServer`."""
    set_trace_modules(None)
    exporter = InMemorySpanExporter()
    proc = SimpleSpanProcessor(exporter)
    existing_provider = trace.get_tracer_provider()
    if hasattr(existing_provider, "add_span_processor"):
        existing_provider.add_span_processor(proc)
    else:
        provider = TracerProvider()
        provider.add_span_processor(proc)
        trace.set_tracer_provider(provider)
    request.addfinalizer(proc.shutdown)
    exporter.clear()

    dataset_dir = ensure_enterprise_raw_dataset()
    cli_mock = FileReplayCliMock(dataset_dir)
    api_mock = FileReplayApiMock(dataset_dir, cli_mock=cli_mock)
    secret_pw = "E2E_HTTPS_Password_Sentinel_42"

    async with CheckPointReplayHttpServer(
        dataset_dir=dataset_dir,
        api_mock=api_mock,
        host="127.0.0.1",
        port=0,
    ) as server:
        settings = ArodonataSettings(
            database_url=f"sqlite+aiosqlite:///{tmp_path / 'e2e_https.sqlite'}",
            mgmt_name="mds",
            mgmt_ip="127.0.0.1",
            mgmt_port=server.port,
            username="admin",
            password=secret_pw,
            tls_trust="pinned",
            tls_fingerprints=f"127.0.0.1:{server.port}={server.fingerprint}",
        )
        fast_waiter = TaskWaiter(task_timeout=10.0, initial_delay=0.01, max_delay=0.05)
        real_api = AMgmtClient(settings=settings, task_waiter=fast_waiter)

        async with ArodonataClient(settings=settings, api=real_api, gateway_cli=cli_mock) as client:
            await client.get_domains(mgmt_name="mds", include_global=True, cache_mode="force")

            # CPCRUD over HTTPS (async publish polled via TaskWaiter + show-task)
            tpl = {
                "version": 1,
                "mgmt_name": "mds",
                "domain": "Branch",
                "objects": [{"type": "host", "name": "H_HTTPS_CPCRUD", "ipv4-address": "10.224.1.10"}],
            }
            plan = await client.cpcrud.plan(tpl)
            report = await client.cpcrud.apply(plan, no_publish=False, session_name="https-cpcrud-e2e")
            assert list(report.published_sessions.keys()) == ["mds:Branch"]
            pub_uid = report.published_sessions["mds:Branch"]

            # Change report over HTTPS (async show-changes polled via TaskWaiter + show-task)
            chg_rep = await client.collect_change_report(
                [SessionScope(mgmt_name="mds", domain="Branch", session_uids=[pub_uid])]
            )
            assert len(chg_rep.sessions) == 1
            assert any(o.name == "H_HTTPS_CPCRUD" for o in chg_rep.sessions[0].object_changes)

            # Global domain write protection enforced over HTTPS
            br_sid, br_ip = await real_api.create_dedicated_session("mds", "Branch")
            try:
                glob_write = await real_api.api_call(
                    "mds",
                    "set-host",
                    {"uid": "uid-glob-host-001", "comments": "should fail over https"},
                    domain="Branch",
                    sid=br_sid,
                    server_ip=br_ip,
                )
                assert not glob_write.success
                assert glob_write.error_code == "generic_err_object_read_only"
            finally:
                await real_api.logout_sid("mds", br_sid, server_ip=br_ip)

            # assign-global-policy over HTTPS (task polled to completion via TaskWaiter)
            mds_sid, mds_ip = await real_api.create_dedicated_session("mds", "System Data")
            try:
                assign_res = await real_api.api_call(
                    "mds",
                    "assign-global-policy",
                    {"dependent-domains": ["Branch"], "global-domains": ["Global"]},
                    domain="System Data",
                    sid=mds_sid,
                    server_ip=mds_ip,
                    wait_for_task=True,
                )
                assert assign_res.success
            finally:
                await real_api.logout_sid("mds", mds_sid, server_ip=mds_ip)

    # Hygiene verification across call_log and OTEL spans
    assert api_mock.assert_no_global_mutations() is None
    assert secret_pw not in json.dumps(api_mock.call_log, default=str)
    spans = list(exporter.get_finished_spans())
    assert spans
    for sp in spans:
        span_dump = json.dumps(dict(sp.attributes or {}), default=str)
        assert secret_pw not in span_dump
        assert "mock-sid-" not in span_dump
