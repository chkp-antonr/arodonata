"""Unit tests for CheckPointReplayHttpServer auth/control endpoints, snapshots, call_log, and OTEL hygiene."""

from __future__ import annotations

import json
import time

import aiohttp
import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from arodonata.core.telemetry import set_trace_modules
from arodonata.testing.mock_server import CheckPointReplayHttpServer, build_arg_parser
from arodonata.testing.replay_mock import FileReplayApiMock


@pytest.mark.spec("SCN-ITEST-008-2", "SCN-ITEST-015-1", "SCN-ITEST-016-1")
@pytest.mark.asyncio
async def test_https_server_auth_sid_enforcement_and_testing_control_endpoints() -> None:
    """Verify HTTPS 401 checks, logout invalidation, and opt-in `/__testing__/*` endpoints."""
    assert build_arg_parser().parse_args([]).enable_test_control is False
    assert build_arg_parser().parse_args(["--enable-test-control"]).enable_test_control is True

    # 0. Constructor defaults to enable_test_control=False (opt-in)
    async with CheckPointReplayHttpServer(host="127.0.0.1", port=0) as srv_default:
        assert srv_default._enable_test_control is False
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as http:
            async with http.post(f"https://127.0.0.1:{srv_default.port}/__testing__/reset") as resp:
                assert resp.status == 404

    # 1. Server with enable_test_control=True requires X-Arodonata-Test-Token or active X-chkp-sid
    async with CheckPointReplayHttpServer(host="127.0.0.1", port=0, enable_test_control=True) as srv:
        root_url = f"https://127.0.0.1:{srv.port}"
        token_headers = {"X-Arodonata-Test-Token": srv.test_control_token}
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as http:
            # Login without credentials -> 401 generic_err_invalid_credentials
            async with http.post(f"{srv.base_url}/login", json={}) as resp:
                assert resp.status == 401
                body = await resp.json()
                assert body["code"] == "generic_err_invalid_credentials"

            # Unauthenticated /__testing__/* -> 401; wrong token -> 401
            async with http.get(f"{root_url}/__testing__/call-log") as resp:
                assert resp.status == 401
                assert (await resp.json())["code"] == "generic_err_missing_required_header"
            async with http.post(
                f"{root_url}/__testing__/snapshot",
                headers={"X-Arodonata-Test-Token": "wrong-token"},
                json={"name": "clean"},
            ) as resp:
                assert resp.status == 401
                assert (await resp.json())["code"] == "generic_err_invalid_credentials"

            # Non-login request without X-chkp-sid -> 401 generic_err_missing_required_header
            async with http.post(f"{srv.base_url}/show-hosts", json={"limit": 5}) as resp:
                assert resp.status == 401
                body = await resp.json()
                assert body["code"] == "generic_err_missing_required_header"

            # Non-login request with unknown X-chkp-sid -> 401 generic_err_invalid_session_id
            async with http.post(
                f"{srv.base_url}/show-hosts",
                headers={"X-chkp-sid": "unknown-bogus-sid-123"},
                json={"limit": 5},
            ) as resp:
                assert resp.status == 401
                body = await resp.json()
                assert body["code"] == "generic_err_invalid_session_id"

            # Snapshot before mutating (using test control token)
            async with http.post(
                f"{root_url}/__testing__/snapshot",
                headers=token_headers,
                json={"name": "clean"},
            ) as resp:
                assert resp.status == 200
                assert (await resp.json())["name"] == "clean"

            # Restoring nonexistent snapshot -> 404
            async with http.post(
                f"{root_url}/__testing__/restore",
                headers=token_headers,
                json={"name": "missing"},
            ) as resp:
                assert resp.status == 404

            # Valid login + read-only login check + add-host + publish
            async with http.post(
                f"{srv.base_url}/login",
                json={"user": "auditor", "password": "SuperSecretPassword!99", "domain": "Branch", "read-only": True},
            ) as resp:
                assert resp.status == 200
                ro_sid = str((await resp.json())["sid"])
            async with http.post(f"{srv.base_url}/logout", headers={"X-chkp-sid": ro_sid}, json={}) as resp:
                assert resp.status == 200

            async with http.post(
                f"{srv.base_url}/login",
                json={"user": "admin", "password": "SuperSecretPassword!99", "domain": "Branch"},
            ) as resp:
                assert resp.status == 200
                sid = str((await resp.json())["sid"])

            # Cross-domain override inside a Branch-bound HTTPS session is rejected (400)
            async with http.post(
                f"{srv.base_url}/show-hosts",
                headers={"X-chkp-sid": sid},
                json={"domain": "Perimeter", "limit": 1},
            ) as resp:
                assert resp.status == 400
                assert (await resp.json())["code"] == "err_validation_failed"

            async with http.post(
                f"{srv.base_url}/add-host",
                headers={"X-chkp-sid": sid},
                json={"name": "H_Http_Ctrl", "ipv4-address": "10.220.1.10"},
            ) as resp:
                assert resp.status == 200

            async with http.post(f"{srv.base_url}/publish", headers={"X-chkp-sid": sid}, json={}) as resp:
                assert resp.status == 200
                pub_body = await resp.json()
                task_id = pub_body["task-id"]
                assert "uid" not in pub_body

            async with http.post(
                f"{srv.base_url}/show-task",
                headers={"X-chkp-sid": sid},
                json={"task-id": task_id},
            ) as resp:
                assert resp.status == 200
                task_json = (await resp.json())["tasks"][0]
                assert task_json["status"] == "succeeded"
                assert task_json["task-details"][0]["revision"]

            # GET /__testing__/call-log works with either active X-chkp-sid or test token & exposes full schema
            async with http.get(f"{root_url}/__testing__/call-log", headers={"X-chkp-sid": sid}) as resp:
                assert resp.status == 200
                calls_payload = await resp.json()
                add_calls = [c for c in calls_payload["calls"] if c.get("command") == "add-host"]
                assert add_calls
                required_keys = {
                    "mgmt_name",
                    "domain",
                    "command",
                    "is_mutating",
                    "sid_ref",
                    "session_uid",
                    "read_only_session",
                    "payload",
                    "payload_summary",
                    "status_code",
                    "success",
                    "error_code",
                }
                assert required_keys <= set(add_calls[0].keys())
                assert add_calls[0]["is_mutating"] is True
                assert add_calls[0]["status_code"] == 200
                assert add_calls[0]["read_only_session"] is False
                ro_logins = [
                    c for c in calls_payload["calls"] if c.get("command") == "login" and c["read_only_session"]
                ]
                assert ro_logins
                dumped = json.dumps(calls_payload)
                assert "SuperSecretPassword!99" not in dumped
                assert sid not in dumped
                assert srv.test_control_token not in dumped

            # POST /__testing__/restore reverts published H_Http_Ctrl and old sid
            async with http.post(
                f"{root_url}/__testing__/restore",
                headers=token_headers,
                json={"name": "clean"},
            ) as resp:
                assert resp.status == 200

            # Login cleanly and verify H_Http_Ctrl is gone
            async with http.post(
                f"{srv.base_url}/login",
                json={"user": "admin", "password": "SuperSecretPassword!99", "domain": "Branch"},
            ) as resp:
                assert resp.status == 200
                sid2 = str((await resp.json())["sid"])

            async with http.post(
                f"{srv.base_url}/show-host",
                headers={"X-chkp-sid": sid2},
                json={"name": "H_Http_Ctrl"},
            ) as resp:
                assert resp.status == 404

            # Logout invalidates sid2 for subsequent requests
            async with http.post(f"{srv.base_url}/logout", headers={"X-chkp-sid": sid2}, json={}) as resp:
                assert resp.status == 200
            async with http.post(
                f"{srv.base_url}/show-hosts",
                headers={"X-chkp-sid": sid2},
                json={"limit": 1},
            ) as resp:
                assert resp.status == 401
                assert (await resp.json())["code"] == "generic_err_invalid_session_id"

            # Reset clears call log & state
            async with http.post(f"{root_url}/__testing__/reset", headers=token_headers, json={}) as resp:
                assert resp.status == 200

    # 2. Server with enable_test_control=False returns 404 for all /__testing__/* endpoints
    async with CheckPointReplayHttpServer(host="127.0.0.1", port=0, enable_test_control=False) as srv_off:
        root_off = f"https://127.0.0.1:{srv_off.port}"
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as http:
            for method, path in (
                ("POST", "/__testing__/reset"),
                ("POST", "/__testing__/snapshot"),
                ("POST", "/__testing__/restore"),
                ("GET", "/__testing__/call-log"),
            ):
                async with http.request(method, f"{root_off}{path}") as resp:
                    assert resp.status == 404


@pytest.mark.spec("SCN-ITEST-015-1", "SCN-ITEST-016-1")
@pytest.mark.asyncio
async def test_snapshot_restore_reset_and_call_log_assertion_helpers() -> None:
    """Verify sub-second snapshot/restore/reset (including CLI overrides) and call_log assertion helpers."""
    api = FileReplayApiMock()
    snap_clean = api.snapshot_state()

    # Mutate domain objects, open work sessions, global assignments, and CLI overrides
    sid, _ = await api.create_dedicated_session("mds", "Branch", session_name="snap-test")
    assert (
        await api.api_call(
            "mds",
            "add-host",
            {"name": "H_Snap_Temp", "ipv4-address": "10.221.1.1"},
            domain="Branch",
            sid=sid,
        )
    ).success
    assert (await api.api_call("mds", "publish", {}, domain="Branch", sid=sid)).success

    mds_sid, _ = await api.create_dedicated_session("mds", "System Data")
    assert (
        await api.api_call(
            "mds",
            "assign-global-policy",
            {"dependent-domains": ["Branch"]},
            domain="System Data",
            sid=mds_sid,
        )
    ).success
    orig_ga_ts = (
        await api.api_call("mds", "show-global-assignment", {"dependent-domain": "Branch"}, domain="System Data")
    ).data["assignment-up-to-date"]["posix"]

    api.update_gateway_cli_stdout("br-spb-gw-01", "custom-route-override", vsid=0)
    api.cli_mock.fail_ssh_nodes.add("br-spb-gw-01")

    # Assertion helpers before violations
    assert api.get_calls(domain="Branch", command="add-host", mutating_only=True)
    api.assert_command_called("add-host", domain="Branch", times=1)
    api.assert_command_not_called("show-hosts", domain="Branch")
    api.assert_no_global_mutations()
    api.assert_no_full_object_scans()

    # Trigger full scan & Global mutation assertion failures
    assert (await api.api_call("mds", "show-hosts", {"limit": 5}, domain="Branch")).success
    with pytest.raises(AssertionError, match="full-object scan"):
        api.assert_no_full_object_scans()

    glob_sid, _ = await api.create_dedicated_session("mds", "Global")
    assert (
        await api.api_call(
            "mds",
            "add-host",
            {"name": "H_Glob_Audit", "ipv4-address": "10.253.99.99"},
            domain="Global",
            sid=glob_sid,
        )
    ).success
    with pytest.raises(AssertionError, match="Global domain"):
        api.assert_no_global_mutations()

    # Restore snapshot and verify rapid rollback across domain, sessions, global assignments, and CLI overrides
    t0 = time.perf_counter()
    api.restore_state(snap_clean)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert elapsed_ms < 200

    assert not (await api.api_call("mds", "show-host", {"name": "H_Snap_Temp"}, domain="Branch")).success
    assert "br-spb-gw-01" not in api.cli_mock.fail_ssh_nodes
    assert api.cli_mock.get_raw_cli_stdout("br-spb-gw-01", 0) != "custom-route-override"
    restored_ga_ts = (
        await api.api_call("mds", "show-global-assignment", {"dependent-domain": "Branch"}, domain="System Data")
    ).data["assignment-up-to-date"]["posix"]
    assert restored_ga_ts < orig_ga_ts

    # Verify reset() also restores clean baseline
    assert (
        await api.api_call(
            "mds",
            "add-host",
            {"name": "H_Reset_Temp", "ipv4-address": "10.221.2.2"},
            domain="Branch",
            sid=(await api.create_dedicated_session("mds", "Branch"))[0],
        )
    ).success
    api.reset()
    assert api.call_log == []
    assert not api._work_sessions


@pytest.mark.spec("SCN-ITEST-016-2")
@pytest.mark.asyncio
async def test_otel_spans_and_zero_sid_or_secret_leakage(request: pytest.FixtureRequest) -> None:
    """Verify OTEL spans record `arodonata.*` attributes/error status with zero raw SID or secret leaks."""
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

    api = FileReplayApiMock()
    secret_pw = "SentinelPass_X91_NeverLeak"
    secret_key = "SentinelKey_Z82_NeverLeak"

    login_pw = await api.api_call(
        "mds",
        "login",
        {"user": "secops", "password": secret_pw, "domain": "Branch"},
        domain="Branch",
    )
    assert login_pw.success
    sid_pw = str(login_pw.data["sid"])

    login_key = await api.api_call(
        "mds",
        "login",
        {"api-key": secret_key, "domain": "Branch"},
        domain="Branch",
    )
    assert login_key.success
    sid_key = str(login_key.data["sid"])

    sid_ded, _ = await api.create_dedicated_session("mds", "Branch")
    assert (
        await api.api_call(
            "mds",
            "add-host",
            {"name": "H_Otel_Ok", "ipv4-address": "10.222.1.1"},
            domain="Branch",
            sid=sid_ded,
        )
    ).success

    # Trigger an API failure (404) so an ERROR span is emitted
    err_res = await api.api_call("mds", "delete-host", {"uid": "nonexistent-uid-999"}, domain="Branch", sid=sid_ded)
    assert not err_res.success

    # Also invoke HTTPS endpoint through CheckPointReplayHttpServer
    async with CheckPointReplayHttpServer(api_mock=api, host="127.0.0.1", port=0) as srv:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as http:
            async with http.post(
                f"{srv.base_url}/show-host",
                headers={"X-chkp-sid": sid_pw},
                json={"uid": "uid-br-host-srv-001"},
            ) as resp:
                assert resp.status == 200

    spans = list(exporter.get_finished_spans())
    assert spans
    assert any("replay_mock" in s.name or "mock_server" in s.name for s in spans)
    assert any(s.status.status_code == StatusCode.ERROR for s in spans)
    assert any(any(k.startswith("arodonata.") for k in (s.attributes or {})) for s in spans)

    forbidden_tokens = (secret_pw, secret_key, sid_pw, sid_key, sid_ded)

    # Assert zero leaks in exported OTEL spans
    for sp in spans:
        serialized_span = json.dumps(
            {
                "name": sp.name,
                "attrs": dict(sp.attributes or {}),
                "status_desc": sp.status.description or "",
                "events": [{"name": ev.name, "attrs": dict(ev.attributes or {})} for ev in (sp.events or ())],
            },
            default=str,
        )
        for token in forbidden_tokens:
            assert token not in serialized_span, f"Leaked secret/SID in OTEL span: {sp.name}"

    # Assert zero leaks in call_log and repr()
    call_log_dump = json.dumps(api.call_log, default=str)
    repr_dump = repr(api) + " " + " ".join(repr(b) for b in api._sid_bindings.values())
    for token in forbidden_tokens:
        assert token not in call_log_dump
        assert token not in repr_dump
