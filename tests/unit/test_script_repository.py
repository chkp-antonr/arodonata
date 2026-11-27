"""Unit tests for Check Point Script Repository models, exceptions, service, and client facade."""

from __future__ import annotations

import base64
from typing import Any

import pytest
from pydantic import ValidationError as PydanticValidationError

import arodonata
from arodonata import (
    CpridScriptMode,
    EnsureRepositoryScriptResult,
    GatewayCliResult,
    GatewayRouteCollectionStatus,
    RepositoryScript,
    RepositoryScriptEnsureAction,
    RepositoryScriptError,
    RepositoryScriptExecutionOutcome,
    RepositoryScriptNotFoundError,
    RepositoryScriptPermissionError,
    RepositoryScriptStatus,
    ScriptTargetExecutionResult,
)
from arodonata.core.errors import REDACTED_PLACEHOLDER
from arodonata.core.models.scripts import normalize_script_body


def test_script_models_defaults_validation_and_reexports() -> None:
    """Verify Script Repository models, topology error_code fields, and top-level re-exports."""
    assert arodonata.RepositoryScript is RepositoryScript
    assert arodonata.RepositoryScriptError is RepositoryScriptError
    assert arodonata.RepositoryScriptNotFoundError is RepositoryScriptNotFoundError
    assert arodonata.RepositoryScriptPermissionError is RepositoryScriptPermissionError

    mode: CpridScriptMode = "repository"
    action: RepositoryScriptEnsureAction = "created"
    assert mode == "repository"
    assert action == "created"

    encoded_body = base64.b64encode(b"#!/bin/bash\necho ok\n").decode("ascii")
    script = RepositoryScript.from_cp_dict(
        "mds1",
        "FallbackDomain",
        {
            "uid": "uid-script-1",
            "name": "app-diag",
            "domain": {"name": "Corp"},
            "script-body-base64": encoded_body,
            "comments": "Diagnostics",
            "color": "green",
            "tags": [{"name": "ops"}, "ro"],
            "x-chkp-sid": "secret-sid-value-1234",
        },
    )
    assert script.uid == "uid-script-1"
    assert script.name == "app-diag"
    assert script.mgmt_name == "mds1"
    assert script.domain_name == "Corp"
    assert script.script_body == "#!/bin/bash\necho ok\n"
    assert script.tags == ["ops", "ro"]
    assert script.raw_data["x-chkp-sid"] == REDACTED_PLACEHOLDER

    assert normalize_script_body("echo 1  \r\necho 2\t\r\n\r\n") == "echo 1\necho 2"

    status = RepositoryScriptStatus(mgmt_name="mds1", domain_name="Corp", script_ref="app-diag", exists=False)
    assert status.script is None
    assert status.matches_expected is None
    assert status.error_code is None

    ensured = EnsureRepositoryScriptResult(
        mgmt_name="mds1",
        domain_name="Corp",
        action="unchanged",
        script=script,
    )
    assert ensured.published is False

    target_res = ScriptTargetExecutionResult(target="gw-01", success=True, stdout="ok")
    outcome = RepositoryScriptExecutionOutcome(
        mgmt_name="mds1",
        domain_name="Corp",
        script_ref="app-diag",
        success=True,
        targets=[target_res],
    )
    assert outcome.task_ids == []
    assert outcome.targets[0].target == "gw-01"

    cli_res = GatewayCliResult(success=False, executor="cprid", error_code="repository_script_not_found")
    assert cli_res.error_code == "repository_script_not_found"

    gw_status = GatewayRouteCollectionStatus(
        mgmt_name="mds1",
        domain_name="Corp",
        gateway_uid="uid-gw-1",
        gateway_name="gw-01",
        gateway_type="simple-gateway",
        success=False,
        error_code="repository_script_permission_denied",
        error="Permission denied",
    )
    assert gw_status.error_code == "repository_script_permission_denied"

    with pytest.raises(PydanticValidationError):
        EnsureRepositoryScriptResult(
            mgmt_name="mds1",
            domain_name="Corp",
            action="invalid",  # type: ignore[arg-type]
            script=script,
        )


def test_repository_script_exceptions_redact_sids_and_secrets() -> None:
    """Verify RepositoryScript* exceptions mask SIDs, API keys, and headers in messages."""
    raw_sid = "sid-top-secret-token-998877"
    not_found = RepositoryScriptNotFoundError(
        "mds1",
        "Corp",
        "arodonata-collect-routes-v1",
        message=f"Script missing while using X-chkp-sid: {raw_sid}",
        known_sids=[raw_sid],
    )
    assert isinstance(not_found, RepositoryScriptError)
    assert not_found.mgmt_name == "mds1"
    assert not_found.domain_name == "Corp"
    assert not_found.script_ref == "arodonata-collect-routes-v1"
    assert raw_sid not in str(not_found)
    assert REDACTED_PLACEHOLDER in str(not_found)

    perm_err = RepositoryScriptPermissionError(
        "mds1",
        "Corp",
        "app-diag",
        operation="run-script",
        message=f"Denied for sid={raw_sid} with 'api-key': 'super-secret-key'",
        known_sids=[raw_sid],
    )
    assert isinstance(perm_err, RepositoryScriptError)
    assert perm_err.operation == "run-script"
    assert raw_sid not in str(perm_err)
    assert "super-secret-key" not in str(perm_err)
    assert REDACTED_PLACEHOLDER in str(perm_err)


@pytest.mark.spec("SCN-CLIENT-010-2")
def test_non_overlay_mutation_targets_skip_session_overlay() -> None:
    """Verify repository-script and permission-profile mutations never pollute SessionOverlay."""
    from arodonata.adapters.checkpoint.client import NON_OVERLAY_MUTATION_TARGETS, _update_overlay_from_command
    from arodonata.core.context import SessionOverlay
    from arodonata.core.models.common import ApiCallResult

    for target in (
        "repository-script",
        "api-key",
        "md-permissions-profile",
        "domain-permissions-profile",
    ):
        assert target in NON_OVERLAY_MUTATION_TARGETS

    overlay = SessionOverlay("mds1", "Corp")
    for cmd in (
        "add-repository-script",
        "set-repository-script",
        "delete-repository-script",
        "add-api-key",
        "set-md-permissions-profile",
        "set-domain-permissions-profile",
    ):
        _update_overlay_from_command(
            overlay,
            cmd,
            {"name": "x", "uid": "uid-1"},
            ApiCallResult(success=True, status_code=200, data={"uid": "uid-1", "name": "x"}),
        )
    assert overlay.upserted_objects == {}
    assert overlay.deleted_object_uids == set()
    assert overlay.upserted_services == {}
    assert overlay.deleted_service_uids == set()


class _ScriptApiStub:
    """Minimal in-memory ApiPort stub for testing ScriptRepositoryService."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.scripts: dict[tuple[str, str], dict[str, dict[str, object]]] = {}
        self.staged: dict[str, dict[str, dict[str, object]]] = {}
        self.session_domains: dict[str, str] = {}
        self.read_only_sids: set[str] = set()
        self.logged_out_sids: list[str] = []
        self.invalidated: list[tuple[str, str | None]] = []
        self.deny_manage: bool = False
        self.deny_run: bool = False
        self.deny_publish: bool = False
        self.force_readonly_dedicated: bool = False
        self.unsupported_api: bool = False
        self.missing_targets: set[str] = set()
        self._seq = 0

    def _dom_key(self, domain: str | None) -> str:
        return domain.strip() if domain and domain.strip() else "System Data"

    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        payload: dict[str, object] | None = None,
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ):
        from arodonata.core.context import get_write_session
        from arodonata.core.models.common import ApiCallResult

        _ = (server_ip, wait_for_task, timeout)
        req = dict(payload or {})
        dom = self._dom_key(domain)
        active_ws = get_write_session(mgmt_name=mgmt_name, domain_name=dom)
        eff_sid = sid or (active_ws.sid if active_ws is not None else None)
        self.calls.append({"mgmt": mgmt_name, "command": command, "domain": dom, "sid": eff_sid, "payload": req})

        if self.unsupported_api and command in (
            "show-repository-script",
            "add-repository-script",
            "set-repository-script",
            "delete-repository-script",
        ):
            return ApiCallResult(
                success=False,
                status_code=400,
                error_code="generic_err_command_not_found",
                error_message=f"Requested API command: [{command}] not found",
                data={
                    "code": "generic_err_command_not_found",
                    "message": f"Requested API command: [{command}] not found",
                },
            )

        if command == "publish":
            if self.deny_publish:
                return ApiCallResult(
                    success=False,
                    status_code=400,
                    error_code="generic_err_no_permissions",
                    error_message="No permission to publish session",
                    data={"code": "generic_err_no_permissions", "message": "No permission to publish session"},
                )
            if eff_sid and eff_sid in self.staged:
                self.scripts[(mgmt_name, dom)] = dict(self.staged[eff_sid])
            return ApiCallResult(success=True, status_code=200, data={"tasks": [{"status": "succeeded"}]})

        if command == "discard":
            if eff_sid and eff_sid in self.staged:
                self.staged.pop(eff_sid, None)
            return ApiCallResult(success=True, status_code=200, data={"message": "OK"})

        store = (
            self.staged[eff_sid]
            if (eff_sid and eff_sid in self.staged)
            else self.scripts.setdefault((mgmt_name, dom), {})
        )

        if command == "show-repository-script":
            ref = str(req.get("uid") or req.get("name") or "")
            for item in store.values():
                if item.get("name") == ref or item.get("uid") == ref:
                    return ApiCallResult(success=True, status_code=200, data=dict(item))
            return ApiCallResult(
                success=False,
                status_code=404,
                error_code="generic_err_object_not_found",
                error_message=f"Requested object [{ref}] not found",
                data={"code": "generic_err_object_not_found", "message": f"Requested object [{ref}] not found"},
            )

        if command == "add-repository-script":
            if self.deny_manage:
                return ApiCallResult(
                    success=False,
                    status_code=400,
                    error_code="generic_err_no_permissions",
                    error_message="Permission denied to manage repository scripts",
                    data={"code": "generic_err_no_permissions", "message": "Permission denied"},
                )
            name = str(req["name"])
            if name in store:
                return ApiCallResult(
                    success=False,
                    status_code=400,
                    error_code="err_validation_failed",
                    error_message=f"More than one object named [{name}] exists",
                    data={"code": "err_validation_failed", "message": f"More than one object named [{name}] exists"},
                )
            self._seq += 1
            obj = {
                "uid": f"11111111-1111-4111-8111-{self._seq:012d}",
                "name": name,
                "type": "repository-script",
                "domain": {"name": dom},
                "script-body": req["script-body"],
                "comments": req.get("comments", ""),
                "color": req.get("color", "black"),
                "tags": req.get("tags", []),
            }
            store[name] = obj
            return ApiCallResult(success=True, status_code=200, data=dict(obj))

        if command == "set-repository-script":
            if self.deny_manage:
                return ApiCallResult(
                    success=False,
                    status_code=400,
                    error_code="generic_err_no_permissions",
                    error_message="Permission denied to manage repository scripts",
                    data={"code": "generic_err_no_permissions", "message": "Permission denied"},
                )
            ref = str(req.get("uid") or req.get("name") or "")
            found_key = next((k for k, v in store.items() if v.get("name") == ref or v.get("uid") == ref), None)
            if found_key is None:
                return ApiCallResult(
                    success=False,
                    status_code=404,
                    error_code="generic_err_object_not_found",
                    error_message=f"Requested object [{ref}] not found",
                )
            obj = dict(store[found_key])
            obj["script-body"] = req.get("script-body", obj.get("script-body", ""))
            if "comments" in req:
                obj["comments"] = req["comments"]
            if "color" in req:
                obj["color"] = req["color"]
            if "tags" in req:
                obj["tags"] = list(req["tags"]) if isinstance(req["tags"], list) else req["tags"]
            store[found_key] = obj
            return ApiCallResult(success=True, status_code=200, data=dict(obj))

        if command == "delete-repository-script":
            if self.deny_manage:
                return ApiCallResult(
                    success=False,
                    status_code=400,
                    error_code="generic_err_no_permissions",
                    error_message="Permission denied to delete repository scripts",
                    data={"code": "generic_err_no_permissions", "message": "Permission denied"},
                )
            ref = str(req.get("uid") or req.get("name") or "")
            found_key = next((k for k, v in store.items() if v.get("name") == ref or v.get("uid") == ref), None)
            if found_key is None:
                return ApiCallResult(
                    success=False,
                    status_code=404,
                    error_code="generic_err_object_not_found",
                    error_message=f"Requested object [{ref}] not found",
                )
            store.pop(found_key)
            return ApiCallResult(success=True, status_code=200, data={"message": "OK"})

        if command == "run-script":
            if eff_sid is None or eff_sid in self.read_only_sids:
                return ApiCallResult(
                    success=False,
                    status_code=400,
                    error_code="err_validation_failed",
                    error_message="Operation is not allowed in read only mode",
                    data={"code": "err_validation_failed", "message": "Operation is not allowed in read only mode"},
                )
            if self.deny_run:
                return ApiCallResult(
                    success=False,
                    status_code=400,
                    error_code="generic_err_no_permissions",
                    error_message="No permission to run action",
                    data={"code": "generic_err_no_permissions", "message": "No permission to run action"},
                )
            ref = str(req.get("uid") or req.get("script-name") or "")
            published = self.scripts.get((mgmt_name, dom), {})
            found = next((v for v in published.values() if v.get("name") == ref or v.get("uid") == ref), None)
            if found is None:
                return ApiCallResult(
                    success=False,
                    status_code=404,
                    error_code="generic_err_object_not_found",
                    error_message=f"Requested object [{ref}] not found",
                    data={"code": "generic_err_object_not_found", "message": f"Requested object [{ref}] not found"},
                )
            targets = list(req.get("targets") or [])  # type: ignore[arg-type]
            missing_tgt = next((str(t) for t in targets if str(t) in self.missing_targets), None)
            if missing_tgt is not None:
                return ApiCallResult(
                    success=False,
                    status_code=404,
                    error_code="generic_err_object_not_found",
                    error_message=f"Requested object [{missing_tgt}] not found",
                    data={
                        "code": "generic_err_object_not_found",
                        "message": f"Requested object [{missing_tgt}] not found",
                    },
                )
            args_val = str(req.get("args") or "")
            tasks = []
            for idx, tgt in enumerate(targets, start=1):
                msg_b64 = base64.b64encode(f"{tgt}:{args_val}\n".encode()).decode("ascii")
                tasks.append(
                    {
                        "task-id": f"task-{idx}",
                        "status": "succeeded",
                        "task-details": [
                            {
                                "gatewayName": tgt,
                                "gatewayId": f"uid-{tgt}",
                                "statusCode": "succeeded",
                                "statusDescription": "Succeeded",
                                "responseMessage": msg_b64,
                                "responseError": "",
                                "revision": "42",
                            }
                        ],
                    }
                )
            return ApiCallResult(success=True, status_code=200, data={"tasks": tasks})

        raise AssertionError(f"Unexpected command {command}")

    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        *,
        domain: str | None = None,
        details_level: str = "standard",
        payload: dict[str, object] | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        limit: int = 300,
    ):
        from arodonata.core.models.common import ApiQueryResult

        _ = (details_level, payload, sid, server_ip, limit)
        dom = self._dom_key(domain)
        self.calls.append({"mgmt": mgmt_name, "command": command, "domain": dom})
        items = list(self.scripts.get((mgmt_name, dom), {}).values())
        return ApiQueryResult(success=True, objects=[dict(i) for i in items], total=len(items))

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth=None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        _ = (auth, session_name, session_description)
        self._seq += 1
        dom = self._dom_key(domain)
        sid = f"ded-sid-{self._seq}"
        self.session_domains[sid] = dom
        if self.force_readonly_dedicated:
            self.read_only_sids.add(sid)
        else:
            self.staged[sid] = dict(self.scripts.get((mgmt_name, dom), {}))
        return sid, "127.0.0.1"

    async def logout_sid(self, mgmt_name: str, sid: str, *, server_ip: str | None = None) -> bool:
        _ = (mgmt_name, server_ip)
        self.logged_out_sids.append(sid)
        self.staged.pop(sid, None)
        return True

    async def close(self, *, logout: bool | None = None) -> None:
        _ = logout

    def invalidate_domain(self, mgmt_name: str, domain: str | None = None) -> None:
        self.invalidated.append((mgmt_name, domain))


@pytest.mark.spec("SCN-CLIENT-010-1", "SCN-CLIENT-010-2", "SCN-CLIENT-012-1")
async def test_script_repository_service_crud_fast_path_and_execution() -> None:
    """Verify ScriptRepositoryService read-only checks, zero-publish fast path, WriteSession isolation, and run_repository_script."""
    from arodonata.core.context import SessionOverlay, WriteSession, write_session_context
    from arodonata.core.services import ScriptRepositoryService

    stub = _ScriptApiStub()
    svc = ScriptRepositoryService(api=stub)

    # 1. Missing check runs read-only without opening a WriteSession
    missing = await svc.check_repository_script("mds1", "app-diag", domain="Corp", expected_body="echo ok\n")
    assert missing.exists is False
    assert missing.matches_expected is False
    assert missing.error_code == "repository_script_not_found"
    assert stub.session_domains == {}

    # 2. Standalone ensure creates and publishes
    created = await svc.ensure_repository_script(
        "mds1",
        "app-diag",
        "echo ok\n",
        domain="Corp",
        comments="App diagnostic",
    )
    assert created.action == "created"
    assert created.published is True
    assert created.script.name == "app-diag"
    assert created.script.uid
    assert ("mds1", "Corp") in stub.invalidated
    assert len(stub.logged_out_sids) == 1
    assert [c["command"] for c in stub.calls if c["command"] in ("add-repository-script", "publish")] == [
        "add-repository-script",
        "publish",
    ]

    # 3. Fast path with CRLF / trailing whitespace differences performs zero writes / zero publish
    stub.calls.clear()
    fast = await svc.ensure_repository_script("mds1", "app-diag", "echo ok  \r\n\r\n", domain="Corp")
    assert fast.action == "unchanged"
    assert fast.published is False
    assert [c["command"] for c in stub.calls] == ["show-repository-script"]

    # 4. Update when body changes
    updated = await svc.ensure_repository_script("mds1", "app-diag", "echo v2\n", domain="Corp")
    assert updated.action == "updated"
    assert updated.published is True
    assert updated.script.script_body == "echo v2\n"

    # 5. Inside an active WriteSession, ensure reuses session without auto-publish or SessionOverlay pollution
    stub.calls.clear()
    ws_sid, ws_ip = await stub.create_dedicated_session("mds1", domain="Corp")
    overlay = SessionOverlay("mds1", "Corp")
    ws = WriteSession(mgmt_name="mds1", domain_name="Corp", sid=ws_sid, server_ip=ws_ip, overlay=overlay)
    with write_session_context(ws):
        in_ws = await svc.ensure_repository_script("mds1", "ws-only-script", "echo ws\n", domain="Corp")
        assert in_ws.action == "created"
        assert in_ws.published is False
    assert not any(c["command"] == "publish" for c in stub.calls)
    assert overlay.upserted_objects == {}
    assert overlay.upserted_services == {}

    # 6. List and get
    listed = await svc.list_repository_scripts("mds1", domain="Corp")
    assert [s.name for s in listed] == ["app-diag"]
    fetched = await svc.get_repository_script("mds1", created.script.uid, domain="Corp")
    assert fetched.name == "app-diag"

    # 7. Universal run_repository_script: forwards args verbatim or space-joined, no publish/discard, multi-target
    stub.calls.clear()
    outcome = await svc.run_repository_script(
        "mds1",
        "app-diag",
        ["gw-01", "gw-02"],
        domain="Corp",
        args=["--mode", "fast"],
        comments="Health check",
        script_timeout=60,
    )
    assert outcome.success is True
    assert outcome.args == "--mode fast"
    assert outcome.task_ids == ["task-1", "task-2"]
    assert len(outcome.targets) == 2
    assert outcome.targets[0].stdout == "gw-01:--mode fast\n"
    assert outcome.targets[1].stdout == "gw-02:--mode fast\n"
    assert outcome.targets[0].revision == "42"
    run_calls = [c for c in stub.calls if c["command"] == "run-script"]
    assert len(run_calls) == 1
    sent_payload = run_calls[0]["payload"]
    assert sent_payload == {
        "script-name": "app-diag",
        "script-type": "repository",
        "targets": ["gw-01", "gw-02"],
        "args": "--mode fast",
        "comments": "Health check",
        "timeout": 60,
    }
    assert "script" not in sent_payload  # type: ignore[operator]
    assert "script-base64" not in sent_payload  # type: ignore[operator]
    assert not any(c["command"] in ("publish", "discard") for c in stub.calls)

    # UUID script ref sends "uid" instead of "script-name" and forwards string args verbatim
    uuid_outcome = await svc.run_repository_script(
        "mds1",
        created.script.uid,
        "gw-01",
        domain="Corp",
        args="--raw   verbatim",
    )
    assert uuid_outcome.success is True
    last_payload = [c for c in stub.calls if c["command"] == "run-script"][-1]["payload"]
    assert last_payload["uid"] == created.script.uid  # type: ignore[index]
    assert "script-name" not in last_payload  # type: ignore[operator]
    assert last_payload["args"] == "--raw   verbatim"  # type: ignore[index]

    # 8. Delete script
    assert await svc.delete_repository_script("mds1", "app-diag", domain="Corp") is True
    assert await svc.list_repository_scripts("mds1", domain="Corp") == []


@pytest.mark.spec("SCN-CLIENT-012-3")
async def test_script_repository_service_error_mappings() -> None:
    """Verify missing script, permission denial, and read-only session rejections map cleanly."""
    from arodonata.core.services import ScriptRepositoryService

    stub = _ScriptApiStub()
    svc = ScriptRepositoryService(api=stub)

    with pytest.raises(RepositoryScriptNotFoundError):
        await svc.run_repository_script("mds1", "missing-script", ["gw-01"], domain="Corp")

    await svc.ensure_repository_script("mds1", "app-diag", "echo ok\n", domain="Corp")

    stub.force_readonly_dedicated = True
    with pytest.raises(RepositoryScriptPermissionError):
        await svc.run_repository_script("mds1", "app-diag", ["gw-01"], domain="Corp")
    stub.force_readonly_dedicated = False

    stub.deny_run = True
    with pytest.raises(RepositoryScriptPermissionError):
        await svc.run_repository_script("mds1", "app-diag", ["gw-01"], domain="Corp")
    stub.deny_run = False

    stub.deny_manage = True
    stub.calls.clear()
    with pytest.raises(RepositoryScriptPermissionError):
        await svc.ensure_repository_script("mds1", "new-script", "echo 1\n", domain="Corp")
    assert any(c["command"] == "discard" for c in stub.calls)

    stub.deny_manage = False
    stub.deny_publish = True
    with pytest.raises(RepositoryScriptPermissionError):
        await svc.ensure_repository_script("mds1", "new-script", "echo 1\n", domain="Corp")


@pytest.mark.spec("SCN-CLIENT-010-2", "SCN-CLIENT-012-1")
async def test_client_facade_script_repository_traced_and_custom_api_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify ArodonataClient repository script facade, write_session forwarding, @traced SID redaction, and arbitrary args."""
    import inspect

    from opentelemetry import trace

    from arodonata import ArodonataClient, ArodonataSettings
    from arodonata.core.telemetry import set_trace_modules

    stub = _ScriptApiStub()
    settings = ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="127.0.0.1",
        api_key="client-secret-api-key",
        database_url="sqlite+aiosqlite:///:memory:",
    )

    recorded_spans: list[dict[str, object]] = []

    class _FakeSpan:
        def __init__(self) -> None:
            self.attrs: dict[str, object] = {}

        def is_recording(self) -> bool:
            return True

        def get_span_context(self):
            return trace.INVALID_SPAN_CONTEXT

        def set_attribute(self, key: str, value: object) -> None:
            self.attrs[key] = value
            recorded_spans.append({key: value})

        def set_status(self, *_args, **_kwargs) -> None:
            return None

    fake_span = _FakeSpan()
    monkeypatch.setattr(trace, "get_current_span", lambda *_args, **_kwargs: fake_span)
    set_trace_modules({"arodonata": True})

    try:
        async with ArodonataClient(settings=settings, api=stub) as client:
            # Verify facade signatures match spec contracts
            sig = inspect.signature(client.run_repository_script)
            assert list(sig.parameters.keys()) == [
                "mgmt_name",
                "script_name_or_uid",
                "targets",
                "domain",
                "args",
                "comments",
                "timeout",
                "script_timeout",
            ]

            checked = await client.check_repository_script("mds1", "app-custom-diag", domain="Corp")
            assert checked.exists is False

            ensured = await client.ensure_repository_script(
                "mds1",
                "app-custom-diag",
                '#!/bin/bash\necho custom "$@"\n',
                domain="Corp",
                comments="Custom app diag",
            )
            assert ensured.action == "created"
            assert ensured.published is True

            # Re-run ensure inside custom ApiPort write_session forwarding -> no publish inside block
            async with client.write_session("mds1", "Corp") as ws:
                assert ws.sid not in str(recorded_spans)
                updated = await client.ensure_repository_script(
                    "mds1",
                    "app-custom-diag",
                    "#!/bin/bash\necho v2\n",
                    domain="Corp",
                )
                assert updated.action == "updated"
                assert updated.published is False

            listed = await client.list_repository_scripts("mds1", domain="Corp")
            assert [s.name for s in listed] == ["app-custom-diag"]
            fetched = await client.get_repository_script("mds1", "app-custom-diag", domain="Corp")
            assert fetched.script_body == "#!/bin/bash\necho v2\n"

            # Arbitrary caller args forwarding (both Sequence[str] and verbatim str)
            run_seq = await client.run_repository_script(
                "mds1",
                "app-custom-diag",
                ["gw-01", "gw-02"],
                domain="Corp",
                args=["--mode", "fast"],
            )
            assert run_seq.success is True
            assert run_seq.args == "--mode fast"
            assert [t.stdout for t in run_seq.targets] == ["gw-01:--mode fast\n", "gw-02:--mode fast\n"]

            run_str = await client.run_repository_script(
                "mds1",
                "app-custom-diag",
                "gw-01",
                domain="Corp",
                args="arg1  arg2",
            )
            assert run_str.success is True
            assert run_str.args == "arg1  arg2"

            # Verify @traced span attributes never leaked any SID or API key
            serialized_attrs = str(recorded_spans)
            assert "ded-sid-" not in serialized_attrs
            assert "client-secret-api-key" not in serialized_attrs

            # Verify @traced scrubs SID patterns even from errors
            stub.deny_run = True
            with pytest.raises(RepositoryScriptPermissionError) as exc_info:
                await client.run_repository_script("mds1", "app-custom-diag", ["gw-01"], domain="Corp")
            assert "ded-sid-" not in str(exc_info.value)

            stub.deny_run = False
            assert await client.delete_repository_script("mds1", "app-custom-diag", domain="Corp") is True
    finally:
        set_trace_modules(None)


@pytest.mark.spec("SCN-CLIENT-008-2")
async def test_concurrent_cross_domain_route_collection_and_script_provisioning() -> None:
    """Verify collect_gateway_routes(domain='Branch') runs concurrently with ensure_route_collection_script('Regional') without session bleed."""
    import asyncio

    from arodonata import ArodonataClient, ArodonataSettings
    from arodonata.testing import FileReplayApiMock

    api_mock = FileReplayApiMock()
    settings = ArodonataSettings(
        mgmt_name="mds",
        mgmt_ip="127.0.0.1",
        api_key="mock-key",
        database_url="sqlite+aiosqlite:///:memory:",
    )

    async with ArodonataClient(settings=settings, api=api_mock) as client:
        await client.refresh_assets(mgmt_name="mds", domains=["Branch", "Regional"], mode="force")
        pre_branch = await client.ensure_route_collection_script("mds", "Branch")
        assert pre_branch.action == "created"
        api_mock.reset_counters()

        collect_task = client.collect_gateway_routes(
            mgmt_name="mds",
            domain="Branch",
            gateways=["br-spb-gw-01", "br-reg-gw-002"],
            cprid_script_mode="repository",
        )
        ensure_task = client.ensure_route_collection_script("mds", "Regional")
        route_outcome, ensure_res = await asyncio.gather(collect_task, ensure_task)

        assert route_outcome.succeeded_gateways == 2
        assert route_outcome.failed_gateways == 0
        assert ensure_res.action == "created"
        assert ensure_res.published is True

        # Ensure Branch run-script never polluted Regional and Regional publish stayed isolated in Regional
        branch_publishes = api_mock.get_calls(domain="Branch", command="publish")
        regional_publishes = api_mock.get_calls(domain="Regional", command="publish")
        assert branch_publishes == []
        assert len(regional_publishes) == 1

        reg_status = await client.check_route_collection_script("mds", "Regional")
        assert reg_status.exists is True
        assert reg_status.matches_expected is True


async def test_system_data_write_session_matching_and_cross_domain_isolation() -> None:
    """Verify `'System Data'` / `domain=None` matches `'System Data'` WriteSessions without bleeding across domains."""
    from arodonata import ArodonataClient, ArodonataSettings
    from arodonata.core.services import ScriptRepositoryService

    stub = _ScriptApiStub()
    settings = ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="127.0.0.1",
        api_key="test-key",
        database_url="sqlite+aiosqlite:///:memory:",
    )

    async with ArodonataClient(settings=settings, api=stub) as client:
        # 1. Explicit 'System Data' WriteSession is reused by both domain='System Data' and domain=None
        async with client.write_session("mds1", "System Data") as ws_sys:
            assert ws_sys.domain_name == "System Data"
            r1 = await client.ensure_repository_script("mds1", "sys-one", "echo 1\n", domain="System Data")
            r2 = await client.ensure_repository_script("mds1", "sys-two", "echo 2\n")
            assert r1.published is False
            assert r2.published is False
            assert r1.domain_name == "System Data"
            assert not any(c["command"] == "publish" for c in stub.calls)

        # 2. Active WriteSession on DomainB MUST NOT capture domain=None ('System Data') mutations
        stub.calls.clear()
        async with client.write_session("mds1", "DomainB") as ws_b:
            assert ws_b.domain_name == "DomainB"
            iso_res = await client.ensure_repository_script("mds1", "sys-isolated", "echo iso\n")
            assert iso_res.action == "created"
            assert iso_res.published is True
            assert iso_res.domain_name == "System Data"

            sys_adds = [c for c in stub.calls if c["command"] == "add-repository-script"]
            assert len(sys_adds) == 1
            assert sys_adds[0]["domain"] == "System Data"
            assert sys_adds[0]["sid"] != ws_b.sid
            assert not any(
                s.name == "sys-isolated" for s in await client.list_repository_scripts("mds1", domain="DomainB")
            )

    # 3. Standalone ScriptRepositoryService without factory opens 'System Data' WriteSession cleanly
    stub2 = _ScriptApiStub()
    svc = ScriptRepositoryService(api=stub2)
    standalone = await svc.ensure_repository_script("mds1", "svc-sys", "echo svc\n")
    assert standalone.action == "created"
    assert standalone.published is True
    assert standalone.domain_name == "System Data"
    assert list(stub2.session_domains.values()) == ["System Data"]


@pytest.mark.spec("SCN-CLIENT-010-1", "SCN-CLIENT-010-2")
async def test_audit_regression_fixes_decoding_targets_metadata_and_permissions() -> None:
    """Verify lenient Base64 decoding, target-vs-script not-found split, unsupported command handling, session_getter errors, and metadata fast-path."""
    from arodonata.core.errors import RepositoryScriptError, SessionError
    from arodonata.core.models.scripts import decode_base64_task_message
    from arodonata.core.services import ScriptRepositoryService

    # 1. Lenient UTF-8 + control char decoding preserves route markers without dropping output
    raw_bytes = b"10.0.0.0/24 dev eth0  # comment \xe9\xff \x1b[32mok\x1b[0m\x00\n===ARODONATA_IP_ROUTE_END===\n"
    b64_payload = base64.b64encode(raw_bytes).decode("ascii")
    decoded = decode_base64_task_message(b64_payload)
    assert "===ARODONATA_IP_ROUTE_END===" in decoded
    assert "10.0.0.0/24 dev eth0" in decoded
    assert decode_base64_task_message("OK") == "OK"
    assert decode_base64_task_message("Failed") == "Failed"
    assert decode_base64_task_message("Error") == "Error"

    # 2. Target object not found during run-script raises RepositoryScriptError (not RepositoryScriptNotFoundError)
    stub = _ScriptApiStub()
    svc = ScriptRepositoryService(api=stub)
    await svc.ensure_repository_script(
        "mds1",
        "app-diag",
        "echo ok\n",
        domain="Corp",
        comments="init",
        color="blue",
        tags=["t1"],
    )
    stub.missing_targets.add("stale-gw-01")
    with pytest.raises(RepositoryScriptError) as target_exc:
        await svc.run_repository_script("mds1", "app-diag", ["stale-gw-01"], domain="Corp")
    assert not isinstance(target_exc.value, RepositoryScriptNotFoundError)

    # 3. Pre-R81.20 unsupported command maps cleanly in check and ensure
    stub.unsupported_api = True
    unsupported_status = await svc.check_repository_script("mds1", "app-diag", domain="Corp")
    assert unsupported_status.exists is False
    assert unsupported_status.error_code == "repository_script_unsupported"
    with pytest.raises(RepositoryScriptError) as unsup_exc:
        await svc.ensure_repository_script("mds1", "app-diag", "echo ok\n", domain="Corp")
    assert not isinstance(unsup_exc.value, RepositoryScriptNotFoundError)
    stub.unsupported_api = False

    # 4. session_getter permission failures map to RepositoryScriptPermissionError
    async def _denied_getter(_mgmt: str, _dom: str | None) -> tuple[str, str]:
        raise SessionError("Permission denied to open dedicated session")

    with pytest.raises(RepositoryScriptPermissionError):
        await svc.run_repository_script(
            "mds1",
            "app-diag",
            ["gw-01"],
            domain="Corp",
            session_getter=_denied_getter,
        )

    # 5. Fast-path checks explicit comments/color/tags when provided
    same_meta = await svc.ensure_repository_script(
        "mds1",
        "app-diag",
        "echo ok\r\n",
        domain="Corp",
        comments="init",
        color="blue",
        tags=["t1"],
    )
    assert same_meta.action == "unchanged"
    assert same_meta.published is False

    new_comment = await svc.ensure_repository_script(
        "mds1",
        "app-diag",
        "echo ok\n",
        domain="Corp",
        comments="Managed by FPCR",
        color="red",
        tags=["t2", "t1"],
    )
    assert new_comment.action == "updated"
    assert new_comment.published is True
    assert new_comment.script.comments == "Managed by FPCR"
    assert new_comment.script.color == "red"
    assert sorted(new_comment.script.tags) == ["t1", "t2"]


def test_repository_script_body_base64_decoding_and_short_token_regressions() -> None:
    """Verify _decode_repository_script_body and RepositoryScript.from_cp_dict handle R82 base64 and preserve short tokens."""
    import base64

    from arodonata.core.models.scripts import RepositoryScript, _decode_repository_script_body

    # 1. Short plaintext tokens that must never be decoded as Base64
    for short_token in ("ls", "date", "show", "test", "hostname", "exit 0", "echo ok\n"):
        assert _decode_repository_script_body(short_token) == short_token
        script = RepositoryScript.from_cp_dict("mds1", "Corp", {"name": "s1", "script-body": short_token})
        assert script.script_body == short_token

    # 2. Multiline bash script passed in plaintext remains unchanged
    bash_script = "#!/bin/bash\necho 'hello world'\nexit 0\n"
    assert _decode_repository_script_body(bash_script) == bash_script
    script = RepositoryScript.from_cp_dict("mds1", "Corp", {"name": "s1", "script-body": bash_script})
    assert script.script_body == bash_script

    # 3. Check Point R82 Base64-encoded script-body decodes cleanly to UTF-8
    b64_payload = base64.b64encode(bash_script.encode("utf-8")).decode("ascii")
    assert _decode_repository_script_body(b64_payload) == bash_script
    r82_script = RepositoryScript.from_cp_dict("mds1", "Corp", {"name": "r82_script", "script-body": b64_payload})
    assert r82_script.script_body == bash_script

    # 4. Check Point legacy script-body-base64 continues to work when script-body is absent
    b64_legacy = RepositoryScript.from_cp_dict("mds1", "Corp", {"name": "legacy_s1", "script-body-base64": b64_payload})
    assert b64_legacy.script_body == bash_script


@pytest.mark.spec("SCN-CLIENT-012-1", "SCN-CLIENT-012-3")
async def test_script_repository_boundary_models_and_session_branches_redact_sids() -> None:
    """SCN-CLIENT-012-1 & SCN-CLIENT-012-3 (DA-011): Scrub patterned and bare SIDs across outputs and all session exception branches."""
    from arodonata.core.context import SessionOverlay, WriteSession, write_session_context
    from arodonata.core.models.common import ApiCallResult
    from arodonata.core.services.script_service import ScriptRepositoryService

    # 1. Model boundaries scrub patterned SIDs in stdout and status_description
    tgt = ScriptTargetExecutionResult(
        target="gw-01",
        success=True,
        stdout="ok X-chkp-sid: PatOutSid1234",
        status_description="desc Authorization: Bearer PatDescTok5678",
    )
    assert "PatOutSid1234" not in tgt.stdout
    assert "PatDescTok5678" not in tgt.status_description
    assert REDACTED_PLACEHOLDER in tgt.stdout
    assert REDACTED_PLACEHOLDER in tgt.status_description

    out = RepositoryScriptExecutionOutcome(
        mgmt_name="mds1",
        domain_name="Corp",
        script_ref="app-diag",
        success=True,
        stdout='{"sid": "PatOutcomeSid999"}',
    )
    assert "PatOutcomeSid999" not in out.stdout
    assert REDACTED_PLACEHOLDER in out.stdout

    # 2. run_repository_script scrubs bare dedicated SID from responseMessage and statusDescription
    stub = _ScriptApiStub()
    ded_token = "DedBareSidToken7788"

    class _LeakOutputApi(_ScriptApiStub):
        async def create_dedicated_session(
            self, mgmt_name: str, domain: str | None = None, **kw: object
        ) -> tuple[str, str]:
            self.calls.append({"command": "create_dedicated_session", "mgmt": mgmt_name, "domain": domain})
            return ded_token, "10.0.0.1"

        async def api_call(
            self, mgmt_name: str, command: str, payload: dict[str, object] | None = None, **kw: object
        ) -> ApiCallResult:
            if command == "run-script":
                return ApiCallResult(
                    success=True,
                    status_code=200,
                    data={
                        "tasks": [
                            {
                                "task-id": "t-leak",
                                "status": "succeeded",
                                "task-details": [
                                    {
                                        "gatewayName": "gw-01",
                                        "statusCode": "succeeded",
                                        "responseMessage": f"out={ded_token}",
                                        "statusDescription": f"status={ded_token}",
                                    }
                                ],
                            }
                        ]
                    },
                )
            return await super().api_call(mgmt_name, command, payload, **kw)  # type: ignore[arg-type]

    leak_api = _LeakOutputApi()
    svc = ScriptRepositoryService(api=leak_api)  # type: ignore[arg-type]
    run_res = await svc.run_repository_script("mds1", "app-diag", ["gw-01"], domain="Corp")
    assert ded_token not in run_res.stdout
    assert ded_token not in run_res.targets[0].stdout
    assert ded_token not in run_res.targets[0].status_description
    assert REDACTED_PLACEHOLDER in run_res.stdout

    # 3. Non-dedicated branches (WriteSession, explicit sid, session_getter) scrub bare SID on exception
    class _ExcApi(_ScriptApiStub):
        def __init__(self, msg_sid: str) -> None:
            super().__init__()
            self._msg_sid = msg_sid

        async def api_call(
            self, mgmt_name: str, command: str, payload: dict[str, object] | None = None, **kw: object
        ) -> ApiCallResult:
            raise RuntimeError(f"boom while calling with {self._msg_sid}")

    ws_sid = "WsActiveBareSid4321"
    ws = WriteSession(
        mgmt_name="mds1", domain_name="Corp", sid=ws_sid, server_ip="10.1.0.1", overlay=SessionOverlay("mds1", "Corp")
    )
    ws_svc = ScriptRepositoryService(api=_ExcApi(ws_sid))  # type: ignore[arg-type]
    with write_session_context(ws):
        with pytest.raises(RepositoryScriptError) as ws_exc:
            await ws_svc.run_repository_script("mds1", "app-diag", ["gw-01"], domain="Corp")
    assert ws_sid not in str(ws_exc.value)
    assert REDACTED_PLACEHOLDER in str(ws_exc.value)

    explicit_sid = "ExplicitBareSid6543"
    exp_svc = ScriptRepositoryService(api=_ExcApi(explicit_sid))  # type: ignore[arg-type]
    with pytest.raises(RepositoryScriptError) as exp_exc:
        await exp_svc.run_repository_script("mds1", "app-diag", ["gw-01"], domain="Corp", sid=explicit_sid)
    assert explicit_sid not in str(exp_exc.value)
    assert REDACTED_PLACEHOLDER in str(exp_exc.value)

    getter_sid = "GetterBareSid9876"
    get_svc = ScriptRepositoryService(api=_ExcApi(getter_sid))  # type: ignore[arg-type]

    async def _getter(_m: str, _d: str | None) -> tuple[str, str]:
        return getter_sid, "10.0.0.1"

    with pytest.raises(RepositoryScriptError) as get_exc:
        await get_svc.run_repository_script("mds1", "app-diag", ["gw-01"], domain="Corp", session_getter=_getter)
    assert getter_sid not in str(get_exc.value)
    assert REDACTED_PLACEHOLDER in str(get_exc.value)
    _ = stub


@pytest.mark.spec("SCN-SESS-013-2")
async def test_decomposed_run_script_and_route_collection_helpers() -> None:
    """Verify `_invoke_run_script_with_session`/`_decode_run_script_tasks` and route collection helpers preserve SID redaction and coalescing."""
    from datetime import UTC, datetime

    from arodonata.core.models.common import ApiCallResult
    from arodonata.core.models.topology import GatewayCliResult, GatewayRouteCollectionStatus
    from arodonata.core.services.script_service import (
        ScriptRepositoryService,
        _decode_run_script_tasks,
        _invoke_run_script_with_session,
    )
    from arodonata.core.services.topology.route_collection import (
        _execute_coalesced_target,
        _finalize_domain_route_sync_states,
        _persist_gateway_routes,
    )

    assert callable(_invoke_run_script_with_session)
    assert callable(_decode_run_script_tasks)
    assert callable(_execute_coalesced_target)
    assert callable(_persist_gateway_routes)

    # 1. Dedicated session mode invokes run-script, scrubs bare SID from stdout, and always logs out
    ded_sid = "HelperDedSid1122"

    class _HelperApi(_ScriptApiStub):
        def __init__(self) -> None:
            super().__init__()
            self.logged_out: list[str] = []

        async def create_dedicated_session(
            self, mgmt_name: str, domain: str | None = None, **kw: object
        ) -> tuple[str, str]:
            return ded_sid, "10.0.0.1"

        async def logout_sid(self, mgmt_name: str, sid: str, **kw: object) -> None:
            self.logged_out.append(sid)

        async def api_call(
            self, mgmt_name: str, command: str, payload: dict[str, object] | None = None, **kw: object
        ) -> ApiCallResult:
            if command == "run-script":
                return ApiCallResult(
                    success=True,
                    status_code=200,
                    data={
                        "tasks": [
                            {
                                "task-id": "t-help",
                                "status": "succeeded",
                                "task-details": [
                                    {
                                        "gatewayName": "gw-01",
                                        "statusCode": "succeeded",
                                        "responseMessage": f"sid={ded_sid}",
                                    }
                                ],
                            }
                        ]
                    },
                )
            return await super().api_call(mgmt_name, command, payload, **kw)  # type: ignore[arg-type]

    h_api = _HelperApi()
    svc = ScriptRepositoryService(api=h_api)  # type: ignore[arg-type]
    outcome = await svc.run_repository_script("mds1", "app-diag", ["gw-01"], domain="Corp")
    assert outcome.success is True
    assert ded_sid not in outcome.stdout
    assert h_api.logged_out == [ded_sid]

    # 2. _finalize_domain_route_sync_states downgrades domain status when any gateway fails
    upserted: list[Any] = []

    class _SyncCache:
        async def upsert_sync_state(self, state: Any) -> None:
            upserted.append(state)

    st_ok = GatewayRouteCollectionStatus(
        mgmt_name="mds1",
        domain_name="Corp",
        gateway_id="id-1",
        gateway_asset_id="aid-1",
        gateway_uid="u-1",
        gateway_name="gw-1",
        gateway_type="simple-gateway",
        success=True,
        routes_collected=4,
    )
    st_fail = GatewayRouteCollectionStatus(
        mgmt_name="mds1",
        domain_name="Corp",
        gateway_id="id-2",
        gateway_asset_id="aid-2",
        gateway_uid="u-2",
        gateway_name="gw-2",
        gateway_type="simple-gateway",
        success=False,
        error="timeout",
    )
    coll = await _finalize_domain_route_sync_states(
        [(st_ok, 4), (st_fail, 0)],
        cache=_SyncCache(),  # type: ignore[arg-type]
        gw_tokens=[],
        total_gateways=2,
        now=datetime.now(UTC),
    )
    assert coll.succeeded_gateways == 1
    assert coll.failed_gateways == 1
    assert coll.total_routes == 4
    assert len(upserted) == 1
    assert upserted[0].status == "failed"
    assert "gw-2: timeout" in (upserted[0].last_error or "")
    _ = GatewayCliResult


async def test_run_repository_script_preserves_server_identity_and_task_errors() -> None:
    """DA-023: `run_repository_script` preserves `ServerIdentityError` and `TaskPollError` from session calls."""
    from arodonata.core.errors import ServerIdentityError, TaskPollError
    from arodonata.core.models.common import ApiCallResult
    from arodonata.core.services.script_service import _invoke_run_script_with_session

    class _IdentityApi:
        async def create_dedicated_session(self, *args: Any, **kwargs: Any) -> tuple[str, str]:
            return "sid-s1", "10.0.0.1"

        async def api_call(self, mgmt: str, cmd: str, *args: Any, **kwargs: Any) -> ApiCallResult:
            if cmd == "run-script":
                raise ServerIdentityError("cert mismatch")
            return ApiCallResult(success=True, data={})

        async def logout_sid(self, mgmt: str, sid: str, **kwargs: Any) -> bool:
            return True

    with pytest.raises(ServerIdentityError, match="cert mismatch"):
        await _invoke_run_script_with_session(
            _IdentityApi(),  # type: ignore[arg-type]
            mgmt_name="mds1",
            dom_key="Corp",
            ref="s1",
            payload={"script": "echo 1"},
            timeout=None,
            sid=None,
            server_ip=None,
            active_ws=None,
            session_getter=None,
        )

    class _TaskFailApi(_IdentityApi):
        async def api_call(self, mgmt: str, cmd: str, *args: Any, **kwargs: Any) -> ApiCallResult:
            if cmd == "run-script":
                raise TaskPollError("script failed")
            return ApiCallResult(success=True, data={})

    with pytest.raises(TaskPollError, match="script failed"):
        await _invoke_run_script_with_session(
            _TaskFailApi(),  # type: ignore[arg-type]
            mgmt_name="mds1",
            dom_key="Corp",
            ref="s1",
            payload={"script": "echo 1"},
            timeout=None,
            sid=None,
            server_ip=None,
            active_ws=None,
            session_getter=None,
        )


@pytest.mark.spec("SCN-TOPO-022-3")
@pytest.mark.asyncio
async def test_script_repository_write_paths_map_permission_errors_and_scrub_bare_sids() -> None:
    """SCN-TOPO-022-3 (DA-028): `ensure_repository_script` / `delete_repository_script` map perms and scrub bare SIDs."""
    from arodonata.core.context import WriteSession, write_session_context
    from arodonata.core.errors import SessionError
    from arodonata.core.models.common import ApiCallResult
    from arodonata.core.services.script_service import ScriptRepositoryService

    active_sid = "BareActiveScriptSid90909"
    iso_sid = "BareIsoScriptSid80808"

    class _PermApi:
        def __init__(self, *, existing: bool = False, leaked_sid: str = iso_sid) -> None:
            self._existing = existing
            self._leaked_sid = leaked_sid

        async def create_dedicated_session(self, *args: Any, **kwargs: Any) -> tuple[str, str]:
            return self._leaked_sid, "10.0.0.1"

        async def api_call(self, mgmt: str, cmd: str, *args: Any, **kwargs: Any) -> ApiCallResult:
            if cmd == "show-repository-script":
                if self._existing:
                    return ApiCallResult(
                        success=True,
                        status_code=200,
                        data={"uid": "u-1", "name": "app-diag", "script-body": ""},
                    )
                return ApiCallResult(
                    success=False,
                    status_code=404,
                    error_code="generic_err_object_not_found",
                    error_message="not found",
                )
            raise SessionError(f"Permission denied (403) while calling {cmd} for session {self._leaked_sid}")

        async def logout_sid(self, mgmt: str, sid: str, **kwargs: Any) -> bool:
            return True

    # 1. Isolated WriteSession branches (no active session)
    svc_iso = ScriptRepositoryService(api=_PermApi(existing=False, leaked_sid=iso_sid))  # type: ignore[arg-type]
    with pytest.raises(RepositoryScriptPermissionError) as exc_ensure_iso:
        await svc_iso.ensure_repository_script("mds1", "app-diag", "echo 1\n", domain="Corp")
    assert iso_sid not in str(exc_ensure_iso.value)
    assert REDACTED_PLACEHOLDER in str(exc_ensure_iso.value)

    svc_iso_del = ScriptRepositoryService(api=_PermApi(existing=True, leaked_sid=iso_sid))  # type: ignore[arg-type]
    with pytest.raises(RepositoryScriptPermissionError) as exc_del_iso:
        await svc_iso_del.delete_repository_script("mds1", "app-diag", domain="Corp")
    assert iso_sid not in str(exc_del_iso.value)
    assert REDACTED_PLACEHOLDER in str(exc_del_iso.value)

    # 2. Active WriteSession branches
    ws = WriteSession(mgmt_name="mds1", domain_name="Corp", sid=active_sid, server_ip="10.0.0.1")
    with write_session_context(ws):
        svc_active = ScriptRepositoryService(api=_PermApi(existing=False, leaked_sid=active_sid))  # type: ignore[arg-type]
        with pytest.raises(RepositoryScriptPermissionError) as exc_ensure_act:
            await svc_active.ensure_repository_script("mds1", "app-diag", "echo 1\n", domain="Corp")
        assert active_sid not in str(exc_ensure_act.value)
        assert REDACTED_PLACEHOLDER in str(exc_ensure_act.value)

        svc_active_del = ScriptRepositoryService(api=_PermApi(existing=True, leaked_sid=active_sid))  # type: ignore[arg-type]
        with pytest.raises(RepositoryScriptPermissionError) as exc_del_act:
            await svc_active_del.delete_repository_script("mds1", "app-diag", domain="Corp")
        assert active_sid not in str(exc_del_act.value)
        assert REDACTED_PLACEHOLDER in str(exc_del_act.value)


@pytest.mark.spec("SCN-CLIENT-020-2")
async def test_repository_script_unsupported_error_and_active_ws_sid_scrubbing() -> None:
    """DA-013 & DA-026: RepositoryScriptUnsupportedError classification and active WriteSession SID scrubbing on read paths."""
    from arodonata import RepositoryScriptUnsupportedError
    from arodonata.core.context import WriteSession, write_session_context
    from arodonata.core.errors import RepositoryScriptError, SessionError
    from arodonata.core.models.common import ApiCallResult, ApiQueryResult
    from arodonata.core.services.script_service import ScriptRepositoryService

    leaked_sid = "sid_secret_read_leak_999"

    class _MockApi:
        async def api_call(self, _m: str, cmd: str, _p: Any = None, **_k: Any) -> ApiCallResult:
            if cmd == "show-repository-script":
                raise SessionError(f"session {leaked_sid} expired")
            return ApiCallResult(
                success=False,
                status_code=400,
                error_code="generic_err_command_not_recognized",
                error_message=f"Requested API command: [{cmd}] not recognized",
            )

        async def api_query(self, *_a: Any, **_k: Any) -> ApiQueryResult:
            return ApiQueryResult(
                success=False,
                objects=[],
                total=0,
                code="generic_err_command_not_found",
                error_message="Requested API command not recognized",
            )

    svc = ScriptRepositoryService(api=_MockApi())  # type: ignore[arg-type]

    # DA-026: active WriteSession bare SID is scrubbed in get_repository_script exception & RepositoryScriptStatus
    ws = WriteSession(mgmt_name="mds1", domain_name="Corp", sid=leaked_sid, server_ip="10.0.0.1")
    with write_session_context(ws):
        with pytest.raises(RepositoryScriptError) as exc_info:
            await svc.get_repository_script("mds1", "demo", domain="Corp")
        assert leaked_sid not in str(exc_info.value)
        assert REDACTED_PLACEHOLDER in str(exc_info.value)

        # DA-013: unsupported error code cleanly maps to RepositoryScriptUnsupportedError in list_repository_scripts
        with pytest.raises(RepositoryScriptUnsupportedError):
            await svc.list_repository_scripts("mds1", domain="Corp")

    # DA-026: RepositoryScriptStatus.error scrubs SID patterns
    st = RepositoryScriptStatus(
        mgmt_name="mds1",
        domain_name="Corp",
        exists=False,
        error=f"failed with password=super-secret-pw sid={leaked_sid}",
    )
    assert "super-secret-pw" not in (st.error or "")
    assert leaked_sid not in (st.error or "")
    assert REDACTED_PLACEHOLDER in (st.error or "")
