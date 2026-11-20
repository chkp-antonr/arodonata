"""Stateful `run-script` handler for one-time, repository, and zero-arg VSX bundle execution."""

from __future__ import annotations

import base64
import copy
import json
from typing import TYPE_CHECKING, Any

from arodonata.core.models.common import ApiCallResult

from ._emulator_models import SidBinding, WorkSession, cp_error, summarize_payload
from ._replay_cli import VS_NAME_SCRIPT_RE, VSID_SCRIPT_RE
from ._replay_repo_scripts import extract_repo_script_body

if TYPE_CHECKING:
    from .replay_mock import FileReplayApiMock


def handle_run_script(
    mock: FileReplayApiMock,
    dom_name: str,
    payload: dict[str, Any],
    *,
    binding: SidBinding | None = None,
    active_ws: WorkSession | None = None,
    wait_for_task: bool,
) -> ApiCallResult:
    """Emulate Check Point `run-script` for one-time inline scripts and repository scripts."""
    if (binding is not None and binding.read_only) or (active_ws is not None and active_ws.read_only):
        return cp_error(
            "err_validation_failed",
            "Operation is not allowed in read only mode",
            status_code=400,
        )

    script_type = str(payload.get("script-type") or "one time").strip().lower()
    if script_type not in ("one time", "repository"):
        return cp_error(
            "err_validation_failed",
            f"Invalid script-type {script_type!r}; expected 'one time' or 'repository'",
            status_code=400,
        )

    inline_script = ""
    repo_script: dict[str, Any] | None = None
    if script_type == "one time":
        if not mock.allow_one_time_script:
            return cp_error(
                "generic_err_no_permissions",
                "No permission to run action",
                status_code=400,
            )
        raw_inline = payload.get("script")
        if isinstance(raw_inline, str) and raw_inline:
            inline_script = raw_inline
        elif isinstance(payload.get("script-base64"), str) and payload["script-base64"].strip():
            inline_script = extract_repo_script_body({"script-body-base64": payload["script-base64"]}) or ""
        if not inline_script:
            return cp_error(
                "err_validation_failed",
                "Missing parameter: [Didn't Provide script or script-base64 for one time script.]",
                status_code=400,
            )
    else:
        if not mock.allow_repository_script:
            return cp_error(
                "generic_err_no_permissions",
                "No permission to run action",
                status_code=400,
            )
        if payload.get("script") or payload.get("script-base64"):
            return cp_error(
                "err_validation_failed",
                "Cannot provide inline 'script' or 'script-base64' when script-type is 'repository'",
                status_code=400,
            )
        raw_args = str(payload.get("args") or "").strip()
        if not mock.allow_one_time_script and raw_args:
            return cp_error(
                "err_validation_failed",
                "Insufficient permissions to run this script with arguments.",
                status_code=400,
            )
        lookup_ref = str(payload.get("uid") or payload.get("script-name") or "").strip()
        if not lookup_ref:
            return cp_error(
                "err_validation_failed",
                "Missing parameter: 'script-name' or 'uid' is required for repository script",
                status_code=400,
            )
        published_scripts = mock._domain_data.get(dom_name, {}).get("show-repository-scripts", {}).get("objects", [])
        repo_script = next(
            (
                s
                for s in published_scripts
                if isinstance(s, dict) and (s.get("uid") == lookup_ref or s.get("name") == lookup_ref)
            ),
            None,
        )
        if repo_script is None:
            return cp_error(
                "generic_err_object_not_found",
                f"Requested repository script [{lookup_ref}] not found in domain [{dom_name}]",
                status_code=404,
            )

    raw_targets = payload.get("targets") or []
    if isinstance(raw_targets, str):
        targets = [raw_targets] if raw_targets.strip() else ["unknown-target"]
    else:
        targets = [str(t) for t in raw_targets if str(t).strip()] or ["unknown-target"]

    built_tasks: list[dict[str, Any]] = []
    async_task_refs: list[dict[str, Any]] = []
    first_script_error: str | None = None

    for target_ref in targets:
        node_name = mock._node_uid_to_name.get(target_ref, target_ref)
        vsid = 0
        prepend_resolved = False
        script_error: str | None = None
        custom_stdout: str | None = None

        if script_type == "one time":
            m_vsid = VSID_SCRIPT_RE.search(inline_script)
            m_vs_name = VS_NAME_SCRIPT_RE.search(inline_script)
            if m_vsid is not None:
                vsid = int(m_vsid.group(1))
                if 'vsenv "$vsid"' not in inline_script or "CTX%05d" not in inline_script:
                    script_error = f"_vs_error=vsenv_{vsid}_missing_guard"
            elif m_vs_name is not None:
                vs_name_val = m_vs_name.group(1)
                if (
                    "vsx stat -l" not in inline_script
                    or 'vsenv "$vsid"' not in inline_script
                    or "CTX%05d" not in inline_script
                ):
                    script_error = f"_vs_error=vsx_stat_missing_guard:{vs_name_val}"
                else:
                    resolved = mock._cli_mock.resolve_vsid_from_stat(node_name, vs_name_val)
                    if resolved is None:
                        script_error = f"_vs_error=vs_not_found:{vs_name_val}"
                    else:
                        vsid = resolved
                        prepend_resolved = True
        else:
            assert repo_script is not None
            repo_body = str(repo_script.get("script-body") or "")
            raw_args = str(payload.get("args") or "").strip()
            if "===ARODONATA_IP_ROUTE_START===" in repo_body or "===ARODONATA_VSX_BUNDLE_START===" in repo_body:
                if raw_args:
                    tokens = raw_args.split()
                    max_tok = tokens[0] if len(tokens) >= 1 else "0"
                    vsid_tok = tokens[1] if len(tokens) >= 2 else "0"
                    vs_name_val = " ".join(tokens[2:]) if len(tokens) >= 3 else ""
                    if not max_tok.isdigit():
                        script_error = f"_vs_error=invalid max_routes argument: {max_tok}"
                    elif not vsid_tok.isdigit():
                        script_error = f"_vs_error=invalid vsid argument: {vsid_tok}"
                    else:
                        vsid = int(vsid_tok)
                        if vsid == 0 and vs_name_val:
                            resolved = mock._cli_mock.resolve_vsid_from_stat(node_name, vs_name_val)
                            if resolved is None:
                                script_error = f"_vs_error=vs_not_found:{vs_name_val}"
                            else:
                                vsid = resolved
                                prepend_resolved = True
                else:
                    vs_list = mock._cli_mock.list_virtual_systems(node_name)
                    if vs_list:
                        bundle_parts = ["===ARODONATA_VSX_BUNDLE_START===\n"]
                        for v_id, v_name in vs_list:
                            v_out = mock._cli_mock.get_raw_cli_stdout(node_name, v_id)
                            bundle_parts.append(f"===ARODONATA_VS_START vsid={v_id} name={v_name}===\n")
                            if v_out is not None:
                                bundle_parts.append(v_out.rstrip() + "\n")
                            else:
                                bundle_parts.append(
                                    f"===ARODONATA_VS_ERROR vsid={v_id} name={v_name} error=vsenv {v_id} failed===\n"
                                )
                            bundle_parts.append("===ARODONATA_VS_END===\n")
                        bundle_parts.append("===ARODONATA_VSX_BUNDLE_END===\n")
                        custom_stdout = "".join(bundle_parts)
                    else:
                        vsid = 0
            else:
                if (node_name, 0) in mock._cli_mock._cli_overrides:
                    custom_stdout = mock._cli_mock.get_raw_cli_stdout(node_name, 0) or ""
                else:
                    custom_stdout = f"target={node_name} script={repo_script.get('name')} args={raw_args}\n"

        task_id = mock._next_task_id()
        default_task_name = (
            str(repo_script.get("name"))
            if repo_script is not None
            else str(payload.get("script-name") or f"arodonata-route-collect-{node_name}")
        )

        if script_error is not None:
            if first_script_error is None:
                first_script_error = script_error
            b64_err = base64.b64encode((script_error + "\n").encode("utf-8")).decode("ascii")
            task_obj = {
                "uid": task_id,
                "task-id": task_id,
                "task-name": default_task_name,
                "status": "failed",
                "progress-percentage": 100,
                "suppressed": False,
                "task-details": [
                    {
                        "uid": f"td-{task_id}",
                        "gatewayId": target_ref,
                        "gatewayName": node_name,
                        "statusCode": "failed",
                        "statusDescription": "Failed",
                        "responseMessage": b64_err,
                        "responseError": b64_err,
                    }
                ],
            }
        elif custom_stdout is not None:
            b64_msg = base64.b64encode(custom_stdout.encode("utf-8")).decode("ascii")
            task_obj = {
                "uid": task_id,
                "task-id": task_id,
                "task-name": default_task_name,
                "status": "succeeded",
                "progress-percentage": 100,
                "suppressed": False,
                "task-details": [
                    {
                        "uid": f"td-{task_id}",
                        "gatewayId": target_ref,
                        "gatewayName": node_name,
                        "statusCode": "succeeded",
                        "statusDescription": "Succeeded",
                        "responseMessage": b64_msg,
                        "responseError": "",
                    }
                ],
            }
        else:
            task_file = mock._dataset_dir / "tasks" / f"{node_name}__vs_{vsid}.json"
            if not task_file.is_file() and vsid == 0:
                alt_task_file = mock._dataset_dir / "tasks" / f"{node_name}__vs_none.json"
                if alt_task_file.is_file():
                    task_file = alt_task_file
            override_stdout = mock._cli_mock.get_raw_cli_stdout(node_name, vsid)

            if task_file.is_file() and (node_name, vsid) not in mock._cli_mock._cli_overrides and not prepend_resolved:
                task_payload = json.loads(task_file.read_text(encoding="utf-8"))
                tasks_list = task_payload.get("tasks", [])
                if tasks_list:
                    task_obj = copy.deepcopy(tasks_list[0])
                    task_obj["task-id"] = task_id
                else:
                    task_obj = {"task-id": task_id, "status": "succeeded", "task-details": []}
            else:
                stdout_str = override_stdout or ""
                if prepend_resolved and stdout_str and f"===ARODONATA_VSID_RESOLVED={vsid}===" not in stdout_str:
                    stdout_str = f"===ARODONATA_VSID_RESOLVED={vsid}===\n{stdout_str}"
                b64_msg = base64.b64encode(stdout_str.encode("utf-8")).decode("ascii")
                task_obj = {
                    "uid": task_id,
                    "task-id": task_id,
                    "task-name": default_task_name,
                    "status": "succeeded" if stdout_str else "failed",
                    "progress-percentage": 100,
                    "suppressed": False,
                    "task-details": [
                        {
                            "uid": f"td-{task_id}",
                            "gatewayId": target_ref,
                            "gatewayName": node_name,
                            "statusCode": "succeeded" if stdout_str else "failed",
                            "statusDescription": "Succeeded" if stdout_str else "Failed",
                            "responseMessage": b64_msg,
                            "responseError": "",
                        }
                    ],
                }

        mock._tasks[task_id] = task_obj
        built_tasks.append(task_obj)
        async_task_refs.append(
            {
                "target": target_ref,
                "task-id": task_id,
                "task-name": task_obj.get("task-name", "run-script"),
            }
        )

    if wait_for_task:
        if first_script_error is not None:
            return ApiCallResult(
                success=False,
                status_code=200,
                error_code="generic_err_task_failed",
                error_message=first_script_error,
                data={"tasks": [copy.deepcopy(t) for t in built_tasks]},
            )
        for t_obj in built_tasks:
            tid_str = str(t_obj.get("task-id") or "")
            mock.api_call_counts[(dom_name, "show-task")] += 1
            mock.command_counts["show-task"] += 1
            show_task_payload = {"task-id": tid_str, "details-level": "full"}
            mock.call_log.append(
                {
                    "mgmt_name": "mds",
                    "domain": dom_name,
                    "command": "show-task",
                    "is_mutating": False,
                    "mutating": False,
                    "sid_ref": None,
                    "session_uid": None,
                    "read_only_session": False,
                    "payload": show_task_payload,
                    "payload_summary": summarize_payload("show-task", show_task_payload),
                    "status_code": 200,
                    "success": True,
                    "error_code": None,
                }
            )
        return ApiCallResult(
            success=True,
            status_code=200,
            data={"tasks": [copy.deepcopy(t) for t in built_tasks]},
        )

    return ApiCallResult(
        success=True,
        status_code=200,
        data={"tasks": async_task_refs},
    )
