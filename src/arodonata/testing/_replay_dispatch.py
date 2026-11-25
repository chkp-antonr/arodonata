"""Top-level command routing and domain mutation dispatcher for `FileReplayApiMock`."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from arodonata.core.models.common import ApiCallResult

from ._emulator_entity_crud import handle_entity_crud
from ._emulator_lookup import delete_unused_objects
from ._emulator_models import (
    CMD_TO_ENTITY_ACTION,
    MutationRecord,
    SidBinding,
    WorkSession,
    cp_error,
    cp_ok,
    is_mutating_command,
)
from ._emulator_rulebase_crud import handle_rulebase_crud
from ._replay_global_and_policy import (
    check_cross_session_locks,
    handle_global_assignments_cmd,
    handle_verify_or_install_policy,
    preflight_target_uids,
)
from ._replay_queries import empty_where_used_bucket
from ._replay_reads import handle_domain_read_command, handle_show_checkpoint_host
from ._replay_repo_scripts import handle_repository_script_mutation
from ._replay_run_script import handle_run_script
from ._replay_sessions import (
    handle_discard,
    handle_disconnect,
    handle_login,
    handle_logout,
    handle_publish,
    handle_set_session,
    handle_show_changes,
    handle_switch_session,
    handle_take_over_session,
    resolve_session_by_uid,
)

if TYPE_CHECKING:
    from .replay_mock import FileReplayApiMock


def apply_domain_mutation(
    mock: FileReplayApiMock,
    clean_cmd: str,
    req: Mapping[str, Any],
    *,
    dom_name: str,
    target_files: dict[str, Any],
    global_files: Mapping[str, Any],
    all_domains: Mapping[str, Mapping[str, Any]],
    user_name: str,
    locked_uids_out: set[str],
    override_now_ms: int | None = None,
) -> tuple[ApiCallResult, str | None] | None:
    """Apply an entity, rulebase, repository-script, or unused-object command against `target_files`."""
    now_ms = override_now_ms if override_now_ms is not None else mock._next_timestamp_ms()
    entity_hit = handle_entity_crud(
        clean_cmd,
        req,
        dom_name=dom_name,
        dom_files=target_files,
        global_files=global_files,
        all_domains_effective=all_domains,
        uid_allocator=mock._allocate_uid,
        now_ms=now_ms,
        user_name=user_name,
        locked_uids_out=locked_uids_out,
    )
    if entity_hit is not None:
        return entity_hit

    rb_hit = handle_rulebase_crud(
        clean_cmd,
        req,
        dom_name=dom_name,
        dom_files=target_files,
        global_files=global_files,
        uid_allocator=mock._allocate_uid,
        now_ms=now_ms,
        user_name=user_name,
        locked_uids_out=locked_uids_out,
    )
    if rb_hit is not None:
        return rb_hit

    repo_hit = handle_repository_script_mutation(
        mock,
        clean_cmd,
        req,
        dom_name=dom_name,
        target_files=target_files,
        now_ms=now_ms,
        user_name=user_name,
        locked_uids_out=locked_uids_out,
    )
    if repo_hit is not None:
        return repo_hit

    if clean_cmd == "delete-unused-objects":
        removed = delete_unused_objects(
            target_files,
            dom_name=dom_name,
            all_domains_effective=all_domains,
            locked_uids_out=locked_uids_out,
            req=req,
        )
        return cp_ok({"deleted-count": removed, "message": f"Deleted {removed} unused objects"}), None

    return None


def dispatch_api_call(
    mock: FileReplayApiMock,
    mgmt_name: str,
    clean_cmd: str,
    req: dict[str, Any],
    *,
    dom_name: str,
    sid: str | None,
    binding: SidBinding | None,
    wait_for_task: bool,
) -> ApiCallResult:
    """Dispatch a single normalized Check Point Management API call on `FileReplayApiMock`."""
    if clean_cmd == "login":
        return handle_login(mock, mgmt_name, req, dom_name=dom_name)

    active_ws: WorkSession | None = None
    if sid is not None:
        if binding is None or not binding.active:
            return cp_error("generic_err_invalid_session_id", "Session ID is invalid or expired", status_code=401)
        active_ws = mock._work_sessions.get(binding.session_uid)
        if active_ws is None:
            return cp_error(
                "generic_err_invalid_session_id",
                "Attached work session is invalid or expired",
                status_code=401,
            )

    if clean_cmd == "logout":
        return handle_logout(req, binding=binding, active_ws=active_ws)
    if clean_cmd in ("disconnect", "continue-session-in-smartconsole"):
        return handle_disconnect(mock, req, binding=binding, active_ws=active_ws)
    if clean_cmd == "keepalive":
        return cp_ok({"message": "OK"})
    if clean_cmd == "set-session":
        return handle_set_session(mock, req, active_ws=active_ws)
    if clean_cmd == "take-over-session":
        return handle_take_over_session(mock, req, binding=binding, active_ws=active_ws)
    if clean_cmd == "switch-session":
        return handle_switch_session(mock, req, binding=binding, active_ws=active_ws)
    if clean_cmd == "discard":
        return handle_discard(mock, req, binding=binding, active_ws=active_ws)
    if clean_cmd == "publish":
        return handle_publish(mock, req, binding=binding, wait_for_task=wait_for_task)
    if clean_cmd == "show-api-versions":
        return cp_ok({"current-version": "1.9.1", "supported-versions": ["1.8", "1.9", "1.9.1"]})

    if clean_cmd == "show-domains":
        items = mock._show_domains.get("objects", [])
        return cp_ok(mock._paginate_list(items, req, collection_key="objects"))
    if clean_cmd == "show-global-domain":
        return cp_ok(copy.deepcopy(mock._show_global_domain))
    if clean_cmd in (
        "show-global-assignments",
        "show-global-assignment",
        "assign-global-assignment",
        "assign-global-policy",
    ):
        return handle_global_assignments_cmd(mock, clean_cmd, req, binding=binding, wait_for_task=wait_for_task)
    if clean_cmd == "show-domain":
        lookup = str(req.get("name") or req.get("uid") or dom_name)
        if lookup.lower() == "global" or lookup == mock._show_global_domain.get("uid"):
            return cp_ok(copy.deepcopy(mock._show_global_domain))
        for d_obj in mock._show_domains.get("objects", []):
            if d_obj.get("name") == lookup or d_obj.get("uid") == lookup:
                return cp_ok(copy.deepcopy(d_obj))
        return cp_error("generic_err_object_not_found", f"Requested domain [{lookup}] not found", status_code=404)
    if clean_cmd == "show-mdss":
        items = mock._show_mdss.get("objects", [])
        return cp_ok(mock._paginate_list(items, req, collection_key="objects"))

    if clean_cmd == "run-script":
        return handle_run_script(mock, dom_name, req, binding=binding, active_ws=active_ws, wait_for_task=wait_for_task)
    if clean_cmd == "show-task":
        raw_tid = req.get("task-id")
        tids = [raw_tid] if isinstance(raw_tid, str) else (list(raw_tid) if isinstance(raw_tid, list) else [])
        found_tasks: list[dict[str, Any]] = []
        for tid in tids:
            if str(tid) in mock._tasks:
                found_tasks.append(copy.deepcopy(mock._tasks[str(tid)]))
        if not found_tasks:
            return cp_error("generic_err_object_not_found", f"Requested task {tids} not found", status_code=404)
        return cp_ok({"tasks": found_tasks})

    if clean_cmd == "show-session":
        req_uid = str(req.get("uid") or "").strip()
        if req_uid:
            resolved = resolve_session_by_uid(mock, req_uid, dom_name)
            if resolved is None:
                return cp_error("generic_err_object_not_found", f"Session [{req_uid}] not found", status_code=404)
            return cp_ok(resolved)
        if active_ws is not None:
            return cp_ok(active_ws.to_checkpoint_dict())
        if dom_name == "System Data":
            return cp_ok(
                {
                    "uid": "sess-system-data-0001",
                    "name": "system-session",
                    "type": "session",
                    "state": "published",
                    "locks": 0,
                    "published-changes": 0,
                    "number-of-published-changes": 0,
                    "publish-time": {"posix": 1794139200000, "iso-8601": "2026-11-08T12:00:00Z"},
                }
            )

    if clean_cmd == "show-sessions":
        if req.get("view-published-sessions") is False:
            open_sessions = [
                ws.to_checkpoint_dict()
                for ws in mock._work_sessions.values()
                if ws.state in ("open", "disconnected") and (dom_name == "System Data" or ws.domain == dom_name)
            ]
            return cp_ok(mock._paginate_list(open_sessions, req, collection_key="objects"))
        if dom_name == "System Data":
            return cp_ok({"objects": [], "from": 0, "to": 0, "total": 0})

    if clean_cmd == "show-changes":
        return handle_show_changes(mock, dom_name, req, binding=binding, wait_for_task=wait_for_task)
    if clean_cmd == "show-checkpoint-host":
        return handle_show_checkpoint_host(mock, mgmt_name, dom_name, req, binding=binding)

    if dom_name == "System Data":
        if clean_cmd == "show-last-published-session":
            return cp_ok(
                {
                    "uid": "sess-system-data-0001",
                    "name": "system-session",
                    "type": "session",
                    "state": "published",
                    "locks": 0,
                    "published-changes": 0,
                    "number-of-published-changes": 0,
                    "publish-time": {"posix": 1794139200000, "iso-8601": "2026-11-08T12:00:00Z"},
                }
            )
        if clean_cmd == "where-used":
            lookup_ref = str(req.get("uid") or req.get("name") or "")
            sys_items = [*mock._show_mdss.get("objects", []), *mock._show_domains.get("objects", [])]
            if lookup_ref and any(
                isinstance(o, dict) and (o.get("uid") == lookup_ref or o.get("name") == lookup_ref) for o in sys_items
            ):
                data_out: dict[str, Any] = {"used-directly": empty_where_used_bucket()}
                if bool(req.get("indirect", False)):
                    data_out["used-indirectly"] = empty_where_used_bucket()
                return cp_ok(data_out)
            return cp_error(
                "generic_err_object_not_found",
                f"Requested object [{lookup_ref}] not found in {dom_name}",
                status_code=404,
            )

    mutating = is_mutating_command(clean_cmd)
    if mutating and dom_name == "System Data":
        return cp_error(
            "err_validation_failed",
            f"Cannot execute domain object/rule mutation {clean_cmd!r} in System Data domain",
            status_code=400,
        )

    dom_files = mock._effective_domain_files(dom_name, binding)
    if dom_files is None:
        return cp_error("generic_err_object_not_found", f"Domain [{dom_name}] not found in dataset", status_code=404)
    global_files = mock._effective_domain_files("Global", binding) or {}

    if mutating and active_ws is not None:
        if active_ws.state != "open":
            return cp_error(
                "err_validation_failed",
                f"Cannot mutate in session [{active_ws.uid}] with state {active_ws.state!r}",
                status_code=400,
            )
        if active_ws.read_only or (binding is not None and binding.read_only):
            return cp_error("err_validation_failed", "Cannot modify database in read-only session", status_code=400)
        if binding is not None and binding.domain != dom_name:
            if dom_name == "Global" and binding.domain != "System Data":
                return cp_error(
                    "generic_err_object_read_only",
                    f"Cannot mutate Global domain from local domain session [{binding.domain}]",
                    status_code=400,
                )
            return cp_error(
                "err_validation_failed",
                f"Session bound to domain [{binding.domain}] cannot mutate domain [{dom_name}]",
                status_code=400,
            )

    if (
        mutating
        or clean_cmd in CMD_TO_ENTITY_ACTION
        or (
            clean_cmd.startswith("show-")
            and not clean_cmd.endswith("-rulebase")
            and any(
                clean_cmd.endswith(f"-{rk}-{sfx}")
                for rk in ("access", "nat", "https", "threat")
                for sfx in ("rule", "section")
            )
        )
    ):
        is_write = mutating
        if is_write and active_ws is not None:
            candidate_uids = preflight_target_uids(clean_cmd, req, dom_files, global_files, dom_name)
            lock_err = check_cross_session_locks(mock, active_ws, candidate_uids)
            if lock_err is not None:
                return lock_err
            target_files = mock._ensure_overlay(active_ws)
            user_name = active_ws.user_name
        elif is_write:
            mock._get_clean_domain_baseline(dom_name)
            target_files = mock._domain_data[dom_name]
            user_name = "admin"
        else:
            target_files = dom_files
            user_name = active_ws.user_name if active_ws is not None else "admin"

        locked_out: set[str] = set()
        all_eff = mock._effective_all_domains(binding)
        outcome = mock._apply_domain_mutation(
            clean_cmd,
            req,
            dom_name=dom_name,
            target_files=target_files,
            global_files=global_files,
            all_domains=all_eff,
            user_name=user_name,
            locked_uids_out=locked_out,
        )
        if outcome is not None:
            res, assigned_uid = outcome
            if res.success and is_write:
                if active_ws is not None:
                    active_ws.locked_uids.update(locked_out)
                    replay_payload = copy.deepcopy(req)
                    if assigned_uid and "uid" not in replay_payload:
                        replay_payload["uid"] = assigned_uid
                    active_ws.mutation_records.append(
                        MutationRecord(
                            command=clean_cmd,
                            domain=dom_name,
                            payload=replay_payload,
                            assigned_uid=assigned_uid,
                        )
                    )
                    active_ws.last_modify_posix = mock._next_timestamp_ms()
                    active_ws.changes_count = len(active_ws.mutation_records)
                else:
                    mock._mark_domain_mutated(dom_name)
            return res

    if clean_cmd in ("verify-policy", "install-policy"):
        return handle_verify_or_install_policy(
            mock,
            clean_cmd,
            req,
            dom_name=dom_name,
            dom_files=dom_files,
            global_files=global_files,
            wait_for_task=wait_for_task,
        )

    read_res = handle_domain_read_command(
        mock,
        clean_cmd,
        req,
        dom_name=dom_name,
        dom_files=dom_files,
        global_files=global_files,
        binding=binding,
    )
    if read_res is not None:
        return read_res

    return cp_error(
        "generic_err_command_not_recognized",
        f"Unsupported command {clean_cmd!r} in FileReplayApiMock",
        status_code=400,
    )
