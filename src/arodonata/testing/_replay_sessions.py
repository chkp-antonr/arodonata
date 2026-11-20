"""Session lifecycle, publish/rebase, discard, takeover, and `show-changes` handlers."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from arodonata.core.models.common import ApiCallResult

from ._emulator_changes import (
    build_show_changes_task,
    compute_session_delta,
    count_delta_items,
    parse_checkpoint_date_ms,
)
from ._emulator_models import PublishedDelta, SidBinding, WorkSession, cp_error, cp_ok

if TYPE_CHECKING:
    from .replay_mock import FileReplayApiMock


def handle_login(
    mock: FileReplayApiMock,
    mgmt_name: str,
    req: Mapping[str, Any],
    *,
    dom_name: str,
) -> ApiCallResult:
    """Create or resume a stateful mock session and bind a fresh `sid`."""
    login_dom = mock._normalize_domain(req.get("domain") or dom_name)
    if login_dom != "System Data" and login_dom not in mock._domain_data:
        return cp_error(
            "generic_err_object_not_found",
            f"Domain [{login_dom}] not found in dataset",
            status_code=404,
        )
    mock._sid_seq += 1
    new_sid = f"mock-sid-{login_dom}-{mock._sid_seq}"
    sid_ref = f"sid#{mock._sid_seq:04d}"
    user_name = str(req.get("user") or "admin")
    read_only = bool(req.get("read-only", False))
    sess_name = str(req.get("session-name") or "")
    sess_desc = str(req.get("session-description") or "")
    app_name = str(req.get("application") or "WEB_API")

    ws: WorkSession | None = None
    if bool(req.get("continue-last-session", False)) and not read_only:
        for cand_ws in reversed(list(mock._work_sessions.values())):
            if (
                cand_ws.domain == login_dom
                and cand_ws.user_name == user_name
                and cand_ws.state == "disconnected"
                and not cand_ws.read_only
            ):
                cand_ws.state = "open"
                cand_ws.last_modify_posix = mock._next_timestamp_ms()
                ws = cand_ws
                break
    if ws is None:
        ws = mock._create_work_session(
            login_dom,
            user_name=user_name,
            name=sess_name,
            description=sess_desc,
            application=app_name,
            read_only=read_only,
        )

    mock._sid_bindings[new_sid] = SidBinding(
        sid=new_sid,
        sid_ref=sid_ref,
        mgmt_name=mgmt_name,
        domain=login_dom,
        user_name=user_name,
        session_uid=ws.uid,
        read_only=ws.read_only,
        active=True,
    )
    return cp_ok(
        {
            "sid": new_sid,
            "uid": ws.uid,
            "session-timeout": 600,
            "api-server-version": "1.9.1",
            "disk-space-message": "OK",
            "read-only": ws.read_only,
        }
    )


def handle_logout(
    req: Mapping[str, Any],
    *,
    binding: SidBinding | None,
    active_ws: WorkSession | None,
) -> ApiCallResult:
    """Deactivate `binding` and either disconnect dirty sessions or discard clean ones."""
    if binding is not None:
        binding.active = False
    if active_ws is not None and active_ws.state == "open":
        has_uncommitted = bool(active_ws.changes_count > 0 or active_ws.locked_uids or active_ws.mutation_records)
        if has_uncommitted or bool(req.get("continue-session-in-smartconsole", False)):
            active_ws.state = "disconnected"
        else:
            active_ws.overlay_data = None
            active_ws.base_snapshot = None
            active_ws.locked_uids.clear()
            active_ws.mutation_records.clear()
            active_ws.changes_count = 0
            active_ws.state = "discarded"
    return cp_ok({"message": "OK"})


def handle_disconnect(
    mock: FileReplayApiMock,
    req: Mapping[str, Any],
    *,
    binding: SidBinding | None,
    active_ws: WorkSession | None,
) -> ApiCallResult:
    """Handle `disconnect` and `continue-session-in-smartconsole` commands."""
    target_uid = str(req.get("uid") or "").strip()
    if target_uid:
        target_ws = mock._work_sessions.get(target_uid)
        if target_ws is None:
            return cp_error("generic_err_object_not_found", f"Session [{target_uid}] not found", status_code=404)
        if binding is not None and binding.domain not in ("System Data", target_ws.domain):
            return cp_error(
                "err_validation_failed",
                f"Session bound to domain [{binding.domain}] cannot disconnect session in [{target_ws.domain}]",
                status_code=400,
            )
    else:
        target_ws = active_ws

    if target_ws is not None:
        for b in mock._sid_bindings.values():
            if b.session_uid == target_ws.uid and b.active:
                b.active = False
        if target_ws.state == "open":
            target_ws.state = "disconnected"
            target_ws.last_modify_posix = mock._next_timestamp_ms()
        return cp_ok(target_ws.to_checkpoint_dict())
    if binding is not None:
        binding.active = False
    return cp_ok({"message": "OK"})


def handle_set_session(
    mock: FileReplayApiMock,
    req: Mapping[str, Any],
    *,
    active_ws: WorkSession | None,
) -> ApiCallResult:
    """Update metadata on the active open `WorkSession`."""
    if active_ws is None:
        return cp_error("generic_err_wrong_session_id", "Active session is required", status_code=400)
    if active_ws.read_only:
        return cp_error("err_validation_failed", "Cannot modify a read-only session", status_code=400)
    if req.get("new-name") is not None:
        active_ws.name = str(req["new-name"])
    elif req.get("name") is not None:
        active_ws.name = str(req["name"])
    if req.get("description") is not None:
        active_ws.description = str(req["description"])
    if req.get("comments") is not None:
        active_ws.comments = str(req["comments"])
    if req.get("color") is not None:
        active_ws.color = str(req["color"])
    if req.get("tags") is not None:
        raw_tags = req["tags"]
        active_ws.tags = list(raw_tags) if isinstance(raw_tags, list) else [raw_tags]
    active_ws.last_modify_posix = mock._next_timestamp_ms()
    return cp_ok(active_ws.to_checkpoint_dict())


def handle_take_over_session(
    mock: FileReplayApiMock,
    req: Mapping[str, Any],
    *,
    binding: SidBinding | None,
    active_ws: WorkSession | None,
) -> ApiCallResult:
    """Transfer an open or disconnected session onto the caller's SID binding."""
    if binding is None or active_ws is None:
        return cp_error("generic_err_wrong_session_id", "Active session is required", status_code=400)
    if binding.read_only:
        return cp_error("err_validation_failed", "Cannot take over a session from a read-only session", status_code=400)
    target_uid = str(req.get("uid") or "").strip()
    target_ws = mock._work_sessions.get(target_uid)
    if target_ws is None:
        return cp_error("generic_err_object_not_found", f"Session [{target_uid}] not found", status_code=404)
    if binding.domain not in ("System Data", target_ws.domain):
        return cp_error(
            "err_validation_failed",
            f"Session bound to domain [{binding.domain}] cannot take over session in [{target_ws.domain}]",
            status_code=400,
        )
    if target_ws.read_only:
        return cp_error("err_validation_failed", "Cannot take over a read-only session", status_code=400)
    if target_ws.state in ("published", "discarded"):
        return cp_error(
            "err_validation_failed",
            f"Cannot take over session [{target_uid}] in state {target_ws.state!r}",
            status_code=400,
        )
    disconnect_active = bool(req.get("disconnect-active-session", False))
    other_active = [
        other_b
        for other_b in mock._sid_bindings.values()
        if other_b.sid != binding.sid and other_b.session_uid == target_ws.uid and other_b.active
    ]
    if other_active:
        if disconnect_active:
            for other_b in other_active:
                other_b.active = False
        elif target_ws.application != "WEB_API" or target_ws.user_name != binding.user_name:
            return cp_error(
                "err_validation_failed",
                f"Session [{target_uid}] is currently active; pass disconnect-active-session=true to take over",
                status_code=400,
            )
        else:
            for other_b in other_active:
                fresh_other_ws = mock._create_work_session(
                    other_b.domain,
                    user_name=other_b.user_name,
                    name="",
                    description="",
                    application="WEB_API",
                    read_only=other_b.read_only,
                )
                other_b.session_uid = fresh_other_ws.uid
    if active_ws.uid != target_ws.uid:
        active_ws.state = "disconnected"
    target_ws.state = "open"
    target_ws.last_modify_posix = mock._next_timestamp_ms()
    binding.session_uid = target_ws.uid
    binding.domain = target_ws.domain
    return cp_ok(target_ws.to_checkpoint_dict())


def handle_switch_session(
    mock: FileReplayApiMock,
    req: Mapping[str, Any],
    *,
    binding: SidBinding | None,
    active_ws: WorkSession | None,
) -> ApiCallResult:
    """Switch the caller's SID binding to another open or disconnected session."""
    if binding is None or active_ws is None:
        return cp_error("generic_err_wrong_session_id", "Active session is required", status_code=400)
    target_uid = str(req.get("uid") or "").strip()
    target_ws = mock._work_sessions.get(target_uid)
    if target_ws is None:
        return cp_error("generic_err_object_not_found", f"Session [{target_uid}] not found", status_code=404)
    if binding.domain not in ("System Data", target_ws.domain):
        return cp_error(
            "err_validation_failed",
            f"Session bound to domain [{binding.domain}] cannot switch to session in [{target_ws.domain}]",
            status_code=400,
        )
    if target_ws.state not in ("open", "disconnected"):
        return cp_error(
            "err_validation_failed",
            f"Cannot switch to session [{target_uid}] in state {target_ws.state!r}",
            status_code=400,
        )
    if active_ws.uid != target_ws.uid:
        active_ws.state = "disconnected"
    target_ws.state = "open"
    target_ws.last_modify_posix = mock._next_timestamp_ms()
    binding.session_uid = target_ws.uid
    binding.domain = target_ws.domain
    return cp_ok(target_ws.to_checkpoint_dict())


def handle_discard(
    mock: FileReplayApiMock,
    req: Mapping[str, Any],
    *,
    binding: SidBinding | None,
    active_ws: WorkSession | None,
) -> ApiCallResult:
    """Discard uncommitted changes for the target or active session and rotate if active."""
    if active_ws is not None and active_ws.read_only:
        return cp_error("err_validation_failed", "Cannot discard from a read-only session", status_code=400)
    target_uid = str(req.get("uid") or "").strip()
    if target_uid:
        target_ws = mock._work_sessions.get(target_uid)
        if target_ws is None:
            return cp_error("generic_err_object_not_found", f"Session [{target_uid}] not found", status_code=404)
        if binding is not None and binding.domain not in ("System Data", target_ws.domain):
            return cp_error(
                "err_validation_failed",
                f"Session bound to domain [{binding.domain}] cannot discard session in [{target_ws.domain}]",
                status_code=400,
            )
        if target_ws.state in ("published", "discarded"):
            return cp_error(
                "err_validation_failed",
                f"Session [{target_uid}] is already {target_ws.state}",
                status_code=400,
            )
    elif active_ws is not None:
        target_ws = active_ws
    else:
        return cp_ok({"message": "OK"})

    discarded_changes = target_ws.changes_count
    target_ws.overlay_data = None
    target_ws.base_snapshot = None
    target_ws.locked_uids.clear()
    target_ws.mutation_records.clear()
    target_ws.changes_count = 0
    target_ws.state = "discarded"
    target_ws.last_modify_posix = mock._next_timestamp_ms()

    rotate_sid_bindings_for_session(mock, target_ws)
    return cp_ok({"message": "OK", "number-of-discarded-changes": discarded_changes})


def resolve_session_by_uid(mock: FileReplayApiMock, uid: str, dom_name: str) -> dict[str, Any] | None:
    """Resolve a session dictionary from active work sessions or domain published history."""
    ws = mock._work_sessions.get(uid)
    if ws is not None:
        return ws.to_checkpoint_dict()
    search_domains = [dom_name] if dom_name in mock._domain_data else list(mock._domain_data.keys())
    for d_name in search_domains:
        d_files = mock._domain_data[d_name]
        for s in d_files.get("show-sessions", {}).get("objects", []):
            if isinstance(s, dict) and s.get("uid") == uid:
                return copy.deepcopy(s)
        last_pub = d_files.get("show-last-published-session", {})
        if isinstance(last_pub, dict) and last_pub.get("uid") == uid:
            return copy.deepcopy(last_pub)
    return None


def handle_show_changes(
    mock: FileReplayApiMock,
    dom_name: str,
    req: Mapping[str, Any],
    *,
    binding: SidBinding | None,
    wait_for_task: bool,
) -> ApiCallResult:
    """Compute and return a `show-changes` task for staged or published revisions."""
    to_uid = str(req.get("to-session") or "").strip()
    from_uid = str(req.get("from-session") or "").strip()
    from_ms = parse_checkpoint_date_ms(req.get("from-date"))
    to_ms = parse_checkpoint_date_ms(req.get("to-date"))
    global_dom = mock._effective_domain_files("Global", binding)

    change_entries: list[dict[str, Any]] = []
    if to_uid and to_uid in mock._work_sessions and mock._work_sessions[to_uid].state in ("open", "disconnected"):
        ws = mock._work_sessions[to_uid]
        before_dom = mock._domain_data.get(ws.domain, {})
        after_dom = ws.overlay_data if ws.overlay_data is not None else before_dom
        delta = compute_session_delta(
            before_dom,
            after_dom,
            global_before=mock._domain_data.get("Global", {}),
            global_after=global_dom,
            session_meta=ws.to_checkpoint_dict(),
        )
        if count_delta_items(delta) > 0:
            change_entries.append(delta)
    elif to_uid:
        matched_deltas = [d for d in mock._published_deltas.get(dom_name, []) if d.session_uid == to_uid]
        if matched_deltas:
            change_entries.extend(copy.deepcopy(d.changes) for d in matched_deltas)
        else:
            sess_meta = resolve_session_by_uid(mock, to_uid, dom_name)
            if sess_meta is None:
                return cp_error(
                    "generic_err_object_not_found",
                    f"Session [{to_uid}] not found in {dom_name}",
                    status_code=404,
                )
    else:
        pub_list = mock._published_deltas.get(dom_name, [])
        in_range = not bool(from_uid)
        for p_delta in pub_list:
            if from_uid and p_delta.session_uid == from_uid:
                in_range = True
                continue
            if not in_range:
                continue
            if from_ms is not None and p_delta.publish_time_posix < from_ms:
                continue
            if to_ms is not None and p_delta.publish_time_posix > to_ms:
                continue
            change_entries.append(copy.deepcopy(p_delta.changes))

    tid = mock._next_task_id()
    task_obj = build_show_changes_task(tid, change_entries)
    mock._tasks[tid] = task_obj
    if wait_for_task:
        return cp_ok({"tasks": [copy.deepcopy(task_obj)]}, task_id=tid)
    return cp_ok({"task-id": tid}, task_id=tid)


def rotate_sid_bindings_for_session(mock: FileReplayApiMock, ws: WorkSession) -> None:
    """Rebind active SIDs attached to `ws.uid` onto fresh open sessions (`OwnedSession` invariant)."""
    for act_binding in mock._sid_bindings.values():
        if act_binding.active and act_binding.session_uid == ws.uid:
            fresh_ws = mock._create_work_session(
                ws.domain,
                user_name=act_binding.user_name,
                name="",
                description="",
                application=ws.application,
                read_only=act_binding.read_only,
            )
            act_binding.session_uid = fresh_ws.uid


def record_publish_task(
    mock: FileReplayApiMock,
    session_uid: str | None,
    n_changes: int,
    *,
    wait_for_task: bool,
) -> ApiCallResult:
    """Create and store a Check Point publish completion task payload."""
    tid = mock._next_task_id()
    detail: dict[str, Any] = {
        "uid": f"td-{tid}",
        "statusDescription": "Publish completed successfully",
    }
    if session_uid:
        detail["revision"] = session_uid
        detail["publishResponse"] = {
            "uid": session_uid,
            "mode": "async",
            "number-of-published-changes": n_changes,
        }
        detail["publish-Response"] = {
            "uid": session_uid,
            "number-of-published-changes": n_changes,
        }
    t_obj: dict[str, Any] = {
        "uid": tid,
        "task-id": tid,
        "task-name": "Publish operation",
        "status": "succeeded",
        "progress-percentage": 100,
        "suppressed": False,
        "task-details": [detail],
    }
    mock._tasks[tid] = t_obj
    if wait_for_task:
        payload: dict[str, Any] = {"tasks": [copy.deepcopy(t_obj)]}
        if session_uid:
            payload["uid"] = session_uid
        return cp_ok(payload, task_id=tid)
    return cp_ok({"task-id": tid}, task_id=tid)


def handle_publish(
    mock: FileReplayApiMock,
    req: Mapping[str, Any],
    *,
    binding: SidBinding | None,
    wait_for_task: bool,
) -> ApiCallResult:
    """Commit or rebase a session's overlay into published domain state and record delta history."""
    req_uid = str(req.get("uid") or "").strip()
    ws: WorkSession | None = None
    if req_uid:
        ws = mock._work_sessions.get(req_uid)
        if ws is None:
            return cp_error("generic_err_object_not_found", f"Session [{req_uid}] not found", status_code=404)
        if binding is not None:
            if binding.read_only:
                return cp_error("err_validation_failed", "Cannot publish from a read-only session", status_code=400)
            if binding.domain not in ("System Data", ws.domain):
                return cp_error(
                    "err_validation_failed",
                    f"Session bound to domain [{binding.domain}] cannot publish session in [{ws.domain}]",
                    status_code=400,
                )
    elif binding is not None:
        ws = mock._work_sessions.get(binding.session_uid)

    if ws is None:
        return record_publish_task(mock, None, 0, wait_for_task=wait_for_task)

    if ws.read_only:
        return cp_error("err_validation_failed", "Cannot publish from a read-only session", status_code=400)
    if ws.state in ("published", "discarded"):
        return cp_error("err_validation_failed", f"Session [{ws.uid}] is already {ws.state}", status_code=400)

    target_dom = ws.domain
    if target_dom not in mock._domain_data:
        pub_ts = mock._next_timestamp_ms()
        ws.state = "published"
        ws.published_time_posix = pub_ts
        ws.last_modify_posix = pub_ts
        ws.published_changes = 0
        ws.changes_count = 0
        ws.locked_uids.clear()
        ws.overlay_data = None
        ws.base_snapshot = None
        rotate_sid_bindings_for_session(mock, ws)
        return record_publish_task(mock, ws.uid, 0, wait_for_task=wait_for_task)

    before_dom = copy.deepcopy(mock._domain_data[target_dom])
    current_pub_uid = mock._published_session_by_domain.get(target_dom, "")

    if ws.overlay_data is not None:
        if ws.base_published_uid == current_pub_uid and ws.base_domain_gen == mock._domain_generation[target_dom]:
            candidate_after = copy.deepcopy(ws.overlay_data)
        else:
            candidate_after = copy.deepcopy(before_dom)
            global_files = mock._domain_data.get("Global", {})
            for rec in ws.mutation_records:
                outcome = mock._apply_domain_mutation(
                    rec.command,
                    rec.payload,
                    dom_name=rec.domain,
                    target_files=candidate_after,
                    global_files=global_files,
                    all_domains=mock._domain_data,
                    user_name=ws.user_name,
                    locked_uids_out=set(),
                )
                if outcome is not None and not outcome[0].success:
                    return outcome[0]
    else:
        candidate_after = copy.deepcopy(before_dom)

    pub_ts = mock._next_timestamp_ms()
    ws.state = "published"
    ws.published_time_posix = pub_ts
    ws.last_modify_posix = pub_ts

    delta = compute_session_delta(
        before_dom,
        candidate_after,
        global_before=before_dom if target_dom == "Global" else mock._domain_data.get("Global", {}),
        global_after=candidate_after if target_dom == "Global" else mock._domain_data.get("Global", {}),
        session_meta=ws.to_checkpoint_dict(),
    )
    n_changes = count_delta_items(delta)
    ws.published_changes = n_changes
    ws.changes_count = 0
    ws.locked_uids.clear()
    ws.overlay_data = None
    ws.base_snapshot = None

    mock._domain_data[target_dom] = candidate_after
    mock._mark_domain_mutated(target_dom)
    mock._published_session_by_domain[target_dom] = ws.uid

    pub_dict = ws.to_checkpoint_dict()
    pub_dict["published-changes"] = n_changes
    pub_dict["number-of-published-changes"] = n_changes
    delta["session"] = copy.deepcopy(pub_dict)

    dom_files = mock._domain_data[target_dom]
    dom_files["show-last-published-session"] = copy.deepcopy(pub_dict)
    sessions_list = dom_files.setdefault("show-sessions", {}).setdefault("objects", [])
    sessions_list.insert(0, copy.deepcopy(pub_dict))
    dom_files["show-sessions"]["total"] = len(sessions_list)
    dom_files["show-sessions"]["to"] = len(sessions_list)
    dom_files["show-sessions"]["from"] = 1 if sessions_list else 0

    mock._published_deltas.setdefault(target_dom, []).append(
        PublishedDelta(
            session_uid=ws.uid,
            session_name=ws.name,
            domain=target_dom,
            user_name=ws.user_name,
            publish_time_posix=pub_ts,
            publish_time_iso=pub_dict["publish-time"]["iso-8601"],
            changes=delta,
        )
    )

    rotate_sid_bindings_for_session(mock, ws)
    return record_publish_task(mock, ws.uid, n_changes, wait_for_task=wait_for_task)
