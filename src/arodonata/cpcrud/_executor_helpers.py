"""Shared command allowlist, domain-head, and retry-folding helpers (`arodonata.cpcrud._executor_helpers`)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from arodonata.core.errors import ServerIdentityError, ValidationError
from arodonata.core.events import CPCRUDActionEvent
from arodonata.core.models.common import parse_cp_publish_timestamp, to_naive_utc
from arodonata.core.ports import ApiPort
from arodonata.cpcrud.models import (
    ActionResult,
    ApplyReport,
    DomainStamp,
    Outcome,
    PlannedAction,
)
from arodonata.cpcrud.state_reader import OBJECT_ITEM_TYPES, SERVICE_ITEM_TYPES

EXECUTABLE_RULE_TYPES: frozenset[str] = frozenset(
    {
        "access-rule",
        "nat-rule",
        "https-rule",
        "threat-rule",
    }
)

ALLOWED_COMMAND_MAP: dict[tuple[str, Outcome], str] = {
    **{(t, Outcome.CREATE): f"add-{t}" for t in OBJECT_ITEM_TYPES | SERVICE_ITEM_TYPES | EXECUTABLE_RULE_TYPES},
    **{(t, Outcome.UPDATE): f"set-{t}" for t in OBJECT_ITEM_TYPES | SERVICE_ITEM_TYPES | EXECUTABLE_RULE_TYPES},
    **{(t, Outcome.DELETE): f"delete-{t}" for t in OBJECT_ITEM_TYPES | SERVICE_ITEM_TYPES | EXECUTABLE_RULE_TYPES},
}


def resolve_allowlisted_command(action: PlannedAction) -> str:
    """Derive the canonical Web API write command for `action` from the strict `(object_type, outcome)` allowlist."""
    expected = ALLOWED_COMMAND_MAP.get((action.object_type, action.outcome))
    if expected is None:
        raise ValidationError(
            f"Unsupported CPCRUD action pair ({action.object_type!r}, {action.outcome.value!r}) for action {action.action_id!r}."
        )
    if action.command and action.command != expected:
        raise ValidationError(
            f"PlannedAction.command {action.command!r} disagrees with allowlisted command {expected!r} "
            f"for ({action.object_type!r}, {action.outcome.value!r})."
        )
    return expected


def _is_domain_head_stale(
    stamp: DomainStamp | None,
    current_uid: str | None,
    current_published_at: datetime | None,
    head_readable: bool,
) -> bool:
    """Return `True` if a domain's current published head cannot be read or drifted since `stamp`."""
    if not head_readable or stamp is None or not stamp.readable:
        return True
    if stamp.last_session_uid is not None:
        if current_uid != stamp.last_session_uid:
            return True
    elif current_uid is not None:
        return True

    if stamp.last_published_at is not None:
        return to_naive_utc(current_published_at) != to_naive_utc(stamp.last_published_at)
    return current_published_at is not None


async def check_current_domain_head(
    api: ApiPort,
    mgmt_name: str,
    domain_name: str,
) -> tuple[bool, str | None, datetime | None, str | None]:
    """Read `show-last-published-session` and return `(readable, uid, published_at, error)`."""
    try:
        res = await api.api_call(
            mgmt_name,
            "show-last-published-session",
            {},
            domain=domain_name or None,
        )
    except ServerIdentityError:
        raise
    except Exception as exc:
        return False, None, None, str(exc)

    if not res.success:
        return (
            False,
            None,
            None,
            res.error_message or res.error_code or f"HTTP {res.status_code}",
        )

    data = res.data if isinstance(res.data, dict) else {}
    uid_raw = data.get("uid")
    uid_str = str(uid_raw).strip() if isinstance(uid_raw, str) and uid_raw.strip() else None
    pub_at = parse_cp_publish_timestamp(data.get("publish-time") or data.get("last-modify-time"))
    return True, uid_str, pub_at, None


def _make_action_result_and_event(
    act: PlannedAction,
    *,
    outcome: Outcome,
    success: bool,
    command: str | None = None,
    target_uid: str | None = None,
    response_data: dict[str, Any] | None = None,
    message: str = "",
    error: str | None = None,
) -> tuple[ActionResult, CPCRUDActionEvent]:
    """Construct paired `ActionResult` and `CPCRUDActionEvent` models for an executor step."""
    res_item = ActionResult(
        action_id=act.action_id,
        mgmt_name=act.mgmt_name,
        domain_name=act.domain_name,
        operation=act.operation,
        object_type=act.object_type,
        name=act.name,
        resolved_name=act.resolved_name,
        target_uid=target_uid if target_uid is not None else act.target_uid,
        planned_outcome=act.outcome,
        outcome=outcome,
        status=outcome.value,
        success=success,
        command=command if command is not None else act.command,
        response_data=response_data or {},
        prior_state=act.prior_state,
        message=message,
        error=error,
    )
    event = CPCRUDActionEvent(
        phase="action_completed" if success else "action_failed",
        mgmt_name=act.mgmt_name,
        domain=act.domain_name or None,
        action_id=act.action_id,
        operation=act.operation,
        object_type=act.object_type,
        object_name=act.name,
        outcome=outcome.value,
        error=error,
        message=message,
    )
    return res_item, event


def _record_runtime_failure(
    act: PlannedAction,
    runtime_failed_names: set[str],
    runtime_failed_ids: set[str],
) -> None:
    """Record failed action IDs and object names so downstream steps skip dependent mutations."""
    if act.requested_name:
        runtime_failed_names.add(act.requested_name)
    if act.name:
        runtime_failed_names.add(act.name)
    runtime_failed_ids.add(act.action_id)


def _extract_published_session_uid(pub_data: dict[str, Any]) -> str | None:
    """Extract the published session UID from a direct `publish` payload or a polled `show-task` payload."""
    direct_uid = pub_data.get("uid")
    if isinstance(direct_uid, str) and direct_uid.strip():
        return direct_uid.strip()

    tasks = pub_data.get("tasks")
    if isinstance(tasks, list):
        for task in tasks:
            if not isinstance(task, dict):
                continue
            details = task.get("task-details")
            if not isinstance(details, list):
                continue
            for detail in details:
                if not isinstance(detail, dict):
                    continue
                rev = detail.get("revision")
                if isinstance(rev, str) and rev.strip():
                    return rev.strip()
                if isinstance(rev, dict):
                    rev_uid = rev.get("uid")
                    if isinstance(rev_uid, str) and rev_uid.strip():
                        return rev_uid.strip()
                for resp_key in ("publishResponse", "publish-Response"):
                    resp_block = detail.get(resp_key)
                    if isinstance(resp_block, dict):
                        block_uid = resp_block.get("uid")
                        if isinstance(block_uid, str) and block_uid.strip():
                            return block_uid.strip()
                sess_uid = detail.get("session-uid")
                if isinstance(sess_uid, str) and sess_uid.strip():
                    return sess_uid.strip()
    return None


def _fold_retry_report(cumulative: ApplyReport, retry_rep: ApplyReport) -> None:
    """Fold a retry pass's `ApplyReport` into the cumulative `ApplyReport`."""
    cumulative.retry_passes += 1
    cumulative.retry_reports.append(retry_rep)
    cumulative.completed_at = retry_rep.completed_at

    retry_by_id = {r.action_id: r for r in retry_rep.results}
    cumulative.results = [retry_by_id.get(r.action_id, r) for r in cumulative.results]

    for dom in retry_rep.published_domains:
        if dom not in cumulative.published_domains:
            cumulative.published_domains.append(dom)
    for s_dom in retry_rep.stale_domains:
        if s_dom not in cumulative.stale_domains:
            cumulative.stale_domains.append(s_dom)
    cumulative.published_sessions.update(retry_rep.published_sessions)
    cumulative.staged_sessions.extend(retry_rep.staged_sessions)
