"""Application-agnostic Check Point Script Repository management and execution service."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager, suppress
from typing import Any

from arodonata.core.config import ArodonataSettings
from arodonata.core.context import (
    WriteSession,
    get_write_session,
    normalize_domain_key,
    open_api_write_session,
)
from arodonata.core.errors import (
    AuthenticationError,
    RepositoryScriptError,
    RepositoryScriptNotFoundError,
    RepositoryScriptPermissionError,
    ServerIdentityError,
    SessionError,
    SessionStateError,
    ValidationError,
    is_script_permission_error,
    is_unsupported_script_command_error,
    redact_sid,
)
from arodonata.core.models.common import ApiCallResult
from arodonata.core.models.scripts import (
    EnsureRepositoryScriptResult,
    RepositoryScript,
    RepositoryScriptEnsureAction,
    RepositoryScriptExecutionOutcome,
    RepositoryScriptStatus,
    ScriptTargetExecutionResult,
    decode_base64_task_message,
    normalize_script_body,
)
from arodonata.core.ports import ApiPort
from arodonata.core.primitives import is_uuid
from arodonata.core.telemetry import span_attrs, traced

_NOT_FOUND_CODES: frozenset[str] = frozenset({"generic_err_object_not_found"})


def _is_not_found_text(code: str, message: str) -> bool:
    low_code = code.strip().lower()
    low_msg = message.strip().lower()
    if low_code in _NOT_FOUND_CODES:
        return True
    return "not found" in low_msg or "does not exist" in low_msg or "doesn't exist" in low_msg


def _is_target_not_found_in_run_script(
    low_msg: str,
    script_ref: str,
    target_refs: Sequence[str] | None,
) -> bool:
    """Return True when a `run-script` object-not-found error points to a target rather than the script."""
    low_ref = script_ref.strip().lower()
    other_targets = [t.strip().lower() for t in (target_refs or ()) if t.strip() and t.strip().lower() != low_ref]
    for tgt in other_targets:
        if f"[{tgt}]" in low_msg or f"'{tgt}'" in low_msg or f'"{tgt}"' in low_msg:
            return True
    if (
        (low_ref and low_ref in low_msg)
        or "repository script" in low_msg
        or "repository-script" in low_msg
        or "script-name" in low_msg
    ):
        return False
    return (
        any(tgt in low_msg for tgt in other_targets)
        or "target" in low_msg
        or "gateway" in low_msg
        or "requested object [" in low_msg
    )


def _classify_api_error(
    mgmt_name: str,
    domain_label: str,
    script_ref: str,
    *,
    operation: str,
    res: ApiCallResult,
    target_refs: Sequence[str] | None = None,
    known_sids: Sequence[str] | None = None,
) -> RepositoryScriptError:
    """Map an unsuccessful Check Point Management `ApiCallResult` to a typed script error."""
    code = str(res.error_code or (res.data.get("code") if isinstance(res.data, dict) else "") or "")
    msg = str(res.error_message or (res.data.get("message") if isinstance(res.data, dict) else "") or "").strip()
    if not msg:
        msg = f"{operation} failed with status {res.status_code}"
    if is_script_permission_error(code, msg):
        return RepositoryScriptPermissionError(
            mgmt_name,
            domain_label,
            script_ref,
            operation=operation,
            message=msg,
            known_sids=known_sids,
        )
    if is_unsupported_script_command_error(code, msg):
        return RepositoryScriptError(
            f"Check Point Script Repository API command {operation!r} is not supported on "
            f"{mgmt_name!r} ({domain_label!r}): {msg}",
            known_sids=known_sids,
        )
    if _is_not_found_text(code, msg):
        if operation == "run-script" and _is_target_not_found_in_run_script(msg.lower(), script_ref, target_refs):
            return RepositoryScriptError(
                f"Repository script {operation!r} failed for {script_ref!r} on {mgmt_name!r} ({domain_label!r}): {msg}",
                known_sids=known_sids,
            )
        return RepositoryScriptNotFoundError(
            mgmt_name,
            domain_label,
            script_ref,
            message=msg,
            known_sids=known_sids,
        )
    return RepositoryScriptError(
        f"Repository script {operation!r} failed for {script_ref!r} on {mgmt_name!r} ({domain_label!r}): {msg}",
        known_sids=known_sids,
    )


def _format_run_args(args: Sequence[str] | str | None) -> str:
    """Format positional `args` for `run-script` (`str` verbatim or space-joined sequence)."""
    if args is None:
        return ""
    if isinstance(args, str):
        return args
    parts = [str(item) for item in args if str(item) != ""]
    return " ".join(parts)


def _metadata_matches(
    existing: RepositoryScript,
    *,
    comments: str | None,
    color: str | None,
    tags: Sequence[str] | None,
) -> bool:
    """Return True if all explicitly supplied metadata fields match `existing`."""
    if comments is not None and existing.comments != comments:
        return False
    if color is not None and existing.color.strip().lower() != color.strip().lower():
        return False
    if tags is not None:
        expected_tags = sorted(str(t).strip() for t in tags if str(t).strip())
        existing_tags = sorted(t.strip() for t in existing.tags if t.strip())
        if existing_tags != expected_tags:
            return False
    return True


class ScriptRepositoryService:
    """Universal Check Point Script Repository CRUD, status, and execution service."""

    def __init__(
        self,
        *,
        api: ApiPort,
        settings: ArodonataSettings | None = None,
        write_session_factory: Callable[..., AbstractAsyncContextManager[WriteSession]] | None = None,
        on_domain_invalidated: Callable[[str, str | None], None] | None = None,
    ) -> None:
        self._api = api
        self._settings = settings
        self._write_session_factory = write_session_factory
        self._on_domain_invalidated = on_domain_invalidated

    def _invalidate_domain(self, mgmt_name: str, domain: str | None) -> None:
        if self._on_domain_invalidated is not None:
            self._on_domain_invalidated(mgmt_name, domain)
        elif hasattr(self._api, "invalidate_domain"):
            self._api.invalidate_domain(mgmt_name, domain)

    @asynccontextmanager
    async def _open_write_session(
        self,
        mgmt_name: str,
        domain: str | None,
        *,
        session_name: str | None = None,
        publish_on_exit: bool = True,
    ) -> AsyncIterator[WriteSession]:
        """Open an isolated `WriteSession` via injected factory or shared `open_api_write_session`."""
        dom_key = normalize_domain_key(domain)
        if self._write_session_factory is not None:
            async with self._write_session_factory(
                mgmt_name,
                dom_key,
                session_name=session_name,
                publish_on_exit=publish_on_exit,
            ) as ws:
                yield ws
            return

        async with open_api_write_session(
            self._api,
            mgmt_name,
            dom_key,
            session_name=session_name,
            publish_on_exit=publish_on_exit,
            on_domain_invalidated=self._invalidate_domain,
        ) as ws:
            yield ws

    @traced
    async def get_repository_script(
        self,
        mgmt_name: str,
        script_name_or_uid: str,
        *,
        domain: str | None = None,
        details_level: str = "full",
    ) -> RepositoryScript:
        """Fetch a single repository script by name or UID (`show-repository-script`)."""
        ref = script_name_or_uid.strip()
        if not ref:
            raise ValidationError("script_name_or_uid must not be blank.")
        dom_key = normalize_domain_key(domain)
        span_attrs(mgmt_name=mgmt_name, domain=dom_key, script_ref=ref)

        payload: dict[str, Any] = {"details-level": details_level}
        if is_uuid(ref):
            payload["uid"] = ref
        else:
            payload["name"] = ref

        res = await self._api.api_call(
            mgmt_name,
            "show-repository-script",
            payload,
            domain=dom_key,
            wait_for_task=True,
        )
        if not res.success:
            raise _classify_api_error(
                mgmt_name,
                dom_key,
                ref,
                operation="show-repository-script",
                res=res,
            )
        return RepositoryScript.from_cp_dict(mgmt_name, dom_key, res.data)

    @traced
    async def list_repository_scripts(
        self,
        mgmt_name: str,
        *,
        domain: str | None = None,
        details_level: str = "full",
        limit: int = 300,
    ) -> list[RepositoryScript]:
        """List repository scripts in `domain` (`show-repository-scripts`)."""
        dom_key = normalize_domain_key(domain)
        span_attrs(mgmt_name=mgmt_name, domain=dom_key, details_level=details_level)

        query_res = await self._api.api_query(
            mgmt_name,
            "show-repository-scripts",
            domain=dom_key,
            details_level=details_level,
            limit=limit,
        )
        if not query_res.success:
            err_res = ApiCallResult(
                success=False,
                status_code=400,
                error_code=query_res.code,
                error_message=query_res.error_message,
            )
            raise _classify_api_error(
                mgmt_name,
                dom_key,
                "*",
                operation="show-repository-scripts",
                res=err_res,
            )
        return [RepositoryScript.from_cp_dict(mgmt_name, dom_key, item) for item in query_res.objects]

    @traced
    async def check_repository_script(
        self,
        mgmt_name: str,
        script_name_or_uid: str,
        *,
        domain: str | None = None,
        expected_body: str | None = None,
    ) -> RepositoryScriptStatus:
        """Check whether a repository script exists and matches `expected_body` strictly read-only.

        Note: `exists=False` is also returned when permission is denied (`error_code='repository_script_permission_denied'`)
        or when the Management API does not support Script Repository commands (`error_code='repository_script_unsupported'`).
        Callers MUST inspect `error_code` before treating `exists=False` as absence of the script.
        """
        ref = script_name_or_uid.strip()
        if not ref:
            raise ValidationError("script_name_or_uid must not be blank.")
        dom_key = normalize_domain_key(domain)
        span_attrs(mgmt_name=mgmt_name, domain=dom_key, script_ref=ref)

        try:
            script = await self.get_repository_script(
                mgmt_name,
                ref,
                domain=dom_key,
                details_level="full",
            )
        except RepositoryScriptNotFoundError as exc:
            return RepositoryScriptStatus(
                mgmt_name=mgmt_name,
                domain_name=dom_key,
                script_ref=ref,
                exists=False,
                script=None,
                matches_expected=False if expected_body is not None else None,
                error_code="repository_script_not_found",
                error=exc.message,
            )
        except RepositoryScriptPermissionError as exc:
            return RepositoryScriptStatus(
                mgmt_name=mgmt_name,
                domain_name=dom_key,
                script_ref=ref,
                exists=False,
                script=None,
                matches_expected=False if expected_body is not None else None,
                error_code="repository_script_permission_denied",
                error=exc.message,
            )
        except RepositoryScriptError as exc:
            if is_unsupported_script_command_error(None, exc.message):
                return RepositoryScriptStatus(
                    mgmt_name=mgmt_name,
                    domain_name=dom_key,
                    script_ref=ref,
                    exists=False,
                    script=None,
                    matches_expected=False if expected_body is not None else None,
                    error_code="repository_script_unsupported",
                    error=exc.message,
                )
            raise

        matches: bool | None = None
        if expected_body is not None:
            matches = normalize_script_body(script.script_body) == normalize_script_body(expected_body)

        return RepositoryScriptStatus(
            mgmt_name=mgmt_name,
            domain_name=dom_key,
            script_ref=ref,
            exists=True,
            script=script,
            matches_expected=matches,
        )

    @traced
    async def ensure_repository_script(
        self,
        mgmt_name: str,
        script_name: str,
        script_body: str,
        *,
        domain: str | None = None,
        comments: str | None = None,
        color: str | None = None,
        tags: Sequence[str] | None = None,
    ) -> EnsureRepositoryScriptResult:
        """Idempotently ensure `script_name` exists with `script_body`, avoiding writes when already matching."""
        clean_name = script_name.strip()
        if not clean_name:
            raise ValidationError("script_name must not be blank.")
        if not script_body or not script_body.strip():
            raise ValidationError("script_body must not be blank.")
        dom_key = normalize_domain_key(domain)
        span_attrs(mgmt_name=mgmt_name, domain=dom_key, script_name=clean_name)

        status = await self.check_repository_script(
            mgmt_name,
            clean_name,
            domain=dom_key,
            expected_body=script_body,
        )
        if status.error_code == "repository_script_permission_denied":
            raise RepositoryScriptPermissionError(
                mgmt_name,
                dom_key,
                clean_name,
                operation="check",
                message=status.error,
            )
        if status.error_code == "repository_script_unsupported":
            raise RepositoryScriptError(status.error or f"Repository scripts are not supported on {mgmt_name!r}.")
        if (
            status.exists
            and status.matches_expected
            and status.script is not None
            and _metadata_matches(status.script, comments=comments, color=color, tags=tags)
        ):
            return EnsureRepositoryScriptResult(
                mgmt_name=mgmt_name,
                domain_name=dom_key,
                action="unchanged",
                script=status.script,
                published=False,
            )

        extra_fields: dict[str, Any] = {}
        if comments is not None:
            extra_fields["comments"] = comments
        if color is not None:
            extra_fields["color"] = color
        if tags is not None:
            extra_fields["tags"] = list(tags)

        async def _apply_in_session() -> tuple[RepositoryScriptEnsureAction, RepositoryScript]:
            if status.exists:
                set_payload: dict[str, Any] = {
                    "script-body": script_body,
                    **extra_fields,
                }
                if status.script and status.script.uid:
                    set_payload["uid"] = status.script.uid
                else:
                    set_payload["name"] = clean_name
                res = await self._api.api_call(
                    mgmt_name,
                    "set-repository-script",
                    set_payload,
                    domain=dom_key,
                    wait_for_task=True,
                )
                if not res.success:
                    raise _classify_api_error(
                        mgmt_name,
                        dom_key,
                        clean_name,
                        operation="set-repository-script",
                        res=res,
                    )
                return "updated", RepositoryScript.from_cp_dict(
                    mgmt_name,
                    dom_key,
                    res.data,
                    fallback_body=script_body,
                )

            add_payload: dict[str, Any] = {
                "name": clean_name,
                "script-body": script_body,
                **extra_fields,
            }
            res = await self._api.api_call(
                mgmt_name,
                "add-repository-script",
                add_payload,
                domain=dom_key,
                wait_for_task=True,
            )
            if not res.success:
                err_msg = (res.error_message or "").lower()
                if "already exists" in err_msg or "more than one object named" in err_msg:
                    set_res = await self._api.api_call(
                        mgmt_name,
                        "set-repository-script",
                        {"name": clean_name, "script-body": script_body, **extra_fields},
                        domain=dom_key,
                        wait_for_task=True,
                    )
                    if not set_res.success:
                        raise _classify_api_error(
                            mgmt_name,
                            dom_key,
                            clean_name,
                            operation="set-repository-script",
                            res=set_res,
                        )
                    return "updated", RepositoryScript.from_cp_dict(
                        mgmt_name,
                        dom_key,
                        set_res.data,
                        fallback_body=script_body,
                    )
                raise _classify_api_error(
                    mgmt_name,
                    dom_key,
                    clean_name,
                    operation="add-repository-script",
                    res=res,
                )
            return "created", RepositoryScript.from_cp_dict(
                mgmt_name,
                dom_key,
                res.data,
                fallback_body=script_body,
            )

        active_ws = get_write_session(mgmt_name=mgmt_name, domain_name=dom_key)
        if active_ws is not None:
            action, script_obj = await _apply_in_session()
            return EnsureRepositoryScriptResult(
                mgmt_name=mgmt_name,
                domain_name=dom_key,
                action=action,
                script=script_obj,
                published=False,
            )

        try:
            async with self._open_write_session(
                mgmt_name,
                dom_key,
                session_name=f"arodonata-ensure-script-{clean_name}",
                publish_on_exit=True,
            ):
                action, script_obj = await _apply_in_session()
        except (SessionError, AuthenticationError) as exc:
            if is_script_permission_error(None, str(exc)):
                raise RepositoryScriptPermissionError(
                    mgmt_name,
                    dom_key,
                    clean_name,
                    operation="publish",
                    message=str(exc),
                ) from exc
            raise

        return EnsureRepositoryScriptResult(
            mgmt_name=mgmt_name,
            domain_name=dom_key,
            action=action,
            script=script_obj,
            published=True,
        )

    @traced
    async def delete_repository_script(
        self,
        mgmt_name: str,
        script_name_or_uid: str,
        *,
        domain: str | None = None,
    ) -> bool:
        """Delete a repository script from `domain` (`delete-repository-script`)."""
        ref = script_name_or_uid.strip()
        if not ref:
            raise ValidationError("script_name_or_uid must not be blank.")
        dom_key = normalize_domain_key(domain)
        span_attrs(mgmt_name=mgmt_name, domain=dom_key, script_ref=ref)

        del_payload: dict[str, Any] = {"uid": ref} if is_uuid(ref) else {"name": ref}

        async def _delete_in_session() -> bool:
            res = await self._api.api_call(
                mgmt_name,
                "delete-repository-script",
                del_payload,
                domain=dom_key,
                wait_for_task=True,
            )
            if not res.success:
                raise _classify_api_error(
                    mgmt_name,
                    dom_key,
                    ref,
                    operation="delete-repository-script",
                    res=res,
                )
            return True

        active_ws = get_write_session(mgmt_name=mgmt_name, domain_name=dom_key)
        if active_ws is not None:
            return await _delete_in_session()

        try:
            async with self._open_write_session(
                mgmt_name,
                dom_key,
                session_name=f"arodonata-delete-script-{ref}",
                publish_on_exit=True,
            ):
                return await _delete_in_session()
        except (SessionError, AuthenticationError) as exc:
            if is_script_permission_error(None, str(exc)):
                raise RepositoryScriptPermissionError(
                    mgmt_name,
                    dom_key,
                    ref,
                    operation="delete-repository-script",
                    message=str(exc),
                ) from exc
            raise

    @traced
    async def run_repository_script(
        self,
        mgmt_name: str,
        script_name_or_uid: str,
        targets: Sequence[str] | str,
        *,
        domain: str | None = None,
        args: Sequence[str] | str | None = None,
        comments: str | None = None,
        timeout: float | None = None,
        script_timeout: int | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        session_getter: Callable[[str, str | None], Awaitable[tuple[str, str]]] | None = None,
    ) -> RepositoryScriptExecutionOutcome:
        """Execute a pre-approved repository script via Check Point `run-script` (`script-type="repository"`).

        Forwards `targets` and `args` (`str` verbatim or space-joined sequence) without route-collection
        or VSX assumptions, running in a dedicated non-read-only session (without `publish` or `discard`)
        unless an explicit `sid` or matching active `WriteSession` is already bound.
        """
        ref = script_name_or_uid.strip()
        if not ref:
            raise ValidationError("script_name_or_uid must not be blank.")
        if isinstance(targets, str):
            target_list = [targets.strip()] if targets.strip() else []
        else:
            target_list = [str(t).strip() for t in targets if str(t).strip()]
        if not target_list:
            raise ValidationError("At least one target gateway name or UID is required.")

        dom_key = normalize_domain_key(domain)
        args_str = _format_run_args(args)
        span_attrs(mgmt_name=mgmt_name, domain=dom_key, script_ref=ref, target_count=len(target_list))

        payload: dict[str, Any] = {
            "script-type": "repository",
            "targets": target_list,
        }
        if is_uuid(ref):
            payload["uid"] = ref
        else:
            payload["script-name"] = ref
        if args_str:
            payload["args"] = args_str
        if comments is not None:
            payload["comments"] = comments
        if script_timeout is not None:
            payload["timeout"] = int(script_timeout)

        active_ws = None if sid is not None else get_write_session(mgmt_name=mgmt_name, domain_name=dom_key)
        used_sids: list[str] = []

        async def _call_run_script(eff_sid: str | None, eff_ip: str | None) -> ApiCallResult:
            return await self._api.api_call(
                mgmt_name,
                "run-script",
                payload,
                domain=dom_key,
                sid=eff_sid,
                server_ip=eff_ip,
                wait_for_task=True,
                timeout=timeout,
            )

        if sid is not None:
            if sid:
                used_sids.append(sid)
            res = await _call_run_script(sid, server_ip)
        elif active_ws is not None:
            if active_ws.sid:
                used_sids.append(active_ws.sid)
            res = await _call_run_script(active_ws.sid, active_ws.server_ip)
        elif session_getter is not None:
            try:
                ded_sid, ded_ip = await session_getter(mgmt_name, dom_key)
            except (SessionError, SessionStateError, AuthenticationError) as exc:
                if is_script_permission_error(None, str(exc)):
                    raise RepositoryScriptPermissionError(
                        mgmt_name,
                        dom_key,
                        ref,
                        operation="run-script",
                        message=str(exc),
                    ) from exc
                raise
            if ded_sid:
                used_sids.append(ded_sid)
            res = await _call_run_script(ded_sid, ded_ip)
        else:
            try:
                ded_sid, ded_ip = await self._api.create_dedicated_session(
                    mgmt_name,
                    domain=dom_key,
                    session_name="arodonata-run-repo-script",
                )
            except (SessionError, SessionStateError, AuthenticationError) as exc:
                if is_script_permission_error(None, str(exc)):
                    raise RepositoryScriptPermissionError(
                        mgmt_name,
                        dom_key,
                        ref,
                        operation="run-script",
                        message=str(exc),
                    ) from exc
                raise
            if ded_sid:
                used_sids.append(ded_sid)
            try:
                res = await _call_run_script(ded_sid, ded_ip)
            except ServerIdentityError:
                raise
            except Exception as exc:
                if ded_sid and len(ded_sid) >= 4 and ded_sid in str(exc):
                    raise RepositoryScriptError(str(exc), known_sids=[ded_sid]) from None
                raise
            finally:
                with suppress(Exception):
                    await self._api.logout_sid(mgmt_name, ded_sid, server_ip=ded_ip)

        known_sids = used_sids or None
        tasks_raw = res.data.get("tasks") if isinstance(res.data, dict) else None
        has_tasks = isinstance(tasks_raw, list) and len(tasks_raw) > 0
        if not res.success and not has_tasks:
            raise _classify_api_error(
                mgmt_name,
                dom_key,
                ref,
                operation="run-script",
                res=res,
                target_refs=target_list,
                known_sids=known_sids,
            )

        if (
            not res.success
            and res.error_message
            and is_script_permission_error(str(res.error_code or ""), str(res.error_message))
        ):
            raise RepositoryScriptPermissionError(
                mgmt_name,
                dom_key,
                ref,
                operation="run-script",
                message=res.error_message,
                known_sids=known_sids,
            )

        task_ids: list[str] = []
        target_results: list[ScriptTargetExecutionResult] = []
        tasks_list = [t for t in tasks_raw if isinstance(t, dict)] if isinstance(tasks_raw, list) else []

        for task_idx, task_dict in enumerate(tasks_list):
            tid = str(task_dict.get("task-id") or task_dict.get("uid") or "")
            if tid and tid not in task_ids:
                task_ids.append(tid)
            task_status = str(task_dict.get("status") or "").strip()
            task_ok = task_status.lower() in ("succeeded", "ok", "")
            details = task_dict.get("task-details")

            if isinstance(details, list) and details:
                for detail in details:
                    if not isinstance(detail, dict):
                        continue
                    t_uid = str(detail.get("gatewayId") or detail.get("target-uid") or "")
                    t_name = str(detail.get("gatewayName") or detail.get("target-name") or detail.get("target") or "")
                    if not t_name and not t_uid and task_idx < len(target_list):
                        t_label = target_list[task_idx]
                    else:
                        t_label = t_name or t_uid
                    raw_msg = (
                        detail.get("responseMessage") or detail.get("response-message") or detail.get("output") or ""
                    )
                    raw_err = (
                        detail.get("responseError")
                        or detail.get("response-error")
                        or detail.get("fault-message")
                        or detail.get("error-message")
                        or ""
                    )
                    stdout_str = decode_base64_task_message(str(raw_msg)) if raw_msg else ""
                    stderr_str = decode_base64_task_message(str(raw_err)) if raw_err else ""
                    if stderr_str and known_sids:
                        stderr_str = redact_sid(stderr_str, known_sids=known_sids)
                    status_desc = str(detail.get("statusDescription") or "").strip()
                    detail_status = str(detail.get("statusCode") or task_status or "").strip()
                    detail_ok = (
                        detail_status.lower() in ("succeeded", "ok")
                        if detail_status
                        else (task_ok and bool(res.success))
                    )
                    rev_raw = detail.get("revision")
                    target_results.append(
                        ScriptTargetExecutionResult(
                            target=t_label,
                            target_name=t_name,
                            target_uid=t_uid,
                            task_id=tid,
                            status=detail_status or task_status,
                            success=detail_ok,
                            stdout=stdout_str,
                            stderr=stderr_str,
                            status_description=status_desc,
                            revision=str(rev_raw) if rev_raw is not None else None,
                        )
                    )
            else:
                t_label = str(task_dict.get("target") or (target_list[task_idx] if task_idx < len(target_list) else ""))
                fallback_stderr = str(res.error_message or "") if not res.success else ""
                if fallback_stderr and known_sids:
                    fallback_stderr = redact_sid(fallback_stderr, known_sids=known_sids)
                target_results.append(
                    ScriptTargetExecutionResult(
                        target=t_label,
                        target_name=t_label,
                        task_id=tid,
                        status=task_status,
                        success=task_ok and bool(res.success),
                        stdout="",
                        stderr=fallback_stderr,
                    )
                )

        if not target_results and isinstance(res.data, dict):
            top_msg = res.data.get("responseMessage") or res.data.get("response-message") or res.data.get("output")
            if isinstance(top_msg, str) and top_msg.strip():
                target_results.append(
                    ScriptTargetExecutionResult(
                        target=target_list[0],
                        target_name=target_list[0],
                        status="succeeded" if res.success else "failed",
                        success=bool(res.success),
                        stdout=decode_base64_task_message(top_msg),
                    )
                )

        combined_stdout = "\n".join(r.stdout for r in target_results if r.stdout)
        combined_stderr = "\n".join(r.stderr for r in target_results if r.stderr)
        if combined_stderr and known_sids:
            combined_stderr = redact_sid(combined_stderr, known_sids=known_sids)
        overall_ok = bool(res.success) and (all(r.success for r in target_results) if target_results else True)
        err_msg: str | None = None
        if not overall_ok:
            err_msg = res.error_message or combined_stderr or "Repository script execution failed."
            if known_sids:
                err_msg = redact_sid(err_msg, known_sids=known_sids)

        return RepositoryScriptExecutionOutcome(
            mgmt_name=mgmt_name,
            domain_name=dom_key,
            script_ref=ref,
            args=args_str,
            success=overall_ok,
            task_ids=task_ids,
            targets=target_results,
            stdout=combined_stdout,
            stderr=combined_stderr,
            error_code=None if overall_ok else (res.error_code or "task_failed"),
            error_message=err_msg,
        )


__all__ = [
    "ScriptRepositoryService",
]
