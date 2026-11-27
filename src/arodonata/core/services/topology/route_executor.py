"""Live CLI execution (`SSH` + `cprid` inline and repository `run-script` fallback)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence

from arodonata.core.context import get_write_session, shielded_best_effort
from arodonata.core.errors import (
    AuthenticationError,
    RepositoryScriptError,
    RepositoryScriptNotFoundError,
    RepositoryScriptPermissionError,
    RepositoryScriptUnsupportedError,
    ServerIdentityError,
    SessionError,
    SessionStateError,
    is_script_permission_error,
    is_unsupported_script_command_error,
    redact_sid,
)
from arodonata.core.models.scripts import CpridScriptMode
from arodonata.core.models.topology import GatewayCliResult, GatewayCliTarget
from arodonata.core.ports import ApiPort, GatewayCliCallable, GatewayCliPort
from arodonata.core.services.script_service import ScriptRepositoryService
from arodonata.core.services.topology._shared import RepositoryScriptArgsCallable
from arodonata.core.services.topology.route_parsers import decode_cprid_task_output, extract_vs_slice_from_bundle
from arodonata.core.services.topology.route_scripts import (
    DEFAULT_ROUTE_COLLECT_REPOSITORY_SCRIPT_NAME,
    VSX_BUNDLE_START_MARKER,
    AutoScriptModeResolver,
)


def _scrub_known_sids(text: str, known_sids: Sequence[str] | None) -> str:
    """Redact explicit session identifiers when bare `known_sids` are present; pattern scrubbing happens on models."""
    if not text or not known_sids:
        return text
    return redact_sid(text, known_sids=known_sids)


def _format_cli_error(
    ssh_error: str | None,
    cprid_detail: str,
    *,
    cprid_prefix: str = "",
    known_sids: Sequence[str] | None = None,
) -> str:
    """Format an SSH/cprid failure message with bare-SID scrubbing (`GatewayCliResult` redacts regex patterns)."""
    msg = (
        f"SSH failed ({ssh_error}); cprid fallback failed ({cprid_detail})"
        if ssh_error
        else (f"{cprid_prefix}{cprid_detail}" if cprid_prefix else cprid_detail)
    )
    return _scrub_known_sids(msg, known_sids)


async def _execute_ssh_gateway_cli(
    target: GatewayCliTarget,
    script: str,
    *,
    gateway_cli: GatewayCliPort | GatewayCliCallable,
    fallback_to_cprid: bool,
    timeout: float,
) -> tuple[GatewayCliResult | None, str | None]:
    """Execute `script` over injected `gateway_cli`, returning `(result_or_None, ssh_error)`."""
    try:
        if isinstance(gateway_cli, GatewayCliPort):
            raw_res = await gateway_cli.execute_command(target, script, timeout=timeout)
        else:
            raw_res = await gateway_cli(target, script)

        if isinstance(raw_res, str):
            has_vs_err = "_vs_error=" in raw_res
            missing_vsid_res = bool(
                target.vs_name
                and target.vsid is None
                and not has_vs_err
                and "===ARODONATA_VSID_RESOLVED=" not in raw_res
            )
            ok = not has_vs_err and not missing_vsid_res
            err_msg = (
                raw_res.strip()
                if has_vs_err
                else (f"Unable to resolve VSID for Virtual System {target.vs_name!r}" if missing_vsid_res else None)
            )
            return (
                GatewayCliResult(
                    success=ok,
                    stdout=raw_res,
                    stderr=err_msg or "",
                    exit_code=0 if ok else 1,
                    executor="ssh",
                    error_message=err_msg,
                ),
                None,
            )

        if isinstance(raw_res, GatewayCliResult):
            if "_vs_error=" in raw_res.stdout and raw_res.success:
                return (
                    GatewayCliResult(
                        success=False,
                        stdout=raw_res.stdout,
                        stderr=raw_res.stderr,
                        exit_code=1,
                        executor=raw_res.executor,
                        error_code=raw_res.error_code,
                        error_message=raw_res.stdout.strip(),
                    ),
                    None,
                )
            if (
                target.vs_name
                and target.vsid is None
                and raw_res.success
                and "===ARODONATA_VSID_RESOLVED=" not in raw_res.stdout
            ):
                return (
                    GatewayCliResult(
                        success=False,
                        stdout=raw_res.stdout,
                        stderr=raw_res.stderr,
                        exit_code=1,
                        executor=raw_res.executor,
                        error_code=raw_res.error_code,
                        error_message=f"Unable to resolve VSID for Virtual System {target.vs_name!r}",
                    ),
                    None,
                )
            if raw_res.success or not fallback_to_cprid:
                if raw_res.stdout or raw_res.stderr or raw_res.error_message or raw_res.bundle_stdout:
                    # Ensure boundary redaction even if raw_res was created via model_construct or mutated
                    return (
                        GatewayCliResult(
                            success=raw_res.success,
                            stdout=raw_res.stdout,
                            stderr=raw_res.stderr,
                            exit_code=raw_res.exit_code,
                            executor=raw_res.executor,
                            error_code=raw_res.error_code,
                            error_message=raw_res.error_message,
                            bundle_stdout=raw_res.bundle_stdout,
                        ),
                        None,
                    )
                return raw_res, None
            ssh_err = raw_res.error_message or raw_res.stderr or f"SSH exited with {raw_res.exit_code}"
            return None, ssh_err
    except ServerIdentityError:
        raise
    except Exception as exc:
        ssh_err = str(exc)
        if not fallback_to_cprid:
            return (
                GatewayCliResult(
                    success=False,
                    stdout="",
                    stderr=ssh_err,
                    exit_code=1,
                    executor="ssh",
                    error_message=ssh_err,
                ),
                ssh_err,
            )
        return None, ssh_err

    if not fallback_to_cprid:
        return (
            GatewayCliResult(
                success=False,
                stdout="",
                stderr="SSH execution failed",
                exit_code=1,
                executor="ssh",
                error_message="SSH execution failed",
            ),
            None,
        )
    return None, None


async def _run_inline_cprid(
    target: GatewayCliTarget,
    script: str,
    *,
    api: ApiPort,
    timeout: float,
    cprid_session_getter: Callable[[str, str], Awaitable[tuple[str, str]]] | None,
    ssh_error: str | None,
) -> GatewayCliResult:
    """Execute inline `run-script` (`one time`) via Check Point `cprid`."""
    payload = {
        "script-name": f"arodonata-route-collect-{target.gateway_name}",
        "script": script,
        "targets": [target.node_uid or target.node_name],
    }
    used_sids: list[str] = []
    active_ws = get_write_session(mgmt_name=target.mgmt_name, domain_name=target.domain_name)
    if active_ws is not None and active_ws.sid:
        used_sids.append(active_ws.sid)
    try:
        try:
            res = await api.api_call(
                target.mgmt_name,
                "run-script",
                payload,
                domain=target.domain_name,
                wait_for_task=True,
                timeout=timeout,
            )
        except SessionStateError:
            if cprid_session_getter is not None:
                ded_sid, ded_ip = await cprid_session_getter(target.mgmt_name, target.domain_name)
                if ded_sid:
                    used_sids.append(ded_sid)
                res = await api.api_call(
                    target.mgmt_name,
                    "run-script",
                    payload,
                    domain=target.domain_name,
                    sid=ded_sid,
                    server_ip=ded_ip,
                    wait_for_task=True,
                    timeout=timeout,
                )
            else:
                ded_sid, ded_ip = await api.create_dedicated_session(
                    target.mgmt_name,
                    domain=target.domain_name,
                    session_name="arodonata-route-collect",
                )
                if ded_sid:
                    used_sids.append(ded_sid)
                try:
                    res = await api.api_call(
                        target.mgmt_name,
                        "run-script",
                        payload,
                        domain=target.domain_name,
                        sid=ded_sid,
                        server_ip=ded_ip,
                        wait_for_task=True,
                        timeout=timeout,
                    )
                finally:
                    await shielded_best_effort(api.logout_sid(target.mgmt_name, ded_sid, server_ip=ded_ip))
    except ServerIdentityError:
        raise
    except (SessionError, AuthenticationError) as exc:
        known = used_sids or None
        exc_msg = _scrub_known_sids(str(exc), known)
        session_err_code = "repository_script_permission_denied" if is_script_permission_error(None, exc_msg) else None
        err_msg = _format_cli_error(ssh_error, exc_msg, cprid_prefix="run-script failed: ", known_sids=known)
        return GatewayCliResult(
            success=False,
            stdout="",
            stderr=err_msg,
            exit_code=1,
            executor="cprid",
            error_code=session_err_code,
            error_message=err_msg,
        )
    except Exception as exc:
        known = used_sids or None
        err_msg = _format_cli_error(ssh_error, str(exc), cprid_prefix="run-script failed: ", known_sids=known)
        return GatewayCliResult(
            success=False,
            stdout="",
            stderr=err_msg,
            exit_code=1,
            executor="cprid",
            error_message=err_msg,
        )

    ok_decode, stdout_str, stderr_str = decode_cprid_task_output(res.data)
    missing_vsid_res = bool(target.vs_name and target.vsid is None and "===ARODONATA_VSID_RESOLVED=" not in stdout_str)
    overall_ok = res.success and ok_decode and not missing_vsid_res
    err_out: str | None = None
    err_code: str | None = None
    known = used_sids or None
    clean_stdout = _scrub_known_sids(stdout_str, known)
    clean_stderr = _scrub_known_sids(stderr_str, known)
    if not overall_ok:
        if not res.success and is_script_permission_error(res.error_code, res.error_message):
            err_code = "repository_script_permission_denied"
        raw_err_out = (
            clean_stderr
            or _scrub_known_sids(res.error_message or "", known)
            or (
                f"Unable to resolve VSID for Virtual System {target.vs_name!r}"
                if missing_vsid_res
                else "run-script task did not succeed"
            )
        )
        err_out = _format_cli_error(ssh_error, raw_err_out, known_sids=known)

    return GatewayCliResult(
        success=overall_ok,
        stdout=clean_stdout,
        stderr=clean_stderr,
        exit_code=0 if overall_ok else 1,
        executor="cprid",
        error_code=err_code,
        error_message=err_out,
    )


async def _run_repository_cprid(
    target: GatewayCliTarget,
    *,
    api: ApiPort,
    timeout: float,
    cprid_session_getter: Callable[[str, str], Awaitable[tuple[str, str]]] | None,
    repository_script_name: str,
    repository_script_args_fn: RepositoryScriptArgsCallable | None,
    max_routes: int | None,
    script_service: ScriptRepositoryService | None,
    ssh_error: str | None,
) -> GatewayCliResult:
    """Execute pre-approved repository `run-script` via `ScriptRepositoryService`."""
    eff_service = script_service or ScriptRepositoryService(api=api)
    try:
        args_val = repository_script_args_fn(target, max_routes) if repository_script_args_fn is not None else None
    except ServerIdentityError:
        raise
    except Exception as exc:
        err_msg = _format_cli_error(ssh_error, str(exc))
        return GatewayCliResult(
            success=False,
            stdout="",
            stderr=err_msg,
            exit_code=1,
            executor="cprid",
            error_message=err_msg,
        )

    used_sids: list[str] = []
    active_ws = get_write_session(mgmt_name=target.mgmt_name, domain_name=target.domain_name)
    if active_ws is not None and active_ws.sid:
        used_sids.append(active_ws.sid)
    session_getter_wrapped: Callable[[str, str | None], Awaitable[tuple[str, str]]] | None = None
    if cprid_session_getter is not None:

        async def _wrapped_getter(m_name: str, d_name: str | None) -> tuple[str, str]:
            sid_val, ip_val = await cprid_session_getter(m_name, d_name or target.domain_name)
            if sid_val:
                used_sids.append(sid_val)
            return sid_val, ip_val

        session_getter_wrapped = _wrapped_getter

    try:
        outcome = await eff_service.run_repository_script(
            target.mgmt_name,
            repository_script_name,
            [target.node_uid or target.node_name],
            domain=target.domain_name,
            args=args_val,
            timeout=timeout,
            session_getter=session_getter_wrapped,
        )
    except ServerIdentityError:
        raise
    except RepositoryScriptNotFoundError as exc:
        known = used_sids or None
        exc_msg = _scrub_known_sids(str(exc), known)
        err_msg = _format_cli_error(ssh_error, exc_msg, known_sids=known)
        return GatewayCliResult(
            success=False,
            stdout="",
            stderr=exc_msg,
            exit_code=1,
            executor="cprid",
            error_code="repository_script_not_found",
            error_message=err_msg,
        )
    except RepositoryScriptPermissionError as exc:
        known = used_sids or None
        exc_msg = _scrub_known_sids(str(exc), known)
        err_msg = _format_cli_error(ssh_error, exc_msg, known_sids=known)
        return GatewayCliResult(
            success=False,
            stdout="",
            stderr=exc_msg,
            exit_code=1,
            executor="cprid",
            error_code="repository_script_permission_denied",
            error_message=err_msg,
        )
    except RepositoryScriptUnsupportedError as exc:
        known = used_sids or None
        exc_msg = _scrub_known_sids(str(exc), known)
        err_msg = _format_cli_error(ssh_error, exc_msg, known_sids=known)
        return GatewayCliResult(
            success=False,
            stdout="",
            stderr=exc_msg,
            exit_code=1,
            executor="cprid",
            error_code="repository_script_unsupported",
            error_message=err_msg,
        )
    except RepositoryScriptError as exc:
        known = used_sids or None
        exc_msg = _scrub_known_sids(str(exc), known)
        err_msg = _format_cli_error(ssh_error, exc_msg, known_sids=known)
        err_code = "repository_script_unsupported" if is_unsupported_script_command_error(None, exc_msg) else None
        return GatewayCliResult(
            success=False,
            stdout="",
            stderr=exc_msg,
            exit_code=1,
            executor="cprid",
            error_code=err_code,
            error_message=err_msg,
        )
    except Exception as exc:
        known = used_sids or None
        err_msg = _format_cli_error(ssh_error, str(exc), cprid_prefix="run-script failed: ", known_sids=known)
        return GatewayCliResult(
            success=False,
            stdout="",
            stderr=err_msg,
            exit_code=1,
            executor="cprid",
            error_message=err_msg,
        )

    known = used_sids or None
    stdout_str = _scrub_known_sids(outcome.stdout, known)
    stderr_str = _scrub_known_sids(outcome.stderr, known)
    is_vs = (target.vsid is not None and int(target.vsid) > 0) or bool(target.vs_name and target.vs_name.strip())
    is_bundle = VSX_BUNDLE_START_MARKER in stdout_str

    if is_bundle:
        overall_ok = outcome.success
        err_out: str | None = None
        if not overall_ok:
            raw_err_out = (
                stderr_str or _scrub_known_sids(outcome.error_message or "", known) or "run-script task did not succeed"
            )
            err_out = _format_cli_error(ssh_error, raw_err_out, known_sids=known)

        base_res = GatewayCliResult(
            success=overall_ok,
            stdout=stdout_str,
            stderr=stderr_str,
            exit_code=0 if overall_ok else 1,
            executor="cprid",
            error_code=None if overall_ok else outcome.error_code,
            error_message=err_out,
            bundle_stdout=stdout_str,
        )
        if is_vs:
            slice_res = extract_vs_slice_from_bundle(
                stdout_str,
                vsid=target.vsid,
                vs_name=target.vs_name,
                executor="cprid",
                base_result=base_res,
            )
            return slice_res.model_copy(update={"bundle_stdout": stdout_str})
        return base_res

    # Non-bundle output:
    if outcome.success and args_val is None and is_vs:
        err_msg = _format_cli_error(
            ssh_error,
            f"Virtual System {target.vs_name or target.vsid} expected VSX bundle output, but no "
            "bundle markers were found in repository script output. The repository script may be outdated.",
            known_sids=known,
        )
        return GatewayCliResult(
            success=False,
            stdout="",
            stderr=stderr_str,
            exit_code=1,
            executor="cprid",
            error_code="vsx_bundle_missing",
            error_message=err_msg,
        )

    has_vs_err = "_vs_error=" in stdout_str
    missing_vsid_res = bool(target.vs_name and target.vsid is None and "===ARODONATA_VSID_RESOLVED=" not in stdout_str)
    overall_ok = outcome.success and not has_vs_err and not missing_vsid_res
    err_out = None
    if not overall_ok:
        raw_err_out = (
            (stdout_str.strip() if has_vs_err else None)
            or stderr_str
            or _scrub_known_sids(outcome.error_message or "", known)
            or (
                f"Unable to resolve VSID for Virtual System {target.vs_name!r}"
                if missing_vsid_res
                else "run-script task did not succeed"
            )
        )
        err_out = _format_cli_error(ssh_error, raw_err_out, known_sids=known)

    return GatewayCliResult(
        success=overall_ok,
        stdout=stdout_str,
        stderr=stderr_str,
        exit_code=0 if overall_ok else 1,
        executor="cprid",
        error_code=None if overall_ok else outcome.error_code,
        error_message=err_out,
    )


async def execute_gateway_cli(
    target: GatewayCliTarget,
    script: str,
    *,
    api: ApiPort,
    gateway_cli: GatewayCliPort | GatewayCliCallable | None = None,
    fallback_to_cprid: bool = True,
    timeout: float = 30.0,
    cprid_session_getter: Callable[[str, str], Awaitable[tuple[str, str]]] | None = None,
    cprid_script_mode: CpridScriptMode = "inline",
    repository_script_name: str = DEFAULT_ROUTE_COLLECT_REPOSITORY_SCRIPT_NAME,
    repository_script_args_fn: RepositoryScriptArgsCallable | None = None,
    max_routes: int | None = None,
    script_service: ScriptRepositoryService | None = None,
    domain_fallback_inline: dict[tuple[str, str], bool] | None = None,
    auto_mode_resolver: AutoScriptModeResolver | None = None,
    preclaimed_auto_probe: bool = False,
) -> GatewayCliResult:
    """Execute `script` on `target` via injected `gateway_cli` (SSH) with optional `cprid` `run-script` fallback."""
    ssh_error: str | None = None
    if gateway_cli is not None:
        ssh_result, ssh_error = await _execute_ssh_gateway_cli(
            target,
            script,
            gateway_cli=gateway_cli,
            fallback_to_cprid=fallback_to_cprid,
            timeout=timeout,
        )
        if ssh_result is not None:
            return ssh_result

    async def _run_inline() -> GatewayCliResult:
        return await _run_inline_cprid(
            target,
            script,
            api=api,
            timeout=timeout,
            cprid_session_getter=cprid_session_getter,
            ssh_error=ssh_error,
        )

    async def _run_repo() -> GatewayCliResult:
        return await _run_repository_cprid(
            target,
            api=api,
            timeout=timeout,
            cprid_session_getter=cprid_session_getter,
            repository_script_name=repository_script_name,
            repository_script_args_fn=repository_script_args_fn,
            max_routes=max_routes,
            script_service=script_service,
            ssh_error=ssh_error,
        )

    if cprid_script_mode == "repository":
        return await _run_repo()

    if cprid_script_mode == "auto":
        if auto_mode_resolver is not None:
            resolved = auto_mode_resolver.get_resolved(target.mgmt_name, target.domain_name)
            if resolved == "inline":
                return await _run_inline()
            if resolved == "repository":
                return await _run_repo()

            is_prober = preclaimed_auto_probe or await auto_mode_resolver.acquire_probe_turn(
                target.mgmt_name,
                target.domain_name,
            )
            if not is_prober:
                resolved = auto_mode_resolver.get_resolved(target.mgmt_name, target.domain_name)
                if resolved == "inline":
                    return await _run_inline()
                return await _run_repo()

            probe_exc: BaseException | None = None
            try:
                repo_res = await _run_repo()
                should_fallback = repo_res.error_code in (
                    "repository_script_not_found",
                    "repository_script_unsupported",
                )
                auto_mode_resolver.resolve_probe(
                    target.mgmt_name,
                    target.domain_name,
                    "inline" if should_fallback else "repository",
                )
                if should_fallback:
                    if domain_fallback_inline is not None:
                        domain_fallback_inline[(target.mgmt_name, target.domain_name)] = True
                    return await _run_inline()
                return repo_res
            except BaseException as exc:
                probe_exc = exc
                raise
            finally:
                auto_mode_resolver.abort_probe_if_unresolved(
                    target.mgmt_name,
                    target.domain_name,
                    exc=probe_exc,
                )

        dom_key = (target.mgmt_name, target.domain_name)
        if domain_fallback_inline is not None and domain_fallback_inline.get(dom_key):
            return await _run_inline()
        repo_res = await _run_repo()
        if repo_res.error_code in ("repository_script_not_found", "repository_script_unsupported"):
            if domain_fallback_inline is not None:
                domain_fallback_inline[dom_key] = True
            return await _run_inline()
        return repo_res

    return await _run_inline()


__all__ = [
    "execute_gateway_cli",
]
