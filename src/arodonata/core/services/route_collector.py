"""Live gateway route collection, CLI execution, VSX `vsenv` scripts, and route table parsers."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import re
import shlex
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from arodonata.core.context import normalize_domain_key
from arodonata.core.errors import (
    AuthenticationError,
    RepositoryScriptError,
    RepositoryScriptNotFoundError,
    RepositoryScriptPermissionError,
    SessionError,
    SessionStateError,
    ValidationError,
    is_script_permission_error,
    is_unsupported_script_command_error,
)
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import utc_now
from arodonata.core.models.scripts import CpridScriptMode, decode_base64_task_message
from arodonata.core.models.topology import (
    GatewayCliResult,
    GatewayCliTarget,
    GatewayTopologyEntry,
    TopologySourceType,
    TopologyZone,
)
from arodonata.core.ports import ApiPort, GatewayCliCallable, GatewayCliPort
from arodonata.core.services.script_service import ScriptRepositoryService

MAX_IPV4_INT = 4294967295
ROUTE_LIMIT_MARKER = "===ARODONATA_ROUTE_LIMIT_REACHED==="
CLISH_SKIPPED_LARGE_TABLE_MARKER = "===ARODONATA_CLISH_SKIPPED_LARGE_TABLE==="
DEFAULT_CLISH_SKIP_THRESHOLD = 10000
DEFAULT_ROUTE_COLLECT_REPOSITORY_SCRIPT_NAME = "arodonata-collect-routes-v1"

RepositoryScriptArgsCallable = Callable[[GatewayCliTarget, int | None], Sequence[str] | str | None]

_UNSAFE_VS_NAME_RE = re.compile(r"[\s\x00-\x1f\x7f'\"\\$`;&|<>()\[\]{}*?!~]")


class AutoScriptModeResolver:
    """Single-flight per-domain resolver for `cprid_script_mode='auto'`."""

    def __init__(self) -> None:
        self._resolved: dict[tuple[str, str], Literal["repository", "inline"]] = {}
        self._flights: dict[tuple[str, str], asyncio.Future[Literal["repository", "inline"]]] = {}

    def get_resolved(self, mgmt_name: str, domain_name: str | None) -> Literal["repository", "inline"] | None:
        """Return the cached script mode decision for `(mgmt_name, domain_name)` if already resolved."""
        return self._resolved.get((mgmt_name, normalize_domain_key(domain_name)))

    async def acquire_probe_turn(self, mgmt_name: str, domain_name: str | None) -> bool:
        """Acquire a single per-domain probe slot or await the in-flight probe without holding `mgmt_sem`."""
        key = (mgmt_name, normalize_domain_key(domain_name))
        while key not in self._resolved:
            fut = self._flights.get(key)
            if fut is None:
                self._flights[key] = asyncio.get_running_loop().create_future()
                return True
            try:
                await asyncio.shield(fut)
            except asyncio.CancelledError:
                cur_task = asyncio.current_task()
                if not fut.done() or (cur_task is not None and cur_task.cancelling() > 0):
                    raise
            except Exception:
                pass
        return False

    def resolve_probe(
        self,
        mgmt_name: str,
        domain_name: str | None,
        mode: Literal["repository", "inline"],
    ) -> None:
        """Record the domain's script mode decision and wake waiting targets."""
        key = (mgmt_name, normalize_domain_key(domain_name))
        self._resolved[key] = mode
        fut = self._flights.pop(key, None)
        if fut is not None and not fut.done():
            fut.set_result(mode)

    def abort_probe_if_unresolved(self, mgmt_name: str, domain_name: str | None) -> None:
        """Release the in-flight probe slot if the prober exited before resolving."""
        key = (mgmt_name, normalize_domain_key(domain_name))
        if key in self._resolved:
            return
        fut = self._flights.pop(key, None)
        if fut is not None and not fut.done():
            fut.set_exception(RuntimeError("auto script probe aborted"))
            fut.exception()


_CLISH_PROTOCOL_MAP: dict[str, TopologySourceType] = {
    "C": "connected_route",
    "S": "gaia_static_route",
    "R": "clish_route",
    "B": "bgp_route",
    "O": "ospf_route",
    "A": "clish_route",
    "K": "gaia_static_route",
    "I": "clish_route",
}

_IP_ROUTE_PROTO_MAP: dict[str, TopologySourceType] = {
    "kernel": "connected_route",
    "bgp": "bgp_route",
    "ospf": "ospf_route",
    "rip": "clish_route",
    "routed": "clish_route",
    "gated": "gaia_static_route",
    "static": "gaia_static_route",
    "boot": "gaia_static_route",
    "zebra": "clish_route",
}

_SKIP_IF_NAMES: frozenset[str] = frozenset({"lo", "loopback"})
_SKIP_ROUTE_KEYWORDS: frozenset[str] = frozenset(
    {
        "local",
        "broadcast",
        "unreachable",
        "prohibit",
        "blackhole",
        "throw",
        "nat",
        "multicast",
    }
)


@dataclass(frozen=True)
class ParsedCliRoute:
    """Normalized IPv4 route entry parsed from `ip -4 route show` or `clish -c "show route"`."""

    destination: ipaddress.IPv4Network
    interface_name: str
    nexthop: ipaddress.IPv4Address | None
    source_type: TopologySourceType
    protocol_label: str


def build_route_collection_script(
    vsid: int | None = None,
    vs_name: str | None = None,
    *,
    max_routes: int | None = None,
) -> str:
    """Build a safe bash script for collecting IPv4 routes from Gaia OS or a VSX Virtual System context.

    When `vsid` is specified (`> 0`), switches context via `vsenv "$vsid" >/dev/null 2>&1 </dev/null`
    and verifies that `$FWDIR` contains `printf "CTX%05d" "$vsid"` before querying routes, redirecting
    stdin from `/dev/null` so nested loops or parent shells never lose stdin. When `vsid` is `None`
    but `vs_name` is set, dynamically resolves `vsid` via `vsx stat -l` on `VS0` and fails cleanly
    if the VSID cannot be resolved. When `max_routes` (`> 0`) is specified, caps CLI output lines via
    `awk` and skips `clish -c "show route"` on BGP full-view / large tables (`> 10000` kernel routes).
    """
    eff_limit = int(max_routes) if max_routes is not None and int(max_routes) > 0 else None
    if eff_limit is not None:
        ip_cmd = (
            f"ip -4 route show 2>/dev/null </dev/null | awk -v lim={eff_limit} "
            f"'NR<=lim {{print}} NR==lim+1 {{print \"{ROUTE_LIMIT_MARKER}\"; exit}}' || true\n"
        )
    else:
        ip_cmd = "ip -4 route show 2>/dev/null </dev/null || true\n"

    if vsid is not None and vsid > 0:
        return (
            f"vsid={int(vsid)}\n"
            'ctx=$(printf "CTX%05d" "$vsid")\n'
            'if ! vsenv "$vsid" >/dev/null 2>&1 </dev/null; then\n'
            '  echo "_vs_error=vsenv $vsid failed"\n'
            "  exit 1\n"
            "fi\n"
            'case "$FWDIR" in\n'
            '  *"$ctx"*) ;;\n'
            '  *) echo "_vs_error=context not switched (FWDIR=$FWDIR)"; exit 1 ;;\n'
            "esac\n"
            'echo "===ARODONATA_IP_ROUTE_START==="\n'
            f"{ip_cmd}"
            'echo "===ARODONATA_IP_ROUTE_END==="\n'
        )
    if vs_name:
        safe_vs_name = shlex.quote(vs_name)
        return (
            f"vs_name={safe_vs_name}\n"
            "vsid=$(vsx stat -l 2>/dev/null </dev/null | awk -v target=\"$vs_name\" '/^VSID:/ {id=$2} /^Name:/ && $2 == target {print id; exit}')\n"
            'case "$vsid" in\n'
            '  ""|0|*[!0-9]*) echo "_vs_error=unable to resolve vsid for $vs_name"; exit 1 ;;\n'
            "esac\n"
            'ctx=$(printf "CTX%05d" "$vsid")\n'
            'if ! vsenv "$vsid" >/dev/null 2>&1 </dev/null; then\n'
            '  echo "_vs_error=vsenv $vsid failed"\n'
            "  exit 1\n"
            "fi\n"
            'case "$FWDIR" in\n'
            '  *"$ctx"*) ;;\n'
            '  *) echo "_vs_error=context not switched (FWDIR=$FWDIR)"; exit 1 ;;\n'
            "esac\n"
            'echo "===ARODONATA_VSID_RESOLVED=${vsid}==="\n'
            'echo "===ARODONATA_IP_ROUTE_START==="\n'
            f"{ip_cmd}"
            'echo "===ARODONATA_IP_ROUTE_END==="\n'
        )
    if eff_limit is not None:
        skip_thr = min(eff_limit, DEFAULT_CLISH_SKIP_THRESHOLD)
        return (
            'echo "===ARODONATA_IP_ROUTE_START==="\n'
            "_ip_rc=0\n"
            f"ip -4 route show 2>/dev/null </dev/null | awk -v lim={eff_limit} -v thr={skip_thr} "
            f'\'NR<=lim {{print}} NR==lim+1 {{print "{ROUTE_LIMIT_MARKER}"; exit 42}} '
            "END {if (NR>thr) exit 42}' || _ip_rc=$?\n"
            'echo "===ARODONATA_IP_ROUTE_END==="\n'
            'if [ "$_ip_rc" -eq 42 ]; then\n'
            f'  echo "{CLISH_SKIPPED_LARGE_TABLE_MARKER}"\n'
            "else\n"
            '  echo "===ARODONATA_CLISH_ROUTE_START==="\n'
            f'  clish -c "show route" 2>/dev/null </dev/null | awk -v lim={eff_limit} '
            f"'NR<=lim {{print}} NR==lim+1 {{print \"{ROUTE_LIMIT_MARKER}\"; exit}}' || true\n"
            '  echo "===ARODONATA_CLISH_ROUTE_END==="\n'
            "fi\n"
        )
    return (
        'echo "===ARODONATA_IP_ROUTE_START==="\n'
        "ip -4 route show 2>/dev/null </dev/null || true\n"
        'echo "===ARODONATA_IP_ROUTE_END==="\n'
        'echo "===ARODONATA_CLISH_ROUTE_START==="\n'
        'clish -c "show route" 2>/dev/null </dev/null || true\n'
        'echo "===ARODONATA_CLISH_ROUTE_END==="\n'
    )


def build_route_collection_repository_script() -> str:
    """Build the canonical parameterized bash script (`arodonata-collect-routes-v1`) for Check Point Script Repository.

    Positional arguments (`run-script` `args`):
    - `$1`: `max_routes` (digits-only; `0` or empty = unlimited)
    - `$2`: `vsid` (digits-only; `0` or empty = host / non-VSX)
    - `$3`: `vs_name` (optional Virtual System name resolved dynamically via `vsx stat -l` when `vsid=0`)
    """
    return (
        'max_routes="${1:-0}"\n'
        'vsid="${2:-0}"\n'
        'vs_name="${3:-}"\n'
        'case "$max_routes" in\n'
        '  ""|*[!0-9]*) echo "_vs_error=invalid max_routes argument"; exit 1 ;;\n'
        "esac\n"
        'case "$vsid" in\n'
        '  ""|*[!0-9]*) echo "_vs_error=invalid vsid argument"; exit 1 ;;\n'
        "esac\n"
        'if [ "$vsid" -gt 0 ]; then\n'
        '  ctx=$(printf "CTX%05d" "$vsid")\n'
        '  if ! vsenv "$vsid" >/dev/null 2>&1 </dev/null; then\n'
        '    echo "_vs_error=vsenv $vsid failed"\n'
        "    exit 1\n"
        "  fi\n"
        '  case "$FWDIR" in\n'
        '    *"$ctx"*) ;;\n'
        '    *) echo "_vs_error=context not switched (FWDIR=$FWDIR)"; exit 1 ;;\n'
        "  esac\n"
        '  echo "===ARODONATA_IP_ROUTE_START==="\n'
        '  if [ "$max_routes" -gt 0 ]; then\n'
        '    ip -4 route show 2>/dev/null </dev/null | awk -v lim="$max_routes" '
        f"'NR<=lim {{print}} NR==lim+1 {{print \"{ROUTE_LIMIT_MARKER}\"; exit}}' || true\n"
        "  else\n"
        "    ip -4 route show 2>/dev/null </dev/null || true\n"
        "  fi\n"
        '  echo "===ARODONATA_IP_ROUTE_END==="\n'
        "  exit 0\n"
        "fi\n"
        'if [ -n "$vs_name" ]; then\n'
        '  vsid=$(vsx stat -l 2>/dev/null </dev/null | awk -v target="$vs_name" '
        "'/^VSID:/ {id=$2} /^Name:/ && $2 == target {print id; exit}')\n"
        '  case "$vsid" in\n'
        '    ""|0|*[!0-9]*) echo "_vs_error=unable to resolve vsid for $vs_name"; exit 1 ;;\n'
        "  esac\n"
        '  ctx=$(printf "CTX%05d" "$vsid")\n'
        '  if ! vsenv "$vsid" >/dev/null 2>&1 </dev/null; then\n'
        '    echo "_vs_error=vsenv $vsid failed"\n'
        "    exit 1\n"
        "  fi\n"
        '  case "$FWDIR" in\n'
        '    *"$ctx"*) ;;\n'
        '    *) echo "_vs_error=context not switched (FWDIR=$FWDIR)"; exit 1 ;;\n'
        "  esac\n"
        '  echo "===ARODONATA_VSID_RESOLVED=${vsid}==="\n'
        '  echo "===ARODONATA_IP_ROUTE_START==="\n'
        '  if [ "$max_routes" -gt 0 ]; then\n'
        '    ip -4 route show 2>/dev/null </dev/null | awk -v lim="$max_routes" '
        f"'NR<=lim {{print}} NR==lim+1 {{print \"{ROUTE_LIMIT_MARKER}\"; exit}}' || true\n"
        "  else\n"
        "    ip -4 route show 2>/dev/null </dev/null || true\n"
        "  fi\n"
        '  echo "===ARODONATA_IP_ROUTE_END==="\n'
        "  exit 0\n"
        "fi\n"
        'if [ "$max_routes" -gt 0 ]; then\n'
        f"  skip_thr={DEFAULT_CLISH_SKIP_THRESHOLD}\n"
        '  if [ "$max_routes" -lt "$skip_thr" ]; then\n'
        '    skip_thr="$max_routes"\n'
        "  fi\n"
        '  echo "===ARODONATA_IP_ROUTE_START==="\n'
        "  _ip_rc=0\n"
        '  ip -4 route show 2>/dev/null </dev/null | awk -v lim="$max_routes" -v thr="$skip_thr" '
        f'\'NR<=lim {{print}} NR==lim+1 {{print "{ROUTE_LIMIT_MARKER}"; exit 42}} '
        "END {if (NR>thr) exit 42}' || _ip_rc=$?\n"
        '  echo "===ARODONATA_IP_ROUTE_END==="\n'
        '  if [ "$_ip_rc" -eq 42 ]; then\n'
        f'    echo "{CLISH_SKIPPED_LARGE_TABLE_MARKER}"\n'
        "  else\n"
        '    echo "===ARODONATA_CLISH_ROUTE_START==="\n'
        '    clish -c "show route" 2>/dev/null </dev/null | awk -v lim="$max_routes" '
        f"'NR<=lim {{print}} NR==lim+1 {{print \"{ROUTE_LIMIT_MARKER}\"; exit}}' || true\n"
        '    echo "===ARODONATA_CLISH_ROUTE_END==="\n'
        "  fi\n"
        "else\n"
        '  echo "===ARODONATA_IP_ROUTE_START==="\n'
        "  ip -4 route show 2>/dev/null </dev/null || true\n"
        '  echo "===ARODONATA_IP_ROUTE_END==="\n'
        '  echo "===ARODONATA_CLISH_ROUTE_START==="\n'
        '  clish -c "show route" 2>/dev/null </dev/null || true\n'
        '  echo "===ARODONATA_CLISH_ROUTE_END==="\n'
        "fi\n"
    )


def format_route_collection_repository_args(
    target: GatewayCliTarget,
    *,
    max_routes: int | None = None,
) -> str:
    """Format safe positional `args` (`<max_routes> <vsid> [<vs_name>]`) for `arodonata-collect-routes-v1`."""
    eff_max = int(max_routes) if max_routes is not None and int(max_routes) > 0 else 0
    eff_vsid = int(target.vsid) if target.vsid is not None and int(target.vsid) > 0 else 0
    if eff_vsid > 0:
        return f"{eff_max} {eff_vsid}"
    if target.vs_name is not None and target.vs_name.strip():
        clean_vs = target.vs_name.strip()
        if _UNSAFE_VS_NAME_RE.search(clean_vs):
            raise ValidationError(
                f"Unsafe Virtual System name {target.vs_name!r} for repository script positional args."
            )
        return f"{eff_max} 0 {clean_vs}"
    return f"{eff_max} 0"


def decode_cprid_task_output(data: dict[str, Any]) -> tuple[bool, str, str]:
    """Extract and Base64-decode `responseMessage` / `responseError` from Check Point `run-script` / `show-task`."""
    if not isinstance(data, dict):
        return False, "", "Empty task response payload"

    tasks: list[dict[str, Any]] = []
    if isinstance(data.get("tasks"), list):
        tasks = [t for t in data["tasks"] if isinstance(t, dict)]
    elif "task-details" in data or "status" in data:
        tasks = [data]

    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    any_failed = False

    for task in tasks:
        st = str(task.get("status") or "").strip().lower()
        if st and st not in ("succeeded", "ok"):
            any_failed = True
        details = task.get("task-details")
        if isinstance(details, list):
            for detail in details:
                if not isinstance(detail, dict):
                    continue
                resp_msg = detail.get("responseMessage") or detail.get("response-message")
                if isinstance(resp_msg, str) and resp_msg.strip():
                    stdout_parts.append(decode_base64_task_message(resp_msg))
                resp_err = (
                    detail.get("responseError")
                    or detail.get("response-error")
                    or detail.get("fault-message")
                    or detail.get("error-message")
                )
                if isinstance(resp_err, str) and resp_err.strip():
                    stderr_parts.append(decode_base64_task_message(resp_err))
                status_desc = detail.get("statusDescription")
                if isinstance(status_desc, str) and status_desc.strip() and not resp_msg:
                    if st and st not in ("succeeded", "ok"):
                        stderr_parts.append(status_desc.strip())
                    else:
                        stdout_parts.append(status_desc.strip())

    # Direct `responseMessage` at top level (some mocks/versions)
    top_msg = data.get("responseMessage") or data.get("response-message") or data.get("output")
    if isinstance(top_msg, str) and top_msg.strip() and not stdout_parts:
        stdout_parts.append(decode_base64_task_message(top_msg))

    stdout_str = "\n".join(stdout_parts).strip()
    stderr_str = "\n".join(stderr_parts).strip()
    if "_vs_error=" in stdout_str:
        return False, stdout_str, stderr_str or stdout_str
    return not any_failed, stdout_str, stderr_str


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
                return GatewayCliResult(
                    success=ok,
                    stdout=raw_res,
                    stderr=err_msg or "",
                    exit_code=0 if ok else 1,
                    executor="ssh",
                    error_message=err_msg,
                )
            if isinstance(raw_res, GatewayCliResult):
                if "_vs_error=" in raw_res.stdout and raw_res.success:
                    return raw_res.model_copy(
                        update={
                            "success": False,
                            "exit_code": 1,
                            "error_message": raw_res.stdout.strip(),
                        }
                    )
                if (
                    target.vs_name
                    and target.vsid is None
                    and raw_res.success
                    and "===ARODONATA_VSID_RESOLVED=" not in raw_res.stdout
                ):
                    return raw_res.model_copy(
                        update={
                            "success": False,
                            "exit_code": 1,
                            "error_message": f"Unable to resolve VSID for Virtual System {target.vs_name!r}",
                        }
                    )
                if raw_res.success or not fallback_to_cprid:
                    return raw_res
                ssh_error = raw_res.error_message or raw_res.stderr or f"SSH exited with {raw_res.exit_code}"
        except Exception as exc:
            ssh_error = str(exc)
            if not fallback_to_cprid:
                return GatewayCliResult(
                    success=False,
                    stdout="",
                    stderr=ssh_error,
                    exit_code=1,
                    executor="ssh",
                    error_message=ssh_error,
                )

    if gateway_cli is not None and not fallback_to_cprid:
        return GatewayCliResult(
            success=False,
            stdout="",
            stderr=ssh_error or "SSH execution failed",
            exit_code=1,
            executor="ssh",
            error_message=ssh_error or "SSH execution failed",
        )

    async def _run_inline_cprid() -> GatewayCliResult:
        payload = {
            "script-name": f"arodonata-route-collect-{target.gateway_name}",
            "script": script,
            "targets": [target.node_uid or target.node_name],
        }
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
                        with contextlib.suppress(Exception):
                            await api.logout_sid(target.mgmt_name, ded_sid, server_ip=ded_ip)
        except (SessionError, AuthenticationError) as exc:
            session_err_code = (
                "repository_script_permission_denied" if is_script_permission_error(None, str(exc)) else None
            )
            err_msg = f"run-script failed: {exc}"
            if ssh_error:
                err_msg = f"SSH failed ({ssh_error}); cprid fallback failed ({exc})"
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
            err_msg = f"run-script failed: {exc}"
            if ssh_error:
                err_msg = f"SSH failed ({ssh_error}); cprid fallback failed ({exc})"
            return GatewayCliResult(
                success=False,
                stdout="",
                stderr=err_msg,
                exit_code=1,
                executor="cprid",
                error_message=err_msg,
            )

        ok_decode, stdout_str, stderr_str = decode_cprid_task_output(res.data)
        missing_vsid_res = bool(
            target.vs_name and target.vsid is None and "===ARODONATA_VSID_RESOLVED=" not in stdout_str
        )
        overall_ok = res.success and ok_decode and not missing_vsid_res
        err_out: str | None = None
        err_code: str | None = None
        if not overall_ok:
            if not res.success and is_script_permission_error(res.error_code, res.error_message):
                err_code = "repository_script_permission_denied"
            err_out = (
                stderr_str
                or res.error_message
                or (
                    f"Unable to resolve VSID for Virtual System {target.vs_name!r}"
                    if missing_vsid_res
                    else "run-script task did not succeed"
                )
            )
            if ssh_error:
                err_out = f"SSH failed ({ssh_error}); cprid fallback failed ({err_out})"

        return GatewayCliResult(
            success=overall_ok,
            stdout=stdout_str,
            stderr=stderr_str,
            exit_code=0 if overall_ok else 1,
            executor="cprid",
            error_code=err_code,
            error_message=err_out,
        )

    async def _run_repository_cprid() -> GatewayCliResult:
        eff_service = script_service or ScriptRepositoryService(api=api)
        try:
            args_val = (
                repository_script_args_fn(target, max_routes)
                if repository_script_args_fn is not None
                else format_route_collection_repository_args(target, max_routes=max_routes)
            )
        except Exception as exc:
            err_msg = f"SSH failed ({ssh_error}); cprid fallback failed ({exc})" if ssh_error else str(exc)
            return GatewayCliResult(
                success=False,
                stdout="",
                stderr=err_msg,
                exit_code=1,
                executor="cprid",
                error_message=err_msg,
            )

        session_getter_wrapped: Callable[[str, str | None], Awaitable[tuple[str, str]]] | None = None
        if cprid_session_getter is not None:

            async def _wrapped_getter(m_name: str, d_name: str | None) -> tuple[str, str]:
                return await cprid_session_getter(m_name, d_name or target.domain_name)

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
        except RepositoryScriptNotFoundError as exc:
            err_msg = f"SSH failed ({ssh_error}); cprid fallback failed ({exc})" if ssh_error else str(exc)
            return GatewayCliResult(
                success=False,
                stdout="",
                stderr=str(exc),
                exit_code=1,
                executor="cprid",
                error_code="repository_script_not_found",
                error_message=err_msg,
            )
        except RepositoryScriptPermissionError as exc:
            err_msg = f"SSH failed ({ssh_error}); cprid fallback failed ({exc})" if ssh_error else str(exc)
            return GatewayCliResult(
                success=False,
                stdout="",
                stderr=str(exc),
                exit_code=1,
                executor="cprid",
                error_code="repository_script_permission_denied",
                error_message=err_msg,
            )
        except RepositoryScriptError as exc:
            err_msg = f"SSH failed ({ssh_error}); cprid fallback failed ({exc})" if ssh_error else str(exc)
            err_code = "repository_script_unsupported" if is_unsupported_script_command_error(None, str(exc)) else None
            return GatewayCliResult(
                success=False,
                stdout="",
                stderr=str(exc),
                exit_code=1,
                executor="cprid",
                error_code=err_code,
                error_message=err_msg,
            )
        except Exception as exc:
            err_msg = (
                f"SSH failed ({ssh_error}); cprid fallback failed ({exc})" if ssh_error else f"run-script failed: {exc}"
            )
            return GatewayCliResult(
                success=False,
                stdout="",
                stderr=err_msg,
                exit_code=1,
                executor="cprid",
                error_message=err_msg,
            )

        stdout_str = outcome.stdout
        stderr_str = outcome.stderr
        has_vs_err = "_vs_error=" in stdout_str
        missing_vsid_res = bool(
            target.vs_name and target.vsid is None and "===ARODONATA_VSID_RESOLVED=" not in stdout_str
        )
        overall_ok = outcome.success and not has_vs_err and not missing_vsid_res
        err_out: str | None = None
        if not overall_ok:
            err_out = (
                (stdout_str.strip() if has_vs_err else None)
                or stderr_str
                or outcome.error_message
                or (
                    f"Unable to resolve VSID for Virtual System {target.vs_name!r}"
                    if missing_vsid_res
                    else "run-script task did not succeed"
                )
            )
            if ssh_error:
                err_out = f"SSH failed ({ssh_error}); cprid fallback failed ({err_out})"

        return GatewayCliResult(
            success=overall_ok,
            stdout=stdout_str,
            stderr=stderr_str,
            exit_code=0 if overall_ok else 1,
            executor="cprid",
            error_code=None if overall_ok else outcome.error_code,
            error_message=err_out,
        )

    if cprid_script_mode == "repository":
        return await _run_repository_cprid()

    if cprid_script_mode == "auto":
        if auto_mode_resolver is not None:
            resolved = auto_mode_resolver.get_resolved(target.mgmt_name, target.domain_name)
            if resolved == "inline":
                return await _run_inline_cprid()
            if resolved == "repository":
                return await _run_repository_cprid()

            is_prober = preclaimed_auto_probe or await auto_mode_resolver.acquire_probe_turn(
                target.mgmt_name,
                target.domain_name,
            )
            if not is_prober:
                resolved = auto_mode_resolver.get_resolved(target.mgmt_name, target.domain_name)
                if resolved == "inline":
                    return await _run_inline_cprid()
                return await _run_repository_cprid()

            try:
                repo_res = await _run_repository_cprid()
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
                    return await _run_inline_cprid()
                return repo_res
            finally:
                auto_mode_resolver.abort_probe_if_unresolved(target.mgmt_name, target.domain_name)

        dom_key = (target.mgmt_name, target.domain_name)
        if domain_fallback_inline is not None and domain_fallback_inline.get(dom_key):
            return await _run_inline_cprid()
        repo_res = await _run_repository_cprid()
        if repo_res.error_code in ("repository_script_not_found", "repository_script_unsupported"):
            if domain_fallback_inline is not None:
                domain_fallback_inline[dom_key] = True
            return await _run_inline_cprid()
        return repo_res

    return await _run_inline_cprid()


def parse_ip_route_show(output: str) -> list[ParsedCliRoute]:
    """Parse Linux/Gaia `ip -4 route show` output into `ParsedCliRoute` items."""
    routes: list[ParsedCliRoute] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("===") or line.startswith("_vs_error=") or line.startswith("#"):
            continue

        tokens = line.split()
        if not tokens:
            continue

        first_tok = tokens[0].lower()
        if first_tok in _SKIP_ROUTE_KEYWORDS:
            continue

        dest_tok = tokens[0]
        if dest_tok.lower() == "default":
            dest_net = ipaddress.IPv4Network("0.0.0.0/0")
        else:
            try:
                if "/" in dest_tok:
                    dest_net = ipaddress.IPv4Network(dest_tok, strict=False)
                else:
                    addr = ipaddress.IPv4Address(dest_tok)
                    dest_net = (
                        ipaddress.IPv4Network("0.0.0.0/0")
                        if str(addr) == "0.0.0.0"
                        else ipaddress.IPv4Network(f"{addr}/32", strict=False)
                    )
            except ValueError:
                continue

        if dest_net.is_loopback or dest_net.is_multicast:
            continue

        dev_name: str | None = None
        via_ip: ipaddress.IPv4Address | None = None
        proto_str = ""
        scope_str = ""

        idx = 1
        while idx < len(tokens):
            tok = tokens[idx].lower()
            if tok == "dev" and idx + 1 < len(tokens):
                dev_name = tokens[idx + 1].strip()
                idx += 2
            elif tok == "via" and idx + 1 < len(tokens):
                try:
                    via_ip = ipaddress.IPv4Address(tokens[idx + 1].strip())
                except ValueError:
                    via_ip = None
                idx += 2
            elif tok == "proto" and idx + 1 < len(tokens):
                proto_str = tokens[idx + 1].strip().lower()
                idx += 2
            elif tok == "scope" and idx + 1 < len(tokens):
                scope_str = tokens[idx + 1].strip().lower()
                idx += 2
            else:
                idx += 1

        if not dev_name or dev_name.lower() in _SKIP_IF_NAMES:
            continue

        if proto_str in _IP_ROUTE_PROTO_MAP:
            src_type = _IP_ROUTE_PROTO_MAP[proto_str]
        elif scope_str == "link" or (via_ip is None and dest_net.prefixlen > 0):
            src_type = "connected_route"
        else:
            src_type = "gaia_static_route"

        routes.append(
            ParsedCliRoute(
                destination=dest_net,
                interface_name=dev_name,
                nexthop=via_ip,
                source_type=src_type,
                protocol_label=proto_str or ("connected" if src_type == "connected_route" else "static"),
            )
        )
    return routes


_CLISH_ROUTE_RE = re.compile(
    r"^(?P<code>[CSRBOKAI])\s+"
    r"(?P<dest>\d+\.\d+\.\d+\.\d+(?:/\d+)?|default)\s+"
    r"(?:is\s+directly\s+connected,\s*(?P<conn_if>\S+)"
    r"|via\s+(?P<nh>\d+\.\d+\.\d+\.\d+),\s*(?P<via_if>[^,\s]+))",
    re.IGNORECASE,
)


def parse_clish_show_route(output: str) -> list[ParsedCliRoute]:
    """Parse Gaia `clish -c "show route"` output into `ParsedCliRoute` items."""
    routes: list[ParsedCliRoute] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("===") or line.startswith("Codes:") or line.startswith("_vs_error="):
            continue

        m = _CLISH_ROUTE_RE.match(line)
        if not m:
            continue

        code = m.group("code").upper()
        dest_raw = m.group("dest")
        conn_if = m.group("conn_if")
        nh_raw = m.group("nh")
        via_if = m.group("via_if")

        if dest_raw.lower() == "default" or dest_raw == "0.0.0.0/0" or dest_raw == "0.0.0.0":
            dest_net = ipaddress.IPv4Network("0.0.0.0/0")
        else:
            try:
                dest_net = (
                    ipaddress.IPv4Network(dest_raw, strict=False)
                    if "/" in dest_raw
                    else ipaddress.IPv4Network(f"{dest_raw}/32", strict=False)
                )
            except ValueError:
                continue

        if dest_net.is_loopback or dest_net.is_multicast:
            continue

        if_name = (conn_if or via_if or "").strip().rstrip(",")
        if not if_name or if_name.lower() in _SKIP_IF_NAMES:
            continue

        nh_ip: ipaddress.IPv4Address | None = None
        if nh_raw:
            try:
                nh_ip = ipaddress.IPv4Address(nh_raw)
            except ValueError:
                nh_ip = None

        src_type = _CLISH_PROTOCOL_MAP.get(code, "clish_route")
        routes.append(
            ParsedCliRoute(
                destination=dest_net,
                interface_name=if_name,
                nexthop=nh_ip,
                source_type=src_type,
                protocol_label=f"clish:{code}",
            )
        )
    return routes


def parse_combined_cli_routes_with_status(
    stdout: str,
    *,
    max_routes: int | None = None,
) -> tuple[list[ParsedCliRoute], bool]:
    """Parse combined `ip -4 route show` and `clish -c "show route"` stdout and report whether `max_routes` truncated any entry."""
    ip_section = stdout
    clish_section = ""

    if "===ARODONATA_IP_ROUTE_START===" in stdout:
        after_start = stdout.split("===ARODONATA_IP_ROUTE_START===", 1)[1]
        ip_section = after_start.split("===ARODONATA_IP_ROUTE_END===", 1)[0]

    if "===ARODONATA_CLISH_ROUTE_START===" in stdout:
        after_clish = stdout.split("===ARODONATA_CLISH_ROUTE_START===", 1)[1]
        clish_section = after_clish.split("===ARODONATA_CLISH_ROUTE_END===", 1)[0]
    elif "===ARODONATA_IP_ROUTE_START===" not in stdout:
        clish_section = stdout

    ip_routes = parse_ip_route_show(ip_section)
    clish_routes = parse_clish_show_route(clish_section) if clish_section else []

    by_key: dict[tuple[str, str], ParsedCliRoute] = {}
    eff_max = int(max_routes) if max_routes is not None and int(max_routes) > 0 else None
    truncated = ROUTE_LIMIT_MARKER in stdout
    for r in ip_routes:
        key = (str(r.destination), r.interface_name)
        if eff_max is not None and key not in by_key and len(by_key) >= eff_max:
            truncated = True
            break
        by_key[key] = r

    for cr in clish_routes:
        key = (str(cr.destination), cr.interface_name)
        existing = by_key.get(key)
        if existing is None:
            if eff_max is not None and len(by_key) >= eff_max:
                truncated = True
                continue
            by_key[key] = cr
        elif existing.source_type == "gaia_static_route" and cr.source_type in (
            "bgp_route",
            "ospf_route",
            "clish_route",
        ):
            # Upgrade generic kernel/static route to specific dynamic protocol discovered by clish
            by_key[key] = cr

    return list(by_key.values()), truncated


def parse_combined_cli_routes(
    stdout: str,
    *,
    max_routes: int | None = None,
) -> list[ParsedCliRoute]:
    """Parse combined `ip -4 route show` and `clish -c "show route"` stdout, upgrading protocol specificity from clish when both report the same `(destination, interface)`."""
    routes, _ = parse_combined_cli_routes_with_status(stdout, max_routes=max_routes)
    return routes


def resolve_gateway_cli_targets(
    gateway_asset: Asset,
    all_assets: Sequence[Asset],
) -> list[GatewayCliTarget]:
    """Resolve a policy-enforcing gateway, cluster, or VSX Virtual System into concrete CLI execution targets.

    - `simple-gateway` -> `[gateway_asset]`
    - `simple-cluster` / `CpmiGatewayCluster` -> each `cluster-member` linked to the cluster (or the cluster itself if no members exist in cache)
    - `virtual-system` / `CpmiVsNetobj` / `CpmiVsClusterNetobj` -> the physical VSX parent (`VS0`) or its cluster members, carrying `vsid` and `vs_name`
    """
    by_uid: dict[str, Asset] = {a.uid: a for a in all_assets}
    by_id: dict[str, Asset] = {a.id: a for a in all_assets}
    by_asset_id: dict[str, Asset] = {a.asset_id: a for a in all_assets}

    is_vs = "virtual-system" in gateway_asset.type.lower() or gateway_asset.type in (
        "vs-netobj",
        "CpmiVsNetobj",
        "CpmiVsClusterNetobj",
    )
    vsid_val: int | None = None
    if is_vs:
        raw_vsid = (
            gateway_asset.raw_data.get("vsid")
            or gateway_asset.raw_data.get("vs-id")
            or gateway_asset.raw_data.get("vs_id")
            or gateway_asset.raw_data.get("virtual-system-id")
        )
        if raw_vsid is not None:
            try:
                vsid_val = int(raw_vsid)
            except (TypeError, ValueError):
                vsid_val = None
        if vsid_val is None:
            m = re.search(r"(?:^|_)VS_?(\d+)(?:_|$)", gateway_asset.name, re.IGNORECASE)
            if m:
                vsid_val = int(m.group(1))

    # If VSX Virtual System, locate physical VSX parent first
    execution_root = gateway_asset
    if is_vs:
        parent: Asset | None = None
        if gateway_asset.parent_id and gateway_asset.parent_id in by_id:
            parent = by_id[gateway_asset.parent_id]
        elif gateway_asset.parent_uid and gateway_asset.parent_uid in by_uid:
            parent = by_uid[gateway_asset.parent_uid]
        elif gateway_asset.parent_asset_id and gateway_asset.parent_asset_id in by_asset_id:
            parent = by_asset_id[gateway_asset.parent_asset_id]
        if parent is not None:
            execution_root = parent

    # Check if `execution_root` is a cluster with member assets
    member_assets: list[Asset] = []
    seen_member_uids: set[str] = set()
    for m_uid in execution_root.member_uids:
        m_asset = by_uid.get(m_uid)
        if m_asset is not None and m_asset.uid not in seen_member_uids:
            seen_member_uids.add(m_asset.uid)
            member_assets.append(m_asset)

    for other in all_assets:
        if other.uid in seen_member_uids or other.uid == execution_root.uid:
            continue
        if (
            other.parent_uid == execution_root.uid
            or other.parent_id == execution_root.id
            or other.parent_asset_id == execution_root.asset_id
        ) and "member" in other.type.lower():
            seen_member_uids.add(other.uid)
            member_assets.append(other)

    nodes = member_assets if member_assets else [execution_root]
    targets: list[GatewayCliTarget] = []
    for node in nodes:
        targets.append(
            GatewayCliTarget(
                mgmt_name=gateway_asset.mgmt_name,
                domain_name=gateway_asset.domain_name,
                gateway_id=gateway_asset.id,
                gateway_asset_id=gateway_asset.asset_id,
                gateway_uid=gateway_asset.uid,
                gateway_name=gateway_asset.name,
                gateway_type=gateway_asset.type,
                node_uid=node.uid,
                node_name=node.name,
                node_ipv4=node.ipv4_address or gateway_asset.ipv4_address,
                vsid=vsid_val,
                vs_name=gateway_asset.name if is_vs else None,
            )
        )
    return targets


def routes_to_topology_entries(
    *,
    gateway_asset: Asset,
    parsed_routes_by_node: dict[str, list[ParsedCliRoute]],
    interface_meta: Mapping[
        str,
        tuple[str | None, int | None, bool, str] | tuple[str | None, int | None, bool, str, bool],
    ],
    installed_access_policy: str | None,
    policy_packages: list[str],
    now: datetime | None = None,
) -> tuple[list[GatewayTopologyEntry], bool, dict[tuple[str, str], list[str]]]:
    """Convert per-node `ParsedCliRoute` lists into `GatewayTopologyEntry` rows and detect cluster member drift.

    Returns `(entries, member_drift_detected, drift_map)` where `drift_map` maps `(interface_name, cidr_or_range)`
    to the subset of cluster node names that reported the route whenever not all nodes reported it.
    """
    ts = now or utc_now()
    node_names = sorted(parsed_routes_by_node.keys())
    total_nodes = len(node_names)

    # Group by (interface_name, cidr_str) -> list of (node_name, ParsedCliRoute)
    by_if_cidr: dict[tuple[str, str], list[tuple[str, ParsedCliRoute]]] = {}
    for node_name in node_names:
        for r in parsed_routes_by_node[node_name]:
            key = (r.interface_name, str(r.destination))
            by_if_cidr.setdefault(key, []).append((node_name, r))

    entries: list[GatewayTopologyEntry] = []
    drift_map: dict[tuple[str, str], list[str]] = {}
    member_drift_detected = False

    for (if_name, cidr_str), node_route_pairs in sorted(by_if_cidr.items()):
        present_nodes = sorted({n for n, _ in node_route_pairs})
        sample_route = node_route_pairs[0][1]
        dest_net = sample_route.destination
        is_default = dest_net.prefixlen == 0 and int(dest_net.network_address) == 0

        # Do not flag connected interface subnet mismatches across cluster member physical IPs if they share the same CIDR,
        # only flag when a prefix is missing on one or more cluster members.
        if total_nodes > 1 and len(present_nodes) < total_nodes:
            member_drift_detected = True
            drift_map[(if_name, cidr_str)] = present_nodes

        meta_val = interface_meta.get(if_name)
        if meta_val is None:
            if_ip, if_mask, leads_dmz, anti_spoof, is_ext_if = None, None, False, "unknown", False
        elif len(meta_val) == 5:
            if_ip, if_mask, leads_dmz, anti_spoof, is_ext_if = meta_val
        else:
            if_ip, if_mask, leads_dmz, anti_spoof = meta_val
            is_ext_if = False

        zone: TopologyZone = "external" if (is_default or is_ext_if) else "internal"

        nh_part = f"nexthop:{sample_route.nexthop}" if sample_route.nexthop is not None else sample_route.protocol_label
        if total_nodes > 1:
            members_tag = ",".join(present_nodes)
            drift_tag = f";drift:{len(present_nodes)}/{total_nodes}" if len(present_nodes) < total_nodes else ""
            src_ref = f"{nh_part};members:{members_tag}{drift_tag}"
        else:
            src_ref = nh_part

        entries.append(
            GatewayTopologyEntry(
                mgmt_name=gateway_asset.mgmt_name,
                domain_name=gateway_asset.domain_name,
                gateway_id=gateway_asset.id,
                gateway_asset_id=gateway_asset.asset_id,
                gateway_uid=gateway_asset.uid,
                gateway_name=gateway_asset.name,
                gateway_type=gateway_asset.type,
                interface_name=if_name,
                interface_ipv4=if_ip,
                interface_mask_length=if_mask,
                topology_zone=zone,
                leads_to_dmz=leads_dmz,
                anti_spoofing_mode=anti_spoof,  # type: ignore[arg-type]
                source_type=sample_route.source_type,
                source_ref=src_ref,
                cidr_or_range="0.0.0.0/0" if is_default else str(dest_net),
                ip_first_int=0 if is_default else int(dest_net.network_address),
                ip_last_int=MAX_IPV4_INT if is_default else int(dest_net.broadcast_address),
                prefix_len=0 if is_default else dest_net.prefixlen,
                installed_access_policy=installed_access_policy,
                policy_packages=list(policy_packages),
                updated_at=ts,
            )
        )

    return entries, member_drift_detected, drift_map
