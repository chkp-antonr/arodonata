"""Route-collection bash script builders, argument formatting, VSX target resolution, and auto-mode resolver."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from arodonata.core.context import normalize_domain_key
from arodonata.core.errors import ServerIdentityError, ValidationError
from arodonata.core.models.assets import Asset
from arodonata.core.models.topology import GatewayCliTarget, TopologySourceType
from arodonata.core.services.topology._shared import RepositoryScriptArgsCallable

ROUTE_LIMIT_MARKER = "===ARODONATA_ROUTE_LIMIT_REACHED==="
CLISH_SKIPPED_LARGE_TABLE_MARKER = "===ARODONATA_CLISH_SKIPPED_LARGE_TABLE==="
DEFAULT_CLISH_SKIP_THRESHOLD = 10000
DEFAULT_ROUTE_COLLECT_REPOSITORY_SCRIPT_NAME = "arodonata-collect-routes-v1"
DEFAULT_REPOSITORY_MAX_ROUTES = 50000
VSX_BUNDLE_START_MARKER = "===ARODONATA_VSX_BUNDLE_START==="
VSX_BUNDLE_END_MARKER = "===ARODONATA_VSX_BUNDLE_END==="
VS_START_PREFIX = "===ARODONATA_VS_START "
VS_END_MARKER = "===ARODONATA_VS_END==="
VS_ERROR_PREFIX = "===ARODONATA_VS_ERROR "

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
            except ServerIdentityError:
                raise
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

    def abort_probe_if_unresolved(
        self,
        mgmt_name: str,
        domain_name: str | None,
        *,
        exc: BaseException | None = None,
    ) -> None:
        """Release the in-flight probe slot if the prober exited before resolving."""
        key = (mgmt_name, normalize_domain_key(domain_name))
        if key in self._resolved:
            return
        fut = self._flights.pop(key, None)
        if fut is not None and not fut.done():
            fut.set_exception(
                exc if isinstance(exc, ServerIdentityError) else RuntimeError("auto script probe aborted")
            )
            fut.exception()


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
            'vsid=$(vsx stat -l 2>/dev/null </dev/null | awk -v target="$vs_name" '
            '\'/^VSID:/ {id=$2} /^Name:[ \\t]*/ {sub(/^Name:[ \\t]*/, ""); sub(/[ \\t\\r]+$/, ""); if ($0 == target) {print id; exit}}\')\n'
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


def build_route_collection_repository_script(
    *,
    default_max_routes: int = DEFAULT_REPOSITORY_MAX_ROUTES,
    default_skip_threshold: int = DEFAULT_CLISH_SKIP_THRESHOLD,
) -> str:
    """Build the canonical self-detecting bash script (`arodonata-collect-routes-v1`) for Check Point Script Repository.

    Execution modes:
    - Zero-argument (`$# -eq 0`): auto-detects VSX via `vsx stat -l </dev/null 2>/dev/null`.
      - On VSX chassis: iterates all L3 Virtual Systems / Virtual Routers (`VSID > 0`, skipping Virtual Switches),
        emitting a bundle delimited by `===ARODONATA_VSX_BUNDLE_START===` ... `===ARODONATA_VSX_BUNDLE_END===`
        with per-VS markers `===ARODONATA_VS_START vsid=<id> name=<name>===` ... `===ARODONATA_VS_END===`
        and isolating failed `vsenv` contexts with `===ARODONATA_VS_ERROR vsid=<id> name=<name> error=<err>===`.
      - On non-VSX gateways: executes with built-in route limit (`default_max_routes`) and clish skip threshold.
    - Parameterized (`$# -gt 0`): preserves backward-compatible positional argument handling:
      - `$1`: `max_routes` (digits-only; `0` or empty = unlimited)
      - `$2`: `vsid` (digits-only; `0` or empty = host / non-VSX)
      - `$3`: `vs_name` (optional Virtual System name resolved dynamically via `vsx stat -l` when `vsid=0`)
    """
    eff_skip_thr = min(default_skip_threshold, default_max_routes) if default_max_routes > 0 else default_skip_threshold
    return (
        'if [ "$#" -eq 0 ]; then\n'
        "  _is_vsx=0\n"
        '  _vs_list=""\n'
        "  if command -v vsx >/dev/null 2>&1 && command -v vsenv >/dev/null 2>&1; then\n"
        "    _vs_list=$(vsx stat -l </dev/null 2>/dev/null | awk '\n"
        "function flush() {\n"
        '  if (vid != "" && (vid + 0) > 0 && index(tolower(vtype), "switch") == 0) {\n'
        '    if (vname == "") vname = "VS_" vid;\n'
        '    print vid "\\t" vname;\n'
        "  }\n"
        '  vid = ""; vname = ""; vtype = "";\n'
        "}\n"
        "/^VSID:[ \\t]*/ { flush(); vid = $2; next }\n"
        '/^Name:[ \\t]*/ { sub(/^Name:[ \\t]*/, ""); sub(/[ \\t\\r]+$/, ""); vname = $0; next }\n'
        '/^Type:[ \\t]*/ { sub(/^Type:[ \\t]*/, ""); vtype = $0; next }\n'
        "END { flush() }')\n"
        '    if [ -n "$_vs_list" ]; then\n'
        "      _is_vsx=1\n"
        "    fi\n"
        "  fi\n"
        '  if [ "$_is_vsx" -eq 1 ]; then\n'
        f'    echo "{VSX_BUNDLE_START_MARKER}"\n'
        "    printf '%s\\n' \"$_vs_list\" | while IFS=\"$(printf '\\t')\" read -r vid vname; do\n"
        '      [ -n "$vid" ] || continue\n'
        f'      echo "{VS_START_PREFIX}vsid=${{vid}} name=${{vname}}==="\n'
        '      ctx=$(printf "CTX%05d" "$vid")\n'
        '      if ! vsenv "$vid" >/dev/null 2>&1 </dev/null; then\n'
        f'        echo "{VS_ERROR_PREFIX}vsid=${{vid}} name=${{vname}} error=vsenv ${{vid}} failed==="\n'
        "      else\n"
        '        case "$FWDIR" in\n'
        '          *"$ctx"*) ;;\n'
        f'          *) echo "{VS_ERROR_PREFIX}vsid=${{vid}} name=${{vname}} error=context not switched (FWDIR=$FWDIR)===" ;;\n'
        "        esac\n"
        '        case "$FWDIR" in\n'
        '          *"$ctx"*)\n'
        '            echo "===ARODONATA_IP_ROUTE_START==="\n'
        f"            ip -4 route show 2>/dev/null </dev/null | awk -v lim={default_max_routes} "
        f"'NR<=lim {{print}} NR==lim+1 {{print \"{ROUTE_LIMIT_MARKER}\"; exit}}' || true\n"
        '            echo "===ARODONATA_IP_ROUTE_END==="\n'
        "            ;;\n"
        "        esac\n"
        "      fi\n"
        f'      echo "{VS_END_MARKER}"\n'
        "    done\n"
        f'    echo "{VSX_BUNDLE_END_MARKER}"\n'
        "    exit 0\n"
        "  else\n"
        f"    max_routes={default_max_routes}\n"
        f"    skip_thr={eff_skip_thr}\n"
        '    echo "===ARODONATA_IP_ROUTE_START==="\n'
        "    _ip_rc=0\n"
        '    ip -4 route show 2>/dev/null </dev/null | awk -v lim="$max_routes" -v thr="$skip_thr" '
        f'\'NR<=lim {{print}} NR==lim+1 {{print "{ROUTE_LIMIT_MARKER}"; exit 42}} '
        "END {if (NR>thr) exit 42}' || _ip_rc=$?\n"
        '    echo "===ARODONATA_IP_ROUTE_END==="\n'
        '    if [ "$_ip_rc" -eq 42 ]; then\n'
        f'      echo "{CLISH_SKIPPED_LARGE_TABLE_MARKER}"\n'
        "    else\n"
        '      echo "===ARODONATA_CLISH_ROUTE_START==="\n'
        '      clish -c "show route" 2>/dev/null </dev/null | awk -v lim="$max_routes" '
        f"'NR<=lim {{print}} NR==lim+1 {{print \"{ROUTE_LIMIT_MARKER}\"; exit}}' || true\n"
        '      echo "===ARODONATA_CLISH_ROUTE_END==="\n'
        "    fi\n"
        "    exit 0\n"
        "  fi\n"
        "fi\n"
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
        '\'/^VSID:/ {id=$2} /^Name:[ \\t]*/ {sub(/^Name:[ \\t]*/, ""); sub(/[ \\t\\r]+$/, ""); if ($0 == target) {print id; exit}}\')\n'
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


def resolve_gateway_cli_targets(
    gateway_asset: Asset,
    all_assets: Sequence[Asset],
) -> list[GatewayCliTarget]:
    """Resolve a policy-enforcing gateway, cluster, or VSX Virtual System into concrete CLI execution targets.

    - `simple-gateway` -> `[gateway_asset]`
    - `simple-cluster` / `CpmiGatewayCluster` -> each `cluster-member` linked to the cluster (or the cluster itself if no members exist in cache)
    - `virtual-system` / `CpmiVsNetobj` / `CpmiVsClusterNetobj` -> the physical VSX parent (`VS0`) or its cluster members, carrying `vsid` and `vs_name`
    """
    scoped_assets = [a for a in all_assets if a.mgmt_name == gateway_asset.mgmt_name]
    by_uid: dict[str, Asset] = {a.uid: a for a in scoped_assets}
    by_id: dict[str, Asset] = {a.id: a for a in scoped_assets}
    by_asset_id: dict[str, Asset] = {a.asset_id: a for a in scoped_assets}

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

    for other in scoped_assets:
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


__all__ = [
    "AutoScriptModeResolver",
    "CLISH_SKIPPED_LARGE_TABLE_MARKER",
    "DEFAULT_CLISH_SKIP_THRESHOLD",
    "DEFAULT_REPOSITORY_MAX_ROUTES",
    "DEFAULT_ROUTE_COLLECT_REPOSITORY_SCRIPT_NAME",
    "ParsedCliRoute",
    "ROUTE_LIMIT_MARKER",
    "RepositoryScriptArgsCallable",
    "VSX_BUNDLE_END_MARKER",
    "VSX_BUNDLE_START_MARKER",
    "VS_END_MARKER",
    "VS_ERROR_PREFIX",
    "VS_START_PREFIX",
    "build_route_collection_repository_script",
    "build_route_collection_script",
    "format_route_collection_repository_args",
    "resolve_gateway_cli_targets",
]
