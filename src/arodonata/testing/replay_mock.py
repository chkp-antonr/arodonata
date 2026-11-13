"""File-backed Check Point Management API and Gateway CLI replay adapters (`replay_mock.py`).

Provides:
- `FileReplayApiMock` (`ApiPort`): serves raw Check Point Management API JSON fixtures from
  `tests/fixtures/enterprise_raw_dataset/` with pagination (`limit`, `offset` -> `from`, `to`, `total`),
  `details-level` (`uid`, `standard`, `full`), `uid`/`name` and `class-name` filtering, rulebase section
  slicing (`show-access-rulebase`, `show-nat-rulebase`), `run-script` + `show-task` Base64 task execution,
  in-memory mutation helpers for targeted refresh tests, and per-domain/per-command call counters.
- `FileReplayCliMock` (`GatewayCliPort`): parses bash scripts produced by `build_route_collection_script`,
  verifies `vsenv "$vsid"` / `vsx stat -l` and `CTX%05d` `$FWDIR` checks, returns raw stdout/stderr from
  `cli/`, supports per-node SSH failure injection to trigger `cprid` `run-script` fallback, and records
  CLI execution counters.
"""

from __future__ import annotations

import base64
import copy
import json
import re
from collections import Counter
from collections.abc import Awaitable
from pathlib import Path
from typing import Any

from arodonata.adapters.checkpoint.pager import DEFAULT_PAGE_LIMIT, paginate_objects
from arodonata.core.context import AuthContext
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.topology import GatewayCliResult, GatewayCliTarget
from arodonata.core.ports import ApiPort, GatewayCliPort
from arodonata.testing.dataset_generator import (
    ALL_DOMAINS,
    DEFAULT_DATASET_DIR,
    ensure_enterprise_raw_dataset,
)

_VSID_SCRIPT_RE = re.compile(r"(?:^|\n)vsid=(\d+)\b")
_VS_NAME_SCRIPT_RE = re.compile(r"(?:^|\n)vs_name=([^\n]+)")

_SHOW_OBJECTS_TYPE_TO_CMD: dict[str, str] = {
    "host": "show-hosts",
    "network": "show-networks",
    "address-range": "show-address-ranges",
    "multicast-address-range": "show-multicast-address-ranges",
    "group": "show-groups",
    "group-with-exclusion": "show-groups-with-exclusion",
    "dns-domain": "show-dns-domains",
    "application-site": "show-application-sites",
    "security-zone": "show-security-zones",
    "dynamic-object": "show-dynamic-objects",
    "service-tcp": "show-services-tcp",
    "service-udp": "show-services-udp",
    "service-icmp": "show-services-icmp",
    "service-icmp6": "show-services-icmp6",
    "service-other": "show-services-other",
    "service-sctp": "show-services-sctp",
    "service-dce-rpc": "show-services-dce-rpc",
    "service-rpc": "show-services-rpc",
    "service-gtp": "show-services-gtp",
    "service-citrix-tcp": "show-services-citrix-tcp",
    "service-compound-tcp": "show-services-compound-tcp",
    "service-group": "show-service-groups",
}

_SHOW_OBJECTS_IP_FIELDS: tuple[str, ...] = (
    "ipv4-address",
    "ipv6-address",
    "subnet4",
    "subnet6",
    "ipv4-address-first",
    "ipv4-address-last",
    "ipv6-address-first",
    "ipv6-address-last",
)

_SHOW_OBJECTS_TEXT_FIELDS: tuple[str, ...] = (
    "name",
    "comments",
    *_SHOW_OBJECTS_IP_FIELDS,
    "port",
    "protocol",
    "ip-protocol",
    "fqdn",
)


def _matches_show_objects_filter(item: dict[str, Any], *, filter_needle: str, ip_only: bool) -> bool:
    """Evaluate Check Point `show-objects` substring filtering (`filter` and `ip-only`)."""
    if not filter_needle:
        if not ip_only:
            return True
        return any(item.get(field) not in (None, "") for field in _SHOW_OBJECTS_IP_FIELDS)

    candidate_fields = _SHOW_OBJECTS_IP_FIELDS if ip_only else _SHOW_OBJECTS_TEXT_FIELDS
    for field in candidate_fields:
        val = item.get(field)
        if val is not None and filter_needle in str(val).lower():
            return True
    if not ip_only:
        url_list = item.get("url-list")
        if isinstance(url_list, list):
            for entry in url_list:
                if entry is not None and filter_needle in str(entry).lower():
                    return True
    return False


def _project_details_level(item: dict[str, Any], details_level: str) -> dict[str, Any]:
    """Project an object dictionary according to Check Point `details-level` (`uid`, `standard`, `full`)."""
    lvl = (details_level or "standard").strip().lower()
    if lvl == "uid":
        uid = item.get("uid")
        return {"uid": uid} if uid is not None else dict(item)
    if lvl == "standard":
        # Keep core summary fields while still preserving enough metadata for standard listings
        summary_keys = {
            "uid",
            "name",
            "type",
            "domain",
            "ipv4-address",
            "ipv6-address",
            "ipv4-address-first",
            "ipv4-address-last",
            "ipv6-address-first",
            "ipv6-address-last",
            "subnet4",
            "subnet6",
            "mask-length4",
            "mask-length6",
            "subnet-mask",
            "port",
            "protocol",
            "icmp-type",
            "icmp-code",
            "ip-protocol",
            "fqdn",
            "is-sub-domain",
            "url-list",
            "urls-defined-as-regular-expression",
            "primary-category",
            "members",
            "color",
            "comments",
            "meta-info",
            "icon",
            "tags",
            "class-name",
        }
        return {k: copy.deepcopy(v) for k, v in item.items() if k in summary_keys}
    return copy.deepcopy(item)


def _slice_rulebase_nodes(
    layer_payload: dict[str, Any],
    *,
    offset: int,
    limit: int,
) -> dict[str, Any]:
    """Slice a Check Point `show-access-rulebase` or `show-nat-rulebase` payload by rule `offset` and `limit`."""
    raw_nodes = layer_payload.get("rulebase")
    nodes = raw_nodes if isinstance(raw_nodes, list) else []

    # Flatten rules with their enclosing section metadata so we can slice accurately by rule index
    flat_rules: list[tuple[dict[str, Any] | None, dict[str, Any]]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_type = str(node.get("type") or "")
        if node_type.endswith("-section") or (isinstance(node.get("rulebase"), list) and "rule-number" not in node):
            child_list = node.get("rulebase")
            children = child_list if isinstance(child_list, list) else []
            for child in children:
                if isinstance(child, dict):
                    flat_rules.append((node, child))
        else:
            flat_rules.append((None, node))

    total = len(flat_rules)
    eff_offset = max(0, int(offset))
    eff_limit = max(1, int(limit))
    sliced = flat_rules[eff_offset : eff_offset + eff_limit]

    page_nodes: list[dict[str, Any]] = []
    current_sec_uid: str | None = None
    current_sec_dict: dict[str, Any] | None = None

    for idx_in_slice, (sec_meta, rule_dict) in enumerate(sliced):
        abs_rule_num = eff_offset + idx_in_slice + 1
        if sec_meta is None:
            current_sec_uid = None
            current_sec_dict = None
            page_nodes.append(copy.deepcopy(rule_dict))
        else:
            sec_uid = str(sec_meta.get("uid") or sec_meta.get("name") or "sec")
            if sec_uid != current_sec_uid or current_sec_dict is None:
                current_sec_uid = sec_uid
                current_sec_dict = {
                    "uid": sec_meta.get("uid"),
                    "name": sec_meta.get("name"),
                    "type": sec_meta.get("type", "access-section"),
                    "from": abs_rule_num,
                    "to": abs_rule_num,
                    "rulebase": [copy.deepcopy(rule_dict)],
                }
                page_nodes.append(current_sec_dict)
            else:
                current_sec_dict["to"] = abs_rule_num
                current_sec_dict["rulebase"].append(copy.deepcopy(rule_dict))

    from_idx = (eff_offset + 1) if sliced else 0
    to_idx = (eff_offset + len(sliced)) if sliced else 0

    result: dict[str, Any] = {
        "uid": layer_payload.get("uid", ""),
        "name": layer_payload.get("name", ""),
        "rulebase": page_nodes,
        "objects-dictionary": copy.deepcopy(layer_payload.get("objects-dictionary", [])),
        "from": from_idx,
        "to": to_idx,
        "total": total,
    }
    if "package" in layer_payload:
        result["package"] = layer_payload["package"]
    return result


class FileReplayCliMock(GatewayCliPort):
    """File-backed `GatewayCliPort` replay adapter for gateway SSH route collection."""

    def __init__(
        self,
        dataset_dir: Path | str = DEFAULT_DATASET_DIR,
        *,
        fail_ssh_nodes: set[str] | None = None,
    ) -> None:
        self._dataset_dir = ensure_enterprise_raw_dataset(dataset_dir)
        self._cli_dir = self._dataset_dir / "cli"
        # Default branch gateways that fail SSH so cprid `run-script` fallback is exercised
        self.fail_ssh_nodes: set[str] = (
            set(fail_ssh_nodes) if fail_ssh_nodes is not None else {"br-reg-gw-138", "br-reg-gw-139", "br-reg-gw-140"}
        )
        self._cli_overrides: dict[tuple[str, int], str] = {}
        self.cli_call_counts: Counter[tuple[str, int]] = Counter()
        self.node_call_counts: Counter[str] = Counter()
        self.cli_call_log: list[dict[str, Any]] = []

    def reset_counters(self) -> None:
        """Clear all CLI execution counters and logs."""
        self.cli_call_counts.clear()
        self.node_call_counts.clear()
        self.cli_call_log.clear()

    def set_cli_stdout(self, node_name: str, vsid: int, stdout: str) -> None:
        """Override the raw CLI stdout returned for `(node_name, vsid)` in memory."""
        self._cli_overrides[(node_name, int(vsid))] = stdout

    def get_raw_cli_stdout(self, node_name: str, vsid: int | None = 0) -> str | None:
        """Return the raw CLI stdout for `(node_name, vsid)` from memory override or disk fixture."""
        eff_vsid = int(vsid) if vsid is not None else 0
        key = (node_name, eff_vsid)
        if key in self._cli_overrides:
            return self._cli_overrides[key]
        candidates = [self._cli_dir / f"{node_name}__vs_{eff_vsid}.txt"]
        if eff_vsid == 0:
            candidates.append(self._cli_dir / f"{node_name}__vs_none.txt")
        for cli_path in candidates:
            if cli_path.is_file():
                return cli_path.read_text(encoding="utf-8")
        return None

    def resolve_vsid_from_stat(self, node_name: str, vs_name: str) -> int | None:
        """Emulate `vsx stat -l` awk resolution of `vs_name` -> `vsid` on `node_name` (`VS0`)."""
        stat_path = self._cli_dir / f"{node_name}__vsx_stat_l.txt"
        if not stat_path.is_file():
            return None
        current_id: int | None = None
        clean_target = vs_name.strip().strip("'\"")
        for raw_line in stat_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line.startswith("VSID:"):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        current_id = int(parts[1])
                    except ValueError:
                        current_id = None
            elif line.startswith("Name:"):
                parts = line.split(None, 1)
                if len(parts) >= 2 and parts[1].strip() == clean_target and current_id is not None:
                    return current_id
        return None

    async def execute_command(
        self,
        target: GatewayCliTarget,
        command: str,
        *,
        timeout: float = 30.0,
    ) -> GatewayCliResult:
        """Validate the incoming route-collection bash script and return raw CLI output from `cli/`."""
        _ = timeout
        node_name = target.node_name
        self.node_call_counts[node_name] += 1

        if node_name in self.fail_ssh_nodes or target.gateway_name in self.fail_ssh_nodes:
            self.cli_call_log.append(
                {
                    "node_name": node_name,
                    "gateway_name": target.gateway_name,
                    "vsid": target.vsid,
                    "vs_name": target.vs_name,
                    "status": "ssh_failed",
                }
            )
            return GatewayCliResult(
                success=False,
                stdout="",
                stderr=f"ssh: connect to host {target.node_ipv4 or node_name} port 22: Connection timed out",
                exit_code=255,
                executor="ssh",
                error_message=f"SSH connection timed out to {node_name}",
            )

        # Parse and validate VS context switching in the bash script
        resolved_vsid = 0
        prepend_resolved_marker = False
        m_vsid = _VSID_SCRIPT_RE.search(command)
        m_vs_name = _VS_NAME_SCRIPT_RE.search(command)

        if m_vsid is not None:
            resolved_vsid = int(m_vsid.group(1))
            if 'vsenv "$vsid"' not in command or "CTX%05d" not in command:
                return GatewayCliResult(
                    success=False,
                    stdout="_vs_error=missing vsenv or CTX%05d check in script\n",
                    stderr="Invalid VSX script structure",
                    exit_code=1,
                    executor="ssh",
                    error_message="_vs_error=missing vsenv or CTX%05d check in script",
                )
        elif m_vs_name is not None:
            raw_vs_name = m_vs_name.group(1).strip()
            if "vsx stat -l" not in command or 'vsenv "$vsid"' not in command or "CTX%05d" not in command:
                return GatewayCliResult(
                    success=False,
                    stdout="_vs_error=missing vsx stat -l or vsenv check in script\n",
                    stderr="Invalid VSX stat script structure",
                    exit_code=1,
                    executor="ssh",
                    error_message="_vs_error=missing vsx stat -l or vsenv check in script",
                )
            vsid_lookup = self.resolve_vsid_from_stat(node_name, raw_vs_name)
            if vsid_lookup is None or vsid_lookup <= 0:
                clean_vs = raw_vs_name.strip("'\"")
                err_out = f"_vs_error=unable to resolve vsid for {clean_vs}\n"
                return GatewayCliResult(
                    success=False,
                    stdout=err_out,
                    stderr=err_out.strip(),
                    exit_code=1,
                    executor="ssh",
                    error_message=err_out.strip(),
                )
            resolved_vsid = vsid_lookup
            prepend_resolved_marker = True

        self.cli_call_counts[(node_name, resolved_vsid)] += 1
        self.cli_call_log.append(
            {
                "node_name": node_name,
                "gateway_name": target.gateway_name,
                "vsid": resolved_vsid,
                "vs_name": target.vs_name,
                "status": "ok",
            }
        )

        stdout = self.get_raw_cli_stdout(node_name, resolved_vsid)
        if stdout is None:
            err_msg = f"_vs_error=vsenv {resolved_vsid} failed\n" if resolved_vsid > 0 else "No CLI fixture found"
            return GatewayCliResult(
                success=False,
                stdout=err_msg if resolved_vsid > 0 else "",
                stderr=err_msg,
                exit_code=1,
                executor="ssh",
                error_message=err_msg.strip(),
            )

        if prepend_resolved_marker and f"===ARODONATA_VSID_RESOLVED={resolved_vsid}===" not in stdout:
            stdout = f"===ARODONATA_VSID_RESOLVED={resolved_vsid}===\n{stdout}"

        return GatewayCliResult(
            success=True,
            stdout=stdout,
            stderr="",
            exit_code=0,
            executor="ssh",
        )


class FileReplayApiMock(ApiPort):
    """File-backed `ApiPort` replay adapter emulating Check Point MDSM and CMA domains from disk fixtures."""

    def __init__(
        self,
        dataset_dir: Path | str = DEFAULT_DATASET_DIR,
        *,
        cli_mock: FileReplayCliMock | None = None,
    ) -> None:
        self._dataset_dir = ensure_enterprise_raw_dataset(dataset_dir)
        self._cli_mock = cli_mock or FileReplayCliMock(self._dataset_dir)

        self._manifest: dict[str, Any] = json.loads((self._dataset_dir / "manifest.json").read_text(encoding="utf-8"))
        self._show_domains: dict[str, Any] = json.loads(
            (self._dataset_dir / "mds" / "show-domains.json").read_text(encoding="utf-8")
        )
        self._show_global_domain: dict[str, Any] = json.loads(
            (self._dataset_dir / "mds" / "show-global-domain.json").read_text(encoding="utf-8")
        )
        self._show_mdss: dict[str, Any] = json.loads(
            (self._dataset_dir / "mds" / "show-mdss.json").read_text(encoding="utf-8")
        )

        # Load domain JSON payloads into memory so tests can mutate single gateways without modifying disk files
        self._domain_data: dict[str, dict[str, Any]] = {}
        for dom_name in ALL_DOMAINS:
            dom_dir = self._dataset_dir / "domains" / dom_name
            dom_files: dict[str, Any] = {}
            if dom_dir.is_dir():
                for json_file in sorted(dom_dir.glob("*.json")):
                    dom_files[json_file.stem] = json.loads(json_file.read_text(encoding="utf-8"))
            self._domain_data[dom_name] = dom_files

        # Index node_uid -> node_name across all domains for `run-script` target resolution
        self._node_uid_to_name: dict[str, str] = {}
        for dom_files in self._domain_data.values():
            gw_and_srv = dom_files.get("show-gateways-and-servers", {}).get("objects", [])
            for obj in gw_and_srv:
                if isinstance(obj, dict) and obj.get("uid") and obj.get("name"):
                    self._node_uid_to_name[str(obj["uid"])] = str(obj["name"])
                    members = obj.get("cluster-member-names")
                    if isinstance(members, list):
                        for m in members:
                            if isinstance(m, dict) and m.get("uid") and m.get("name"):
                                self._node_uid_to_name[str(m["uid"])] = str(m["name"])

        self._tasks: dict[str, dict[str, Any]] = {}
        self._sid_seq = 0
        self._task_seq = 0

        # Call counters and call logs for test assertions
        self.api_call_counts: Counter[tuple[str, str]] = Counter()
        self.api_query_counts: Counter[tuple[str, str]] = Counter()
        self.command_counts: Counter[str] = Counter()
        self.gateway_detail_queries: list[tuple[str, str, str]] = []
        self.call_log: list[dict[str, Any]] = []

    @property
    def dataset_dir(self) -> Path:
        """Path to the backing `enterprise_raw_dataset` fixture directory."""
        return self._dataset_dir

    @property
    def cli_mock(self) -> FileReplayCliMock:
        """Associated `FileReplayCliMock` instance."""
        return self._cli_mock

    @property
    def manifest(self) -> dict[str, Any]:
        """Loaded `manifest.json` metadata dictionary."""
        return self._manifest

    def reset_counters(self) -> None:
        """Reset all API and CLI call counters and logs."""
        self.api_call_counts.clear()
        self.api_query_counts.clear()
        self.command_counts.clear()
        self.gateway_detail_queries.clear()
        self.call_log.clear()
        self._cli_mock.reset_counters()

    # ------------------------------------------------------------------
    # In-Memory Mutation Helpers for Step 6 Targeted Gateway Refresh
    # ------------------------------------------------------------------

    def update_gateway_interfaces(
        self,
        domain: str,
        gateway_name_or_uid: str,
        interfaces: list[dict[str, Any]],
    ) -> None:
        """Update the raw `interfaces` list for a single gateway across summary and detail payloads in memory."""
        dom_files = self._domain_data[domain]
        target_uid: str | None = None
        target_name: str | None = None

        for obj in dom_files.get("show-gateways-and-servers", {}).get("objects", []):
            if obj.get("uid") == gateway_name_or_uid or obj.get("name") == gateway_name_or_uid:
                target_uid = str(obj["uid"])
                target_name = str(obj["name"])
                obj["interfaces"] = copy.deepcopy(interfaces)
                break

        for detail_cmd in ("show-simple-gateway", "show-simple-cluster", "show-generic-object"):
            store = dom_files.get(detail_cmd, {})
            for key in (gateway_name_or_uid, target_uid, target_name):
                if key and key in store:
                    store[key]["interfaces"] = copy.deepcopy(interfaces)

    def update_gateway_cli_stdout(
        self,
        node_name: str,
        stdout: str,
        *,
        vsid: int = 0,
    ) -> None:
        """Update the raw CLI routing stdout for `(node_name, vsid)` in the associated `FileReplayCliMock`."""
        self._cli_mock.set_cli_stdout(node_name, vsid, stdout)

    def bump_published_session(
        self,
        domain: str,
        *,
        new_session_uid: str,
        new_iso_time: str = "2026-11-09T12:00:00Z",
        new_posix_time: int = 1794225600000,
    ) -> None:
        """Simulate a new `publish` in `domain` by updating `show-last-published-session` and `show-sessions`."""
        dom_files = self._domain_data[domain]
        new_sess = {
            "uid": new_session_uid,
            "name": f"session-{domain.lower()}-updated",
            "type": "session",
            "state": "published",
            "locks": 0,
            "published-changes": 1,
            "number-of-published-changes": 0,
            "publish-time": {"posix": new_posix_time, "iso-8601": new_iso_time},
            "last-login-was-at": {"posix": new_posix_time - 5000, "iso-8601": new_iso_time},
        }
        dom_files["show-last-published-session"] = copy.deepcopy(new_sess)
        sessions_list = dom_files.setdefault("show-sessions", {}).setdefault("objects", [])
        sessions_list.insert(0, copy.deepcopy(new_sess))
        dom_files["show-sessions"]["total"] = len(sessions_list)
        dom_files["show-sessions"]["to"] = len(sessions_list)

    # ------------------------------------------------------------------
    # Internal Command Dispatch
    # ------------------------------------------------------------------

    def _normalize_domain(self, domain: str | None) -> str:
        if not domain or not domain.strip() or domain.strip() == "System Data":
            return "System Data"
        clean = domain.strip()
        if clean in self._domain_data:
            return clean
        # Check by domain UID or case-insensitive name
        for d_obj in self._show_domains.get("objects", []):
            if d_obj.get("uid") == clean or str(d_obj.get("name", "")).lower() == clean.lower():
                return str(d_obj["name"])
        if clean.lower() == "global" or self._show_global_domain.get("uid") == clean:
            return "Global"
        return clean

    @staticmethod
    def _paginate_list(
        items: list[dict[str, Any]],
        payload: dict[str, Any],
        *,
        collection_key: str = "objects",
    ) -> dict[str, Any]:
        details_level = str(payload.get("details-level") or "standard")
        limit = int(payload.get("limit", DEFAULT_PAGE_LIMIT))
        offset = int(payload.get("offset", 0))
        total = len(items)
        sliced = items[offset : offset + limit]
        projected = [_project_details_level(item, details_level) for item in sliced]
        from_val = (offset + 1) if projected else 0
        to_val = (offset + len(projected)) if projected else 0
        return {
            collection_key: projected,
            "from": from_val,
            "to": to_val,
            "total": total,
        }

    def _handle_run_script(
        self,
        dom_name: str,
        payload: dict[str, Any],
        *,
        wait_for_task: bool,
    ) -> ApiCallResult:
        targets = payload.get("targets") or []
        if isinstance(targets, str):
            targets = [targets]
        target_ref = str(targets[0]) if targets else "unknown-target"
        node_name = self._node_uid_to_name.get(target_ref, target_ref)
        script = str(payload.get("script") or "")

        vsid = 0
        m_vsid = _VSID_SCRIPT_RE.search(script)
        m_vs_name = _VS_NAME_SCRIPT_RE.search(script)
        prepend_resolved = False
        script_error: str | None = None
        if m_vsid is not None:
            vsid = int(m_vsid.group(1))
            if 'vsenv "$vsid"' not in script or "CTX%05d" not in script:
                script_error = f"_vs_error=vsenv_{vsid}_missing_guard"
        elif m_vs_name is not None:
            vs_name_val = m_vs_name.group(1)
            if "vsx stat -l" not in script or 'vsenv "$vsid"' not in script or "CTX%05d" not in script:
                script_error = f"_vs_error=vsx_stat_missing_guard:{vs_name_val}"
            else:
                resolved = self._cli_mock.resolve_vsid_from_stat(node_name, vs_name_val)
                if resolved is None:
                    script_error = f"_vs_error=vs_not_found:{vs_name_val}"
                else:
                    vsid = resolved
                    prepend_resolved = True

        self._task_seq += 1
        task_id = f"12345678-8888-4888-8888-{self._task_seq:012d}"

        if script_error is not None:
            b64_err = base64.b64encode((script_error + "\n").encode("utf-8")).decode("ascii")
            task_obj = {
                "uid": task_id,
                "task-id": task_id,
                "task-name": str(payload.get("script-name") or f"arodonata-route-collect-{node_name}"),
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
            self._tasks[task_id] = task_obj
            if wait_for_task:
                return ApiCallResult(
                    success=False,
                    status_code=200,
                    error_code="generic_err_task_failed",
                    error_message=script_error,
                    data={"tasks": [copy.deepcopy(task_obj)]},
                )
            return ApiCallResult(
                success=True,
                status_code=200,
                data={"tasks": [{"target": target_ref, "task-id": task_id}]},
            )

        # Load pre-generated task file if present and not overridden in memory
        task_file = self._dataset_dir / "tasks" / f"{node_name}__vs_{vsid}.json"
        if not task_file.is_file() and vsid == 0:
            alt_task_file = self._dataset_dir / "tasks" / f"{node_name}__vs_none.json"
            if alt_task_file.is_file():
                task_file = alt_task_file
        override_stdout = self._cli_mock.get_raw_cli_stdout(node_name, vsid)

        if task_file.is_file() and (node_name, vsid) not in self._cli_mock._cli_overrides and not prepend_resolved:
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
                "task-name": str(payload.get("script-name") or f"arodonata-route-collect-{node_name}"),
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

        self._tasks[task_id] = task_obj

        if wait_for_task:
            # Also record the show-task poll so tests can verify run-script + show-task interaction
            self.api_call_counts[(dom_name, "show-task")] += 1
            self.command_counts["show-task"] += 1
            self.call_log.append(
                {
                    "mgmt_name": "mds",
                    "domain": dom_name,
                    "command": "show-task",
                    "payload": {"task-id": task_id, "details-level": "full"},
                }
            )
            return ApiCallResult(
                success=True,
                status_code=200,
                data={"tasks": [copy.deepcopy(task_obj)]},
            )

        return ApiCallResult(
            success=True,
            status_code=200,
            data={
                "tasks": [
                    {
                        "target": target_ref,
                        "task-id": task_id,
                        "task-name": task_obj.get("task-name", "run-script"),
                    }
                ]
            },
        )

    # ------------------------------------------------------------------
    # ApiPort Implementation
    # ------------------------------------------------------------------

    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ) -> ApiCallResult:
        """Execute a single Check Point Management API command against the loaded raw dataset."""
        _ = (sid, server_ip, timeout)
        clean_cmd = command.strip().lstrip("/")
        if clean_cmd.startswith("web_api/"):
            clean_cmd = clean_cmd.removeprefix("web_api/")
        req = dict(payload) if payload else {}
        dom_name = self._normalize_domain(domain or (req.get("domain") if clean_cmd != "login" else None))

        self.api_call_counts[(dom_name, clean_cmd)] += 1
        self.command_counts[clean_cmd] += 1
        self.call_log.append(
            {
                "mgmt_name": mgmt_name,
                "domain": dom_name,
                "command": clean_cmd,
                "payload": copy.deepcopy(req),
            }
        )

        # 1. Session & system lifecycle commands
        if clean_cmd == "login":
            self._sid_seq += 1
            login_dom = self._normalize_domain(req.get("domain") or domain)
            return ApiCallResult(
                success=True,
                status_code=200,
                data={
                    "sid": f"mock-sid-{login_dom}-{self._sid_seq}",
                    "uid": f"sess-login-{self._sid_seq:06d}",
                    "session-timeout": 600,
                    "api-server-version": "1.9.1",
                    "disk-space-message": "OK",
                },
            )

        if clean_cmd in ("logout", "keepalive", "discard"):
            return ApiCallResult(success=True, status_code=200, data={"message": "OK"})

        if clean_cmd == "publish":
            self._task_seq += 1
            tid = f"12345678-9999-4999-8999-{self._task_seq:012d}"
            t_obj = {
                "uid": tid,
                "task-id": tid,
                "task-name": "Publish operation",
                "status": "succeeded",
                "progress-percentage": 100,
                "suppressed": False,
                "task-details": [{"uid": f"td-{tid}", "statusDescription": "Publish completed successfully"}],
            }
            self._tasks[tid] = t_obj
            if wait_for_task:
                return ApiCallResult(success=True, status_code=200, data={"tasks": [t_obj]})
            return ApiCallResult(success=True, status_code=200, data={"task-id": tid})

        if clean_cmd == "show-api-versions":
            return ApiCallResult(
                success=True,
                status_code=200,
                data={"current-version": "1.9.1", "supported-versions": ["1.8", "1.9", "1.9.1"]},
            )

        # 2. MDS domain discovery commands
        if clean_cmd == "show-domains":
            items = self._show_domains.get("objects", [])
            return ApiCallResult(
                success=True,
                status_code=200,
                data=self._paginate_list(items, req, collection_key="objects"),
            )

        if clean_cmd == "show-global-domain":
            return ApiCallResult(
                success=True,
                status_code=200,
                data=copy.deepcopy(self._show_global_domain),
            )

        if clean_cmd == "show-domain":
            lookup = str(req.get("name") or req.get("uid") or dom_name)
            if lookup.lower() == "global" or lookup == self._show_global_domain.get("uid"):
                return ApiCallResult(success=True, status_code=200, data=copy.deepcopy(self._show_global_domain))
            for d_obj in self._show_domains.get("objects", []):
                if d_obj.get("name") == lookup or d_obj.get("uid") == lookup:
                    return ApiCallResult(success=True, status_code=200, data=copy.deepcopy(d_obj))
            return ApiCallResult(
                success=False,
                status_code=404,
                error_code="generic_err_object_not_found",
                error_message=f"Requested domain [{lookup}] not found",
                data={"code": "generic_err_object_not_found", "message": f"Requested domain [{lookup}] not found"},
            )

        if clean_cmd == "show-mdss":
            items = self._show_mdss.get("objects", [])
            return ApiCallResult(
                success=True,
                status_code=200,
                data=self._paginate_list(items, req, collection_key="objects"),
            )

        # 3. Task polling & cprid `run-script`
        if clean_cmd == "run-script":
            return self._handle_run_script(dom_name, req, wait_for_task=wait_for_task)

        if clean_cmd == "show-task":
            raw_tid = req.get("task-id")
            tids = [raw_tid] if isinstance(raw_tid, str) else (list(raw_tid) if isinstance(raw_tid, list) else [])
            found_tasks: list[dict[str, Any]] = []
            for tid in tids:
                if str(tid) in self._tasks:
                    found_tasks.append(copy.deepcopy(self._tasks[str(tid)]))
            if not found_tasks:
                return ApiCallResult(
                    success=False,
                    status_code=404,
                    error_code="generic_err_object_not_found",
                    error_message=f"Requested task {tids} not found",
                    data={"code": "generic_err_object_not_found", "message": f"Requested task {tids} not found"},
                )
            return ApiCallResult(success=True, status_code=200, data={"tasks": found_tasks})

        # 4. Domain-scoped commands
        if dom_name == "System Data":
            if clean_cmd in ("show-last-published-session", "show-session"):
                return ApiCallResult(
                    success=True,
                    status_code=200,
                    data={
                        "uid": "sess-system-data-0001",
                        "name": "system-session",
                        "type": "session",
                        "state": "published",
                        "locks": 0,
                        "published-changes": 0,
                        "number-of-published-changes": 0,
                        "publish-time": {"posix": 1794139200000, "iso-8601": "2026-11-08T12:00:00Z"},
                    },
                )
            if clean_cmd == "show-sessions":
                return ApiCallResult(
                    success=True,
                    status_code=200,
                    data={"objects": [], "from": 0, "to": 0, "total": 0},
                )

        dom_files = self._domain_data.get(dom_name)
        if dom_files is None:
            return ApiCallResult(
                success=False,
                status_code=404,
                error_code="generic_err_object_not_found",
                error_message=f"Domain [{dom_name}] not found in dataset",
                data={"code": "generic_err_object_not_found", "message": f"Domain [{dom_name}] not found"},
            )

        if clean_cmd in ("show-last-published-session", "show-session"):
            sess_data = dom_files.get(clean_cmd) or dom_files.get("show-last-published-session") or {}
            return ApiCallResult(success=True, status_code=200, data=copy.deepcopy(sess_data))

        if clean_cmd in ("show-simple-gateway", "show-simple-cluster", "show-generic-object"):
            lookup_key = str(req.get("uid") or req.get("name") or "")
            self.gateway_detail_queries.append((dom_name, clean_cmd, lookup_key))
            store = dom_files.get(clean_cmd, {})
            if lookup_key in store:
                return ApiCallResult(
                    success=True,
                    status_code=200,
                    data=_project_details_level(store[lookup_key], str(req.get("details-level") or "full")),
                )
            for item_val in store.values():
                if isinstance(item_val, dict) and item_val.get("name") == lookup_key:
                    return ApiCallResult(
                        success=True,
                        status_code=200,
                        data=_project_details_level(item_val, str(req.get("details-level") or "full")),
                    )
            if clean_cmd == "show-generic-object":
                raw_gen = dom_files.get("show-generic-objects", {})
                gen_lists = (
                    [raw_gen["objects"]]
                    if isinstance(raw_gen.get("objects"), list)
                    else [v for v in raw_gen.values() if isinstance(v, list)]
                )
                for g_list in gen_lists:
                    for g_obj in g_list:
                        if isinstance(g_obj, dict) and (
                            g_obj.get("uid") == lookup_key or g_obj.get("name") == lookup_key
                        ):
                            return ApiCallResult(
                                success=True,
                                status_code=200,
                                data=_project_details_level(g_obj, str(req.get("details-level") or "full")),
                            )
            return ApiCallResult(
                success=False,
                status_code=404,
                error_code="generic_err_object_not_found",
                error_message=f"Requested object [{lookup_key}] not found",
                data={"code": "generic_err_object_not_found", "message": f"Requested object [{lookup_key}] not found"},
            )

        if clean_cmd == "show-generic-objects":
            raw_gen = dom_files.get("show-generic-objects", {})
            cls_filter = req.get("class-name")
            name_filter = req.get("name")
            if isinstance(raw_gen.get("objects"), list):
                all_generic = [g for g in raw_gen["objects"] if not cls_filter or g.get("class-name") == cls_filter]
            elif cls_filter:
                all_generic = list(raw_gen.get(str(cls_filter), []))
            else:
                all_generic = [g for v in raw_gen.values() if isinstance(v, list) for g in v if isinstance(g, dict)]
            filtered = [g for g in all_generic if not name_filter or g.get("name") == name_filter]
            return ApiCallResult(
                success=True,
                status_code=200,
                data=self._paginate_list(filtered, req, collection_key="objects"),
            )

        if clean_cmd == "show-access-rulebase":
            rb_store = dom_files.get("show-access-rulebase", {})
            lookup = str(req.get("uid") or req.get("name") or "")
            layer_payload = rb_store.get(lookup)
            if layer_payload is None and lookup in self._domain_data.get("Global", {}).get("show-access-rulebase", {}):
                layer_payload = self._domain_data["Global"]["show-access-rulebase"][lookup]
            if layer_payload is None:
                return ApiCallResult(
                    success=False,
                    status_code=404,
                    error_code="generic_err_object_not_found",
                    error_message=f"Requested access layer [{lookup}] not found in {dom_name}",
                    data={
                        "code": "generic_err_object_not_found",
                        "message": f"Requested access layer [{lookup}] not found in {dom_name}",
                    },
                )
            sliced_rb = _slice_rulebase_nodes(
                layer_payload,
                offset=int(req.get("offset", 0)),
                limit=int(req.get("limit", 100)),
            )
            return ApiCallResult(success=True, status_code=200, data=sliced_rb)

        if clean_cmd == "show-nat-rulebase":
            nat_store = dom_files.get("show-nat-rulebase", {})
            pkg_lookup = str(req.get("package") or req.get("uid") or req.get("name") or "")
            nat_payload = nat_store.get(pkg_lookup)
            if nat_payload is None:
                return ApiCallResult(
                    success=False,
                    status_code=404,
                    error_code="generic_err_object_not_found",
                    error_message=f"Requested NAT package [{pkg_lookup}] not found in {dom_name}",
                    data={
                        "code": "generic_err_object_not_found",
                        "message": f"Requested NAT package [{pkg_lookup}] not found in {dom_name}",
                    },
                )
            sliced_nat = _slice_rulebase_nodes(
                nat_payload,
                offset=int(req.get("offset", 0)),
                limit=int(req.get("limit", 100)),
            )
            return ApiCallResult(success=True, status_code=200, data=sliced_nat)

        if clean_cmd == "show-package":
            pkg_lookup = str(req.get("name") or req.get("uid") or "")
            for pkg in dom_files.get("show-packages", {}).get("packages", []):
                if pkg.get("name") == pkg_lookup or pkg.get("uid") == pkg_lookup:
                    return ApiCallResult(success=True, status_code=200, data=copy.deepcopy(pkg))
            return ApiCallResult(
                success=False,
                status_code=404,
                error_code="generic_err_object_not_found",
                error_message=f"Package [{pkg_lookup}] not found",
                data={"code": "generic_err_object_not_found", "message": f"Package [{pkg_lookup}] not found"},
            )

        if clean_cmd == "show-access-layer":
            layer_lookup = str(req.get("name") or req.get("uid") or "")
            for lyr in dom_files.get("show-access-layers", {}).get("access-layers", []):
                if lyr.get("name") == layer_lookup or lyr.get("uid") == layer_lookup:
                    return ApiCallResult(success=True, status_code=200, data=copy.deepcopy(lyr))
            return ApiCallResult(
                success=False,
                status_code=404,
                error_code="generic_err_object_not_found",
                error_message=f"Access layer [{layer_lookup}] not found",
                data={"code": "generic_err_object_not_found", "message": f"Access layer [{layer_lookup}] not found"},
            )

        if clean_cmd == "show-object":
            lookup_uid = str(req.get("uid") or req.get("name") or "")
            for file_val in dom_files.values():
                if not isinstance(file_val, dict):
                    continue
                items = file_val.get("objects")
                if isinstance(items, list):
                    for obj in items:
                        if isinstance(obj, dict) and (obj.get("uid") == lookup_uid or obj.get("name") == lookup_uid):
                            return ApiCallResult(
                                success=True,
                                status_code=200,
                                data={"object": copy.deepcopy(obj)},
                            )
                elif lookup_uid in file_val and isinstance(file_val[lookup_uid], dict):
                    return ApiCallResult(
                        success=True,
                        status_code=200,
                        data={"object": copy.deepcopy(file_val[lookup_uid])},
                    )
            return ApiCallResult(
                success=False,
                status_code=404,
                error_code="generic_err_object_not_found",
                error_message=f"Object [{lookup_uid}] not found",
                data={"code": "generic_err_object_not_found", "message": f"Object [{lookup_uid}] not found"},
            )

        if clean_cmd == "show-objects":
            req_type = str(req.get("type") or "object").strip()
            filter_raw = req.get("filter")
            filter_needle = str(filter_raw).strip().lower() if filter_raw is not None else ""
            ip_only = bool(req.get("ip-only", False))

            candidates: list[dict[str, Any]] = []
            seen_uids: set[str] = set()
            if req_type in _SHOW_OBJECTS_TYPE_TO_CMD:
                plural_payload = dom_files.get(_SHOW_OBJECTS_TYPE_TO_CMD[req_type], {})
                raw_items = plural_payload.get("objects", []) if isinstance(plural_payload, dict) else []
                for item in raw_items:
                    if not isinstance(item, dict):
                        continue
                    item_type = item.get("type")
                    if item_type is not None and str(item_type) != req_type:
                        continue
                    uid_key = str(item.get("uid") or "")
                    if uid_key and uid_key in seen_uids:
                        continue
                    if uid_key:
                        seen_uids.add(uid_key)
                    candidates.append(item)
            elif req_type == "object":
                for plural_cmd in _SHOW_OBJECTS_TYPE_TO_CMD.values():
                    plural_payload = dom_files.get(plural_cmd, {})
                    raw_items = plural_payload.get("objects", []) if isinstance(plural_payload, dict) else []
                    for item in raw_items:
                        if not isinstance(item, dict):
                            continue
                        uid_key = str(item.get("uid") or "")
                        if uid_key and uid_key in seen_uids:
                            continue
                        if uid_key:
                            seen_uids.add(uid_key)
                        candidates.append(item)
            else:
                for file_val in dom_files.values():
                    if not isinstance(file_val, dict):
                        continue
                    raw_items = file_val.get("objects", [])
                    if not isinstance(raw_items, list):
                        continue
                    for item in raw_items:
                        if not isinstance(item, dict) or str(item.get("type") or "") != req_type:
                            continue
                        uid_key = str(item.get("uid") or "")
                        if uid_key and uid_key in seen_uids:
                            continue
                        if uid_key:
                            seen_uids.add(uid_key)
                        candidates.append(item)

            matched = [
                item
                for item in candidates
                if _matches_show_objects_filter(item, filter_needle=filter_needle, ip_only=ip_only)
            ]
            return ApiCallResult(
                success=True,
                status_code=200,
                data=self._paginate_list(matched, req, collection_key="objects"),
            )

        # Singular object lookups (`show-host`, `show-network`, `show-group`, `show-package`, etc.)
        singular_to_plural = {
            "show-host": ("show-hosts", "objects"),
            "show-network": ("show-networks", "objects"),
            "show-address-range": ("show-address-ranges", "objects"),
            "show-group": ("show-groups", "objects"),
            "show-dns-domain": ("show-dns-domains", "objects"),
            "show-package": ("show-packages", "packages"),
            "show-service-tcp": ("show-services-tcp", "objects"),
            "show-service-udp": ("show-services-udp", "objects"),
            "show-service-icmp": ("show-services-icmp", "objects"),
            "show-service-group": ("show-service-groups", "objects"),
        }
        if clean_cmd in singular_to_plural:
            plural_cmd, col_key = singular_to_plural[clean_cmd]
            lookup_ref = str(req.get("uid") or req.get("name") or "")
            plural_payload = dom_files.get(plural_cmd, {})
            items_list = plural_payload.get(col_key, []) if isinstance(plural_payload, dict) else []
            for item in items_list:
                if isinstance(item, dict) and (item.get("uid") == lookup_ref or item.get("name") == lookup_ref):
                    return ApiCallResult(
                        success=True,
                        status_code=200,
                        data=_project_details_level(item, str(req.get("details-level", "standard"))),
                    )
            return ApiCallResult(
                success=False,
                status_code=404,
                error_code="generic_err_object_not_found",
                error_message=f"Requested object [{lookup_ref}] not found",
                data={"code": "generic_err_object_not_found", "message": f"Requested object [{lookup_ref}] not found"},
            )

        # Standard paginated listing commands (`show-gateways-and-servers`, `show-hosts`, `show-networks`, etc.)
        if clean_cmd in dom_files and isinstance(dom_files[clean_cmd], dict):
            file_payload = dom_files[clean_cmd]
            col_key = "objects"
            for candidate_key in ("objects", "packages", "access-layers", "nat-rules", "sessions"):
                if isinstance(file_payload.get(candidate_key), list):
                    col_key = candidate_key
                    break
            items = file_payload.get(col_key, [])
            return ApiCallResult(
                success=True,
                status_code=200,
                data=self._paginate_list(items, req, collection_key=col_key),
            )

        # Empty paginated response for optional plural object/service/layer types not populated in fixture
        if clean_cmd.startswith(
            ("show-services-", "show-groups-with-", "show-threat-", "show-https-")
        ) or clean_cmd in {
            "show-multicast-address-ranges",
            "show-security-zones",
            "show-dynamic-objects",
            "show-tags",
            "show-time-groups",
            "show-times",
            "show-wildcard",
            "show-wildcards",
            "show-gsn-handover-groups",
            "show-access-section",
            "show-nat-section",
        }:
            return ApiCallResult(
                success=True,
                status_code=200,
                data={"objects": [], "from": 0, "to": 0, "total": 0},
            )

        return ApiCallResult(
            success=False,
            status_code=400,
            error_code="generic_err_command_not_recognized",
            error_message=f"Unsupported command {clean_cmd!r} in FileReplayApiMock",
            data={"code": "generic_err_command_not_recognized", "message": f"Unsupported command {clean_cmd!r}"},
        )

    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        *,
        domain: str | None = None,
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        limit: int = DEFAULT_PAGE_LIMIT,
    ) -> ApiQueryResult:
        """Execute a continuity-verified paginated listing query via `paginate_objects`."""
        clean_cmd = command.strip().lstrip("/")
        dom_name = self._normalize_domain(domain)
        self.api_query_counts[(dom_name, clean_cmd)] += 1

        async def _call_page(page_payload: dict[str, Any]) -> ApiCallResult:
            return await self.api_call(
                mgmt_name,
                clean_cmd,
                page_payload,
                domain=domain,
                sid=sid,
                server_ip=server_ip,
            )

        return await paginate_objects(
            clean_cmd,
            _call_page,
            details_level=details_level,
            payload=payload,
            limit=limit,
        )

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        """Open an isolated mock session and return `(sid, server_ip)`."""
        _ = (mgmt_name, auth, session_name, session_description)
        self._sid_seq += 1
        dom_name = self._normalize_domain(domain)
        return f"dedicated-sid-{dom_name}-{self._sid_seq}", "127.0.0.1"

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> Awaitable[bool]:
        """Log out a mock session identifier."""
        _ = (mgmt_name, sid, server_ip)

        async def _noop() -> bool:
            return True

        return _noop()

    async def close(self, *, logout: bool | None = None) -> None:
        """Close the mock adapter."""
        _ = logout
        return None


__all__ = [
    "FileReplayApiMock",
    "FileReplayCliMock",
]
