"""File-backed `GatewayCliPort` replay adapter for gateway SSH and VSX route collection."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

from arodonata.core.models.topology import GatewayCliResult, GatewayCliTarget
from arodonata.core.ports import GatewayCliPort

from .dataset_generator import DEFAULT_DATASET_DIR, ensure_enterprise_raw_dataset

VSID_SCRIPT_RE = re.compile(r"(?:^|\n)vsid=(\d+)\b")
VS_NAME_SCRIPT_RE = re.compile(r"(?:^|\n)vs_name=([^\n]+)")


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

    def list_virtual_systems(self, node_name: str) -> list[tuple[int, str]]:
        """Return list of `(vsid, vs_name)` for all non-switch Virtual Systems on `node_name`."""
        stat_path = self._cli_dir / f"{node_name}__vsx_stat_l.txt"
        results: list[tuple[int, str]] = []
        seen_vsids: set[int] = set()

        if stat_path.is_file():
            current_id: int | None = None
            current_name: str | None = None
            current_type: str | None = None

            def _flush() -> None:
                nonlocal current_id, current_name, current_type
                if (
                    current_id is not None
                    and current_id > 0
                    and current_id not in seen_vsids
                    and (not current_type or "switch" not in current_type.lower())
                ):
                    eff_name = current_name or f"VS_{current_id}"
                    results.append((current_id, eff_name))
                    seen_vsids.add(current_id)
                current_id = None
                current_name = None
                current_type = None

            for raw_line in stat_path.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if line.startswith("VSID:"):
                    _flush()
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            current_id = int(parts[1])
                        except ValueError:
                            current_id = None
                elif line.startswith("Name:"):
                    parts = line.split(None, 1)
                    current_name = parts[1].strip() if len(parts) >= 2 else None
                elif line.startswith("Type:"):
                    parts = line.split(None, 1)
                    current_type = parts[1].strip() if len(parts) >= 2 else None
            _flush()

        for n_name, v_id in self._cli_overrides:
            if n_name == node_name and v_id > 0 and v_id not in seen_vsids:
                results.append((v_id, f"VS_{v_id}"))
                seen_vsids.add(v_id)

        results.sort(key=lambda item: item[0])
        return results

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

        resolved_vsid = 0
        prepend_resolved_marker = False
        m_vsid = VSID_SCRIPT_RE.search(command)
        m_vs_name = VS_NAME_SCRIPT_RE.search(command)

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
