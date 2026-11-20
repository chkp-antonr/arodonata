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

import copy
from collections import Counter
from collections.abc import Awaitable, Iterable, Mapping
from pathlib import Path
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from arodonata.adapters.checkpoint.pager import DEFAULT_PAGE_LIMIT, paginate_objects
from arodonata.core.context import AuthContext
from arodonata.core.errors import REDACTED_PLACEHOLDER, SessionError
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.ports import ApiPort
from arodonata.core.telemetry import span_attrs, traced
from arodonata.testing._emulator_models import (
    PublishedDelta,
    ReplayStateSnapshot,
    SidBinding,
    WorkSession,
    format_domain_meta,
    is_mutating_command,
    sanitize_call_payload,
    summarize_payload,
)
from arodonata.testing._emulator_projection import paginate_items, project_replay_details_level
from arodonata.testing._replay_cli import FileReplayCliMock
from arodonata.testing._replay_dispatch import apply_domain_mutation, dispatch_api_call
from arodonata.testing._replay_state import (
    apply_snapshot,
    assert_command_called,
    assert_command_not_called,
    assert_no_full_object_scans,
    assert_no_global_mutations,
    bump_published_session,
    capture_snapshot,
    filter_calls,
    initialize_dataset_state,
    load_domain_files,
    reset_mock_state,
    update_gateway_interfaces,
)
from arodonata.testing.dataset_generator import (
    DEFAULT_DATASET_DIR,
    ensure_enterprise_raw_dataset,
)


class FileReplayApiMock(ApiPort):
    """File-backed `ApiPort` replay adapter emulating Check Point MDSM and CMA domains from disk fixtures."""

    _manifest: dict[str, Any]
    _show_domains: dict[str, Any]
    _show_global_domain: dict[str, Any]
    _show_mdss: dict[str, Any]
    _domain_data: dict[str, dict[str, Any]]
    _node_uid_to_name: dict[str, str]
    _show_global_assignments: list[dict[str, Any]]
    _initial_domain_data: dict[str, dict[str, Any]]
    _initial_global_assignments: list[dict[str, Any]]
    _dirty_domains: set[str]
    _domain_generation: Counter[str]
    _tasks: dict[str, dict[str, Any]]
    _sid_bindings: dict[str, SidBinding]
    _work_sessions: dict[str, WorkSession]
    _published_session_by_domain: dict[str, str]
    _published_deltas: dict[str, list[PublishedDelta]]

    def __init__(
        self,
        dataset_dir: Path | str = DEFAULT_DATASET_DIR,
        *,
        cli_mock: FileReplayCliMock | None = None,
        allow_one_time_script: bool = True,
        allow_repository_script: bool = True,
        manage_repository_scripts: str = "write",
        encode_repository_script_body_base64: bool = False,
    ) -> None:
        self._dataset_dir = ensure_enterprise_raw_dataset(dataset_dir)
        self._cli_mock = cli_mock or FileReplayCliMock(self._dataset_dir)
        self.allow_one_time_script: bool = bool(allow_one_time_script)
        self.allow_repository_script: bool = bool(allow_repository_script)
        self.manage_repository_scripts: str = str(manage_repository_scripts)
        self.encode_repository_script_body_base64: bool = bool(encode_repository_script_body_base64)

        initialize_dataset_state(self)

        self._sid_seq = 0
        self._task_seq = 0
        self._session_seq = 0
        self._uid_seq = 0
        self._ts_seq = 1794300000000

        # Call counters and call logs for test assertions
        self.api_call_counts: Counter[tuple[str, str]] = Counter()
        self.api_query_counts: Counter[tuple[str, str]] = Counter()
        self.command_counts: Counter[str] = Counter()
        self.gateway_detail_queries: list[tuple[str, str, str]] = []
        self.call_log: list[dict[str, Any]] = []

    def __repr__(self) -> str:
        return (
            f"FileReplayApiMock(dataset_dir={self._dataset_dir!s}, "
            f"domains={len(self._domain_data)}, active_sessions={sum(1 for b in self._sid_bindings.values() if b.active)})"
        )

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
    # State Snapshots, Reset, Session Inspection & Call-Log Assertions
    # ------------------------------------------------------------------

    def get_active_sid_binding(self, sid: str | None) -> SidBinding | None:
        """Return the active `SidBinding` for `sid`, or `None` if unknown or logged out."""
        if not sid:
            return None
        binding = self._sid_bindings.get(sid)
        if binding is None or not binding.active:
            return None
        return binding

    def _load_domain_files(self, dom_name: str) -> dict[str, Any]:
        return load_domain_files(self, dom_name)

    def _get_clean_domain_baseline(self, dom_name: str) -> dict[str, Any]:
        baseline = self._initial_domain_data.get(dom_name)
        if baseline is None:
            baseline = self._load_domain_files(dom_name)
            self._initial_domain_data[dom_name] = baseline
        return baseline

    def _mark_domain_mutated(self, dom_name: str) -> None:
        self._dirty_domains.add(dom_name)
        self._domain_generation[dom_name] += 1

    def snapshot_state(self) -> ReplayStateSnapshot:
        """Capture an in-memory snapshot of modified domains, sessions, locks, tasks, and CLI overrides."""
        return capture_snapshot(self)

    def restore_state(self, snapshot: ReplayStateSnapshot) -> None:
        """Restore emulator state rapidly from a previously captured `ReplayStateSnapshot`."""
        apply_snapshot(self, snapshot)

    def reset(self) -> None:
        """Reset all in-memory domain data, sessions, locks, tasks, counters, and CLI overrides to baseline."""
        reset_mock_state(self)

    def get_calls(
        self,
        *,
        domain: str | None = None,
        command: str | None = None,
        mutating_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Return recorded `call_log` entries matching optional `domain`, `command`, and `mutating_only` filters."""
        return filter_calls(self, domain=domain, command=command, mutating_only=mutating_only)

    def assert_no_global_mutations(self) -> None:
        """Fail if any mutating API command targeted the `Global` domain."""
        assert_no_global_mutations(self)

    def assert_no_full_object_scans(
        self,
        commands: Iterable[str] = ("show-hosts", "show-networks", "show-address-ranges", "show-groups"),
    ) -> None:
        """Fail if any command in `commands` was invoked (e.g., to guard against uncached full-table scans)."""
        assert_no_full_object_scans(self, commands)

    def assert_command_called(
        self,
        command: str,
        *,
        domain: str | None = None,
        times: int | None = None,
    ) -> None:
        """Assert that `command` was called (optionally within `domain` and exact `times` count)."""
        assert_command_called(self, command, domain=domain, times=times)

    def assert_command_not_called(self, command: str, *, domain: str | None = None) -> None:
        """Assert that `command` was never called (optionally restricted to `domain`)."""
        assert_command_not_called(self, command, domain=domain)

    # ------------------------------------------------------------------
    # Internal Session, Timestamp & Overlay Helpers
    # ------------------------------------------------------------------

    def _next_timestamp_ms(self) -> int:
        self._ts_seq += 1000
        return self._ts_seq

    def _allocate_uid(self, prefix: str) -> str:
        self._uid_seq += 1
        clean = prefix.replace("-", "_")
        return f"uid-{clean}-{self._uid_seq:06d}"

    def _next_task_id(self) -> str:
        self._task_seq += 1
        return f"12345678-9999-4999-8999-{self._task_seq:012d}"

    def _allocate_repo_script_uid(self) -> str:
        self._uid_seq += 1
        return f"00000000-7777-4777-8777-{self._uid_seq:012d}"

    def _known_sids(self, extra_sid: str | None = None) -> set[str]:
        sids = set(self._sid_bindings.keys())
        if extra_sid:
            sids.add(extra_sid)
        return sids

    def _create_work_session(
        self,
        domain: str,
        *,
        user_name: str = "admin",
        name: str = "",
        description: str = "",
        application: str = "WEB_API",
        read_only: bool = False,
    ) -> WorkSession:
        self._session_seq += 1
        ts_ms = self._next_timestamp_ms()
        dom_meta = format_domain_meta(domain)
        ws = WorkSession(
            uid=f"sess-{domain.lower().replace(' ', '-')}-{self._session_seq:06d}",
            domain=domain,
            user_name=user_name,
            name=name,
            description=description,
            application=application,
            read_only=read_only,
            state="open",
            base_published_uid=self._published_session_by_domain.get(domain, ""),
            created_time_posix=ts_ms,
            last_modify_posix=ts_ms,
            base_domain_gen=self._domain_generation[domain],
            domain_meta=dom_meta,
        )
        self._work_sessions[ws.uid] = ws
        return ws

    def _effective_domain_files(self, dom_name: str, binding: SidBinding | None) -> dict[str, Any] | None:
        if binding is not None and binding.active and binding.domain == dom_name:
            ws = self._work_sessions.get(binding.session_uid)
            if ws is not None and ws.state == "open" and ws.overlay_data is not None:
                return ws.overlay_data
        return self._domain_data.get(dom_name)

    def _ensure_overlay(self, ws: WorkSession) -> dict[str, Any]:
        if ws.overlay_data is None:
            published = self._domain_data.get(ws.domain, {})
            ws.base_snapshot = copy.deepcopy(published)
            ws.overlay_data = copy.deepcopy(published)
            ws.base_published_uid = self._published_session_by_domain.get(ws.domain, "")
            ws.base_domain_gen = self._domain_generation[ws.domain]
        return ws.overlay_data

    def _effective_all_domains(self, binding: SidBinding | None) -> dict[str, Mapping[str, Any]]:
        out: dict[str, Mapping[str, Any]] = {}
        for dom_n in self._domain_data:
            eff = self._effective_domain_files(dom_n, binding)
            if eff is not None:
                out[dom_n] = eff
        return out

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
        update_gateway_interfaces(self, domain, gateway_name_or_uid, interfaces)

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
        bump_published_session(
            self,
            domain,
            new_session_uid=new_session_uid,
            new_iso_time=new_iso_time,
            new_posix_time=new_posix_time,
        )

    # ------------------------------------------------------------------
    # Internal Command Dispatch
    # ------------------------------------------------------------------

    def _normalize_domain(self, domain: str | None) -> str:
        if not domain or not domain.strip() or domain.strip() == "System Data":
            return "System Data"
        clean = domain.strip()
        if clean in self._domain_data:
            return clean
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
        return paginate_items(
            items,
            payload,
            collection_key=collection_key,
            default_limit=DEFAULT_PAGE_LIMIT,
            default_details_level="standard",
            min_limit=0,
            projector=project_replay_details_level,
        )

    def _apply_domain_mutation(
        self,
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
        return apply_domain_mutation(
            self,
            clean_cmd,
            req,
            dom_name=dom_name,
            target_files=target_files,
            global_files=global_files,
            all_domains=all_domains,
            user_name=user_name,
            locked_uids_out=locked_uids_out,
            override_now_ms=override_now_ms,
        )

    def _dispatch_api_call(
        self,
        mgmt_name: str,
        clean_cmd: str,
        req: dict[str, Any],
        *,
        dom_name: str,
        sid: str | None,
        binding: SidBinding | None,
        wait_for_task: bool,
    ) -> ApiCallResult:
        return dispatch_api_call(
            self,
            mgmt_name,
            clean_cmd,
            req,
            dom_name=dom_name,
            sid=sid,
            binding=binding,
            wait_for_task=wait_for_task,
        )

    @traced
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
        """Execute a single Check Point Management API command with stateful sessions, overlays, and OTEL spans."""
        _ = (server_ip, timeout)
        clean_cmd = command.strip().lstrip("/")
        if clean_cmd.startswith("web_api/"):
            clean_cmd = clean_cmd.removeprefix("web_api/")
        req = dict(payload) if payload else {}
        binding = self._sid_bindings.get(sid) if sid is not None else None

        if clean_cmd == "login":
            dom_name = self._normalize_domain(req.get("domain") or domain)
        elif domain is not None:
            dom_name = self._normalize_domain(domain)
        elif req.get("domain") is not None:
            dom_name = self._normalize_domain(req.get("domain"))
        elif binding is not None:
            dom_name = binding.domain
        else:
            dom_name = self._normalize_domain(None)

        sid_ref: str | None = binding.sid_ref if binding is not None else ("invalid-sid" if sid is not None else None)
        known_sids = self._known_sids(sid)

        is_mut = is_mutating_command(clean_cmd)
        self.api_call_counts[(dom_name, clean_cmd)] += 1
        self.command_counts[clean_cmd] += 1
        log_entry: dict[str, Any] = {
            "mgmt_name": mgmt_name,
            "domain": dom_name,
            "command": clean_cmd,
            "is_mutating": is_mut,
            "mutating": is_mut,
            "sid_ref": sid_ref,
            "session_uid": binding.session_uid if binding is not None else None,
            "read_only_session": binding.read_only if binding is not None else None,
            "payload": sanitize_call_payload(req, known_sids=known_sids),
            "payload_summary": summarize_payload(clean_cmd, req, known_sids=known_sids),
            "status_code": 200,
            "success": True,
            "error_code": None,
        }
        self.call_log.append(log_entry)

        span_attrs(
            mgmt_name=mgmt_name,
            domain=dom_name,
            command=clean_cmd,
            sid_ref=sid_ref or "",
            session_uid=binding.session_uid if binding is not None else "",
            mutating=is_mut,
        )

        res = self._dispatch_api_call(
            mgmt_name,
            clean_cmd,
            req,
            dom_name=dom_name,
            sid=sid,
            binding=binding,
            wait_for_task=wait_for_task,
        )

        log_entry["status_code"] = res.status_code
        log_entry["success"] = res.success
        log_entry["error_code"] = res.error_code
        if clean_cmd == "login" and res.success and isinstance(res.data, dict):
            new_sid = str(res.data.get("sid") or "")
            new_binding = self._sid_bindings.get(new_sid)
            if new_binding is not None:
                log_entry["sid_ref"] = new_binding.sid_ref
                log_entry["session_uid"] = new_binding.session_uid
                log_entry["read_only_session"] = new_binding.read_only
                span_attrs(sid_ref=new_binding.sid_ref, session_uid=new_binding.session_uid)

        span_attrs(status_code=res.status_code, success=res.success, error_code=res.error_code or "")
        if not res.success:
            span = trace.get_current_span()
            span.set_status(Status(StatusCode.ERROR, res.error_code or "api_error"))
        return res

    @traced
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
        binding = self._sid_bindings.get(sid) if sid is not None else None
        dom_name = self._normalize_domain(domain if domain is not None else (binding.domain if binding else None))
        self.api_query_counts[(dom_name, clean_cmd)] += 1
        span_attrs(
            mgmt_name=mgmt_name,
            domain=dom_name,
            command=clean_cmd,
            details_level=details_level,
            limit=limit,
        )

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

    @traced
    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        """Open a registered stateful mock session and return `(sid, server_ip)`."""
        dom_name = self._normalize_domain(domain)
        user_name = "admin"
        if auth is not None and getattr(auth, "username", None):
            user_name = str(auth.username)
        login_payload: dict[str, Any] = {"domain": dom_name, "user": user_name}
        if session_name:
            login_payload["session-name"] = session_name
        if session_description:
            login_payload["session-description"] = session_description
        if domain == "Global":
            login_payload["domain"] = "Global"
        res = await self.api_call(mgmt_name, "login", login_payload, domain=dom_name)
        new_sid = str(res.data.get("sid") or "") if isinstance(res.data, dict) else ""
        if not res.success or not new_sid:
            err_detail = res.error_message or res.error_code or f"HTTP {res.status_code}"
            raise SessionError(
                f"Failed to create dedicated session for domain {dom_name!r}: {err_detail}",
                known_sids=[new_sid] if new_sid else None,
            )
        span_attrs(mgmt_name=mgmt_name, domain=dom_name, sid_ref=REDACTED_PLACEHOLDER)
        return new_sid, "127.0.0.1"

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> Awaitable[bool]:
        """Log out a registered mock session identifier and clean up uncommitted work."""
        _ = server_ip

        async def _do_logout() -> bool:
            binding = self.get_active_sid_binding(sid)
            if binding is None:
                return False
            res = await self.api_call(mgmt_name, "logout", {}, domain=binding.domain, sid=sid)
            return res.success

        return _do_logout()

    async def close(self, *, logout: bool | None = None) -> None:
        """Close the mock adapter, optionally logging out all active sessions."""
        if logout:
            for sid in [s for s, b in self._sid_bindings.items() if b.active]:
                await self.logout_sid("mds", sid)
        return None


__all__ = [
    "FileReplayApiMock",
    "FileReplayCliMock",
    "ReplayStateSnapshot",
    "ensure_enterprise_raw_dataset",
]
