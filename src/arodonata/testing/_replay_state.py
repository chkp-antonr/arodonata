"""Snapshot/restore, call-log assertions, and in-memory test mutation helpers for `FileReplayApiMock`."""

from __future__ import annotations

import copy
import json
from collections import Counter
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from ._emulator_models import ReplayStateSnapshot
from .dataset_generator import ALL_DOMAINS

if TYPE_CHECKING:
    from .replay_mock import FileReplayApiMock


def load_domain_files(mock: FileReplayApiMock, dom_name: str) -> dict[str, Any]:
    """Load all per-command JSON fixture files for `dom_name` from disk."""
    dom_dir = mock._dataset_dir / "domains" / dom_name
    dom_files: dict[str, Any] = {}
    if dom_dir.is_dir():
        for json_file in sorted(dom_dir.glob("*.json")):
            dom_files[json_file.stem] = json.loads(json_file.read_text(encoding="utf-8"))
    return dom_files


def initialize_dataset_state(mock: FileReplayApiMock) -> None:
    """Load MDS/domain JSON fixtures and index node UIDs and published session pointers."""
    mock._manifest = json.loads((mock._dataset_dir / "manifest.json").read_text(encoding="utf-8"))
    mock._show_domains = json.loads((mock._dataset_dir / "mds" / "show-domains.json").read_text(encoding="utf-8"))
    mock._show_global_domain = json.loads(
        (mock._dataset_dir / "mds" / "show-global-domain.json").read_text(encoding="utf-8")
    )
    mock._show_mdss = json.loads((mock._dataset_dir / "mds" / "show-mdss.json").read_text(encoding="utf-8"))
    mock._domain_data = {dom_name: load_domain_files(mock, dom_name) for dom_name in ALL_DOMAINS}

    mock._node_uid_to_name = {}
    for dom_files in mock._domain_data.values():
        gw_and_srv = dom_files.get("show-gateways-and-servers", {}).get("objects", [])
        for obj in gw_and_srv:
            if isinstance(obj, dict) and obj.get("uid") and obj.get("name"):
                mock._node_uid_to_name[str(obj["uid"])] = str(obj["name"])
                members = obj.get("cluster-member-names")
                if isinstance(members, list):
                    for m in members:
                        if isinstance(m, dict) and m.get("uid") and m.get("name"):
                            mock._node_uid_to_name[str(m["uid"])] = str(m["name"])

    ga_path = mock._dataset_dir / "mds" / "show-global-assignments.json"
    raw_ga = json.loads(ga_path.read_text(encoding="utf-8")) if ga_path.is_file() else {"objects": []}
    mock._show_global_assignments = list(raw_ga.get("objects", []))
    mock._initial_domain_data = {}
    mock._initial_global_assignments = copy.deepcopy(mock._show_global_assignments)
    mock._dirty_domains = set()
    mock._domain_generation = Counter()

    mock._tasks = {}
    mock._sid_bindings = {}
    mock._work_sessions = {}
    mock._published_session_by_domain = {}
    for dom_n, d_files in mock._domain_data.items():
        last_pub = d_files.get("show-last-published-session", {})
        if isinstance(last_pub, dict) and last_pub.get("uid"):
            mock._published_session_by_domain[dom_n] = str(last_pub["uid"])
    mock._published_deltas = {}


def capture_snapshot(mock: FileReplayApiMock) -> ReplayStateSnapshot:
    """Capture an in-memory snapshot of modified domains, sessions, locks, tasks, and CLI overrides."""
    domain_copies = {
        dom_name: copy.deepcopy(mock._domain_data[dom_name])
        for dom_name in mock._dirty_domains
        if dom_name in mock._domain_data
    }
    return ReplayStateSnapshot(
        domain_copies=domain_copies,
        dirty_domains=set(domain_copies.keys()),
        work_sessions=copy.deepcopy(mock._work_sessions),
        sid_bindings=copy.deepcopy(mock._sid_bindings),
        published_session_by_domain=dict(mock._published_session_by_domain),
        published_deltas=copy.deepcopy(mock._published_deltas),
        tasks=copy.deepcopy(mock._tasks),
        show_global_assignments=copy.deepcopy(mock._show_global_assignments),
        counters={
            "sid_seq": mock._sid_seq,
            "task_seq": mock._task_seq,
            "session_seq": mock._session_seq,
            "uid_seq": mock._uid_seq,
            "ts_seq": mock._ts_seq,
        },
        cli_overrides=copy.deepcopy(mock._cli_mock._cli_overrides),
        fail_ssh_nodes=set(mock._cli_mock.fail_ssh_nodes),
        call_log=copy.deepcopy(mock.call_log),
        domain_generations=dict(mock._domain_generation),
        allow_one_time_script=mock.allow_one_time_script,
        allow_repository_script=mock.allow_repository_script,
        manage_repository_scripts=mock.manage_repository_scripts,
        encode_repository_script_body_base64=mock.encode_repository_script_body_base64,
    )


def apply_snapshot(mock: FileReplayApiMock, snapshot: ReplayStateSnapshot) -> None:
    """Restore emulator state rapidly from a previously captured `ReplayStateSnapshot`."""
    for dom_name in snapshot.dirty_domains | mock._dirty_domains:
        if dom_name in snapshot.domain_copies:
            mock._domain_data[dom_name] = copy.deepcopy(snapshot.domain_copies[dom_name])
        elif dom_name in mock._domain_data:
            mock._domain_data[dom_name] = copy.deepcopy(mock._get_clean_domain_baseline(dom_name))

    mock._dirty_domains = set(snapshot.dirty_domains)
    mock._domain_generation = Counter(snapshot.domain_generations)
    mock._work_sessions = copy.deepcopy(snapshot.work_sessions)
    mock._sid_bindings = copy.deepcopy(snapshot.sid_bindings)
    mock._published_session_by_domain = dict(snapshot.published_session_by_domain)
    mock._published_deltas = copy.deepcopy(snapshot.published_deltas)
    mock._tasks = copy.deepcopy(snapshot.tasks)
    mock._show_global_assignments = copy.deepcopy(snapshot.show_global_assignments)
    mock.allow_one_time_script = bool(snapshot.allow_one_time_script)
    mock.allow_repository_script = bool(snapshot.allow_repository_script)
    mock.manage_repository_scripts = str(snapshot.manage_repository_scripts)
    mock.encode_repository_script_body_base64 = bool(getattr(snapshot, "encode_repository_script_body_base64", False))

    mock._sid_seq = snapshot.counters.get("sid_seq", mock._sid_seq)
    mock._task_seq = snapshot.counters.get("task_seq", mock._task_seq)
    mock._session_seq = snapshot.counters.get("session_seq", mock._session_seq)
    mock._uid_seq = snapshot.counters.get("uid_seq", mock._uid_seq)
    mock._ts_seq = snapshot.counters.get("ts_seq", mock._ts_seq)

    mock._cli_mock._cli_overrides = copy.deepcopy(snapshot.cli_overrides)
    mock._cli_mock.fail_ssh_nodes = set(snapshot.fail_ssh_nodes)
    mock.call_log = copy.deepcopy(snapshot.call_log)
    mock.api_call_counts.clear()
    mock.command_counts.clear()
    mock.api_query_counts.clear()
    mock.gateway_detail_queries.clear()
    for entry in mock.call_log:
        if not isinstance(entry, dict):
            continue
        cmd = str(entry.get("command") or "")
        dom = str(entry.get("domain") or "")
        if cmd:
            mock.api_call_counts[(dom, cmd)] += 1
            mock.command_counts[cmd] += 1


def reset_mock_state(mock: FileReplayApiMock) -> None:
    """Reset all in-memory domain data, sessions, locks, tasks, counters, and CLI overrides to baseline."""
    for dom_name in list(mock._dirty_domains):
        if dom_name in mock._domain_data:
            mock._domain_data[dom_name] = copy.deepcopy(mock._get_clean_domain_baseline(dom_name))
    mock._dirty_domains.clear()
    mock._domain_generation.clear()
    mock._show_global_assignments = copy.deepcopy(mock._initial_global_assignments)
    mock._work_sessions.clear()
    mock._sid_bindings.clear()
    mock._published_deltas.clear()
    mock._tasks.clear()
    mock._published_session_by_domain.clear()
    for dom_n, d_files in mock._domain_data.items():
        last_pub = d_files.get("show-last-published-session", {})
        if isinstance(last_pub, dict) and last_pub.get("uid"):
            mock._published_session_by_domain[dom_n] = str(last_pub["uid"])
    mock._sid_seq = 0
    mock._task_seq = 0
    mock._session_seq = 0
    mock._uid_seq = 0
    mock._ts_seq = 1794300000000
    mock._cli_mock._cli_overrides.clear()
    mock._cli_mock.fail_ssh_nodes = set(mock._cli_mock._initial_fail_ssh_nodes)
    mock.allow_one_time_script = bool(getattr(mock, "_initial_allow_one_time_script", True))
    mock.allow_repository_script = bool(getattr(mock, "_initial_allow_repository_script", True))
    mock.manage_repository_scripts = str(getattr(mock, "_initial_manage_repository_scripts", "write"))
    mock.encode_repository_script_body_base64 = bool(
        getattr(mock, "_initial_encode_repository_script_body_base64", False)
    )
    mock.reset_counters()


def filter_calls(
    mock: FileReplayApiMock,
    *,
    domain: str | None = None,
    command: str | None = None,
    mutating_only: bool = False,
) -> list[dict[str, Any]]:
    """Return recorded `call_log` entries matching optional `domain`, `command`, and `mutating_only` filters."""
    norm_dom = mock._normalize_domain(domain) if domain is not None else None
    out: list[dict[str, Any]] = []
    for entry in mock.call_log:
        if norm_dom is not None and entry.get("domain") != norm_dom:
            continue
        if command is not None and entry.get("command") != command:
            continue
        if mutating_only and not entry.get("is_mutating", entry.get("mutating")):
            continue
        out.append(entry)
    return out


def assert_no_global_mutations(mock: FileReplayApiMock) -> None:
    """Fail if any mutating API command targeted the `Global` domain."""
    global_writes = [
        f"{e.get('command')} ({e.get('payload_summary')})"
        for e in mock.call_log
        if e.get("domain") == "Global" and e.get("is_mutating", e.get("mutating"))
    ]
    if global_writes:
        raise AssertionError(f"Unexpected mutating commands in Global domain: {', '.join(global_writes)}")


def assert_no_full_object_scans(
    mock: FileReplayApiMock,
    commands: Iterable[str] = ("show-hosts", "show-networks", "show-address-ranges", "show-groups"),
) -> None:
    """Fail if any command in `commands` was invoked (e.g., to guard against uncached full-table scans)."""
    target_cmds = set(commands)
    hits = [f"{e.get('domain')}:{e.get('command')}" for e in mock.call_log if e.get("command") in target_cmds]
    if hits:
        raise AssertionError(f"Unexpected full-object scan commands invoked: {', '.join(hits)}")


def assert_command_called(
    mock: FileReplayApiMock,
    command: str,
    *,
    domain: str | None = None,
    times: int | None = None,
) -> None:
    """Assert that `command` was called (optionally within `domain` and exact `times` count)."""
    matches = filter_calls(mock, domain=domain, command=command)
    if times is None:
        if not matches:
            scope = f" in domain {domain!r}" if domain else ""
            raise AssertionError(f"Expected command {command!r}{scope} to be called at least once, got 0")
    elif len(matches) != times:
        scope = f" in domain {domain!r}" if domain else ""
        raise AssertionError(f"Expected command {command!r}{scope} {times} time(s), got {len(matches)}")


def assert_command_not_called(mock: FileReplayApiMock, command: str, *, domain: str | None = None) -> None:
    """Assert that `command` was never called (optionally restricted to `domain`)."""
    matches = filter_calls(mock, domain=domain, command=command)
    if matches:
        scope = f" in domain {domain!r}" if domain else ""
        raise AssertionError(f"Expected command {command!r}{scope} not to be called, got {len(matches)}")


def update_gateway_interfaces(
    mock: FileReplayApiMock,
    domain: str,
    gateway_name_or_uid: str,
    interfaces: list[dict[str, Any]],
) -> None:
    """Update the raw `interfaces` list for a single gateway across summary and detail payloads in memory."""
    mock._mark_domain_mutated(domain)
    dom_files = mock._domain_data[domain]
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


def bump_published_session(
    mock: FileReplayApiMock,
    domain: str,
    *,
    new_session_uid: str,
    new_iso_time: str = "2026-11-09T12:00:00Z",
    new_posix_time: int = 1794225600000,
) -> None:
    """Simulate a new `publish` in `domain` by updating `show-last-published-session` and `show-sessions`."""
    mock._mark_domain_mutated(domain)
    mock._published_session_by_domain[domain] = new_session_uid
    dom_files = mock._domain_data[domain]
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
