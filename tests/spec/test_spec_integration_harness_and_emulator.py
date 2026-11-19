"""Specification acceptance tests for `integration-testing-and-examples` (`SCN-ITEST-*`)."""

from __future__ import annotations

import inspect
import json
import os
import stat
import subprocess
import tomllib
from pathlib import Path
from typing import Any

import pytest

from arodonata.core.models.common import ApiCallResult
from arodonata.cpcrud.rule_identity import NAT_ANY_OBJECT_UID
from arodonata.testing import FileReplayApiMock
from tests.integration import conftest as int_conftest
from tests.integration.cp_revision import (
    REVERT_TIMEOUT_SECONDS,
    restore_to_baseline,
    snapshot_baseline,
    write_baseline_file,
)
from tests.integration.lab_env import load_lab_env
from tests.integration.lab_ready import LabNotReady, answered_by_api, wait_until_ready
from tests.integration.run_lock import IntegrationRunLock, IntegrationRunLocked

REPO_ROOT = Path(__file__).resolve().parents[2]


def _make_stub_pytest_runner_workspace(tmp_path: Path, *, fail_marker: str | None = None) -> tuple[Path, Path, Path]:
    """Create an isolated `tmp_path` sandbox with `pytest.sh` and a stub `uv` binary."""
    src_script = REPO_ROOT / "pytest.sh"
    dst_script = tmp_path / "pytest.sh"
    dst_script.write_text(src_script.read_text(encoding="utf-8"), encoding="utf-8")
    dst_script.chmod(dst_script.stat().st_mode | stat.S_IXUSR)

    for sub in ("tests/unit", *(f"tests/integration/b{i}" for i in range(1, 8))):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)

    log_file = tmp_path / "uv_calls.log"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    uv_stub = bin_dir / "uv"
    fail_clause = f'if [[ " $* " == *" {fail_marker} "* ]]; then exit 1; fi\n' if fail_marker else ""
    uv_stub.write_text(
        f'#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "{log_file}"\n{fail_clause}exit 0\n',
        encoding="utf-8",
    )
    uv_stub.chmod(0o755)
    return dst_script, bin_dir, log_file


# ==============================================================================
# Runner, Auto-Markers, Env Loader, Lock, Readiness, and Revision Baseline
# ==============================================================================


@pytest.mark.spec("SCN-ITEST-001-1")
def test_default_pytest_config_and_unit_runner_exclude_integration(tmp_path: Path) -> None:
    """SCN-ITEST-001-1: `pyproject.toml` excludes integration tests and `./pytest.sh [unit]` targets fast unit runs."""
    pyproject_data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    addopts = list(pyproject_data["tool"]["pytest"]["ini_options"]["addopts"])
    assert "-v" in addopts
    assert "-m" in addopts and "not integration" in addopts

    script_path, bin_dir, log_file = _make_stub_pytest_runner_workspace(tmp_path)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ.get('PATH', '')}")

    r_default = subprocess.run([str(script_path)], capture_output=True, text=True, env=env, check=False)
    r_unit = subprocess.run(
        [str(script_path), "unit", "-k", "smoke"], capture_output=True, text=True, env=env, check=False
    )
    assert r_default.returncode == 0
    assert r_unit.returncode == 0
    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "run pytest -v tests/unit"
    assert lines[1] == "run pytest -v tests/unit -k smoke"


@pytest.mark.spec("SCN-ITEST-001-2")
def test_single_integration_bucket_runner_passes_short_tb_and_info_cli_logs(tmp_path: Path) -> None:
    """SCN-ITEST-001-2: `./pytest.sh int-<N>` passes bucket filter, `--tb=short`, `--durations=15`, and INFO logs."""
    script_path, bin_dir, log_file = _make_stub_pytest_runner_workspace(tmp_path)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ.get('PATH', '')}")

    res = subprocess.run(
        [str(script_path), "int-2", "-k", "login"], capture_output=True, text=True, env=env, check=False
    )
    assert res.returncode == 0
    call = log_file.read_text(encoding="utf-8").strip()
    for token in (
        "run pytest",
        "-v",
        "-o log_cli=true",
        "--log-cli-level=INFO",
        "--durations=15",
        "--tb=short",
        "tests/integration/b2",
        "-m bucket_2",
        "-k login",
    ):
        assert token in call


@pytest.mark.spec("SCN-ITEST-001-3")
def test_int_full_runner_runs_all_buckets_sequentially_and_exits_nonzero_on_failure(tmp_path: Path) -> None:
    """SCN-ITEST-001-3: `./pytest.sh int-full` executes b1..b7 in separate sessions and exits non-zero if any fails."""
    script_path, bin_dir, log_file = _make_stub_pytest_runner_workspace(tmp_path, fail_marker="bucket_3")
    env = dict(
        os.environ,
        PATH=f"{bin_dir}:{os.environ.get('PATH', '')}",
        BUCKET_PAUSE_SECONDS="0",
    )

    res = subprocess.run([str(script_path), "int-full"], capture_output=True, text=True, env=env, check=False)
    assert res.returncode == 1
    assert "FAILED buckets: b3" in res.stdout

    calls = log_file.read_text(encoding="utf-8").splitlines()
    assert len(calls) == 7
    for idx in range(1, 8):
        assert f"tests/integration/b{idx}" in calls[idx - 1]
        assert f"-m bucket_{idx}" in calls[idx - 1]


@pytest.mark.spec("SCN-ITEST-001-4")
def test_unknown_integration_target_exits_2_before_pytest_collection(tmp_path: Path) -> None:
    """SCN-ITEST-001-4: `./pytest.sh int-unknown` exits with code 2 and never invokes pytest."""
    script_path, bin_dir, log_file = _make_stub_pytest_runner_workspace(tmp_path)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ.get('PATH', '')}")

    res = subprocess.run([str(script_path), "int-unknown"], capture_output=True, text=True, env=env, check=False)
    assert res.returncode == 2
    assert "Valid: unit | int-1 .. int-7 | int-full" in res.stderr
    assert not log_file.exists()


@pytest.mark.spec("SCN-ITEST-002-1")
def test_integration_collection_hook_attaches_bucket_markers_and_sorts_ascending(tmp_path: Path) -> None:
    """SCN-ITEST-002-1: Collection hook attaches `integration` + `bucket_<N>` markers and sorts by bucket."""

    class _FakeItem:
        def __init__(self, rel_path: str) -> None:
            self.fspath = str(tmp_path / rel_path)
            self.markers: list[str] = []

        def add_marker(self, marker: Any) -> None:
            self.markers.append(marker.name)

    unit_item = _FakeItem("tests/unit/test_fast.py")
    b5_item = _FakeItem("tests/integration/b5/test_reports.py")
    b1_item = _FakeItem("tests/integration/b1/test_auth.py")
    items: list[Any] = [b5_item, unit_item, b1_item]

    int_conftest.pytest_collection_modifyitems(items)
    assert items == [unit_item, b1_item, b5_item]
    assert unit_item.markers == []
    assert b1_item.markers == ["integration", "bucket_1"]
    assert b5_item.markers == ["integration", "bucket_5"]


@pytest.mark.spec("SCN-ITEST-003-1")
def test_load_lab_env_loads_test_then_secrets_without_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-ITEST-003-1: `load_lab_env()` loads `.env.test` (`override=False`) then `.env.secrets` (`override=True`)."""
    (tmp_path / ".env.test").write_text(
        "CALLER_PINNED=from_test\nSHARED_KEY=from_test\nTEST_DEFAULT=yes\n",
        encoding="utf-8",
    )
    (tmp_path / ".env.secrets").write_text("SHARED_KEY=from_secrets\n", encoding="utf-8")

    monkeypatch.delenv("ARODONATA_LAB", raising=False)
    monkeypatch.setenv("CALLER_PINNED", "from_caller")
    monkeypatch.delenv("SHARED_KEY", raising=False)
    monkeypatch.delenv("TEST_DEFAULT", raising=False)

    active = load_lab_env(tmp_path)
    assert active is None
    assert os.environ["CALLER_PINNED"] == "from_caller"
    assert os.environ["SHARED_KEY"] == "from_secrets"
    assert os.environ["TEST_DEFAULT"] == "yes"


@pytest.mark.spec("SCN-ITEST-004-1")
def test_concurrent_integration_run_lock_raises_locked_with_pid_and_exit_3(tmp_path: Path) -> None:
    """SCN-ITEST-004-1: Contended `IntegrationRunLock.acquire()` names holder PID/timestamp and maps to exit code 3."""
    assert int_conftest.EXIT_LOCK_CONTENTION == 3
    lock_file = tmp_path / "_tmp" / "integration.lock"
    lock1 = IntegrationRunLock(lock_file)
    lock2 = IntegrationRunLock(lock_file)

    lock1.acquire()
    try:
        with pytest.raises(IntegrationRunLocked) as exc_info:
            lock2.acquire()
        msg = str(exc_info.value)
        assert f"pid={os.getpid()}" in msg
        assert "started_at=" in msg
    finally:
        lock1.release()


@pytest.mark.spec("SCN-ITEST-004-2")
async def test_readiness_gate_probes_without_login_and_aborts_exit_4_on_timeout() -> None:
    """SCN-ITEST-004-2: Readiness gate accepts `generic_err_missing_required_header` or version and aborts exit 4."""
    assert int_conftest.EXIT_LAB_NOT_READY == 4
    assert answered_by_api({"code": "generic_err_missing_required_header"}) is True
    assert answered_by_api({"current-version": "1.9.1"}) is True
    assert answered_by_api({"code": "http_503"}) is False
    assert answered_by_api(None) is False

    attempts = 0

    async def _flaky_then_ready(_ip: str) -> dict[str, Any] | None:
        nonlocal attempts
        attempts += 1
        return None if attempts == 1 else {"code": "generic_err_missing_required_header"}

    ticks = iter([0.0, 0.05, 0.10, 0.15])

    async def _no_sleep(_sec: float) -> None:
        return None

    elapsed = await wait_until_ready(
        "10.0.0.1",
        timeout=5.0,
        interval=0.01,
        probe=_flaky_then_ready,
        monotonic=lambda: next(ticks),
        sleep=_no_sleep,
    )
    assert elapsed >= 0.0 and attempts == 2

    async def _always_503(_ip: str) -> dict[str, Any] | None:
        return None

    deadline_ticks = iter([0.0, 1.5])
    with pytest.raises(LabNotReady):
        await wait_until_ready(
            "10.0.0.1",
            timeout=1.0,
            interval=0.1,
            probe=_always_503,
            monotonic=lambda: next(deadline_ticks),
            sleep=_no_sleep,
        )


@pytest.mark.spec("SCN-ITEST-005-1")
async def test_baseline_snapshot_persisted_and_reverted_on_mutation(tmp_path: Path) -> None:
    """SCN-ITEST-005-1: Baseline snapshot writes JSON and restores drifted domains discarding open sessions."""
    assert REVERT_TIMEOUT_SECONDS == 900.0
    recorded: list[tuple[str, dict[str, Any], float | None, str | None]] = []

    class _RevClient:
        def __init__(self) -> None:
            self.head_uid = "rev-clean-1"
            self.evicted: list[tuple[str, str]] = []
            self.invalidated: list[tuple[str, str | None]] = []

            class _Cache:
                def __init__(self, outer: _RevClient) -> None:
                    self._outer = outer

                async def evict_sid(self, mgmt_name: str, domain: str, *, auth_identity: str | None = None) -> None:
                    self._outer.evicted.append((mgmt_name, domain))

            self.cache = _Cache(self)

        def invalidate_domain(self, mgmt_name: str, domain: str | None = None) -> None:
            self.invalidated.append((mgmt_name, domain))

        async def create_dedicated_session(
            self,
            mgmt_name: str,
            domain: str,
            *,
            session_name: str = "",
            session_description: str = "",
        ) -> tuple[str, str]:
            return ("sid-rev-helper", "10.0.0.1")

        async def logout_sid(self, mgmt_name: str, sid: str, *, server_ip: str | None = None) -> bool:
            return True

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
            req = dict(payload or {})
            recorded.append((command, req, timeout, domain))
            if command == "show-sessions":
                if req.get("view-published-sessions"):
                    return ApiCallResult(
                        success=True,
                        data={
                            "objects": [
                                {
                                    "uid": self.head_uid,
                                    "name": "clean-baseline-rev",
                                    "publish-time": {"iso-8601": "2026-11-18T12:00:00Z"},
                                }
                            ]
                        },
                    )
                return ApiCallResult(
                    success=True,
                    data={"objects": [{"uid": "dirty-open-1", "changes": 2, "locks": 1}]},
                )
            return ApiCallResult(success=True, data={"message": "OK"})

    fake_client = _RevClient()
    snap = await snapshot_baseline(
        fake_client,  # type: ignore[arg-type]
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        domains=["DomainA"],
    )
    baseline_path = tmp_path / "_tmp" / "cp_baseline" / "baseline-20261119T120000Z.json"
    write_baseline_file(snap, baseline_path)
    saved = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert saved["domains"]["DomainA"]["session_uid"] == "rev-clean-1"

    # Simulate drifted head UID after cp_mutates test
    fake_client.head_uid = "rev-mutated-2"
    reverted = await restore_to_baseline(fake_client, snap)  # type: ignore[arg-type]
    assert reverted == {"DomainA": True}
    assert ("discard", {"uid": "dirty-open-1"}, None, "DomainA") in recorded
    assert ("revert-to-revision", {"to-session": "rev-clean-1"}, 900.0, "DomainA") in recorded
    assert fake_client.evicted == [("mds1", "DomainA")]
    assert fake_client.invalidated == [("mds1", "DomainA")]


@pytest.mark.spec("SCN-ITEST-005-2")
async def test_baseline_snapshot_failure_aborts_session_with_exit_5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-ITEST-005-2: Initial `snapshot_baseline()` failure aborts session with `EXIT_BASELINE_FAILURE` (5)."""
    assert int_conftest.EXIT_BASELINE_FAILURE == 5

    class _AbortCalled(BaseException):
        def __init__(self, msg: str, returncode: int) -> None:
            super().__init__(msg)
            self.returncode = returncode

    async def _fake_make_client(*_a: Any, **_kw: Any) -> Any:
        class _Dummy:
            async def close(self, *, logout: bool = False) -> None:
                return None

        return _Dummy()

    async def _failing_snapshot(*_a: Any, **_kw: Any) -> Any:
        raise RuntimeError("Domain has zero published sessions")

    def _fake_exit(reason: str = "", returncode: int = 1) -> None:
        raise _AbortCalled(reason, returncode)

    monkeypatch.setattr(int_conftest, "_make_client", _fake_make_client)
    monkeypatch.setattr(int_conftest, "snapshot_baseline", _failing_snapshot)
    monkeypatch.setattr(pytest, "exit", _fake_exit)

    unwrapped = inspect.unwrap(int_conftest.cp_baseline_snapshot)
    agen = unwrapped(None, "mds1", "10.0.0.1", "k1", ["DomainA"])
    with pytest.raises(_AbortCalled) as exc_info:
        await agen.__anext__()
    assert exc_info.value.returncode == 5


# ==============================================================================
# FileReplayApiMock Stateful Lifecycle, Changes, Integrity, Rulebase, Global, Scripts
# ==============================================================================


@pytest.mark.spec("SCN-ITEST-010-2")
async def test_emulator_session_metadata_takeover_switch_discard_and_dirty_logout() -> None:
    """SCN-ITEST-010-2: Emulator manages `set-session`, `take-over-session`, `switch-session`, `discard`, and dirty logout."""
    mock = FileReplayApiMock()

    # 1. Login session A, update metadata via set-session, verify via show-session, stage an edit
    la = await mock.api_call("mds", "login", {"user": "admin", "password": "pw", "domain": "Branch"})
    assert la.success
    sid_a = la.data["sid"]
    uid_a = la.data["uid"]

    set_res = await mock.api_call(
        "mds",
        "set-session",
        {"new-name": "SpecSessionA", "description": "Testing takeover"},
        domain="Branch",
        sid=sid_a,
    )
    assert set_res.success
    shown_a = await mock.api_call("mds", "show-session", {"uid": uid_a}, domain="Branch", sid=sid_a)
    assert shown_a.success
    assert shown_a.data["name"] == "SpecSessionA"
    assert shown_a.data["description"] == "Testing takeover"

    added = await mock.api_call(
        "mds",
        "add-host",
        {"name": "H_Takeover_Spec", "ipv4-address": "10.241.0.10"},
        domain="Branch",
        sid=sid_a,
    )
    assert added.success
    added_uid = added.data["uid"]

    # 2. Session B switches cleanly, then takes over Session A disconnecting sid_a (HTTP 401 on subsequent use)
    lb = await mock.api_call("mds", "login", {"user": "eng1", "password": "pw", "domain": "Branch"})
    sid_b = lb.data["sid"]
    takeover = await mock.api_call(
        "mds",
        "take-over-session",
        {"uid": uid_a, "disconnect-active-session": True},
        domain="Branch",
        sid=sid_b,
    )
    assert takeover.success
    assert takeover.data["uid"] == uid_a

    # Old SID A is invalidated with HTTP 401 generic_err_invalid_session_id
    stale_a = await mock.api_call("mds", "show-session", {}, domain="Branch", sid=sid_a)
    assert not stale_a.success and stale_a.status_code == 401
    assert stale_a.error_code == "generic_err_invalid_session_id"

    # Session B can see uncommitted H_Takeover_Spec in taken-over session, switch back to a new session, then discard
    lc = await mock.api_call("mds", "login", {"user": "eng1", "password": "pw", "domain": "Branch"})
    uid_c = lc.data["uid"]
    sw = await mock.api_call("mds", "switch-session", {"uid": uid_c}, domain="Branch", sid=sid_b)
    assert sw.success

    disc = await mock.api_call("mds", "discard", {"uid": uid_a}, domain="Branch", sid=sid_b)
    assert disc.success and disc.data["number-of-discarded-changes"] >= 1
    gone = await mock.api_call("mds", "show-object", {"uid": added_uid}, domain="Branch", sid=sid_b)
    assert not gone.success and gone.status_code == 404

    # 3. Clean logout discards immediately; dirty logout transitions to "disconnected" preserving locks
    clean_out = await mock.api_call("mds", "logout", {}, domain="Branch", sid=sid_b)
    assert clean_out.success
    ld = await mock.api_call("mds", "login", {"user": "admin", "password": "pw", "domain": "Branch"})
    sid_d, uid_d = ld.data["sid"], ld.data["uid"]
    add_dirty = await mock.api_call(
        "mds", "add-host", {"name": "H_Dirty_Out", "ipv4-address": "10.241.0.11"}, domain="Branch", sid=sid_d
    )
    assert add_dirty.success
    dirty_out = await mock.api_call("mds", "logout", {}, domain="Branch", sid=sid_d)
    assert dirty_out.success

    le = await mock.api_call("mds", "login", {"user": "admin", "password": "pw", "domain": "Branch"})
    sid_e = le.data["sid"]
    info_d = await mock.api_call("mds", "show-session", {"uid": uid_d}, domain="Branch", sid=sid_e)
    assert info_d.success
    assert info_d.data["state"] == "disconnected"
    assert info_d.data["locks"] >= 1


@pytest.mark.spec("SCN-ITEST-010-3")
async def test_emulator_show_changes_staged_published_and_sync_show_task_logs() -> None:
    """SCN-ITEST-010-3 (FC-11): `show-changes` returns direct delta buckets, and `wait_for_task=True` logs `show-task` with `200`/`True`."""
    mock = FileReplayApiMock()
    head_before = await mock.api_call("mds", "show-last-published-session", {}, domain="Branch")
    prev_pub_uid = head_before.data["uid"]

    l1 = await mock.api_call("mds", "login", {"user": "admin", "password": "pw", "domain": "Branch"})
    sid = l1.data["sid"]
    ws_uid = l1.data["uid"]

    assert (
        await mock.api_call(
            "mds",
            "add-host",
            {"name": "H_Delta_Spec", "ipv4-address": "10.242.0.10", "comments": "v1"},
            domain="Branch",
            sid=sid,
        )
    ).success
    layers_res = await mock.api_call("mds", "show-access-layers", {"limit": 5}, domain="Branch", sid=sid)
    layers_list = layers_res.data.get("objects") or layers_res.data.get("access-layers") or []
    layer_name = layers_list[0]["name"]
    assert (
        await mock.api_call(
            "mds",
            "add-access-rule",
            {
                "layer": layer_name,
                "name": "Rule_Delta_Spec",
                "position": "top",
                "source": ["H_Delta_Spec"],
                "destination": ["Any"],
                "service": ["Any"],
                "action": "Accept",
            },
            domain="Branch",
            sid=sid,
        )
    ).success

    # 1. Staged show-changes (sync + async) -> added-objects, added-rules, modified-objects with field-changes
    assert (
        await mock.api_call(
            "mds",
            "set-host",
            {"name": "H_Delta_Spec", "comments": "v2"},
            domain="Branch",
            sid=sid,
        )
    ).success
    staged_sync = await mock.api_call(
        "mds", "show-changes", {"to-session": ws_uid}, domain="Branch", sid=sid, wait_for_task=True
    )
    assert staged_sync.success
    staged_task = staged_sync.data["tasks"][0]
    staged_changes = staged_task["task-details"][0]["changes"]
    assert len(staged_changes) == 1
    assert "added-objects" in staged_changes[0] and "operations" not in staged_changes[0]
    assert any(o.get("name") == "H_Delta_Spec" for o in staged_changes[0]["added-objects"])
    assert any(
        r.get("name") == "Rule_Delta_Spec" and r.get("layer") == layer_name and r.get("rule-number") == 1
        for r in staged_changes[0]["added-rules"]
    )

    # 2. Publish and query async show-changes -> show-task
    pub_res = await mock.api_call("mds", "publish", {}, domain="Branch", sid=sid, wait_for_task=True)
    pub_uid = pub_res.data["uid"]

    async_chg = await mock.api_call(
        "mds",
        "show-changes",
        {"from-session": prev_pub_uid, "to-session": pub_uid},
        domain="Branch",
        sid=sid,
        wait_for_task=False,
    )
    assert async_chg.success and async_chg.data.get("task-id")
    polled = await mock.api_call("mds", "show-task", {"task-id": async_chg.data["task-id"]}, domain="Branch", sid=sid)
    assert polled.success
    pub_changes = polled.data["tasks"][0]["task-details"][0]["changes"]
    assert any(o.get("name") == "H_Delta_Spec" for ch in pub_changes for o in ch["added-objects"])

    # Modify published rule/host in next session so modified-objects/modified-rules record old-object/new-object/field-changes
    l2 = await mock.api_call("mds", "login", {"user": "admin", "password": "pw", "domain": "Branch"})
    sid2 = l2.data["sid"]
    assert (
        await mock.api_call("mds", "set-host", {"name": "H_Delta_Spec", "comments": "v3"}, domain="Branch", sid=sid2)
    ).success
    staged_mod = await mock.api_call(
        "mds", "show-changes", {"to-session": l2.data["uid"]}, domain="Branch", sid=sid2, wait_for_task=True
    )
    mod_objs = staged_mod.data["tasks"][0]["task-details"][0]["changes"][0]["modified-objects"]
    assert any(
        m.get("name") == "H_Delta_Spec"
        and m.get("old-object", {}).get("comments") == "v2"
        and m.get("new-object", {}).get("comments") == "v3"
        and m.get("field-changes")
        for m in mod_objs
    )

    # 3. FC-11: Synchronous run-script records synthetic show-task with HTTP status 200 and success=True
    gws = await mock.api_query("mds", "show-gateways-and-servers", domain="Branch")
    gw_name = next(o["name"] for o in gws.objects if o.get("type") in ("simple-gateway", "CpmiGatewayCluster"))
    rs = await mock.api_call(
        "mds",
        "run-script",
        {"script-name": "spec-route", "script": "ip -4 route show", "targets": [gw_name]},
        domain="Branch",
        sid=sid,
        wait_for_task=True,
    )
    assert rs.success
    synthetic_show_tasks = [e for e in mock.call_log if e["command"] == "show-task" and e["sid_ref"] is None]
    assert synthetic_show_tasks
    assert all(e["status_code"] == 200 and e["success"] is True for e in synthetic_show_tasks)


@pytest.mark.spec("SCN-ITEST-011-2")
async def test_emulator_show_and_delete_unused_objects_preserves_referenced_and_global() -> None:
    """SCN-ITEST-011-2: `show-unused-objects` and `delete-unused-objects` remove only local unreferenced entities."""
    mock = FileReplayApiMock()
    l1 = await mock.api_call("mds", "login", {"user": "admin", "password": "pw", "domain": "Branch"})
    sid = l1.data["sid"]

    assert (
        await mock.api_call(
            "mds", "add-host", {"name": "H_Spec_Unused", "ipv4-address": "10.243.0.1"}, domain="Branch", sid=sid
        )
    ).success
    assert (
        await mock.api_call(
            "mds", "add-host", {"name": "H_Spec_InUse", "ipv4-address": "10.243.0.2"}, domain="Branch", sid=sid
        )
    ).success
    assert (
        await mock.api_call(
            "mds", "add-group", {"name": "G_Spec_Wrap", "members": ["H_Spec_InUse"]}, domain="Branch", sid=sid
        )
    ).success
    assert (await mock.api_call("mds", "publish", {}, domain="Branch", sid=sid)).success

    unused_res = await mock.api_call(
        "mds", "show-unused-objects", {"type": "host", "filter": "H_Spec_"}, domain="Branch", sid=sid
    )
    assert unused_res.success
    unused_names = {o["name"] for o in unused_res.data["objects"]}
    assert "H_Spec_Unused" in unused_names
    assert "H_Spec_InUse" not in unused_names
    assert "H_Global_DNS_001" not in unused_names

    del_res = await mock.api_call("mds", "delete-unused-objects", {"object": "H_Spec_Unused"}, domain="Branch", sid=sid)
    assert del_res.success and del_res.data["deleted-count"] == 1

    # Deleted in staging overlay, while referenced host & Global object remain untouched
    chk_unused = await mock.api_call("mds", "show-host", {"name": "H_Spec_Unused"}, domain="Branch", sid=sid)
    assert not chk_unused.success and chk_unused.status_code == 404
    chk_used = await mock.api_call("mds", "show-host", {"name": "H_Spec_InUse"}, domain="Branch", sid=sid)
    assert chk_used.success
    chk_glob = await mock.api_call("mds", "show-host", {"name": "H_Global_DNS_001"}, domain="Global")
    assert chk_glob.success


@pytest.mark.spec("SCN-ITEST-012-1")
async def test_emulator_rejects_delete_of_referenced_object_group_and_service_with_blocking_errors() -> None:
    """SCN-ITEST-012-1: `delete-*` on referenced hosts, groups, and services returns 400 `generic_err_object_cannot_be_deleted`."""
    mock = FileReplayApiMock()
    l1 = await mock.api_call("mds", "login", {"user": "admin", "password": "pw", "domain": "Branch"})
    sid = l1.data["sid"]

    layers = await mock.api_call("mds", "show-access-layers", {"limit": 5}, domain="Branch", sid=sid)
    layers_list = layers.data.get("objects") or layers.data.get("access-layers") or []
    layer_name = layers_list[0]["name"]

    assert (
        await mock.api_call(
            "mds", "add-host", {"name": "H_Ref_Grp", "ipv4-address": "10.244.0.1"}, domain="Branch", sid=sid
        )
    ).success
    assert (
        await mock.api_call(
            "mds", "add-group", {"name": "G_Ref_Rule", "members": ["H_Ref_Grp"]}, domain="Branch", sid=sid
        )
    ).success
    assert (
        await mock.api_call(
            "mds", "add-service-tcp", {"name": "TCP_Ref_19001", "port": "19001"}, domain="Branch", sid=sid
        )
    ).success
    assert (
        await mock.api_call(
            "mds",
            "add-access-rule",
            {
                "layer": layer_name,
                "name": "Rule_Blocking_Del",
                "position": "top",
                "enabled": False,
                "source": ["G_Ref_Rule"],
                "destination": ["Any"],
                "service": ["TCP_Ref_19001"],
                "action": "Drop",
            },
            domain="Branch",
            sid=sid,
        )
    ).success
    assert (await mock.api_call("mds", "publish", {}, domain="Branch", sid=sid)).success

    for cmd, payload in (
        ("delete-host", {"name": "H_Ref_Grp"}),
        ("delete-group", {"name": "G_Ref_Rule"}),
        ("delete-service-tcp", {"name": "TCP_Ref_19001"}),
    ):
        res = await mock.api_call("mds", cmd, payload, domain="Branch", sid=sid)
        assert not res.success and res.status_code == 400
        assert res.error_code == "generic_err_object_cannot_be_deleted"
        assert res.data.get("blocking-errors")

    assert (await mock.api_call("mds", "show-host", {"name": "H_Ref_Grp"}, domain="Branch", sid=sid)).success


@pytest.mark.spec("SCN-ITEST-013-1")
async def test_emulator_access_rule_and_section_crud_any_stripping_reordering_and_dict_toggle() -> None:
    """SCN-ITEST-013-1: Access rule/section CRUD maintains sequential numbers, Any stripping/reversion, and layer reads."""
    mock = FileReplayApiMock()
    l1 = await mock.api_call("mds", "login", {"user": "admin", "password": "pw", "domain": "Branch"})
    sid = l1.data["sid"]

    # Read-only show-{access,https,threat}-layer(s) reads
    layers = await mock.api_call("mds", "show-access-layers", {"limit": 20}, domain="Branch", sid=sid)
    layers_list = layers.data.get("objects") or layers.data.get("access-layers") or []
    assert layers.success and layers_list
    parent_layer = layers_list[0]["name"]
    one_layer = await mock.api_call("mds", "show-access-layer", {"name": parent_layer}, domain="Branch", sid=sid)
    assert one_layer.success and one_layer.data["name"] == parent_layer
    assert (await mock.api_call("mds", "show-https-layers", {}, domain="Branch", sid=sid)).success
    assert (await mock.api_call("mds", "show-threat-layers", {}, domain="Branch", sid=sid)).success

    # Add host and section at top, add rule referencing Any -> patch {add, remove} strips Any then empties back to Any
    assert (
        await mock.api_call(
            "mds", "add-host", {"name": "H_Rule_Edit", "ipv4-address": "10.245.0.10"}, domain="Branch", sid=sid
        )
    ).success
    sec = await mock.api_call(
        "mds",
        "add-access-section",
        {"layer": parent_layer, "name": "SpecTopSection", "position": "top"},
        domain="Branch",
        sid=sid,
    )
    assert sec.success
    r_add = await mock.api_call(
        "mds",
        "add-access-rule",
        {
            "layer": parent_layer,
            "name": "Spec_Rule_1",
            "position": {"top": "SpecTopSection"},
            "source": ["Any"],
            "destination": ["Any"],
            "service": ["Any"],
            "action": "Accept",
        },
        domain="Branch",
        sid=sid,
    )
    assert r_add.success and r_add.data["rule-number"] == 1
    r_second = await mock.api_call(
        "mds",
        "add-access-rule",
        {
            "layer": parent_layer,
            "name": "Spec_Rule_2",
            "position": {"bottom": "SpecTopSection"},
            "source": ["H_Rule_Edit"],
            "destination": ["Any"],
            "service": ["Any"],
            "action": "Drop",
        },
        domain="Branch",
        sid=sid,
    )
    assert r_second.success and r_second.data["rule-number"] == 2

    # Reposition Spec_Rule_2 above Spec_Rule_1 via new-position
    r_move = await mock.api_call(
        "mds",
        "set-access-rule",
        {"layer": parent_layer, "uid": r_second.data["uid"], "new-position": {"above": r_add.data["uid"]}},
        domain="Branch",
        sid=sid,
    )
    assert r_move.success and r_move.data["rule-number"] == 1

    # Adding a concrete host strips NAT_ANY_OBJECT_UID; removing it reverts to Any
    r_patch = await mock.api_call(
        "mds",
        "set-access-rule",
        {"layer": parent_layer, "uid": r_add.data["uid"], "source": {"add": "H_Rule_Edit"}},
        domain="Branch",
        sid=sid,
    )
    assert r_patch.success
    src_uids = [s if isinstance(s, str) else s.get("uid") for s in r_patch.data["source"]]
    assert NAT_ANY_OBJECT_UID not in src_uids

    r_empty = await mock.api_call(
        "mds",
        "set-access-rule",
        {"layer": parent_layer, "uid": r_add.data["uid"], "source": {"remove": "H_Rule_Edit"}},
        domain="Branch",
        sid=sid,
    )
    assert r_empty.success
    src_after = [s if isinstance(s, str) else s.get("uid") for s in r_empty.data["source"]]
    assert src_after == [NAT_ANY_OBJECT_UID]

    # use-object-dictionary=False vs True + section from/to & layer total recomputation
    rb_dict = await mock.api_call(
        "mds",
        "show-access-rulebase",
        {"name": parent_layer, "use-object-dictionary": True, "limit": 20},
        domain="Branch",
        sid=sid,
    )
    rb_inline = await mock.api_call(
        "mds",
        "show-access-rulebase",
        {"name": parent_layer, "use-object-dictionary": False, "limit": 20},
        domain="Branch",
        sid=sid,
    )
    assert rb_dict.success and rb_dict.data.get("objects-dictionary")
    assert rb_inline.success and rb_inline.data["rulebase"][0]["from"] == 1 and rb_inline.data["rulebase"][0]["to"] == 2
    assert rb_inline.data["total"] >= 2


@pytest.mark.spec("SCN-ITEST-013-3")
async def test_emulator_post_mutation_reads_stay_consistent_in_where_used_and_rulebases() -> None:
    """SCN-ITEST-013-3: Uncommitted mutations appear immediately in `where-used`, `show-objects`, `show-object`, and rulebases."""
    mock = FileReplayApiMock()
    l1 = await mock.api_call("mds", "login", {"user": "admin", "password": "pw", "domain": "Branch"})
    sid = l1.data["sid"]

    layers = await mock.api_call("mds", "show-access-layers", {"limit": 5}, domain="Branch", sid=sid)
    layers_list = layers.data.get("objects") or layers.data.get("access-layers") or []
    layer_name = layers_list[0]["name"]

    h_res = await mock.api_call(
        "mds", "add-host", {"name": "H_Staged_Ref", "ipv4-address": "10.246.0.10"}, domain="Branch", sid=sid
    )
    assert h_res.success
    h_uid = h_res.data["uid"]
    g_res = await mock.api_call("mds", "add-group", {"name": "G_Staged_Wrap", "members": []}, domain="Branch", sid=sid)
    assert g_res.success
    g_uid = g_res.data["uid"]

    # Mutate group + add access rule referencing group WITHOUT publishing yet
    assert (
        await mock.api_call(
            "mds", "set-group", {"uid": g_uid, "members": {"add": "H_Staged_Ref"}}, domain="Branch", sid=sid
        )
    ).success
    assert (
        await mock.api_call(
            "mds",
            "add-access-rule",
            {
                "layer": layer_name,
                "name": "Rule_Staged_Cons",
                "position": "top",
                "source": ["G_Staged_Wrap"],
                "destination": ["Any"],
                "service": ["Any"],
                "action": "Accept",
            },
            domain="Branch",
            sid=sid,
        )
    ).success

    wu = await mock.api_call("mds", "where-used", {"uid": h_uid, "indirect": True}, domain="Branch", sid=sid)
    assert wu.success
    direct_names = {o.get("name") for o in wu.data["used-directly"]["objects"]}
    indirect_rules = {r.get("rule", {}).get("name") for r in wu.data["used-indirectly"]["access-control-rules"]}
    assert "G_Staged_Wrap" in direct_names
    assert "Rule_Staged_Cons" in indirect_rules

    so = await mock.api_call("mds", "show-object", {"uid": h_uid}, domain="Branch", sid=sid)
    sh = await mock.api_call("mds", "show-host", {"name": "H_Staged_Ref"}, domain="Branch", sid=sid)
    sq = await mock.api_query(
        "mds", "show-objects", domain="Branch", payload={"filter": "H_Staged_Ref", "type": "host"}, sid=sid
    )
    rb = await mock.api_call(
        "mds",
        "show-access-rulebase",
        {"name": layer_name, "use-object-dictionary": True, "limit": 10},
        domain="Branch",
        sid=sid,
    )
    assert so.success and sh.success and any(o.get("uid") == h_uid for o in sq.objects)
    assert any(o.get("uid") == g_uid for o in rb.data.get("objects-dictionary", []))


@pytest.mark.spec("SCN-ITEST-014-2")
async def test_emulator_global_read_only_from_local_session_and_global_session_integrity() -> None:
    """SCN-ITEST-014-2: Local sessions reject mutations on `Global` (`generic_err_object_read_only`); `Global` session enforces cross-domain refs."""
    mock = FileReplayApiMock()

    # 1. Local domain session attempting to modify/delete Global host H_Global_DNS_001 -> 400 generic_err_object_read_only
    l_branch = await mock.api_call("mds", "login", {"user": "admin", "password": "pw", "domain": "Branch"})
    sid_branch = l_branch.data["sid"]
    for cmd, payload in (
        ("set-host", {"name": "H_Global_DNS_001", "comments": "illegal local edit"}),
        ("delete-host", {"name": "H_Global_DNS_001"}),
    ):
        err = await mock.api_call("mds", cmd, payload, domain="Global", sid=sid_branch)
        assert not err.success and err.status_code == 400
        assert err.error_code == "generic_err_object_read_only"

    # 2. Direct Global write session mutates/deletes unreferenced Global host, but refuses referenced H_Global_DNS_001
    l_glob = await mock.api_call("mds", "login", {"user": "admin", "password": "pw", "domain": "Global"})
    sid_glob = l_glob.data["sid"]
    add_g = await mock.api_call(
        "mds", "add-host", {"name": "H_Global_Temp_Spec", "ipv4-address": "10.254.0.2"}, domain="Global", sid=sid_glob
    )
    assert add_g.success
    assert (
        await mock.api_call(
            "mds", "set-host", {"name": "H_Global_Temp_Spec", "comments": "global ok"}, domain="Global", sid=sid_glob
        )
    ).success
    assert (
        await mock.api_call("mds", "delete-host", {"name": "H_Global_Temp_Spec"}, domain="Global", sid=sid_glob)
    ).success

    blocked_g = await mock.api_call("mds", "delete-host", {"name": "H_Global_DNS_001"}, domain="Global", sid=sid_glob)
    assert not blocked_g.success and blocked_g.status_code == 400
    assert blocked_g.error_code == "generic_err_object_cannot_be_deleted"


@pytest.mark.spec("SCN-ITEST-017-1")
def test_examples_catalog_covers_v2_workflows_and_guarded_auth_invariants() -> None:
    """SCN-ITEST-017-1: `examples/` provides `01`..`13`, crash-safe `guarded_session` on mutating scripts, and MCP auth in `12`."""
    ex_dir = REPO_ROOT / "examples"
    expected_prefixes = (
        "01_basic_queries.py",
        "02_search_and_query.py",
        "03_gateway_relationships.py",
        "04_smart_refresh.py",
        "05_rulebase_queries.py",
        "06_session_basics.py",
        "07_context_and_overlay.py",
        "08_cpcrud_operations.py",
        "09_cpcrud_inverse.py",
        "10_change_report_evidence.py",
        "11_otel_tracing.py",
        "12_mcp_embedded.py",
        "13_gateway_topology_matching.py",
    )
    for fname in expected_prefixes:
        assert (ex_dir / fname).is_file(), f"Missing example {fname}"

    for mutating in (
        "06_session_basics.py",
        "08_cpcrud_operations.py",
        "09_cpcrud_inverse.py",
        "10_change_report_evidence.py",
    ):
        text = (ex_dir / mutating).read_text(encoding="utf-8")
        assert "guarded_session" in text, f"{mutating} must use guarded_session"

    mcp_ex = (ex_dir / "12_mcp_embedded.py").read_text(encoding="utf-8")
    assert 'auth_mode="host"' in mcp_ex
    assert "Authorization" in mcp_ex and "Bearer" in mcp_ex


@pytest.mark.spec("SCN-ITEST-018-1")
async def test_emulator_repository_script_staging_isolation_and_permission_toggles() -> None:
    """SCN-ITEST-018-1: Repository-script CRUD stays staged per SID until `publish` and honors permission flags."""
    mock = FileReplayApiMock()
    la = await mock.api_call("mds", "login", {"user": "admin", "password": "pw", "domain": "Branch"})
    lb = await mock.api_call("mds", "login", {"user": "eng1", "password": "pw", "domain": "Branch"})
    sid_a, sid_b = la.data["sid"], lb.data["sid"]

    # 1. Stage script in Session A; invisible to Session B before publish
    add_res = await mock.api_call(
        "mds",
        "add-repository-script",
        {"name": "spec-script", "script-body": "#!/bin/bash\necho spec\n"},
        domain="Branch",
        sid=sid_a,
    )
    assert add_res.success
    in_a = await mock.api_call("mds", "show-repository-script", {"name": "spec-script"}, domain="Branch", sid=sid_a)
    not_in_b = await mock.api_call("mds", "show-repository-script", {"name": "spec-script"}, domain="Branch", sid=sid_b)
    assert in_a.success
    assert not not_in_b.success and not_in_b.status_code == 404

    # Publish -> visible to Session B and updateable/deletable
    assert (await mock.api_call("mds", "publish", {}, domain="Branch", sid=sid_a)).success
    now_in_b = await mock.api_call("mds", "show-repository-script", {"name": "spec-script"}, domain="Branch", sid=sid_b)
    assert now_in_b.success

    # 2. Permission toggles: manage_repository_scripts="read" | "none", allow_one_time_script=False, allow_repository_script=False
    mock.manage_repository_scripts = "read"
    deny_write = await mock.api_call(
        "mds",
        "set-repository-script",
        {"name": "spec-script", "comments": "denied"},
        domain="Branch",
        sid=sid_a,
    )
    assert not deny_write.success and deny_write.error_code == "generic_err_no_permissions"

    mock.manage_repository_scripts = "none"
    deny_read = await mock.api_call("mds", "show-repository-scripts", {}, domain="Branch", sid=sid_a)
    assert not deny_read.success and deny_read.error_code == "generic_err_no_permissions"

    mock.manage_repository_scripts = "write"
    mock.allow_one_time_script = False
    deny_one_time = await mock.api_call(
        "mds",
        "run-script",
        {"script-name": "inline-denied", "script": "echo hi", "targets": ["any-gw"]},
        domain="Branch",
        sid=sid_a,
    )
    assert not deny_one_time.success and deny_one_time.error_code == "generic_err_no_permissions"

    mock.allow_repository_script = False
    deny_repo_run = await mock.api_call(
        "mds",
        "run-script",
        {"script-type": "repository", "script-name": "spec-script", "targets": ["any-gw"]},
        domain="Branch",
        sid=sid_a,
    )
    assert not deny_repo_run.success and deny_repo_run.error_code == "generic_err_no_permissions"

    # Cleanup
    assert (
        await mock.api_call("mds", "delete-repository-script", {"name": "spec-script"}, domain="Branch", sid=sid_a)
    ).success
