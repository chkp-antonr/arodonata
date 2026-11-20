"""Architectural, DRY, cold-import, and dataset parity tests for Wave 6 testing decomposition."""

from __future__ import annotations

import ast
import inspect
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import arodonata.testing as testing_pkg
from arodonata.core.models import sentinels as core_sentinels
from arodonata.testing import (
    _emulator_crud,
    _emulator_models,
    _emulator_projection,
    dataset_generator,
    replay_mock,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTING_DIR = REPO_ROOT / "src" / "arodonata" / "testing"
MAX_MODULE_LOC = 650

FORBIDDEN_REPLAY_DUPLICATES = frozenset(
    {
        "_project_details_level",
        "_extract_ref_uids",
        "_INLINE_LIST_RULE_FIELDS",
        "_INLINE_SCALAR_RULE_FIELDS",
        "_inline_rule_objects",
        "_slice_rulebase_nodes",
    }
)

SENTINEL_NAMES = frozenset(
    {
        "ANY_UID",
        "ORIGINAL_UID",
        "ACCEPT_UID",
        "DROP_UID",
        "LOG_TRACK_UID",
        "POLICY_TARGETS_UID",
    }
)


def _iter_testing_modules() -> list[Path]:
    return sorted(TESTING_DIR.glob("*.py"))


def _defined_top_level_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def test_testing_modules_within_loc_budget() -> None:
    """Every module in src/arodonata/testing stays within the Wave 6 LOC ceiling."""
    modules = _iter_testing_modules()
    assert len(modules) >= 20
    oversized = [
        f"{path.name}: {len(path.read_text(encoding='utf-8').splitlines())}"
        for path in modules
        if len(path.read_text(encoding="utf-8").splitlines()) > MAX_MODULE_LOC
    ]
    assert not oversized, f"Oversized testing modules (> {MAX_MODULE_LOC} LOC): {oversized}"


def test_testing_submodules_cold_import_cleanly() -> None:
    """Every submodule under arodonata.testing cold-imports cleanly in both orders."""
    module_names = [f"arodonata.testing.{path.stem}" for path in _iter_testing_modules() if path.stem != "__init__"]
    for order in (module_names, list(reversed(module_names))):
        script = "import importlib\nfor name in " + repr(order) + ":\n    importlib.import_module(name)\n"
        proc = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"Cold import failed:\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"


def test_backward_compatible_reexports_preserved() -> None:
    """Public and backward-compatible re-exports preserve object identity across facades."""
    expected_replay_exports = (
        "FileReplayApiMock",
        "FileReplayCliMock",
        "ReplayStateSnapshot",
        "ensure_enterprise_raw_dataset",
    )
    assert set(replay_mock.__all__) == set(expected_replay_exports)
    for name in expected_replay_exports:
        assert getattr(replay_mock, name) is getattr(testing_pkg, name)

    expected_dataset_exports = (
        "ALL_DOMAINS",
        "DATASET_VERSION",
        "DEFAULT_DATASET_DIR",
        "DEFAULT_SEED",
        "USER_DOMAINS",
        "ensure_enterprise_raw_dataset",
        "generate_enterprise_raw_dataset",
    )
    assert set(dataset_generator.__all__) == set(expected_dataset_exports)
    for name in expected_dataset_exports:
        assert getattr(dataset_generator, name) is getattr(testing_pkg, name)

    expected_crud_exports = (
        "_inline_rule_objects",
        "_iter_flat_rule_entries",
        "_normalize_subnet_fields",
        "build_objects_dictionary",
        "collect_blocking_references",
        "delete_unused_objects",
        "extract_ref_uids",
        "filter_show_objects",
        "find_effective_object",
        "find_in_scope",
        "find_unused_objects",
        "handle_entity_crud",
        "handle_rulebase_crud",
        "inline_rule_objects",
        "make_object_summary",
        "paginate_items",
        "parse_rule_number",
        "project_details_level",
        "slice_rulebase_with_sections",
    )
    assert set(_emulator_crud.__all__) == set(expected_crud_exports)
    assert _emulator_crud.project_details_level is _emulator_projection.project_details_level
    assert _emulator_crud.paginate_items is _emulator_projection.paginate_items
    assert _emulator_crud.inline_rule_objects is _emulator_projection.inline_rule_objects
    assert _emulator_crud.slice_rulebase_with_sections is _emulator_projection.slice_rulebase_with_sections
    assert _emulator_crud.extract_ref_uids is _emulator_projection.extract_ref_uids


def test_replay_mock_deduplicates_projection_and_sentinels() -> None:
    """replay_mock omits duplicated projection helpers and sentinels remain single-sourced."""
    replay_defs = _defined_top_level_names(TESTING_DIR / "replay_mock.py")
    assert not (replay_defs & FORBIDDEN_REPLAY_DUPLICATES)

    for path in _iter_testing_modules():
        if path.name == "_emulator_models.py":
            continue
        assert not (_defined_top_level_names(path) & SENTINEL_NAMES), f"{path.name} redefines core sentinels"

    for sentinel in SENTINEL_NAMES:
        assert getattr(_emulator_models, sentinel) == getattr(core_sentinels, sentinel)


@pytest.mark.spec("SCN-ITEST-006-1", "SCN-ITEST-006-2")
def test_dataset_generator_deterministic_parity(tmp_path: Path) -> None:
    """Generating into a fresh directory reproduces exact manifest counts and file bytes."""
    fresh_dir = tmp_path / "enterprise_raw"
    manifest: dict[str, Any] = dataset_generator.generate_enterprise_raw_dataset(fresh_dir)

    assert manifest["version"] == dataset_generator.DATASET_VERSION == "1.2.0"
    assert manifest["seed"] == dataset_generator.DEFAULT_SEED
    counts: dict[str, int] = manifest["counts"]
    assert counts["total_domains"] == 10
    assert counts["user_domains"] == 9
    assert counts["total_assets"] == 341
    assert counts["policy_enforcing_gateways"] == 315
    assert counts["total_network_objects"] == 2951
    assert counts["total_service_objects"] == 210
    assert counts["total_access_rules"] == 1050
    assert counts["total_nat_rules"] == 120
    assert counts["total_cli_targets"] == 325

    default_dir = dataset_generator.ensure_enterprise_raw_dataset()
    fresh_manifest = json.loads((fresh_dir / "manifest.json").read_text(encoding="utf-8"))
    default_manifest = json.loads((default_dir / "manifest.json").read_text(encoding="utf-8"))
    assert fresh_manifest == default_manifest

    fresh_files = sorted(p.relative_to(fresh_dir) for p in fresh_dir.rglob("*") if p.is_file())
    default_files = sorted(p.relative_to(default_dir) for p in default_dir.rglob("*") if p.is_file())
    assert fresh_files == default_files
    for rel_path in fresh_files:
        assert (fresh_dir / rel_path).read_bytes() == (default_dir / rel_path).read_bytes(), str(rel_path)


@pytest.mark.spec("SCN-ITEST-009-2")
@pytest.mark.asyncio
async def test_nat_rule_lock_preflight_without_package_parameter() -> None:
    """NAT lock preflight still resolves target UIDs when `package` is omitted on set/delete by name."""
    api = replay_mock.FileReplayApiMock()
    sid_a, _ = await api.create_dedicated_session("mds", "Branch")
    sid_b, _ = await api.create_dedicated_session("mds", "Branch")

    rb_res = await api.api_call(
        "mds",
        "show-nat-rulebase",
        {"package": "Branch_Standard_Pkg", "limit": 10},
        domain="Branch",
        sid=sid_a,
    )
    assert rb_res.success
    nat_rule = next(
        rule
        for _, rule in _emulator_projection.iter_flat_rule_entries(rb_res.data["rulebase"])
        if rule.get("type") == "nat-rule"
    )
    rule_name = f"nat_lock_test_{nat_rule['rule-number']}"

    named = await api.api_call(
        "mds",
        "set-nat-rule",
        {"package": "Branch_Standard_Pkg", "uid": nat_rule["uid"], "new-name": rule_name},
        domain="Branch",
        sid=sid_a,
    )
    assert named.success
    assert (await api.api_call("mds", "publish", {}, domain="Branch", sid=sid_a)).success

    # Lock the published named NAT rule in session A (with explicit package).
    locked = await api.api_call(
        "mds",
        "set-nat-rule",
        {"package": "Branch_Standard_Pkg", "uid": nat_rule["uid"], "comments": "locked-by-a"},
        domain="Branch",
        sid=sid_a,
    )
    assert locked.success

    blocked_set = await api.api_call(
        "mds",
        "set-nat-rule",
        {"name": rule_name, "comments": "conflict"},
        domain="Branch",
        sid=sid_b,
    )
    assert not blocked_set.success
    assert blocked_set.status_code == 400
    assert blocked_set.error_code == "generic_err_object_locked"

    blocked_del = await api.api_call(
        "mds",
        "delete-nat-rule",
        {"name": rule_name},
        domain="Branch",
        sid=sid_b,
    )
    assert not blocked_del.success
    assert blocked_del.status_code == 400
    assert blocked_del.error_code == "generic_err_object_locked"


@pytest.mark.spec("SCN-ITEST-015-1")
def test_reset_restores_initial_fail_ssh_nodes() -> None:
    """`reset()` restores constructor `fail_ssh_nodes` defaults and custom sets."""
    default_api = replay_mock.FileReplayApiMock()
    expected_defaults = {"br-reg-gw-138", "br-reg-gw-139", "br-reg-gw-140"}
    assert default_api.cli_mock.fail_ssh_nodes == expected_defaults

    default_api.cli_mock.fail_ssh_nodes.add("br-spb-gw-01")
    default_api.cli_mock.fail_ssh_nodes.discard("br-reg-gw-138")
    default_api.reset()
    assert default_api.cli_mock.fail_ssh_nodes == expected_defaults

    custom_cli = replay_mock.FileReplayCliMock(fail_ssh_nodes={"custom-gw-01"})
    custom_api = replay_mock.FileReplayApiMock(cli_mock=custom_cli)
    custom_api.cli_mock.fail_ssh_nodes.clear()
    custom_api.reset()
    assert custom_api.cli_mock.fail_ssh_nodes == {"custom-gw-01"}


@pytest.mark.spec("SCN-ITEST-010-2")
@pytest.mark.asyncio
async def test_discard_by_uid_rotates_all_sid_bindings_and_blocks_non_open_writes() -> None:
    """Discarding another session by UID rotates its active SID and guards non-open writes."""
    api = replay_mock.FileReplayApiMock()
    sid_a, _ = await api.create_dedicated_session("mds", "Branch")
    sid_b, _ = await api.create_dedicated_session("mds", "Branch")
    uid_b = (await api.api_call("mds", "show-session", {}, domain="Branch", sid=sid_b)).data["uid"]

    assert (
        await api.api_call(
            "mds",
            "add-host",
            {"name": "H_Discard_Before", "ipv4-address": "10.220.1.1"},
            domain="Branch",
            sid=sid_b,
        )
    ).success

    disc_res = await api.api_call("mds", "discard", {"uid": uid_b}, domain="Branch", sid=sid_a)
    assert disc_res.success
    assert disc_res.data["number-of-discarded-changes"] == 1
    assert api.get_active_sid_binding(sid_b).session_uid != uid_b  # type: ignore[union-attr]

    # Session B's SID now targets a fresh open work session rather than the discarded one.
    add_after = await api.api_call(
        "mds",
        "add-host",
        {"name": "H_Discard_After", "ipv4-address": "10.220.1.2"},
        domain="Branch",
        sid=sid_b,
    )
    assert add_after.success
    shown = await api.api_call("mds", "show-host", {"name": "H_Discard_After"}, domain="Branch", sid=sid_b)
    assert shown.success
    pub = await api.api_call("mds", "publish", {}, domain="Branch", sid=sid_b)
    assert pub.success

    # Defense in depth: if a SID binding somehow points at a non-open WorkSession, mutations fail closed.
    sid_c, _ = await api.create_dedicated_session("mds", "Branch")
    binding_c = api.get_active_sid_binding(sid_c)
    assert binding_c is not None
    api._work_sessions[binding_c.session_uid].state = "discarded"
    dead_write = await api.api_call(
        "mds",
        "add-host",
        {"name": "H_Dead_Overlay", "ipv4-address": "10.220.1.3"},
        domain="Branch",
        sid=sid_c,
    )
    assert not dead_write.success
    assert dead_write.status_code == 400
    assert dead_write.error_code == "err_validation_failed"


@pytest.mark.spec("SCN-ITEST-007-1")
@pytest.mark.asyncio
async def test_projection_separation_determinism_and_pagination_clamping() -> None:
    """Replay vs CRUD projections are separated, deterministic, and pagination handles limit=0 cleanly."""
    assert "strict_standard" not in inspect.signature(_emulator_projection.project_details_level).parameters
    assert "groups" not in _emulator_projection.REPLAY_STANDARD_SUMMARY_KEYS

    large_obj = {k: f"val-{k}" for k in reversed(_emulator_projection.CRUD_STANDARD_KEEP_KEYS)}
    large_obj.update(
        {
            "fqdn": "example.internal",
            "subnet6": "2001:db8::",
            "mask-length6": 64,
            "ipv6-address-first": "2001:db8::1",
            "ipv6-address-last": "2001:db8::9",
            "icon": "Hosts/Host",
            "class-name": "com.checkpoint.objects.classes.dummy.CpmiHostPlain",
            "extra-field": "drop-me",
        }
    )
    crud_slim = _emulator_projection.project_details_level(large_obj, "standard")
    assert list(crud_slim.keys()) == list(_emulator_projection.CRUD_STANDARD_KEEP_KEYS)
    for forbidden in (
        "fqdn",
        "subnet6",
        "mask-length6",
        "ipv6-address-first",
        "ipv6-address-last",
        "icon",
        "class-name",
    ):
        assert forbidden not in crud_slim

    api = replay_mock.FileReplayApiMock()
    sid, _ = await api.create_dedicated_session("mds", "Branch")
    created = await api.api_call(
        "mds",
        "add-host",
        {"name": "H_Replay_Std_Shape", "ipv4-address": "10.220.2.1"},
        domain="Branch",
        sid=sid,
    )
    assert created.success
    assert "groups" in created.data

    hosts_page = await api.api_call(
        "mds",
        "show-hosts",
        {"filter": "H_Replay_Std_Shape", "details-level": "standard"},
        domain="Branch",
        sid=sid,
    )
    assert hosts_page.success
    matched = [h for h in hosts_page.data["objects"] if h["name"] == "H_Replay_Std_Shape"]
    assert matched and "groups" not in matched[0]

    empty_hosts = await api.api_call("mds", "show-hosts", {"limit": 0, "offset": -5}, domain="Branch", sid=sid)
    assert empty_hosts.success
    assert empty_hosts.data["objects"] == []
    assert empty_hosts.data["from"] == 0
    assert empty_hosts.data["to"] == 0
    assert empty_hosts.data["total"] >= 1

    assert (
        await api.api_call(
            "mds",
            "add-repository-script",
            {"name": "pagination-probe", "script-body": "echo ok\n"},
            domain="Branch",
            sid=sid,
        )
    ).success
    empty_scripts = await api.api_call(
        "mds", "show-repository-scripts", {"limit": 0, "offset": -3}, domain="Branch", sid=sid
    )
    assert empty_scripts.success
    assert empty_scripts.data["objects"] == []
    assert empty_scripts.data["from"] == 0
    assert empty_scripts.data["to"] == 0
    assert empty_scripts.data["total"] >= 1


@pytest.mark.spec("SCN-ITEST-014-3")
@pytest.mark.asyncio
async def test_local_domain_session_cannot_assign_global_policy() -> None:
    """A session bound to a local domain cannot invoke `assign-global-policy` even on that domain."""
    api = replay_mock.FileReplayApiMock()
    br_sid, _ = await api.create_dedicated_session("mds", "Branch")

    for cmd in ("assign-global-policy", "assign-global-assignment"):
        res = await api.api_call(
            "mds",
            cmd,
            {"dependent-domains": ["DC_Pod"], "global-domains": ["Global"]},
            domain="Branch",
            sid=br_sid,
        )
        assert not res.success
        assert res.status_code == 400
        assert res.error_code == "generic_err_object_read_only"


@pytest.mark.spec("SCN-ITEST-018-1")
@pytest.mark.asyncio
async def test_apply_domain_mutation_seam_and_unified_run_script_task_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """Live dispatch routes mutations through `_apply_domain_mutation` and `run-script` uses `_next_task_id`."""
    api = replay_mock.FileReplayApiMock()
    sid, _ = await api.create_dedicated_session("mds", "Branch")

    seen_cmds: list[str] = []
    orig_apply = api._apply_domain_mutation

    def wrapped_apply(*args: Any, **kwargs: Any) -> Any:
        seen_cmds.append(str(args[0]))
        return orig_apply(*args, **kwargs)

    monkeypatch.setattr(api, "_apply_domain_mutation", wrapped_apply)
    res = await api.api_call(
        "mds",
        "add-host",
        {"name": "H_Seam_Test", "ipv4-address": "10.220.3.1"},
        domain="Branch",
        sid=sid,
    )
    assert res.success
    assert "add-host" in seen_cmds

    script_res = await api.api_call(
        "mds",
        "run-script",
        {"script-name": "show-ver", "script": "echo ok", "targets": ["br-spb-gw-01"]},
        domain="Branch",
        sid=sid,
    )
    assert script_res.success
    task_ids = [t["task-id"] for t in script_res.data["tasks"]]
    assert task_ids and all(tid.startswith("12345678-9999-4999-8999-") for tid in task_ids)
