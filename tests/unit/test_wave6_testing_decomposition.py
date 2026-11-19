"""Architectural, DRY, cold-import, and dataset parity tests for Wave 6 testing decomposition."""

from __future__ import annotations

import ast
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
