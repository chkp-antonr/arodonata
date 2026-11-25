"""Unit tests for AI builder packaging isolation, quirk bundles, and SDK quick-reference generation."""

from __future__ import annotations

import importlib.util
import sys
import tomllib
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

import arodonata
import arodonata.testing as arodonata_testing
from arodonata import (
    ApiReferenceEngine,
    ArodonataClient,
    ArodonataSettings,
    Asset,
    ChangeReport,
    CPCRUDService,
    CPObject,
    CPService,
    DomainInfo,
    ScriptRepositoryService,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BUILD_SCRIPT_PATH = REPO_ROOT / "docs" / "scripts" / "build_notebooklm_docs.py"


def _load_build_docs_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("arodonata_build_notebooklm_docs", BUILD_SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _collect_nav_md_paths(node: Any) -> list[str]:
    paths: list[str] = []
    if isinstance(node, list):
        for item in node:
            paths.extend(_collect_nav_md_paths(item))
    elif isinstance(node, dict):
        for val in node.values():
            paths.extend(_collect_nav_md_paths(val))
    elif isinstance(node, str) and node.endswith(".md"):
        paths.append(node)
    return paths


@pytest.mark.spec("SCN-AIBUILD-001-1")
def test_wheel_and_sdist_exclude_ai_builder_plugins_and_notebooklm() -> None:
    """Verify wheel targets only `src/arodonata` and sdist excludes `plugins/` and `docs-notebooklm/`."""
    pyproject_data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    hatch_targets = pyproject_data["tool"]["hatch"]["build"]["targets"]

    wheel_cfg = hatch_targets["wheel"]
    assert wheel_cfg["packages"] == ["src/arodonata"]
    wheel_includes = [str(entry).strip("/") for entry in wheel_cfg.get("include", [])]
    assert not any(item.startswith(("plugins", "docs-notebooklm")) for item in wheel_includes)

    sdist_cfg = hatch_targets["sdist"]
    normalized_excludes = {str(entry).strip("/") for entry in sdist_cfg.get("exclude", [])}
    assert {"plugins", "docs-notebooklm", "docs/_html", "openspec", "examples"}.issubset(normalized_excludes)


@pytest.mark.spec("SCN-AIBUILD-002-1")
def test_generated_guide_bundle_and_mkdocs_include_api_and_ops_quirks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify both troubleshooting quirk docs appear in guide bundle, staging dir, and MkDocs nav."""
    api_quirks_path = REPO_ROOT / "docs" / "troubleshooting" / "checkpoint-api-quirks.md"
    ops_quirks_path = REPO_ROOT / "docs" / "troubleshooting" / "checkpoint-ops-quirks.md"
    assert api_quirks_path.is_file()
    assert ops_quirks_path.is_file()

    api_quirks = api_quirks_path.read_text(encoding="utf-8")
    ops_quirks = ops_quirks_path.read_text(encoding="utf-8")
    for body in (api_quirks, ops_quirks):
        assert "X-chkp-sid:" not in body
        assert "BEGIN PRIVATE KEY" not in body

    mod = _load_build_docs_module()
    guide_text = mod.build_guide()
    assert "[MISSING SNIPPET:" not in guide_text
    assert "source: `docs/troubleshooting/checkpoint-api-quirks.md`" in guide_text
    assert "source: `docs/troubleshooting/checkpoint-ops-quirks.md`" in guide_text
    assert "MDSM Global vs. Local" in guide_text
    assert "Single-Pass `cpinfo -y all`" in guide_text

    disk_guide = (REPO_ROOT / "docs-notebooklm" / "01-guide-and-concepts.md").read_text(encoding="utf-8")
    assert disk_guide == guide_text

    staging_dir = tmp_path / "bundle"
    monkeypatch.setattr(mod, "BUNDLE_DIR", staging_dir)
    mod.prepare_build_docs_bundle()
    staged_files = {p.name: p.read_text(encoding="utf-8") for p in staging_dir.glob("*.md")}
    assert any("MDSM Global vs. Local" in text for text in staged_files.values())
    assert any("Single-Pass `cpinfo -y all`" in text for text in staged_files.values())
    assert all("[MISSING SNIPPET:" not in text for text in staged_files.values())

    mkdocs_cfg = yaml.load((REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    nav_paths = _collect_nav_md_paths(mkdocs_cfg["nav"])
    assert "troubleshooting/checkpoint-api-quirks.md" in nav_paths
    assert "troubleshooting/checkpoint-ops-quirks.md" in nav_paths
    for rel_md in nav_paths:
        if rel_md in ("CHANGELOG.md", "LICENSE"):
            continue
        assert (REPO_ROOT / "docs" / rel_md).is_file(), f"Missing MkDocs nav file: docs/{rel_md}"


@pytest.mark.spec("SCN-AIBUILD-002-2")
def test_generated_examples_bundle_includes_all_tracked_examples() -> None:
    """Verify `03-examples-and-recipes.md` embeds every tracked `01`..`13` example in deterministic order."""
    example_paths = sorted((REPO_ROOT / "docs" / "examples").glob("[0-9][0-9]-*.md"))
    prefixes = [p.name[:2] for p in example_paths]
    assert prefixes[:13] == [f"{idx:02d}" for idx in range(1, 14)]

    mod = _load_build_docs_module()
    discovered = mod.discover_example_md_files()
    discovered_relpaths = [rel for _, rel in discovered]
    assert discovered_relpaths[0] == "examples/index.md"
    assert discovered_relpaths[1:] == [f"examples/{p.name}" for p in example_paths]

    examples_text = mod.build_examples()
    assert "[MISSING SNIPPET:" not in examples_text

    positions = [examples_text.index(f"source: `docs/examples/{p.name}`") for p in example_paths]
    assert positions == sorted(positions)

    disk_examples = (REPO_ROOT / "docs-notebooklm" / "03-examples-and-recipes.md").read_text(encoding="utf-8")
    assert disk_examples == examples_text


@pytest.mark.spec("SCN-AIBUILD-003-1")
def test_sdk_quickref_matches_exports_and_is_deterministic() -> None:
    """Verify `build_sdk_quickref()` matches live exports, signatures, fields, and is byte-identical."""
    mod = _load_build_docs_module()
    out1 = mod.build_sdk_quickref()
    out2 = mod.build_sdk_quickref()
    assert out1 == out2

    disk_quickref = (REPO_ROOT / "docs-notebooklm" / "05-sdk-quickref.md").read_text(encoding="utf-8")
    assert disk_quickref == out1
    assert arodonata.__version__ in out1

    for method_name in (
        "refresh_objects",
        "query_objects",
        "write_session",
        "run_repository_script",
        "reconcile_gateway_topology",
        "collect_change_report",
    ):
        assert hasattr(ArodonataClient, method_name)
        assert f"def {method_name}(" in out1

    for field_name in ("mgmt_names", "database_url", "tls_trust", "cprid_script_mode"):
        assert field_name in ArodonataSettings.model_fields
        assert f"{field_name}:" in out1

    for model_cls in (Asset, CPObject, CPService, DomainInfo, ChangeReport):
        assert model_cls.__name__ in out1
        for key_field in ("uid", "name") if "uid" in model_cls.model_fields else ("format_version", "sessions"):
            assert key_field in model_cls.model_fields
            assert f"{key_field}:" in out1

    assert hasattr(ScriptRepositoryService, "ensure_repository_script")
    assert "def ensure_repository_script(" in out1
    assert hasattr(CPCRUDService, "plan")
    assert "def plan(" in out1
    assert hasattr(ApiReferenceEngine, "validate_payload")
    assert "def validate_payload(" in out1

    for export_name in (
        "FileReplayApiMock",
        "FileReplayCliMock",
        "CheckPointReplayHttpServer",
        "ensure_enterprise_raw_dataset",
    ):
        assert export_name in arodonata_testing.__all__
        assert export_name in out1

    assert "arlogi.setup_logging(" in out1
    assert "json_file_only=False" in out1
    assert "3-Tier Check Point API Lookup Ladder" in out1
