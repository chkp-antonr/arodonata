"""Unit tests for AI builder packaging isolation, quirk bundles, and SDK quick-reference generation."""

from __future__ import annotations

import ast
import importlib.util
import json
import re
import subprocess
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


@pytest.mark.spec("SCN-AIBUILD-003-2")
def test_sdk_quickref_valid_lambda_defaults_and_full_testing_methods() -> None:
    """Verify lambda default_factory unparsing produces valid Python and testing classes are not truncated."""
    mod = _load_build_docs_module()
    quickref = mod.build_sdk_quickref()
    disk_quickref = (REPO_ROOT / "docs-notebooklm" / "05-sdk-quickref.md").read_text(encoding="utf-8")
    assert disk_quickref == quickref

    # No invalid `lambda: ...()` syntax anywhere in generated quickref
    assert "lambda:" not in quickref
    tls_line = next(line for line in quickref.splitlines() if line.startswith("tls_known_hosts_path:"))
    assert "lambda" not in tls_line
    default_expr = tls_line.split(" = ", 1)[1]
    ast.parse(default_expr, mode="eval")

    replay_api_sigs = mod._extract_class_method_sigs("testing/replay_mock.py", "FileReplayApiMock")
    mock_http_sigs = mod._extract_class_method_sigs("testing/mock_server.py", "CheckPointReplayHttpServer")
    assert len(replay_api_sigs) > 8
    assert len(mock_http_sigs) > 8
    for sig in replay_api_sigs:
        assert sig in quickref, f"Missing FileReplayApiMock method in quickref: {sig}"
    for sig in mock_http_sigs:
        assert sig in quickref, f"Missing CheckPointReplayHttpServer method in quickref: {sig}"


def _collect_hatchling_build_paths(repo_root: Path) -> tuple[list[str], list[str]]:
    """Collect wheel and sdist distribution paths via Hatchling (in-process or offline `uv` tool env)."""
    try:
        from hatchling.builders.sdist import SdistBuilder
        from hatchling.builders.wheel import WheelBuilder
    except ImportError:
        script = (
            "import json; "
            "from hatchling.builders.wheel import WheelBuilder; "
            "from hatchling.builders.sdist import SdistBuilder; "
            "wb = WheelBuilder('.'); "
            "sb = SdistBuilder('.'); "
            "print(json.dumps({"
            "'wheel': [f.distribution_path for f in wb.recurse_included_files()], "
            "'sdist': [f.distribution_path for f in sb.recurse_included_files()]"
            "}))"
        )
        proc = subprocess.run(
            ["uv", "run", "--with", "hatchling", "--offline", "python", "-c", script],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(proc.stdout)
        return list(data["wheel"]), list(data["sdist"])

    wb = WheelBuilder(str(repo_root))
    sb = SdistBuilder(str(repo_root))
    return (
        [f.distribution_path for f in wb.recurse_included_files()],
        [f.distribution_path for f in sb.recurse_included_files()],
    )


@pytest.mark.spec("SCN-AIBUILD-001-2")
def test_built_wheel_and_sdist_exclude_populated_plugins_and_notebooklm() -> None:
    """Verify real Hatchling wheel and sdist file sets exclude populated `plugins/` and `docs-notebooklm/`."""
    plugin_root = REPO_ROOT / "plugins" / "arodonata-aibuilder"
    assert (plugin_root / "plugin.json").is_file()
    assert (plugin_root / "README.md").is_file()
    assert (REPO_ROOT / "docs-notebooklm" / "05-sdk-quickref.md").is_file()

    wheel_files, sdist_files = _collect_hatchling_build_paths(REPO_ROOT)

    assert wheel_files
    assert "arodonata/__init__.py" in wheel_files
    assert all(path.startswith("arodonata/") or ".dist-info/" in path for path in wheel_files)
    assert not any(path.startswith(("plugins/", "docs-notebooklm/")) for path in wheel_files)

    assert sdist_files
    assert "pyproject.toml" in sdist_files
    assert "src/arodonata/__init__.py" in sdist_files
    assert not any(Path(path).parts[0] in {"plugins", "docs-notebooklm"} for path in sdist_files if Path(path).parts)


@pytest.mark.spec("SCN-AIBUILD-004-1")
def test_plugin_manifests_match_schema_version_and_commitizen() -> None:
    """Verify Antigravity and Claude Code manifests match schema, package version, and Commitizen config."""
    plugin_root = REPO_ROOT / "plugins" / "arodonata-aibuilder"
    ag_manifest_path = plugin_root / "plugin.json"
    cc_manifest_path = plugin_root / ".claude-plugin" / "plugin.json"
    readme_path = plugin_root / "README.md"

    assert ag_manifest_path.is_file()
    assert cc_manifest_path.is_file()
    assert readme_path.is_file()
    assert not list(plugin_root.rglob("mcp_config.json"))

    ag_data = json.loads(ag_manifest_path.read_text(encoding="utf-8"))
    cc_data = json.loads(cc_manifest_path.read_text(encoding="utf-8"))

    allowed_ag_fields = {
        "name",
        "displayName",
        "description",
        "version",
        "author",
        "homepage",
        "repository",
        "suggestedPrompts",
    }
    assert set(ag_data.keys()).issubset(allowed_ag_fields)
    assert ag_data["name"] == "arodonata-aibuilder"
    assert cc_data["name"] == "arodonata-aibuilder"
    assert ag_data["version"] == arodonata.__version__
    assert cc_data["version"] == arodonata.__version__

    prompts = ag_data["suggestedPrompts"]
    assert isinstance(prompts, list) and 1 <= len(prompts) <= 3
    assert all(isinstance(item, str) and item.strip() for item in prompts)

    pyproject_data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version_files = pyproject_data["tool"]["commitizen"]["version_files"]
    for rel_manifest, manifest_path in (
        ("plugins/arodonata-aibuilder/plugin.json", ag_manifest_path),
        ("plugins/arodonata-aibuilder/.claude-plugin/plugin.json", cc_manifest_path),
    ):
        matches = [entry for entry in version_files if entry.startswith(f"{rel_manifest}:")]
        assert len(matches) == 1, f"Expected Commitizen entry for {rel_manifest}"
        pattern = matches[0].split(":", 1)[1]
        text = manifest_path.read_text(encoding="utf-8")
        assert re.search(pattern, text, re.MULTILINE), f"Commitizen pattern {pattern!r} did not match {rel_manifest}"


@pytest.mark.spec("SCN-AIBUILD-005-1")
def test_synced_plugin_references_match_canonical_sources_byte_for_byte(tmp_path: Path) -> None:
    """Verify synced skill references match canonical quickref and quirk sources byte-for-byte."""
    mod = _load_build_docs_module()
    plugin_refs_dir = REPO_ROOT / "plugins" / "arodonata-aibuilder" / "skills" / "arodonata-aibuilder" / "references"

    temp_refs_dir = tmp_path / "refs"
    written = mod.sync_plugin_references(temp_refs_dir)
    assert len(written) == 3

    expected_bytes = {
        "sdk-quickref.md": (REPO_ROOT / "docs-notebooklm" / "05-sdk-quickref.md").read_bytes(),
        "checkpoint-api-quirks.md": mod._resolve_snippets(
            (REPO_ROOT / "docs" / "troubleshooting" / "checkpoint-api-quirks.md").read_text(encoding="utf-8")
        ).encode("utf-8"),
        "checkpoint-ops-quirks.md": mod._resolve_snippets(
            (REPO_ROOT / "docs" / "troubleshooting" / "checkpoint-ops-quirks.md").read_text(encoding="utf-8")
        ).encode("utf-8"),
    }
    assert expected_bytes["sdk-quickref.md"] == mod.build_sdk_quickref().encode("utf-8")

    for filename, expected in expected_bytes.items():
        disk_path = plugin_refs_dir / filename
        temp_path = temp_refs_dir / filename
        assert disk_path.is_file(), f"Missing synced reference: {disk_path}"
        assert disk_path.read_bytes() == expected
        assert temp_path.read_bytes() == expected
        assert "[MISSING SNIPPET:" not in disk_path.read_text(encoding="utf-8")


@pytest.mark.spec("SCN-AIBUILD-004-2")
def test_skill_frontmatter_and_progressive_disclosure_links() -> None:
    """Verify `SKILL.md` frontmatter and resolve every relative `references/` and `templates/` link."""
    plugin_root = REPO_ROOT / "plugins" / "arodonata-aibuilder"
    skill_dir = plugin_root / "skills" / "arodonata-aibuilder"
    skill_path = skill_dir / "SKILL.md"
    readme_path = plugin_root / "README.md"

    assert readme_path.is_file()
    assert skill_path.is_file()

    raw_text = skill_path.read_text(encoding="utf-8")
    fm_match = re.match(r"^---\n(.*?)\n---\n", raw_text, re.DOTALL)
    assert fm_match is not None, "SKILL.md must begin with YAML frontmatter"
    frontmatter = yaml.safe_load(fm_match.group(1))
    assert isinstance(frontmatter, dict)
    assert frontmatter.get("name") == "arodonata-aibuilder"
    description = frontmatter.get("description")
    assert isinstance(description, str) and description.strip()
    assert "Check Point" in description
    assert "Arodonata" in description

    rel_links = re.findall(r"\[[^\]]+\]\(((?:references|templates)/[^)#\s]+)\)", raw_text)
    assert rel_links, "SKILL.md must link to references/ and templates/"
    assert any(link.startswith("references/") for link in rel_links)
    assert any(link.startswith("templates/") for link in rel_links)
    for rel_link in rel_links:
        target = (skill_dir / rel_link).resolve()
        assert target.is_file(), f"Broken relative link in SKILL.md: {rel_link}"
        assert target.is_relative_to(skill_dir.resolve())


@pytest.mark.spec("SCN-AIBUILD-005-2")
def test_hand_authored_references_preserved_and_plugin_secret_hygiene(tmp_path: Path) -> None:
    """Verify hand-authored references survive `sync_plugin_references()` and plugin contains no secrets/SIDs."""
    mod = _load_build_docs_module()
    plugin_root = REPO_ROOT / "plugins" / "arodonata-aibuilder"
    refs_dir = plugin_root / "skills" / "arodonata-aibuilder" / "references"

    hand_authored = ("cli-architecture-and-arlogi.md", "replay-testing-guide.md")
    sandbox_refs = tmp_path / "refs"
    sandbox_refs.mkdir()
    before_bytes: dict[str, bytes] = {}
    for name in hand_authored:
        src_path = refs_dir / name
        assert src_path.is_file(), f"Missing hand-authored reference: {src_path}"
        content = src_path.read_bytes()
        before_bytes[name] = content
        (sandbox_refs / name).write_bytes(content)

    mod.sync_plugin_references(sandbox_refs)
    for name in hand_authored:
        assert (sandbox_refs / name).read_bytes() == before_bytes[name]

    forbidden_patterns = (
        re.compile(r"X-chkp-sid\s*:", re.IGNORECASE),
        re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
        re.compile(
            r"(?:api_key|password)\s*=\s*['\"](?!offline-replay-placeholder|dummy|mock-key)[A-Za-z0-9+/=_-]{16,}['\"]"
        ),
    )
    for path in sorted(plugin_root.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        body = path.read_text(encoding="utf-8")
        for pat in forbidden_patterns:
            assert not pat.search(body), f"Secret/SID hygiene violation ({pat.pattern}) in {path}"


@pytest.mark.spec("SCN-AIBUILD-006-1")
def test_starter_templates_parse_cleanly_and_follow_sdk_conventions() -> None:
    """Verify starter Python and TOML templates parse cleanly and encode PEP 723, arlogi, dry-run, and Asset rules."""
    templates_dir = REPO_ROOT / "plugins" / "arodonata-aibuilder" / "skills" / "arodonata-aibuilder" / "templates"
    cli_script_path = templates_dir / "cli_script_pep723.py"
    pyproject_tmpl_path = templates_dir / "cli_project_pyproject.toml"
    replay_test_path = templates_dir / "test_script_replay.py"

    for path in (cli_script_path, pyproject_tmpl_path, replay_test_path):
        assert path.is_file(), f"Missing template: {path}"

    cli_source = cli_script_path.read_text(encoding="utf-8")
    replay_source = replay_test_path.read_text(encoding="utf-8")
    pyproject_text = pyproject_tmpl_path.read_text(encoding="utf-8")

    ast.parse(cli_source, filename=str(cli_script_path))
    ast.parse(replay_source, filename=str(replay_test_path))
    parsed_toml = tomllib.loads(pyproject_text)

    deps = parsed_toml["project"]["dependencies"]
    assert any(dep.startswith("arodonata") for dep in deps)
    assert any(dep.startswith("arlogi") for dep in deps)

    for text in (cli_source, replay_source):
        assert "arodonata" in text
        assert "arlogi" in text

    assert "# /// script" in cli_source
    assert "# ///" in cli_source
    assert "arlogi.setup_logging(" in cli_source
    assert "json_file_only=False" in cli_source
    assert "--dry-run" in cli_source
    assert "roles=" in cli_source
    assert "platforms=" in cli_source
    assert "is_policy_target" in cli_source
    assert "is_execution_target" in cli_source


@pytest.mark.spec("SCN-AIBUILD-006-2")
@pytest.mark.asyncio
async def test_starter_replay_template_executes_offline_against_file_replay_mock() -> None:
    """Verify `templates/test_script_replay.py` executes cleanly offline against `FileReplayApiMock`."""
    replay_test_path = (
        REPO_ROOT
        / "plugins"
        / "arodonata-aibuilder"
        / "skills"
        / "arodonata-aibuilder"
        / "templates"
        / "test_script_replay.py"
    )
    spec = importlib.util.spec_from_file_location("arodonata_plugin_template_replay", replay_test_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    await module.test_offline_replay_inventory_and_classification()


@pytest.mark.spec("SCN-AIBUILD-007-1")
def test_scn_aibuild_007_1_replay_docs_and_governance_ports_match_sdk() -> None:
    """SCN-AIBUILD-007-1: replay-testing-guide.md, AGENTS.md, and openspec/config.yaml match live SDK and testing contracts."""
    guide_text = (
        REPO_ROOT
        / "plugins"
        / "arodonata-aibuilder"
        / "skills"
        / "arodonata-aibuilder"
        / "references"
        / "replay-testing-guide.md"
    ).read_text(encoding="utf-8")
    assert '"read_only"' not in guide_text
    assert '"deny"' not in guide_text
    assert "server.base_url" not in guide_text
    for token in (
        '"write"',
        '"read"',
        '"none"',
        "mgmt_ip",
        "mgmt_port",
        "tls_trust",
        "tls_fingerprints",
        "server.snapshot_state()",
    ):
        assert token in guide_text, f"replay-testing-guide.md missing {token!r}"

    agents_text = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
    config_text = (REPO_ROOT / "openspec" / "config.yaml").read_text(encoding="utf-8")
    for doc_name, text in (("AGENTS.md", agents_text), ("openspec/config.yaml", config_text)):
        for port_name in (
            "ApiPort",
            "LockPort",
            "CachePort",
            "DomainCachePort",
            "SidCachePort",
            "SyncStatePort",
            "ObjectCachePort",
            "ServiceCachePort",
            "AssetCachePort",
            "TopologyCachePort",
            "RulebaseCachePort",
        ):
            assert port_name in text, f"{doc_name} missing port reference {port_name!r}"
