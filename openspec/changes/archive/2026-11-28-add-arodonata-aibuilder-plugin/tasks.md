# Tasks

## 1. Plugin Manifests, Version Sync & Build Isolation

- [x] 1.1 Create `plugins/arodonata-aibuilder/plugin.json` (using strictly allowed Antigravity top-level fields and 3 `suggestedPrompts`), `plugins/arodonata-aibuilder/.claude-plugin/plugin.json`, and `plugins/arodonata-aibuilder/README.md`, register both manifests in `[tool.commitizen].version_files` inside `pyproject.toml`, and add `@pytest.mark.spec("SCN-AIBUILD-004-1")` in `tests/unit/test_aibuilder_docs_and_packaging.py` verifying manifest fields, version parity with `arodonata.__version__`, Commitizen registration, and absence of `mcp_config.json` (`uv run pytest tests/unit/test_aibuilder_docs_and_packaging.py` and `npx markdownlint-cli plugins/arodonata-aibuilder/README.md`)
- [x] 1.2 Add `@pytest.mark.spec("SCN-AIBUILD-001-2")` in `tests/unit/test_aibuilder_docs_and_packaging.py` exercising Hatchling `WheelBuilder` and `SdistBuilder` against `pyproject.toml` with `plugins/arodonata-aibuilder/` present on disk to assert `wheel` includes only `arodonata` Python artifacts/metadata and `sdist` excludes every entry under `plugins/` and `docs-notebooklm/` (`uv run pytest tests/unit/test_aibuilder_docs_and_packaging.py`)

## 2. Primary Skill & Deterministic Reference Synchronization

- [x] 2.1 Add `PLUGIN_REFS_DIR` and `sync_plugin_references(target_dir: Path | None = None)` in `docs/scripts/build_notebooklm_docs.py` (invoked from `main()`) to synchronize `sdk-quickref.md`, `checkpoint-api-quirks.md`, and `checkpoint-ops-quirks.md` into `plugins/arodonata-aibuilder/skills/arodonata-aibuilder/references/`, run `uv run python docs/scripts/build_notebooklm_docs.py`, ensure zero `markdownlint-cli` issues on synced files, and add `@pytest.mark.spec("SCN-AIBUILD-005-1")` in `tests/unit/test_aibuilder_docs_and_packaging.py` (`uv run pytest tests/unit/test_aibuilder_docs_and_packaging.py` and `npx markdownlint-cli "plugins/**/*.md"`)
- [x] 2.2 Author `plugins/arodonata-aibuilder/skills/arodonata-aibuilder/SKILL.md` plus hand-authored `references/cli-architecture-and-arlogi.md` and `references/replay-testing-guide.md`, and add `@pytest.mark.spec("SCN-AIBUILD-004-2")` and `@pytest.mark.spec("SCN-AIBUILD-005-2")` in `tests/unit/test_aibuilder_docs_and_packaging.py` verifying `SKILL.md` frontmatter, valid relative `references/`/`templates/` links, preservation of hand-authored files across `sync_plugin_references()`, and absence of live secrets/SIDs (`uv run pytest tests/unit/test_aibuilder_docs_and_packaging.py` and `npx markdownlint-cli "plugins/**/*.md"`)

## 3. Verified Starter Templates & Repository Documentation

- [x] 3.1 Author `templates/cli_script_pep723.py`, `templates/cli_project_pyproject.toml`, and `templates/test_script_replay.py` under `plugins/arodonata-aibuilder/skills/arodonata-aibuilder/templates/`, and add `@pytest.mark.spec("SCN-AIBUILD-006-1")` and `@pytest.mark.spec("SCN-AIBUILD-006-2")` in `tests/unit/test_aibuilder_docs_and_packaging.py` verifying AST/TOML validity, PEP 723 + `arlogi` + `--dry-run` + `Asset` classification conventions, `ruff` compliance, and live offline execution of `test_script_replay.py` against `FileReplayApiMock` (`uv run ruff check plugins` and `uv run pytest tests/unit/test_aibuilder_docs_and_packaging.py`)
- [x] 3.2 Document `plugins/arodonata-aibuilder/` and reference synchronization in `README.md` and `AGENTS.md`, re-run `uv run python docs/scripts/build_notebooklm_docs.py`, and verify `npx markdownlint-cli README.md AGENTS.md "plugins/**/*.md"` and `uv run pytest tests/unit/test_aibuilder_docs_and_packaging.py` pass

## 4. End-to-End Quality & Traceability Verification

- [x] 4.1 Run full repository quality gates (`uv run ruff check .`, `uv run ruff format --check .`, `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --ignore "docs/_audit_/**" --fix`, `uv run mypy src`, `openspec schema validate arodonata`, `openspec validate --changes --strict --no-interactive`, `openspec validate --specs --strict --no-interactive`, `uv run python scripts/check_spec_traceability.py`, and `uv run pytest`) and verify zero errors

## Workflow follow-up

- Sync `specs/ai-builder/spec.md` into `openspec/specs/ai-builder/spec.md`, archive `add-arodonata-aibuilder-plugin`, regenerate `docs-notebooklm/`, update `CHANGELOG.md`, and create a checkpoint commit on `feat/arodonata-aibuilder`.
- Proceed to Step 3 on the roadmap: OpenSpec change `add-arodonata-aibuilder-playbooks` for end-to-end English playbooks validated against `arodonata.testing`.
