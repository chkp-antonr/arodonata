# Proposal

## Why

With Check Point API and operational quirk documentation, native `Asset` role and platform classification, and deterministic `05-sdk-quickref.md` generation in place, AI coding agents across Antigravity, Claude Code, Codex CLI, Cursor, and Gemini CLI still lack an installable, self-contained plugin bundle that teaches them how to scaffold, secure, and replay-test lightweight Check Point automation scripts on top of Arodonata v2 and `arlogi` without hallucinating SDK signatures or bloating Python package distributions.

## What Changes

- Create the repository-hosted multi-agent plugin `plugins/arodonata-aibuilder/` containing Antigravity (`plugin.json` using strictly supported top-level fields), Claude Code (`.claude-plugin/plugin.json`), an English multi-agent installation `README.md`, and a single primary skill `skills/arodonata-aibuilder/SKILL.md`.
- Extend `docs/scripts/build_notebooklm_docs.py` with `sync_plugin_references()` so `sdk-quickref.md`, `checkpoint-api-quirks.md`, and `checkpoint-ops-quirks.md` are deterministically synchronized into `plugins/arodonata-aibuilder/skills/arodonata-aibuilder/references/` (with resolved snippets and zero drift) alongside hand-authored `cli-architecture-and-arlogi.md` and `replay-testing-guide.md`.
- Add verified Python 3.13 / `uv` starter templates under `plugins/arodonata-aibuilder/skills/arodonata-aibuilder/templates/` (`cli_script_pep723.py`, `cli_project_pyproject.toml`, `test_script_replay.py`) exercising `ArodonataClient`, native `Asset` role/platform classification, `arlogi`, `--dry-run`, and offline `FileReplayApiMock` tests.
- Register both plugin manifest files in `[tool.commitizen].version_files` inside `pyproject.toml`, document `plugins/arodonata-aibuilder/` in `README.md` and `AGENTS.md`, and add offline unit tests verifying manifest schema/version parity, real Hatchling `wheel`/`sdist` exclusion of `plugins/` and `docs-notebooklm/`, byte-identical reference sync, secret hygiene, and live offline execution of the starter replay template.

## Capabilities

### New Capabilities

<!-- None -->

### Modified Capabilities

- `ai-builder`: Extend `REQ-AIBUILD-001` (`SCN-AIBUILD-001-2`) to verify real Hatchling `wheel`/`sdist` exclusion with `plugins/arodonata-aibuilder/` present on disk, and add `REQ-AIBUILD-004` (multi-agent plugin manifests and universal skill contract), `REQ-AIBUILD-005` (deterministic skill reference synchronization and security hygiene), and `REQ-AIBUILD-006` (verified runnable script and offline replay starter templates).

## Impact

- **Plugin Bundle**: `plugins/arodonata-aibuilder/` (`plugin.json`, `.claude-plugin/plugin.json`, `README.md`, `skills/arodonata-aibuilder/SKILL.md`, `references/*`, `templates/*`).
- **Tooling, Config & Docs**: `docs/scripts/build_notebooklm_docs.py`, `pyproject.toml` (`[tool.commitizen].version_files`), `README.md`, `AGENTS.md`, `docs-notebooklm/*`.
- **Tests**: `tests/unit/test_aibuilder_docs_and_packaging.py`.
- **Runtime SDK (`src/arodonata/`)**: Zero runtime code or dependency changes.
