# Design

## Context

See `proposal.md` for motivation and `specs/ai-builder/spec.md` for normative behavior contracts.

Current baseline on `feat/arodonata-aibuilder`:

1. `docs/troubleshooting/checkpoint-api-quirks.md`, `docs/troubleshooting/checkpoint-ops-quirks.md`, and deterministic `docs-notebooklm/05-sdk-quickref.md` generation in `docs/scripts/build_notebooklm_docs.py` are complete and verified.
2. Vendor-neutral `Asset` role/platform classification (`AssetRole`, `AssetPlatform`, `is_policy_target`, `is_execution_target`, `roles`/`platforms` filters) is implemented and covered by `REQ-CACHE-019`.
3. `pyproject.toml` excludes `/plugins` and `/docs-notebooklm` from `[tool.hatch.build.targets.sdist]` and restricts `[tool.hatch.build.targets.wheel]` to `packages = ["src/arodonata"]`.
4. `.ruff.toml` automatically lints all `.py` files across the repository (including upcoming `plugins/` Python templates), while `markdownlint-cli` checks all Markdown files outside `.markdownlintignore`.

## Goals / Non-Goals

**Goals:**

- Deliver a single-source-of-truth multi-agent plugin directory at `plugins/arodonata-aibuilder/` compatible with Antigravity, Claude Code, Codex CLI, Cursor, and Gemini CLI.
- Guarantee zero drift between canonical SDK signatures / Check Point quirk docs and `plugins/arodonata-aibuilder/skills/arodonata-aibuilder/references/` via `sync_plugin_references()`.
- Enforce strict Antigravity and Claude Code manifest schemas and keep plugin versions synchronized via Commitizen.
- Ship executable, Ruff-compliant starter templates verified offline against `FileReplayApiMock`, plus real Hatchling `WheelBuilder`/`SdistBuilder` exclusion tests.

**Non-Goals:**

- Bundling `mcp_config.json` inside `plugins/arodonata-aibuilder/` (management endpoints, credentials, and TLS trust stores vary per user environment).
- Authoring end-to-end English operational playbooks and their replay-emulator test suite (scheduled for Step 3: `add-arodonata-aibuilder-playbooks`).
- Modifying `src/arodonata/` runtime code or adding PyPI package dependencies.

## Decisions

### 1. Multi-Agent Manifest Layout (`plugin.json` + `.claude-plugin/plugin.json` + Universal `skills/`)

- **Choice**: Place `plugin.json` (Antigravity) and `.claude-plugin/plugin.json` (Claude Code) alongside `README.md` at `plugins/arodonata-aibuilder/`, with the portable skill rooted at `plugins/arodonata-aibuilder/skills/arodonata-aibuilder/SKILL.md`.
- **Rationale**:
  - Antigravity recognizes `plugin.json` with a strict top-level allowlist (`name`, `displayName`, `description`, `version`, `author`, `homepage`, `repository`, `suggestedPrompts` with up to 3 prompts; unknown top-level keys are silently discarded).
  - Claude Code reads `.claude-plugin/plugin.json` (`name`, `description`, `version`, `author`, `homepage`, `repository`, `license`, `keywords`).
  - Codex CLI, Cursor, and Gemini CLI consume the portable `skills/arodonata-aibuilder/` directory directly (documented in `plugins/arodonata-aibuilder/README.md`).
- **Alternatives considered**: Shipping only `skills/arodonata-aibuilder/SKILL.md` without manifests was rejected because Antigravity and Claude Code lose native plugin metadata, starter prompts, and single-unit enable/disable packaging.

### 2. Single Cohesive Primary Skill (`arodonata-aibuilder`) with Progressive Disclosure

- **Choice**: Author one focused skill `arodonata-aibuilder` (`SKILL.md` kept concise around ~120–180 lines) encoding "Delegate, Never Duplicate", the 3-Tier Check Point API Lookup Ladder, a 5-step script-authoring workflow, security/SID hygiene, and explicit links to `references/*.md` and `templates/*`.
- **Rationale**: Real Check Point scripts frequently combine inventory/classification, `run-script` / Gaia CLI parsing, `arlogi` setup, and offline replay testing; a single skill avoids ambiguous multi-skill routing while keeping initial token footprint small via progressive disclosure.
- **Alternatives considered**: Splitting into separate inventory, CPCRUD, and Gaia-ops skills was rejected as premature fragmentation that risks overlapping triggers and duplicated rules.

### 3. Deterministic Reference Synchronization (`sync_plugin_references` in `build_notebooklm_docs.py`)

- **Choice**: Add `PLUGIN_REFS_DIR` and `sync_plugin_references(target_dir: Path | None = None) -> list[Path]` in `docs/scripts/build_notebooklm_docs.py`, called automatically by `main()`, writing:
  - `sdk-quickref.md` (exact output of `build_sdk_quickref()`, byte-identical to `docs-notebooklm/05-sdk-quickref.md`)
  - `checkpoint-api-quirks.md` (`_resolve_snippets(...)` of `docs/troubleshooting/checkpoint-api-quirks.md`)
  - `checkpoint-ops-quirks.md` (`_resolve_snippets(...)` of `docs/troubleshooting/checkpoint-ops-quirks.md`)
  while leaving hand-authored `cli-architecture-and-arlogi.md` and `replay-testing-guide.md` untouched.
- **Rationale**: Eliminates manual copy-paste drift whenever `src/arodonata` signatures or troubleshooting quirk docs evolve, and guarantees every synced file remains valid under `npx markdownlint-cli "plugins/**/*.md"`.

### 4. Real Hatchling Build Verification & Executable Starter Templates

- **Choice**:
  - Test actual `hatchling.builders.wheel.WheelBuilder` and `hatchling.builders.sdist.SdistBuilder` file inclusion lists in `SCN-AIBUILD-001-2` once `plugins/arodonata-aibuilder/` exists on disk.
  - Keep `templates/cli_script_pep723.py` and `templates/test_script_replay.py` compliant with `.ruff.toml`, and execute `test_script_replay.py` directly inside pytest (`SCN-AIBUILD-006-2`) against `FileReplayApiMock`.
- **Rationale**: Ensures starter templates do not silently rot when `ArodonataClient`, `Asset`, or `FileReplayApiMock` evolve, and proves `pip`/`uv` package builds remain free of plugin assets.

### 5. Version Parity via Commitizen (`pyproject.toml`)

- **Choice**: Register `plugins/arodonata-aibuilder/plugin.json:^  "version":` and `plugins/arodonata-aibuilder/.claude-plugin/plugin.json:^  "version":` in `[tool.commitizen].version_files` inside `pyproject.toml`.
- **Rationale**: Keeps plugin manifest versions automatically aligned with `arodonata.__version__` across releases without manual edits.

## Risks / Trade-offs

- **[Risk] Generated `sdk-quickref.md` violates `markdownlint-cli` inside `plugins/`** → Mitigation: Validate `npx markdownlint-cli "plugins/**/*.md"` during implementation and adjust `build_sdk_quickref()` formatting if any rule triggers rather than adding `plugins/` to `.markdownlintignore`.
- **[Risk] Starter Python templates fail `ruff check` or drift from SDK APIs** → Mitigation: Run `uv run ruff check .` across the repo (including `plugins/`) and execute `templates/test_script_replay.py` inside `tests/unit/test_aibuilder_docs_and_packaging.py`.
- **[Risk] Synced `references/*.md` files drift after editing `src/` or `docs/troubleshooting/`** → Mitigation: Enforce byte-identical comparison in `SCN-AIBUILD-005-1` and run `sync_plugin_references()` inside `docs/scripts/build_notebooklm_docs.py:main()`.
