# Spec Delta

## MODIFIED Requirements

### Requirement: Python Distribution Packaging Isolation

**ID**: REQ-AIBUILD-001\
**Intent**: Keep `uv add arodonata` and `pip install arodonata` lightweight and free of repository-hosted AI skill packs or large LLM bundles.\
**Non-goals**: Publishing `plugins/arodonata-aibuilder` as an importable Python runtime module inside `arodonata`.

Both wheel and source distribution (`sdist`) builds of the `arodonata` package MUST exclude repository-hosted `plugins/` directories and `docs-notebooklm/` knowledge bundles so installing `arodonata` distributes strictly the Python SDK artifacts.

#### Scenario: SCN-AIBUILD-001-1 — Wheel and sdist exclude AI builder plugins and NotebookLM bundles

- **GIVEN** the repository contains `docs-notebooklm/` bundles and `plugins/` skill directories
- **WHEN** wheel and source distribution package targets are inspected or built from `pyproject.toml`
- **THEN** wheel packages SHALL include only `src/arodonata`
- **AND** source distributions SHALL exclude `plugins/` and `docs-notebooklm/`

#### Scenario: SCN-AIBUILD-001-2 — Built wheel and sdist artifacts exclude populated plugins and docs-notebooklm directories

- **GIVEN** `plugins/arodonata-aibuilder/` and `docs-notebooklm/` contain tracked files in the repository
- **WHEN** Hatchling wheel and sdist build file sets are constructed from `pyproject.toml`
- **THEN** the wheel artifact SHALL include only `arodonata` Python package files and package metadata
- **AND** the sdist artifact SHALL exclude every entry under `plugins/` and `docs-notebooklm/`

## ADDED Requirements

### Requirement: Multi-Agent Plugin Manifest and Skill Entry Contract

**ID**: REQ-AIBUILD-004\
**Intent**: Ship a portable, version-synchronized multi-agent plugin bundle usable in Antigravity, Claude Code, Codex CLI, Cursor, and Gemini CLI.\
**Non-goals**: Bundling pre-configured live Check Point MCP server credentials or environment-specific TLS trust stores inside the plugin.

The repository MUST provide a self-contained plugin at `plugins/arodonata-aibuilder/` containing an Antigravity `plugin.json` using strictly supported top-level fields, a Claude Code `.claude-plugin/plugin.json` manifest synchronized with `arodonata.__version__`, an English multi-agent `README.md`, and a portable `skills/arodonata-aibuilder/SKILL.md` entry point without bundling unconfigured MCP server definitions.

#### Scenario: SCN-AIBUILD-004-1 — Antigravity and Claude Code manifests match schema and package version

- **GIVEN** `plugins/arodonata-aibuilder/plugin.json` and `plugins/arodonata-aibuilder/.claude-plugin/plugin.json` exist in the repository
- **WHEN** both JSON manifests are parsed and compared against `arodonata.__version__` and `pyproject.toml` commitizen configuration
- **THEN** `plugin.json` SHALL contain only allowed Antigravity top-level fields (`name`, `displayName`, `description`, `version`, `author`, `homepage`, `repository`, `suggestedPrompts`) with `name == "arodonata-aibuilder"` and up to three non-empty `suggestedPrompts`
- **AND** both manifests SHALL match `arodonata.__version__`, appear in `[tool.commitizen].version_files`, and omit any bundled `mcp_config.json`

#### Scenario: SCN-AIBUILD-004-2 — Universal skill entry point exposes valid frontmatter and progressive-disclosure links

- **GIVEN** `plugins/arodonata-aibuilder/skills/arodonata-aibuilder/SKILL.md` and `plugins/arodonata-aibuilder/README.md` exist
- **WHEN** YAML frontmatter and relative Markdown references inside `SKILL.md` are inspected
- **THEN** `SKILL.md` SHALL declare `name: arodonata-aibuilder` and a non-empty `description` covering Check Point automation with Arodonata
- **AND** every referenced `references/*.md` and `templates/*` path SHALL resolve to an existing file inside the skill directory

### Requirement: Deterministic Skill Reference Synchronization

**ID**: REQ-AIBUILD-005\
**Intent**: Keep skill-bundled SDK signatures and Check Point quirk references synchronized with `src/arodonata` and `docs/troubleshooting/` without manual copy-paste drift.\
**Non-goals**: Overwriting hand-authored CLI architecture or replay-testing skill guides during doc rebuilds.

The documentation bundle build MUST deterministically synchronize `sdk-quickref.md`, `checkpoint-api-quirks.md`, and `checkpoint-ops-quirks.md` into `plugins/arodonata-aibuilder/skills/arodonata-aibuilder/references/` with all snippets resolved and byte-identical to canonical documentation sources, while preserving hand-authored CLI and replay-testing references free of live secrets or session identifiers.

#### Scenario: SCN-AIBUILD-005-1 — Synced skill references match canonical quickref and quirk sources byte-for-byte

- **GIVEN** canonical documentation in `docs/troubleshooting/` and the current `src/arodonata` source tree
- **WHEN** `sync_plugin_references()` runs during the documentation bundle build
- **THEN** `references/sdk-quickref.md` SHALL be byte-identical to `docs-notebooklm/05-sdk-quickref.md`
- **AND** `references/checkpoint-api-quirks.md` and `references/checkpoint-ops-quirks.md` SHALL match their snippet-resolved canonical sources with zero `[MISSING SNIPPET:` markers

#### Scenario: SCN-AIBUILD-005-2 — Hand-authored references are preserved and satisfy security hygiene

- **GIVEN** hand-authored `references/cli-architecture-and-arlogi.md` and `references/replay-testing-guide.md` exist alongside synced references
- **WHEN** `sync_plugin_references()` executes and all Markdown files under `plugins/arodonata-aibuilder/` are inspected
- **THEN** hand-authored reference files SHALL remain intact without being overwritten or deleted
- **AND** no file under `plugins/arodonata-aibuilder/` SHALL contain live secrets, `X-chkp-sid:` headers, or private key blocks

### Requirement: Runnable Script and Offline Replay Starter Templates

**ID**: REQ-AIBUILD-006\
**Intent**: Give AI coding agents ready-to-adapt, verified Python 3.13 / `uv` CLI script and offline `FileReplayApiMock` test starters that compile and pass immediately.\
**Non-goals**: Shipping customer-specific playbooks or live SmartCenter integration harnesses inside the starter templates.

The `arodonata-aibuilder` skill MUST include verified starter templates under `templates/` providing a single-file PEP 723 `uv` script (`cli_script_pep723.py`), a multi-file `uv` project manifest (`cli_project_pyproject.toml`), and an offline replay test (`test_script_replay.py`) demonstrating `ArodonataClient`, native `Asset` classification, `arlogi`, and `FileReplayApiMock`.

#### Scenario: SCN-AIBUILD-006-1 — Starter Python and TOML templates parse cleanly and follow SDK conventions

- **GIVEN** `cli_script_pep723.py`, `cli_project_pyproject.toml`, and `test_script_replay.py` exist under `plugins/arodonata-aibuilder/skills/arodonata-aibuilder/templates/`
- **WHEN** the Python templates are parsed with `ast.parse` and the TOML template is parsed with `tomllib.loads`
- **THEN** all templates SHALL parse without syntax errors and reference `arodonata` and `arlogi`
- **AND** `cli_script_pep723.py` SHALL include a PEP 723 `# /// script` block, `arlogi.setup_logging(..., json_file_only=False)`, `--dry-run`, and native `Asset` classification filtering

#### Scenario: SCN-AIBUILD-006-2 — Starter replay template executes offline against FileReplayApiMock

- **GIVEN** `templates/test_script_replay.py` is loaded in an offline test environment with no network access
- **WHEN** its replay test coroutine executes against `FileReplayApiMock` and `ArodonataClient`
- **THEN** the test SHALL pass cleanly, verifying mocked Check Point asset/object retrieval and native `Asset` role/platform classification without live credentials
