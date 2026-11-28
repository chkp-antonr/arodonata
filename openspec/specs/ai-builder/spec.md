# ai-builder Specification

## Purpose

Defines packaging isolation, consolidated Check Point quirk knowledge bundles, compact SDK quick-reference generation, and multi-agent skill/playbook contracts for authoring lightweight Check Point automation scripts on top of Arodonata and `arlogi`.

## Requirements

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

### Requirement: Check Point API and Operational Quirks Knowledge Bundle

**ID**: REQ-AIBUILD-002\
**Intent**: Ensure LLM context bundles and documentation sites carry authoritative Check Point API and operational automation pitfalls in one synchronized build.\
**Non-goals**: Modifying runtime `ArodonataClient` transport or asset classification logic.

The documentation bundle build MUST include Check Point Management API quirks, Check Point operational automation quirks (gateway/cluster/VSX boundaries, Gaia `python3` vs. Gaia Embedded `sh` execution, `cpinfo`/`cplp`/CPUSE collection, CDT workflows, MDSM Global/Local rules, and CLI SQLite + `arlogi` usage), and all tracked runnable examples without embedding live secrets or session identifiers.

#### Scenario: SCN-AIBUILD-002-1 — Generated guide bundle includes API and operational quirks

- **GIVEN** `docs/troubleshooting/checkpoint-api-quirks.md` and `docs/troubleshooting/checkpoint-ops-quirks.md` exist in the documentation tree
- **WHEN** the documentation bundle build executes
- **THEN** `docs-notebooklm/01-guide-and-concepts.md` and the portable HTML staging directory SHALL include both quirk documents with resolved snippets
- **AND** MkDocs navigation SHALL expose both troubleshooting guides without broken links

#### Scenario: SCN-AIBUILD-002-2 — Generated examples bundle includes all tracked runnable examples

- **GIVEN** tracked example guides exist in `docs/examples/` (including `01` through `13`)
- **WHEN** the documentation bundle build executes
- **THEN** `docs-notebooklm/03-examples-and-recipes.md` SHALL embed every tracked example guide in deterministic order

### Requirement: Deterministic Agent SDK Quick-Reference Generation

**ID**: REQ-AIBUILD-003\
**Intent**: Provide AI coding agents with a compact, up-to-date signature cheat sheet extracted from the actual `arodonata` codebase so generated scripts never hallucinate SDK methods or model fields.\
**Non-goals**: Replacing the full multi-thousand-line `docs-notebooklm/02-api-reference.md` reference.

The documentation bundle build MUST generate a deterministic, compact Markdown SDK quick-reference summarizing current `arodonata.__version__`, public `ArodonataClient` and `ScriptRepositoryService` signatures, key fields of `Asset`, `CPObject`, and `CPService`, `CPCRUDService` and `ApiReferenceEngine` entry points, `arodonata.testing` replay helpers, and idiomatic `arlogi` CLI logging setup.

#### Scenario: SCN-AIBUILD-003-1 — SDK quick-reference matches public package exports and signatures

- **GIVEN** the current `arodonata` source tree in `src/arodonata`
- **WHEN** the documentation bundle build generates the compact SDK quick-reference
- **THEN** the output Markdown SHALL match `arodonata.__version__` and include verified signatures and model fields for `ArodonataClient`, `Asset`, `CPObject`, `CPService`, `ScriptRepositoryService`, `CPCRUDService`, and `ApiReferenceEngine`
- **AND** re-running the generator without source edits SHALL produce byte-identical output

#### Scenario: SCN-AIBUILD-003-2 — Valid default-factory rendering and complete arodonata.testing method coverage

- **GIVEN** Pydantic fields using `lambda` `default_factory` expressions (including `ArodonataSettings.tls_known_hosts_path`) and public methods on `FileReplayApiMock` and `CheckPointReplayHttpServer`
- **WHEN** the documentation bundle build generates `docs-notebooklm/05-sdk-quickref.md`
- **THEN** lambda-backed defaults SHALL render valid Python expressions without invalid `lambda: ...()` syntax
- **AND** `FileReplayApiMock` and `CheckPointReplayHttpServer` sections SHALL include all public methods and properties without `[:8]` truncation

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

### Requirement: Plugin Replay Documentation Accuracy and Governance Port-Summary Alignment

**ID**: REQ-AIBUILD-007\
**Intent**: Keep AI-builder plugin testing documentation and repository governance docs aligned with actual `FileReplayApiMock`, `ArodonataSettings`, and hexagonal port boundaries.\
**Non-goals**: Adding new starter templates or changing plugin manifest fields (`REQ-AIBUILD-004`).

`plugins/arodonata-aibuilder/skills/arodonata-aibuilder/references/replay-testing-guide.md` MUST document only valid `FileReplayApiMock` `manage_repository_scripts` modes (`"write"`, `"read"`, `"none"`) and valid `ArodonataSettings` parameters (`mgmt_ip`, `mgmt_port`, `tls_trust`, `tls_fingerprints`, `server.snapshot_state()`). Repository governance docs (`AGENTS.md`, `openspec/config.yaml`) MUST accurately reflect `LockPort` and segregated `CachePort` sub-protocols.

#### Scenario: SCN-AIBUILD-007-1 — Plugin replay guide and governance port docs match live SDK and testing contracts

- **GIVEN** `plugins/arodonata-aibuilder/skills/arodonata-aibuilder/references/replay-testing-guide.md`, `AGENTS.md`, and `openspec/config.yaml`
- **WHEN** documented `FileReplayApiMock` modes, `ArodonataSettings` / `CheckPointReplayHttpServer` snippets, and `core` hexagonal port summaries are checked against `src/arodonata`
- **THEN** `replay-testing-guide.md` SHALL reference only `"write"`, `"read"`, `"none"` and valid `ArodonataSettings` / `CheckPointReplayHttpServer` APIs
- **AND** `AGENTS.md` and `openspec/config.yaml` SHALL name `LockPort` and segregated `CachePort` sub-protocols alongside `ApiPort`
