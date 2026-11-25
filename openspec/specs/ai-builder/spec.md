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
