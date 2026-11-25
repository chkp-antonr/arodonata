# Proposal

## Why

Downstream Check Point automation—both enterprise platforms (`FPCR`, `MMP`, `DMNSync`) and lightweight administrator CLI scripts—repeatedly encounters subtle Check Point Management API, Gaia OS (`clish`, `python3`, `cpinfo`, `cplp`, `autoupdatercli`), Central Deployment Tool (CDT), VSX/ClusterXL, and MDSM operational quirks that generic AI coding agents do not know. Before introducing the `plugins/arodonata-aibuilder` skill pack, Arodonata needs a single authoritative knowledge base of these field-proven quirks, synchronized `docs-notebooklm/` and agent-ready SDK quick-reference bundles, and strict Python build exclusion so repository-hosted AI skills never bloat `uv add arodonata` installations.

## What Changes

- Expand [`docs/troubleshooting/checkpoint-api-quirks.md`](../../../docs/troubleshooting/checkpoint-api-quirks.md) with additional Management API, MDSM Global vs. Local layer/assignment, network/range/DNS filter, `show-changes`, `verify-policy`/`install-policy` session, and targeted session-lock cleanup quirks harvested from `FPCR`, `MMP`, and `Sync_MDM`.
- Add `docs/troubleshooting/checkpoint-ops-quirks.md` documenting operational Check Point automation rules on top of Arodonata: gateway/ClusterXL/VSX/Maestro/Quantum Spark platform boundaries (clearly separating what `Asset` resolves natively from platform-specific nuances), Gaia stdlib `python3` vs. Gaia Embedded `sh` execution in `run-script`, single-pass `cpinfo -y all` / `cplp` / `autoupdatercli` parsing, CDT (`sk111158`) deployment constraints, Gaia R81.x vs. R82+ `clish` dialect differences, and standalone CLI SQLite + `arlogi` lifecycle best practices.
- Register the new troubleshooting and CLI scripting documentation in `mkdocs.yml`.
- Update `docs/scripts/build_notebooklm_docs.py` to dynamically include current guides, examples (`01`..`13`), and troubleshooting quirk references in `docs-notebooklm/`, and emit a compact AST-derived `sdk-quickref.md` reference artifact suitable for AI agent skills.
- Configure `[tool.hatch.build.targets.sdist]` alongside `[tool.hatch.build.targets.wheel]` in `pyproject.toml` so `plugins/` (and `docs-notebooklm/`) are strictly excluded from distributed Python packages (`wheel` and `sdist`).
- Register the `ai-builder` capability prefix (`AIBUILD`) in `scripts/check_spec_traceability.py` and add offline unit tests verifying distribution archive isolation and deterministic reference bundle generation.

## Capabilities

### New Capabilities

- `ai-builder`: Packaging isolation for repository-hosted `plugins/arodonata-aibuilder` artifacts and deterministic generation of consolidated Check Point quirk knowledge bundles and compact SDK/CLI quick-reference documents for AI agents.

### Modified Capabilities

<!-- None: runtime SDK behavior in src/arodonata is unchanged in this step. -->

## Impact

- **Documentation & Knowledge Bundles**: `docs/troubleshooting/checkpoint-api-quirks.md`, `docs/troubleshooting/checkpoint-ops-quirks.md`, `mkdocs.yml`, `docs/scripts/build_notebooklm_docs.py`, and regenerated `docs-notebooklm/*.md`.
- **Packaging & Tooling**: `pyproject.toml` (`[tool.hatch.build.targets.sdist]` exclusions) and `scripts/check_spec_traceability.py` (`CAPABILITY_PREFIXES["ai-builder"] = "AIBUILD"`).
- **Runtime SDK (`src/arodonata/`)**: Zero runtime code or dependency changes; `uv add arodonata` wheel size and transitive dependencies remain completely unchanged.
