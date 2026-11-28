# Tasks

## 1. Packaging Isolation & Traceability Registration

- [x] 1.1 Register `"ai-builder": "AIBUILD"` in `CAPABILITY_PREFIXES` inside `scripts/check_spec_traceability.py` and configure `[tool.hatch.build.targets.sdist]` exclusions (`plugins/`, `docs-notebooklm/`, `docs/_html/`, `openspec/`, `examples/`) in `pyproject.toml`, verifying `ruff check scripts/check_spec_traceability.py` passes
- [x] 1.2 Add unit test `@pytest.mark.spec("SCN-AIBUILD-001-1")` in `tests/unit/test_aibuilder_docs_and_packaging.py` asserting wheel target restriction to `src/arodonata` and `sdist` exclusion of `plugins/` and `docs-notebooklm/`, and verify `uv run pytest tests/unit/test_aibuilder_docs_and_packaging.py` passes

## 2. Check Point API & Operational Quirks Knowledge Base

- [x] 2.1 Expand `docs/troubleshooting/checkpoint-api-quirks.md` with MDSM Global vs. Local `"Network"` layer collisions, `show-global-assignments` safeguards (`never_assigned`, status spaces, 15-minute polling), `show-networks` mask-length post-filtering, `dns-domain` leading-dot requirement, `nat-rule` package scoping, `verify-policy`/`install-policy` non-publish write-session requirements, and targeted `session_uid` + `take-over-session` discard rules, verifying `npx markdownlint-cli docs/troubleshooting/checkpoint-api-quirks.md` passes
- [x] 2.2 Create `docs/troubleshooting/checkpoint-ops-quirks.md` covering native `Asset` cluster/VSX resolution vs. external platform nuances (Maestro `gclish`/`asg_cp2blades`, Quantum Spark Gaia Embedded), Gaia stdlib `python3` vs. POSIX `sh` in `run-script`/`ScriptRepositoryService`, single-pass `cpinfo -y all` / `cplp` / `autoupdatercli` parsing, CDT (`sk111158`) XML/CSV/exit-code (`222` vs. `0`) rules, Gaia R81.x vs. R82+ `clish` grammar differences, and standalone CLI SQLite + `arlogi` (`json_file_only=False`, secret-free `extra` kwargs) lifecycle practices, and register it in `mkdocs.yml` (`npx markdownlint-cli docs/troubleshooting/checkpoint-ops-quirks.md` and `uv run mkdocs build --strict`)

## 3. Documentation Bundles & Compact SDK Quick-Reference Generator

- [x] 3.1 Update `docs/scripts/build_notebooklm_docs.py` to read `arodonata.__version__` dynamically, include current mock/testing guides and both troubleshooting quirk files in `GUIDE_SOURCES`, discover all tracked `docs/examples/[0-9][0-9]-*.md` guides (`01`..`13`), and emit `docs-notebooklm/05-sdk-quickref.md` (`build_sdk_quickref()`) with deterministic signatures/fields for `ArodonataClient`, `ArodonataSettings`, `Asset`, `CPObject`, `CPService`, `ScriptRepositoryService`, `CPCRUDService`, `ApiReferenceEngine`, `ChangeReport`, `arodonata.testing`, `arlogi` CLI setup, and the 3-tier API lookup ladder; regenerate `docs-notebooklm/` and verify `ruff check docs/scripts/build_notebooklm_docs.py` passes
- [x] 3.2 Add unit tests `@pytest.mark.spec("SCN-AIBUILD-002-1")`, `@pytest.mark.spec("SCN-AIBUILD-002-2")`, and `@pytest.mark.spec("SCN-AIBUILD-003-1")` in `tests/unit/test_aibuilder_docs_and_packaging.py` verifying quirk bundle inclusion, MkDocs navigation integrity, example `01`..`13` coverage, and byte-identical `build_sdk_quickref()` output matching public exports (`uv run pytest tests/unit/test_aibuilder_docs_and_packaging.py`)

## 4. End-to-End Quality & Traceability Verification

- [x] 4.1 Run full repository quality gates (`uv run ruff check .`, `uv run ruff format --check .`, `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix`, `uv run mypy src`, `uv run pytest`, `openspec schema validate arodonata`, `openspec validate --changes --strict --no-interactive`, and `uv run python scripts/check_spec_traceability.py`) and verify zero errors

## Workflow follow-up

- Sync delta specs and archive `concentrate-cp-quirks-and-doc-bundles` after implementation review.
- Proceed to the next OpenSpec changes on the roadmap: clean vendor-neutral `Asset` role/platform classification in `arodonata`, `plugins/arodonata-aibuilder` skill bundle, and end-to-end English playbooks.
