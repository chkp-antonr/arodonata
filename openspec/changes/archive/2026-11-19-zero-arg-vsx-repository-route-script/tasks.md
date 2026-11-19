# Tasks

## 1. Script Repository Base64 Decoding (`REQ-CLIENT-010`)

- [x] 1.1 Implement `_decode_repository_script_body()` and wire it into `RepositoryScript.from_cp_dict()` in `src/arodonata/core/models/scripts.py` so Base64-encoded `"script-body"` values returned by Check Point R82 `show-repository-script` decode cleanly to UTF-8 without corrupting short plaintext script strings or breaking `"script-body-base64"`, and verify with `@pytest.mark.spec("SCN-CLIENT-010-4")` plus short-token regression cases in `tests/unit/test_script_repository.py` and `tests/spec/test_spec_client_and_config.py` (`uv run pytest tests/unit/test_script_repository.py tests/spec/test_spec_client_and_config.py`).

## 2. Zero-Argument Self-Detecting Canonical Route Script (`REQ-TOPO-008`)

- [x] 2.1 Add `DEFAULT_REPOSITORY_MAX_ROUTES = 50000`, `VSX_BUNDLE_START_MARKER`, `VSX_BUNDLE_END_MARKER`, `VS_START_PREFIX`, `VS_END_MARKER`, and `VS_ERROR_PREFIX` in `src/arodonata/core/services/topology/route_scripts.py` and re-export them from `src/arodonata/core/services/topology/__init__.py` and the backward-compatible shim `src/arodonata/core/services/route_collector.py`, verifying shim object identity in `tests/unit/test_topology_compat_and_security.py`.
- [x] 2.2 Upgrade `build_route_collection_repository_script()` in `src/arodonata/core/services/topology/route_scripts.py` to auto-detect VSX via `vsx stat -l </dev/null` when `$# -eq 0`, iterate L3 Virtual Systems/Virtual Routers (`VSID > 0`, skipping L2 Virtual Switches) with `vsenv`/`CTX%05d` checks and per-VS `===ARODONATA_VS_ERROR ...===` isolation into `===ARODONATA_VSX_BUNDLE_START===` ... `===ARODONATA_VSX_BUNDLE_END===`, handle non-VSX gateways with built-in `50000` cap and `clish` `10000`-line threshold, and preserve `$# -gt 0` positional-arg compatibility; verify real `bash` execution across non-VSX, multi-VS VSX (with Virtual Switch skipped and one failing `vsenv`), and legacy parameterized invocations in `tests/unit/test_topology_service.py` (`uv run pytest tests/unit/test_topology_service.py tests/unit/test_topology_compat_and_security.py`).

## 3. Bundle Parser, Zero-Arg Default Execution, and Per-Node Coalescing (`REQ-TOPO-008`)

- [x] 3.1 Implement `VsxBundleSlice`, `parse_vsx_bundle_output()`, and `extract_vs_slice_from_bundle()` in `src/arodonata/core/services/topology/route_parsers.py` matching slices by `vsid` (with case-insensitive `vs_name` fallback), propagating per-VS errors, failing closed on missing VS slices, and preserving `max_routes` truncation; verify with unit tests covering multi-VS bundles, error isolation, missing VS slices, and non-bundle passthrough in `tests/unit/test_topology_service.py`.
- [x] 3.2 Update `_run_repository_cprid()` in `src/arodonata/core/services/topology/route_executor.py` to omit `"args"` when `repository_script_args_fn is None` (while honoring explicit `repository_script_args_fn` verbatim and keeping `format_route_collection_repository_args()` exported), and add per-physical-node zero-arg repository coalescing (`(mgmt_name, domain_name, node_key)`) plus VS slice extraction in `src/arodonata/core/services/topology/route_collection.py` (preserving fail-fast `ServerIdentityError` and SID redaction); verify with `@pytest.mark.spec("SCN-TOPO-008-1")`, `@pytest.mark.spec("SCN-TOPO-008-2")`, and `@pytest.mark.spec("SCN-TOPO-008-4")` tests (`uv run pytest tests/unit/test_topology_service.py tests/spec/test_spec_mcp_and_topology.py`).

## 4. Check Point R82 Replay Mock Parity (`REQ-TOPO-018`)

- [x] 4.1 Update `FileReplayApiMock` in `src/arodonata/testing/replay_mock.py` to add `encode_repository_script_body_base64: bool = False` on `show-repository-script`, return `HTTP 400 err_validation_failed` (`"Insufficient permissions to run this script with arguments."`) when `script-type="repository"` passes non-empty `"args"` under `allow_one_time_script=False`, and synthesize zero-arg VSX bundles for VSX replay hosts; verify with `@pytest.mark.spec("SCN-TOPO-018-1")` and `@pytest.mark.spec("SCN-TOPO-018-2")` tests in `tests/unit/test_replay_mock_repository_scripts.py` (`uv run pytest tests/unit/test_replay_mock_repository_scripts.py`).

## 5. Full Verification and Spec Traceability

- [x] 5.1 Run full `arodonata_v2` quality gates (`uv run ruff check .`, `uv run ruff format --check .`, `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix`, `uv run mypy src`, `uv run pytest`, `openspec schema validate arodonata`, `openspec validate --specs --strict --no-interactive`, and `uv run python scripts/check_spec_traceability.py`) and verify zero errors or uncovered scenarios.

## Workflow follow-up

- Sync delta specs and archive `zero-arg-vsx-repository-route-script` after implementation and code review pass.
- Re-run `FPCR_v2` `uv run pytest` and verify live R82 `check_route_collection_script` + `collect_gateway_routes` under `fpcr_ro`.
