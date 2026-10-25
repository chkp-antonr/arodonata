# Tasks

## 1. Repository Layout, Dependencies, Environment Files, and `./pytest.sh` Runner

- [x] 1.1 Update `pyproject.toml` to add `python-dotenv` and `fastapi` to `[dependency-groups].dev`, configure pytest markers (`integration`, `bucket_1`..`bucket_7`, `cp_mutates`), and set `addopts = ["-v", "-ra", "--strict-markers", "-m", "not integration"]`; verify `uv sync` succeeds.
- [x] 1.2 Update `.gitignore` to ignore `.env`, `.env.test`, `.env.secrets`, `.env.lib`, `.env.lab.*`, `_tmp/`, `examples/_tmp/`, and `tls_known_hosts.json` while keeping `.env.example` tracked; copy and adapt `.env.example`, `.env.test`, `.env.lab.home`, `.env.lib`, and `.env.secrets` from `../arodonata/` and verify `git status` shows only `.env.example` as untracked/tracked.
- [x] 1.3 Move all existing unit test files from `tests/test_*.py` into `tests/unit/test_*.py` (creating `tests/__init__.py` and `tests/unit/__init__.py`), create executable `./pytest.sh` supporting default/`unit`, `int-1`..`int-7`, `int-full`, and passthrough args, and verify `./pytest.sh` passes all existing unit tests and `./pytest.sh int-bad` exits with code 2.

## 2. Integration Harness Infrastructure & Diagnostic Utilities (`tests/integration/`)

- [x] 2.1 Implement `tests/integration/lab_env.py` (`load_lab_env`, `LabProfileMissing`, `allowed_test_domains`, `is_test_domain`) and `tests/integration/run_lock.py` (`IntegrationRunLock`, `IntegrationRunLocked`) and add unit tests in `tests/unit/test_integration_harness.py` verifying profile loading, missing profile error, and `flock` contention.
- [x] 2.2 Implement `tests/integration/lab_ready.py` (`answered_by_api`, `api_versions_probe`, `wait_until_ready`, `LabNotReady`) using Arodonata v2 `ApiTransport` and `TrustPolicy`, and add unit tests in `tests/unit/test_integration_harness.py` verifying readiness detection and timeout behavior.
- [x] 2.3 Implement `tests/integration/cp_revision.py` (`last_published_session`, `snapshot_baseline`, `write_baseline_file`, `discard_open_sessions`, `revert_domain_to`, `restore_to_baseline`) and `tests/integration/restore_baseline.py` using Arodonata v2 `ArodonataClient.api_call`, and add unit tests in `tests/unit/test_integration_harness.py` verifying snapshot and revert retry logic.
- [x] 2.4 Implement `tests/integration/conftest.py` with auto-marker hook (`pytest_collection_modifyitems`), session fixtures (`integration_tracing`, `integration_run_lock`, `lab_ready`, `db_engine`, `cp_baseline_snapshot`, `all_domains`), and per-user client fixtures (`apikey_client`, `admin_client`, `antonr_client`, `eng1_client`..`eng4_client`).
- [x] 2.5 Port standalone lab utilities `tests/integration/probe_lab_domains.py`, `tests/integration/probe_login_throttle.py`, and `tests/integration/lab_build.py` to Arodonata v2 `ApiTransport` and `TrustPolicy`, and verify they pass `ruff` and `--help` invocation.

## 3. Live Integration Test Buckets `b1`, `b2`, and `b3`

- [x] 3.1 Create `tests/integration/b1/` tests adapted to v2 APIs: `test_harness_smoke.py`, `test_auth.py` (API key, credentials, dynamic `auth_context`, invalid credentials fast-fail), `test_session_lifecycle.py` (SID caching, reuse, logout, stale SID recovery, startup cleanup), and `test_session_names.py` (`write_session` / `user_context` session naming and UID lookup).
- [x] 3.2 Create remaining `tests/integration/b1/` tests: `test_concurrent_admins.py`, `test_rate_limiting.py`, `test_reads_and_search.py` (`get_hosts`, `get_networks`, `search_objects`, `query_objects`, `get_object_by_uid`), `test_rulebase_reads.py` (`refresh_rulebases`, `get_access_rules`, `get_nat_rules`, `get_package_rulebase`, `locate_rules`), and `test_change_report_reads.py`; verify collection with `./pytest.sh int-1 --collect-only`.
- [x] 3.3 Create `tests/integration/b2/` tests adapted to v2 APIs: `test_cache_build.py` (`refresh_objects`, `refresh_services`, `stream_refresh_objects`, `mode="smart"` skip) and `test_cpcrud_live.py` (`plan`, `apply`, idempotency, staleness & `force=True`, `inverse`, conflict policies, services, groups, rules); verify collection with `./pytest.sh int-2 --collect-only`.
- [x] 3.4 Create `tests/integration/b3/` tests adapted to v2 APIs: `test_publish_revert.py` (`create_dedicated_session`, `write_session` with `SessionOverlay` read-your-own-writes, `add_object`, publish, `smart-fast` incremental pickup, discard, revert) and `test_throttling.py` (`70s` login throttle window recovery); verify collection with `./pytest.sh int-3 --collect-only`.

## 4. Live Integration Test Buckets `b4`, `b5`, `b6`, and `b7`

- [x] 4.1 Create `tests/integration/b4/` tests adapted to v2 APIs: `test_cache_mode_matrix.py` (`cache`, `smart`, `smart-fast`, `force`, missing-baseline fallback, `max_incremental_changes` fallback) and `test_multi_domain.py` (`TEST_DOMAIN_A` vs `TEST_DOMAIN_B` isolation, concurrent domain refresh, `Global` domain resolution); verify collection with `./pytest.sh int-4 --collect-only`.
- [x] 4.2 Create `tests/integration/b5/` tests adapted to v2 APIs: `test_full_rebuild.py` (`refresh_objects`, `refresh_services`, `refresh_assets` with cluster/VSX parent relationships, `refresh_rulebases` across all domains), `test_large_layer.py` (120-rule pagination across 3 sections), `test_rulebase_session_refresh.py`, `test_publish_matrix.py`, and `test_change_report_session.py`; verify collection with `./pytest.sh int-5 --collect-only`.
- [x] 4.3 Create `tests/integration/b6/test_soak.py` (bounded 8-cycle publish -> `smart-fast` -> revert loop) and `tests/integration/b7/` MCP live tests (`test_mcp_server.py`, `test_mcp_tools.py` covering `arodonata_init`, `show_hosts`, `show_gateways_and_servers`, `show_packages`, `show_access_rulebase`, `show_nat_rulebase`, `search_objects`, `query_objects`, `describe_objects`, `get_cache_status`, `change_report`, and `api_call` write gate); verify collection with `./pytest.sh int-6 --collect-only` and `./pytest.sh int-7 --collect-only`.

## 5. Progressive Runnable SDK Examples (`examples/`)

- [x] 5.1 Create `examples/_session_guard.py` (crash-safe baseline snapshot/restore context manager and CLI utility) and `examples/crud_example.yaml`, plus `examples/01_basic_queries.py`, `examples/02_search_and_query.py`, `examples/03_gateway_relationships.py`, `examples/04_smart_refresh.py`, and `examples/05_rulebase_queries.py`.
- [x] 5.2 Create session, context, CPCRUD, report, observability, and MCP examples: `examples/06_session_basics.py`, `examples/07_context_and_overlay.py` (`auth_context`, `user_context`, `SessionOverlay` read-your-own-writes), `examples/08_cpcrud_operations.py`, `examples/09_cpcrud_inverse.py`, `examples/10_change_report_evidence.py`, `examples/11_otel_tracing.py`, and `examples/12_mcp_embedded.py`.
- [x] 5.3 Create `examples/README.md` and `examples/README_CRUD.md` documenting setup, environment configuration, and execution order for all 12 examples, and update root `README.md` to reference `./pytest.sh` and `examples/`.

## 6. Quality Gates and Live Smoke Verification

- [x] 6.1 Run all static and unit quality gates (`./pytest.sh`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src`, `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix`, `openspec validate --specs --no-interactive`) and verify zero errors.
- [x] 6.2 Run live lab smoke verification (`./pytest.sh int-1 tests/integration/b1/test_harness_smoke.py`) if the lab server is reachable on the network, or verify graceful readiness/skip behavior.

## Workflow follow-up

- Run `/archive-task live-integration-tests-and-examples` and `/opsx-archive` after implementation and verification are complete.
