# Spec Delta

## Purpose

Defines the live Check Point integration testing harness (`tests/integration/b1..b7`), the `./pytest.sh` runner separating the mandatory zero-network unit test gate (`tests/unit/`) from bucketed live-environment integration suites, the lab safety net (exclusive run lock, unauthenticated API readiness gate, and automatic revision baseline snapshot/restore), and the runnable SDK usage examples (`examples/`).

## ADDED Requirements

### Requirement: Unit and Integration Test Separation and Runner

The repository SHALL separate fast, zero-network unit tests (`tests/unit/`) from live Check Point integration tests (`tests/integration/b1..b7`) and provide an executable `./pytest.sh` runner at the repository root.

#### Scenario: Default test invocation executes only fast unit tests

- **WHEN** `./pytest.sh`, `./pytest.sh unit`, or bare `uv run pytest` is executed
- **THEN** pytest SHALL run only unit tests (`-m "not integration"`) with verbose test names (`-v`) by default, excluding `tests/integration/`, with zero network access required so it acts as a fast mandatory pre-PR quality gate

#### Scenario: Single integration bucket runs in an isolated session with short tracebacks

- **WHEN** `./pytest.sh int-<N>` (`N` in `1..7`) is executed
- **THEN** it SHALL launch an isolated `pytest` session targeting `tests/integration/b<N>` with verbose output (`-v`), live CLI info logging (`-o log_cli=true --log-cli-level=INFO`), `--durations=15`, and `--tb=short` so frame-local credentials or API keys are never printed on failure

#### Scenario: Full integration suite runs all buckets sequentially with throttle pauses

- **WHEN** `./pytest.sh int-full` is executed
- **THEN** it SHALL execute buckets `b1` through `b7` in separate sequential `pytest` sessions, pausing `BUCKET_PAUSE_SECONDS` (default `90` seconds) between buckets to clear Check Point's per-IP login rate-limit window, continuing past failed buckets, and exiting non-zero if any bucket failed

#### Scenario: Unknown integration target is rejected before pytest collection

- **WHEN** `./pytest.sh int-unknown` is executed with an invalid `int-*` target
- **THEN** `./pytest.sh` SHALL exit with code `2` and print valid bucket targets (`int-1`..`int-7`, `int-full`) instead of passing the invalid argument to `pytest`

### Requirement: Automatic Directory-Based Integration Markers

Integration tests under `tests/integration/` SHALL automatically receive `integration` and `bucket_<N>` pytest markers from their directory path during collection without manual per-test marker declarations.

#### Scenario: Collection hook applies integration and bucket markers

- **WHEN** `pytest` collects test items located under `tests/integration/b<N>/`
- **THEN** the collection hook SHALL automatically attach `pytest.mark.integration` and `pytest.mark.bucket_<N>` to each item and sort collected integration items by bucket number

### Requirement: Multi-Profile Lab Environment Loader

The integration harness and diagnostic scripts SHALL load lab configuration deterministically from `.env.test`, `.env.secrets`, and an optional `.env.lab.<ARODONATA_LAB>` profile override.

#### Scenario: Default lab environment loads when ARODONATA_LAB is unset

- **WHEN** `load_lab_env()` is called without `ARODONATA_LAB` set
- **THEN** it SHALL load `.env.test` followed by `.env.secrets` with `override=True` and return `None` as the active profile name

#### Scenario: Named lab profile layers overrides and expands secret references

- **WHEN** `ARODONATA_LAB=<profile>` is set and `.env.lab.<profile>` exists
- **THEN** `load_lab_env()` SHALL load `.env.lab.<profile>` after `.env.test` and `.env.secrets`, expanding `${VAR}` secret references and returning `<profile>`

#### Scenario: Missing selected lab profile fails fast

- **WHEN** `ARODONATA_LAB=<profile>` is set but `.env.lab.<profile>` does not exist
- **THEN** `load_lab_env()` SHALL raise `LabProfileMissing` rather than silently falling back to `.env.test`

### Requirement: Exclusive Integration Run Lock and Lab Readiness Gate

Each integration session SHALL acquire a non-blocking exclusive OS file lock (`_tmp/integration.lock`) and verify that the target Check Point API server is responsive before touching the SQLite cache database or logging in.

#### Scenario: Concurrent integration run fails fast on lock contention

- **WHEN** an integration session starts while another process holds `_tmp/integration.lock`
- **THEN** `IntegrationRunLock.acquire()` SHALL raise `IntegrationRunLocked` naming the holding PID and start timestamp, and the session SHALL exit immediately with return code `3`

#### Scenario: Readiness gate probes API server without spending login allowance

- **WHEN** the `lab_ready` session fixture runs against `API_MGMT`
- **THEN** it SHALL poll `show-api-versions` without a session header (`sid=None`) up to `ARODONATA_TEST_READY_WAIT` seconds, treating a Check Point JSON error code (`generic_err_missing_required_header`) or `success=True` as proof the API server is awake without consuming any per-minute login rate-limit slot, or abort with return code `4` if the budget expires

### Requirement: Automatic Revision Baseline Snapshot and Teardown Revert

Integration sessions SHALL snapshot the last published revision (`show-last-published-session`) of `TEST_DOMAIN_A` and `TEST_DOMAIN_B` before running tests and revert any drifted domain on teardown if any `cp_mutates`-marked test executed.

#### Scenario: Baseline snapshot persisted before tests and restored after mutations

- **WHEN** an integration session runs with `TEST_DOMAIN_A` or `TEST_DOMAIN_B` configured and at least one `@pytest.mark.cp_mutates` test executes
- **THEN** the harness SHALL write `_tmp/cp_baseline/baseline-<UTC>.json` before the first test, and on session teardown SHALL discard open sessions holding locks/changes and execute `revert-to-revision` (`timeout=900s`) for any snapshotted domain whose `show-last-published-session` UID drifted from the baseline

#### Scenario: Baseline snapshot failure aborts the session before running tests

- **WHEN** capturing the initial baseline snapshot of `TEST_DOMAIN_A` or `TEST_DOMAIN_B` fails
- **THEN** the session fixture SHALL abort the entire pytest run immediately with return code `5` rather than executing mutating tests without a recovery baseline

### Requirement: Progressive Runnable SDK Examples Catalog

The repository SHALL provide a runnable `examples/` catalog demonstrating Arodonata v2 capabilities from basic cached queries to advanced multi-tenant contexts, CPCRUD, change reports, OpenTelemetry tracing, and ASGI MCP embedding.

#### Scenario: Examples cover core and advanced v2 workflows with crash-safe lab guard

- **WHEN** a developer inspects or executes scripts in `examples/`
- **THEN** the catalog SHALL include runnable scripts for basic domain/object/service queries (`01`), search and structured queries (`02`), gateway/cluster/VSX relationships (`03`), streaming cache refresh (`04`), rulebase queries and numbering (`05`), session lifecycle (`06`), `auth_context`/`user_context` and `SessionOverlay` read-your-own-writes (`07`), CPCRUD idempotent apply (`08`) and compensating inverse (`09`), change report evidence (`10`), OpenTelemetry tracing with module gating (`11`), and FastAPI MCP embedding (`12`), with all mutating examples wrapped in `guarded_session` so target lab domains are automatically restored on exit
