# Integration Testing and Examples Specification

## Purpose

Defines the live Check Point integration testing harness (`tests/integration/b1..b7`), the `./pytest.sh` runner separating the mandatory zero-network unit test gate (`tests/unit/`) from bucketed live-environment integration suites, the lab safety net (exclusive run lock, unauthenticated API readiness gate, and automatic revision baseline snapshot/restore), and the runnable SDK usage examples (`examples/`).

## Requirements

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

The repository SHALL provide a runnable `examples/` catalog demonstrating Arodonata v2 capabilities from basic cached queries to advanced multi-tenant contexts, CPCRUD, change reports, OpenTelemetry tracing, and ASGI MCP embedding, ensuring that embedded MCP examples enforce host or bearer authentication when write tools (`cpcrud=True` or `live_compat=True`) are enabled.

#### Scenario: Examples cover core and advanced v2 workflows with crash-safe lab guard

- **WHEN** a developer inspects or executes scripts in `examples/`
- **THEN** the catalog SHALL include runnable scripts for basic domain/object/service queries (`01`), search and structured queries (`02`), gateway/cluster/VSX relationships (`03`), streaming cache refresh (`04`), rulebase queries and numbering (`05`), session lifecycle (`06`), `auth_context`/`user_context` and `SessionOverlay` read-your-own-writes (`07`), CPCRUD idempotent apply (`08`) and compensating inverse (`09`), change report evidence (`10`), OpenTelemetry tracing with module gating (`11`), FastAPI MCP embedding (`12`, configured with explicit bearer/host authentication middleware protecting write-capable MCP routes), and gateway interface topology caching and affected gateway candidate matching (`13`), with all mutating examples wrapped in `guarded_session` so target lab domains are automatically restored on exit

### Requirement: Deterministic Enterprise Raw Dataset and Generator

The testing harness SHALL provide a deterministic (fixed-seed) generator and raw fixture dataset (`tests/fixtures/enterprise_raw_dataset/`) containing Check Point Management API JSON payloads and gateway CLI routing outputs for an enterprise MDSM topology (8–10 domains plus `Global`, hundreds of gateways/clusters/VSX Virtual Systems, thousands of objects with 6–7-level nested groups, and 1,000+ policy rules).

#### Scenario: Raw dataset covers multi-domain API payloads and gateway CLI outputs

- **WHEN** the enterprise raw dataset is generated or loaded from `tests/fixtures/enterprise_raw_dataset/`
- **THEN** it SHALL provide deterministic raw Check Point API JSON files (`show-domains`, `show-sessions`, `show-last-published-session`, `show-session`, `show-gateways-and-servers`, `show-simple-gateway`, `show-simple-cluster`, `show-generic-object`, `show-generic-objects` for `CpmiVsNetobj`, `CpmiVsxNetobj`, `CpmiVsxSlotObj`, and `CpmiVsSlotObj`, `show-hosts`, `show-networks`, `show-address-ranges`, `show-groups` nested 6–7 levels deep, `show-services-*`, `show-packages`, `show-access-layers`, `show-access-rulebase`, `show-nat-rulebase`) and raw CLI stdout files (`vsx stat -l`, `ip -4 route show`, `clish -c "show route"`, and Base64 `run-script`/`show-task` payloads) across 8–10 MDSM domains plus `Global`

### Requirement: File-Backed Check Point API and Gateway CLI Replay Doubles

The testing package SHALL provide `FileReplayApiMock` (`ApiPort`) and `FileReplayCliMock` (`GatewayCliPort`) backed by the raw dataset on disk, emulating Check Point pagination (`limit`/`offset`/`from`/`to`/`total`), `details-level`, `uid`/`name` and `class-name` filtering, rulebase section slicing (`show-access-rulebase`, `show-nat-rulebase`) including `use-object-dictionary=False` object inlining, `where-used` dependency resolution (direct and indirect group memberships, access rules, and NAT rules), `run-script` + `show-task` Base64 task responses, VSX `vsenv` / `vsx stat -l` / `CTX%05d` bash validation, and per-call audit counters.

#### Scenario: Paginated API queries and VSX CLI context validation execute against raw fixture files

- **WHEN** `ArodonataClient` queries `FileReplayApiMock` with `limit`/`offset`, `uid`/`name`/`class-name` filters, `where-used`, or `show-access-rulebase` / `show-nat-rulebase` (`use-object-dictionary=True | False`), and executes route collection scripts against `FileReplayCliMock` (or `run-script` + `show-task` fallback)
- **THEN** `FileReplayApiMock` SHALL return continuity-valid slices (`from`, `to`, `total`), resolve `where-used` direct and indirect group/access-rule/NAT-rule references (and inline `objects-dictionary` dicts when `use-object-dictionary=False`), and return Base64-encoded `show-task` responses from the raw dataset while recording per-command call counters, and `FileReplayCliMock` SHALL verify `vsenv` / `vsx stat -l` and `CTX%05d` `$FWDIR` guards before returning the raw CLI stdout for the target node and VSID

### Requirement: Standalone Check Point Web API HTTPS Mock Server for Downstream Applications

The testing package SHALL provide an embeddable and CLI-runnable HTTPS server (`python -m arodonata.testing.mock_server`) serving `/web_api/{cmd}` from the raw dataset with per-domain `X-chkp-sid` session tracking and host-rewritten `show-domains` endpoints so downstream applications (such as MMP and FPCR) can point `ArodonataClient` at `localhost:<port>` without a live Check Point appliance.

#### Scenario: Downstream application connects over HTTPS to localhost and syncs multi-domain dataset

- **WHEN** `CheckPointReplayHttpServer` is started on `localhost:<port>` (e.g., `localhost:443` or an ephemeral test port) and a client connects via real `AMgmtClient` / `ApiTransport`
- **THEN** `/web_api/login` SHALL issue domain-bound session tokens (`X-chkp-sid`), `/web_api/show-domains` SHALL rewrite active CMA/MDS server `ipv4-address` fields to the server's bound host, and subsequent `/web_api/{cmd}` requests (`show-gateways-and-servers`, `show-hosts`, `show-groups`, `show-packages`, `show-access-rulebase`, `run-script`, `show-task`, etc.) SHALL return the corresponding domain's paginated raw dataset without artificial rate limiting or login delays
