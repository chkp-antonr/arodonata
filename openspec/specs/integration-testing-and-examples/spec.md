# Integration Testing and Examples Specification

## Purpose

Defines the live Check Point integration testing harness (`tests/integration/b1..b7`), the `./pytest.sh` runner separating the mandatory zero-network unit test gate (`tests/unit/`) from bucketed live-environment integration suites, the lab safety net (exclusive run lock, unauthenticated API readiness gate, and automatic revision baseline snapshot/restore), the deterministic enterprise raw dataset and stateful API/CLI replay emulator (`FileReplayApiMock`, `FileReplayCliMock`, `CheckPointReplayHttpServer`), and the runnable SDK usage examples (`examples/`).

## Requirements

### Requirement: Unit and Integration Test Separation and Runner

**ID**: REQ-ITEST-001\
**Intent**: Keep default unit testing fast and network-free while organizing live lab tests into rate-limit-safe buckets.\
**Non-goals**: Automatic pytest directory marker attachment (`REQ-ITEST-002`).

The repository SHALL separate fast, zero-network unit tests (`tests/unit/`) from live Check Point integration tests (`tests/integration/b1..b7`) and provide an executable `./pytest.sh` runner at the repository root.

#### Scenario: SCN-ITEST-001-1 — Default test invocation executes only fast unit tests

- **WHEN** `./pytest.sh`, `./pytest.sh unit`, or bare `uv run pytest` is executed
- **THEN** pytest SHALL run only unit tests (`-m "not integration"`) with verbose names (`-v`) and zero network access, excluding `tests/integration/`

#### Scenario: SCN-ITEST-001-2 — Single integration bucket runs in an isolated session with short tracebacks

- **WHEN** `./pytest.sh int-<N>` (`N` in `1..7`) is executed
- **THEN** it SHALL invoke `pytest` on `tests/integration/b<N>` with `-v`, live CLI info logging (`-o log_cli=true --log-cli-level=INFO`), `--durations=15`, and `--tb=short` so frame-local secrets never print on failure

#### Scenario: SCN-ITEST-001-3 — Full integration suite runs all buckets sequentially with throttle pauses

- **WHEN** `./pytest.sh int-full` is executed
- **THEN** it SHALL run buckets `b1` through `b7` sequentially in separate `pytest` sessions, pausing `BUCKET_PAUSE_SECONDS` (default `90s`) between buckets
- **AND** it SHALL continue past failed buckets and exit non-zero if any bucket failed

#### Scenario: SCN-ITEST-001-4 — Unknown integration target is rejected before pytest collection

- **WHEN** `./pytest.sh int-unknown` is executed with an invalid `int-*` target
- **THEN** `./pytest.sh` SHALL exit with code `2` and print valid bucket targets (`int-1`..`int-7`, `int-full`) without invoking `pytest`

### Requirement: Automatic Directory-Based Integration Markers

**ID**: REQ-ITEST-002\
**Intent**: Ensure every integration test receives its bucket and integration markers automatically based on file location.\
**Non-goals**: Test runner invocation options (`REQ-ITEST-001`).

Integration tests under `tests/integration/` SHALL automatically receive `integration` and `bucket_<N>` pytest markers from their directory path during collection without manual per-test marker declarations.

#### Scenario: SCN-ITEST-002-1 — Collection hook applies integration and bucket markers

- **WHEN** `pytest` collects test items located under `tests/integration/b<N>/`
- **THEN** the collection hook SHALL attach `pytest.mark.integration` and `pytest.mark.bucket_<N>` to each item and sort collected items by bucket number

### Requirement: Multi-Profile Lab Environment Loader

**ID**: REQ-ITEST-003\
**Intent**: Allow live integration suites and lab diagnostic scripts to switch target labs cleanly via env profiles.\
**Non-goals**: Library `ArodonataSettings` explicit env resolution (`REQ-CONFIG-001`).

The integration harness and diagnostic scripts SHALL load lab configuration deterministically from `.env.test`, `.env.secrets`, and an optional `.env.lab.<ARODONATA_LAB>` profile override.

#### Scenario: SCN-ITEST-003-1 — Default lab environment loads when ARODONATA_LAB is unset

- **WHEN** `load_lab_env()` is called without `ARODONATA_LAB` set
- **THEN** it SHALL load `.env.test` with `override=False` (preserving caller env vars), followed by `.env.secrets` with `override=True`, and return `None`

#### Scenario: SCN-ITEST-003-2 — Named lab profile layers overrides and expands secret references

- **GIVEN** `ARODONATA_LAB=<profile>` where `.env.lab.<profile>` exists
- **WHEN** `load_lab_env()` runs
- **THEN** it SHALL load `.env.lab.<profile>` after `.env.test` and `.env.secrets`, expanding `${VAR}` secret references and returning `<profile>`

#### Scenario: SCN-ITEST-003-3 — Missing selected lab profile fails fast

- **GIVEN** `ARODONATA_LAB=<profile>` where `.env.lab.<profile>` does not exist
- **WHEN** `load_lab_env()` runs
- **THEN** it SHALL raise `LabProfileMissing` rather than silently falling back to `.env.test`

### Requirement: Exclusive Integration Run Lock and Lab Readiness Gate

**ID**: REQ-ITEST-004\
**Intent**: Prevent parallel integration runs from colliding on a live lab and verify API readiness without wasting login rate-limit slots.\
**Non-goals**: Domain revision baseline capture and restore (`REQ-ITEST-005`).

Each integration session SHALL acquire a non-blocking exclusive OS file lock (`_tmp/integration.lock`) and verify that the target Check Point API server is responsive before touching the SQLite cache database or logging in.

#### Scenario: SCN-ITEST-004-1 — Concurrent integration run fails fast on lock contention

- **GIVEN** another process holding `_tmp/integration.lock`
- **WHEN** a new integration session starts
- **THEN** `IntegrationRunLock.acquire()` SHALL raise `IntegrationRunLocked` naming the holding PID and start timestamp, exiting with return code `3`

#### Scenario: SCN-ITEST-004-2 — Readiness gate probes API server without spending login allowance

- **WHEN** the `lab_ready` fixture probes `API_MGMT` via `show-api-versions` (`sid=None`) up to `ARODONATA_TEST_READY_WAIT` seconds
- **THEN** `generic_err_missing_required_header` or `success=True` SHALL count as ready without consuming a login rate-limit slot
- **AND** expiring the readiness budget SHALL abort with return code `4`

### Requirement: Automatic Revision Baseline Snapshot and Teardown Revert

**ID**: REQ-ITEST-005\
**Intent**: Protect live lab domains by reverting any published mutations automatically on test session teardown.\
**Non-goals**: In-memory replay mock state snapshots (`REQ-ITEST-015`).

Integration sessions SHALL snapshot the last published revision via `show-sessions` (`view-published-sessions=True`) for `TEST_DOMAIN_A` and `TEST_DOMAIN_B` before running tests and revert any drifted domain on teardown if any `cp_mutates`-marked test executed.

#### Scenario: SCN-ITEST-005-1 — Baseline snapshot persisted before tests and restored after mutations

- **GIVEN** `TEST_DOMAIN_A` or `TEST_DOMAIN_B` configured and at least one `@pytest.mark.cp_mutates` test executed
- **WHEN** the integration session starts and tears down
- **THEN** it SHALL write `_tmp/cp_baseline/baseline-<UTC>.json` before the first test
- **AND** on teardown it SHALL discard open sessions holding locks/changes and run `revert-to-revision` (`timeout=900s`) for any domain whose head UID drifted from baseline

#### Scenario: SCN-ITEST-005-2 — Baseline snapshot failure aborts the session before running tests

- **WHEN** capturing the initial baseline snapshot of `TEST_DOMAIN_A` or `TEST_DOMAIN_B` fails
- **THEN** the session fixture SHALL abort immediately with return code `5` rather than executing mutating tests without recovery

### Requirement: Deterministic Enterprise Raw Dataset and Generator

**ID**: REQ-ITEST-006\
**Intent**: Supply a reproducible, multi-domain Check Point enterprise dataset for offline scale, topology, and replay verification.\
**Non-goals**: Replay mock runtime query execution (`REQ-ITEST-007`).

The testing harness SHALL provide a deterministic (fixed-seed) generator (`ensure_enterprise_raw_dataset()`) and raw fixture dataset (`tests/fixtures/enterprise_raw_dataset/`) containing Check Point Management API JSON payloads and gateway CLI routing outputs for an enterprise MDSM topology.

#### Scenario: SCN-ITEST-006-1 — Raw dataset covers multi-domain API payloads and gateway CLI outputs

- **WHEN** the enterprise raw dataset is generated or loaded from `tests/fixtures/enterprise_raw_dataset/`
- **THEN** it SHALL provide domain/session JSON fixtures (`show-domains`, `show-global-assignments`, `show-sessions`, `show-last-published-session`, `show-session`)
- **AND** it SHALL provide gateway JSON fixtures (`show-gateways-and-servers`, `show-simple-gateway`, `show-simple-cluster`, `show-generic-object`, `show-generic-objects`)
- **AND** it SHALL provide object/service JSON fixtures (`show-hosts`, `show-networks`, `show-address-ranges`, `show-groups` nested 6–7 levels deep, `show-services-*`)
- **AND** it SHALL provide rulebase JSON fixtures (`show-packages`, `show-access-layers`, `show-access-rulebase`, `show-nat-rulebase`)
- **AND** it SHALL provide raw CLI stdout fixtures (`vsx stat -l`, `ip -4 route show`, `clish -c "show route"`, Base64 `run-script`/`show-task`) across `9` user MDSM domains plus `Global`

#### Scenario: SCN-ITEST-006-2 — Raw dataset includes deterministic Global object and group usage in local domain rules without breaking scale invariants

- **WHEN** `ensure_enterprise_raw_dataset()` materializes `tests/fixtures/enterprise_raw_dataset/`
- **THEN** local domains SHALL reference `Global` entities (`H_Global_DNS_001`, `G_Global_Branch_Supernet`, `G_Global_DC_Supernet`, `TCP_53`, `UDP_53`) in rule #104 (`uid-arule-<domain>-0104`) and provide `mds/show-global-assignments.json`
- **AND** the dataset SHALL preserve `10` domains, `341` cached assets, `315` gateways (with `simple-gateway`, HA cluster, and `CpmiVsNetobj` Virtual Systems per user domain plus `>= 15` cross-domain Virtual Systems), and `325` CLI routing targets
- **AND** it SHALL preserve unique per-domain gateway/interface IPs and Virtual System internal `/24` subnets plus complete `CpmiVsxSlotObj` / `CpmiVsSlotObj` entries
- **AND** it SHALL preserve `105` access rules in `3` sections per domain, `12` NAT rules per domain, `< 250` topology-cached objects, and unmodified rule #1 fixtures

### Requirement: File-Backed Check Point API and Gateway CLI Replay Doubles

**ID**: REQ-ITEST-007\
**Intent**: Emulate Check Point `ApiPort` pagination/queries and `GatewayCliPort` VSX context checks deterministically offline.\
**Non-goals**: Standalone HTTPS HTTP server wrapper (`REQ-ITEST-008`) or write overlays (`REQ-ITEST-009`).

The testing package SHALL provide `FileReplayApiMock` (`ApiPort`) and `FileReplayCliMock` (`GatewayCliPort`) backed by the disk raw dataset, emulating pagination (`limit`/`offset`/`from`/`to`/`total`), `details-level`, `uid`/`name`/`class-name` filters, `use-object-dictionary=False` rulebase inlining, `where-used`, `run-script` + `show-task`, VSX CLI checks, per-`sid` writes, and redacted call logs.

#### Scenario: SCN-ITEST-007-1 — Paginated API queries and VSX CLI context validation execute against raw fixture files

- **WHEN** `ArodonataClient` queries `FileReplayApiMock` (`limit`/`offset`, `uid`/`name`/`class-name`, `where-used`, `show-*-rulebase` with `use-object-dictionary=True | False`) and invokes `FileReplayCliMock` (or `run-script` + `show-task`)
- **THEN** `FileReplayApiMock` SHALL return continuity-valid slices (`from`, `to`, `total`), resolve direct/indirect `where-used`, and inline `objects-dictionary` when `use-object-dictionary=False`
- **AND** `FileReplayApiMock` SHALL return Base64 `show-task` payloads and record per-command call counters
- **AND** `FileReplayCliMock` SHALL verify `vsenv` / `vsx stat -l` and `CTX%05d` `$FWDIR` guards before returning the raw CLI stdout for the target node and VSID

#### Scenario: SCN-ITEST-007-2 — Stateless read calls without SID continue reading published domain state

- **WHEN** read-only `FileReplayApiMock.api_call(...)` or `api_query(...)` is called with `sid=None`
- **THEN** `FileReplayApiMock` SHALL serve responses from the domain's published snapshot without failing authentication

### Requirement: Standalone Check Point Web API HTTPS Mock Server for Downstream Applications

**ID**: REQ-ITEST-008\
**Intent**: Allow downstream services and tests to run full real-HTTPS Check Point read/write workflows locally without a live lab.\
**Non-goals**: In-memory replay state isolation semantics (`REQ-ITEST-009`..`REQ-ITEST-014`).

The testing package SHALL provide an embeddable and CLI-runnable HTTPS server (`python -m arodonata.testing.mock_server`) sharing unified session, async task, and mutation state with `FileReplayApiMock`, serving `/web_api/{cmd}` with host-rewritten `show-domains`, `X-chkp-sid` session enforcement, and fast state reset controls so downstream applications can run full read and write workflows against `localhost:<port>`.

#### Scenario: SCN-ITEST-008-1 — Downstream application connects over HTTPS to localhost and syncs multi-domain dataset

- **GIVEN** `CheckPointReplayHttpServer` listening on `localhost:<port>`
- **WHEN** a client connects via real `AMgmtClient` TLS transport and logs in via `/web_api/login`
- **THEN** `/web_api/login` SHALL issue domain-bound `X-chkp-sid` tokens and `/web_api/show-domains` SHALL rewrite server `ipv4-address` fields to the bound host
- **AND** `/web_api/{cmd}` endpoints (`show-gateways-and-servers`, `show-hosts`, `show-groups`, `show-packages`, `show-access-rulebase`, `run-script`, `show-task`) SHALL return paginated raw domain datasets without rate-limit delays

#### Scenario: SCN-ITEST-008-2 — Downstream application executes stateful write workflows and resets state via CheckPointReplayHttpServer

- **WHEN** an HTTPS client logs in, runs mutating `/web_api/{cmd}` calls, and polls `/web_api/show-task` for async tasks (`publish`, `show-changes`, `verify-policy`, `install-policy`, `assign-global-assignment`, `assign-global-policy`, `run-script`)
- **AND** the client subsequently resets server state between test scenarios
- **THEN** `/web_api/{cmd}` SHALL enforce HTTP `401` (`generic_err_missing_required_header` or `generic_err_invalid_session_id`) on missing or invalid `X-chkp-sid`
- **AND** committed writes SHALL appear immediately across subsequent requests, and `snapshot_state()`, `restore_state()`, `reset()`, or opt-in `/__testing__/*` endpoints SHALL restore clean state

### Requirement: Per-Session Staging Overlay and Read-Your-Own-Writes Isolation

**ID**: REQ-ITEST-009\
**Intent**: Emulate Check Point's copy-on-write work-session isolation, read-only guards, and cross-session object locks faithfully.\
**Non-goals**: Publish, discard, and adoption lifecycle transitions (`REQ-ITEST-010`).

`FileReplayApiMock` and `CheckPointReplayHttpServer` MUST isolate uncommitted write operations inside a copy-on-write per-`sid` staging overlay (`login`, `create_dedicated_session`, `/web_api/login`) until `publish`, while enforcing Check Point `"read-only": true` restrictions and cross-session object locks.

#### Scenario: SCN-ITEST-009-1 — Uncommitted mutations are visible to the mutating SID and isolated from other sessions

- **GIVEN** Session A (`sid_a`) mutating objects, groups, or rules without calling `publish`
- **WHEN** Session A (`sid_a`) and Session B (`sid_b`, a read-only session, or `sid=None`) read from that domain
- **THEN** reads with `sid_a` SHALL reflect all uncommitted mutations, while reads with `sid_b`, `"read-only": true`, or `sid=None` SHALL see only the last published domain state

#### Scenario: SCN-ITEST-009-2 — Read-only sessions and object locks reject conflicting write commands

- **WHEN** a `"read-only": true` session sends a write command, OR Session B edits or deletes a UID currently modified or deleted in uncommitted Session A
- **THEN** the emulator SHALL reject the read-only write with HTTP `400` (`err_validation_failed`)
- **AND** it SHALL reject Session B's conflicting edit with HTTP `400` (`generic_err_object_locked`)

### Requirement: Session Lifecycle, Adoption, Discard, and Change History Emulation

**ID**: REQ-ITEST-010\
**Intent**: Emulate Check Point session commit, discard, takeover, rotation, and `show-changes` history for end-to-end testing.\
**Non-goals**: Per-session staging overlay isolation (`REQ-ITEST-009`).

The emulator SHALL support `login`, `logout` / `logout_sid`, `set-session`, `take-over-session`, `switch-session`, `publish`, `discard`, `show-session`, `show-sessions`, `show-last-published-session`, and `show-changes` with atomic publish commits, post-publish work-session rotation, rollback on discard or logout without publish, and structured change deltas.

#### Scenario: SCN-ITEST-010-1 — Publish commits overlay atomically, rotates active work session, and records change history

- **WHEN** a write session calls `publish` (`{}` or `{"uid": <session_uid>}`)
- **THEN** the emulator SHALL apply the overlay atomically, update `show-last-published-session`, prepend the revision (`published-changes`, `number-of-published-changes`) to `show-sessions`, and record `show-changes` deltas
- **AND** it SHALL return a completed `tasks` response (`wait_for_task=True`) or pollable `task-id` (`wait_for_task=False`) and rotate `sid` to a fresh `"open"` session (`changes=0`, `locks=0`, `number-of-published-changes=0`, no `publish-time`)

#### Scenario: SCN-ITEST-010-2 — Discard, logout without publish, set-session, take-over-session, and switch-session manage uncommitted state

- **WHEN** a client executes `set-session`, `take-over-session` (`uid`, optional `disconnect-active-session`), `switch-session` (`uid`), `discard` (`{}` or `{"uid": <target_session_uid>}`), or `logout`/`logout_sid` before `publish`
- **THEN** `set-session` SHALL persist `name` and `description` in `show-session`, and session adoption SHALL transfer the overlay (invalidating disconnected active SIDs with HTTP `401` `generic_err_invalid_session_id`)
- **AND** `discard` (or clean `logout`) SHALL roll back uncommitted changes and release locks immediately, whereas `logout` on a dirty uncommitted session SHALL transition the session to `"disconnected"` while preserving object locks for Check Point parity

#### Scenario: SCN-ITEST-010-3 — Querying show-changes returns structured deltas for staged and published sessions

- **WHEN** `show-changes` queries a published session (`to-session`, optional `from-session`, `from-date`, `to-date`) or an uncommitted staged session
- **THEN** the emulator SHALL return `changes[]` items carrying `added-objects`, `modified-objects`, `deleted-objects`, `added-rules`, `modified-rules`, and `deleted-rules` directly (without an `.operations` wrapper)
- **AND** each bucket entry SHALL carry `old-object`, `new-object`, `field-changes`, `layer`, `package`, `rule-number`, and `old-rule-number` metadata
- **AND** it SHALL return a completed task (`wait_for_task=True`) or pollable `task-id` (`wait_for_task=False`)

### Requirement: Stateful Object, Service, and Group CRUD Operations

**ID**: REQ-ITEST-011\
**Intent**: Emulate Check Point CRUD semantics, validation errors, and unused-object cleanup across objects, services, and groups.\
**Non-goals**: Deletion blocking when references remain (`REQ-ITEST-012`) or rulebase CRUD (`REQ-ITEST-013`).

The emulator SHALL support `add-*`, `set-*`, `delete-*`, and singular `show-*` commands for `host`, `network`, `address-range`, `dns-domain`, `application-site`, `group`, `service-tcp`, `service-udp`, `service-icmp`, `service-icmp6`, `service-other`, and `service-group`, plus `show-unused-objects` and `delete-unused-objects`.

#### Scenario: SCN-ITEST-011-1 — CRUD lifecycle for network objects, services, and groups

- **WHEN** a write session creates, renames (`new-name`), updates (`set-*`, `members` full or `add`/`remove`, `groups`, `set-if-exists`), and deletes supported objects, services, or groups
- **THEN** the emulator SHALL enforce name uniqueness (`ignore-warnings` for value warnings), keep bidirectional group memberships consistent, and return `generic_err_object_not_found` for unknown UIDs or names

#### Scenario: SCN-ITEST-011-2 — Unused object discovery and cleanup via show-unused-objects and delete-unused-objects

- **WHEN** `show-unused-objects` or `delete-unused-objects` runs (with optional object or group filters)
- **THEN** `show-unused-objects` SHALL return domain objects with zero references in groups, Access/NAT rules, or gateway interfaces
- **AND** `delete-unused-objects` SHALL delete only unreferenced local objects into the active staging overlay while leaving referenced and `Global` objects intact

### Requirement: Referential Integrity Enforcement on Object and Service Deletion

**ID**: REQ-ITEST-012\
**Intent**: Reproduce Check Point server-side deletion rejections accurately for decommission and rollback testing.\
**Non-goals**: Non-referenced object CRUD (`REQ-ITEST-011`).

The emulator MUST reject `delete-*` on any object, service, or group that is still referenced within the effective domain by any group, Access rule (enabled or disabled), NAT rule, or gateway interface topology.

#### Scenario: SCN-ITEST-012-1 — Deleting a referenced object, service, or group fails with Check Point validation error

- **WHEN** a write session calls `delete-host`, `delete-network`, `delete-address-range`, `delete-dns-domain`, `delete-application-site`, `delete-group`, or `delete-service-*`
- **AND** the target entity is still referenced by a group, Access rule, NAT rule, or gateway topology
- **THEN** the emulator SHALL reject the deletion with HTTP `400` and `generic_err_object_cannot_be_deleted` (with `blocking-errors` identifying referencers, compatible with `err_validation_failed`)
- **AND** the target entity SHALL remain intact

#### Scenario: SCN-ITEST-012-2 — Deleting an object succeeds after removing all group and rule references

- **WHEN** a workflow removes the target object from referencing groups (`set-group` with `members.remove`), removes it from multi-member rule cells or disables/deletes sole-member rules, and then calls `delete-*`
- **THEN** `delete-*` SHALL succeed once zero staged references remain in the session overlay

### Requirement: Access, HTTPS, Threat, and NAT Rulebase CRUD and Consistency

**ID**: REQ-ITEST-013\
**Intent**: Keep rule numbers, section bounds, `objects-dictionary`, `where-used`, and `show-objects` consistent across staged rulebase edits.\
**Non-goals**: MDSM `Global` domain write protection (`REQ-ITEST-014`).

The emulator SHALL support Access, HTTPS, Threat-prevention, and NAT rulebase, rule, and section CRUD, read-only `show-{access,https,threat}-layer(s)` with `inline-layer` references, and `verify-policy`/`install-policy` task simulation, automatically recomputing sequential rule numbers, section ranges, live `objects-dictionary`, `show-objects`, `show-object`, and `where-used`.

#### Scenario: SCN-ITEST-013-1 — Access rule, section, and read-only inline-layer reads maintain rule-numbers, section bounds, and objects-dictionary

- **WHEN** a write session executes Access rule/section CRUD or `show-{access,https,threat}-layer(s)` (including `inline-layer` references), toggles `enabled`, or patches rule cells via list replacement or `{"add": ..., "remove": ...}`
- **AND** rules are positioned via `position` / `new-position` (`"top"`, `"bottom"`, 1-based `rule-number`, `{"top": section}`, `{"bottom": section}`, `{"above": ref}`, `{"below": ref}`)
- **THEN** the emulator SHALL strip `"Any"` (`97aeb369-9aea-11d5-bd16-0090272ccb30`) on member addition, revert emptied cells to `"Any"`, and recompute sequential 1-based `rule-number`, section `from`/`to`, and layer `total`
- **AND** `show-access-rule`, `show-access-rulebase`, and `show-{access,https,threat}-layer(s)` SHALL reflect live `objects-dictionary` entries (or inline dicts for `use-object-dictionary=False`) and layer metadata

#### Scenario: SCN-ITEST-013-2 — HTTPS, Threat-prevention, and NAT rulebase CRUD and policy verification/install tasks

- **WHEN** a write session runs `show-https-rulebase`, `show-threat-rulebase`, `https-rule`/`threat-rule` CRUD, or `verify-policy`/`install-policy`
- **AND** NAT rules/sections run with `"Original"`, `"Any"`, sentinel UIDs (`85c0f50f-6d8a-4528-88ab-5fb11d8fe16c` / `97aeb369-9aea-11d5-bd16-0090272ccb30`), names, or UIDs
- **THEN** the emulator SHALL store normalized sentinel/object UIDs, recompute rule numbers, section `from`/`to` bounds, and `objects-dictionary`
- **AND** it SHALL return updated `show-nat-rule` / `show-*-rulebase` data and Check Point task responses for `verify-policy` and `install-policy`

#### Scenario: SCN-ITEST-013-3 — Post-mutation reads stay consistent across where-used, show-objects, show-object, and inline rulebases

- **WHEN** any group membership or Access/NAT rule cell is mutated in a session overlay or published into domain state
- **THEN** subsequent `where-used` (direct and indirect), `show-objects`, `show-object`, singular `show-*`, and `show-*-rulebase` (`use-object-dictionary=True | False`) calls SHALL immediately reflect the updated references

### Requirement: MDSM Global Domain Visibility, Write Protection, and Policy Assignment

**ID**: REQ-ITEST-014\
**Intent**: Emulate MDSM `Global` object read visibility from local domains, local write refusal, and global policy assignments.\
**Non-goals**: Standalone single-domain object CRUD (`REQ-ITEST-011`).

In MDSM mode, `Global` domain entities SHALL be readable from local domain sessions and visible in rule references, whereas attempts to modify or delete `Global` objects or rules from a local domain session MUST fail with a realistic Check Point read-only / domain-ownership error, and `assign-global-assignment` / `assign-global-policy` SHALL be supported.

#### Scenario: SCN-ITEST-014-1 — Local domain queries resolve Global objects while bulk domain syncs remain domain-scoped

- **WHEN** a local domain (`Branch`, `Perimeter`) queries `show-object`, `show-objects`, singular `show-*`, `where-used`, or `show-*-rulebase` referencing `Global` entities
- **THEN** lookups and `objects-dictionary` SHALL resolve `Global` entities tagged with `"domain": {"uid": "uid-dom-global", "name": "Global", "domain-type": "global domain"}`
- **AND** bulk sync endpoints (`show-hosts`, `show-networks`, `show-groups`, `show-services-*`) SHALL remain scoped strictly to the queried local domain

#### Scenario: SCN-ITEST-014-2 — Local domain sessions cannot modify or delete Global objects or Global rules

- **WHEN** a write session opened on a local domain invokes `set-*` or `delete-*` on a `Global` object, service, group, or Global rule/layer
- **THEN** the emulator SHALL reject the mutation with HTTP `400` (`generic_err_object_read_only` / `err_validation_failed`) without modifying `Global` state
- **AND** a write session opened directly on `"Global"` MAY mutate unreferenced `Global` objects while still enforcing cross-domain referential integrity on deletion

#### Scenario: SCN-ITEST-014-3 — Global policy assignment emulates Check Point task execution and assignment metadata

- **WHEN** a client executes `assign-global-assignment` (or `assign-global-policy`) and `show-global-assignment` / `show-global-assignments`
- **THEN** the emulator SHALL update global assignment metadata for the specified `global-domains` and `dependent-domains`
- **AND** it SHALL return `{"tasks": [...]}` (`wait_for_task=True`) or pollable `task-id` metadata (`wait_for_task=False`)

### Requirement: Fast In-Memory State Snapshot, Restore, and Reset

**ID**: REQ-ITEST-015\
**Intent**: Reset emulator state between test cases in milliseconds without touching disk fixtures.\
**Non-goals**: Live lab revision revert (`REQ-ITEST-005`).

`FileReplayApiMock` and `CheckPointReplayHttpServer` SHALL provide fast in-memory state snapshot, restore, and reset primitives so test suites roll back all domain mutations, active sessions, tasks, and attached CLI overrides between scenarios without re-reading or regenerating disk fixtures.

#### Scenario: SCN-ITEST-015-1 — Snapshot, restore, and reset roll back emulator and CLI state in milliseconds

- **WHEN** a test captures `snap = api_mock.snapshot_state()` (or `/__testing__/snapshot`), mutates domain state or `FileReplayCliMock` overrides, and calls `restore_state(snap)` or `reset()` (or `/__testing__/restore` / `/__testing__/reset`)
- **THEN** all published domain data, MDSM assignments, session bindings, work sessions, `show-changes` history, dynamic tasks, and CLI overrides SHALL revert cleanly in memory with zero disk I/O

### Requirement: SID-Redacted Call Auditing and OpenTelemetry Span Hygiene

**ID**: REQ-ITEST-016\
**Intent**: Give tests structured SID-redacted call logs, scan/global-safety assertions, and end-to-end OTel hygiene verification.\
**Non-goals**: Core telemetry attribute decorator implementation (`REQ-CLIENT-015`).

The emulator SHALL record `sid`-redacted call audit entries (`call_log`), expose test assertion helpers, and propagate provider-agnostic OpenTelemetry spans (`@traced`) without owning a global `TracerProvider` or leaking credentials or raw session IDs.

#### Scenario: SCN-ITEST-016-1 — Enriched call_log and assertion helpers verify domain safety and query efficiency

- **WHEN** tests run workflows against `FileReplayApiMock` or `CheckPointReplayHttpServer` and inspect `call_log` or `get_calls(...)`
- **AND** tests invoke `assert_no_global_mutations()`, `assert_no_full_object_scans()`, `assert_command_called(...)`, or `assert_command_not_called(...)`
- **THEN** every `call_log` entry SHALL record `mgmt_name`, `domain`, `command`, `is_mutating`, `sid_ref` (`"sid#..."`), `session_uid`, `read_only_session`, sanitized `payload`, `payload_summary`, `status_code`, `success`, and `error_code`
- **AND** `call_log` entries SHALL contain zero raw `sid`, `api-key`, or `password` values
- **AND** assertion helpers SHALL raise descriptive failures on any unexpected `Global` mutation or any full-table `show-hosts`, `show-networks`, `show-address-ranges`, or `show-groups` call regardless of pagination flags

#### Scenario: SCN-ITEST-016-2 — OpenTelemetry spans propagate over FileReplayApiMock and CheckPointReplayHttpServer without SID leakage

- **GIVEN** an external host test attaching `InMemorySpanExporter` to its own `TracerProvider`
- **WHEN** `ArodonataClient` runs E2E write, publish, and diff workflows over both `FileReplayApiMock` and `CheckPointReplayHttpServer`
- **THEN** `@traced` spans SHALL record expected span names, `arodonata.*` attributes, and statuses without configuring any global `TracerProvider`
- **AND** zero occurrences of raw `sid`, `X-chkp-sid`, `api-key`, or `password` strings SHALL appear across all span names, attributes, events, and status descriptions

### Requirement: Progressive Runnable SDK Examples Catalog

**ID**: REQ-ITEST-017\
**Intent**: Document every major SDK capability with executable, lab-safe examples including authenticated ASGI MCP embedding.\
**Non-goals**: Core library runtime features covered in feature specs.

The repository SHALL provide a runnable `examples/` catalog demonstrating Arodonata v2 capabilities from basic cached queries to advanced multi-tenant contexts, CPCRUD, change reports, OpenTelemetry tracing, and ASGI MCP embedding, ensuring that embedded MCP examples enforce host or bearer authentication when write tools (`cpcrud=True` or `allow_write_api=True`) are enabled.

#### Scenario: SCN-ITEST-017-1 — Examples cover core and advanced v2 workflows with crash-safe lab guard

- **WHEN** a developer inspects or executes scripts in `examples/`
- **THEN** scripts `01`–`07` SHALL cover basic queries (`01`), search/query (`02`), gateway/VSX relationships (`03`), streaming sync (`04`), rulebases/numbering (`05`), session lifecycle (`06`), and contexts/`SessionOverlay` (`07`)
- **AND** scripts `08`–`13` SHALL cover CPCRUD apply (`08`) and inverse (`09`), change reports (`10`), OTel tracing (`11`), authenticated FastAPI MCP embedding (`12`), and gateway topology/candidate matching (`13`)
- **AND** all mutating examples SHALL wrap execution in `guarded_session` so target lab domains restore automatically on exit

### Requirement: Emulator Repository-Script CRUD and Permission Toggles

**ID**: REQ-ITEST-018\
**Intent**: Emulate Check Point repository-script lifecycle CRUD and session/permission enforcement offline cleanly alongside gateway route-collection scenarios.\
**Non-goals**: Gateway CPRID route-collection execution covered in `REQ-TOPO-018`.

`FileReplayApiMock` and `CheckPointReplayHttpServer` SHALL implement per-domain `add-repository-script`, `show-repository-script`, `show-repository-scripts`, `set-repository-script`, and `delete-repository-script` inside uncommitted staging overlays until `publish`, honoring `allow_one_time_script`, `allow_repository_script`, and `manage_repository_scripts` permission flags.

#### Scenario: SCN-ITEST-018-1 — Emulator enforces repository-script CRUD isolation and permission toggles

- **WHEN** callers run `add/set/delete/show-repository-script(s)` or configure `allow_one_time_script`, `allow_repository_script`, or `manage_repository_scripts` on `FileReplayApiMock`
- **THEN** uncommitted script edits SHALL remain isolated to the writing session until `publish`
- **AND** disabling `manage_repository_scripts` or `allow_repository_script` SHALL reject restricted operations with Check Point permission errors
