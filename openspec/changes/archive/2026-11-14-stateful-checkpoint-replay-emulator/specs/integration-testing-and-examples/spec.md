# Spec Delta

## MODIFIED Requirements

### Requirement: Deterministic Enterprise Raw Dataset and Generator

The testing harness SHALL provide a deterministic (fixed-seed) generator and raw fixture dataset (`tests/fixtures/enterprise_raw_dataset/`) containing Check Point Management API JSON payloads (including MDSM global assignments and deterministic `Global` object/group usage in local rules without altering baseline domain, asset, gateway, rulebase, or topology counts) and gateway CLI routing outputs for an enterprise MDSM topology.

#### Scenario: Raw dataset covers multi-domain API payloads and gateway CLI outputs

- **WHEN** the enterprise raw dataset is generated or loaded from `tests/fixtures/enterprise_raw_dataset/`
- **THEN** it SHALL provide deterministic raw Check Point API JSON files (`show-domains`, `show-global-assignments`, `show-sessions`, `show-last-published-session`, `show-session`, `show-gateways-and-servers`, `show-simple-gateway`, `show-simple-cluster`, `show-generic-object`, `show-generic-objects`, `show-hosts`, `show-networks`, `show-address-ranges`, `show-groups` nested 6–7 levels deep, `show-services-*`, `show-packages`, `show-access-layers`, `show-access-rulebase`, `show-nat-rulebase`) and raw CLI stdout files (`vsx stat -l`, `ip -4 route show`, `clish -c "show route"`, and Base64 `run-script`/`show-task` payloads) across 9 user MDSM domains plus `Global`

#### Scenario: Raw dataset includes deterministic Global object and group usage in local domain rules without breaking scale invariants

- **WHEN** `ensure_enterprise_raw_dataset()` materializes `tests/fixtures/enterprise_raw_dataset/`
- **THEN** local user domains SHALL deterministically reference `Global` objects, services, and groups (such as `H_Global_DNS_001`, `G_Global_Branch_Supernet`, `G_Global_DC_Supernet`, `TCP_53`, and `UDP_53`) inside existing Access rule #104 (`uid-arule-<domain>-0104`) and expose `mds/show-global-assignments.json` while preserving existing scale invariants (`10` domains, `284` cached assets, `276` gateways, `105` access rules in `3` sections per domain, `12` NAT rules per domain, fewer than `250` topology-cached objects, and unmodified rule #1 fixtures)

### Requirement: File-Backed Check Point API and Gateway CLI Replay Doubles

The testing package SHALL provide `FileReplayApiMock` (`ApiPort`) and `FileReplayCliMock` (`GatewayCliPort`) backed by the raw dataset on disk, emulating Check Point pagination (`limit`/`offset`/`from`/`to`/`total`), `details-level`, `uid`/`name`/`class-name` filtering, rulebase slicing with `use-object-dictionary=False` inlining, `where-used` dependency resolution, `run-script` + `show-task`, VSX CLI validation, stateful per-`sid` mutations, and redacted call auditing.

#### Scenario: Paginated API queries and VSX CLI context validation execute against raw fixture files

- **WHEN** `ArodonataClient` queries `FileReplayApiMock` with `limit`/`offset`, `uid`/`name`/`class-name` filters, `where-used`, or `show-access-rulebase` / `show-nat-rulebase` (`use-object-dictionary=True | False`), and executes route collection scripts against `FileReplayCliMock` (or `run-script` + `show-task` fallback)
- **THEN** `FileReplayApiMock` SHALL return continuity-valid slices (`from`, `to`, `total`), resolve `where-used` direct and indirect group/access-rule/NAT-rule references (and inline `objects-dictionary` dicts when `use-object-dictionary=False`), and return Base64-encoded `show-task` responses from the raw dataset while recording per-command call counters, and `FileReplayCliMock` SHALL verify `vsenv` / `vsx stat -l` and `CTX%05d` `$FWDIR` guards before returning the raw CLI stdout for the target node and VSID

#### Scenario: Stateless read calls without SID continue reading published domain state

- **WHEN** a caller invokes read-only `FileReplayApiMock.api_call(...)` or `api_query(...)` with `sid=None`
- **THEN** `FileReplayApiMock` SHALL continue serving responses from the domain's published snapshot without failing authentication, ensuring existing unit and topology scale tests remain backward-compatible

### Requirement: Standalone Check Point Web API HTTPS Mock Server for Downstream Applications

The testing package SHALL provide an embeddable and CLI-runnable HTTPS server (`python -m arodonata.testing.mock_server`) sharing unified session, async task, and mutation state with `FileReplayApiMock`, serving `/web_api/{cmd}` with host-rewritten `show-domains`, `X-chkp-sid` session enforcement, and fast state reset controls so downstream applications can run full read and write workflows against `localhost:<port>`.

#### Scenario: Downstream application connects over HTTPS to localhost and syncs multi-domain dataset

- **WHEN** `CheckPointReplayHttpServer` is started on `localhost:<port>` (e.g., `localhost:443` or an ephemeral test port) and a client connects via real `AMgmtClient` / `ApiTransport`
- **THEN** `/web_api/login` SHALL issue domain-bound session tokens (`X-chkp-sid`), `/web_api/show-domains` SHALL rewrite active CMA/MDS server `ipv4-address` fields to the server's bound host, and subsequent `/web_api/{cmd}` requests (`show-gateways-and-servers`, `show-hosts`, `show-groups`, `show-packages`, `show-access-rulebase`, `run-script`, `show-task`, etc.) SHALL return the corresponding domain's paginated raw dataset without artificial rate limiting or login delays

#### Scenario: Downstream application executes stateful write workflows and resets state via CheckPointReplayHttpServer

- **WHEN** an HTTPS client authenticates via `/web_api/login`, executes mutating `/web_api/{cmd}` calls, polls `/web_api/show-task` for asynchronous commands (`publish`, `show-changes`, `assign-global-assignment`, `assign-global-policy`, `run-script`), and subsequently resets server state between test scenarios
- **THEN** `/web_api/{cmd}` SHALL enforce HTTP `401` (`generic_err_missing_required_header` or `generic_err_invalid_session_id`) on missing or invalidated `X-chkp-sid` headers, reflect committed changes immediately across subsequent HTTPS requests, and restore clean state via `snapshot_state()`, `restore_state()`, `reset()`, or opt-in `/__testing__/*` endpoints

## ADDED Requirements

### Requirement: Per-Session Staging Overlay and Read-Your-Own-Writes Isolation

`FileReplayApiMock` and `CheckPointReplayHttpServer` MUST isolate uncommitted write operations inside a copy-on-write per-`sid` staging overlay (`login`, `create_dedicated_session`, `/web_api/login`) until `publish`, while enforcing Check Point `"read-only": true` restrictions and cross-session object locks.

#### Scenario: Uncommitted mutations are visible to the mutating SID and isolated from other sessions

- **WHEN** Session A (`sid_a`) creates, modifies, or deletes objects, groups, or rules without calling `publish`, and both Session A and Session B (`sid_b`, a read-only session, or `sid=None`) read from the same domain
- **THEN** reads using `sid_a` SHALL reflect all uncommitted mutations in Session A's staging overlay, while reads using `sid_b`, a `"read-only": true` session, or `sid=None` SHALL observe only the last published domain state

#### Scenario: Read-only sessions and object locks reject conflicting write commands

- **WHEN** a client sends a mutating command using a `"read-only": true` session SID, OR Session B attempts to modify or delete an existing object or rule UID currently modified or deleted by open uncommitted Session A
- **THEN** the emulator SHALL reject the read-only write with HTTP `400` (`err_validation_failed`) and reject the conflicting edit with HTTP `400` (`generic_err_object_locked`)

### Requirement: Session Lifecycle, Adoption, Discard, and Change History Emulation

The emulator SHALL support `login`, `logout` / `logout_sid`, `set-session`, `take-over-session`, `switch-session`, `publish`, `discard`, `show-session`, `show-sessions`, `show-last-published-session`, and `show-changes` with atomic publish commits, post-publish work-session rotation, rollback on discard or logout without publish, and structured change deltas.

#### Scenario: Publish commits overlay atomically, rotates active work session, and records change history

- **WHEN** a write session calls `publish` (`{}` or `{"uid": <session_uid>}`)
- **THEN** the emulator SHALL atomically apply the session's overlay into published domain state, update `show-last-published-session` and prepend the published revision (including `published-changes` and `number-of-published-changes`) to `show-sessions`, record structured deltas for `show-changes`, return a completed `tasks` response when `wait_for_task=True` or a pollable `task-id` when `wait_for_task=False`, and bind `sid` to a fresh `"open"` work session (`changes=0`, `locks=0`, `number-of-published-changes=0`, no `publish-time`)

#### Scenario: Discard, logout without publish, set-session, take-over-session, and switch-session manage uncommitted state

- **WHEN** a client updates session metadata via `set-session`, adopts or switches an open session via `take-over-session` (`uid`, optional `disconnect-active-session`) or `switch-session` (`uid`), or invokes `discard` (`{}` or `{"uid": <target_session_uid>}`) or `logout` / `logout_sid` before `publish`
- **THEN** `set-session` SHALL persist session `name` and `description` in `show-session`, session adoption SHALL transfer the staging overlay and invalidate disconnected active SIDs with HTTP `401` (`generic_err_invalid_session_id`), and `discard` or `logout` SHALL roll back all uncommitted overlay changes and release session object locks

#### Scenario: Querying show-changes returns structured deltas for staged and published sessions

- **WHEN** a client invokes `show-changes` targeting a published session (`to-session`, optional `from-session`, `from-date`, `to-date`) or an uncommitted staged session
- **THEN** the emulator SHALL return Check Point `changes[].operations` buckets (`added-objects`, `modified-objects`, `deleted-objects`, `added-rules`, `modified-rules`, `deleted-rules`) with `old-object`, `new-object`, `field-changes`, `layer`, `package`, `rule-number`, and `old-rule-number` metadata, wrapped as a completed task when `wait_for_task=True` or a `task-id` for `show-task` when `wait_for_task=False`

### Requirement: Stateful Object, Service, and Group CRUD Operations

The emulator SHALL support `add-*`, `set-*`, `delete-*`, and singular `show-*` commands for `host`, `network`, `address-range`, `dns-domain`, `application-site`, `group`, `service-tcp`, `service-udp`, `service-icmp`, `service-icmp6`, `service-other`, and `service-group`, plus `show-unused-objects` and `delete-unused-objects`.

#### Scenario: CRUD lifecycle for network objects, services, and groups

- **WHEN** a write session creates, renames (`new-name`), updates (`set-*` including `members` full replacement or `{"add": ..., "remove": ...}`, `groups` updates, and `set-if-exists`), and deletes supported network objects, services, or groups
- **THEN** the emulator SHALL enforce Check Point uniqueness validation (`ignore-warnings` awareness for duplicate values, error on duplicate names), maintain bidirectional group membership consistency across staged reads, and return Check Point `generic_err_object_not_found` for unknown UIDs or names

#### Scenario: Unused object discovery and cleanup via show-unused-objects and delete-unused-objects

- **WHEN** a client calls `show-unused-objects` or a write session calls `delete-unused-objects` (with optional object or group filters)
- **THEN** `show-unused-objects` SHALL return domain objects with zero references in groups, Access rules, NAT rules, or gateway interfaces, and `delete-unused-objects` SHALL remove only unreferenced local objects into the active staging overlay while leaving referenced or `Global` objects untouched

### Requirement: Referential Integrity Enforcement on Object and Service Deletion

The emulator MUST reject `delete-*` on any object, service, or group that is still referenced within the effective domain by any group, Access rule (enabled or disabled), NAT rule, or gateway interface topology.

#### Scenario: Deleting a referenced object, service, or group fails with Check Point validation error

- **WHEN** a write session calls `delete-host`, `delete-network`, `delete-address-range`, `delete-dns-domain`, `delete-application-site`, `delete-group`, or `delete-service-*` for an entity still referenced by a group, Access rule, NAT rule, or gateway topology
- **THEN** the emulator SHALL reject the deletion with HTTP `400` and Check Point error code `generic_err_object_cannot_be_deleted` (including `blocking-errors` identifying the referencing entities, compatible with `err_validation_failed` checks) and leave the target entity intact

#### Scenario: Deleting an object succeeds after removing all group and rule references

- **WHEN** a Decommission workflow first removes the target object from referencing groups (`set-group` with `members.remove`), removes it from multi-member rule cells or disables/deletes sole-member rules (`set-*-rule` / `delete-*-rule`), and then invokes `delete-*`
- **THEN** `delete-*` SHALL succeed because zero staged references remain in the session overlay

### Requirement: Access and NAT Rulebase CRUD, Positioning, and Automatic Consistency

The emulator SHALL support `show-access-rule`, `add-access-rule`, `set-access-rule`, `delete-access-rule`, `add-access-section`, `set-access-section`, `delete-access-section`, `show-nat-rule`, `add-nat-rule`, `set-nat-rule`, `delete-nat-rule`, `add-nat-section`, `set-nat-section`, and `delete-nat-section`, automatically recomputing rule numbers, section ranges, live `objects-dictionary`, `show-objects`, `show-object`, and `where-used`.

#### Scenario: Access rule and section CRUD maintains rule-numbers, section bounds, and objects-dictionary

- **WHEN** a write session adds, edits, reorders (`position` / `new-position` with `"top"`, `"bottom"`, 1-based integer `rule-number`, `{"top": section}`, `{"bottom": section}`, `{"above": ref}`, `{"below": ref}`), enables/disables, or deletes Access rules or sections, or mutates rule cells via full replacement or `{"add": ..., "remove": ...}`
- **THEN** the emulator SHALL strip `"Any"` (`97aeb369-9aea-11d5-bd16-0090272ccb30`) when concrete members are added, revert emptied cells to `"Any"`, recompute sequential 1-based `rule-number` values and section `from`/`to` bounds (plus layer `total`), and return live `objects-dictionary` entries (or inline dicts for `use-object-dictionary=False`) on subsequent `show-access-rule` and `show-access-rulebase` reads

#### Scenario: NAT rule CRUD normalizes Original and Any sentinels and updates NAT rule numbers

- **WHEN** a write session creates, updates, repositions, or deletes NAT rules or sections in a package using `"Original"`, `"Any"`, sentinel UIDs (`85c0f50f-6d8a-4528-88ab-5fb11d8fe16c`, `97aeb369-9aea-11d5-bd16-0090272ccb30`), object names, or object UIDs
- **THEN** the emulator SHALL normalize and store sentinel/object UIDs cleanly, recompute sequential NAT `rule-number` values, section `from`/`to` bounds, and package `objects-dictionary`, and serve updated rules via `show-nat-rule` and `show-nat-rulebase`

#### Scenario: Post-mutation reads stay consistent across where-used, show-objects, show-object, and inline rulebases

- **WHEN** any group membership or Access/NAT rule cell is mutated in a session overlay or published into domain state
- **THEN** subsequent calls to `where-used` (direct and indirect), `show-objects`, `show-object`, singular `show-*`, and `show-*-rulebase` (`use-object-dictionary=True | False`) with visibility into that state SHALL immediately reflect added, renamed, re-bound, or removed references

### Requirement: MDSM Global Domain Visibility, Write Protection, and Policy Assignment

In MDSM mode, `Global` domain entities SHALL be readable from local domain sessions and visible in rule references, whereas attempts to modify or delete `Global` objects or rules from a local domain session MUST fail with a realistic Check Point read-only / domain-ownership error, and `assign-global-assignment` / `assign-global-policy` SHALL be supported.

#### Scenario: Local domain queries resolve Global objects while bulk domain syncs remain domain-scoped

- **WHEN** a client queries `show-object`, `show-objects`, singular `show-*`, `where-used`, or `show-*-rulebase` in a local domain (such as `Branch` or `Perimeter`) that references `Global` objects, services, or groups
- **THEN** those lookups and `objects-dictionary` entries SHALL resolve the `Global` entities tagged with `"domain": {"uid": "uid-dom-global", "name": "Global", "domain-type": "global domain"}`, while bulk per-domain sync endpoints (`show-hosts`, `show-networks`, `show-groups`, `show-services-*`) remain scoped to the queried domain

#### Scenario: Local domain sessions cannot modify or delete Global objects or Global rules

- **WHEN** a write session opened on a local domain invokes `set-*` or `delete-*` targeting a `Global`-owned object, service, group, or Global rule/layer (by UID or name)
- **THEN** the emulator SHALL reject the mutation with HTTP `400` (`generic_err_object_read_only` / `err_validation_failed`) without altering `Global` state, whereas a write session opened directly on the `Global` domain MAY mutate unreferenced `Global` objects (while still enforcing cross-domain referential integrity on deletion)

#### Scenario: Global policy assignment emulates Check Point task execution and assignment metadata

- **WHEN** a client executes `assign-global-assignment` (or `assign-global-policy`) and `show-global-assignment` / `show-global-assignments`
- **THEN** the emulator SHALL update global assignment metadata for the specified `global-domains` and `dependent-domains` and return a Check Point task response (`{"tasks": [...]}` for `wait_for_task=True` or pollable `{"task-id": ...}` / `{"tasks": [{"task-id": ...}]}` for `wait_for_task=False`)

### Requirement: Fast In-Memory State Snapshot, Restore, and Reset

`FileReplayApiMock` and `CheckPointReplayHttpServer` SHALL provide fast in-memory state snapshot, restore, and reset primitives so test suites roll back all domain mutations, active sessions, tasks, and attached CLI overrides between scenarios without re-reading or regenerating disk fixtures.

#### Scenario: Snapshot, restore, and reset roll back emulator and CLI state in milliseconds

- **WHEN** a test captures `snap = api_mock.snapshot_state()` (or via `CheckPointReplayHttpServer` method or `/__testing__/snapshot`), mutates or publishes domain state, modifies attached `FileReplayCliMock` overrides, and calls `api_mock.restore_state(snap)` or `reset()` (or `/__testing__/restore` / `/__testing__/reset`)
- **THEN** all published domain data, MDSM assignments, session bindings, work sessions, `show-changes` history, dynamic tasks, and attached CLI overrides SHALL revert cleanly in memory without disk I/O or dataset regeneration

### Requirement: SID-Redacted Call Auditing and OpenTelemetry Span Hygiene

The emulator SHALL record SID-redacted call audit entries (`call_log`), expose test assertion helpers, and emit provider-agnostic OpenTelemetry spans (`arodonata.core.telemetry`) without owning a global `TracerProvider` or leaking credentials or raw session IDs.

#### Scenario: Enriched call_log and assertion helpers verify domain safety and query efficiency

- **WHEN** tests run E2E workflows against `FileReplayApiMock` or `CheckPointReplayHttpServer` and inspect `call_log`, `get_calls(...)`, or invoke `assert_no_global_mutations()`, `assert_no_full_object_scans()`, `assert_command_called(...)`, or `assert_command_not_called(...)`
- **THEN** every `call_log` entry SHALL contain `mgmt_name`, `domain`, `command`, `is_mutating`, a deterministic non-secret `sid_ref` (`"sid#..."`), `session_uid`, `read_only_session`, sanitized `payload`, `payload_summary`, `status_code`, `success`, and `error_code` with zero raw `sid`, `api-key`, or `password` values, and assertion helpers SHALL raise descriptive failures if unexpected `Global` mutations or unpaginated bulk `show-hosts` / `show-networks` scans occur

#### Scenario: OpenTelemetry spans propagate over FileReplayApiMock and CheckPointReplayHttpServer without SID leakage

- **WHEN** an external host test configures `InMemorySpanExporter` on its own `TracerProvider` and runs `ArodonataClient` E2E write/publish/diff workflows over both `FileReplayApiMock` and `CheckPointReplayHttpServer`
- **THEN** Arodonata and replay spans SHALL record expected span names, `arodonata.*` attributes, and success/error statuses without initializing any global `TracerProvider` and with zero occurrences of raw `sid`, `X-chkp-sid`, `api-key`, or `password` strings across all span names, attributes, events, and status descriptions
