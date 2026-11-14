# Proposal

## Why

`FileReplayApiMock` (`src/arodonata/testing/replay_mock.py`) and `CheckPointReplayHttpServer` (`src/arodonata/testing/mock_server.py`) currently provide a read-only replay surface (`show-*`, `where-used`, `run-script`, `show-task`) plus ad-hoc in-memory helpers (`update_gateway_interfaces`, `bump_published_session`), while ignoring `sid` isolation, treating `login`, `publish`, `discard`, and `logout` as stateless no-ops, and rejecting all mutating commands (`add-*`, `set-*`, `delete-*`) as well as single-rule and session-diff queries (`show-access-rule`, `show-nat-rule`, `show-changes`) with `generic_err_command_not_recognized`. Because downstream MMP workflows (CACF, Decommission, Rule Creator, CPCRUD, Change Reports, AI MCP) require end-to-end verification of object/rule mutations, reference-cleanup sequencing, `Global` domain protections, session staging vs. publish/discard isolation, and change-report reconciliation, Arodonata needs a deterministic, in-memory stateful Check Point Management and MDSM emulator that exercises these flows without a live MDS appliance.

## What Changes

- **Unified Session Registry & Per-`sid` Copy-on-Write Staging Overlay (`FileReplayApiMock` & `CheckPointReplayHttpServer`)**:
  - Model Check Point `_WorkSession` records (`uid`, `domain`, `name`, `description`, `user-name`, `state`, `changes`, `locks`, `locked-uids`, `published-changes`, `publish-time`, copy-on-write `working_domain_data`, ordered `mutation_records`) separately from `_SidBinding` (`sid`, `sid_ref`, `mgmt_name`, `domain`, `session_uid`, `read_only`).
  - Enforce Check Point read-your-own-writes isolation: reads carrying a write `sid` observe that session's uncommitted overlay, whereas reads with another `sid`, a `"read-only": true` `sid`, or `sid=None` observe only published `_domain_data`.
  - Enforce Check Point session guards: reject mutations on `"read-only": true` sessions (`err_validation_failed`, HTTP `400`), missing `sid` on authenticated endpoints (`generic_err_missing_required_header`, HTTP `401`), invalidated/unknown `sid` (`generic_err_invalid_session_id`, HTTP `401`), and concurrent edits to an object/rule UID locked by another open session (`generic_err_object_locked`, HTTP `400`).
  - Implement full session lifecycle and diff commands: `login`, `logout` / `logout_sid`, `set-session` (`new-name`/`name`, `description`, `comments`, `tags`, `color`), `publish` (atomically commits session overlay into `_domain_data`, updates `show-last-published-session` and `show-sessions`, records structured delta for `show-changes`, rotates `sid` onto a fresh `"open"` work session with `changes=0`, `locks=0`, and no `publish-time` to match Check Point R81.20 and `arodonata.reports.placement`), `discard` (both current session `{}` and target `{"uid": "<session_uid>"}` for helper-session cleanup), `take-over-session` (`uid`, `disconnect-active-session`), `switch-session` (`uid`), and `show-changes` (`to-session`, `from-session`, `from-date`, `to-date` for both staged unpublished sessions and published revisions).

- **Stateful CRUD, Rule Positioning, Referential Integrity, and Automatic Read Consistency**:
  - Implement `add-*`, `set-*`, `delete-*`, and singular `show-*` for network objects, groups, and services (`host`, `network`, `address-range`, `dns-domain`, `application-site`, `group`, `service-tcp`, `service-udp`, `service-icmp`, `service-icmp6`, `service-other`, `service-group`), supporting list replacement and `{"add": ..., "remove": ...}` for `members`, `groups` membership sync, `new-name` rename propagation, `set-if-exists`, duplicate name/IP checks (`ignore-warnings`), `show-unused-objects`, and `delete-unused-objects`.
  - Enforce referential integrity on `delete-*`: reject deleting any object, service, or group still referenced by any group (`group`, `service-group`), Access rule (enabled or disabled), NAT rule, or gateway interface topology with HTTP `400` (`generic_err_object_cannot_be_deleted` plus `blocking-errors`, compatible with `err_validation_failed` checks).
  - Implement `show-access-rule`, `add-access-rule`, `set-access-rule`, `delete-access-rule`, `add-access-section`, `set-access-section`, `delete-access-section`, `show-nat-rule`, `add-nat-rule`, `set-nat-rule`, `delete-nat-rule`, `add-nat-section`, `set-nat-section`, and `delete-nat-section` with full `position` / `new-position` resolution (`"top"`, `"bottom"`, 1-based integer `rule-number`, `{"top": section}`, `{"bottom": section}`, `{"above": ref}`, `{"below": ref}`), cell `add`/`remove` mutations (stripping `"Any"` when adding concrete members and reverting emptied cells to `NAT_ANY_OBJECT_UID`), NAT `"Original"` / `"Any"` sentinel normalization, and automatic recomputation of sequential `rule-number`s, section `from`/`to` bounds, `total`, and live `objects-dictionary`.
  - Guarantee immediate post-mutation consistency across `where-used` (direct & indirect), `show-objects`, `show-object`, singular `show-*`, and `show-*-rulebase` (`use-object-dictionary=True | False`).

- **MDSM Domain Security, `Global` Visibility, and Policy Assignment**:
  - Expose `Global` domain objects, services, and groups (with `"domain": {"uid": "uid-dom-global", "name": "Global", "domain-type": "global domain"}`) to local-domain lookups (`show-object`, `show-objects`, singular `show-*`, `where-used`, rulebases) while keeping plural domain sync endpoints (`show-hosts`, `show-networks`, `show-groups`, `show-services-*`) domain-scoped.
  - Wire deterministic `Global` objects, services, and groups (`H_Global_DNS_001`, `G_Global_Branch_Supernet`, `G_Global_DC_Supernet`, `TCP_53`, `UDP_53`) into local domain rule #104 (`uid-arule-<domain>-0104`) in `dataset_generator.py` (`DATASET_VERSION = "1.1.0"`) plus `mds/show-global-assignments.json` without changing any existing scale-test counts (10 domains, 284 cached assets, 276 gateways, 105 access rules in 3 sections, 12 NAT rules, `<250` topology-cached objects, and untouched rule #1 fixtures).
  - Reject local-domain `set-*` / `delete-*` attempts against `Global`-owned objects, services, groups, or Global rules with HTTP `400` (`generic_err_object_read_only` / `err_validation_failed`), enforce cross-domain referential integrity on `Global` deletions, and support `assign-global-assignment` / `assign-global-policy` and `show-global-assignment` / `show-global-assignments`.

- **Fast State Snapshot/Reset, Redacted `call_log` Assertions, and OTEL Verification**:
  - Provide millisecond in-memory `snapshot_state()`, `restore_state(snapshot)`, and `reset()` on `FileReplayApiMock` and `CheckPointReplayHttpServer` (synchronizing attached `FileReplayCliMock` overrides and opt-in `/__testing__/reset`, `/__testing__/snapshot`, `/__testing__/restore`, `/__testing__/call-log` control endpoints).
  - Enrich `call_log` entries with `mgmt_name`, `domain`, `command`, `is_mutating`, deterministic redacted `sid_ref`, `session_uid`, `read_only_session`, `sanitize_mapping`-scrubbed `payload`, `payload_summary`, `status_code`, `success`, and `error_code` alongside assertion helpers (`assert_no_global_mutations`, `assert_no_full_object_scans`, `get_calls`, `assert_command_called`, `assert_command_not_called`).
  - Annotate emulator entrypoints with provider-agnostic OpenTelemetry (`arodonata.core.telemetry` `@traced`, `span_attrs`) and verify with `InMemorySpanExporter` that spans propagate cleanly over both `FileReplayApiMock` and `CheckPointReplayHttpServer` without leaking raw `sid`, `api-key`, or `password` values.

## Capabilities

### New Capabilities

<!-- None -->

### Modified Capabilities

- `integration-testing-and-examples`: Expand `dataset_generator.py`, `FileReplayApiMock`, and `CheckPointReplayHttpServer` into a stateful Check Point Management and MDSM emulator supporting per-`sid` staging overlays, object/service/group/rule CRUD, referential integrity, MDSM `Global` domain write protection, `show-changes` delta tracking, fast state snapshot/restore/reset, SID-redacted call auditing, and OpenTelemetry span hygiene verification.

## Impact

- **Affected Modules & Fixtures**: `src/arodonata/testing/dataset_generator.py`, `src/arodonata/testing/replay_mock.py`, `src/arodonata/testing/mock_server.py`, `src/arodonata/testing/__init__.py`, `tests/fixtures/enterprise_raw_dataset/`, new unit and loopback E2E test suites in `tests/unit/`, and `docs/guides/`.
- **Downstream Consumers (MMP)**: Unlocks full offline end-to-end testing of MMP CACF, Decommission, Rule Creator, CPCRUD staged/published workflows, Change Reports (`OwnedSession` and published session diffs), and AI MCP tools against `FileReplayApiMock` and `CheckPointReplayHttpServer`.
- **No Breaking Changes**: Existing `ApiPort`, `GatewayCliPort`, `ArodonataClient`, `test_topology_raw_replay_scale.py`, `test_replay_mock_where_used.py`, `test_replay_mock_show_objects.py`, and `test_cpcrud_planner.py` interfaces and invariants remain backward-compatible.
