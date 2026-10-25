# CPCRUD Declarative Policy-as-Code Engine Specification

## Purpose

Defines the declarative, idempotent Check Point CRUD engine (`CPCRUDService`, `Planner`, `HybridStateReader`, `Executor`, `Differ`, `build_inverse_template`) for validating, planning, applying, and rolling back security object, service, and rulebase changes across management servers and domains.

## Requirements

### Requirement: Offline JSON Schema Validation

`CPCRUDService.validate()` SHALL validate YAML/JSON templates against `checkpoint_ops_schema.json` (or `cpcrud_schema_path` override) using `jsonschema.Draft7Validator` without making any network or database calls.

#### Scenario: Invalid template returns structured schema errors

- **WHEN** `validate(template)` is called with a template violating `checkpoint_ops_schema.json`
- **THEN** it SHALL return a non-empty list of human-readable validation error strings and perform zero API calls

### Requirement: Two-Axis Conflict Resolution and Idempotent Planning

`CPCRUDService.plan()` (`Planner.decide`) SHALL inspect state via an isolated `HybridStateReader` per run (using `arodonata_objects` and `arodonata_services` when `arodonata_domain_sync_state` matches the domain head), validate template `type` values against the CPCRUD allowlist, reject duplicate operation `id` values, evaluate `NameConflictPolicy` and `IpConflictPolicy`, compute field diffs (`differ.py`), and produce a `Plan` with SID-redacted `DomainStamp` records read before domain lookups.

#### Scenario: Re-planning an already-applied template yields UNCHANGED or REUSE

- **WHEN** `plan(template)` runs against a domain where all desired objects, services, and rules already exist with matching attributes
- **THEN** every planned action SHALL have `Outcome.UNCHANGED` or `Outcome.REUSE` and require zero API write operations during `apply()`

#### Scenario: IP conflict with create_new auto-names object using NamingPrefixes

- **WHEN** a host or network operation encounters an IP/subnet match under a different name and `on_ip_conflict="create_new"` is active
- **THEN** the planner SHALL generate a convention-compliant name using `NamingPrefixes` (`Host_`, `Net_`, `IPR_`, `TCP_`, `UDP_`, `ICMP_`)

#### Scenario: Failed state lookup produces ERROR action rather than false CREATE

- **WHEN** an API or cache lookup (including `dns-domain` leading-dot retry, name lookup, IP lookup, service port listing, rulebase read, or `where-used`) fails or returns `paging_inconsistent`, or when a domain's `show-last-published-session` head cannot be read
- **THEN** the planner SHALL NOT treat the failure as "not found"; it SHALL plan an `Outcome.ERROR` action (`lookup failed, nothing planned (re-plan to retry): ...`) with SID-redacted error details that writes nothing and marks dependent actions as `skipped_dependency`

#### Scenario: Cache-first object lookups gated by exact domain head stamp

- **WHEN** `HybridStateReader` looks up a host, network, address range, dns-domain, group, or service during `plan()`
- **THEN** it SHALL read from `arodonata_objects` or `arodonata_services` ONLY while the domain's stored `arodonata_domain_sync_state` row for that specific `(scope, item_type)` matches the head `last_published_at` and `last_session_uid` read by the planner at the start of `plan()`, falling back to live API queries otherwise

#### Scenario: Duplicate template operation IDs or unknown object types rejected

- **WHEN** `plan(template)` encounters two operations with the same `id` or an `object_type` outside the canonical CPCRUD type registry
- **THEN** `plan()` SHALL raise `ValidationError` (or record a validation failure) rather than silently overwriting action results or constructing arbitrary `show-<type>` / `add-<type>` commands

### Requirement: Rule Identity Matching, Cleanup-Aware Positioning, and NAT Sentinels

The planner and position helper SHALL resolve access, HTTPS, threat-prevention, and NAT rules by explicit key (`uid`, `name`, `rule_number`) or by traffic tuple, support cleanup-rule-aware `"bottom"` positioning, and normalize Check Point NAT `"Original"` and `"Any"` sentinel UIDs (`NAT_ORIGINAL_OBJECT_UID`, `NAT_ANY_OBJECT_UID`).

#### Scenario: Cleanup-aware bottom rule placement

- **WHEN** a rule operation specifies `position="bottom"` or `position={"bottom": "<section>"}` and the last rule in that layer or section is an `Any / Any / Any` cleanup rule
- **THEN** `position_helper` SHALL anchor the new rule at `{"above": "<cleanup_rule_uid>"}` instead of placing it after the cleanup rule

#### Scenario: NAT rule traffic matching with Original sentinel normalization

- **WHEN** a NAT rule with empty/Original `translated-*` fields is planned against a live NAT rulebase
- **THEN** `rule_identity` and `differ` SHALL match Check Point's dereferenced `"Original"` sentinel UID (`NAT_ORIGINAL_OBJECT_UID`) as equivalent to no translation so re-applying the template reports `Outcome.UNCHANGED` rather than creating a duplicate rule

### Requirement: Dedicated-Session Execution, Stale Plan Safeguard, and Session Staging

`CPCRUDService` SHALL provide `apply` and `stream_apply`, deriving Web API commands strictly from an allowlist of `(object_type, operation)` pairs, executing actions in an isolated `WriteSession` per `(mgmt_name, domain_name)`, verifying the domain head has not drifted before each pass and immediately before `publish`, shielding `discard` before `logout` on any unhandled `BaseException`, and providing `publish_staged_session` and `discard_staged_session`.

#### Scenario: Stale plan abort when domain published after planning

- **WHEN** `apply(plan, force=False)` runs (on the initial pass, on any `retry_remaining` pass, or immediately before issuing `publish`) and a target domain's current `show-last-published-session` UID or `last_published_at` differs from the `DomainStamp` recorded in `plan` (including when `stamp.last_session_uid is None` and the domain now has a published session, or when the head cannot be read)
- **THEN** the executor SHALL mark all remaining actions in that domain as `Outcome.PLAN_STALE` (or discard the uncommitted session if detected pre-publish) and publish no writes in that domain

#### Scenario: Forged or unlisted action command rejected before execution

- **WHEN** `apply(plan)` receives a `PlannedAction` whose `object_type` and `operation` do not map to the canonical CPCRUD command allowlist or whose `command` field disagrees with the allowlisted command for `(object_type, operation)`
- **THEN** the executor SHALL reject the action with `ValidationError` before opening a session or sending any Web API call

#### Scenario: Unhandled exception, cancellation, or publish failure discards uncommitted session before logout

- **WHEN** an exception, `asyncio.CancelledError`, or `publish` transport/task failure occurs while executing a domain in `apply()` or `stream_apply()` (unless `no_publish=True and keep_session=True` completed cleanly or recorded the staged session prior to error)
- **THEN** the executor SHALL shield `discard` followed by `logout_sid` in `finally` so no uncommitted changes or object locks remain orphaned on the management server, and record any staged session opened under `keep_session=True` as soon as the session is created

#### Scenario: Keep-session staging mode preserves unpublished session for external workflow

- **WHEN** `apply(plan, no_publish=True, keep_session=True)` is called
- **THEN** the executor SHALL leave the dedicated write session open without publishing, record its details (`sid`, `server_ip`, `session_uid`, `session_name`) in `ApplyReport.staged_sessions` immediately upon session creation, and emit a `StagedSessionEvent` (`CPCRUDEvent`) in `stream_apply()`

#### Scenario: Staged session publication adopts ownership via take-over-session and invalidates domain cache

- **WHEN** `await client.publish_staged_session(mgmt_name, domain, session_uid=session_uid)` or `client.stream_publish_staged_session(...)` is called for a previously staged session
- **THEN** the service SHALL adopt ownership of `session_uid` via `take-over-session` (`uid=session_uid`), execute `publish` (`payload={}`) while polling task progress, log out the session, and call `client.invalidate_domain(mgmt_name, domain)`

#### Scenario: Staged session discard adopts ownership via take-over-session before discarding

- **WHEN** `await client.discard_staged_session(mgmt_name, domain, session_uid=session_uid)` is called for an open or orphaned staged session
- **THEN** the service SHALL issue `take-over-session` (`uid=session_uid`) prior to `discard` so foreign locks or session ownership divergence do not prevent clean session termination

#### Scenario: Post-publish domain cache invalidation and retry_remaining folding

- **WHEN** `apply()` publishes changes in a domain or `retry_remaining > 0` re-runs failed/remaining actions
- **THEN** `client.invalidate_domain(mgmt_name, domain_name)` SHALL be called so subsequent smart reads re-sync the domain, and retry passes SHALL re-verify domain head freshness (never forcing `force=True` automatically) and fold their `ApplyReport` into the cumulative report

### Requirement: Compensating Rollback Template Generation

`CPCRUDService.inverse(plan, report)` SHALL build a schema-valid compensating template from `Plan` and `ApplyReport`, inverting only actions that actually succeeded when `report` is supplied, targeting created objects by the real `uid` returned in `ApplyReport` (refusing unsafe delete-by-name for unexecuted `planned:` UIDs), and restoring all mutated fields present in `PlannedAction.prior_state`.

#### Scenario: Inverse template restores deleted and updated objects and removes created ones

- **WHEN** `inverse(plan, report)` is called after an apply pass where some actions succeeded and others failed or were skipped/stale
- **THEN** it SHALL produce a dictionary valid against `checkpoint_ops_schema.json` that includes compensating operations ONLY for actions that succeeded in `report`, deletes `CREATE` actions using the concrete `uid` recorded in `report` (skipping any `CREATE` that lacks a real created UID), restores all prior field values from `prior_state` for `UPDATE` actions, and re-creates `DELETE` actions from `prior_state`
