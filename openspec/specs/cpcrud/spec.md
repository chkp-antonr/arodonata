# CPCRUD Declarative Policy-as-Code Engine Specification

## Purpose

Defines the declarative, idempotent Check Point CRUD engine (`CPCRUDService`, `Planner`, `HybridStateReader`, `Executor`, `Differ`, `build_inverse_template`) for validating, planning, applying, and rolling back security object and rulebase changes across management servers and domains.

## Requirements

### Requirement: Offline JSON Schema Validation

`CPCRUDService.validate()` SHALL validate YAML/JSON templates against `checkpoint_ops_schema.json` (or `cpcrud_schema_path` override) using `jsonschema.Draft7Validator` without making any network or database calls.

#### Scenario: Invalid template returns structured schema errors

- **WHEN** `validate(template)` is called with a template violating `checkpoint_ops_schema.json`
- **THEN** it SHALL return a non-empty list of human-readable validation error strings and perform zero API calls

### Requirement: Two-Axis Conflict Resolution and Idempotent Planning

`CPCRUDService.plan()` (`Planner.decide`) SHALL inspect state via an isolated `HybridStateReader` per run, evaluate `NameConflictPolicy` (`update` | `error`) and `IpConflictPolicy` (`reuse` | `create_new` | `error`), compute field-level diffs (`differ.py`), and produce a deterministic `Plan` with `DomainStamp` records (`last_publish_session`) read BEFORE any domain lookups.

#### Scenario: Re-planning an already-applied template yields UNCHANGED or REUSE

- **WHEN** `plan(template)` runs against a domain where all desired objects and rules already exist with matching attributes
- **THEN** every planned action SHALL have `Outcome.UNCHANGED` or `Outcome.REUSE` and require zero API write operations during `apply()`

#### Scenario: IP conflict with create_new auto-names object using NamingPrefixes

- **WHEN** a host or network operation encounters an IP/subnet match under a different name and `on_ip_conflict="create_new"` is active
- **THEN** the planner SHALL generate a convention-compliant name using `NamingPrefixes` (`Host_`, `Net_`, `IPR_`, `TCP_`, `UDP_`, `ICMP_`)

#### Scenario: Failed state lookup produces ERROR action rather than false CREATE

- **WHEN** an API or cache lookup (name lookup, IP lookup, service port listing, rulebase read, or `where-used`) fails or returns `paging_inconsistent`, or when a domain's `show-last-published-session` head cannot be read
- **THEN** the planner SHALL NOT treat the failure as "not found"; it SHALL plan an `Outcome.ERROR` action (`lookup failed, nothing planned (re-plan to retry): ...`) that writes nothing and marks dependent actions as `skipped_dependency`

#### Scenario: Cache-first object lookups gated by exact domain head stamp

- **WHEN** `HybridStateReader` looks up a host, network, address range, or group during `plan()`
- **THEN** it SHALL read from the local object cache ONLY while the domain's stored `last_published_sessions` UID equals the head UID read by the planner at the start of that `plan()` run, falling back to live API queries otherwise

### Requirement: Rule Identity Matching, Cleanup-Aware Positioning, and NAT Sentinels

The planner and position helper SHALL resolve access, HTTPS, threat-prevention, and NAT rules by explicit key (`uid`, `name`, `rule_number`) or by traffic tuple, support cleanup-rule-aware `"bottom"` positioning, and normalize Check Point NAT `"Original"` and `"Any"` sentinel UIDs (`NAT_ORIGINAL_OBJECT_UID`, `NAT_ANY_OBJECT_UID`).

#### Scenario: Cleanup-aware bottom rule placement

- **WHEN** a rule operation specifies `position="bottom"` or `position={"bottom": "<section>"}` and the last rule in that layer or section is an `Any / Any / Any` cleanup rule
- **THEN** `position_helper` SHALL anchor the new rule at `{"above": "<cleanup_rule_uid>"}` instead of placing it after the cleanup rule

#### Scenario: NAT rule traffic matching with Original sentinel normalization

- **WHEN** a NAT rule with empty/Original `translated-*` fields is planned against a live NAT rulebase
- **THEN** `rule_identity` and `differ` SHALL match Check Point's dereferenced `"Original"` sentinel UID (`NAT_ORIGINAL_OBJECT_UID`) as equivalent to no translation so re-applying the template reports `Outcome.UNCHANGED` rather than creating a duplicate rule

### Requirement: Dedicated-Session Execution, Stale Plan Safeguard, and Session Staging

`CPCRUDService.apply()` (`Executor.stream`) SHALL execute planned actions in a dedicated session per `(mgmt_name, domain_name)`, verify that the domain's published head has not drifted since `plan()`, stream `SSEEvent` updates, and yield a final `ApplyReport`.

#### Scenario: Stale plan abort when domain published after planning

- **WHEN** `apply(plan, force=False)` runs and a target domain's current `show-last-published-session` UID differs from the `DomainStamp` recorded in `plan` (or cannot be read)
- **THEN** the executor SHALL mark all actions in that domain as `Outcome.PLAN_STALE` and perform no writes in that domain

#### Scenario: Keep-session staging mode preserves unpublished session for external workflow

- **WHEN** `apply(plan, no_publish=True, keep_session=True)` is called
- **THEN** the executor SHALL leave the dedicated write session open without publishing, record its details (`sid`, `server_ip`, `session_uid`, `session_name`) in `ApplyReport.staged_sessions`, and emit a `staged_session` `SSEEvent`

#### Scenario: Post-publish domain cache invalidation and retry_remaining folding

- **WHEN** `apply()` publishes changes in a domain or `retry_remaining > 0` re-runs failed/remaining actions
- **THEN** `client.invalidate_domain(mgmt_name, domain_name)` SHALL be called so subsequent smart reads re-sync the domain, and retry passes SHALL fold their `ApplyReport` into the cumulative report

### Requirement: Compensating Rollback Template Generation

`CPCRUDService.inverse(plan, report)` SHALL build a schema-valid compensating template from `Plan` (and optional `ApplyReport`) that reverses created, updated, and deleted objects and rules using captured `PlannedAction.prior_state`.

#### Scenario: Inverse template restores deleted and updated objects and removes created ones

- **WHEN** `inverse(plan, report)` is called after an apply pass
- **THEN** it SHALL produce a dictionary valid against `checkpoint_ops_schema.json` where `CREATE` actions become `delete` operations, `UPDATE` actions restore prior field values, and `DELETE` actions become `add` operations populated from `prior_state`
