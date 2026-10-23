# CPCRUD Declarative Policy-as-Code Engine Specification Delta

## MODIFIED Requirements

### Requirement: Two-Axis Conflict Resolution and Idempotent Planning

`CPCRUDService.plan()` (`Planner.decide`) SHALL inspect state via an isolated `HybridStateReader` per run (querying `arodonata_objects` and `arodonata_services` when `domain_sync_state` matches the domain head), evaluate `NameConflictPolicy` (`update` | `error`) and `IpConflictPolicy` (`reuse` | `create_new` | `error`), compute field-level diffs (`differ.py`), and produce a deterministic `Plan` with `DomainStamp` records read BEFORE any domain lookups.

#### Scenario: Re-planning an already-applied template yields UNCHANGED or REUSE

- **WHEN** `plan(template)` runs against a domain where all desired objects, services, and rules already exist with matching attributes
- **THEN** every planned action SHALL have `Outcome.UNCHANGED` or `Outcome.REUSE` and require zero API write operations during `apply()`

#### Scenario: IP conflict with create_new auto-names object using NamingPrefixes

- **WHEN** a host or network operation encounters an IP/subnet match under a different name and `on_ip_conflict="create_new"` is active
- **THEN** the planner SHALL generate a convention-compliant name using `NamingPrefixes` (`Host_`, `Net_`, `IPR_`, `TCP_`, `UDP_`, `ICMP_`)

#### Scenario: Failed state lookup produces ERROR action rather than false CREATE

- **WHEN** an API or cache lookup (name lookup, IP lookup, service port listing, rulebase read, or `where-used`) fails or returns `paging_inconsistent`, or when a domain's `show-last-published-session` head cannot be read
- **THEN** the planner SHALL NOT treat the failure as "not found"; it SHALL plan an `Outcome.ERROR` action (`lookup failed, nothing planned (re-plan to retry): ...`) that writes nothing and marks dependent actions as `skipped_dependency`

#### Scenario: Cache-first object lookups gated by exact domain head stamp

- **WHEN** `HybridStateReader` looks up a host, network, address range, dns-domain, group, or service during `plan()`
- **THEN** it SHALL read from `arodonata_objects` or `arodonata_services` ONLY while the domain's stored `domain_sync_state` row for that specific `(scope, item_type)` matches the head `last_published_at` and `last_session_uid` read by the planner at the start of `plan()`, falling back to live API queries otherwise

### Requirement: Dedicated-Session Execution, Stale Plan Safeguard, and Session Staging

`CPCRUDService` SHALL provide both `await apply(plan, ...) -> ApplyReport` and `stream_apply(plan, ...) -> AsyncIterator[CPCRUDEvent]`, executing planned actions in an isolated `WriteSession` per `(mgmt_name, domain_name)` (updating `SessionOverlay` as each action succeeds) and verifying that the domain's published head has not drifted since `plan()`.

#### Scenario: Stale plan abort when domain published after planning

- **WHEN** `apply(plan, force=False)` runs and a target domain's current `show-last-published-session` UID differs from the `DomainStamp` recorded in `plan` (or cannot be read)
- **THEN** the executor SHALL mark all actions in that domain as `Outcome.PLAN_STALE` and perform no writes in that domain

#### Scenario: Keep-session staging mode preserves unpublished session for external workflow

- **WHEN** `apply(plan, no_publish=True, keep_session=True)` is called
- **THEN** the executor SHALL leave the dedicated write session open without publishing, record its details (`sid`, `server_ip`, `session_uid`, `session_name`) in `ApplyReport.staged_sessions`, and emit a `StagedSessionEvent` (`CPCRUDEvent`) in `stream_apply()`

#### Scenario: Post-publish domain cache invalidation and retry_remaining folding

- **WHEN** `apply()` publishes changes in a domain or `retry_remaining > 0` re-runs failed/remaining actions
- **THEN** `client.invalidate_domain(mgmt_name, domain_name)` SHALL be called so subsequent smart reads re-sync the domain, and retry passes SHALL fold their `ApplyReport` into the cumulative report
