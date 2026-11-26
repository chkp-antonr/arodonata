# Spec Delta

## ADDED Requirements

### Requirement: Fail-Closed Staged Publishing, Active Where-Used Enforcement, Empty-List Inverse Rollback, and Unified Entity Planning

**ID**: REQ-CPCRUD-017\
**Intent**: Prevent stale staged publishes after LRU eviction or restart, enforce `check_where_used` across all entity deletions, restore newly added groups/tags on rollback, and honor `check_domain_head` consistently.\
**Non-goals**: Base CPCRUD shorthand parsing (`REQ-CPCRUD-002`) or HMAC MCP plan signing (`REQ-MCP-009`).

`Executor` SHALL fail closed on `publish_staged_session(..., allow_stale=False)` when no verified baseline stamp is present, honor `check_domain_head` across all passes, enforce non-empty `check_where_used` usage across objects, services, and groups via unified entity planning, and emit `groups: []` / `tags: []` in `inverse()` when newly added.

#### Scenario: SCN-CPCRUD-017-1 — Fail-closed allow_stale=False staged publishing and consistent check_domain_head dispatch

- **GIVEN** a staged session whose entry was evicted from `Executor._staged_sessions` or adopted post-restart, or an `Executor(check_domain_head=custom_cb)` instance
- **WHEN** `stream_publish_staged_session(..., allow_stale=False)` runs without an explicit baseline stamp, or `apply()` / `stream_apply()` runs retry passes
- **THEN** `stream_publish_staged_session` SHALL fail closed when no verified baseline stamp is available (while accepting explicit baseline stamps forwarded from `stored_staged`)
- **AND** `apply()` and `stream_apply()` SHALL invoke `check_domain_head` consistently across all domain-head verification paths

#### Scenario: SCN-CPCRUD-017-2 — check_where_used blocks referenced objects, services, and groups via unified entity planner

- **GIVEN** a CPCRUD `delete` step with `check_where_used: true` on an object (`host`), service (`service-tcp`), `group`, or `service-group` that has active `used-directly`/`used-indirectly` references outside deleted plan entities
- **WHEN** `CPCRUDService.plan()` executes via the consolidated entity planner
- **THEN** `plan()` SHALL emit `Outcome.ERROR` and block deletion rather than discarding `where-used` usage data

#### Scenario: SCN-CPCRUD-017-3 — inverse() restores empty groups and tags on previously ungrouped/untagged entities

- **GIVEN** an existing host, service, `group`, or `service-group` with `groups=[]` and `tags=[]` that was updated to add parent `groups` or `tags`
- **WHEN** `CPCRUDService.inverse(plan, report)` generates a compensating rollback template
- **THEN** the rollback `set-*` operations SHALL emit `groups: []` and `tags: []` whenever those fields were mutated from empty prior state
