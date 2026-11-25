# Spec Delta

## ADDED Requirements

### Requirement: Unified CPCRUD State-Reader Lookups, Single-Pass Planning, and Split Differ/Executor/Inverse Helpers

**ID**: REQ-CPCRUD-016\
**Intent**: Eliminate behavioral drift across mirrored CPCRUD object/service lookup mixins, duplicated staged-session finalizers, repeated inverse helpers, duplicated step collection, and high-branching diff functions.\
**Non-goals**: Base CPCRUD expression evaluation (`REQ-CPCRUD-002`) or staged session registry persistence (`REQ-CPCRUD-011`).

`HybridStateReader` SHALL consolidate cache/overlay/live lookup helpers in `_HybridStateReaderBase` (with exact service-name checks), `Planner.decide` SHALL cache target steps in `_DomainPlanState`, `differ.py` SHALL delegate to per-type diff helpers, and `Executor`/`inverse.py` SHALL share staged-session and prior-field helpers.

#### Scenario: SCN-CPCRUD-016-1 — Unified state reader enforces exact service name match and shared staged/inverse helpers preserve semantics

- **GIVEN** a `HybridStateReader` service lookup where cache returns a mismatched service name, an adopted staged session interrupted by error or cancellation, or an inverse rollback over prior fields
- **WHEN** `get_service_by_name()`, `stream_publish_staged_session()`, `discard_staged_session()`, or `CPCRUDService.inverse()` executes
- **THEN** `get_service_by_name()` SHALL reject mismatched service names identically to `get_object_by_name()`
- **AND** adopted staged operations SHALL shield `logout_sid` cleanup through one shared runner, and `inverse()` SHALL copy prior fields uniformly via shared helpers

#### Scenario: SCN-CPCRUD-016-2 — Single-pass planner step collection and split object/rule differs maintain exact plan parity

- **GIVEN** a multi-target CPCRUD template modifying hosts, networks, ranges, application sites, NAT rules, and policy rules
- **WHEN** `Planner.decide()`, `compute_object_diff()`, and `compute_rule_diff()` compute actions
- **THEN** `_collect_ordered_steps` SHALL be evaluated at most once per target during `Planner.decide()` with per-domain state stored in `_DomainPlanState`
- **AND** per-type object and rule diff helpers SHALL produce identical actions and field diffs across every entity and rulebase type
