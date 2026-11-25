# Spec Delta

## ADDED Requirements

### Requirement: Per-Rulebase Track Wire Encoding, Fail-Closed Defaults, and Validation Parity

**ID**: REQ-CPCRUD-014\
**Intent**: Ensure CPCRUD schema validation, planning, and rollback match Check Point Web API wire formats, fail-closed rule defaults, and anti-widening invariants across all rulebase types.\
**Non-goals**: Base shorthand expression parsing (`REQ-CPCRUD-002`) or rule list-cell patch syntax (`REQ-CPCRUD-009`).

`CPCRUDService` SHALL encode `track` as a settings object (`{"type": ...}`) for `access` rules and a plain string for `https`/`threat` rules, default omitted rule actions fail-closed (`"Drop"` for `access`, `"Inspect"` for `https`, `"Optimized"` for `threat`), reject empty list replacements (`[]`, `""`, `[""]`) and `default_any` coercion on `install-on`, and infer omitted `type` with `operation > state > action` precedence and `check_where_used` schema support during `validate()`.

#### Scenario: SCN-CPCRUD-014-1 — Access vs HTTPS/Threat track wire encoding and sub-field diffs

- **GIVEN** an existing `access`, `https`, or `threat` rule in Check Point
- **WHEN** `CPCRUDService.plan()` and `execute()` create, update, or roll back rules with `track` settings (including `accounting`, `per-session`, `per-connection`, `alert`, or `enable-firewall-session` on `access` rules)
- **THEN** `access` rule payloads SHALL encode `track` as a `TrackSettingsForRequest` object and detect sub-field diffs while `https` and `threat` payloads SHALL encode `track` as a plain string
- **AND** compensating rollback templates SHALL preserve the prior `track` object or string wire representation

#### Scenario: SCN-CPCRUD-014-2 — Fail-closed rule defaults, install-on anti-Any guard, and empty-list rejection

- **GIVEN** a CPCRUD rule operation omitting `rule_action`/`action`, omitting `install-on`, or attempting an empty list replacement (`[]`, `""`, `[""]`)
- **WHEN** `CPCRUDService.validate()` or `plan()` evaluates the rule operation
- **THEN** omitted rule actions SHALL resolve fail-closed to `"Drop"` (`access`), `"Inspect"` (`https`), or `"Optimized"` (`threat`) identically across planning and unnamed-rule traffic matching
- **AND** `install-on` SHALL NOT default to `"Any"`, empty list replacements SHALL fail with `ValidationError` / `DiffSafetyError`, and `is_cleanup_rule` SHALL require `Any`/`Any`/`Any` traffic even when `"cleanup"` appears in the rule name

#### Scenario: SCN-CPCRUD-014-3 — Offline validation parity, multi-target state continuity, and NAT/resolved-object parity

- **GIVEN** a multi-target CPCRUD template with omitted `type` on rules/groups, `check_where_used: true`, or NAT/access rules carrying `_resolved_objects`
- **WHEN** `CPCRUDService.validate()` and `plan()` execute across multiple targets referencing the same domain
- **THEN** `validate()` SHALL infer default types, apply `operation > state > action` precedence, and accept `check_where_used`
- **AND** `plan()` SHALL preserve failure propagation, name resolutions, and `depends_on` edges across targets on the same domain while passing resolved object dictionaries to NAT and traffic-tuple helpers

### Requirement: Hardened Staged Session Lifecycle, Provenance, and Placeholder-Free Rollback

**ID**: REQ-CPCRUD-015\
**Intent**: Prevent dedicated session leaks, stale staged publishes, synthetic UID leaks in rollback templates, and dead provenance checks in staged CPCRUD workflows.\
**Non-goals**: Base staged session registry persistence (`REQ-CPCRUD-011`) or compensating rollback ordering (`REQ-CPCRUD-012`).

`CPCRUDService` SHALL shield staged-session `logout_sid` cleanup under cancellation and `ServerIdentityError`, verify domain-head freshness before publishing staged sessions, align `arodonata*` session provenance checks with `REQ-CPCRUD-011`, strip synthetic `planned:` UIDs from rollback `UPDATE` operations, and restore parent-group memberships and `service-group` rollbacks accurately.

#### Scenario: SCN-CPCRUD-015-1 — Staged session cleanup shields cancellation and verifies head staleness before publish

- **GIVEN** an active or adopted staged `CPCRUDService` session (`publish_staged_session`, `discard_staged_session`, or `execute(..., keep_session=True)`)
- **WHEN** `asyncio.CancelledError` or `ServerIdentityError` interrupts registration, adoption, publish, or discard, OR the domain published head changed since staging
- **THEN** temporary/owned sessions SHALL be logged out via shielded `logout_sid` cleanup without leaking open Check Point sessions
- **AND** `publish_staged_session` SHALL reject stale domain heads when `allow_stale=False` and enforce consistent `arodonata*` provenance rules

#### Scenario: SCN-CPCRUD-015-2 — Rollback templates strip synthetic planned UIDs and invert group/service-group mutations

- **GIVEN** a CPCRUD plan that creates and subsequently updates an entity in the same run (`planned:<type>:<name>`), modifies group memberships, or modifies a `service-group`
- **WHEN** `CPCRUDService.inverse()` generates a compensating rollback template
- **THEN** rollback `UPDATE` operations SHALL omit synthetic `planned:` UIDs rather than emitting placeholder identifiers
- **AND** group and `service-group` rollbacks SHALL restore prior parent-group memberships and route `service-group` inversions to the group inverter
