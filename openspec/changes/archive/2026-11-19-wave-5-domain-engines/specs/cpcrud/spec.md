# Spec Delta

## MODIFIED Requirements

### Requirement: Two-Axis Conflict Resolution and Idempotent Planning

**ID**: REQ-CPCRUD-003\
**Intent**: Produce deterministic, side-effect-free execution plans that resolve name and value conflicts safely and fail closed on state-read errors.\
**Non-goals**: Opening write sessions or mutating Check Point state (handled during plan execution).

`CPCRUDService.plan()` SHALL record a `sid`-redacted `DomainStamp` per domain before state lookups, inspect domain state via an isolated per-run cache-first view gated by domain head freshness while maintaining intra-plan virtual overlay coherency across creations, updates, renames, and deletions, enforce the CPCRUD `type` allowlist and unique operation `id`s, evaluate `NameConflictPolicy` and `IpConflictPolicy`, compute `FieldChange` diffs, and return a deterministic `Plan`.

#### Scenario: SCN-CPCRUD-003-6 — Intra-plan virtual overlay coherency across same-template updates, renames, and deletions

- **GIVEN** a template containing multiple sequential operations targeting the same `group`, `service-group`, network object (`host`, `network`, `application-site`, `dns-domain`), or service (`service-tcp`, `service-icmp`)
- **WHEN** an earlier step updates attributes, members, or name (`new-name`) or deletes an entity, and a subsequent step in the same `plan()` run looks up, modifies, deletes, or checks value conflicts against that entity or its prior/new values
- **THEN** `Planner` and `HybridStateReader` SHALL reflect the post-update model (including `group` and `service-group` members/metadata, object/service values, and renamed names) or deletion tombstone in the virtual overlay
- **AND** same-template updates or deletions of an earlier `CREATE` SHALL emit valid wire `"name"` identifiers instead of synthetic `"planned:"` UIDs
- **AND** a `set` targeting a virtually deleted entity SHALL fail closed with `Outcome.ERROR`, while a repeat identical update SHALL yield `Outcome.UNCHANGED`
