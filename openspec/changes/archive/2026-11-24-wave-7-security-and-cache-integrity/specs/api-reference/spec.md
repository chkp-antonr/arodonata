# Spec Delta

## MODIFIED Requirements

### Requirement: Version-Filtered Command Schema Inspection

**ID**: REQ-APIREF-003\
**Intent**: Expose accurate, version-scoped request schemas and examples on demand for bounded batches of commands.\
**Non-goals**: Ranking or searching commands by keyword (`REQ-APIREF-002`) or validating user payloads (`REQ-APIREF-004`).

`ApiReferenceEngine.describe_command` (and top-level helper `describe_api_command`) SHALL accept one command name or a bounded batch sequence (`<= 50` deduplicated command names, raising `ValidationError` when exceeded) and return resolved schemas (`fields`, `field_alternatives`, `nested_objects`, `enums`, `example`) dynamically filtered to the target API version.

#### Scenario: SCN-APIREF-003-1 — Step 2 describe dynamically filters fields and nested objects by target version

- **WHEN** `describe_command("add-interface", version="v1.9")` and `describe_command("add-interface", version="v2.2")` are called
- **THEN** the `v1.9` schema SHALL include `v1.9`-only fields (such as `gateway-owner` and `anti-spoofing-enabled`) and omit `v2+`-only fields
- **AND** the `v2.2` schema SHALL include only fields and nested objects valid in `v2.2`

#### Scenario: SCN-APIREF-003-2 — Batch describe accepts multiple command names in a single call

- **WHEN** `describe_command(["add-host", "set-host", "add-host"], version="v2.2")` is called, OR a sequence exceeding `50` unique command names is supplied
- **THEN** valid batches SHALL deduplicate repeated command names, return resolved schemas plus clear `not_found` entries, and sequences with `> 50` unique command names SHALL raise `ValidationError`

### Requirement: Offline Request Payload Validation Against Versioned Schema

**ID**: REQ-APIREF-004\
**Intent**: Catch invalid commands, missing required parameters, and incompatible fields (including `list[enum]` values) offline before sending requests.\
**Non-goals**: CPCRUD declarative template schema validation (`REQ-CPCRUD-001`) or server-side semantic checks.

`ApiReferenceEngine.validate_payload(command, payload, *, version="v2.2")` (and `validate_api_payload`) SHALL validate a candidate request `payload` dictionary offline against the command's schema for `version`, reporting structured validation errors for unknown or version-unsupported commands/fields, missing `required` fields, unsatisfied/conflicting `field_alternatives`, invalid types, and scalar or `list[enum]` `valid_values` mismatches.

#### Scenario: SCN-APIREF-004-1 — Payload validation catches missing required fields and version-unsupported parameters

- **WHEN** `validate_payload("add-host", {"color": "invalid-color"}, version="v2.2")` or a command payload with an invalid value inside a `list[enum]` field runs
- **THEN** it SHALL return `valid=False` with zero network or database calls
- **AND** the errors SHALL identify missing required fields (`name` and `ip-address` / `ipv4-address` / `ipv6-address`) and invalid scalar or `list[enum]` `valid_values` items
