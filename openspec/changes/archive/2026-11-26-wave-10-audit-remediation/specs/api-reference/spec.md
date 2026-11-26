# Spec Delta

## MODIFIED Requirements

### Requirement: Version-Filtered Command Schema Inspection

**ID**: REQ-APIREF-003\
**Intent**: Expose accurate, version-scoped request schemas and examples on demand for one or more commands.\
**Non-goals**: Ranking or searching commands by keyword (`REQ-APIREF-002`) or validating user payloads (`REQ-APIREF-004`).

`ApiReferenceEngine.describe_command` (and top-level helper `describe_api_command`) SHALL accept one or more command names and return resolved schemas (`fields`, `field_alternatives`, `nested_objects`, `enums`, `example`) dynamically filtered to the target API version for `"management"` commands while preserving fields for non-management (`"gaia"`/`"cme"`) commands.

#### Scenario: SCN-APIREF-003-1 — Step 2 describe dynamically filters fields and nested objects by target version

- **WHEN** `describe_command("add-interface", version="v1.9")` and `describe_command("add-interface", version="v2.2")` are called
- **THEN** the `v1.9` schema SHALL include `v1.9`-only fields (such as `gateway-owner` and `anti-spoofing-enabled`) and omit `v2+`-only fields
- **AND** the `v2.2` schema SHALL include only fields and nested objects valid in `v2.2`

#### Scenario: SCN-APIREF-003-2 — Batch describe accepts multiple command names in a single call

- **WHEN** `describe_command(["add-host", "set-host"], version="v2.2")` is called with a list of command names
- **THEN** it SHALL return resolved command descriptions for each requested command
- **AND** it SHALL report any unknown or version-unsupported command names clearly

#### Scenario: SCN-APIREF-003-3 — Gaia and CME commands preserve fields and validate payloads under default v2.2 and v2.0.1

- **GIVEN** bundled `"gaia"` and `"cme"` commands (such as `gaia-show-interface`, `cme-azure`, `cme-management`)
- **WHEN** `describe_command()` or `validate_payload()` is called with default `version="v2.2"` or `version="v2.0.1"`
- **THEN** non-management commands SHALL retain their `fields` and nested objects without management-version stripping and validate valid payloads as `valid=True`
