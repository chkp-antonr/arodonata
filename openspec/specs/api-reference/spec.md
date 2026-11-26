# Check Point API Reference Engine Specification

## Purpose

Defines the bundled multi-version Check Point API schema index (`cp_api_index.json.gz`, covering Management API `v1.9` through `v2.2` and Gaia API `v2.0.1`), lazy in-memory `ApiReferenceEngine`, two-step command discovery (`search_commands` and `describe_command` with dynamic version filtering), and offline request payload validation (`validate_payload`).

## Requirements

### Requirement: Bundled Multi-Version API Schema Index and Lazy Loading

**ID**: REQ-APIREF-001\
**Intent**: Provide offline access to multi-version Check Point API schemas without startup overhead or network dependencies.\
**Non-goals**: Inferring default management server versions from client topology (handled by `ArodonataClient`, `REQ-CLIENT-014`).

`arodonata.api_reference` SHALL package the compressed multi-version Check Point API schema bundle (`cp_api_index.json.gz`, covering Management API `v1.9`, `v2`, `v2.1`, `v2.2` and Gaia API `v2.0.1`) inside the installed distribution, load and decompress it lazily in memory via zero-argument `get_api_reference()` / `ApiReferenceEngine.default()` (or custom index files via `ApiReferenceEngine.from_path(path)`), and perform zero network or database calls.

#### Scenario: SCN-APIREF-001-1 — Default bundled index loads lazily without network or database access

- **GIVEN** an offline process with no `ArodonataClient` or database configured
- **WHEN** `get_api_reference()` or `ApiReferenceEngine.default()` is called
- **THEN** it SHALL decompress the bundled `cp_api_index.json.gz` into memory once and cache the singleton instance for subsequent calls
- **AND** it SHALL expose `meta` (`versions`, `latest`, `commands_count`, `shared_objects_count`, `enums_count`)
- **AND** it SHALL perform zero network or database calls

### Requirement: Version-Aware Command Search

**ID**: REQ-APIREF-002\
**Intent**: Allow callers and agents to discover relevant Check Point API commands quickly without loading full schemas.\
**Non-goals**: Returning full per-command field definitions and nested object schemas (`REQ-APIREF-003`).

`ApiReferenceEngine.search_commands` (and top-level helper `search_api_commands`) SHALL provide ranked lightweight command summaries filtered by `version`, `category`, `crud_type`, and `api_family`.

#### Scenario: SCN-APIREF-002-1 — Step 1 search filters by API version, CRUD type, and category

- **WHEN** `search_commands("export-access-rulebase", version="v1.9")` and `search_commands("export-access-rulebase", version="v2.2")` are called
- **THEN** the `v1.9` search SHALL exclude commands introduced after `v1.9`
- **AND** the `v2.2` search SHALL return the matching command summary with `added_in`, `supported_versions`, and `short_description`

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

### Requirement: Offline Request Payload Validation Against Versioned Schema

**ID**: REQ-APIREF-004\
**Intent**: Catch invalid commands, missing required parameters, and incompatible fields offline before sending requests.\
**Non-goals**: CPCRUD declarative template schema validation (`REQ-CPCRUD-001`) or server-side semantic checks.

`ApiReferenceEngine.validate_payload(command, payload, *, version="v2.2")` (and `validate_api_payload`) SHALL validate a candidate request `payload` dictionary offline against the command's schema for `version`, reporting structured validation errors for unknown or version-unsupported commands and fields, missing `required` fields, unsatisfied or conflicting `field_alternatives`, invalid types, and enum `valid_values` mismatches.

#### Scenario: SCN-APIREF-004-1 — Payload validation catches missing required fields and version-unsupported parameters

- **WHEN** `validate_payload("add-host", {"color": "invalid-color"}, version="v2.2")` is called
- **THEN** it SHALL return `valid=False` with zero network or database calls
- **AND** the errors SHALL identify missing required fields (`name` and `ip-address` / `ipv4-address` / `ipv6-address`) and the invalid enum value for `color`
