# api-reference Specification

## Purpose

Defines the bundled multi-version Check Point API schema index (`cp_api_index.json.gz`, covering Management API `v1.9` through `v2.2` and Gaia API `v2.0.1`), lazy in-memory `ApiReferenceEngine`, two-step command discovery (`search_commands` and `describe_command` with dynamic version filtering), and offline request payload validation (`validate_payload`).

## Requirements

### Requirement: Bundled Multi-Version API Schema Index and Lazy Loading

`arodonata.api_reference` SHALL package the compressed multi-version Check Point API schema bundle (`cp_api_index.json.gz`, covering Management API `v1.9`, `v2`, `v2.1`, `v2.2` and Gaia API `v2.0.1`) inside the installed distribution, load and decompress it lazily in memory on first query (with optional custom `index_path` override), and perform zero network or database calls.

#### Scenario: Default bundled index loads lazily without network or database access

- **WHEN** `get_api_reference()` or `ApiReferenceEngine.default()` is called in an offline process with no `ArodonataClient` or database configured
- **THEN** it SHALL decompress the bundled `cp_api_index.json.gz` into memory once, cache the singleton instance for subsequent calls, and expose `meta` (`versions`, `latest`, `commands_count`, `shared_objects_count`, `enums_count`)

### Requirement: Two-Step Version-Aware Command Discovery (Search and Describe)

`ApiReferenceEngine` (and top-level helpers `search_api_commands` / `describe_api_command`) SHALL provide a two-step lookup contract: `search_commands` returning ranked lightweight command summaries filtered by version, category, `crud_type`, and `api_family`, and `describe_command` accepting one or more command names and returning resolved schemas (`fields`, `field_alternatives`, `nested_objects`, `enums`, `example`) dynamically filtered to the target API version.

#### Scenario: Step 1 search filters by API version, CRUD type, and category

- **WHEN** `search_commands("export-access-rulebase", version="v1.9")` and `search_commands("export-access-rulebase", version="v2.2")` are called
- **THEN** the `v1.9` search SHALL exclude commands added after `v1.9`, while the `v2.2` search SHALL return the matching command summary with `added_in`, `supported_versions`, and `short_description`

#### Scenario: Step 2 describe dynamically filters fields and nested objects by target version

- **WHEN** `describe_command("add-interface", version="v1.9")` and `describe_command("add-interface", version="v2.2")` are called
- **THEN** the `v1.9` schema SHALL include `v1.9`-only fields (such as `gateway-owner` and `anti-spoofing-enabled`) and omit `v2+`-only fields, while the `v2.2` schema SHALL include only fields and nested objects valid in `v2.2`

#### Scenario: Batch describe accepts multiple command names in a single call

- **WHEN** `describe_command(["add-host", "set-host"], version="v2.2")` is called with a list of command names
- **THEN** it SHALL return a mapping or list of resolved command descriptions for each requested command (and report any unknown or version-unsupported command names clearly)

### Requirement: Offline Request Payload Validation Against Versioned Schema

`ApiReferenceEngine.validate_payload(command, payload, *, version="v2.2")` (and `validate_api_payload`) SHALL validate a candidate request `payload` dictionary offline against the command's schema for `version`, reporting structured validation errors for unknown or version-unsupported commands and fields, missing `required` fields, unsatisfied or conflicting `field_alternatives`, invalid types, and enum `valid_values` mismatches.

#### Scenario: Payload validation catches missing required fields and version-unsupported parameters

- **WHEN** `validate_payload("add-host", {"color": "invalid-color"}, version="v2.2")` is called
- **THEN** it SHALL return `valid=False` with actionable errors identifying missing required fields (`name` and `ip-address` / `ipv4-address` / `ipv6-address`) and the invalid enum value for `color`
