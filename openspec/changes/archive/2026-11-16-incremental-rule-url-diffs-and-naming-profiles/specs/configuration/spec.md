# Spec Delta

## ADDED Requirements

### Requirement: Environment-Backed CPCRUD Naming Profile Configuration

`ArodonataSettings` SHALL resolve a default `cpcrud_naming_prefixes` profile from explicit constructor arguments and `ARODONATA_CPCRUD_*` (falling back to `CPCRUD_*`) environment variables without loading `.env` files implicitly, covering host, network, range, group, service, and application-site formatting options.

#### Scenario: Environment variables populate CPCRUD naming profile defaults

- **WHEN** `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_RANGE="Range_"`, `ARODONATA_CPCRUD_RANGE_SEPARATOR="_"`, `ARODONATA_CPCRUD_RANGE_COMPRESS_OCTETS="true"`, `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_GROUP=""`, `ARODONATA_CPCRUD_AUTO_NAME_SUFFIX_GROUP="_Grp"`, `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_APP_SITE="Site_"`, and `ARODONATA_CPCRUD_APP_SITE_WILDCARD_MARKER="_"` are set in `os.environ`
- **THEN** `ArodonataSettings().cpcrud_naming_prefixes` SHALL reflect those configured prefixes, suffixes, range separator, compression flag, and wildcard marker without reading `.env` files from disk

#### Scenario: Secondary CPCRUD environment aliases are accepted when ARODONATA_CPCRUD variables are absent

- **WHEN** `CPCRUD_AUTO_NAME_PREFIX_RANGE="Range_"` and `CPCRUD_RANGE_COMPRESS_OCTETS="true"` are present without `ARODONATA_CPCRUD_*` counterparts
- **THEN** `ArodonataSettings().cpcrud_naming_prefixes` SHALL resolve those `CPCRUD_*` values as fallback defaults while prioritizing `ARODONATA_CPCRUD_*` and explicit constructor arguments

#### Scenario: CPCRUDService planning uses ArodonataSettings naming profile by default

- **WHEN** a caller invokes `client.cpcrud.plan(template)` without supplying an explicit `naming_prefixes` argument or template `naming_prefixes` block
- **THEN** the planner SHALL apply `settings.cpcrud_naming_prefixes` when auto-naming newly created objects and services
