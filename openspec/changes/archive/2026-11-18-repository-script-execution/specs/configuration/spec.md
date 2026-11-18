# Spec Delta

## ADDED Requirements

### Requirement: CPRID Repository Script Execution Configuration

`ArodonataSettings` SHALL resolve `cprid_script_mode` (`"inline" | "repository" | "auto"`, default `"inline"`, env alias `ARODONATA_CPRID_SCRIPT_MODE`) and `cprid_repository_script_name` (default `"arodonata-collect-routes-v1"`, env alias `ARODONATA_CPRID_REPOSITORY_SCRIPT_NAME`, rejecting blank strings) from constructor arguments and `os.environ` without implicitly loading `.env` files.

#### Scenario: Default mode preserves backward-compatible inline execution

- **WHEN** `ArodonataSettings()` is instantiated without `cprid_script_mode` or `cprid_repository_script_name` overrides
- **THEN** `cprid_script_mode` SHALL equal `"inline"` and `cprid_repository_script_name` SHALL equal `"arodonata-collect-routes-v1"`

#### Scenario: Constructor and environment overrides resolve repository mode settings

- **WHEN** `ARODONATA_CPRID_SCRIPT_MODE="repository"` and `ARODONATA_CPRID_REPOSITORY_SCRIPT_NAME="custom-routes-script"` are present in `os.environ`, or overridden via `ArodonataSettings(cprid_script_mode="auto", cprid_repository_script_name="corp-routes")`
- **THEN** `ArodonataSettings` SHALL prioritize explicit constructor arguments over `os.environ` without reading `.env` files from disk

#### Scenario: Invalid mode or blank repository script name rejected on settings initialization

- **WHEN** `ArodonataSettings` receives an unsupported `cprid_script_mode` (e.g., `"ssh-only"`) or a blank/whitespace-only `cprid_repository_script_name`
- **THEN** settings validation SHALL fail immediately with a `ValidationError`
