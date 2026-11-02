## ADDED Requirements

### Requirement: Client Facade API Reference Introspection with Management Version Inference

`ArodonataClient` SHALL expose `api_reference` (`ApiReferenceEngine`) and convenience methods `search_api_commands(...)`, `describe_api_command(...)`, and `validate_api_payload(...)` that automatically infer the default target API `version` from the configured management server's `api_version` when `version=None` (using `mgmt_name` or the sole configured management server, and falling back to the index's `latest` version `"v2.2"` when no server version is configured).

#### Scenario: Client facade infers target API version from configured management server

- **WHEN** `client.describe_api_command("add-interface", mgmt_name="corp-mds")` is called with `version=None` on a client where `"corp-mds"` is configured with `api_version="1.9"`
- **THEN** `ArodonataClient` SHALL resolve `version="v1.9"` automatically from `"corp-mds"` settings and return the `v1.9`-filtered schema for `add-interface`
