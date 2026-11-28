# Spec Delta

## ADDED Requirements

### Requirement: Nested Pydantic Secret Serialization Masking

**ID**: REQ-CONFIG-010\
**Intent**: Prevent settings credentials and database passwords from leaking in plaintext when settings objects are nested inside parent Pydantic v2 models.\
**Non-goals**: Changing top-level `ArodonataSettings` or `ArodonataMCPSettings` environment variable parsing.

`ArodonataSettings` and `ArodonataMCPSettings` MUST enforce secret redaction via Pydantic field serializers so sensitive fields (`password`, `api_key`, `api_keys`, `database_url`, and `tokens`) remain masked in both direct and enclosing-model `model_dump()` and `model_dump_json()` serialization.

#### Scenario: SCN-CONFIG-010-1 — Enclosing Pydantic models serialize nested settings without exposing secrets

- **GIVEN** an `ArodonataSettings` or `ArodonataMCPSettings` instance containing credentials, API keys, bearer tokens, or a database URL password
- **WHEN** an enclosing Pydantic `BaseModel` serializes the nested settings via `model_dump()` or `model_dump_json()`
- **THEN** all sensitive fields SHALL be emitted as redacted placeholders or masked URLs in both Python dicts and JSON output
- **AND** direct `model_dump()` and `model_dump_json()` calls on the settings models SHALL continue masking those fields
