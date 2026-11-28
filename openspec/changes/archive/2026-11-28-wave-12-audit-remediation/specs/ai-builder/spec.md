# Spec Delta

## ADDED Requirements

### Requirement: Plugin Replay Documentation Accuracy and Governance Port-Summary Alignment

**ID**: REQ-AIBUILD-007\
**Intent**: Keep AI-builder plugin testing documentation and repository governance docs aligned with actual `FileReplayApiMock`, `ArodonataSettings`, and hexagonal port boundaries.\
**Non-goals**: Adding new starter templates or changing plugin manifest fields (`REQ-AIBUILD-004`).

`plugins/arodonata-aibuilder/skills/arodonata-aibuilder/references/replay-testing-guide.md` MUST document only valid `FileReplayApiMock` `manage_repository_scripts` modes (`"write"`, `"read"`, `"none"`) and valid `ArodonataSettings` parameters (`mgmt_ip`, `mgmt_port`, `tls_trust`, `tls_fingerprints`, `server.snapshot_state()`). Repository governance docs (`AGENTS.md`, `openspec/config.yaml`) MUST accurately reflect `LockPort` and segregated `CachePort` sub-protocols.

#### Scenario: SCN-AIBUILD-007-1 — Plugin replay guide and governance port docs match live SDK and testing contracts

- **GIVEN** `plugins/arodonata-aibuilder/skills/arodonata-aibuilder/references/replay-testing-guide.md`, `AGENTS.md`, and `openspec/config.yaml`
- **WHEN** documented `FileReplayApiMock` modes, `ArodonataSettings` / `CheckPointReplayHttpServer` snippets, and `core` hexagonal port summaries are checked against `src/arodonata`
- **THEN** `replay-testing-guide.md` SHALL reference only `"write"`, `"read"`, `"none"` and valid `ArodonataSettings` / `CheckPointReplayHttpServer` APIs
- **AND** `AGENTS.md` and `openspec/config.yaml` SHALL name `LockPort` and segregated `CachePort` sub-protocols alongside `ApiPort`
