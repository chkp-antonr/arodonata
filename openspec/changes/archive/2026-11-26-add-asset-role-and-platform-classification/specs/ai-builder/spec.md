# Spec Delta

## MODIFIED Requirements

### Requirement: Deterministic Agent SDK Quick-Reference Generation

**ID**: REQ-AIBUILD-003\
**Intent**: Provide AI coding agents with a compact, up-to-date signature cheat sheet extracted from the actual `arodonata` codebase so generated scripts never hallucinate SDK methods or model fields.\
**Non-goals**: Replacing the full multi-thousand-line `docs-notebooklm/02-api-reference.md` reference.

The documentation bundle build MUST generate a deterministic, compact Markdown SDK quick-reference summarizing current `arodonata.__version__`, public `ArodonataClient` and `ScriptRepositoryService` signatures, key fields of `Asset`, `CPObject`, and `CPService`, `CPCRUDService` and `ApiReferenceEngine` entry points, `arodonata.testing` replay helpers, and idiomatic `arlogi` CLI logging setup.

#### Scenario: SCN-AIBUILD-003-1 — SDK quick-reference matches public package exports and signatures

- **GIVEN** the current `arodonata` source tree in `src/arodonata`
- **WHEN** the documentation bundle build generates the compact SDK quick-reference
- **THEN** the output Markdown SHALL match `arodonata.__version__` and include verified signatures and model fields for `ArodonataClient`, `Asset`, `CPObject`, `CPService`, `ScriptRepositoryService`, `CPCRUDService`, and `ApiReferenceEngine`
- **AND** re-running the generator without source edits SHALL produce byte-identical output

#### Scenario: SCN-AIBUILD-003-2 — Valid default-factory rendering and complete arodonata.testing method coverage

- **GIVEN** Pydantic fields using `lambda` `default_factory` expressions (including `ArodonataSettings.tls_known_hosts_path`) and public methods on `FileReplayApiMock` and `CheckPointReplayHttpServer`
- **WHEN** the documentation bundle build generates `docs-notebooklm/05-sdk-quickref.md`
- **THEN** lambda-backed defaults SHALL render valid Python expressions without invalid `lambda: ...()` syntax
- **AND** `FileReplayApiMock` and `CheckPointReplayHttpServer` sections SHALL include all public methods and properties without `[:8]` truncation
