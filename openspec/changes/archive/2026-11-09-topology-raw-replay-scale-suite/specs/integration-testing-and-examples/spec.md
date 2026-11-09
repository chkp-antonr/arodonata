# Spec Delta

## ADDED Requirements

### Requirement: Deterministic Enterprise Raw Dataset and Generator

The testing harness SHALL provide a deterministic (fixed-seed) generator and raw fixture dataset (`tests/fixtures/enterprise_raw_dataset/`) containing Check Point Management API JSON payloads and gateway CLI routing outputs for an enterprise MDSM topology (8–10 domains plus `Global`, hundreds of gateways/clusters/VSX Virtual Systems, thousands of objects with 6–7-level nested groups, and 1,000+ policy rules).

#### Scenario: Raw dataset covers multi-domain API payloads and gateway CLI outputs

- **WHEN** the enterprise raw dataset is generated or loaded from `tests/fixtures/enterprise_raw_dataset/`
- **THEN** it SHALL provide deterministic raw Check Point API JSON files (`show-domains`, `show-sessions`, `show-last-published-session`, `show-session`, `show-gateways-and-servers`, `show-simple-gateway`, `show-simple-cluster`, `show-generic-object`, `show-generic-objects` for `CpmiVsNetobj`, `CpmiVsxNetobj`, `CpmiVsxSlotObj`, and `CpmiVsSlotObj`, `show-hosts`, `show-networks`, `show-address-ranges`, `show-groups` nested 6–7 levels deep, `show-services-*`, `show-packages`, `show-access-layers`, `show-access-rulebase`, `show-nat-rulebase`) and raw CLI stdout files (`vsx stat -l`, `ip -4 route show`, `clish -c "show route"`, and Base64 `run-script`/`show-task` payloads) across 8–10 MDSM domains plus `Global`

### Requirement: File-Backed Check Point API and Gateway CLI Replay Doubles

The testing package SHALL provide `FileReplayApiMock` (`ApiPort`) and `FileReplayCliMock` (`GatewayCliPort`) backed by the raw dataset on disk, emulating Check Point pagination (`limit`/`offset`/`from`/`to`/`total`), `details-level`, `uid`/`name` and `class-name` filtering, `run-script` + `show-task` Base64 task responses, VSX `vsenv` / `vsx stat -l` / `CTX%05d` bash validation, and per-call audit counters.

#### Scenario: Paginated API queries and VSX CLI context validation execute against raw fixture files

- **WHEN** `ArodonataClient` queries `FileReplayApiMock` with `limit`/`offset` or `uid`/`name`/`class-name` filters and executes route collection scripts against `FileReplayCliMock` (or `run-script` + `show-task` fallback)
- **THEN** `FileReplayApiMock` SHALL return continuity-valid slices (`from`, `to`, `total`) and Base64-encoded `show-task` responses from the raw dataset while recording per-command call counters, and `FileReplayCliMock` SHALL verify `vsenv` / `vsx stat -l` and `CTX%05d` `$FWDIR` guards before returning the raw CLI stdout for the target node and VSID

### Requirement: Standalone Check Point Web API HTTPS Mock Server for Downstream Applications

The testing package SHALL provide an embeddable and CLI-runnable HTTPS server (`python -m arodonata.testing.mock_server`) serving `/web_api/{cmd}` from the raw dataset with per-domain `X-chkp-sid` session tracking and host-rewritten `show-domains` endpoints so downstream applications (such as MMP and FPCR) can point `ArodonataClient` at `localhost:<port>` without a live Check Point appliance.

#### Scenario: Downstream application connects over HTTPS to localhost and syncs multi-domain dataset

- **WHEN** `CheckPointReplayHttpServer` is started on `localhost:<port>` (e.g., `localhost:443` or an ephemeral test port) and a client connects via real `AMgmtClient` / `ApiTransport`
- **THEN** `/web_api/login` SHALL issue domain-bound session tokens (`X-chkp-sid`), `/web_api/show-domains` SHALL rewrite active CMA/MDS server `ipv4-address` fields to the server's bound host, and subsequent `/web_api/{cmd}` requests (`show-gateways-and-servers`, `show-hosts`, `show-groups`, `show-packages`, `show-access-rulebase`, `run-script`, `show-task`, etc.) SHALL return the corresponding domain's paginated raw dataset without artificial rate limiting or login delays
