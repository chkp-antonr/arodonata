# Spec Delta

## MODIFIED Requirements

### Requirement: Deterministic Enterprise Raw Dataset and Generator

The testing harness SHALL provide a deterministic (fixed-seed) generator and raw fixture dataset (`tests/fixtures/enterprise_raw_dataset/`) containing Check Point Management API JSON payloads (including MDSM global assignments, deterministic `Global` object/group usage in local rules, heterogeneous standalone gateway, HA cluster, Virtual System, and cross-domain VSX distributions across every user domain, unique per-domain gateway/interface IPs and Virtual System internal subnets, and complete `CpmiVsxSlotObj`/`CpmiVsSlotObj` metadata) and gateway CLI routing outputs for an enterprise MDSM topology.

#### Scenario: Raw dataset covers multi-domain API payloads and gateway CLI outputs

- **WHEN** the enterprise raw dataset is generated or loaded from `tests/fixtures/enterprise_raw_dataset/`
- **THEN** it SHALL provide deterministic raw Check Point API JSON files (`show-domains`, `show-global-assignments`, `show-sessions`, `show-last-published-session`, `show-session`, `show-gateways-and-servers`, `show-simple-gateway`, `show-simple-cluster`, `show-generic-object`, `show-generic-objects`, `show-hosts`, `show-networks`, `show-address-ranges`, `show-groups` nested 6–7 levels deep, `show-services-*`, `show-packages`, `show-access-layers`, `show-access-rulebase`, `show-nat-rulebase`) and raw CLI stdout files (`vsx stat -l`, `ip -4 route show`, `clish -c "show route"`, and Base64 `run-script`/`show-task` payloads) across 9 user MDSM domains plus `Global`

#### Scenario: Raw dataset includes deterministic Global object and group usage in local domain rules without breaking scale invariants

- **WHEN** `ensure_enterprise_raw_dataset()` materializes `tests/fixtures/enterprise_raw_dataset/`
- **THEN** local user domains SHALL deterministically reference `Global` objects, services, and groups (such as `H_Global_DNS_001`, `G_Global_Branch_Supernet`, `G_Global_DC_Supernet`, `TCP_53`, and `UDP_53`) inside existing Access rule #104 (`uid-arule-<domain>-0104`) and expose `mds/show-global-assignments.json` while preserving existing scale invariants (`10` domains, `341` cached assets, `315` gateways with `simple-gateway`, cluster, and `CpmiVsNetobj` Virtual System assets in every user domain plus at least `15` cross-domain Virtual Systems, `325` CLI routing targets, unique per-domain gateway and interface IPv4 addresses and Virtual System internal `/24` subnets, complete `CpmiVsxSlotObj` and `CpmiVsSlotObj` entries across VSX chassis hosts, `105` access rules in `3` sections per domain, `12` NAT rules per domain, fewer than `250` topology-cached objects, and unmodified rule #1 fixtures)

### Requirement: Standalone Check Point Web API HTTPS Mock Server for Downstream Applications

The testing package SHALL provide an embeddable and CLI-runnable HTTPS server (`python -m arodonata.testing.mock_server`) sharing unified session, async task, and mutation state with `FileReplayApiMock`, serving `/web_api/{cmd}` with host-rewritten `show-domains`, `X-chkp-sid` session enforcement, and fast state reset controls so downstream applications can run full read and write workflows against `localhost:<port>`.

#### Scenario: Downstream application connects over HTTPS to localhost and syncs multi-domain dataset

- **WHEN** `CheckPointReplayHttpServer` is started on `localhost:<port>` (e.g., `localhost:443` or an ephemeral test port) and a client connects via real `AMgmtClient` / `ApiTransport`
- **THEN** `/web_api/login` SHALL issue domain-bound session tokens (`X-chkp-sid`), `/web_api/show-domains` SHALL rewrite active CMA/MDS server `ipv4-address` fields to the server's bound host, and subsequent `/web_api/{cmd}` requests (`show-gateways-and-servers`, `show-hosts`, `show-groups`, `show-packages`, `show-access-rulebase`, `run-script`, `show-task`, etc.) SHALL return the corresponding domain's paginated raw dataset without artificial rate limiting or login delays

#### Scenario: Downstream application executes stateful write workflows and resets state via CheckPointReplayHttpServer

- **WHEN** an HTTPS client authenticates via `/web_api/login`, executes mutating `/web_api/{cmd}` calls, polls `/web_api/show-task` for asynchronous commands (`publish`, `show-changes`, `verify-policy`, `install-policy`, `assign-global-assignment`, `assign-global-policy`, `run-script`), and subsequently resets server state between test scenarios
- **THEN** `/web_api/{cmd}` SHALL enforce HTTP `401` (`generic_err_missing_required_header` or `generic_err_invalid_session_id`) on missing or invalidated `X-chkp-sid` headers, reflect committed changes immediately across subsequent HTTPS requests, and restore clean state via `snapshot_state()`, `restore_state()`, `reset()`, or opt-in `/__testing__/*` endpoints

### Requirement: Access and NAT Rulebase CRUD, Positioning, and Automatic Consistency

The emulator SHALL support `show-access-rule`, `add-access-rule`, `set-access-rule`, `delete-access-rule`, `add-access-section`, `set-access-section`, `delete-access-section`, `show-access-layer`, `add-access-layer`, `set-access-layer`, `delete-access-layer` (including inline layers), `show-https-rulebase`, `show-threat-rulebase`, `https-rule` / `threat-rule` CRUD, `show-nat-rule`, `add-nat-rule`, `set-nat-rule`, `delete-nat-rule`, `add-nat-section`, `set-nat-section`, `delete-nat-section`, and `verify-policy` / `install-policy` task simulation, automatically recomputing rule numbers, section ranges, live `objects-dictionary`, `show-objects`, `show-object`, and `where-used`.

#### Scenario: Access rule and section CRUD maintains rule-numbers, section bounds, and objects-dictionary

- **WHEN** a write session adds, edits, reorders (`position` / `new-position` with `"top"`, `"bottom"`, 1-based integer `rule-number`, `{"top": section}`, `{"bottom": section}`, `{"above": ref}`, `{"below": ref}`), enables/disables, or deletes Access rules or sections, or mutates rule cells via full replacement or `{"add": ..., "remove": ...}`
- **THEN** the emulator SHALL strip `"Any"` (`97aeb369-9aea-11d5-bd16-0090272ccb30`) when concrete members are added, revert emptied cells to `"Any"`, recompute sequential 1-based `rule-number` values and section `from`/`to` bounds (plus layer `total`), and return live `objects-dictionary` entries (or inline dicts for `use-object-dictionary=False`) on subsequent `show-access-rule` and `show-access-rulebase` reads

#### Scenario: NAT rule CRUD normalizes Original and Any sentinels and updates NAT rule numbers

- **WHEN** a write session creates, updates, repositions, or deletes NAT rules or sections in a package using `"Original"`, `"Any"`, sentinel UIDs (`85c0f50f-6d8a-4528-88ab-5fb11d8fe16c`, `97aeb369-9aea-11d5-bd16-0090272ccb30`), object names, or object UIDs
- **THEN** the emulator SHALL normalize and store sentinel/object UIDs cleanly, recompute sequential NAT `rule-number` values, section `from`/`to` bounds, and package `objects-dictionary`, and serve updated rules via `show-nat-rule` and `show-nat-rulebase`

#### Scenario: Post-mutation reads stay consistent across where-used, show-objects, show-object, and inline rulebases

- **WHEN** any group membership or Access/NAT rule cell is mutated in a session overlay or published into domain state
- **THEN** subsequent calls to `where-used` (direct and indirect), `show-objects`, `show-object`, singular `show-*`, and `show-*-rulebase` (`use-object-dictionary=True | False`) with visibility into that state SHALL immediately reflect added, renamed, re-bound, or removed references
