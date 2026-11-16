# Enterprise Raw-Replay Dataset & Standalone HTTPS Mock Server

`arodonata.testing` provides a deterministic, enterprise-scale raw Check Point Management API and Gateway CLI fixture dataset (`tests/fixtures/enterprise_raw_dataset/`), in-memory replay adapters (`FileReplayApiMock`, `FileReplayCliMock`), and a standalone/embeddable HTTPS server (`CheckPointReplayHttpServer`).

This allows downstream applications such as **MMP** and **FPCR** to point `ArodonataClient` at `localhost:443` (or any custom `host:port`) and receive 10 MDSM domains, 315 policy-enforcing gateways, 2,950+ objects (including 7-level nested groups), 1,050+ access rules, 120 NAT rules, and live gateway CLI routes via real HTTPS without requiring physical Check Point appliances or waiting for artificial rate limits / login throttling.

> **Practical Test Scenarios**: Looking for concrete source/destination IP flows across multiple gateways, pre-existing object/service reuse examples for `Evidence` verification, and planted topology discrepancies in **FPCR v2**? See [Mock Testing Scenarios & Rule Creation Guide](mock-testing-scenarios.md).

## 1. Enterprise Dataset Overview (`tests/fixtures/enterprise_raw_dataset/`)

Generated deterministically with `DEFAULT_SEED = 20261108` (`DATASET_VERSION = "1.2.0"`) via `ensure_enterprise_raw_dataset()`:

- **Domains (10 total)**: 9 user domains (`Branch`, `Regional`, `WAN_Core`, `Perimeter`, `Transit`, `DC_Spine`, `DC_Pod`, `DB_Seg`, `Partner_DMZ`) plus `Global`.
- **Gateways & Assets (341 total assets / 315 policy-enforcing gateways, 325 CLI routing targets)**:
  - Simple gateways (`simple-gateway`), clusters (`simple-cluster` / `CpmiGatewayCluster` with `cluster-member` nodes), VSX physical chassis (`vsx-cluster` / `CpmiVsxNetobj` / `CpmiVsxSlotObj`), and VSX Virtual Systems (`virtual-system` / `CpmiVsNetobj` / `CpmiVsSlotObj`) distributed heterogeneously across every user domain (`Branch` through `Partner_DMZ`), including 15+ cross-domain VSX Virtual Systems.
  - Covers all Check Point interface topology representations (`interfaces`, `interfaces_installed`, `leads-to-internet`, `leads-to-specific-network`, `anti-spoofing-settings`, `routes_installed`).
- **Network & Service Objects (2,951 network objects, 210 services)**:
  - Hosts, networks, address ranges, DNS domains, and nested object groups up to 7 levels deep (`G_L1_*` through `G_L7_*`).
- **Policy Packages & Rulebases (1,050 access rules, 120 NAT rules)**:
  - Ordered access layers, sections, inline layers, `Global` placeholder rules, and NAT rulebases across all domains.
- **Raw Gateway CLI Routing Outputs (`cli/` & `tasks/`)**:
  - `vsx stat -l`, `ip -4 route show`, and `clish -c "show route"` covering `kernel`/`C`, `static`/`S`, `bgp`/`B`, `ospf`/`O`, `routed`/`R`, `I` IS-IS, ECMP, and cluster member drift.
  - Base64-encoded `run-script` / `show-task` payloads (`tasks/<node>__vs_<vsid>.json`) for `cprid` fallback testing.

## 2. Running the Standalone HTTPS Mock Server for MMP / FPCR

Start the HTTPS mock server from the command line:

```bash
# Run on localhost:8443 (unprivileged)
uv run python -m arodonata.testing.mock_server --host 127.0.0.1 --port 8443

# Or bind to port 443 for applications configured with default HTTPS port
sudo uv run python -m arodonata.testing.mock_server --host 127.0.0.1 --port 443
```

When started, the server automatically:

1. Generates a self-signed RSA-2048 TLS certificate and prints its SHA-256 fingerprint (`SHA256:...`).
2. Tracks `X-chkp-sid -> domain` mappings created during `POST /web_api/login` (`{"domain": "..."}`) so subsequent domain-scoped `POST /web_api/<command>` calls are routed to the right CMA domain dataset.
3. Rewrites CMA and MDS `ipv4-address` entries in `/web_api/show-domains`, `/web_api/show-global-domain`, and `/web_api/show-mdss` to the mock server's bound host (`127.0.0.1` / `localhost`), so multi-domain `ArodonataClient` connections stay on the local mock server.

### Connecting `ArodonataClient` (or MMP / FPCR) to the Mock Server

```python
from arodonata import ArodonataClient, ArodonataSettings

settings = ArodonataSettings(
    database_url="sqlite+aiosqlite:////tmp/arodonata_mock.sqlite",
    mgmt_name="mds",
    mgmt_ip="127.0.0.1",
    mgmt_port=8443,
    api_key="mock-key",
    tls_trust="tofu",
    tls_known_hosts_path="/tmp/mock_known_hosts",
)

async with ArodonataClient(settings=settings) as client:
    domains = await client.get_domains(mgmt_name="mds", include_global=True)
    await client.topology_service.refresh_topology(mgmt_name="mds", collect_routes=True)
    hops = await client.topology_service.find_affected_gateways(
        sources=["10.11.1.25"],
        destinations=["10.220.77.50"],
        mgmt_name="mds",
        cache_mode="cache",
    )
```

## 3. Using `FileReplayApiMock` and `FileReplayCliMock` in Automated Tests

For fast, zero-socket unit and scale tests, inject `FileReplayApiMock` (`ApiPort`) and `FileReplayCliMock` (`GatewayCliPort`) directly into `ArodonataClient`:

```python
from arodonata import ArodonataClient, ArodonataSettings
from arodonata.testing import FileReplayApiMock, FileReplayCliMock

cli_mock = FileReplayCliMock()
api_mock = FileReplayApiMock(cli_mock=cli_mock)
settings = ArodonataSettings(
    database_url="sqlite+aiosqlite:///:memory:",
    mgmt_name="mds",
    mgmt_ip="127.0.0.1",
    mgmt_port=8443,
    api_key="mock-key",
)

async with ArodonataClient(settings=settings, api=api_mock, gateway_cli=cli_mock) as client:
    await client.topology_service.refresh_topology(mgmt_name="mds", collect_routes=True)
```

## Stateful Session Isolation, CRUD, and MDSM Emulation

Both `FileReplayApiMock` and `CheckPointReplayHttpServer` emulate stateful Check Point Management & MDSM behavior on top of the loaded dataset:

- **Per-`sid` Staging Overlays & Session Lifecycle**: Sessions opened via `login`, `/web_api/login`, or `create_dedicated_session` receive an isolated copy-on-write staging overlay and acquire per-object UID locks on modification. Supports `read-only` sessions, `set-session`, `take-over-session` (including disconnecting the prior active SID), `switch-session`, `discard`, `logout` / `logout_sid`, `publish` (with conflict-checked rebase fallback and post-publish work-session rotation), `show-session`, `show-sessions`, `show-last-published-session`, and `show-changes`.
- **Stateful Object, Service, Group & Rule CRUD**: Supports `show-*` / `add-*` / `set-*` / `delete-*` for `host`, `network`, `address-range`, `dns-domain`, `application-site`, `group`, `service-tcp`, `service-udp`, `service-icmp`, `service-icmp6`, `service-other`, `service-group`, `access-rule`, `access-section`, `access-layer` (including inline layers), `https-rule`, `threat-rule`, `nat-rule`, `nat-section`, plus `show-https-rulebase`, `show-threat-rulebase`, `verify-policy`, `install-policy`, `show-unused-objects`, and `delete-unused-objects`.
- **Referential Integrity & Consistency**: Enforces Check Point deletion blocking (`generic_err_object_cannot_be_deleted` with `blocking-errors`) whenever an object or group is referenced by groups, Access rules, or NAT rules, and keeps `where-used`, `show-objects`, `show-object`, and `objects-dictionary` synchronized after every change.
- **MDSM `Global` Read/Write Protection**: `Global` objects and groups are visible across local user domains (`show-object`, `show-objects`, `where-used`, `show-access-rulebase`), while local-domain `set-*` / `delete-*` calls targeting `Global` entities are rejected with `generic_err_object_read_only`. Also supports `show-global-assignments`, `show-global-assignment`, `assign-global-assignment`, and `assign-global-policy`.

## Fast Snapshot/Restore, Test Control Endpoints, and Call-Log Assertions

### In-Memory Snapshot & Reset (`ReplayStateSnapshot`)

Use `snapshot_state()` and `restore_state(snapshot)` on either `FileReplayApiMock` or `CheckPointReplayHttpServer` to isolate multi-step E2E scenarios in milliseconds without regenerating disk fixtures (capturing domain data, sessions, locks, tasks, global assignments, and `FileReplayCliMock` overrides), or call `reset()` to return to the baseline fixture state.

### Opt-In HTTP Test-Control Endpoints (`--enable-test-control`)

Programmatic `CheckPointReplayHttpServer(..., enable_test_control=True)` (default `False` in both the constructor and CLI; opt-in via `--enable-test-control`, optionally with `--test-control-token`) requires authentication on all control endpoints via either `X-Arodonata-Test-Token: <server.test_control_token>` or an active `X-chkp-sid` header, and exposes:

- `POST /__testing__/reset`: Resets all server state back to dataset baseline.
- `POST /__testing__/snapshot`: Saves a named snapshot (`{"name": "..."}`, defaults to `"default"`).
- `POST /__testing__/restore`: Restores a named snapshot (`{"name": "..."}`, defaults to `"default"`).
- `GET /__testing__/call-log`: Returns the SID-redacted `api_mock.call_log`.

### SID-Safe `call_log` & Assertion Helpers

`FileReplayApiMock.call_log` redacts raw SIDs, passwords, and API keys while recording non-secret `mgmt_name`, `domain`, `command`, `is_mutating`, `sid_ref`, `session_uid`, `read_only_session`, `payload`, `payload_summary`, `status_code`, `success`, and `error_code`. Built-in helpers:

- `get_calls(domain=..., command=..., mutating_only=...)`
- `assert_no_global_mutations()`
- `assert_no_full_object_scans(...)`
- `assert_command_called(command, domain=..., times=...)`
- `assert_command_not_called(command, domain=...)`
