# Enterprise Raw-Replay Dataset & Standalone HTTPS Mock Server

`arodonata.testing` provides a deterministic, enterprise-scale raw Check Point Management API and Gateway CLI fixture dataset (`tests/fixtures/enterprise_raw_dataset/`), in-memory replay adapters (`FileReplayApiMock`, `FileReplayCliMock`), and a standalone/embeddable HTTPS server (`CheckPointReplayHttpServer`).

This allows downstream applications such as **MMP** and **FPCR** to point `ArodonataClient` at `localhost:443` (or any custom `host:port`) and receive 10 MDSM domains, 276 policy-enforcing gateways, 2,950+ objects (including 7-level nested groups), 1,050+ access rules, 120 NAT rules, and live gateway CLI routes via real HTTPS without requiring physical Check Point appliances or waiting for artificial rate limits / login throttling.

## 1. Enterprise Dataset Overview (`tests/fixtures/enterprise_raw_dataset/`)

Generated deterministically with `DEFAULT_SEED = 20261108` via `ensure_enterprise_raw_dataset()`:

- **Domains (10 total)**: 9 user domains (`Branch`, `Regional`, `WAN_Core`, `Perimeter`, `Transit`, `DC_Spine`, `DC_Pod`, `DB_Seg`, `Partner_DMZ`) plus `Global`.
- **Gateways & Assets (284 total assets / 276 policy-enforcing gateways)**:
  - Simple gateways (`simple-gateway`), clusters (`simple-cluster` with `cluster-member` nodes), VSX physical chassis (`vsx-cluster` / `CpmiVsxNetobj` / `CpmiVsxSlotObj`), and VSX Virtual Systems (`virtual-system` / `CpmiVsNetobj` / `CpmiVsSlotObj`).
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
from arodonata import ArodonataClient, ArodonataSettings, ServerEndpointConfig

settings = ArodonataSettings(
    servers={
        "mds": ServerEndpointConfig(
            name="mds",
            host="127.0.0.1",
            port=8443,
            username="admin",
            password="mock-password",
        )
    },
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
from arodonata import ArodonataClient
from arodonata.testing import FileReplayApiMock, FileReplayCliMock

cli_mock = FileReplayCliMock()
api_mock = FileReplayApiMock(cli_mock=cli_mock)

async with ArodonataClient(api=api_mock, gateway_cli=cli_mock) as client:
    await client.topology_service.refresh_topology(mgmt_name="mds", collect_routes=True)
```
