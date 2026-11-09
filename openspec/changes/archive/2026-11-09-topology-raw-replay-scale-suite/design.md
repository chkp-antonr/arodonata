# Design

## Context

See `proposal.md` for motivation. `ArodonataClient` orchestrates domain discovery (`DomainService`), object/service synchronization (`ObjectService`, `ServiceCacheService`), gateway/cluster/VSX asset enrichment (`AssetRefreshService`), rulebase snapshots (`RulebaseRefreshService`), and static + live CLI topology analysis (`TopologyService`, `route_collector`) over two hexagonal ports: `ApiPort` and `GatewayCliPort`. When used by downstream applications (MMP, FPCR), `ArodonataClient` communicates over HTTPS (`POST /web_api/{cmd}`) via `AMgmtClient` and `ApiTransport`.

## Goals / Non-Goals

**Goals:**

- Provide a deterministic (fixed-seed) generator and on-disk raw fixture dataset (`tests/fixtures/enterprise_raw_dataset/`) covering 9 MDSM user domains plus `Global`, 260+ gateways/clusters/VSX Virtual Systems, 2,500+ network/service objects (with 6–7-level nested groups), 1,000+ access/NAT rules, and raw CLI routing outputs (`vsx stat -l`, `ip -4 route show`, `clish -c "show route"`, Base64 `show-task`).
- Implement `FileReplayApiMock` (`ApiPort`) and `FileReplayCliMock` (`GatewayCliPort`) with faithful Check Point pagination (`limit`/`offset` -> `from`/`to`/`total`), `details-level`, `uid`/`name`/`class-name` filtering, bash `vsenv` / `vsx stat -l` / `CTX%05d` validation, `run-script` + `show-task` Base64 emulation, and granular call counters.
- Provide a standalone and embeddable HTTPS `/web_api/{cmd}` mock server (`CheckPointReplayHttpServer` and CLI `python -m arodonata.testing.mock_server`) so external applications (MMP, FPCR) pointed at `localhost:443` (or any custom port) can query all domains, objects, gateways, rulebases, and `run-script` routes through real `ArodonataClient` HTTPS transport.
- Validate the full 6-stage topology pipeline in `tests/unit/test_topology_raw_replay_scale.py`.

**Non-Goals:**

- Simulating network latency, HTTP 429 rate limiting, or login throttling in the replay mock (already covered by dedicated unit tests and live lab integration buckets).
- Persisting mutating `add-*`/`set-*`/`delete-*` CPCRUD operations back to the static fixture files on disk.

## Decisions

### 1. On-Disk Raw Fixture Layout and Deterministic Generator (`src/arodonata/testing/dataset_generator.py`)

- **Decision**: Organize `tests/fixtures/enterprise_raw_dataset/` into human-inspectable raw JSON and text files generated deterministically with `random.Random(20261108)`:
  - `manifest.json`: dataset version, seed, domain list, asset/object/rule counts, and expected diagnostic/reconciliation anomaly inventory.
  - `mds/show-domains.json`, `mds/show-mdss.json`, `mds/show-global-domain.json`: raw MDSM domain definitions across 9 user domains (`Branch`, `Regional`, `WAN_Core`, `Perimeter`, `Transit`, `DC_Spine`, `DC_Pod`, `DB_Seg`, `Partner_DMZ`) + `Global`.
  - `domains/<domain>/`: raw API payloads per command (`show-last-published-session.json`, `show-session.json`, `show-sessions.json`, `show-gateways-and-servers.json`, `show-simple-gateway.json`, `show-simple-cluster.json`, `show-generic-objects.json` partitioned by `class-name` for `CpmiVsNetobj`, `CpmiVsxNetobj`, `CpmiVsxSlotObj`, and `CpmiVsSlotObj`, `show-hosts.json`, `show-networks.json`, `show-address-ranges.json`, `show-groups.json` with 6–7 nesting levels, `show-services-tcp.json`, `show-services-udp.json`, `show-services-icmp.json`, `show-service-groups.json`, `show-packages.json`, `show-access-layers.json`, `show-access-rulebase.json`, `show-nat-rulebase.json`).
  - `cli/<node_name>__vs_<vsid>.txt` and `cli/<node_name>__vsx_stat_l.txt`: raw Gaia / VSX CLI stdout (`===ARODONATA_IP_ROUTE_START===`, `ip -4 route show`, `===ARODONATA_CLISH_ROUTE_START===`, `clish -c "show route"` with `kernel`, `static`, `bgp`, `ospf`, `routed`, `I` IS-IS, ECMP, and cluster member drift).
  - `tasks/<node_name>__vs_<vsid>.json`: raw `show-task` JSON payloads with Base64-encoded `responseMessage` for `cprid` fallback testing.
- **Rationale**: Keeping raw JSON and CLI stdout files on disk (with automatic deterministic materialization if missing or when invoked via CLI) satisfies "from raw source files" fidelity while allowing developers to inspect or tweak individual gateway responses during tests.

### 2. Enterprise Topology Architecture & Planted Test Scenarios

- **Decision**: Embed structured enterprise routing topologies alongside bulk scale assets (260+ policy-enforcing gateways, 2,500+ objects, 1,000+ rules):
  - **9-Hop Inter-Domain Chain**:
    1. `Branch` (`br-spb-gw-01`, `simple-gateway`)
    2. `Regional` (`reg-nw-cluster`, `simple-cluster` with 2 cluster members)
    3. `WAN_Core` (`wan-core-ecmp-a` and `wan-core-ecmp-b` parallel active ECMP gateways + `wan-core-bgp-standby` standby BGP gateway)
    4. `Perimeter` (`perim-edge-cluster`, `CpmiGatewayCluster`)
    5. `Transit` (`ix-transit-gw-01`, `internal_to_internal` inter-domain transit router)
    6. `DC_Spine` (`dc-vsx-spine-vs01`, `CpmiVsNetobj` hosted on `dc-vsx-chassis-01` in `DC_Spine`, linked via `CpmiVsSlotObj` / `CpmiVsxSlotObj`)
    7. `DC_Pod` (`dc-vs-tier1-web`, cross-domain `CpmiVsNetobj` with `vsid=11` hosted on `dc-vsx-chassis-01`)
    8. `DC_Pod` (`dc-vs-tier2-app`, `CpmiVsNetobj` without static `vsid` in summary, dynamically resolved via `vsx stat -l` -> `vsid=12` and `CTX00012`)
    9. `DB_Seg` (`db-seg-internal-fw-01`, internal-only segmentation firewall with zero `external` interfaces).
  - **LPM Matryoshka Gateway (`lpm-matryoshka-gw` in `Transit`)**:
    - Configures 7 nested prefixes across distinct internal interfaces (`10.0.0.0/8` on `eth1`, `10.16.0.0/12` on `eth2`, `10.24.0.0/16` on `eth3`, `10.24.4.0/22` on `eth4`, `10.24.5.0/24` on `eth5`, `10.24.5.16/28` on `eth6`, `10.24.5.20/32` on `eth7`) plus `eth0` (`external`) to test exact longest-prefix-match specificity at every mask depth.
  - **Planted Diagnostics & Reconciliation Anomalies**:
    - Dedicated gateways/interfaces exercising `not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`, `one_arm_topology` (`severity="info"`), internal-only gateways (zero warnings), `stale_in_topology`, `missing_in_topology`, `interface_mismatch`, `cluster_member_drift`, `default_route_mismatch`, and `resolved_by_routing`.

### 3. Shared Replay Engine for `ApiPort`/`GatewayCliPort` and Standalone HTTPS Server (`CheckPointReplayHttpServer`)

- **Decision**: Build `FileReplayApiMock` (`ApiPort`) and `FileReplayCliMock` (`GatewayCliPort`) in `src/arodonata/testing/replay_mock.py`, and wrap them in `CheckPointReplayHttpServer` (`src/arodonata/testing/mock_server.py`) using `aiohttp.web`:
  - **Pagination & Filtering**: `FileReplayApiMock` slices domain object arrays according to `offset` and `limit`, returning Check Point-compliant `{"objects": [...], "from": offset + 1, "to": offset + len(page), "total": total}` (or rulebase `{"rulebase": [...], "from": ..., "to": ..., "total": ...}`), honours `details-level` (`"uid"`, `"standard"`, `"full"`), filters `show-generic-objects` by `class-name`, and resolves single objects by `uid` or `name`.
  - **CLI Script Validation & `cprid` Fallback**: `FileReplayCliMock` inspects the bash script produced by `build_route_collection_script`:
    - If targeting a VS with known `vsid`, verifies `vsenv "$vsid"` and `CTX%05d` check are present.
    - If targeting a VS by `vs_name` without `vsid`, parses the `vsx stat -l` awk pipeline against `cli/<node_name>__vsx_stat_l.txt`, resolves `vsid`, emits `===ARODONATA_VSID_RESOLVED=<vsid>===`, and returns `cli/<node_name>__vs_<vsid>.txt`.
    - When `run-script` is invoked on `FileReplayApiMock` (e.g., when SSH fails on a branch gateway or when MMP/FPCR connects over HTTPS without SSH), `FileReplayApiMock` runs the same CLI script resolution, returns `{"tasks": [{"task-id": "<id>"}]}`, and serves the Base64-encoded stdout in `show-task` (`tasks[0].task-details[0].responseMessage`).
  - **Multi-Domain Routing on `localhost:<port>` for MMP / FPCR**:
    - In `CheckPointReplayHttpServer`, `POST /web_api/login` reads `domain` from the JSON request body, mints a unique `sid`, and stores `sid -> domain_name` in the server's session table.
    - `POST /web_api/show-domains` dynamically rewrites each domain's CMA `servers[].ipv4-address` and `multi-domain-server` IP to the HTTP server's bound address (e.g., `127.0.0.1` or `localhost`) so `ArodonataClient` routes all per-domain logins and queries to the same local mock server.
    - Every subsequent `POST /web_api/{cmd}` resolves its target domain from `request.headers["X-chkp-sid"]` (with payload `domain` fallback) and delegates to `FileReplayApiMock`.

## Risks / Trade-offs

- **[Risk] Large raw fixture files bloating git history or slowing test startup** → **Mitigation**: Keep individual JSON files compact and deterministic via `ensure_enterprise_raw_dataset()`, loading domain files lazily on first query and caching parsed JSON structures inside `FileReplayApiMock` with copy-on-mutation support for Step 6 targeted refresh tests.
- **[Risk] Port 443 requires elevated privileges on macOS/Linux when running standalone** → **Mitigation**: Allow `--port` CLI flag (defaulting to `8443` or `443` when specified) and configurable `--host` / `--cert` / `--key` in `python -m arodonata.testing.mock_server`, while unit tests bind to `127.0.0.1:0` (ephemeral port).
