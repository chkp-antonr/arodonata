# Mock Testing Scenarios & Rule Creation Guide

Practical scenarios for testing multi-gateway rule provisioning, pre-existing object/service reuse in change evidence, and static-vs-route topology discrepancy audits against the deterministic `arodonata` enterprise replay dataset (`DATASET_VERSION = "1.2.0"`, `DEFAULT_SEED = 20261108`) and **FPCR v2**.

> **Reference Server Guide**: For standalone HTTPS mock server options, in-memory snapshots (`ReplayStateSnapshot`), and `/__testing__/*` endpoints, see [Enterprise Raw-Replay Dataset & Standalone HTTPS Mock Server](enterprise-replay-mock-server.md).

## 1. Quick Start

### Standalone `arodonata` HTTPS Mock Server

```bash
uv run python -m arodonata.testing.mock_server --host 127.0.0.1 --port 8443
```

### Full FPCR v2 Mock Environment

From the `FPCR_v2` repository root, launch the isolated `fpcr_mock` PostgreSQL database, background `arodonata.testing.mock_server` (`https://127.0.0.1:8443/web_api`, `ARODONATA_MOCK_CLI=true`), and FastAPI + React WebUI:

```bash
./run_fa_mock.sh
```

- **WebUI**: `http://localhost:8080`
- **API Docs**: `http://localhost:8080/docs`
- **Credentials**: Sign in as `admin`, `eng1`..`eng4`, or `AntonR` with any non-empty password. To test Four-Eyes approval end-to-end, stage the change as `eng1` and approve/publish as `eng2`.

## 2. Multi-Gateway Traffic Flows (Source -> Destination Examples)

Use these IP pairs to exercise multi-domain, multi-gateway path prediction in `ArodonataClient.topology_service.find_affected_gateways(...)` and **FPCR v2** (`Predict Gateways` / `fan_out_multi_gateway`).

| Scenario | Source(s) | Destination(s) | `arodonata` Gateways Matched | `FPCR_v2` Prediction Behavior |
| --- | --- | --- | --- | --- |
| **Flow A: 9-Hop Cross-Domain Chain** (`Branch` -> `DB_Seg`) | `10.11.1.10`, `10.11.1.0/24`, `10.11.1.100-10.11.1.199`, or `10.11.1.77` | `10.220.77.0/24` or `10.220.77.88` | **10 gateways** static-only / **11** with routes across **8 domains** | **Primary (4 leaf domains / 5 gateways)**: `Branch`, `Regional`, `DC_Pod`, `DB_Seg`. **Superseded supernets (4 transit domains, expandable in UI)**: `WAN_Core`, `Perimeter`, `Transit`, `DC_Spine`. |
| **Flow B: Direct `/16` Transit Core Flow** (no `/24` leaf overlap) | `10.11.200.10` | `10.220.200.50` | **5 gateways** static-only / **6** with routes across `WAN_Core`, `Perimeter`, `Transit`, `DC_Spine` | **Primary**: `WAN_Core`, `Perimeter`, `Transit` (plus `DC_Spine` when routes are loaded), because no narrower `/24` leaf supersedes the `/16` transit networks. |
| **Flow C: Branch to Partner Extranet** (`Branch` -> `Partner_DMZ`) | `10.11.1.10` (or `10.12.1.25` VoIP with routes) | `172.30.1.50` | **9 gateways** across `Branch`, `Regional`, `WAN_Core`, `Perimeter`, `Transit`, `Partner_DMZ` (or **4 gateways** for `10.12.1.25` with routes) | **Primary**: `Branch`, `Regional`, `Partner_DMZ` (plus `lpm-matryoshka-gw` / `/16` transit entries shown under superseded/broad exclusions). |

### Hop-by-Hop Breakdown of Flow A (`10.11.1.x` -> `10.220.77.x`)

1. **`Branch`** -> `br-spb-gw-01` (`Branch_Standard_Pkg` / `Branch_Standard_Pkg Network`): `eth1` (`10.11.1.0/24`, internal) -> `eth0` (external).
2. **`Regional`** -> `reg-nw-cluster` (`Regional_Hub_Pkg` / `Regional_Hub_Pkg Network`): `eth1` (7-level nested group `G_Reg_NW_L1_Root` -> ... -> `G_Reg_NW_L7_Leaf`) -> `eth0`.
3. **`WAN_Core`** -> `wan-core-ecmp-a`, `wan-core-ecmp-b` (active ECMP), and `wan-core-bgp-standby` (`WAN_Core_Transit_Pkg` / `WAN_Core_Transit_Pkg Network`): `/16` transit `10.11.0.0/16` -> `10.220.0.0/16`.
4. **`Perimeter`** -> `perim-edge-cluster` (`Perimeter_Edge_Pkg` / `Perimeter_Edge_Pkg Network`): Global groups `G_Global_Branch_Supernet` -> `G_Global_DC_Supernet`.
5. **`Transit`** -> `ix-transit-gw-01` (`Transit_Interconnect_Pkg` / `Transit_Interconnect_Pkg Network`): `eth1` (`N_Transit_West_10_11`) -> `eth2` (`N_Transit_East_10_220`).
6. **`DC_Spine`** -> `dc-vsx-spine-vs01` (`DC_Spine_VS_Pkg` / `DC_Spine_VS_Pkg Network`): VSX `vsid=1` on `dc-vsx-chassis-01` (matched when `vs_static_route` / CLI routes are present).
7. **`DC_Pod`** -> `dc-vs-tier1-web` (`vsid=11`) and `dc-vs-tier2-app` (dynamic `vsid=12` resolved via `vsx stat -l`) (`DC_Pod_Tier_Pkg` / `DC_Pod_Tier_Pkg Network`).
8. **`DB_Seg`** -> `db-seg-internal-fw-01` (`DB_Vault_Seg_Pkg` / `DB_Vault_Seg_Pkg Network`): internal-only firewall (`eth1` `G_DB_Allowed_Clients` -> `eth2` `10.220.77.0/24`).

> **Tip**: In **FPCR v2** `Predict Gateways`, Flow A selects the narrow `/24` leaf domains (`Branch`, `Regional`, `DC_Pod`, `DB_Seg`) as **Primary** targets and places the `/16` transit core domains (`WAN_Core`, `Perimeter`, `Transit`, `DC_Spine`) in the expandable **Superseded / Excluded** panel (`min_internal_prefix_len=16`). Check those transit entries in the Target Proposal modal or use Flow B (`10.11.200.10` -> `10.220.200.50`) to target core gateways directly.

## 3. Reusing Pre-Existing Objects & Services in Rules & `Evidence`

With `on_ip_conflict="reuse"` (default in both `arodonata.cpcrud` and **FPCR v2**), the planner matches candidate IPs, subnets, address ranges, and services against existing local-domain and `Global` objects. When a match exists under another name, the rule references the **pre-existing Check Point object name**, and the `Object Changes` section in `Evidence` records **only newly created (`NEW`) objects**.

### Pre-Existing Dataset Objects vs Unused Values

| Object Type | Raw Value / Token | Outcome (`on_ip_conflict="reuse"`) | Resolved Object Name in Rule (`Evidence`) | Scope / Notes |
| --- | --- | --- | --- | --- |
| **Host** | `10.11.1.10` | `reuse` | `H_Branch_001_Server` | `Branch` (`10.11.<b>.10` -> `H_Branch_<b:03d>_Server`, `b=1..140`) |
| **Host** | `10.121.0.2` | `reuse` | `H_Branch_AppNode_001` | `Branch` (`10.<120+d_idx>.0.2` -> `H_<Domain>_AppNode_001` for `d_idx=1..9`) |
| **Host** | `10.253.0.1` | `reuse` | `H_Global_DNS_001` | `Global` (`10.253.0.1..80` -> `H_Global_DNS_001..080`, visible in all domains) |
| **Host (new)** | `10.11.1.77` or `10.220.77.88` | `create` | `Host_10.11.1.77` / `Host_10.220.77.88` | Not in dataset; appears as `NEW` in `Object Changes` |
| **Network** | `10.11.1.0/24` | `reuse` | `N_Branch_001_LAN` (`Branch`) / `N_Reg_Branch_001_LAN` (`Regional`) | Domain-specific `/24` LAN network |
| **Network** | `10.220.77.0/24` | `reuse` in `DC_Pod` / `create` in `Branch` | `N_DC_DB_Vault_Sub` (`DC_Pod`) / `Net_10.220.77.0_24` (`Branch`) | Demonstrates cross-domain contrast in a single multi-domain RITM |
| **Network** | `10.11.0.0/16` | `reuse` | `N_Global_All_Branches` (`Global`) / `N_WAN_Branch_Agg` (`WAN_Core`) | Also `N_Transit_West_10_11` in `Transit` |
| **Address Range** | `10.11.1.100-10.11.1.199` | `reuse` | `R_Branch_001_DHCP` | `Branch` (`b=1..30`) |
| **Address Range** | `10.161.1.10-10.161.1.50` | `reuse` | `R_Branch_Pool_001` | `Branch`; pattern `10.<160+d_idx>.<1..20>.10-50` -> `R_<Domain>_Pool_001..020` (e.g. `10.167.1.10-10.167.1.50` in `DC_Pod`, `10.168.1.10-10.168.1.50` in `DB_Seg`) |
| **Address Range (new)** | `10.11.1.210-10.11.1.220` | `create` | `IPR_10.11.1.210-10.11.1.220` | Not in dataset; appears as `NEW` in `Object Changes` |
| **Service (ICMP)** | `ICMP/8` (`icmp-type: 8`) | `reuse` | `ICMP_Branch_Echo` / `ICMP_<Domain>_Echo` | Resolves raw `ICMP/8` by ICMP type to the domain's pre-existing object name |
| **Service (TCP/UDP)** | `SVC_Branch_TCP_5432`, `SVC_Branch_UDP_53`, `G_Web_Services` | `unchanged` (by name) or `reuse` (by port when requested name differs from `TCP_<port>`) | `SVC_Branch_TCP_5432` / `SVC_<Domain>_TCP_<port>` | Pre-seeded TCP ports: `22, 53, 80, 443, 1521, 3306, 5432, 6379, 8080, 8443, 9092, 9200`; UDP: `53, 123, 161, 500, 514, 1812, 4500`. Note: `Global` also defines `TCP_<port>` and `UDP_<port>`, so raw `TCP/5432` matches `TCP_5432` as `unchanged` (still zero `NEW` objects in `Object Changes`). |
| **Service (new)** | `TCP/15432` | `create` | `TCP_15432` | Not in dataset; appears as `NEW` in `Object Changes` |

### Mixed Rule Example (FPCR v2 Rule Editor)

Enter the following in an **FPCR v2** RITM rule and run **Predict Gateways** -> **Try & Verify**:

- **Source**: `10.11.1.10, 10.121.0.2, 10.11.1.0/24, 10.11.1.100-10.11.1.199, 10.161.1.10-10.161.1.50, 10.11.1.77`
- **Destination**: `10.253.0.1, 10.220.77.0/24, 10.220.77.88`
- **Service**: `ICMP/8, SVC_Branch_TCP_5432, TCP/15432`
- **Action / Track**: `Accept` / `Log`

### Mixed Rule Example (Direct `arodonata.cpcrud` Script + Evidence Output)

```python
import asyncio
import tempfile
from pathlib import Path
from arodonata import ArodonataClient, ArodonataSettings
from arodonata.reports import RenderOptions, SessionScope
from arodonata.testing import FileReplayApiMock, FileReplayCliMock, ensure_enterprise_raw_dataset


async def main() -> None:
    dataset_dir = ensure_enterprise_raw_dataset()
    cli_mock = FileReplayCliMock(dataset_dir)
    api_mock = FileReplayApiMock(dataset_dir, cli_mock=cli_mock)

    with tempfile.TemporaryDirectory() as tmp:
        settings = ArodonataSettings(
            database_url=f"sqlite+aiosqlite:///{Path(tmp) / 'mock.sqlite'}",
            mgmt_name="mds",
            mgmt_ip="127.0.0.1",
            mgmt_port=8443,
            api_key="mock-key",
        )
        async with ArodonataClient(settings=settings, api=api_mock, gateway_cli=cli_mock) as client:
            template = {
                "mgmt_name": "mds",
                "domains": [
                    {
                        "domain": "Branch",
                        "operations": [
                            {"operation": "add", "type": "host", "name": "Host_10.11.1.10", "ipv4-address": "10.11.1.10"},
                            {"operation": "add", "type": "host", "name": "Host_10.121.0.2", "ipv4-address": "10.121.0.2"},
                            {"operation": "add", "type": "network", "name": "Net_10.11.1.0_24", "subnet4": "10.11.1.0", "mask-length4": 24},
                            {
                                "operation": "add",
                                "type": "address-range",
                                "name": "IPR_10.11.1.100-10.11.1.199",
                                "ipv4-address-first": "10.11.1.100",
                                "ipv4-address-last": "10.11.1.199",
                            },
                            {
                                "operation": "add",
                                "type": "address-range",
                                "name": "IPR_10.161.1.10-10.161.1.50",
                                "ipv4-address-first": "10.161.1.10",
                                "ipv4-address-last": "10.161.1.50",
                            },
                            {"operation": "add", "type": "host", "name": "Host_10.11.1.77", "ipv4-address": "10.11.1.77"},
                            {"operation": "add", "type": "host", "name": "Host_10.253.0.1", "ipv4-address": "10.253.0.1"},
                            {"operation": "add", "type": "network", "name": "Net_10.220.77.0_24", "subnet4": "10.220.77.0", "mask-length4": 24},
                            {"operation": "add", "type": "host", "name": "Host_10.220.77.88", "ipv4-address": "10.220.77.88"},
                            {"operation": "add", "type": "service-icmp", "name": "ICMP_8", "icmp-type": 8},
                            {"operation": "add", "type": "service-tcp", "name": "Svc_PG_5432", "port": "5432"},
                            {"operation": "add", "type": "service-tcp", "name": "TCP_15432", "port": "15432"},
                            {
                                "operation": "add",
                                "type": "access-rule",
                                "layer": "Branch_Standard_Pkg Network",
                                "position": "top",
                                "name": "RITM0099001_Branch_to_Vault",
                                "enabled": True,
                                "source": [
                                    "Host_10.11.1.10",
                                    "Host_10.121.0.2",
                                    "Net_10.11.1.0_24",
                                    "IPR_10.11.1.100-10.11.1.199",
                                    "IPR_10.161.1.10-10.161.1.50",
                                    "Host_10.11.1.77",
                                ],
                                "destination": ["Host_10.253.0.1", "Net_10.220.77.0_24", "Host_10.220.77.88"],
                                "service": ["ICMP_8", "Svc_PG_5432", "TCP_15432"],
                                "rule_action": "Accept",
                                "track": {"type": "Log"},
                            },
                        ],
                    }
                ],
            }
            plan = await client.cpcrud.plan(template, on_ip_conflict="reuse")
            await client.cpcrud.apply(plan, no_publish=False, session_name="RITM0099001")
            last_pub = await client.api_call("mds", "show-last-published-session", {}, domain="Branch")
            chg = await client.collect_change_report(
                [SessionScope(mgmt_name="mds", domain="Branch", session_uids=[last_pub.data["uid"]])]
            )
            print(client.render_change_report(chg, formats=["markdown"], options=RenderOptions(title="Evidence: RITM0099001")).markdown)


asyncio.run(main())
```

How to verify object reuse in the resulting **Evidence** report:

- **Rule Changes table** displays the pre-existing object names in `Source`, `Destination`, and `Service` (`H_Branch_001_Server`, `H_Branch_AppNode_001`, `N_Branch_001_LAN`, `R_Branch_001_DHCP`, `R_Branch_Pool_001`, `H_Global_DNS_001`, `ICMP_Branch_Echo`, `SVC_Branch_TCP_5432`) alongside newly created objects (`Host_10.11.1.77`, `Net_10.220.77.0_24`, `Host_10.220.77.88`, `TCP_15432`).
- **Object Changes table** lists **only** the 4 `NEW` objects (`Host_10.11.1.77`, `Host_10.220.77.88`, `Net_10.220.77.0_24`, `TCP_15432`); reused hosts, networks, ranges, and services are absent from `Object Changes`.

## 4. Inspecting Topology Discrepancies in FPCR v2

### Where to View Discrepancies

1. **WebUI (`Topology Audit & Routes` — `http://localhost:8080/topology-audit`)**:
   - Open **Topology Audit & Routes** in the left navigation sidebar.
   - Views are cache-first on navigation: click **Refresh Static Topology** (if needed) and **Collect Live Routes (cprid)** in the top toolbar to pull simulated `ip -4 route show` / `clish -c "show route"` data from `FileReplayCliMock` and run reconciliation.
   - Inspect the four tabs:
     - **Static Diagnostics & Interfaces**: SmartConsole interface config, Anti-Spoofing mode, static health warnings (`not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`, `one_arm_topology`), and expandable `[+]` static vs live intervals per interface.
     - **Route vs Static Discrepancies**: Discrepancies grouped by `Domain` -> `Gateway` -> `Interface` (`stale_in_topology`, `missing_in_topology`, `interface_mismatch`, `default_route_mismatch`, `cluster_member_drift`, `resolved_by_routing`), with **Fix / Remediate** and **Add Exception** actions.
     - **Known Networks & Subnets**: Unified `(domain, gateway, interface, CIDR)` pairing table across static and live entries.
     - **Exceptions**: Saved `TopologyAnnotation` suppressions (`confirmed`, `standby_dynamic`, `ignore`, `manual`).
   - Use **Export CSV** (unified or 6 table presets) or **Export JSON** above the tabs to download the full reconciliation bundle.
2. **CLI (`fpcr domains reconcile`, run from `FPCR_v2`)**:

   ```bash
   FPCR_ENV_FILE=.env.mock uv run fpcr domains reconcile --collect-routes
   FPCR_ENV_FILE=.env.mock uv run fpcr domains reconcile -d Partner_DMZ -g partner-b2b-cluster --collect-routes
   FPCR_ENV_FILE=.env.mock uv run fpcr domains reconcile -d Transit -g anomaly-audit-gw --collect-routes
   FPCR_ENV_FILE=.env.mock uv run fpcr domains reconcile -d WAN_Core -g wan-core-bgp-standby --collect-routes
   ```

3. **REST API (`FPCR_v2`)**:
   - `GET /api/v1/domains/topology/reconcile?domain=Partner_DMZ&cache_mode=cache` (read cached report)
   - `POST /api/v1/domains/topology/reconcile` with `{"domain": "Partner_DMZ", "collect_routes": true}` (trigger live route collection and reconciliation)

### Planted Discrepancies & Diagnostics in the Mock Dataset

Across 315 policy-enforcing gateways, full reconciliation surfaces **13 static diagnostics** and **164 route-vs-static discrepancies**:

| Domain | Gateway | Interface | Code / Discrepancy Type | What It Demonstrates |
| --- | --- | --- | --- | --- |
| `Partner_DMZ` | `partner-b2b-cluster` | `eth1` | `stale_in_topology` | `172.30.2.0/24` in SmartConsole static group, absent in live routes |
| `Partner_DMZ` | `partner-b2b-cluster` | `eth1` | `interface_mismatch` | `172.30.3.0/24` declared on `eth1`, routed via `eth2` in live CLI |
| `Partner_DMZ` | `partner-b2b-cluster` | `eth1` | `missing_in_topology` | `172.30.5.0/24` (OSPF) & `172.30.10.0/24` (connected) missing from SmartConsole |
| `Partner_DMZ` | `partner-b2b-cluster` | `eth2` | `cluster_member_drift` | `172.30.6.0/24` (BGP) present only on `partner-b2b-1a`, missing on `partner-b2b-1b` |
| `Partner_DMZ` | `partner-b2b-cluster` | `eth2` | `resolved_by_routing` | `172.30.4.0/24`, `172.30.6.0/24`, `172.30.20.0/24` on `network defined by routing` |
| `Partner_DMZ` | `partner-onearm-gw-01..10` | `eth0` | `one_arm_topology` (diagnostic) | Single-interface layout relying on external fabric/PBR |
| `Transit` | `anomaly-audit-gw` | `eth0` / `eth5` | `default_route_mismatch` | `eth0` marked external, but live `0.0.0.0/0` egresses via internal `eth5` |
| `Transit` | `anomaly-audit-gw` | `eth2` / `eth3` / `eth4` | `anti_spoofing_detect_or_off`, `not_defined`, `routing_defined_without_routes` | Anti-Spoofing in `detect`, undefined topology, and dynamic routing without routes |
| `Transit` | `ix-transit-gw-02..11` | `eth1` | `missing_in_topology` | `10.81.2.0/24`..`10.81.11.0/24` (`clish` RIP routes) missing from static topology |
| `WAN_Core` | `wan-core-bgp-standby` | `eth2` | `stale_in_topology` | `10.220.0.0/16` static on `eth2`, absent from standby BGP routing table |
| `DC_Spine` | `dc-vsx-spine-vs01` | `wrp0` / `eth1.100` | `stale_in_topology` / `missing_in_topology` | `192.168.250.0/30` stale on `wrp0`; `10.220.0.0/16` BGP missing on `eth1.100` |
| `DC_Pod` | `dc-vs-tier1-web` | `eth2.11` | `missing_in_topology` | Connected `10.216.11.0/24` missing when `eth2.11` uses `specific` network |
| `DB_Seg` | `db-seg-internal-fw-01` | `eth1` | `missing_in_topology` | Connected `10.210.1.0/24` missing when `eth1` uses `specific` group |
| `Branch` | `br-spb-gw-01`, `br-reg-gw-002..140` | `eth2` | `resolved_by_routing` | `10.12.1.0/24`..`10.12.140.0/24` OSPF VoIP subnets resolved via CLI routes |
