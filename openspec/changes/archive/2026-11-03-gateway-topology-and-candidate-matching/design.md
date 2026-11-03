# Design: Gateway Interface Topology Caching & Affected Gateway / Policy Candidate Matching

## Context

See `proposal.md` for motivation and scope. `arodonata` already collects gateway, cluster, and VSX assets in `AssetRefreshService` (`arodonata_assets`) and caches network hosts, subnets, address ranges, and groups in `ObjectService` (`arodonata_objects`). However, downstream consumers (such as FPCR v2) currently have no way to ask `arodonata`: *"Given these Source and Destination IPs/networks, which Check Point gateways/VSs sit on the path across distinct interfaces, and which Domain and Policy Package enforce policy on each affected gateway?"*

## Goals / Non-Goals

**Goals:**

- Extract, expand, and persist gateway interface topology intervals in `arodonata_gateway_topology` (`GatewayTopologyRecord`) across `simple-gateway`, `simple-cluster` / `CpmiGatewayCluster`, and VSX Virtual Systems (`virtual-system` / `CpmiVsNetobj` / `CpmiVsClusterNetobj`).
- Support all Phase 1 static/API topology sources:
  1. `"interface_connected"` (`"network defined by the interface ip and net mask"`).
  2. `"interface_specific"` (`"specific"` network/group behind interface, recursively expanded via `arodonata_objects` with `"Global"` domain fallback).
  3. `"vs_static_route"` (static routes defined on VSX Virtual Systems in Check Point Management DB via `CpmiVsSlotObj` / `CpmiVsNetobj` / `CpmiVsClusterNetobj` generic objects).
  4. `"external_interface"` (`leads-to-internet: true`, `topology == "external"`, or a `0.0.0.0/0` VS static route).
- Design the persistence model and service architecture with an extensible `source_type` discriminator and pluggable extractor boundary so future CLI/dynamic routing sources (`"gaia_static_route"`, `"clish_route"`, `"bgp_route"`, `"ospf_route"`) drop in without schema or matcher changes.
- Provide `TopologyService.find_affected_gateways()` (and facade/MCP wrappers) returning affected gateways where `Source` and `Destination` resolve to **different** interfaces (`src_interface != dst_interface`), enriched with `domain_name`, `installed_access_policy`, `policy_packages`, and `access_layers`.

**Non-Goals:**

- Querying live gateways over SSH/Clish or Gaia API for BGP/OSPF runtime routing tables in this change (architecturally prepared via `TopologySourceType`, deferred to a subsequent change).
- Building application-specific ticket/rule draft structures (downstream consumers such as FPCR v2 consume `AffectedGatewayCandidate` items from `arodonata` to construct their own workflow models).

## Decisions

### 1. Policy-Enforcing Target Asset Filtering

Not every row in `arodonata_assets` enforces a standalone firewall policy or owns independent routing topology:

- **Included (`POLICY_GATEWAY_TYPES`)**:
  - Single Gateways: `"simple-gateway"`, `"gateway"`, `"CpmiHostCkp"`
  - Gateway Clusters: `"simple-cluster"`, `"cluster"`, `"CpmiGatewayCluster"`
  - VSX Virtual Systems (single & cluster VS): `"virtual-system"`, `"vs-netobj"`, `"CpmiVsNetobj"`, `"CpmiVsClusterNetobj"`
- **Excluded**:
  - Cluster Members (`"cluster-member"`, `"vsx-cluster-member"`, `"CpmiClusterMember"`, `"CpmiVsxClusterMember"`): topology and policy belong to the parent cluster (`CpmiGatewayCluster` / `CpmiVsClusterNetobj`).
  - Physical VSX Hosts (`"vsx-gateway"`, `"vsx-cluster"`, `"CpmiVsxNetobj"`, `"CpmiVsxClusterNetobj"` — i.e., `VS0`): traffic filtering rules are provisioned on individual Virtual Systems (`CpmiVsNetobj` / `CpmiVsClusterNetobj`), not on `VS0`.
  - Management Servers (`"checkpoint-host"`, `"mds"`).

### 2. Multi-Format Check Point Interface Schema Normalization

Check Point Management API returns interface topology in three distinct shapes depending on the endpoint:

1. **`show-gateways-and-servers` (`details-level: "full"`)**:

   ```json
   {
     "interface-name": "eth1",
     "ipv4-address": "10.10.1.1",
     "ipv4-network-mask": "255.255.255.0",
     "ipv4-mask-length": 24,
     "topology": {
       "leads-to-internet": false,
       "ip-address-behind-this-interface": "specific",
       "specific-network": "G_Internal_Nets",
       "specific-network-uid": "...",
       "leads-to-dmz": false
     }
   }
   ```

2. **`show-simple-gateway` / `show-simple-cluster` / `show-interfaces`**:
   - Uses `name` (or `interface-name`), `topology` (`"external" | "internal" | "automatic"`), `topology-automatic-calculation` (`"external" | "internal"`), and `topology-settings` / `topology-settings-automatic` (`ip-address-behind-this-interface`, `specific-network`, `specific-network-uid`, `interface-leads-to-dmz`).
3. **`show-generic-object` / `show-generic-objects` (`CpmiVsSlotObj`, `CpmiVsNetobj`, `CpmiVsClusterNetobj`)**:
   - CPMI interface dictionaries inside `interfaces` or `interfaces_installed` (sometimes wrapped in `{"objects": [...]}` or `owned-object`) using keys `officialname` / `OfficialName` / `iffullname` / `name`, `ipaddr` / `ipv4-address`, `netmask` / `ipv4-network-mask`, and `topology` / `antiSpoofing` (`specificGroup`, `leads-to-internet`, `netaccess`).

`TopologyService._normalize_interface(raw_if)` normalizes all three representations into a single internal structure (`interface_name`, `ipv4_address`, `mask_length`, `is_external`, `leads_to_dmz`, `behind_mode`, `specific_network_ref`).

When a policy-enforcing asset in `arodonata_assets` has an empty `interfaces` list (common on `CpmiGatewayCluster` or `CpmiVsNetobj` in some MDS versions), `TopologyService` performs an on-demand detail call (`show-simple-cluster`, `show-simple-gateway`, or `show-generic-object` with `uid` and `details-level="full"`) and updates the cached `Asset` row so subsequent reads do not repeat the call.

### 3. VSX Slot Reconciliation & Static Route Extraction (`vs_static_route`)

In Check Point MDS environments (verified on `mdsNP2`), VSX Virtual Systems have two special characteristics:

1. **Cross-Domain Slot Objects (`CpmiVsxSlotObj` & `CpmiVsSlotObj`)**:
   - The `CpmiVsNetobj` / `CpmiVsClusterNetobj` object in a tenant domain often carries no direct reference to its parent VSX gateway. Instead, the VSX's domain holds `com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj` (`vsid == 0`, `vsxGateway = <vsx_uid>`) and `com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj` (`vsid > 0`, `targetCustomer = <tenant_domain>`, `name = <vs_name>`, `vsxGateway = <vsx_uid>`).
   - Furthermore, `CpmiVsSlotObj` (and/or `show-generic-object` on `CpmiVsNetobj` / `CpmiVsClusterNetobj`) stores the VS's configured `interfaces` / `interfaces_installed` and static `routes` / `routes_installed` / `routing_table`.
   - `VSXRelationshipManager` will query `CpmiVsxSlotObj` and `CpmiVsSlotObj` alongside `CpmiVsxNetobj`, `CpmiVsxClusterNetobj`, `CpmiVsNetobj`, and `CpmiVsClusterNetobj`, linking cross-domain VS assets via `(targetCustomer, name)` and merging slot `interfaces` and `routes` into the VS asset's `raw_data`.
2. **Mapping VS Static Routes to VS Interfaces**:
   - In VSX, Virtual Systems frequently calculate interface topology from their static routing table (including routes across `wrpj` warp links to Virtual Routers / Virtual Switches).
   - First, `TopologyService` computes the connected IPv4 subnet (`ip/mask`) of every interface on the VS.
   - Next, for each static route entry on the VS (`dest`/`subnet`/`address` + `mask`/`mask-length`, and `nexthop`/`next-hop`/`gateway` or `interface`/`ifname`):
     - Determine the outgoing VS interface:
       - If an explicit `interface` name is present on the route, use it.
       - Otherwise, if a next-hop IPv4 address is present, find the VS interface whose connected subnet contains that next-hop IPv4 address.
     - If the route destination is `0.0.0.0/0` (default route), mark the resolved outgoing VS interface as `topology_zone="external"` (`0.0.0.0/0`, `source_type="vs_static_route"`).
     - Otherwise, emit a `GatewayTopologyEntry` for `(gateway_uid, interface_name)` with the route's destination CIDR, `topology_zone="internal"`, and `source_type="vs_static_route"`.

### 4. Database Table Schema (`arodonata_gateway_topology`)

`GatewayTopologyRecord` in `src/arodonata/adapters/storage/tables.py` (added to `ARODONATA_TABLE_NAMES` so `DatabaseManager` auto-migrates it via `schema_hash`):

- `id: str` (PK): `"{mgmt_name}:{domain_name}:{gateway_uid}:{interface_name}:{source_type}:{cidr_or_range}"`
- `mgmt_name: str` (indexed)
- `domain_name: str` (indexed)
- `gateway_id: str` (indexed): `"{mgmt_name}:{domain_name}:{gateway_uid}"`
- `gateway_asset_id: str` (indexed): `"{mgmt_name}:{domain_name}:{gateway_name}"`
- `gateway_uid: str` (indexed)
- `gateway_name: str` (indexed)
- `gateway_type: str`
- `interface_name: str` (indexed)
- `interface_ipv4: str | None`
- `interface_mask_length: int | None`
- `topology_zone: str` (indexed): `"internal"` | `"external"`
- `leads_to_dmz: bool`
- `source_type: str` (indexed): `"interface_connected"` | `"interface_specific"` | `"vs_static_route"` | `"external_interface"` | `"gaia_static_route"` | `"clish_route"` | `"bgp_route"` | `"ospf_route"`
- `source_ref: str`: originating object/group name, route next-hop, or `"connected"` / `"external"`
- `cidr_or_range: str`: canonical CIDR (e.g. `"10.1.1.0/24"`, `"0.0.0.0/0"`) or range (`"10.1.1.10-10.1.1.20"`)
- `ip_first_int: int` (indexed, 64-bit integer / `BigInteger` for unsigned 32-bit IPv4 bounds `0..4294967295`)
- `ip_last_int: int` (indexed, 64-bit integer / `BigInteger`)
- `prefix_len: int`: `0..32` (for ranges, effective specificity derived from interval span)
- `updated_at: datetime` (naive UTC)

Note on integer column types: IPv4 addresses as unsigned 32-bit integers reach `4,294,967,295` (`255.255.255.255`), which exceeds PostgreSQL signed 32-bit `INTEGER` (`2,147,483,647`). Therefore, `ip_first_int` and `ip_last_int` MUST use `sa.BigInteger()` in `GatewayTopologyRecord` so PostgreSQL and SQLite both handle upper-half IPv4 space (`128.0.0.0`–`255.255.255.255`) without overflow.

### 5. Affected Gateway Matching Algorithm (`find_affected_gateways`)

Given `sources: Sequence[str]` and `destinations: Sequence[str]`:

1. **Input Resolution (`_resolve_endpoint_intervals`)**:
   - Each item in `sources` or `destinations` is classified via `classify_search_term`:
     - `"ipv4"`, `"cidr"`, `"range"` → converted directly to `(lo_int, hi_int, label)`.
     - `"uid"` or `"name"` (or composite `mgmt:domain:name`) → resolved from `arodonata_objects` (expanding `host`, `network`, `address-range`, or recursive `group` members into `(lo_int, hi_int, label)` intervals).
2. **Per-Gateway Interface Resolution (`_locate_interval_on_gateway`)**:
   - For a query interval `(q_lo, q_hi)` and a gateway $G$:
     - Check all `"internal"` topology entries of $G$ that contain or overlap `(q_lo, q_hi)` (`not (entry.ip_last_int < q_lo or entry.ip_first_int > q_hi)`).
     - Prefer full containment (`entry.ip_first_int <= q_lo and q_hi <= entry.ip_last_int`) and smallest interval span `(entry.ip_last_int - entry.ip_first_int)` (longest prefix match).
     - If one or more internal interfaces match, return the best matching internal interface (`topology_zone="internal"`).
     - If **no** internal interface on $G$ matches `(q_lo, q_hi)`:
       - Check whether $G$ has an `"external"` interface (`topology_zone="external"`).
       - If yes, return that external interface (`topology_zone="external"`, `source_type="external_fallback"`, `matched_cidr="0.0.0.0/0"`).
       - If $G$ has no external interface, `(q_lo, q_hi)` is unreachable on $G$ (`None`).
3. **Cross-Interface Filtering & Exclusion Invariant**:
   - For each `(src_interval, dst_interval)` pair on gateway $G$:
     - Resolve `src_match = _locate_interval_on_gateway(src_interval, G)` and `dst_match = _locate_interval_on_gateway(dst_interval, G)`.
     - If either is `None`, skip.
     - **Exclusion Rule**: If `src_match.interface_name == dst_match.interface_name` OR (`src_match.topology_zone == "external"` and `dst_match.topology_zone == "external"`), skip!
       - This single rule eliminates both:
         1. Traffic where `Source` and `Destination` sit behind the **same internal interface** (`eth1 == eth1`).
         2. Unrelated gateways where **neither** `Source` nor `Destination` belongs to any internal interface, so both fall back to `external` (`external == external`).
     - Otherwise, record a `TrafficFlowMatch`:
       - `"internal_to_internal"` when both `src_match` and `dst_match` are `"internal"` on different interfaces (`src_if != dst_if`).
       - `"internal_to_external"` when `src_match` is `"internal"` and `dst_match` is `"external"`.
       - `"external_to_internal"` when `src_match` is `"external"` and `dst_match` is `"internal"`.
4. **Policy Package & Domain Enrichment**:
   - For each affected gateway $G$, `TopologyService` resolves:
     - `mgmt_name` and `domain_name` (from $G$'s `Asset` record — for a cross-domain VS, this is the VS's own tenant domain where its policy package lives, while `parent_asset_id` points to the physical VSX host in the VSX domain).
     - `installed_access_policy`: extracted from `G.raw_data.get("policy", {}).get("access-policy-name")` (or `access_policy_name`).
     - `policy_packages` and `access_layers`: combined from `installed_access_policy` and any cached `RulebasePackageLayerRecord` / `PolicyPackageInfo` in `(mgmt_name, domain_name)` whose `installation-targets` matches $G$'s UID/name (or `"all"`), or all packages in the domain if only one package exists in that domain.
   - Candidates are sorted deterministically: gateways with `"internal_to_internal"` matches first, then `"internal_to_external"` / `"external_to_internal"`, tie-breaking by number of matched flows and `(mgmt_name, domain_name, gateway_name)`.

## Risks / Trade-offs

- **[Risk] Signed 32-bit integer overflow in PostgreSQL for IPv4 addresses $\ge 128.0.0.0$ (`2147483648`–`4294967295`)** → **Mitigation**: Explicitly declare `sa_column=Column(BigInteger, nullable=False, index=True)` on `ip_first_int` and `ip_last_int` in `GatewayTopologyRecord`.
- **[Risk] Circular group memberships when expanding `"specific"` interface groups** → **Mitigation**: Use breadth-first traversal with a `visited_uids: set[str]` guard (matching `SearchService`).
- **[Risk] Missing `interfaces` in `show-gateways-and-servers` summary on some Check Point versions for clusters or VSs** → **Mitigation**: Automatically fall back to `show-simple-cluster`, `show-simple-gateway`, or `show-generic-object` (`details-level="full"`) when a target gateway/cluster/VS has no interfaces in its summary payload, and merge `CpmiVsSlotObj` `interfaces`/`routes` during VSX enrichment.

## Migration Plan

1. Adding `GatewayTopologyRecord` (`arodonata_gateway_topology`) to `tables.py` and `ARODONATA_TABLE_NAMES` automatically changes the computed `schema_hash` in `DatabaseManager.initialize()`, triggering non-destructive creation of `arodonata_gateway_topology` on both SQLite and PostgreSQL without touching existing cached tables or host application tables.
2. No breaking changes to existing `ArodonataClient` or MCP tools.
