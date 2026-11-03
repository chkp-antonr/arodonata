# Proposal: Gateway Interface Topology Caching & Affected Gateway / Policy Candidate Matching

## Why

Downstream automation platforms (such as FPCR v2, MMP, and AI agents) need to determine which Check Point gateways, clusters, or VSX Virtual Systems sit along the traffic path between a set of `Source` and `Destination` IPv4 addresses, subnets,ranges, or network objects so they can automatically select or recommend the appropriate `(mgmt_name, domain_name, policy_package)` when provisioning access rules. Following Arodonata's *"Delegate, Never Duplicate"* principle, topology extraction, recursive network-group expansion, VSX static route resolution, database indexing, and candidate gateway matching belong inside `arodonata` as a reusable platform capability rather than being re-implemented in individual consumer applications.

## What Changes

- **Add Extensible Gateway Interface Topology Model & Persistence (`arodonata_gateway_topology`)**:
  - Introduce typed domain models (`GatewayTopologyEntry`, `GatewayInterfaceSummary`, `AffectedGatewayCandidate`, `TrafficFlowMatch`, `TopologySourceType`) in `src/arodonata/core/models/topology.py` and the `GatewayTopologyRecord` SQLModel table (`arodonata_gateway_topology`) in `src/arodonata/adapters/storage/tables.py`.
  - Store pre-expanded IPv4 intervals (`ip_first_int`, `ip_last_int`, `cidr_or_range`, `prefix_len`) per `(mgmt_name, domain_name, gateway_uid, interface_name)` alongside `topology_zone` (`"internal"` or `"external"`), `leads_to_dmz`, and an extensible `source_type` discriminator (`"interface_connected"`, `"interface_specific"`, `"vs_static_route"`, `"external_interface"`, with forward-compatible support for `"gaia_static_route"`, `"clish_route"`, `"bgp_route"`, `"ospf_route"`).
- **Implement Phase 1 Static & API-Based Topology Extraction (`TopologyService`)**:
  - Filter policy-enforcing gateway targets: include `simple-gateway`, `simple-cluster` / `CpmiGatewayCluster`, and VSX Virtual Systems (`virtual-system` / `CpmiVsNetobj` / `CpmiVsClusterNetobj`), while excluding physical VSX hosts (`vsx-gateway` / `vsx-cluster` / `CpmiVsxNetobj` / `CpmiVsxClusterNetobj`, i.e., `VS0`), cluster members (`cluster-member` / `CpmiClusterMember` / `CpmiVsxClusterMember`), and management hosts (`checkpoint-host`, `mds`).
  - Extract interface topology from cached gateway/cluster/VS assets (and on-demand `show-simple-gateway` / `show-simple-cluster` / `show-generic-object` enrichment when `show-gateways-and-servers` omits detailed interface topology):
    1. **External Interfaces (`leads-to-internet: true` or `topology == "external"`)**: Record the interface as an `"external"` default-route zone (`0.0.0.0/0`, *"everything else not behind an internal interface"*).
    2. **Connected Interface Subnets (`"network defined by the interface ip and net mask"`)**: Compute the IPv4 network interval from `ipv4-address` and `ipv4-mask-length` / `ipv4-network-mask` (`source_type="interface_connected"`).
    3. **Specific Network/Group Behind Interface (`"specific"`)**: Resolve `specific-network` / `specific-network-uid` / `specificGroup` against `arodonata_objects` (including `"Global"` fallback) and recursively expand `host`, `network`, `address-range`, and nested `group` members into flat IPv4 intervals (`source_type="interface_specific"`).
    4. **VSX Virtual System Static Routes (`source_type="vs_static_route"`)**: Extract static routes configured on VS objects from Management API generic objects (`CpmiVsSlotObj`, `CpmiVsNetobj`, `CpmiVsClusterNetobj` via `routes` / `routes_installed` / `routing_table`) and bind each destination subnet to the corresponding VS interface (by explicit interface name or by matching the route's next-hop IP against the VS interfaces' connected subnets; a `0.0.0.0/0` route marks that outgoing VS interface as `"external"`).
    5. **Undefined / Dynamic Routing Interfaces (`"network defined by routing"` or `"not defined"`)**: Log a structured warning when no static routes are available for an internal route-defined interface and skip static interval generation for that interface.
- **Enhance VSX Slot Discovery in `VSXRelationshipManager`**:
  - Extend `VSX_GENERIC_OBJECT_CLASSES` in `src/arodonata/core/services/asset_service.py` to also query `com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj` (`vsid == 0`) and `com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj` (`vsid > 0`, matching cross-domain VS assets via `targetCustomer` and `vsxGateway` as well as preserving `interfaces` / `interfaces_installed` and `routes` / `routes_installed` metadata on the VS asset).
- **Implement Affected Gateway & Policy Package Candidate Matching (`find_affected_gateways`)**:
  - Resolve caller-supplied `sources` and `destinations` (accepting IPv4 addresses, CIDRs, IP ranges, or cached Check Point object/group names/UIDs) against each gateway's topology intervals:
    - First match against `"internal"` interfaces (selecting the most specific / longest-prefix match when multiple interfaces match).
    - If an address/subnet does not match any `"internal"` interface of a gateway and the gateway has an `"external"` interface, resolve it to the `"external"` interface (`"external_fallback"`).
    - **Exclusion Invariant**: Discard any gateway where `Source` and `Destination` resolve to the **same** interface (`src_interface == dst_interface`, whether both are behind the same internal interface or both fall back to `external`).
    - Return all affected gateways where `src_interface != dst_interface` (`internal_to_internal`, `internal_to_external`, `external_to_internal`), enriched with `mgmt_name`, `domain_name`, `gateway_id`, `gateway_asset_id`, `parent_asset_id` (for VS on VSX), `installed_access_policy` (from `asset.raw_data["policy"]["access-policy-name"]`), targeted `policy_packages` / `access_layers` (from cached rulebase packages when available), and per-flow interface match evidence.
- **Expose Facade Methods & MCP Tooling**:
  - Expose `refresh_topology`, `stream_refresh_topology`, `get_gateway_topology`, and `find_affected_gateways` on `ArodonataClient` (`src/arodonata/client.py`) and top-level `arodonata` exports.
  - Extend MCP `cache_control` (`scope="topology"`) and register `locate_gateways` in `src/arodonata/mcp/tools.py`.

## Capabilities

### New Capabilities

- `gateway-topology`: Gateway, cluster, and VSX Virtual System interface topology extraction (`interface_connected`, `interface_specific`, `vs_static_route`, and `external_interface`), extensible multi-source persistence in `arodonata_gateway_topology`, and `(source, destination)` candidate gateway, domain, and policy package resolution (`TopologyService`).

### Modified Capabilities

- `cache-and-sync`: Add `arodonata_gateway_topology` to `ARODONATA_TABLE_NAMES` and `CachePort`, support `scope="topology"` synchronization via `DomainSyncCoordinator`, and include `CpmiVsxSlotObj` / `CpmiVsSlotObj` (`targetCustomer` + VS slot interfaces/routes) in `VSXRelationshipManager`.
- `client-and-facade`: Expose `topology_service`, `refresh_topology`, `stream_refresh_topology`, `get_gateway_topology`, and `find_affected_gateways` on `ArodonataClient` and top-level `arodonata` exports.
- `mcp-server`: Support `scope="topology"` in `cache_control` and expose the `locate_gateways` MCP tool for resolving traffic flows (`sources`, `destinations`) to candidate Check Point gateways, domains, and policy packages.

## Impact

- **New Files**:
  - `src/arodonata/core/models/topology.py`
  - `src/arodonata/core/services/topology_service.py`
  - `tests/unit/test_topology_service.py`
- **Updated Files**:
  - `src/arodonata/core/models/common.py` (`SyncScope` extended with `"topology"`)
  - `src/arodonata/core/models/__init__.py`
  - `src/arodonata/core/ports/__init__.py` (`CachePort` topology methods)
  - `src/arodonata/core/services/asset_service.py` (`CpmiVsxSlotObj` / `CpmiVsSlotObj` support)
  - `src/arodonata/core/services/search_service.py` (`get_cache_status` includes `"topology"`)
  - `src/arodonata/core/services/__init__.py`
  - `src/arodonata/adapters/storage/tables.py` (`GatewayTopologyRecord`)
  - `src/arodonata/adapters/storage/database.py` (`ARODONATA_TABLE_NAMES`)
  - `src/arodonata/adapters/storage/cache_adapter.py` (`SqlCacheAdapter` topology CRUD)
  - `src/arodonata/client.py` (`ArodonataClient` topology facade)
  - `src/arodonata/__init__.py`
  - `src/arodonata/mcp/tools.py` & `src/arodonata/mcp/prompts.py`
- **Dependencies**: Zero new external dependencies (uses Python stdlib `ipaddress` and existing SQLModel/SQLAlchemy/Pydantic stack).
