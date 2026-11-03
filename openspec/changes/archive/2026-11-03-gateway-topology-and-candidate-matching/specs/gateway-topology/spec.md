# Gateway Topology and Candidate Matching Specification

## ADDED Requirements

### Requirement: Policy-Enforcing Gateway Target Selection

`TopologyService` SHALL extract and index interface topology only for policy-enforcing gateway assets (`simple-gateway`, `simple-cluster`, `CpmiGatewayCluster`, `virtual-system`, `CpmiVsNetobj`, and `CpmiVsClusterNetobj`), skipping cluster members (`cluster-member`, `CpmiClusterMember`, `CpmiVsxClusterMember`), physical VSX containers (`vsx-gateway`, `vsx-cluster`, `CpmiVsxNetobj`, `CpmiVsxClusterNetobj`), and management servers (`checkpoint-host`, `mds`).

#### Scenario: Cluster topology is derived from the cluster object while members and VSX hosts are skipped

- **WHEN** `refresh_topology` processes a domain containing a `CpmiGatewayCluster`, its `cluster-member` nodes, a `CpmiVsxNetobj` physical host (`VS0`), and a `CpmiVsNetobj` Virtual System
- **THEN** `TopologyService` SHALL build topology entries only for the `CpmiGatewayCluster` and the `CpmiVsNetobj` Virtual System, emitting zero topology rows for `cluster-member` or `CpmiVsxNetobj` assets

### Requirement: Static Interface Topology Extraction and Group Expansion

`TopologyService` SHALL normalize interface definitions across `show-gateways-and-servers`, `show-simple-gateway`, `show-simple-cluster`, and `show-generic-object` payloads, expanding connected subnets (`"network defined by the interface ip and net mask"`), recursively resolving `"specific"` network/group objects from `arodonata_objects` (with `"Global"` fallback), recording `"external"` interfaces (`leads-to-internet: true`), and logging a warning on unresolvable route-based interfaces.

#### Scenario: Connected subnet and specific group behind interfaces expand into IPv4 intervals

- **WHEN** a gateway has `eth0` configured with `leads-to-internet: true`, `eth1` (`10.10.1.1/24`) configured with `"network defined by the interface ip and net mask"`, and `eth2` configured with `"specific"` referencing group `"G_App_Subnets"` (which contains a host `10.20.1.5`, a subnet `10.20.2.0/24`, and a nested group with range `10.20.3.10-10.20.3.20`)
- **THEN** `TopologyService` SHALL persist an `"external"` entry (`source_type="external_interface"`, `0.0.0.0/0`) for `eth0`, a connected interval (`10.10.1.0/24`, `source_type="interface_connected"`) for `eth1`, and three expanded intervals (`10.20.1.5/32`, `10.20.2.0/24`, `10.20.3.10-10.20.3.20`, `source_type="interface_specific"`) for `eth2`

#### Scenario: Interface with routing-defined or undefined topology logs a warning and is skipped

- **WHEN** a non-external gateway interface has `ip-address-behind-this-interface` set to `"network defined by routing"` (without static route records) or `"not defined"`
- **THEN** `TopologyService` SHALL emit a structured warning log identifying the gateway, domain, interface name, and topology setting, and skip static interval creation for that interface

#### Scenario: On-demand detail fallback when gateway summary lacks interface topology

- **WHEN** a policy-enforcing gateway or cluster in `arodonata_assets` has an empty `interfaces` list or lacks topology settings in its `show-gateways-and-servers` summary
- **THEN** `TopologyService` SHALL query `show-simple-gateway`, `show-simple-cluster`, or `show-generic-object` (`details-level="full"`) for that asset UID to retrieve its complete interface list and topology settings before extracting intervals

### Requirement: VSX Virtual System Static Route Topology Resolution

For VSX Virtual Systems (`virtual-system`, `CpmiVsNetobj`, `CpmiVsClusterNetobj`), `TopologyService` SHALL extract static routes from Check Point Management API generic objects (`CpmiVsSlotObj`, `CpmiVsNetobj`, `CpmiVsClusterNetobj` via `routes`, `routes_installed`, or `routing_table`) and associate each routed destination network with the corresponding VS interface (`source_type="vs_static_route"`).

#### Scenario: VS static route next-hop IP resolves to the matching VS connected interface

- **WHEN** a Virtual System has interface `wrp128` (`192.168.100.2/30`), interface `eth1.50` (`10.50.0.1/24`), a static route for `172.16.80.0/24` with next-hop `10.50.0.254`, and a default route `0.0.0.0/0` with next-hop `192.168.100.1`
- **THEN** `TopologyService` SHALL bind `172.16.80.0/24` to interface `eth1.50` with `source_type="vs_static_route"` and `topology_zone="internal"`, and mark `wrp128` as an `"external"` interface (`source_type="vs_static_route"`, `0.0.0.0/0`)

### Requirement: Extensible Multi-Source Topology Schema

Each persisted `GatewayTopologyEntry` in `arodonata_gateway_topology` SHALL carry a `source_type` discriminator (`"interface_connected"`, `"interface_specific"`, `"vs_static_route"`, `"external_interface"`, `"gaia_static_route"`, `"clish_route"`, `"bgp_route"`, or `"ospf_route"`) so future dynamic or CLI-collected routing providers can store intervals in the same table and participate in candidate matching without schema changes.

#### Scenario: Multiple topology sources coexist per gateway interface

- **WHEN** an interface has both a connected subnet (`source_type="interface_connected"`) and routed subnets (`source_type="vs_static_route"` or `"bgp_route"`)
- **THEN** `arodonata_gateway_topology` SHALL store and query all intervals for that `(gateway_uid, interface_name)` while preserving each interval's `source_type` and `source_ref`

### Requirement: Affected Gateway and Policy Package Candidate Matching

`TopologyService.find_affected_gateways()` SHALL resolve `sources` and `destinations` (IPv4 addresses, CIDRs, ranges, or cached object/group names) against each gateway's internal intervals first (longest-prefix match) and external interface second (`0.0.0.0/0` fallback), exclude any gateway where `Source` and `Destination` resolve to the same interface (`src_interface == dst_interface`), and return affected gateways with their domain and policy packages.

#### Scenario: Traffic between two internal interfaces or between internal and external interfaces matches

- **WHEN** `find_affected_gateways(sources=["10.10.1.25"], destinations=["8.8.8.8"])` runs against Gateway A (`10.10.1.0/24` on `eth1`, `external` on `eth0`, policy `"Perimeter_Pkg"` in domain `"Corp"`), Gateway B (`10.10.1.0/24` on `bond0.10`, `8.8.8.0/24` on `bond0.20`, policy `"Core_Pkg"` in domain `"DC"`), and Gateway C (`192.168.1.0/24` on `eth1`, `external` on `eth0`)
- **THEN** it SHALL return Gateway B (`match_type="internal_to_internal"`, `bond0.10 -> bond0.20`, domain `"DC"`, package `"Core_Pkg"`) and Gateway A (`match_type="internal_to_external"`, `eth1 -> eth0`, domain `"Corp"`, package `"Perimeter_Pkg"`), and exclude Gateway C because both `10.10.1.25` and `8.8.8.8` fall back to Gateway C's `eth0` (`external == external`)

#### Scenario: Traffic where both source and destination sit behind the same internal interface is excluded

- **WHEN** `find_affected_gateways(sources=["10.10.1.10"], destinations=["10.10.1.99"])` runs against a gateway where both addresses match `10.10.1.0/24` on `eth1`
- **THEN** that gateway SHALL be excluded from the returned candidates because `src_interface == dst_interface == "eth1"`

#### Scenario: Policy package resolution combines asset policy metadata and rulebase installation targets

- **WHEN** an affected gateway has `raw_data["policy"]["access-policy-name"] = "Standard_Policy"` and/or is listed in `installation-targets` of a cached `PolicyPackageInfo` in `arodonata_rulebase_package_layer`
- **THEN** the returned `AffectedGatewayCandidate` SHALL populate `installed_access_policy="Standard_Policy"`, `policy_packages` with all matching package names, and `access_layers` with the ordered access layer names when the domain's rulebase snapshot is cached
