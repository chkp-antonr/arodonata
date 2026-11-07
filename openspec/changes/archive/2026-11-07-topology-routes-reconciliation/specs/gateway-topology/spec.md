# Gateway Topology Specification Delta

## MODIFIED Requirements

### Requirement: Static Interface Topology Extraction and Group Expansion

`TopologyService` SHALL normalize interface definitions across `show-gateways-and-servers`, `show-simple-gateway`, `show-simple-cluster`, and `show-generic-object` payloads, extracting Anti-Spoofing enforcement mode (`"prevent"`, `"detect"`, `"off"`, or `"unknown"`), expanding connected subnets (`"network defined by the interface ip and net mask"`), recursively resolving `"specific"` network/group objects from `arodonata_objects` (with `"Global"` fallback), recording `"external"` interfaces (`leads-to-internet: true`), and logging a warning on unresolvable route-based interfaces.

#### Scenario: Connected subnet and specific group behind interfaces expand into IPv4 intervals

- **WHEN** a gateway has `eth0` configured with `leads-to-internet: true`, `eth1` (`10.10.1.1/24`) configured with `"network defined by the interface ip and net mask"`, and `eth2` configured with `"specific"` referencing group `"G_App_Subnets"` (which contains a host `10.20.1.5`, a subnet `10.20.2.0/24`, and a nested group with range `10.20.3.10-10.20.3.20`) and Anti-Spoofing action `"prevent"`
- **THEN** `TopologyService` SHALL persist an `"external"` entry (`source_type="external_interface"`, `0.0.0.0/0`) for `eth0`, a connected interval (`10.10.1.0/24`, `source_type="interface_connected"`) for `eth1`, and three expanded intervals (`10.20.1.5/32`, `10.20.2.0/24`, `10.20.3.10-10.20.3.20`, `source_type="interface_specific"`, `anti_spoofing_mode="prevent"`) for `eth2`

#### Scenario: Interface with routing-defined or undefined topology logs a warning and is skipped

- **WHEN** a non-external gateway interface has `ip-address-behind-this-interface` set to `"network defined by routing"` (without static route records) or `"not defined"`
- **THEN** `TopologyService` SHALL emit a structured warning log identifying the gateway, domain, interface name, and topology setting, and skip static interval creation for that interface

#### Scenario: On-demand detail fallback when gateway summary lacks interface topology

- **WHEN** a policy-enforcing gateway or cluster in `arodonata_assets` has an empty `interfaces` list or lacks topology settings in its `show-gateways-and-servers` summary
- **THEN** `TopologyService` SHALL query `show-simple-gateway`, `show-simple-cluster`, or `show-generic-object` (`details-level="full"`) for that asset UID to retrieve its complete interface list and topology settings before extracting intervals

### Requirement: Extensible Multi-Source Topology Schema

Each persisted `GatewayTopologyEntry` in `arodonata_gateway_topology` SHALL carry a `source_type` discriminator (`"interface_connected"`, `"interface_specific"`, `"vs_static_route"`, `"external_interface"`, `"connected_route"`, `"gaia_static_route"`, `"clish_route"`, `"bgp_route"`, `"ospf_route"`, or `"manual"`) and `anti_spoofing_mode` metadata so static Management API definitions, live CLI-collected routing tables, and manual entries coexist without overwriting unrelated source categories during refresh.

#### Scenario: Multiple topology sources coexist per gateway interface

- **WHEN** an interface has both a connected or specific subnet (`source_type="interface_connected"` or `"interface_specific"`) and routed subnets (`source_type="vs_static_route"` or `"bgp_route"`), and `refresh_topology(collect_routes=False)` subsequently refreshes static topology
- **THEN** `arodonata_gateway_topology` SHALL store and query all intervals for that `(gateway_uid, interface_name)` while preserving each interval's `source_type`, `source_ref`, and existing CLI-collected route entries

### Requirement: Affected Gateway and Policy Package Candidate Matching

`TopologyService.find_affected_gateways()` SHALL resolve `sources` and `destinations` against each gateway's internal intervals first (longest-prefix match) and external interface second (`0.0.0.0/0` fallback), apply `TopologyAnnotation` overrides, compute delta-based `confidence` scores (`0.0..1.0`) with `confidence_factors` and `is_standby_path` flags, exclude any gateway where `Source` and `Destination` resolve to the same interface (`src_interface == dst_interface`), both fall back to `external`, or fall below `min_confidence`, and return affected gateways with their domain, policy packages, `matched_flows`, and input-ordered `matched_sources` and `matched_destinations`.

#### Scenario: Traffic between two internal interfaces or between internal and external interfaces matches

- **WHEN** `find_affected_gateways(sources=["10.10.1.25"], destinations=["8.8.8.8"])` runs against Gateway A (`10.10.1.0/24` on `eth1`, `external` on `eth0`, policy `"Perimeter_Pkg"` in domain `"Corp"`), Gateway B (`10.10.1.0/24` on `bond0.10`, `8.8.8.0/24` on `bond0.20`, policy `"Core_Pkg"` in domain `"DC"`), and Gateway C (`192.168.1.0/24` on `eth1`, `external` on `eth0`)
- **THEN** it SHALL return Gateway B (`match_type="internal_to_internal"`, `bond0.10 -> bond0.20`, domain `"DC"`, package `"Core_Pkg"`, `matched_sources=["10.10.1.25"]`, `matched_destinations=["8.8.8.8"]`) and Gateway A (`match_type="internal_to_external"`, `eth1 -> eth0`, domain `"Corp"`, package `"Perimeter_Pkg"`, `matched_sources=["10.10.1.25"]`, `matched_destinations=["8.8.8.8"]`), and exclude Gateway C because both `10.10.1.25` and `8.8.8.8` fall back to Gateway C's `eth0` (`external == external`)

#### Scenario: Traffic where both source and destination sit behind the same internal interface is excluded

- **WHEN** `find_affected_gateways(sources=["10.10.1.10"], destinations=["10.10.1.99"])` runs against a gateway where both addresses match `10.10.1.0/24` on `eth1`
- **THEN** that gateway SHALL be excluded from the returned candidates because `src_interface == dst_interface == "eth1"`

#### Scenario: Multi-gateway and transit topology filters matched_sources and matched_destinations per gateway in input order

- **WHEN** `find_affected_gateways(sources, destinations)` runs with multiple sources and destinations across a 4-gateway topology (`GW1` and `GW2` serving distinct source branches, `GW3` acting as a transit gateway with upstream branch networks on one interface, its own local subnets on another interface, and downstream networks on a third interface, plus `GW4` behind `GW3`)
- **THEN** each returned `AffectedGatewayCandidate` SHALL populate `matched_sources` and `matched_destinations` with only the unique `source_query` and `destination_query` strings present in that gateway's cross-interface `matched_flows`, strictly preserving the caller's input order from `sources` and `destinations`, and excluding any gateway where all pairs resolve to the same interface (`src_interface == dst_interface`) or `external == external`

#### Scenario: Policy package resolution combines asset policy metadata and rulebase installation targets

- **WHEN** an affected gateway has `raw_data["policy"]["access-policy-name"] = "Standard_Policy"` and/or is listed in `installation-targets` of a cached `PolicyPackageInfo` in `arodonata_rulebase_package_layer`
- **THEN** the returned `AffectedGatewayCandidate` SHALL populate `installed_access_policy="Standard_Policy"`, `policy_packages` with all matching package names, and `access_layers` with the ordered access layer names when the domain's rulebase snapshot is cached

## ADDED Requirements

### Requirement: Static Topology Health Diagnostics and One-Arm Classification

`TopologyService.get_topology_diagnostics()` SHALL inspect policy-enforcing gateways and interfaces to report completeness and trust diagnostics (`not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`, `unresolved_specific`, `empty_specific`, `missing_ip_mask`, `no_interfaces`), while treating internal-only gateways as valid and classifying single-interface or external-only gateways as `one_arm_topology` (`severity="info"`).

#### Scenario: Diagnostics report incomplete interfaces and Detect-mode anti-spoofing without false positives on internal-only or one-arm gateways

- **WHEN** `get_topology_diagnostics()` evaluates Gateway 1 (`eth1` with `not defined`, `eth2` with `network defined by routing` and no cached routes, `eth3` with `specific` group and Anti-Spoofing set to `Detect`), Gateway 2 (an internal segmentation firewall with `eth1` and `eth2` internal subnets and no `external` interface), and Gateway 3 (a single-interface `one_arm` gateway)
- **THEN** it SHALL emit warning diagnostics for Gateway 1's `eth1` (`not_defined`), `eth2` (`routing_defined_without_routes`), and `eth3` (`anti_spoofing_detect_or_off`), emit zero warnings for Gateway 2, and report Gateway 3 with `code="one_arm_topology"` at `severity="info"`

### Requirement: Live Gateway Route Collection via SSH Dependency Injection and CPRID Fallback

`TopologyService.collect_gateway_routes()` SHALL collect live IPv4 routing tables (`connected_route`, `gaia_static_route`, `clish_route`, `bgp_route`, `ospf_route`, and `0.0.0.0/0` default routes) by invoking an injected `GatewayCliPort` (or async SSH callback in bash) first, and falling back to Check Point Management API `run-script` (`cprid` via `TaskWaiter`) when no SSH executor is provided or when SSH execution fails and `fallback_to_cprid=True`.

#### Scenario: Cluster and VSX Virtual System route collection via SSH DI and vsenv context switching

- **WHEN** `collect_gateway_routes()` runs for a `CpmiGatewayCluster` (with two `cluster-member` nodes) and a VSX `CpmiVsNetobj` (`vsid=3` hosted on physical parent `VSX-GW-01`)
- **THEN** it SHALL resolve the cluster to its `cluster-member` node targets and resolve the Virtual System to `VSX-GW-01` (`vsid=3`), executing a bash script that switches context via `vsenv "$vsid" >/dev/null 2>&1 </dev/null`, verifies `$FWDIR` contains `CTX00003`, and runs `ip -4 route show </dev/null` to persist normalized route intervals in `arodonata_gateway_topology`

#### Scenario: Automatic fallback from SSH callback to Management API run-script

- **WHEN** a host application provides an SSH `gateway_cli` callback that raises a connection error for a remote branch gateway while `fallback_to_cprid=True`
- **THEN** `TopologyService` SHALL execute the route collection script on that gateway via Management API `run-script`, wait for the task via `TaskWaiter`, decode the Base64 output from `task-details[].responseMessage`, and parse the resulting routes

### Requirement: Targeted Per-Gateway Topology and Route Refresh

`TopologyService.refresh_topology()` and `TopologyService.collect_gateway_routes()` SHALL accept an optional `gateways: Sequence[str] | None` filter (matching gateway UID, name, `id`, or `asset_id`) that refreshes and replaces cached topology and route intervals strictly for the specified gateways without re-querying or deleting cached topology rows for other gateways in the domain.

#### Scenario: Refreshing a single modified gateway in a large domain preserves other gateways

- **WHEN** an administrator updates topology or routing on `"gw-branch-42"` and calls `refresh_topology(mgmt_name="mds1", domains=["Corp"], gateways=["gw-branch-42"], collect_routes=True, mode="force")`
- **THEN** `TopologyService` SHALL query Management API gateway details and collect live routes only for `"gw-branch-42"`, atomically replacing only `"gw-branch-42"` rows in `arodonata_gateway_topology` while leaving all other gateways in `"Corp"` untouched

### Requirement: Static Topology vs Live Routing Reconciliation and Cluster Drift Detection

`TopologyService.reconcile_gateway_topology()` SHALL compare SmartConsole static topology intervals against live CLI-collected routing intervals and across cluster members for each gateway, returning a `TopologyReconciliationReport` classifying discrepancies (`stale_in_topology`, `missing_in_topology`, `interface_mismatch`, `default_route_mismatch`, `cluster_member_drift`, `resolved_by_routing`) while honoring `TopologyAnnotation` dispositions.

#### Scenario: Reconciliation detects stale anti-spoofing subnets, interface mismatches, and cluster member drift

- **WHEN** SmartConsole static topology on Cluster A declares `10.50.0.0/24` and `10.60.0.0/24` behind `eth1` and `10.70.0.0/24` behind `eth2`, while live routing tables show `10.50.0.0/24` routed via `eth1`, `10.60.0.0/24` absent from all interfaces, `10.70.0.0/24` routed via `eth1` (instead of `eth2`), and `10.80.0.0/24` routed via `eth1` on `member-1` only (absent on `member-2`)
- **THEN** `reconcile_gateway_topology()` SHALL report `stale_in_topology` for `10.60.0.0/24` on `eth1`, `interface_mismatch` for `10.70.0.0/24`, `missing_in_topology` and `cluster_member_drift` for `10.80.0.0/24` on `eth1`, and suppress `stale_in_topology` if `10.60.0.0/24` is annotated with `disposition="standby_dynamic"`

### Requirement: Persistent Administrator Topology Annotations and IPAM Prefix Export

The cache layer SHALL persist `TopologyAnnotation` records in `arodonata_topology_annotations` across topology refreshes, supporting gateway/interface-level `trust_static_topology` overrides, prefix-level dispositions (`"confirmed"`, `"standby_dynamic"`, `"ignore"`, `"manual"`), and IPAM enrichment fields (`zone`, `site`, `comment`, `custom_metadata`), and `TopologyService.export_topology_prefixes()` SHALL export the annotated prefix inventory.

#### Scenario: Annotations survive topology refresh and enrich IPAM prefix export

- **WHEN** an administrator saves a `TopologyAnnotation` marking `10.90.0.0/24` on `gw1:eth1` as `disposition="standby_dynamic"`, `zone="DMZ-Partner"`, `site="Branch-SPB"`, `comment="Backup BGP path"`, and marks `10.99.0.0/24` as `disposition="ignore"`, followed by `refresh_topology(mode="force")` and `export_topology_prefixes()`
- **THEN** the annotations SHALL remain intact after `refresh_topology`, `10.99.0.0/24` SHALL be excluded from active candidate matching, and `export_topology_prefixes()` SHALL include `10.90.0.0/24` with `zone="DMZ-Partner"`, `site="Branch-SPB"`, `comment="Backup BGP path"`, and `disposition="standby_dynamic"`

### Requirement: Extensible Evidence Delta Confidence Scoring

`TopologyService` SHALL compute endpoint and flow confidence in `[0.0, 1.0]` by summing configurable signed evidence deltas (`TopologyConfidenceWeights` for positive route, static topology, annotation, and policy/VPN/bridge hooks, minus conflict penalties) and attaching `confidence`, `is_standby_path`, and `confidence_factors` (`list[ConfidenceDelta]`) to each `TrafficFlowMatch` and `AffectedGatewayCandidate`.

#### Scenario: Delta confidence reflects route agreement, detect-only anti-spoofing, conflicts, and standby annotations

- **WHEN** `find_affected_gateways()` evaluates flows across interfaces with (a) matching live route + SmartConsole `Prevent` topology, (b) live route on `eth1` conflicting with mismatched SmartConsole static topology on `eth2`, and (c) a subnet present only in SmartConsole topology and annotated as `standby_dynamic`
- **THEN** case (a) SHALL clamp to `confidence=1.0`, case (b) SHALL yield a high but penalized confidence (rising when static topology is marked `trust_static_topology=False`), and case (c) SHALL set `is_standby_path=True` with the `admin_standby_dynamic` delta recorded in `confidence_factors`
