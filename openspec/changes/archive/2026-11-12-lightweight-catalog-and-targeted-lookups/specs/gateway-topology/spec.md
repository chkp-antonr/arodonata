# Spec Delta: Gateway Topology and Candidate Matching

## MODIFIED Requirements

### Requirement: Static Interface Topology Extraction and Group Expansion

`TopologyService` SHALL normalize interface definitions across `show-gateways-and-servers`, `show-simple-gateway`, `show-simple-cluster`, and `show-generic-object` payloads, extracting Anti-Spoofing enforcement mode (`"prevent"`, `"detect"`, `"off"`, or `"unknown"`), expanding connected subnets (`"network defined by the interface ip and net mask"`), recursively resolving `"specific"` network/group objects from fresh cached objects or via targeted single-object/group API lookups across the domain and `"Global"` without refreshing full `DEFAULT_OBJECT_TYPES` (`show-hosts`, `show-dns-domains`), recording `"external"` interfaces (`leads-to-internet: true`), and logging a warning on unresolvable route-based interfaces.

#### Scenario: Connected subnet and specific group behind interfaces expand into IPv4 intervals

- **WHEN** a gateway has `eth0` configured with `leads-to-internet: true`, `eth1` (`10.10.1.1/24`) configured with `"network defined by the interface ip and net mask"`, and `eth2` configured with `"specific"` referencing group `"G_App_Subnets"` (which contains a host `10.20.1.5`, a subnet `10.20.2.0/24`, and a nested group with range `10.20.3.10-10.20.3.20`) and Anti-Spoofing action `"prevent"`
- **THEN** `TopologyService` SHALL persist an `"external"` entry (`source_type="external_interface"`, `0.0.0.0/0`) for `eth0`, a connected interval (`10.10.1.0/24`, `source_type="interface_connected"`) for `eth1`, and three expanded intervals (`10.20.1.5/32`, `10.20.2.0/24`, `10.20.3.10-10.20.3.20`, `source_type="interface_specific"`, `anti_spoofing_mode="prevent"`) for `eth2`

#### Scenario: Cold topology refresh resolves specific and VPN domain references on demand without bulk show-hosts

- **WHEN** `refresh_topology` or `stream_refresh_topology` runs on a cold database across domains containing thousands of `host` and `dns-domain` objects, where gateways use connected/external interfaces and a `"specific"` or `vpn-domain` group `"G_App_Subnets"`
- **THEN** the refresh SHALL synchronize gateway assets and resolve `"G_App_Subnets"` and its transitive member UIDs via targeted object/group lookups (persisting resolved objects without marking whole-domain `"host"` or `"group"` slices as fully synced), and SHALL perform zero full-domain `show-hosts` or `show-dns-domains` paginated queries

#### Scenario: Interface with routing-defined or undefined topology logs a warning and is skipped

- **WHEN** a non-external gateway interface has `ip-address-behind-this-interface` set to `"network defined by routing"` (without static route records) or `"not defined"`
- **THEN** `TopologyService` SHALL emit a structured warning log identifying the gateway, domain, interface name, and topology setting, and skip static interval creation for that interface

#### Scenario: On-demand detail fallback when gateway summary lacks interface topology

- **WHEN** a policy-enforcing gateway or cluster in `arodonata_assets` has an empty `interfaces` list or lacks topology settings in its `show-gateways-and-servers` summary
- **THEN** `TopologyService` SHALL query `show-simple-gateway`, `show-simple-cluster`, or `show-generic-object` (`details-level="full"`) for that asset UID to retrieve its complete interface list and topology settings before extracting intervals

### Requirement: Affected Gateway and Policy Package Candidate Matching

`TopologyService.find_affected_gateways()` SHALL resolve `sources` and `destinations` against each gateway's internal intervals first (longest-prefix match) and external interface second (`0.0.0.0/0` fallback), optionally filter evaluated intervals by `source_types` and toggle `TopologyAnnotation` overrides via `include_annotations`, compute delta-based `confidence` scores (`0.0..1.0`) with `confidence_factors` and `is_standby_path` flags, exclude any gateway where `Source` and `Destination` resolve to the same interface (`src_interface == dst_interface`), both fall back to `external`, or fall below `min_confidence`, and return affected gateways with their domain, policy packages, `matched_flows`, and input-ordered `matched_sources` and `matched_destinations`.

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
- **THEN** the returned `AffectedGatewayCandidate` SHALL populate `installed_access_policy="Standard_Policy"`, `policy_packages` with all matching package names, and `access_layers` with the ordered access layer names when the domain's rulebase package catalog or snapshot is cached

#### Scenario: Static-only source_types and disabled annotations filter out live route and manual intervals

- **WHEN** `find_affected_gateways(sources, destinations, source_types=STATIC_TOPOLOGY_SOURCES, include_annotations=False)` runs on a cache containing static interface topology, live `bgp_route` entries, and `manual` annotations
- **THEN** candidate matching SHALL evaluate strictly the intervals matching `source_types` and ignore `TopologyAnnotation` overrides without mutating cached rows
