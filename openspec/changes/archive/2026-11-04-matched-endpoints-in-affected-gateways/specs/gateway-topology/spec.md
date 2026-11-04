## MODIFIED Requirements

### Requirement: Affected Gateway and Policy Package Candidate Matching

`TopologyService.find_affected_gateways()` SHALL resolve `sources` and `destinations` against each gateway's internal intervals first (longest-prefix match) and external interface second (`0.0.0.0/0` fallback), exclude any gateway where `Source` and `Destination` resolve to the same interface (`src_interface == dst_interface`) or both fall back to `external`, and return affected gateways with their domain, policy packages, `matched_flows`, and input-ordered `matched_sources` and `matched_destinations`.

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
