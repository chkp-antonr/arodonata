# Spec Delta: gateway-topology

## ADDED Requirements

### Requirement: VPN Encryption Domain Topology Extraction

During topology extraction, the system SHALL extract each policy-enforcing gateway or cluster `vpn-domain` (`encryption-domain`) reference, recursively expand the referenced network or group object from cached domain and `"Global"` objects into IPv4 intervals with `source_type="vpn_domain"`, and apply the `vpn_encryption_domain` confidence delta when matching endpoints against those intervals.

#### Scenario: Gateway encryption domain group expands into vpn_domain intervals and contributes vpn_encryption_domain confidence

- **WHEN** a gateway or cluster defines `vpn-domain` (or `encryption-domain`) referencing group `"G_VPN_Encryption_Domain"` containing `10.77.1.0/24` and `10.77.2.0/24`, and `refresh_topology` extracts its topology
- **THEN** `arodonata_gateway_topology` SHALL persist `10.77.1.0/24` and `10.77.2.0/24` with `source_type="vpn_domain"`, and `find_affected_gateways` matching an endpoint inside `10.77.1.0/24` SHALL include the `vpn_encryption_domain` (`+0.45`) delta in `confidence_factors`

### Requirement: Policy and NAT Rule Topology Inference and Confidence Evidence

`find_affected_gateways()` SHALL evaluate enabled, non-negated, non-`Any` Access Control and NAT rules in each gateway's installed policy package (honoring `install_on` targets), awarding `+policy_rule_evidence` in `confidence_factors` to cross-interface L3 candidates and, when `include_policy_inferred=True`, returning one-arm or incomplete-topology gateways whose installed rules explicitly cover the queried `sources` and `destinations` with `match_type="policy_inferred"`.

#### Scenario: Cross-interface L3 gateway receives policy_rule_evidence bonus from matching Access or NAT rules

- **WHEN** `find_affected_gateways(sources=["10.10.1.25"], destinations=["10.20.2.50"])` matches a multi-interface L3 gateway whose installed policy package contains an enabled, non-`Any` Access rule or NAT rule (`original` or `translated` source/destination) covering `10.10.1.25` and `10.20.2.50` and targeting that gateway (or `"Policy Targets"`)
- **THEN** the matched flow and `AffectedGatewayCandidate` SHALL include `ConfidenceDelta(code="policy_rule_evidence", delta=0.25, ...)` in `confidence_factors`

#### Scenario: One-arm Cisco ACI service-graph gateway is discovered via installed EPG policy while unrelated one-arm gateways are excluded

- **WHEN** a domain contains 10 one-arm Cisco ACI service-graph gateways (`corp-aci-onearm-01` .. `corp-aci-onearm-10`, each having only a single `external` interface) and only `corp-aci-onearm-03` has an installed policy rule explicitly permitting or translating traffic between `10.160.10.0/24` (EPG-Web) and `10.160.20.0/24` (EPG-App)
- **THEN** `find_affected_gateways(sources=["10.160.10.15"], destinations=["10.160.20.25"], include_policy_inferred=True)` SHALL return `corp-aci-onearm-03` with `match_type="policy_inferred"` and `policy_rule_evidence` in `confidence_factors`, while excluding the remaining 9 one-arm gateways (`corp-aci-onearm-01..02`, `04..10`), and `find_affected_gateways(..., include_policy_inferred=False)` SHALL exclude all 10 one-arm gateways

## MODIFIED Requirements

### Requirement: Extensible Multi-Source Topology Schema

Each persisted `GatewayTopologyEntry` in `arodonata_gateway_topology` SHALL carry a `source_type` discriminator (`"interface_connected"`, `"interface_specific"`, `"vs_static_route"`, `"vpn_domain"`, `"external_interface"`, `"connected_route"`, `"gaia_static_route"`, `"clish_route"`, `"bgp_route"`, `"ospf_route"`, or `"manual"`) and `anti_spoofing_mode` metadata so static Management API definitions, live CLI-collected routing tables, and manual entries coexist without overwriting unrelated source categories during refresh.

#### Scenario: Multiple topology sources coexist per gateway interface

- **WHEN** an interface has both a connected or specific subnet (`source_type="interface_connected"` or `"interface_specific"`), VPN encryption domain intervals (`source_type="vpn_domain"`), and routed subnets (`source_type="vs_static_route"` or `"bgp_route"`), and `refresh_topology(collect_routes=False)` subsequently refreshes static topology
- **THEN** `arodonata_gateway_topology` SHALL store and query all intervals for that `(gateway_uid, interface_name)` while preserving each interval's `source_type`, `source_ref`, and existing CLI-collected route entries

### Requirement: Static Topology vs Live Routing Reconciliation and Cluster Drift Detection

`TopologyService.reconcile_gateway_topology()` SHALL compare SmartConsole static topology intervals against live CLI-collected routing intervals, across cluster members, and optionally against gateway-targeted policy rules (`check_policy=True`), returning a `TopologyReconciliationReport` classifying discrepancies (`stale_in_topology`, `missing_in_topology`, `interface_mismatch`, `default_route_mismatch`, `cluster_member_drift`, `resolved_by_routing`, `policy_topology_mismatch`) while honoring `TopologyAnnotation` dispositions.

#### Scenario: Reconciliation detects stale anti-spoofing subnets, interface mismatches, and cluster member drift

- **WHEN** SmartConsole static topology on Cluster A declares `10.50.0.0/24` and `10.60.0.0/24` behind `eth1` and `10.70.0.0/24` behind `eth2`, while live routing tables show `10.50.0.0/24` routed via `eth1`, `10.60.0.0/24` absent from all interfaces, `10.70.0.0/24` routed via `eth1` (instead of `eth2`), and `10.80.0.0/24` routed via `eth1` on `member-1` only (absent on `member-2`)
- **THEN** `reconcile_gateway_topology()` SHALL report `stale_in_topology` for `10.60.0.0/24` on `eth1`, `interface_mismatch` for `10.70.0.0/24`, `missing_in_topology` and `cluster_member_drift` for `10.80.0.0/24` on `eth1`, and suppress `stale_in_topology` if `10.60.0.0/24` is annotated with `disposition="standby_dynamic"`

#### Scenario: Policy reconciliation flags gateway-targeted rules whose explicit networks are absent from gateway topology and routes

- **WHEN** `reconcile_gateway_topology(..., check_policy=True)` evaluates a gateway with internal topology `10.10.0.0/16` and an enabled Access or NAT rule explicitly targeting that gateway in `install_on` whose explicit (non-`Any`) `source` (`192.168.50.0/24`) and `destination` (`192.168.60.0/24`) both fall outside all internal topology and route intervals of that gateway
- **THEN** `reconcile_gateway_topology()` SHALL emit a `TopologyDiscrepancy` with `discrepancy_type="policy_topology_mismatch"` identifying the gateway, rule, and unmatched networks
