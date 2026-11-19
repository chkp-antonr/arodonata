# Gateway Topology and Candidate Matching Specification

## Purpose

Defines Check Point gateway interface topology extraction (`TopologyService`), static and live CLI route resolution into `arodonata_gateway_topology`, health diagnostics and live-route reconciliation (`get_topology_diagnostics`, `reconcile_gateway_topology`), persistent administrator annotations (`arodonata_topology_annotations`), delta-based confidence scoring, and affected gateway / policy package candidate matching (`find_affected_gateways`) across simple gateways, clusters, and VSX Virtual Systems.

## Requirements

### Requirement: Extensible Multi-Source Topology Schema

**ID**: REQ-TOPO-001\
**Intent**: Allow static API definitions, VPN domains, live CLI routes, and manual prefixes to coexist safely without clobbering unrelated sources on refresh.\
**Non-goals**: Extracting individual interface or route sources (`REQ-TOPO-003`..`REQ-TOPO-007`).

Each persisted `GatewayTopologyEntry` in `arodonata_gateway_topology` SHALL carry a `source_type` discriminator (covering static API definitions, VPN encryption domains, live CLI routes, and manual entries) and `anti_spoofing_mode` metadata so distinct topology sources coexist without overwriting unrelated categories during refresh.

#### Scenario: SCN-TOPO-001-1 — Multiple topology sources coexist per gateway interface

- **GIVEN** an interface storing static intervals (`"interface_connected"`, `"interface_specific"`, `"external_interface"`), `"vpn_domain"`, `"vs_static_route"`, or `"manual"` entries
- **AND** CLI-collected route intervals (`"connected_route"`, `"gaia_static_route"`, `"clish_route"`, `"bgp_route"`, `"ospf_route"`)
- **WHEN** `refresh_topology(collect_routes=False)` refreshes static topology
- **THEN** `arodonata_gateway_topology` SHALL preserve and query all intervals for `(gateway_uid, interface_name)` with each interval's `source_type`, `source_ref`, and `anti_spoofing_mode`
- **AND** existing CLI-collected route and `"manual"` entries SHALL remain intact

### Requirement: Policy-Enforcing Gateway Target Selection

**ID**: REQ-TOPO-002\
**Intent**: Index topology strictly for policy-enforcing gateways, clusters, and Virtual Systems rather than cluster members or physical VSX hosts.\
**Non-goals**: Routing CLI target expansion to cluster members and VSX hosts (`REQ-TOPO-007`).

`TopologyService` SHALL index topology only for policy-enforcing gateway assets (`simple-gateway`, `simple-cluster`, `CpmiGatewayCluster`, `virtual-system`, `CpmiVsNetobj`, `CpmiVsClusterNetobj`), skipping cluster members (`cluster-member`, `CpmiClusterMember`, `CpmiVsxClusterMember`), physical VSX hosts (`vsx-gateway`, `vsx-cluster`, `CpmiVsxNetobj`, `CpmiVsxClusterNetobj`), and management servers (`checkpoint-host`, `mds`).

#### Scenario: SCN-TOPO-002-1 — Cluster topology is derived from the cluster object while members and VSX hosts are skipped

- **GIVEN** a domain containing a `CpmiGatewayCluster`, its `cluster-member` nodes, a `CpmiVsxNetobj` physical host (`VS0`), and a `CpmiVsNetobj` Virtual System
- **WHEN** `refresh_topology` processes the domain
- **THEN** `TopologyService` SHALL build topology entries only for the `CpmiGatewayCluster` and the `CpmiVsNetobj` Virtual System
- **AND** it SHALL emit zero topology rows for `cluster-member` or `CpmiVsxNetobj` assets

### Requirement: Static Interface Topology Extraction and Detail Fallback

**ID**: REQ-TOPO-003\
**Intent**: Extract normalized IPv4 intervals and Anti-Spoofing modes from Check Point gateway interface definitions with on-demand detail fallback.\
**Non-goals**: Specific-group object resolution without bulk scans (`REQ-TOPO-004`) or VPN domain expansion (`REQ-TOPO-005`).

`TopologyService` SHALL normalize interface definitions across `show-gateways-and-servers`, `show-simple-gateway`, `show-simple-cluster`, and `show-generic-object` payloads, extracting Anti-Spoofing (`"prevent"`, `"detect"`, `"off"`, `"unknown"`), connected subnets (`"network defined by the interface ip and net mask"`), `"external"` interfaces (`leads-to-internet: true`), and logging a warning on unresolvable route-based or undefined interfaces.

#### Scenario: SCN-TOPO-003-1 — Connected subnet and specific group behind interfaces expand into IPv4 intervals

- **GIVEN** a gateway with `eth0` (`leads-to-internet: true`) and `eth1` (`10.10.1.1/24`, `"network defined by the interface ip and net mask"`)
- **AND** `eth2` configured with `"specific"` group `"G_App_Subnets"` (`10.20.1.5`, `10.20.2.0/24`, nested `10.20.3.10-10.20.3.20`) and Anti-Spoofing `"prevent"`
- **WHEN** `TopologyService` extracts interface topology
- **THEN** it SHALL persist `"external"` (`source_type="external_interface"`, `0.0.0.0/0`) for `eth0` and `10.10.1.0/24` (`source_type="interface_connected"`) for `eth1`
- **AND** it SHALL persist three expanded intervals (`10.20.1.5/32`, `10.20.2.0/24`, `10.20.3.10-10.20.3.20`) with `source_type="interface_specific"` and `anti_spoofing_mode="prevent"` for `eth2`

#### Scenario: SCN-TOPO-003-2 — Interface with routing-defined or undefined topology logs a warning and is skipped

- **WHEN** a non-external gateway interface has `ip-address-behind-this-interface` set to `"network defined by routing"` (without static route records) or `"not defined"`
- **THEN** `TopologyService` SHALL emit a structured warning log identifying the gateway, domain, interface name, and topology setting
- **AND** it SHALL skip static interval creation for that interface

#### Scenario: SCN-TOPO-003-3 — On-demand detail fallback when gateway summary lacks interface topology

- **GIVEN** a policy-enforcing gateway or cluster in `arodonata_assets` whose `show-gateways-and-servers` summary lacks `interfaces` or topology settings
- **WHEN** `TopologyService` extracts topology for that asset
- **THEN** it SHALL query `show-simple-gateway`, `show-simple-cluster`, or `show-generic-object` (`details-level="full"`) for that UID before extracting intervals

### Requirement: On-Demand Specific Group Expansion Without Bulk Object Scans

**ID**: REQ-TOPO-004\
**Intent**: Keep cold topology refreshes fast in large domains by resolving referenced groups and objects on demand without downloading all hosts.\
**Non-goals**: Full domain object cache synchronization (`REQ-CACHE-005`).

`TopologyService` SHALL recursively resolve `"specific"` network and group objects behind gateway interfaces across the domain and `"Global"` using fresh cached objects or targeted single-object/group API lookups, without triggering bulk default-object-type refreshes (`show-hosts`, `show-dns-domains`) or falsely stamping whole-domain object slices as synced.

#### Scenario: SCN-TOPO-004-1 — Cold topology refresh resolves specific and VPN domain references on demand without bulk show-hosts

- **GIVEN** a cold database on domains holding thousands of `host` and `dns-domain` objects where gateways reference a `"specific"` or `vpn-domain` group `"G_App_Subnets"`
- **WHEN** `refresh_topology` or `stream_refresh_topology` runs
- **THEN** it SHALL synchronize gateway assets and resolve `"G_App_Subnets"` and transitive member UIDs via targeted object/group lookups
- **AND** it SHALL persist resolved objects without marking whole-domain `"host"` or `"group"` slices as fully synced
- **AND** it SHALL execute zero full-domain `show-hosts` or `show-dns-domains` paginated queries

### Requirement: VPN Encryption Domain Topology Extraction

**ID**: REQ-TOPO-005\
**Intent**: Include Check Point gateway VPN encryption domains in topology intervals and candidate confidence scoring.\
**Non-goals**: Specific interface behind-IP topology (`REQ-TOPO-003`) or evidence-delta weights (`REQ-TOPO-013`).

During topology extraction, the system SHALL extract each policy-enforcing gateway or cluster `vpn-domain` (`encryption-domain`) reference, recursively expand the referenced network or group object from cached domain and `"Global"` objects into IPv4 intervals with `source_type="vpn_domain"`, and apply the `vpn_encryption_domain` confidence delta when matching endpoints against those intervals.

#### Scenario: SCN-TOPO-005-1 — Gateway encryption domain group expands into vpn_domain intervals and contributes vpn_encryption_domain confidence

- **GIVEN** a gateway or cluster whose `vpn-domain` (`encryption-domain`) references group `"G_VPN_Encryption_Domain"` (`10.77.1.0/24`, `10.77.2.0/24`)
- **WHEN** `refresh_topology` extracts topology and `find_affected_gateways` matches an endpoint in `10.77.1.0/24`
- **THEN** `arodonata_gateway_topology` SHALL persist `10.77.1.0/24` and `10.77.2.0/24` with `source_type="vpn_domain"`
- **AND** `confidence_factors` on the match SHALL include the `vpn_encryption_domain` (`+0.45`) delta

### Requirement: VSX Virtual System Static Route Topology Resolution

**ID**: REQ-TOPO-006\
**Intent**: Map Check Point Management API VSX static routes onto the corresponding Virtual System interface intervals.\
**Non-goals**: VSX slot relationship linking (`REQ-CACHE-010`) or live CLI route collection (`REQ-TOPO-007`).

For VSX Virtual Systems (`virtual-system`, `CpmiVsNetobj`, `CpmiVsClusterNetobj`), `TopologyService` SHALL extract static routes from Check Point Management API generic objects (`CpmiVsSlotObj`, `CpmiVsNetobj`, `CpmiVsClusterNetobj` via `routes`, `routes_installed`, or `routing_table`) and associate each routed destination network with the corresponding VS interface (`source_type="vs_static_route"`).

#### Scenario: SCN-TOPO-006-1 — VS static route next-hop IP resolves to the matching VS connected interface

- **GIVEN** a Virtual System with `wrp128` (`192.168.100.2/30`), `eth1.50` (`10.50.0.1/24`), static route `172.16.80.0/24` via `10.50.0.254`, and default route `0.0.0.0/0` via `192.168.100.1`
- **WHEN** `TopologyService` resolves VS static routes
- **THEN** it SHALL bind `172.16.80.0/24` to `eth1.50` with `source_type="vs_static_route"` and `topology_zone="internal"`
- **AND** it SHALL mark `wrp128` as an `"external"` interface (`source_type="vs_static_route"`, `0.0.0.0/0`)

### Requirement: Live Gateway Route Collection via SSH Dependency Injection and CPRID Fallback

**ID**: REQ-TOPO-007\
**Intent**: Collect live gateway routing tables safely via injected SSH or `cprid` fallback with VSX context checks and route-scale protection.\
**Non-goals**: CPRID script mode selection (`REQ-TOPO-008`) or targeted gateway filtering (`REQ-TOPO-009`).

`TopologyService.collect_gateway_routes()` SHALL collect live IPv4 routing tables (`connected_route`, `gaia_static_route`, `clish_route`, `bgp_route`, `ospf_route`, and `0.0.0.0/0` default routes) via an injected `GatewayCliPort` (or async SSH bash callback) first, falling back to Management API `run-script` (`cprid` with `show-task` polling) when absent or failing under `fallback_to_cprid=True`.

#### Scenario: SCN-TOPO-007-1 — Cluster and VSX Virtual System route collection via SSH DI and vsenv context switching

- **WHEN** `collect_gateway_routes()` runs for a `CpmiGatewayCluster` (two `cluster-member` nodes) and a VSX `CpmiVsNetobj` (`vsid=3` on `VSX-GW-01`)
- **THEN** it SHALL resolve the cluster to its `cluster-member` targets and the Virtual System to `VSX-GW-01` (`vsid=3`)
- **AND** the executed script SHALL switch context via `vsenv "$vsid" >/dev/null 2>&1 </dev/null`, verify `$FWDIR` contains `CTX00003`, and run `ip -4 route show </dev/null`
- **AND** parsed route intervals SHALL be persisted in `arodonata_gateway_topology`

#### Scenario: SCN-TOPO-007-2 — Automatic fallback from SSH callback to Management API run-script

- **GIVEN** an injected SSH `gateway_cli` callback that raises a connection error for a remote gateway while `fallback_to_cprid=True`
- **WHEN** `collect_gateway_routes()` runs
- **THEN** `TopologyService` SHALL run the route collection script via Management API `run-script`, poll `show-task`, Base64-decode `task-details[].responseMessage`, and parse the routes

#### Scenario: SCN-TOPO-007-3 — Per-physical-node VSX serialization, MDS concurrency cap, and single-flight route collection

- **WHEN** `collect_gateway_routes()` runs across multiple Virtual Systems sharing `VS0` alongside independent gateways, or when identical calls overlap concurrently
- **THEN** CLI/`cprid` execution SHALL be serialized per physical `node_uid` on `VS0` without blocking independent gateways up to `route_collect_concurrency`
- **AND** identical concurrent calls SHALL coalesce into a single in-flight collection

#### Scenario: SCN-TOPO-007-4 — Large routing table cap and clish bypass protect gateways holding BGP full-view tables

- **WHEN** `collect_gateway_routes()` runs on a gateway exceeding `max_routes_per_gateway` (or `10000` kernel routes for `clish`)
- **THEN** the collection script SHALL skip `clish -c "show route"` when kernel routes exceed `10000` lines
- **AND** collected routes SHALL be truncated at `max_routes_per_gateway` with a warning recorded in `GatewayRouteCollectionStatus.warnings`

### Requirement: CPRID Script Execution Modes for Route Collection

**ID**: REQ-TOPO-008\
**Intent**: Support pre-approved repository scripts, inline scripts, and automatic fallback when collecting gateway routes via `run-script`.\
**Non-goals**: General-purpose application repository scripts (`REQ-CLIENT-012`) or `ArodonataSettings` validation (`REQ-CONFIG-005`).

`collect_gateway_routes()`, `refresh_topology()`, `stream_refresh_topology()`, and `reconcile_gateway_topology()` SHALL honor `cprid_script_mode` (`"inline" | "repository" | "auto"`), `repository_script_name`, and `repository_script_args_fn` overrides when falling back to Management API `run-script`.

#### Scenario: SCN-TOPO-008-1 — Repository mode executes canonical pre-approved script across standalone, cluster, and VSX gateways

- **GIVEN** an account holding `run-repository-script` without `run-one-time-script`
- **WHEN** `collect_gateway_routes(..., cprid_script_mode="repository")` runs across standalone, cluster, and VSX (`vsid=3`, `vs_name="VS_DMZ"`) targets
- **THEN** `TopologyService` SHALL send `run-script` with `script-type="repository"`, `script-name=settings.cprid_repository_script_name`, positional `args` (`"<max_routes> <vsid> <vs_name>"`), and zero `"script"`/`"script-base64"` fields
- **AND** it SHALL parse Gaia/Clish/VSX route markers identically to inline mode, or fail closed with `error_code="repository_script_not_found"` or `"repository_script_permission_denied"`

#### Scenario: SCN-TOPO-008-2 — Host application overrides repository script name and positional arguments builder

- **WHEN** `collect_gateway_routes(..., cprid_script_mode="repository", repository_script_name="corp-routes-v2", repository_script_args_fn=custom_fn)` runs
- **THEN** `TopologyService` SHALL invoke `"corp-routes-v2"` with `"script-type": "repository"` and pass `custom_fn(target, max_routes)` as `"args"`

#### Scenario: SCN-TOPO-008-3 — Auto mode falls back per domain on missing repository script while preserving strict repository errors

- **GIVEN** `"DomainA"` having `arodonata-collect-routes-v1` and `"DomainB"` lacking it
- **WHEN** `collect_gateway_routes(..., cprid_script_mode="auto")` runs vs `cprid_script_mode="repository"`
- **THEN** in `"auto"` mode, `"DomainA"` SHALL use `"script-type": "repository"` and `"DomainB"` SHALL fall back per domain to inline `"one time"` execution (cached per flight)
- **AND** in `"repository"` mode, `"DomainB"` SHALL fail with `error_code="repository_script_not_found"` without sending an inline script

### Requirement: Targeted Per-Gateway Topology and Route Refresh

**ID**: REQ-TOPO-009\
**Intent**: Allow incremental refresh of a single modified gateway without re-querying or deleting untouched gateways in large domains.\
**Non-goals**: Whole-domain topology sync-state stamping (`REQ-CACHE-011`).

`TopologyService.refresh_topology()` and `TopologyService.collect_gateway_routes()` SHALL accept an optional `gateways: Sequence[str] | None` filter (matching gateway UID, name, `id`, or `asset_id`) that refreshes and replaces cached topology and route intervals strictly for the specified gateways without re-querying or deleting cached topology rows for other gateways in the domain.

#### Scenario: SCN-TOPO-009-1 — Refreshing a single modified gateway in a large domain preserves other gateways

- **WHEN** `refresh_topology(mgmt_name="mds1", domains=["Corp"], gateways=["gw-branch-42"], collect_routes=True, mode="force")` runs
- **THEN** `TopologyService` SHALL query Management API gateway details and collect live routes ONLY for `"gw-branch-42"`
- **AND** it SHALL atomically replace only `"gw-branch-42"` rows in `arodonata_gateway_topology` while leaving all other gateways in `"Corp"` untouched

### Requirement: Persistent Administrator Topology Annotations and IPAM Prefix Export

**ID**: REQ-TOPO-010\
**Intent**: Preserve operator overrides and IPAM metadata across topology refreshes and allow exporting the annotated prefix inventory.\
**Non-goals**: Confidence delta scoring formulas (`REQ-TOPO-013`).

The cache layer SHALL persist `TopologyAnnotation` records in `arodonata_topology_annotations` across topology refreshes, supporting gateway/interface `trust_static_topology` overrides, prefix dispositions (`"confirmed"`, `"standby_dynamic"`, `"ignore"`, `"manual"`), and IPAM fields (`zone`, `site`, `comment`, `custom_metadata`), while `TopologyService.export_topology_prefixes()` exports the annotated prefix inventory.

#### Scenario: SCN-TOPO-010-1 — Annotations survive topology refresh and enrich IPAM prefix export

- **GIVEN** a `TopologyAnnotation` marking `10.90.0.0/24` on `gw1:eth1` as `disposition="standby_dynamic"`, `zone="DMZ-Partner"`, `site="Branch-SPB"`, `comment="Backup BGP path"`, and `10.99.0.0/24` as `disposition="ignore"`
- **WHEN** `refresh_topology(mode="force")` and `export_topology_prefixes()` execute
- **THEN** both annotations SHALL survive `refresh_topology` intact and `10.99.0.0/24` SHALL be excluded from active candidate matching
- **AND** `export_topology_prefixes()` SHALL include `10.90.0.0/24` with `zone="DMZ-Partner"`, `site="Branch-SPB"`, `comment="Backup BGP path"`, and `disposition="standby_dynamic"`

### Requirement: Affected Gateway LPM Candidate Matching and Exclusion

**ID**: REQ-TOPO-011\
**Intent**: Identify gateways whose interfaces traverse source-to-destination traffic via LPM while eliminating same-interface and external-only false positives.\
**Non-goals**: Package metadata attachment (`REQ-TOPO-012`) or policy-rule inference (`REQ-TOPO-014`).

`TopologyService.find_affected_gateways()` SHALL match `sources` and `destinations` against internal intervals first (longest-prefix match) and external interfaces second (`0.0.0.0/0`), excluding any gateway where pairs share one interface (`src_interface == dst_interface`), both hit `external`, or confidence falls below `min_confidence`.

#### Scenario: SCN-TOPO-011-1 — Traffic between two internal interfaces or between internal and external interfaces matches

- **GIVEN** Gateway A (`10.10.1.0/24` on `eth1`, `external` on `eth0`, `"Perimeter_Pkg"` in `"Corp"`) and Gateway C (`192.168.1.0/24` on `eth1`, `external` on `eth0`)
- **AND** Gateway B (`10.10.1.0/24` on `bond0.10`, `8.8.8.0/24` on `bond0.20`, `"Core_Pkg"` in `"DC"`)
- **WHEN** `find_affected_gateways(sources=["10.10.1.25"], destinations=["8.8.8.8"])` runs
- **THEN** it SHALL return Gateway B (`match_type="internal_to_internal"`, `bond0.10 -> bond0.20`, domain `"DC"`, package `"Core_Pkg"`)
- **AND** it SHALL return Gateway A (`match_type="internal_to_external"`, `eth1 -> eth0`, domain `"Corp"`, package `"Perimeter_Pkg"`) with `matched_sources=["10.10.1.25"]` and `matched_destinations=["8.8.8.8"]`
- **AND** it SHALL exclude Gateway C because both endpoints fall back to Gateway C's `eth0` (`external == external`)

#### Scenario: SCN-TOPO-011-2 — Traffic where both source and destination sit behind the same internal interface is excluded

- **WHEN** `find_affected_gateways(sources=["10.10.1.10"], destinations=["10.10.1.99"])` runs against a gateway where both addresses match `10.10.1.0/24` on `eth1`
- **THEN** that gateway SHALL be excluded because `src_interface == dst_interface == "eth1"`

### Requirement: Affected Gateway Candidate Package Enrichment, Source Filtering, and Input Ordering

**ID**: REQ-TOPO-012\
**Intent**: Give callers deterministic input-ordered flow matches, linked policy packages/layers, and control over evaluated interval sources.\
**Non-goals**: LPM exclusion logic (`REQ-TOPO-011`) or confidence-delta math (`REQ-TOPO-013`).

`TopologyService.find_affected_gateways()` SHALL honor `source_types` and `include_annotations` filters, attach domain, `installed_access_policy`, `policy_packages`, `access_layers`, and `matched_flows`, and populate `matched_sources` and `matched_destinations` per gateway in the caller's input order.

#### Scenario: SCN-TOPO-012-1 — Multi-gateway and transit topology filters matched_sources and matched_destinations per gateway in input order

- **GIVEN** multiple `sources` and `destinations` traversing a 4-gateway topology including `GW3` acting as a multi-interface transit gateway and `GW4` behind `GW3`
- **WHEN** `find_affected_gateways(sources, destinations)` runs
- **THEN** each returned `AffectedGatewayCandidate` SHALL list only the unique `source_query` and `destination_query` strings from its cross-interface `matched_flows` in exact caller input order
- **AND** any gateway where all pairs resolve to `src_interface == dst_interface` or `external == external` SHALL be excluded

#### Scenario: SCN-TOPO-012-2 — Policy package resolution combines asset policy metadata and rulebase installation targets

- **GIVEN** an affected gateway with `raw_data["policy"]["access-policy-name"] = "Standard_Policy"` and/or entries in cached `PolicyPackageInfo.installation_targets`
- **WHEN** `find_affected_gateways()` builds the candidate
- **THEN** it SHALL populate `installed_access_policy="Standard_Policy"`, all matching `policy_packages`, and ordered `access_layers` when the package catalog or rulebase snapshot is cached

#### Scenario: SCN-TOPO-012-3 — Static-only source_types and disabled annotations filter out live route and manual intervals

- **GIVEN** a cache containing static interface intervals, live `bgp_route` entries, and `manual` annotations
- **WHEN** `find_affected_gateways(sources, destinations, source_types=STATIC_TOPOLOGY_SOURCES, include_annotations=False)` runs
- **THEN** matching SHALL evaluate strictly intervals matching `source_types` and ignore `TopologyAnnotation` overrides without mutating cached rows

### Requirement: Extensible Evidence Delta Confidence Scoring

**ID**: REQ-TOPO-013\
**Intent**: Quantify path reliability transparently using configurable signed evidence deltas and conflict penalties.\
**Non-goals**: Policy rule inference evidence (`REQ-TOPO-014`).

`TopologyService` SHALL compute endpoint and flow confidence in `[0.0, 1.0]` by summing configurable signed evidence deltas (`TopologyConfidenceWeights` for positive route, static topology, annotation, and policy/VPN/bridge hooks, minus conflict penalties) and attaching `confidence`, `is_standby_path`, and `confidence_factors` (`list[ConfidenceDelta]`) to each `TrafficFlowMatch` and `AffectedGatewayCandidate`.

#### Scenario: SCN-TOPO-013-1 — Delta confidence reflects route agreement, detect-only anti-spoofing, conflicts, and standby annotations

- **WHEN** `find_affected_gateways()` evaluates (a) matching live route + `Prevent` topology, (b) live route on `eth1` conflicting with static topology on `eth2`, and (c) static topology annotated as `standby_dynamic`
- **THEN** case (a) SHALL clamp to `confidence=1.0`
- **AND** case (b) SHALL yield a high penalized confidence that increases when static topology has `trust_static_topology=False`
- **AND** case (c) SHALL set `is_standby_path=True` with `admin_standby_dynamic` recorded in `confidence_factors`

### Requirement: Policy and NAT Rule Topology Inference and Confidence Evidence

**ID**: REQ-TOPO-014\
**Intent**: Reinforce gateway candidates using installed Access/NAT rules and discover one-arm gateways when `include_policy_inferred=True`.\
**Non-goals**: Interface-only LPM matching (`REQ-TOPO-011`).

`find_affected_gateways()` SHALL evaluate enabled, non-negated, non-`Any` Access/NAT rules in each gateway's installed policy package (`install_on`-aware), awarding `+policy_rule_evidence` in `confidence_factors` to cross-interface L3 candidates and returning one-arm or incomplete-topology gateways whose installed rules explicitly cover `sources` and `destinations` as `match_type="policy_inferred"` when `include_policy_inferred=True`.

#### Scenario: SCN-TOPO-014-1 — Cross-interface L3 gateway receives policy_rule_evidence bonus from matching Access or NAT rules

- **GIVEN** a multi-interface L3 gateway whose installed policy contains an enabled non-`Any` Access or NAT rule (`original` or `translated` traffic) covering `10.10.1.25` and `10.20.2.50` for that gateway or `"Policy Targets"`
- **WHEN** `find_affected_gateways(sources=["10.10.1.25"], destinations=["10.20.2.50"])` matches that gateway
- **THEN** `confidence_factors` on the matched flow and candidate SHALL include `ConfidenceDelta(code="policy_rule_evidence", delta=0.25, ...)`

#### Scenario: SCN-TOPO-014-2 — One-arm Cisco ACI service-graph gateway is discovered via installed EPG policy while unrelated one-arm gateways are excluded

- **GIVEN** 10 single-interface `external` one-arm gateways (`corp-aci-onearm-01`..`10`) where only `corp-aci-onearm-03` has an installed rule permitting or translating `10.160.10.0/24` to `10.160.20.0/24`
- **WHEN** `find_affected_gateways(sources=["10.160.10.15"], destinations=["10.160.20.25"], include_policy_inferred=...)` runs
- **THEN** with `include_policy_inferred=True`, it SHALL return only `corp-aci-onearm-03` (`match_type="policy_inferred"`, `policy_rule_evidence` in `confidence_factors`) and exclude the other 9 one-arm gateways
- **AND** with `include_policy_inferred=False`, it SHALL exclude all 10 one-arm gateways

### Requirement: Static Topology Health Diagnostics and One-Arm Classification

**ID**: REQ-TOPO-015\
**Intent**: Audit static gateway topology completeness without raising false warnings on valid internal-only firewalls or one-arm gateways.\
**Non-goals**: Live CLI routing reconciliation (`REQ-TOPO-016`).

`TopologyService.get_topology_diagnostics()` SHALL inspect policy-enforcing gateways and interfaces for completeness and trust (`not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`, `unresolved_specific`, `empty_specific`, `missing_ip_mask`, `no_interfaces`), treating internal-only gateways as valid and classifying single-interface or external-only gateways as `one_arm_topology` (`severity="info"`).

#### Scenario: SCN-TOPO-015-1 — Diagnostics report incomplete interfaces and Detect-mode anti-spoofing without false positives on internal-only or one-arm gateways

- **GIVEN** Gateway 1 (`eth1` `not defined`, `eth2` `network defined by routing` without routes, `eth3` `specific` with Anti-Spoofing `Detect`)
- **AND** internal-only Gateway 2 (`eth1` and `eth2`) plus single-interface `one_arm` Gateway 3
- **WHEN** `get_topology_diagnostics()` runs
- **THEN** it SHALL emit warnings for Gateway 1 (`not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`)
- **AND** it SHALL emit zero warnings for internal-only Gateway 2 and report Gateway 3 as `code="one_arm_topology"` with `severity="info"`

### Requirement: Static Topology vs Live Routing Reconciliation and Cluster Drift Detection

**ID**: REQ-TOPO-016\
**Intent**: Detect anti-spoofing staleness, interface mismatches, cluster member routing drift, and policy-vs-topology gaps automatically.\
**Non-goals**: Static completeness checks without routing comparison (`REQ-TOPO-015`).

`TopologyService.reconcile_gateway_topology()` SHALL compare SmartConsole static topology against live CLI routes, across cluster members, and optionally against gateway-targeted policy rules (`check_policy=True`), returning a `TopologyReconciliationReport` of typed discrepancies while honoring `TopologyAnnotation` dispositions.

#### Scenario: SCN-TOPO-016-1 — Reconciliation detects stale anti-spoofing subnets, interface mismatches, and cluster member drift

- **GIVEN** Cluster A with static `10.50.0.0/24` and `10.60.0.0/24` on `eth1`, `10.70.0.0/24` on `eth2`, live routes showing `10.50.0.0/24` on `eth1`, `10.60.0.0/24` absent, `10.70.0.0/24` on `eth1`, and `10.80.0.0/24` on `eth1` on `member-1` only
- **WHEN** `reconcile_gateway_topology()` evaluates Cluster A
- **THEN** it SHALL report `stale_in_topology` for `10.60.0.0/24`, `interface_mismatch` for `10.70.0.0/24`, and `missing_in_topology` plus `cluster_member_drift` for `10.80.0.0/24`
- **AND** it SHALL classify `default_route_mismatch` and `resolved_by_routing` where applicable, and suppress `stale_in_topology` when `10.60.0.0/24` is annotated `standby_dynamic`

#### Scenario: SCN-TOPO-016-2 — Policy reconciliation flags gateway-targeted rules whose explicit networks are absent from gateway topology and routes

- **GIVEN** a gateway with internal topology `10.10.0.0/16` and an enabled Access or NAT rule targeting that gateway in `install_on` with explicit `source=192.168.50.0/24` and `destination=192.168.60.0/24` outside all internal intervals
- **WHEN** `reconcile_gateway_topology(..., check_policy=True)` runs
- **THEN** it SHALL emit a `TopologyDiscrepancy` with `discrepancy_type="policy_topology_mismatch"` naming the gateway, rule, and unmatched networks

### Requirement: Enterprise Raw-Replay Scale Verification for Multi-Hop, ECMP, LPM, and Batch Topology Queries

**ID**: REQ-TOPO-017\
**Intent**: Verify topology synchronization, diagnostics, reconciliation, and batch LPM candidate matching at enterprise MDSM scale.\
**Non-goals**: Raw dataset fixture generation rules (`REQ-ITEST-006`).

`TopologyService` SHALL accurately synchronize, diagnose, reconcile, and resolve 7–10-hop cross-domain transit chains, parallel ECMP paths, standby BGP paths, nested `/8`–`/32` longest-prefix-match (LPM) hierarchies, and `20x20+` batch source/destination matrices when driven end-to-end from raw Check Point Management API and gateway CLI routing fixtures.

#### Scenario: SCN-TOPO-017-1 — Cold raw-replay sync, smart-cache reuse, anomaly reconciliation, and administrator annotations

- **GIVEN** the enterprise raw dataset loaded via `FileReplayApiMock` and `FileReplayCliMock`
- **WHEN** cold `refresh_topology(..., collect_routes=True)` runs, followed by `"smart"` / `"cache"` re-runs, diagnostics, reconciliation, `upsert_topology_annotations()`, and `export_topology_prefixes()`
- **THEN** cold sync SHALL populate `CachePort` from raw payloads, and subsequent `"smart"`/`"cache"` runs SHALL make zero `show-gateways-and-servers` or SSH calls while `show-last-published-session` is unchanged
- **AND** diagnostics SHALL detect `not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`, and `one_arm_topology` with zero false warnings on internal-only gateways
- **AND** reconciliation SHALL detect `stale_in_topology`, `missing_in_topology`, `interface_mismatch`, `cluster_member_drift`, and `default_route_mismatch`
- **AND** annotations (`standby_dynamic`, `ignore`, `manual`, `confirmed`, `trust_static_topology=False`, `zone`, `site`, `comment`) SHALL govern candidate matching and IPAM export

#### Scenario: SCN-TOPO-017-2 — Deep 7 to 10 hop inter-domain transit chain, ECMP, standby BGP, LPM matryoshka, and 20x20 batch matrix

- **WHEN** `find_affected_gateways()` evaluates a 7–10 hop ECMP/standby-BGP flow (`include_standby=True` vs `False`), nested `/8`–`/32` prefixes, and a `20+ x 20+` batch with nested groups and ranges
- **THEN** it SHALL return all active hops (including both ECMP legs) while filtering standby BGP hops via `include_standby`
- **AND** it SHALL select the exact most-specific interface at every `/8`–`/32` matryoshka level via LPM
- **AND** it SHALL complete the `20+ x 20+` batch from cache in sub-second time while preserving exact caller input order in `matched_sources` and `matched_destinations`

#### Scenario: SCN-TOPO-017-3 — Targeted single-gateway refresh after raw API and CLI mutation queries only the target gateway

- **GIVEN** a modified raw API/CLI fixture adding a new routed subnet on `target_gateway`
- **WHEN** `refresh_topology(gateways=[target_gateway], collect_routes=True)` runs
- **THEN** replay call counters SHALL confirm only `target_gateway` was queried via Management API and SSH CLI
- **AND** `find_affected_gateways()` SHALL immediately reflect the updated routing graph

### Requirement: Stateful Script Repository and Repository-Mode Run-Script Emulation in FileReplayApiMock

**ID**: REQ-TOPO-018\
**Intent**: Enable offline end-to-end testing of repository-script provisioning, session isolation, and permission enforcement.\
**Non-goals**: General replay CRUD and session emulation (`REQ-ITEST-009`..`REQ-ITEST-014`).

`FileReplayApiMock` SHALL support per-domain `add-repository-script`, `show-repository-script`, `show-repository-scripts`, `set-repository-script`, and `delete-repository-script` (isolated in uncommitted write sessions until `publish`), enforce non-read-only sessions and configurable `run-repository-script` vs `run-one-time-script` permissions on `run-script`, and execute `script-type="repository"` targets using positional `args`.

#### Scenario: SCN-TOPO-018-1 — End-to-end provisioning and restricted-permission repository execution in FileReplayApiMock

- **GIVEN** `arodonata-collect-routes-v1` provisioned via `ensure_route_collection_script` (invisible to other sessions until `publish`) and `FileReplayApiMock(allow_one_time_script=False, allow_repository_script=True)`
- **WHEN** `collect_gateway_routes(cprid_script_mode="repository")` vs `cprid_script_mode="inline"` runs across cluster and VSX replay fixtures
- **THEN** `"repository"` mode SHALL succeed using `script-type="repository"`, whereas `"inline"` mode SHALL fail with `error_code="repository_script_permission_denied"`
