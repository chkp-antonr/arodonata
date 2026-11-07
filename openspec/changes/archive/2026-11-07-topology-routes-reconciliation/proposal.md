# Proposal

## Why

SmartConsole gateway interface topology is configured primarily for Anti-Spoofing rather than routing calculation, which makes relying solely on static Management API topology error-prone: interfaces frequently have topology set to `not defined` (`None`) or `network defined by routing`, or use `specific` network groups that retain stale subnets after routes are removed or omit newly added routes when Anti-Spoofing is disabled or set to `Detect`. To calculate affected gateways accurately and help administrators audit and clean up topology drift across hundreds or thousands of gateways, Arodonata needs static topology health diagnostics, live routing collection (via host-app SSH dependency injection with Check Point `cprid` `run-script` fallback), targeted single-gateway refresh, static-vs-routing reconciliation, persistent administrator annotations (including standby dynamic route markers and IPAM zone/site metadata), and an extensible delta-based confidence scoring model.

## What Changes

- **Static Topology Health Diagnostics (`TopologyDiagnostic`)**:
  - Inspect normalized gateway interfaces during topology extraction and via `get_topology_diagnostics()` to surface incomplete or low-trust interface configurations (`not_defined`, `routing_defined_without_routes`, `unresolved_specific`, `empty_specific`, `missing_ip_mask`, and `anti_spoofing_detect_or_off` when Anti-Spoofing is disabled or set to `Detect` rather than `Prevent`).
  - Classify legitimate architectural patterns such as internal-only gateways (no `external` interface) and `one_arm` gateways (single interface or external-only, e.g., Cisco ACI service graphs) as informational traits rather than warnings.
- **Live Gateway Route Collection (`GatewayCliPort` SSH DI + `cprid` Fallback)**:
  - Define `GatewayCliPort` (and accept an async callable `gateway_cli` in `ArodonataClient`) so a host application can execute bash commands on gateways over SSH directly in expert/bash mode.
  - Provide a built-in fallback adapter (`CpridCliAdapter`) that executes scripts via Check Point Management API `run-script` (`cprid`), awaits completion via `TaskWaiter`, and decodes Base64 `responseMessage` payloads when SSH is not provided or fails for a target node.
  - Resolve logical clusters (`simple-cluster`, `CpmiGatewayCluster`) to their `cluster-member` assets and VSX Virtual Systems (`virtual-system`, `CpmiVsNetobj`, `CpmiVsClusterNetobj`) to their physical VSX parent (`VS0`), switching VS contexts safely in bash using `vsenv "$vsid" >/dev/null 2>&1 </dev/null`, verifying `$FWDIR` against `CTX%05d`, and protecting `stdin` with `</dev/null` across `while read` loops.
  - Parse `ip -4 route show` and `clish -c "show route"` outputs into normalized `GatewayTopologyEntry` intervals (`connected_route`, `gaia_static_route`, `clish_route`, `bgp_route`, `ospf_route`).
- **Targeted Per-Gateway Topology & Route Refresh**:
  - Add `gateways: Sequence[str] | None = None` and `collect_routes: bool = False` to `refresh_topology` / `stream_refresh_topology` (plus `collect_gateway_routes`), allowing selective re-fetching of 1..N specific gateways and atomic per-gateway, per-source-category replacement in `arodonata_gateway_topology` without re-polling all gateways in a domain or wiping other source categories.
- **Static vs. Live Route Reconciliation (`TopologyReconciliationReport`)**:
  - Compare SmartConsole static topology against collected live routes per gateway and interface, reporting structured discrepancies: `stale_in_topology` (subnet in SmartConsole `specific` group but absent from interface routes), `missing_in_topology` (routed subnet behind internal interface missing from SmartConsole static topology), `interface_mismatch` (subnet declared on `ifA` in SmartConsole but routed via `ifB`), `default_route_mismatch`, `cluster_member_drift` (asymmetric routes across cluster members), and `resolved_by_routing`.
- **Persistent Topology Annotations & IPAM Export (`arodonata_topology_annotations`)**:
  - Add `TopologyAnnotationRecord` (`arodonata_topology_annotations`) to persist administrator overrides and metadata across cache resyncs: interface-level `trust_static_topology: bool | None` (allowing administrators to mark broken SmartConsole topology as untrusted without modifying SmartConsole), prefix-level dispositions (`confirmed`, `standby_dynamic` for backup dynamic routes, `ignore` for stale anti-spoofing entries, `manual` for manually added subnets), and semantic IPAM fields (`zone`, `site`, `comment`, `custom_metadata`).
  - Provide `export_topology_prefixes()` to export enriched gateway/interface prefix inventories with `zone`, `site`, `comment`, `source_types`, and `confidence` for IPAM reconciliation.
- **Extensible Evidence Delta Confidence Scoring (`ConfidenceDelta` & `TopologyConfidenceWeights`)**:
  - Replace fixed confidence constants with an additive delta accumulation model configured via `TopologyConfidenceWeights` on `ArodonataSettings`.
  - Accumulate positive deltas (`route_connected`, `route_static`, `route_dynamic`, `topology_connected`, `topology_specific_prevent`, `topology_specific_detect`, `topology_external_fallback`, `admin_confirmed`, `admin_standby_dynamic`, plus extensible hooks for future `policy_rule_match`, `vpn_domain_match`, and `bridge_arp_mac_match`) and negative conflict penalties (`conflict_missing_in_live_routes`, `conflict_routed_to_other_interface`, `conflict_cluster_member_drift`), clamping to `[0.0, 1.0]` and returning `confidence`, `is_standby_path`, and `confidence_factors: list[ConfidenceDelta]` on `TrafficFlowMatch` and `AffectedGatewayCandidate`.

## Capabilities

### New Capabilities

<!-- None: all capabilities extend existing spec domains below -->

### Modified Capabilities

- `gateway-topology`: Add static topology diagnostics, `GatewayCliPort` SSH DI with `cprid` `run-script` fallback and safe VSX `vsenv` collection, targeted per-gateway refresh, source-category-isolated persistence, static-vs-live route reconciliation, persistent administrator annotations (`arodonata_topology_annotations`), IPAM prefix export, and delta-based confidence scoring.
- `client-and-facade`: Expose `GatewayCliPort` / `gateway_cli` injection, targeted `gateways` and `collect_routes` parameters on topology refresh, and facade methods for diagnostics, route collection, reconciliation, topology annotations, and IPAM prefix export.
- `mcp-server`: Extend `locate_gateways` and `cache_control(scope="topology")` with targeted gateway refresh, optional route collection, confidence scores, `confidence_factors`, standby path indicators, and topology diagnostics/reconciliation inspection.

## Impact

- **Core Models & Config (`src/arodonata/core/models/topology.py`, `src/arodonata/core/config.py`, `src/arodonata/core/ports/__init__.py`)**: New models (`GatewayCliTarget`, `GatewayCliResult`, `GatewayCliPort`, `TopologyDiagnostic`, `TopologyDiscrepancy`, `TopologyReconciliationReport`, `TopologyAnnotation`, `ConfidenceDelta`, `TopologyConfidenceWeights`, `ExportedTopologyPrefix`) and extended fields on `GatewayTopologyEntry`, `TrafficFlowMatch`, and `AffectedGatewayCandidate`.
- **Storage (`src/arodonata/adapters/storage/tables.py`, `src/arodonata/adapters/storage/cache_adapter.py`)**: New `TopologyAnnotationRecord` table (`arodonata_topology_annotations`), `anti_spoofing_mode` metadata on `GatewayTopologyRecord`, and scoped topology replacement by gateway and source category.
- **Services & Facade (`src/arodonata/core/services/topology_service.py`, `src/arodonata/client.py`, `src/arodonata/mcp/tools.py`)**: Route collection, reconciliation, annotation overlay, and delta confidence calculation in `TopologyService`, wired into `ArodonataClient` and `arodonata.mcp`.
