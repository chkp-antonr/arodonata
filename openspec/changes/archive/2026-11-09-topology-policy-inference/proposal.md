# Proposal

## Why

Stage 1 of gateway topology and route reconciliation (`TopologyService`) locates affected gateways by resolving traffic endpoints across distinct L3 interfaces (`src_interface != dst_interface`), which cannot identify one-arm appliances (such as Cisco ACI service-graph gateways where traffic enters and leaves via a single or external-only interface) or gateways with incomplete interface definitions (`not defined` or `network defined by routing` without collected routes). Additionally, cached Access Control and NAT rulebases (`arodonata_rulebase_access_rule`, `arodonata_rulebase_nat_rule`) and gateway VPN encryption domains (`vpn-domain` / `encryption-domain`) already reside in the local SQL cache and provide high-value evidence to boost candidate confidence, infer policy-enforced one-arm gateways, and audit policy-vs-topology discrepancies.

## What Changes

- **Policy & NAT Rule Evidence and One-Arm Gateway Inference (`find_affected_gateways`)**:
  - Evaluate active (`enabled=True`), non-negated, non-`Any` Access Control (`arodonata_rulebase_access_rule`) and NAT (`arodonata_rulebase_nat_rule` `original` and `translated`) rules belonging to each gateway's installed policy package (honoring rule-level `install_on` targets matching the gateway or `"Policy Targets"` / `"All"`).
  - For standard cross-interface (`src_interface != dst_interface`) gateway candidates, award the `+policy_rule_evidence` (`+0.25`, aliased with `policy_rule_match`) confidence delta in `confidence_factors` when installed Access or NAT rules explicitly cover the queried `sources` and `destinations`.
  - Add `include_policy_inferred: bool = True` to `find_affected_gateways`: for one-arm gateways (single interface or external-only) and gateways with incomplete interface topology (`not defined` or `network defined by routing` without routes) that cannot match via `src_interface != dst_interface`, infer candidate gateways when their installed Access or NAT policy contains explicit (non-`Any`) rules covering both `sources` and `destinations`, returning `match_type="policy_inferred"` with corresponding `confidence_factors`.
- **VPN Encryption Domain Extraction (`vpn_domain`)**:
  - Extract gateway and cluster `vpn-domain` / `encryption-domain` references during `TopologyService` topology extraction, recursively expanding the referenced network/group object via `arodonata_objects` (with `"Global"` fallback) into `GatewayTopologyEntry` intervals with `source_type="vpn_domain"`.
  - Apply the `vpn_encryption_domain` (`+0.45`, aliased with `vpn_domain_match`) confidence weight when scoring endpoints matched via `vpn_domain` intervals.
- **Policy vs Topology/Routes Reconciliation (`reconcile_gateway_topology`)**:
  - Add `check_policy: bool = False` to `reconcile_gateway_topology` to cross-check explicit (non-`Any`) source and destination networks in rules specifically targeting a gateway via `install_on` against that gateway's effective internal topology and route intervals, reporting `policy_topology_mismatch` discrepancies when neither source nor destination of a gateway-targeted rule resides behind the gateway's internal interfaces or routes.
- **Client Facade & MCP Tool Surface (`ArodonataClient`, `locate_gateways`)**:
  - Expose `include_policy_inferred: bool = True` on `ArodonataClient.find_affected_gateways` and MCP `locate_gateways`, and `check_policy: bool = False` on `ArodonataClient.reconcile_gateway_topology`.

## Capabilities

### New Capabilities

- None

### Modified Capabilities

- `gateway-topology`: Add `source_type="vpn_domain"` extraction and `vpn_encryption_domain` confidence scoring, `+policy_rule_evidence` confidence boosting from installed Access/NAT rules, `include_policy_inferred` (`match_type="policy_inferred"`) candidate discovery for one-arm and incomplete-topology gateways, and `check_policy` reconciliation in `reconcile_gateway_topology`.
- `client-and-facade`: Forward `include_policy_inferred` in `ArodonataClient.find_affected_gateways` and `check_policy` in `ArodonataClient.reconcile_gateway_topology`.
- `mcp-server`: Expose `include_policy_inferred` in the `locate_gateways` MCP tool and include `policy_inferred` flow matches in tool responses.

## Impact

- **Core Models & Config**: `src/arodonata/core/config.py` (`TopologyConfidenceWeights`), `src/arodonata/core/models/topology.py` (`TopologySourceType`, `STATIC_TOPOLOGY_SOURCES`, `FlowMatchType`, `TopologyDiscrepancyType`).
- **Core Services**: `src/arodonata/core/services/topology_service.py` (`TopologyService` extraction, confidence scoring, policy/NAT rule indexing, `find_affected_gateways`, `reconcile_gateway_topology`).
- **Client Facade & MCP**: `src/arodonata/client.py` (`ArodonataClient`), `src/arodonata/mcp/tools.py` (`locate_gateways`).
- **Tests**: `tests/unit/test_topology_service.py` and `tests/unit/test_topology_scale_scenarios.py` (including 10 one-arm Cisco ACI service-graph gateways where 1 is discovered via its installed EPG policy while 9 are excluded).
