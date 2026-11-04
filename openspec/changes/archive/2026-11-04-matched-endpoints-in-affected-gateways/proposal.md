# Proposal

## Why

When callers invoke `TopologyService.find_affected_gateways(sources, destinations)` with multiple IP addresses, CIDRs, ranges, or Check Point object/group names, different subsets of those sources and destinations may traverse different gateways (including transit gateways and downstream edge gateways), while other endpoints sit behind the same interface (`src_interface == dst_interface`) or are unrelated (`external == external`) on a given gateway. Downstream policy automation workflows need each returned `AffectedGatewayCandidate` to explicitly list only the deduplicated `matched_sources` and `matched_destinations` that actually traverse distinct interfaces on that specific gateway, preserving the caller's input order.

## What Changes

- **Extend `AffectedGatewayCandidate` (`src/arodonata/core/models/topology.py`)**:
  - Add `matched_sources: list[str] = Field(default_factory=list)` containing the unique `source_query` strings from `matched_flows` on that gateway, ordered by their appearance in the input `sources`.
  - Add `matched_destinations: list[str] = Field(default_factory=list)` containing the unique `destination_query` strings from `matched_flows` on that gateway, ordered by their appearance in the input `destinations`.
- **Populate `matched_sources` and `matched_destinations` in `TopologyService.find_affected_gateways()` (`src/arodonata/core/services/topology_service.py`)**:
  - For each candidate gateway with non-empty `matched_flows`, compute the set of `source_query` and `destination_query` values present in `matched_flows` (i.e., endpoints participating in at least one valid cross-interface flow `src_interface != dst_interface` and not `external == external` on that gateway) and filter the normalized input `src_list` and `dst_list` to unique matching queries while strictly preserving input order.
- **Add 4-Gateway Multi-Hop & Transit Topology Unit Tests (`tests/unit/test_topology_service.py`)**:
  - Add unit test coverage with a 4-gateway topology (`GW1`, `GW2`, transit gateway `GW3` with its own networks and transit interface covering upstream/downstream networks, and `GW4` behind `GW3`), verifying candidate selection, exclusion of non-affected gateways, and exact order-preserving population of `matched_sources` and `matched_destinations` per gateway.

## Capabilities

### New Capabilities

<!-- None -->

### Modified Capabilities

- `gateway-topology`: `AffectedGatewayCandidate` returned by `TopologyService.find_affected_gateways()` includes per-gateway filtered `matched_sources` and `matched_destinations` derived from cross-interface `matched_flows` in input order.

## Impact

- **Models**: `AffectedGatewayCandidate` in `src/arodonata/core/models/topology.py` (additive fields with `default_factory=list`; backward-compatible).
- **Services**: `TopologyService.find_affected_gateways` in `src/arodonata/core/services/topology_service.py`.
- **Facade & MCP**: `ArodonataClient.find_affected_gateways` and MCP `locate_gateways` automatically serialize the new fields via `AffectedGatewayCandidate.model_dump(mode="json")`.
- **Tests**: `tests/unit/test_topology_service.py`.
