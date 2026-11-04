# Design

## Context

`TopologyService.find_affected_gateways(sources, destinations)` resolves each caller-supplied source and destination query (IPv4 address, CIDR, IP range, or Check Point object/group name) into `_ResolvedEndpointInterval` items and matches them against each gateway's interface topology intervals (`GatewayTopologyEntry`). Currently, `AffectedGatewayCandidate` records the cross-interface `matched_flows: list[TrafficFlowMatch]`, where each `TrafficFlowMatch` stores `source_query` and `destination_query`. However, consumers requesting rules across multi-gateway paths (including branch gateways, transit gateways, and downstream gateways) must manually post-process `matched_flows` to determine which subset of input `sources` and `destinations` actually applies to each gateway. See `proposal.md` for motivation.

## Goals / Non-Goals

**Goals:**

- Add `matched_sources: list[str] = Field(default_factory=list)` and `matched_destinations: list[str] = Field(default_factory=list)` to `AffectedGatewayCandidate` in `src/arodonata/core/models/topology.py`.
- Populate `matched_sources` and `matched_destinations` in `TopologyService.find_affected_gateways()` with unique `source_query` and `destination_query` values from that gateway's `matched_flows`, strictly preserving the order in which they were passed in `sources` and `destinations`.
- Verify multi-gateway and transit-gateway behavior with a 4-gateway unit test topology (`GW1`, `GW2`, `GW3` transit + local subnets, `GW4` behind `GW3`).

**Non-Goals:**

- Modifying the SQLite/PostgreSQL cache schema (`arodonata_gateway_topology` is unchanged).
- Changing how `TrafficFlowMatch` or `_locate_intervals_on_gateway` resolves longest-prefix internal matches or external fallbacks.

## Decisions

### 1. Deriving `matched_sources` and `matched_destinations` from `matched_flows` in Input Order

- **Decision**: After collecting all valid cross-interface `matched_flows` for a gateway (`src_match.interface_name != dst_match.interface_name` and not both `"external"`), collect the sets of matched queries:
  - `matched_src_set = {f.source_query for f in matched_flows}`
  - `matched_dst_set = {f.destination_query for f in matched_flows}`
  Then iterate over the normalized `src_list` and `dst_list` (using `dict.fromkeys(...)` to deduplicate any repeated caller inputs while preserving first-seen order):
  - `matched_sources = [s for s in dict.fromkeys(src_list) if s in matched_src_set]`
  - `matched_destinations = [d for d in dict.fromkeys(dst_list) if d in matched_dst_set]`
- **Rationale**:
  - Guarantees that an endpoint that resolved on a gateway's interface—or even expanded from a group into multiple intervals—is included in `matched_sources` / `matched_destinations` **if and only if** at least one of its intervals formed a valid cross-interface flow (`src_interface != dst_interface` and not `external == external`) with an opposite endpoint on that gateway.
  - Strictly preserves the caller's original ordering in `sources` and `destinations`, even if duplicate items were passed in the input sequence or if an object/group expanded into multiple `TrafficFlowMatch` entries.
- **Alternatives Considered**:
  - Collecting `f.source_query` and `f.destination_query` in `matched_flows` iteration order: While `src_intervals` iterates in `src_list` order, `dst_intervals` is the inner loop, so `f.destination_query` appearance order across multiple sources could differ from `dst_list` if an earlier source only matched the second destination while a later source matched the first destination. Filtering `dict.fromkeys(dst_list)` by `matched_dst_set` guarantees exact input order in all cases.

### 2. 4-Gateway Multi-Hop & Transit Topology Test Design

- **Decision**: Construct a dedicated unit test in `tests/unit/test_topology_service.py` with 4 gateways:
  - **GW1** (Branch 1 gateway): `eth1` internal `10.1.0.0/24`, `eth0` external (`0.0.0.0/0`) or specific transit link.
  - **GW2** (Branch 2 gateway): `eth1` internal `10.2.0.0/24`, `eth0` external (`0.0.0.0/0`) or specific transit link.
  - **GW3** (Transit + Core gateway):
    - `eth1` configured with `"specific"` group/networks covering `GW1` and `GW2` networks (`10.1.0.0/24`, `10.2.0.0/24`) — or external/upstream link,
    - `eth2` internal `10.3.0.0/24` (GW3's own local network),
    - `eth3` configured with `"specific"` network `10.4.0.0/24` (leading toward `GW4`).
  - **GW4** (Downstream gateway behind GW3):
    - `eth0` external (`0.0.0.0/0`) or specific upstream covering `10.1.0.0/24`, `10.2.0.0/24`, `10.3.0.0/24` on `eth0`,
    - `eth1` internal `10.4.0.0/24`.
  Test multiple queries where subsets of `sources` (e.g., from GW1 `10.1.0.10`, GW2 `10.2.0.20`, GW3 local `10.3.0.30`, and an intra-subnet/unmatched address) and `destinations` (e.g., in GW3 local `10.3.0.99` and GW4 `10.4.0.40`) traverse different gateways, verifying both gateway selection/exclusion and exact `matched_sources` / `matched_destinations` lists on each candidate.

## Risks / Trade-offs

- **[Risk] Caller passes duplicate strings in `sources` or `destinations`** → Mitigation: `dict.fromkeys(src_list)` deduplicates while preserving first-seen input order.
- **[Risk] Whitespace around caller query strings** → Mitigation: `src_list` and `dst_list` already strip each element before `_resolve_endpoint_intervals`, and `classify_search_term(raw).raw` preserves the stripped string, so `f.source_query` / `f.destination_query` match elements of `src_list` / `dst_list` 1-to-1.
