# Spec Delta

## ADDED Requirements

### Requirement: Enterprise Raw-Replay Scale Verification for Multi-Hop, ECMP, LPM, and Batch Topology Queries

`TopologyService` SHALL accurately synchronize, diagnose, reconcile, and resolve 7–10-hop cross-domain transit chains, parallel ECMP paths, standby BGP paths, nested `/8`–`/32` longest-prefix-match (LPM) hierarchies, and `20x20+` batch source/destination matrices when driven end-to-end from raw Check Point Management API and gateway CLI routing fixtures.

#### Scenario: Cold raw-replay sync, smart-cache reuse, anomaly reconciliation, and administrator annotations

- **WHEN** `refresh_topology(..., collect_routes=True)` executes cold against the multi-domain enterprise raw dataset, followed by a `cache_mode="smart"` / `"cache"` re-run, `get_topology_diagnostics()`, `reconcile_gateway_topology()`, `upsert_topology_annotations()`, and `export_topology_prefixes()`
- **THEN** the cold sync SHALL populate `SqlCacheAdapter` from raw API/CLI payloads, the subsequent `smart` and `cache` runs SHALL perform zero `show-gateways-and-servers` or SSH calls while `show-last-published-session` is unchanged, diagnostics and reconciliation SHALL detect all planted anomalies (`not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`, `one_arm_topology`, `stale_in_topology`, `missing_in_topology`, `interface_mismatch`, `cluster_member_drift`, `default_route_mismatch`) with zero false warnings on internal-only gateways, and administrator annotations (`standby_dynamic`, `ignore`, `manual`, `confirmed`, `trust_static_topology=False`, `zone`, `site`, `comment`) SHALL govern candidate matching and IPAM prefix export

#### Scenario: Deep 7 to 10 hop inter-domain transit chain, ECMP, standby BGP, LPM matryoshka, and 20x20 batch matrix

- **WHEN** `find_affected_gateways()` evaluates (a) a cross-domain flow traversing 7–10 hops (`Branch -> Regional -> WAN_Core -> Perimeter -> Transit -> DC_Spine -> VS Tier-1 -> VS Tier-2 -> DB_Seg`) with parallel ECMP hops and standby BGP gateways (`include_standby=True` vs `False`), (b) packets targeting nested prefixes (`/8`, `/12`, `/16`, `/22`, `/24`, `/28`, `/32`) distributed across distinct interfaces of a single gateway, and (c) a `20+ x 20+` batch of sources and destinations (including nested groups and address ranges)
- **THEN** it SHALL return all active hops (including both ECMP legs) while filtering standby BGP hops according to `include_standby`, select the exact most-specific interface at every `/8`–`/32` matryoshka level via LPM, and complete the `20+ x 20+` batch query in sub-second time from cache while strictly preserving the caller's input order in `matched_sources` and `matched_destinations`

#### Scenario: Targeted single-gateway refresh after raw API and CLI mutation queries only the target gateway

- **WHEN** the raw API/CLI fixture for a single gateway is modified to add a new routed subnet and `refresh_topology(gateways=[target_gateway], collect_routes=True)` is invoked
- **THEN** the replay call counters SHALL confirm that only `target_gateway` was queried via Management API and SSH CLI, and `find_affected_gateways()` SHALL immediately reflect the updated routing graph
