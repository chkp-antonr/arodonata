# Design: Gateway Topology Diagnostics, Live Route Collection, Reconciliation & Delta Confidence

## Context

See `proposal.md` for motivation. Currently, `TopologyService` extracts static topology intervals from Check Point Management API gateway/cluster/VS definitions and stores them in `arodonata_gateway_topology`, replacing all rows in a domain on each `refresh_topology` call. Interfaces with `not defined` or `network defined by routing` (without VS static routes) only emit a log warning, Anti-Spoofing enforcement mode (`Prevent` vs `Detect`) is not captured, live routing tables from gateways are not collected or reconciled, and administrator overrides/annotations cannot be persisted across cache refreshes.

## Goals / Non-Goals

**Goals:**

- Expose structured static topology diagnostics (`get_topology_diagnostics`) for incomplete or low-trust interfaces (`not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`, `unresolved_specific`, `empty_specific`, `missing_ip_mask`) without false-positive warnings on internal-only gateways or `one_arm` gateways (e.g., Cisco ACI).
- Provide a hexagonal `GatewayCliPort` protocol and simple async callback integration on `ArodonataClient` for direct bash execution over SSH, with automatic/configurable fallback to Check Point Management API `run-script` (`cprid`).
- Handle Check Point clusters (resolving `cluster-member` nodes and detecting member route drift) and VSX Virtual Systems (batching or targeting `vsid` contexts on the physical VSX parent via safe `vsenv` + `$FWDIR` `CTX%05d` verification and `</dev/null` stdin protection).
- Support targeted per-gateway refresh (`gateways=[...]`) and source-category-isolated persistence so refreshing 1 gateway out of 500 or refreshing static topology does not wipe cached live routes or other gateways.
- Reconcile SmartConsole static topology against live routing tables (`reconcile_gateway_topology`), persist administrator annotations/overrides and IPAM metadata (`zone`, `site`, `comment`, `disposition`, `trust_static_topology`) in `arodonata_topology_annotations`, export enriched prefix inventories (`export_topology_prefixes`), and compute extensible delta-based confidence scores (`ConfidenceDelta`, `TopologyConfidenceWeights`).

**Non-Goals (Deferred to Stages 2–4):**

- Security policy rulebase inference for `one_arm` gateways and unroutable rule detection (Stage 2).
- Multi-hop logical gateway overlay graph construction across ~2,000 gateways and interactive graph layout export (Stage 3).
- Bridge-mode L2 MAC/ARP collection, in-flight NAT IP translation along multi-hop paths, and VPN domain tunnel topology (Stage 4 — source types and delta hooks are reserved now).

## Decisions

### 1. Hexagonal `GatewayCliPort` with Async Callback Wrapper and `cprid` Fallback

- **Choice**: Define `GatewayCliPort` in `arodonata.core.ports` accepting a `GatewayCliTarget` (`mgmt_name`, `domain_name`, `gateway_uid`, `gateway_name`, `gateway_type`, `node_uid`, `node_name`, `node_ipv4`, `vsid`) and `command: str`, returning `GatewayCliResult(success, stdout, stderr, exit_code, executor)`. Allow `ArodonataClient(..., gateway_cli=...)` to accept either a `GatewayCliPort` instance or a simple async callable `Callable[[GatewayCliTarget, str], Awaitable[str | GatewayCliResult]]`.
- **Fallback (`CpridCliAdapter`)**: When `gateway_cli` is `None` or fails for a target node (and `fallback_to_cprid=True`), `TopologyService` invokes `ApiPort.api_call(mgmt_name, "run-script", {"script-name": "arodonata-route-collect", "script": script, "targets": [target.node_uid]}, domain=domain)`. `TaskWaiter` polls `show-task` to completion, and the adapter extracts and Base64-decodes `task-details[].responseMessage`.
- **Rationale**: Host applications often maintain their own SSH connection pools and credential vaults where sessions land directly in Gaia `bash` (`expert` mode). Supporting both a protocol and a plain async function makes DI effortless while `run-script` guarantees standalone operation when only Management API access exists.

### 2. Safe VSX `vsenv` Switching and Cluster Member Resolution

- **Choice**:
  - **Clusters (`simple-cluster`, `CpmiGatewayCluster`)**: Resolve `Asset.member_uids` from `arodonata_assets` to execute route collection on cluster member nodes. Store the canonical `GatewayTopologyEntry` rows under the parent cluster's `gateway_uid`, while recording per-member route sets in `source_ref` / reconciliation metadata to detect `cluster_member_drift` when members disagree.
  - **VSX Virtual Systems (`virtual-system`, `CpmiVsNetobj`, `CpmiVsClusterNetobj`)**: Resolve the VS to its physical VSX parent (`parent_uid` or VSX cluster member) and `vsid` (from `raw_data["vsid"]` or `vsx stat -l`). When executing in bash on a VSX host, use the battle-tested `vsenv` pattern:

    ```bash
    ctx=$(printf "CTX%05d" "$vsid")
    if ! vsenv "$vsid" >/dev/null 2>&1 </dev/null; then
      echo "_vs_error=vsenv $vsid failed"
    elif [ "${FWDIR#*$ctx}" = "$FWDIR" ]; then
      echo "_vs_error=context not switched (FWDIR=$FWDIR)"
    else
      ip -4 route show </dev/null
    fi
    ```

  - **Route Parser**: Parse `ip -4 route show` (`proto kernel` -> `connected_route`, `proto static`/`boot` -> `gaia_static_route`, `proto bgp` -> `bgp_route`, `proto ospf` -> `ospf_route`, `proto zebra`/`routed` -> `clish_route`, `default` -> `0.0.0.0/0` external) as well as `clish -c "show route"` output (`C`, `S`, `B`, `O`, `R` codes) as a secondary format.
- **Rationale**: `vsenv` is a shell function that mutates `$FWDIR` and virtual context in the current shell process, and commands inside `while read` loops must redirect `</dev/null` to avoid consuming loop stdin. Verifying `$FWDIR` against `CTX%05d` prevents accidentally attributing `VS0` routes to a Virtual System if `vsenv` silently fails.

### 3. Smart Cache Integration, Source-Category-Isolated Persistence & Targeted Per-Gateway Refresh

- **Choice**:
  - **Built-in Smart Cache Integration (`DomainSyncCoordinator` & `arodonata_domain_sync_state`)**:
    - Static topology extraction continues to use `DomainSyncCoordinator` (`scope="topology"`, `item_type="*"`), leveraging `arodonata_assets` and `arodonata_objects` already cached by the smart cache (`last_published_at`, `last_session_uid`, `cache_ttl`, and distributed locks). When a domain has no new published changes on the Management Server, `mode="smart"` serves topology directly from the SQLite/PostgreSQL cache with zero API calls.
    - Live gateway routes (`SSH` / `cprid`) change independently of Management Server `publish` operations. Their freshness is tracked in `arodonata_domain_sync_state` under `scope="topology"`, `item_type="routes"` (using `synced_at` + `cache_ttl` in `"smart"` mode). Read and search operations (`find_affected_gateways`, `reconcile_gateway_topology`, `get_topology_diagnostics`, `export_topology_prefixes`) query the cached SQLite/PostgreSQL rows in `arodonata_gateway_topology` without triggering live SSH/`cprid` calls unless `collect_routes=True` is explicitly requested.
  - **Source-Category Isolation**:
    - Partition `TopologySourceType` into two persistence categories:
      - `STATIC_TOPOLOGY_SOURCES = {"interface_connected", "interface_specific", "vs_static_route", "external_interface"}`
      - `LIVE_ROUTE_SOURCES = {"connected_route", "gaia_static_route", "clish_route", "bgp_route", "ospf_route"}`
    - Extend `CachePort.replace_domain_topology` with optional `gateway_uids: Sequence[str] | None = None` and `source_types: Sequence[str] | None = None` filters.
    - When `refresh_topology(..., gateways=["gw1"])` runs, only `"gw1"` is fetched/extracted and only `"gw1"`'s `STATIC_TOPOLOGY_SOURCES` rows are replaced in `arodonata_gateway_topology` (plus `LIVE_ROUTE_SOURCES` if `collect_routes=True`).
- **Rationale**: Reuses the existing SQL smart cache for sub-millisecond reads, prevents `refresh_topology` from wiping expensive SSH/`cprid`-collected routes, and allows selective single-gateway re-reads after an administrator fixes a gateway in SmartConsole or `clish`.

### 4. Static Topology Diagnostics & Anti-Spoofing Mode Extraction

- **Choice**:
  - Extend `_NormalizedInterface` and `GatewayTopologyEntry` / `GatewayTopologyRecord` with `anti_spoofing_mode: Literal["prevent", "detect", "off", "unknown"] = "unknown"`.
  - Inspect `topology-settings` / `anti-spoofing` / `antiSpoofing` dicts in Check Point payloads (`perform-anti-spoofing`, `anti-spoofing-tracking`, `spoof-tracking`, `action`: `"prevent"` vs `"detect"` / `"log"`).
  - `get_topology_diagnostics()` returns `list[TopologyDiagnostic]` per gateway/interface. Gateways with only internal interfaces (`internal_only`) generate zero warnings; gateways with a single active interface or only an external interface are reported with `code="one_arm_topology"` and `severity="info"`.

### 5. Persistent Administrator Annotations (`arodonata_topology_annotations`) & Reconciliation

- **Choice**:
  - Create `TopologyAnnotationRecord` (`arodonata_topology_annotations`) keyed by deterministic `id = "{mgmt_name}:{domain_name}:{gateway_uid}:{interface_name}:{cidr_or_range}"` (where `interface_name` or `cidr_or_range` can be `"*"` for gateway-level or interface-level annotations).
  - Fields: `trust_static_topology: bool | None`, `disposition: Literal["confirmed", "standby_dynamic", "ignore", "manual"] | None`, `topology_zone: str | None`, `zone: str`, `site: str`, `comment: str`, `custom_metadata: dict[str, Any]`, `updated_at: datetime`.
  - `reconcile_gateway_topology()` compares `STATIC_TOPOLOGY_SOURCES` against `LIVE_ROUTE_SOURCES` and `TopologyAnnotation` records, producing `TopologyReconciliationReport` with `diagnostics` and `discrepancies` (`stale_in_topology`, `missing_in_topology`, `interface_mismatch`, `default_route_mismatch`, `cluster_member_drift`, `resolved_by_routing`).

### 6. Extensible Evidence Delta Confidence Scoring (`ConfidenceDelta` & `TopologyConfidenceWeights`)

- **Choice**:
  - Configure default signed weights in `TopologyConfidenceWeights` (embedded in `ArodonataSettings`):
    - Positive deltas: `route_connected: +0.65`, `route_static: +0.55`, `route_dynamic: +0.50`, `topology_connected: +0.50`, `topology_specific_prevent: +0.40`, `topology_specific_detect: +0.15`, `topology_external_fallback: +0.30`, `admin_confirmed: +0.50`, `admin_manual: +0.60`, `admin_standby_dynamic: +0.35`, `policy_rule_match: +0.25` (Stage 2), `vpn_domain_match: +0.35` (Stage 4), `bridge_arp_mac_match: +0.40` (Stage 4).
    - Negative deltas: `conflict_missing_in_live_routes: -0.35`, `conflict_routed_to_other_interface_static: -0.50`, `conflict_routed_to_other_interface_route: -0.10`, `conflict_cluster_member_drift: -0.20`.
  - For each matched `(interface, endpoint)` interval on a gateway:
    - If annotated with `disposition="ignore"`, exclude the interval completely.
    - If interface/gateway has `trust_static_topology=False`, skip positive static `topology_specific_*` deltas and suppress the `-0.10` static-conflict penalty on live routes.
    - Sum all applicable `ConfidenceDelta(code, delta, detail)` entries and clamp to `[0.0, 1.0]`.
    - Flow confidence is `round(min(src_confidence, dst_confidence), 4)`, and candidate gateway confidence is `max(flow.confidence for flow in matched_flows)`.

## Risks / Trade-offs

- **[Risk] `run-script` requires write/exec permissions on Management API and active SIC to gateways** → Mitigation: Prefer injected SSH `GatewayCliPort` first, use `run-script` only when requested (`collect_routes=True`), and record per-gateway collection errors gracefully in `RouteCollectionOutcome` without aborting topology sync for other gateways.
- **[Risk] Schema change on `arodonata_gateway_topology` and new `arodonata_topology_annotations` table** → Mitigation: `DatabaseManager` computes a SHA-256 hash over `SQLModel.metadata` (`arodonata_schema_version`) and automatically recreates/migrates cache tables on schema hash change.
