# Tasks: Gateway Interface Topology Caching & Affected Gateway / Policy Candidate Matching

## 1. Domain Models, Ports & SQL Storage (`arodonata_gateway_topology`)

- [x] 1.1 Create `src/arodonata/core/models/topology.py` defining `TopologySourceType`, `TopologyZone`, `GatewayTopologyEntry`, `GatewayInterfaceSummary`, `TrafficFlowMatch`, and `AffectedGatewayCandidate`, extend `SyncScope` in `src/arodonata/core/models/common.py` with `"topology"`, export the new models in `src/arodonata/core/models/__init__.py`, and verify `uv run mypy src/arodonata/core/models` passes.
- [x] 1.2 Add `GatewayTopologyRecord` (`__tablename__ = "arodonata_gateway_topology"`, using `BigInteger` for `ip_first_int` and `ip_last_int`) in `src/arodonata/adapters/storage/tables.py`, register `"arodonata_gateway_topology"` in `ARODONATA_TABLE_NAMES` in `src/arodonata/adapters/storage/database.py`, extend `CachePort` in `src/arodonata/core/ports/__init__.py` with `get_gateway_topology`, `replace_domain_topology`, and `upsert_gateway_topology`, and implement them in `src/arodonata/adapters/storage/cache_adapter.py`.
- [x] 1.3 Add storage unit tests in `tests/unit/test_storage.py` covering `arodonata_gateway_topology` schema auto-migration, `replace_domain_topology`, `upsert_gateway_topology`, and upper-half IPv4 (`>= 128.0.0.0`, e.g. `192.168.1.0/24` and `255.255.255.255`) 64-bit integer persistence, and verify `uv run pytest tests/unit/test_storage.py` passes.

## 2. VSX Slot (`CpmiVsxSlotObj` / `CpmiVsSlotObj`) & Cross-Domain Route Enrichment

- [x] 2.1 Extend `VSX_GENERIC_OBJECT_CLASSES` and `VSXRelationshipManager` in `src/arodonata/core/services/asset_service.py` to query `com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj` (`vsid == 0`) and `com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj` (`vsid > 0`), link cross-domain VS assets via `targetCustomer` and `vsxGateway`, and merge slot `interfaces`, `interfaces_installed`, `routes`, and `routes_installed` onto matching VS assets (`CpmiVsNetobj` / `CpmiVsClusterNetobj`).
- [x] 2.2 Add unit tests in `tests/unit/test_asset_service.py` verifying that `CpmiVsxSlotObj` and `CpmiVsSlotObj` in a VSX domain link a `CpmiVsNetobj` / `CpmiVsClusterNetobj` in a different `targetCustomer` domain and preserve slot `interfaces` and `routes` on the VS asset, and verify `uv run pytest tests/unit/test_asset_service.py` passes.

## 3. `TopologyService` Extraction, Group Expansion & Candidate Matching

- [x] 3.1 Implement `TopologyService` in `src/arodonata/core/services/topology_service.py` (and export in `src/arodonata/core/services/__init__.py`):
  - Target filtering (`simple-gateway`, `simple-cluster` / `CpmiGatewayCluster`, `virtual-system` / `CpmiVsNetobj` / `CpmiVsClusterNetobj`; skipping `cluster-member`, `CpmiVsxNetobj` / `CpmiVsxClusterNetobj` `VS0`, and `checkpoint-host` / `mds`).
  - Multi-format interface normalization (`show-gateways-and-servers`, `show-simple-gateway`, `show-simple-cluster`, `show-generic-object` / `CpmiVsSlotObj`) with on-demand detail fallback when `interfaces` is empty.
  - Static topology extraction: `"external_interface"` (`leads-to-internet` / `topology == "external"`), `"interface_connected"` (`ip/mask`), `"interface_specific"` (cycle-safe recursive `group` / `network` / `host` / `address-range` expansion from `arodonata_objects` with `"Global"` fallback), `"vs_static_route"` (mapping VS static routes to VS interfaces via explicit interface name or next-hop IP containment in connected VS subnets, including `0.0.0.0/0` external marking), and structured warning logs for unresolvable `"network defined by routing"` / `"not defined"` interfaces.
  - `refresh_topology` and `stream_refresh_topology` coordinated via `DomainSyncCoordinator` (`scope="topology"`, `item_type="*"`), plus `get_gateway_topology` and `find_affected_gateways(sources, destinations, ...)` implementing longest-prefix internal matching, `"external"` (`0.0.0.0/0`) fallback, same-interface exclusion (`src_interface == dst_interface`), and policy package / access layer resolution.
- [x] 3.2 Update `SearchService.get_cache_status` in `src/arodonata/core/services/search_service.py` to include `"topology"` scope when inspecting synchronization state.
- [x] 3.3 Create `tests/unit/test_topology_service.py` testing:
  - Skipping `cluster-member` and `CpmiVsxNetobj` (`VS0`) while indexing `CpmiGatewayCluster`, `simple-gateway`, `CpmiVsNetobj`, and `CpmiVsClusterNetobj`.
  - Connected subnet calculation, recursive nested group expansion (including cycle protection and `"Global"` objects), and warning emission on `"network defined by routing"`.
  - VS static route next-hop resolution to VS interfaces and `0.0.0.0/0` default route external interface marking.
  - `find_affected_gateways` across `internal_to_internal`, `internal_to_external`, and `external_to_internal` flows, excluding gateways where both endpoints sit behind the same internal interface or both fall back to `external`, and enriching candidates with `domain_name`, `installed_access_policy`, `policy_packages`, and `access_layers`.
  - Verify `uv run pytest tests/unit/test_topology_service.py` passes.

## 4. `ArodonataClient` Facade & MCP Tool Surface

- [x] 4.1 Wire `TopologyService` into `ArodonataClient` (`src/arodonata/client.py`), expose `topology_service`, `refresh_topology`, `stream_refresh_topology`, `get_gateway_topology`, and `find_affected_gateways`, and export the new models/service in `src/arodonata/__init__.py`.
- [x] 4.2 Extend `cache_control` in `src/arodonata/mcp/tools.py` to accept `scope="topology"`, register the `locate_gateways(sources, destinations, mgmt_name=..., domain=..., cache_mode="smart")` MCP tool, and update MCP prompt guidance in `src/arodonata/mcp/prompts.py`.
- [x] 4.3 Add facade and MCP unit tests in `tests/unit/test_client_facade.py` and `tests/unit/test_mcp_tools.py` covering `client.find_affected_gateways`, `cache_control(scope="topology")`, and `locate_gateways`, and run full quality gates (`uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src`, `uv run pytest`, `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix`, `openspec validate --specs --no-interactive`).

## Workflow follow-up

- Run `/openspec-archive-change` and `/archive-task` once implementation and verification are complete.
