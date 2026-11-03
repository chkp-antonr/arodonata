# Cache, Synchronization, and Search Specification (Delta)

## ADDED Requirements

### Requirement: Gateway Interface Topology Persistence and Coordinator Synchronization

`SqlCacheAdapter` and `DatabaseManager` SHALL persist normalized gateway topology intervals in `arodonata_gateway_topology` (registered in `ARODONATA_TABLE_NAMES`), and `TopologyService` (`refresh_topology`, `stream_refresh_topology`) SHALL synchronize domain topology under `DomainSyncCoordinator` (`scope="topology"`, `item_type="*"`) with atomic per-domain replacement (`replace_domain_topology`).

#### Scenario: Atomic domain topology replacement and sync state recording

- **WHEN** `await client.refresh_topology(mgmt_name="mds1", domains=["Domain4"], mode="force")` completes
- **THEN** `TopologyService` SHALL ensure domain assets and network objects are fresh, compute all `GatewayTopologyEntry` rows for `"Domain4"`, atomically replace existing `"Domain4"` rows in `arodonata_gateway_topology` alongside the updated `arodonata_domain_sync_state` row (`scope="topology"`, `item_type="*"`), and expose `"topology"` freshness in `SearchService.get_cache_status()`

### Requirement: VSX Slot Generic Object Enrichment for Cross-Domain Virtual Systems

`VSXRelationshipManager` SHALL query `com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj` (`vsid == 0`) and `com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj` (`vsid > 0`) in addition to `CpmiVsxNetobj`, `CpmiVsxClusterNetobj`, `CpmiVsNetobj`, and `CpmiVsClusterNetobj`, linking cross-domain Virtual Systems via `targetCustomer` and `vsxGateway` and preserving slot `interfaces`, `interfaces_installed`, `routes`, and `routes_installed` on the Virtual System asset.

#### Scenario: VSX slot objects in the VSX domain link a Virtual System in a tenant domain and attach VS routes

- **WHEN** a VSX gateway's domain stores a `CpmiVsxSlotObj` (`vsid=0`, `vsxGateway="vsx-uid"`) and a `CpmiVsSlotObj` (`vsid=1`, `name="VS_Tenant"`, `targetCustomer="TenantDomain"`, `vsxGateway="vsx-uid"`, `routes=[...]`), while the `CpmiVsNetobj` asset `"VS_Tenant"` lives in `"TenantDomain"` without a direct `vsx-gateway` field
- **THEN** `VSXRelationshipManager` SHALL link `" mds1:TenantDomain:VS_Tenant"` to parent `"mds1:VSXDomain:<vsx-name>"` and merge the slot's `routes` and `interfaces` metadata onto the `"VS_Tenant"` asset's `raw_data`
