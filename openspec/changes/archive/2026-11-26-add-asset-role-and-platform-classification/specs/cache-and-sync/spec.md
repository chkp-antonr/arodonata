# Spec Delta

## ADDED Requirements

### Requirement: Vendor-Neutral Asset Role and Platform Classification

**ID**: REQ-CACHE-019\
**Intent**: Expose vendor-neutral Asset role, platform, and target flags.\
**Non-goals**: Customer hostname rules or live SSH probing.

`Asset` SHALL expose `management_blades`, `asset_role`, `platform_family`, `is_policy_target`, and `is_execution_target` from API metadata; asset enrichment SHALL inherit parent cluster fields and isolate VSX links; and asset/search/MCP queries SHALL normalize `"mds"`/`"CpmiMds"` and support role/platform filtering consistently.

#### Scenario: SCN-CACHE-019-1 — Vendor-neutral role classification across gateways, clusters, VSX, management, and log servers

- **GIVEN** raw Check Point asset payloads for standalone gateways (`simple-gateway`, `CpmiGatewayPlain`), clusters (`simple-cluster`, `CpmiGatewayCluster`), cluster members (`cluster-member`, `CpmiClusterMember`), VSX hosts/clusters/members/virtual systems, `mds`, `checkpoint-host` / `CpmiHostCkp` servers with `management-blades` or `network-security-blades`, and `interoperable-device`
- **WHEN** `Asset.from_cp_dict()` or `classify_asset_role()` classifies each asset
- **THEN** `asset_role` SHALL resolve deterministically across `"gateway"`, `"cluster"`, `"cluster_member"`, `"vsx_gateway"`, `"vsx_cluster"`, `"vsx_cluster_member"`, `"virtual_system"`, `"management_server"`, `"mds"`, `"log_server"`, `"interoperable_device"`, and `"unknown"`
- **AND** `is_policy_target` SHALL match `is_policy_enforcing_gateway()` (`True` only for `"gateway"`, `"cluster"`, and `"virtual_system"`, preserving `CpmiHostCkp` with `firewall=True` as `"gateway"`), while `is_execution_target` SHALL be `True` only for OS-backed execution hosts (`"gateway"`, `"cluster_member"`, `"vsx_gateway"`, `"vsx_cluster_member"`, `"management_server"`, `"mds"`, `"log_server"`)

#### Scenario: SCN-CACHE-019-2 — Vendor-neutral platform family classification across Gaia, Gaia Embedded, Maestro, CloudGuard, and Open Server

- **GIVEN** Check Point asset payloads with vendor `os-name`, `hardware`, or `raw_data` platform metadata (and ignoring arbitrary `name`, `comments`, or `tags`)
- **WHEN** `Asset.from_cp_dict()` or `classify_asset_platform()` classifies `platform_family`
- **THEN** it SHALL classify `"gaia_embedded"` before generic `"gaia"`, `"maestro"` (`MHO`/`SMO`/`SGM`/`Orchestrator`/`Scalable Platform`), `"cloudguard"` (CloudGuard/AWS/Azure/GCP/VMSS), `"open_server"`, `"gaia"`, or `"unknown"` strictly from vendor attributes

#### Scenario: SCN-CACHE-019-3 — Cluster member metadata inheritance and re-classification during ClusterRelationshipManager enrichment

- **GIVEN** a parent cluster (`simple-cluster`, `CpmiGatewayCluster`, `vsx-cluster`, or `CpmiVsxClusterNetobj`) carrying `hardware`, `os_name`, and `version`, and linked child members missing one or more of those fields
- **WHEN** `ClusterRelationshipManager.enrich()` enriches the assets
- **THEN** each linked member SHALL inherit missing `hardware`, `os_name`, and `version` from its parent cluster without overwriting non-empty member values
- **AND** `ClusterRelationshipManager` SHALL recompute member `asset_role` (promoting `"cluster_member"` under a VSX cluster parent to `"vsx_cluster_member"`), `platform_family`, `is_policy_target`, and `is_execution_target`

#### Scenario: SCN-CACHE-019-4 — Cache persistence, in-place schema migration, and role/platform filtering and grouping

- **GIVEN** an existing `arodonata_assets` cache table (including legacy rows with `NULL` classification columns) and newly synced assets
- **WHEN** `DatabaseManager.initialize()` evolves the schema, `Asset` rows are round-tripped through `arodonata_assets`, and callers invoke `get_assets()`, `get_gateways()`, `query_objects()`, `describe_objects()`, MCP `list_assets()`, or MCP `query_objects()`
- **THEN** missing classification columns SHALL migrate in place without wiping cached rows and legacy `NULL` rows SHALL auto-classify on hydration
- **AND** `get_assets()`, `get_gateways()`, and MCP `list_assets()` SHALL support `roles` and `platforms` filtering, while `query_objects()` and `describe_objects()` SHALL support filtering (`roles`, `platforms`, `is_policy_target`, `is_execution_target`) and `group_by` across `asset_role`, `platform_family`, `is_policy_target`, and `is_execution_target` (including `"role"` and `"platform"` aliases)

#### Scenario: SCN-CACHE-019-5 — Canonical MDS asset routing, VSX member/self-link isolation, and MCP query_objects asset-scope parity

- **GIVEN** `"mds"` / `"CpmiMds"` assets, `vsx_cluster_member`/`vs_netobj` underscore aliases, VSX/cluster parent-child link candidates (parent lists, slot objects, pass-2 cluster links), and MCP `query_objects` calls grouping by `role`/`asset_role`/`platform`/`platform_family`/`is_policy_target`/`is_execution_target` with `types=None`
- **WHEN** callers normalize aliases, query, look up, search, enrich VSX/cluster relationships, or invoke MCP `query_objects`
- **THEN** every `ASSET_TYPE_EQUIVALENTS` alias (including `vsx_cluster_member` and `vs_netobj`) and `"mds"`/`"CpmiMds"` SHALL normalize and route cleanly to `scope="assets"`, and VSX/cluster enrichment SHALL exclude cluster members, VSX parents, Virtual Systems (from cluster members), and self-links across parent lists, slots, and cross-domain links
- **AND** MCP `query_objects` SHALL pass normalized `group_by` and asset classification filters to scope resolution so live quota, cold-cache auto-upgrade, and `cache_age_seconds` evaluate against `scope="assets"`
