# Design

## Context

See `proposal.md` for motivation and `specs/cache-and-sync/spec.md` (`REQ-CACHE-019`) for normative contracts.

Today in Arodonata v2:

1. `Asset` (`src/arodonata/core/models/assets.py`) stores `type`, `os_name`, `hardware`, `version`, `network_security_blades`, and parent-child topology links (`parent_uid`, `member_uids`, `virtual_system_uids`), but lacks `management_blades`, normalized role (`asset_role`), normalized platform (`platform_family`), and policy/execution target flags (`is_policy_target`, `is_execution_target`).
2. `ClusterRelationshipManager.enrich()` (`src/arodonata/core/services/_asset_linking.py`) links cluster members to parent clusters (`parent_uid`, `member_uids`), yet leaves `hardware`, `os_name`, and `version` unset on members when Check Point omits them from member objects.
3. Policy-enforcing classification lives exclusively inside `is_policy_enforcing_gateway()` (`src/arodonata/core/services/topology/_shared.py`), forcing callers outside `TopologyService` to duplicate type and `network_security_blades` checks when separating policy targets from physical CLI/upgrade targets.
4. `AssetRecord` (`src/arodonata/adapters/storage/tables.py`) has no columns for `management_blades`, `asset_role`, `platform_family`, `is_policy_target`, or `is_execution_target`, and `SearchService.query_objects()` / `describe_objects()` cannot filter or group assets by role or platform.

## Goals / Non-Goals

**Goals:**

- Separate **role** (`AssetRole`) from **platform** (`AssetPlatform`) as orthogonal, vendor-neutral literals derived strictly from Check Point API attributes.
- Maintain 100% parity between `Asset.is_policy_target` and `is_policy_enforcing_gateway()` (`REQ-TOPO-002`).
- Provide `Asset.is_execution_target` to distinguish OS-backed hosts (`ssh`/`run-script`/`cpinfo`/`cdt` targets) from logical containers (`cluster`, `virtual_system`, `interoperable_device`).
- Inherit missing `hardware`, `os_name`, and `version` from parent clusters onto cluster members in `ClusterRelationshipManager.enrich()` and re-classify immediately.
- Evolve `arodonata_assets` in place via nullable SQLModel columns so existing SQLite/PostgreSQL caches are preserved and legacy `NULL` rows auto-classify on hydration.
- Preserve `AssetCachePort.get_assets()` backward compatibility for custom test doubles while supporting `roles` / `platforms` filters on `AssetRefreshService.get_assets()`, `ArodonataClient.get_gateways()`, and `SearchService.query_objects()` / `describe_objects()`.

**Non-Goals:**

- Customer-specific hostname regexes, site naming conventions, or customer-specific platform heuristics.
- Live SSH/CPRID probing during `Asset` classification or cache hydration.
- Breaking changes to `AssetCachePort` or existing `Asset` constructor calls.

## Decisions

### 1. Orthogonal Role (`AssetRole`) and Platform (`AssetPlatform`) Taxonomies

- **Choice**: Define explicit `Literal` types and frozen target sets in `src/arodonata/core/models/assets.py`:
  - `AssetRole`: `"gateway"`, `"cluster"`, `"cluster_member"`, `"vsx_gateway"`, `"vsx_cluster"`, `"vsx_cluster_member"`, `"virtual_system"`, `"management_server"`, `"mds"`, `"log_server"`, `"interoperable_device"`, `"unknown"`.
  - `AssetPlatform`: `"gaia"`, `"gaia_embedded"`, `"maestro"`, `"cloudguard"`, `"open_server"`, `"unknown"`.
  - `POLICY_TARGET_ROLES: frozenset[str] = frozenset({"gateway", "cluster", "virtual_system"})`.
  - `EXECUTION_TARGET_ROLES: frozenset[str] = frozenset({"gateway", "cluster_member", "vsx_gateway", "vsx_cluster_member", "management_server", "mds", "log_server"})`.
- **Role Classification Precedence (`classify_asset_role`)**:
  1. `"interoperable-device"` -> `"interoperable_device"`.
  2. Virtual systems (`"virtual-system"`, `"vs-netobj"`, `"CpmiVsNetobj"`, `"CpmiVsClusterNetobj"`) -> `"virtual_system"`.
  3. VSX cluster members (`"vsx-cluster-member"`, `"CpmiVsxClusterMember"`, or a cluster member whose raw parent metadata / enriched parent indicates VSX) -> `"vsx_cluster_member"`.
  4. Cluster members (`"cluster-member"`, `"CpmiClusterMember"`) -> `"cluster_member"`.
  5. VSX clusters (`"vsx-cluster"`, `"CpmiVsxClusterNetobj"`) -> `"vsx_cluster"`.
  6. VSX gateways (`"vsx-gateway"`, `"CpmiVsxNetobj"`) -> `"vsx_gateway"`.
  7. Clusters (`"simple-cluster"`, `"cluster"`, `"CpmiGatewayCluster"`) -> `"cluster"`.
  8. MDS (`"mds"`, `"CpmiMds"`, or `management_blades.get("multi-domain-server") is True`) -> `"mds"`.
  9. Management / Log hosts (`"checkpoint-host"`, `"CpmiHostCkp"`):
     - If `type == "CpmiHostCkp"` and `network_security_blades.get("firewall") is True` -> `"gateway"` (preserves `REQ-TOPO-002` / `is_policy_enforcing_gateway()`).
     - Else if `management_blades.get("network-policy-management") is True` or `management_blades.get("secondary") is True` or `management_blades.get("primary") is True` or `management_blades.get("smart-event-server") is True` -> `"management_server"`.
     - Else if `management_blades.get("logging-and-status") is True` (without policy management blades) -> `"log_server"`.
     - Else -> `"management_server"` (default for `checkpoint-host` / `CpmiHostCkp` when blade flags are absent).
  10. Gateways (`"simple-gateway"`, `"gateway"`, `"CpmiGatewayPlain"`) -> `"gateway"`.
  11. Substring fallback mirroring `is_policy_enforcing_gateway()` (`"member"`, `"vsx"`, `"checkpoint-host"`, `"gateway"`, `"cluster"`, `"virtual-system"`), else `"unknown"`.
- **Platform Classification Precedence (`classify_asset_platform`)**:
  - Inspect strictly vendor metadata (`os_name`, `hardware`, and vendor `raw_data` keys such as `os-name`, `appliance`, `platform`, `model`, `deployment-type`) — NEVER `Asset.name`, `comments`, or `tags`:
    1. `"gaia_embedded"`: `"gaia embedded"` or `"smb"` / `"quantum spark"` in `os_name` or vendor hardware/platform tokens.
    2. `"maestro"`: `"maestro"`, `"scalable platform"`, `"mho"`, `"smo"`, or `"sgm"` word tokens in `os_name` / `hardware` / vendor platform fields.
    3. `"cloudguard"`: `"cloudguard"`, `"ve-series"`, `"virtual edition"`, or cloud vendor tokens (`"aws"`, `"azure"`, `"gcp"`, `"vmss"`) in `hardware` / `os_name` / vendor platform fields.
    4. `"open_server"`: `"open server"` in `hardware` / vendor platform fields.
    5. `"gaia"`: `"gaia"` in `os_name` (when not embedded) or Check Point hardware appliance indicators with Gaia OS.
    6. `"unknown"` otherwise.
- **Model Integration**: Populate `management_blades` in `Asset.from_cp_dict()` from `management-blades` / `management_blades`, and auto-compute missing classification fields inside `Asset.model_post_init()` via `self.model_fields_set` (so explicit overrides in tests/callers are preserved while default construction always produces consistent values).
- **Rationale**: Computing classification deterministically in `Asset.model_post_init()` guarantees every `Asset` instance—whether built from Check Point JSON, constructed in unit tests, or hydrated from a legacy cache row—carries consistent classification without extra service calls.

### 2. Cluster Member Metadata Inheritance & Re-Classification

- **Choice**: In `ClusterRelationshipManager.enrich()` (`src/arodonata/core/services/_asset_linking.py`), after linking cluster members to parents (`_link_parent_and_child_assets`), inherit `hardware`, `os_name`, and `version` when the member's value is `None` or whitespace-empty (`not str(val or "").strip()`) and the parent cluster has a non-empty value. Re-run `classify_asset()` on the updated member, passing `parent_type=parent_asset.type` so `"cluster-member"` assets under `"vsx-cluster"` / `"CpmiVsxClusterNetobj"` promote cleanly to `"vsx_cluster_member"`.
- **Rationale**: Check Point often omits `hardware` on cluster member dictionaries and labels VSX cluster members generically as `"cluster-member"`. Re-classifying after parent enrichment resolves both issues in one place.

### 3. In-Place Nullable Schema Evolution on `arodonata_assets`

- **Choice**: Add `management_blades: dict[str, Any] | None` (JSON column, nullable), `asset_role: str | None` (indexed, nullable), `platform_family: str | None` (indexed, nullable), `is_policy_target: bool | None` (indexed, nullable), and `is_execution_target: bool | None` (indexed, nullable) to `AssetRecord` (`src/arodonata/adapters/storage/tables.py`).
- **Rationale**: Per `DatabaseManager` (`src/arodonata/adapters/storage/database.py`), adding nullable columns triggers safe in-place `ALTER TABLE ADD COLUMN` rather than dropping and recreating `arodonata_assets` (`I1`). In `_record_to_asset()`, omit any `None` classification columns when instantiating `Asset(...)` so `Asset.model_post_init()` automatically backfills legacy rows on read, while `_asset_to_row()` persists all populated fields on write.
- **Alternative considered**: Making new columns `NOT NULL` was rejected because `DatabaseManager` would drop and recreate `arodonata_assets`, wiping warm caches on upgrade.

### 4. Backwards-Compatible Filtering, Grouping, and Topology Alignment

- **Choice**:
  - Keep `AssetCachePort.get_assets(self, mgmt_name=None, domain_name=None, *, types=None)` unchanged so existing custom `CachePort` doubles remain compatible; apply `roles` and `platforms` filtering (case-insensitive normalized sequences) inside `AssetRefreshService.get_assets()` and expose `roles` and `platforms` on `ArodonataClient.get_gateways()`.
  - Add `"asset_role"`, `"platform_family"`, `"is_policy_target"`, `"is_execution_target"` to `ALLOWED_QUERY_GROUP_BY_FIELDS` and `"role": "asset_role"`, `"platform": "platform_family"` to `QUERY_GROUP_BY_ALIASES` (`src/arodonata/core/models/common.py` and `src/arodonata/core/services/search/query.py`). Also add `roles: Sequence[str] | None = None` / `platforms: Sequence[str] | None = None` support on `SearchService.query_objects()` / `ArodonataClient.query_objects()` and expose `asset_roles` / `asset_platforms` breakdowns plus new filterable/groupable fields in `describe_objects()`.
  - Align `is_policy_enforcing_gateway(asset)` in `src/arodonata/core/services/topology/_shared.py` with `asset.is_policy_target` (delegating to `classify_asset_role(asset) in POLICY_TARGET_ROLES`) so `TopologyService` and `Asset` can never drift.

### 5. Deep Audit Hardening (Branch Delta Remediation)

- **MCP `query_objects` Asset Scope Parity (`DA-003`, `DA-004`)**: In `src/arodonata/mcp/tools/objects.py`, parse and validate `group_by` via `_parse_and_validate_group_by(group_by)` before calling `resolve_query_scopes()`, passing `group_by_attrs=parsed_group_by` so queries with `types=None` grouping by `role`/`asset_role`, `platform`/`platform_family`, `is_policy_target`, or `is_execution_target` route `target_scopes` to `("assets", None)` for cold-cache auto-upgrade, `_enforce_live_quota_if_sync_required`, and `_compute_cache_age`.
- **Canonical `"mds"` / `"CpmiMds"` Asset Routing (`DA-023`)**: Add `"mds"` and `"CpmiMds"` to `CANONICAL_ASSET_TYPES`, add `(("mds", "cpmimds"), ("mds", "CpmiMds"))` as a dedicated group in `_ASSET_EQUIVALENT_GROUPS`, and map `"cpmimds": "mds"` in `ASSET_TYPE_ALIASES` (`src/arodonata/core/models/common.py`) without merging them into `checkpoint-host`/`CpmiHostCkp` so role distinctions remain intact.
- **VSX Relationship Linking Exclusions (`DA-027`)**: In `VSXRelationshipManager._link_vsx_children_to_parents()` and `reconcile_cross_domain()` (`src/arodonata/core/services/_asset_linking.py`), skip assets whose type is in `CLUSTER_MEMBER_TYPES` (or contains `"member"` case-insensitively) or in `VSX_PARENT_TYPES`, and enforce `parent_asset.uid != curr.uid` / `parent_asset.id != curr.id` self-link guards before calling `_link_parent_and_child_assets(..., list_kind="vsx")`.
- **Quick-Reference Generator & Documentation Sync (`DA-040`, `DA-046`, `DA-048`, `DA-049`)**:
  - In `docs/scripts/build_notebooklm_docs.py`, handle `isinstance(kw.value, ast.Lambda)` in `_compact_field_default()` by unparsing `kw.value.body` cleanly, and remove the `[:8]` slices on `replay_api_sigs` and `mock_http_sigs` in `build_sdk_quickref()`.
  - Update `README.md` (`05-sdk-quickref.md`, 13 OpenSpec capabilities, `01..05.md` rebuild comment) and `AGENTS.md` (add `docs/architecture/`, `docs/scripts/`, `docs-notebooklm/` to the documentation tree).
  - During change finalization, sync `cache-and-sync` and `ai-builder` deltas into `openspec/specs/` before regenerating `docs-notebooklm/04-capabilities-db-mcp-and-openspec.md`.

## Risks / Trade-offs

- **[Risk] Ambiguous vendor hardware or OS strings could misclassify a platform** → Mitigation: Prioritize explicit `os_name` checks (`gaia_embedded` before `gaia`), use word-boundary regexes for short tokens (`mho`, `smo`, `sgm`, `smb`, `aws`, `gcp`), ignore customer-controlled `name`/`comments`/`tags`, and default uncertain payloads to `"unknown"`.
- **[Risk] Legacy cached `AssetRecord` rows have `NULL` for newly added columns before next `refresh_assets()`** → Mitigation: `_record_to_asset()` omits `None` fields when constructing `Asset`, letting `Asset.model_post_init()` compute `asset_role`, `platform_family`, `is_policy_target`, and `is_execution_target` transparently on every read.
- **[Risk] Drift between `Asset.is_policy_target` and `is_policy_enforcing_gateway()`** → Mitigation: Delegate `is_policy_enforcing_gateway()` directly through the shared `classify_asset_role()` logic and assert exact parity across all canonical and `Cpmi*` asset types in unit tests.
- **[Risk] Adding `"mds"`/`"CpmiMds"` to `CANONICAL_ASSET_TYPES` or passing `group_by_attrs` in MCP could break `search_objects`/`show_object` live commands** → Mitigation: Keep `("mds", "CpmiMds")` in its own equivalence group and verify `query_objects`, `find_object`, `search_objects`, `get_gateways`, and MCP `show_object` / `query_objects` quota tests under `SCN-CACHE-019-5`.
