# Design: Cache-Aligned MCP Tool Consolidation (`mcp-tool-consolidation`)

## Context

See `proposal.md` for motivation and the delta specifications under `specs/mcp-server/spec.md` and `specs/client-and-facade/spec.md` for behavioral contracts. In `arodonata_v2`, synchronization (`DomainSyncCoordinator`) populates five SQLite/PostgreSQL cache scopes (`domains`, `objects`, `services`, `assets`, `rulebase`) at `details-level="full"`. However, `src/arodonata/mcp/tools.py` currently exposes 24–34 tools modeled after individual Check Point Web API endpoints, while `ArodonataClient.find_object` and `SearchService.get_group_members` do not consult `arodonata_assets`.

## Goals / Non-Goals

**Goals:**

- Reduce the registered MCP tool count from 24–34 down to **13 base tools** (plus **5 opt-in CPCRUD tools** when `ARODONATA_MCP_CPCRUD=true`) aligned 1-to-1 with Arodonata's cached database tables.
- Disambiguate collection listing (`list_domains`, `list_objects`, `list_services`, `list_assets`) from single-entity or rulebase inspection (`show_object`, `show_rulebase`).
- Eliminate unnecessary live API round-trips when inspecting gateways, clusters, cluster members, VSX systems, virtual systems, management servers (`arodonata_assets`), or rulebase layers (`arodonata_rulebase_layer`) by querying those cached tables directly.
- Replace blind "not found" or "missing parameter" errors in `show_object` and `show_rulebase` with bounded, context-safe discovery payloads (`limit=20` by default) so the agent's next request succeeds without context window overflow.

**Non-Goals:**

- Modifying the underlying SQLite/PostgreSQL table schemas (`src/arodonata/adapters/storage/tables.py`) or `DomainSyncCoordinator` refresh logic.
- Removing `ArodonataClient`'s typed Python convenience methods (`get_hosts`, `get_networks`, `get_address_ranges`, `get_dns_domains`, `get_groups`, `describe_objects`, `get_cache_status`), which remain stable for direct Python SDK consumers.

## Decisions

### 1. Cache-Aligned Tool Taxonomy (13 Base Tools + 5 Opt-In CPCRUD Tools)

| Tool Name | Backing Cache Table(s) / Service | Replaces |
| :--- | :--- | :--- |
| `list_domains` | `arodonata_domains` (`DomainService`) | `show_domains` |
| `list_objects` | `arodonata_objects` (`ObjectService`) | `show_hosts`, `show_networks`, `show_address_ranges`, `show_dns_domains`, `show_groups` |
| `list_services` | `arodonata_services` (`ServiceCacheService`) | `show_services` |
| `list_assets` | `arodonata_assets` (`AssetRefreshService`) | `show_gateways_and_servers` |
| `show_object` | `arodonata_objects`, `arodonata_services`, `arodonata_assets`, `arodonata_rulebase_layer`, `arodonata_rulebase_package_layer` | `show_object`, `find_object` |
| `show_rulebase` | `arodonata_rulebase_package_layer`, `arodonata_rulebase_layer`, `arodonata_rulebase_access` / `_nat` / `_https` / `_threat` | `show_access_rulebase`, `show_nat_rulebase`, `show_https_rulebase`, `show_threat_rulebase`, `show_policy_packages` |
| `locate_rules` | `arodonata_rulebase_*` (`CachedRulebaseSource.locate_rules`) | `locate_rules` |
| `search_objects` | `arodonata_objects` (`SearchService.search_objects`) | `search_objects` |
| `get_group_members` | `arodonata_objects`, `arodonata_services`, `arodonata_assets` | `get_group_members` |
| `query_objects` | `arodonata_objects`, `arodonata_services`, `arodonata_assets` (`aggregate="list" \| "count" \| "describe"`) | `query_objects`, `describe_objects` |
| `cache_control` | `arodonata_domain_sync_state` (`action="status" \| "refresh"`) | `cache_status`, `refresh_cache` |
| `change_report` | `reports` (`client.build_change_report`) | `change_report` |
| `api_call` | `ApiPort.api_call` (with read-only allowlist & dedicated write session isolation) | `api_call`, `where_used`, `show_sessions`, `show_unused_objects`, `show_task` |
| `cpcrud_validate`, `cpcrud_plan`, `cpcrud_apply`, `cpcrud_inverse`, `cpcrud_staged_session` | `CPCRUDService` (registered when `ARODONATA_MCP_CPCRUD=true`) | `cpcrud_validate`, `cpcrud_plan`, `cpcrud_apply`, `cpcrud_inverse`, `cpcrud_publish_staged`, `cpcrud_discard_staged` |

### 2. Alias Normalization for `types` and `obj_type`

LLM agents frequently pass short type names (`"tcp"`, `"udp"`, `"range"`, `"gateway"`, `"cluster"`) instead of Check Point's canonical names (`"service-tcp"`, `"address-range"`, `"simple-gateway"`). We normalize aliases in a central helper:

- **Object aliases (`list_objects` / `show_object` / `query_objects`)**:
  - `"range"` / `"ip-range"` $\rightarrow$ `"address-range"`
  - `"dns"` / `"fqdn"` $\rightarrow$ `"dns-domain"`
  - `"dynamic"` $\rightarrow$ `"dynamic-object"`
- **Service aliases (`list_services` / `show_object` / `query_objects`)**:
  - `"tcp"` $\rightarrow$ `"service-tcp"`
  - `"udp"` $\rightarrow$ `"service-udp"`
  - `"icmp"` $\rightarrow$ `"service-icmp"`
  - `"icmp6"` / `"icmpv6"` $\rightarrow$ `"service-icmp6"`
  - `"sctp"` $\rightarrow$ `"service-sctp"`
  - `"other"` $\rightarrow$ `"service-other"`
  - `"dce-rpc"` $\rightarrow$ `"service-dce-rpc"`
  - `"rpc"` $\rightarrow$ `"service-rpc"`
  - `"group"` / `"svc-group"` (inside `list_services`) $\rightarrow$ `"service-group"`
- **Asset aliases (`list_assets` / `show_object`)**:
  - `"gateway"` $\rightarrow$ `"simple-gateway"`
  - `"cluster"` $\rightarrow$ `"simple-cluster"`
  - `"member"` $\rightarrow$ `"cluster-member"`
  - `"vsx"` $\rightarrow$ `"vsx-gateway"`
  - `"vs"` $\rightarrow$ `"virtual-system"`
  - `"server"` / `"mgmt"` / `"host-ckp"` $\rightarrow$ `"checkpoint-host"`

### 3. `list_assets` Filtering by `types` and `parent`

`list_assets` queries `client.get_gateways(...)` (`arodonata_assets`) and supports:

- `types: list[str] | None = None`: normalized asset types (`"simple-gateway"`, `"simple-cluster"`, `"cluster-member"`, `"vsx-gateway"`, `"vsx-cluster"`, `"virtual-system"`, `"checkpoint-host"`, `"interoperable-device"`).
- `parent: str | None = None`: filters cached assets where `asset.parent_uid == parent` or `asset.parent_name.lower() == parent.lower()`, or where `asset.uid` is in the parent cluster's `member_uids` or parent VSX's `virtual_system_uids`. This allows listing all members of a cluster or all virtual systems of a VSX gateway from cache in one call.
- `limit: int = 50` (max `500`), `offset: int = 0`.

### 4. Three-Tier Matching and Bounded Pagination in `show_object`

`show_object(uid_or_name, mgmt_name=None, domain=None, obj_type=None, details_level="full", limit=20, offset=0, cache_mode="smart")` resolves across:

1. `arodonata_objects` (`CPObject`)
2. `arodonata_services` (`CPService`)
3. `arodonata_assets` (`Asset` — with `interfaces`, `network_security_blades`, `member_uids`, `virtual_system_uids`, and `raw_data` already populated in cache)
4. `arodonata_rulebase_layer` / `arodonata_rulebase_package_layer` (`RulebaseLayerEntry` / `PolicyPackageInfo`)

**Matching Tiers:**

- **Tier 1 — Exact Match (when `uid_or_name` contains no `*` or `?`)**:
  - Checks exact UID match or case-insensitive exact `name` match across the target table(s).
  - If matched, returns immediately with `match_type="exact"`, `from=1`, `to=1`, `total=1`, `object=<full serialized dict>`, `objects=[<full serialized dict>]`.
- **Tier 2 — Explicit Wildcard (when `uid_or_name` contains `*` or `?`)**:
  - Evaluates `fnmatchcase(candidate.name.lower(), uid_or_name.strip().lower())` **strictly as written** (never prepending or appending `*`).
  - If `total == 1`, returns that single object serialized at `details_level` (`"full"` by default) under both `object` and `objects`, with `match_type="wildcard"`.
  - If `total > 1`, slices candidates by `offset` and `limit` (default `20`, capped at `500`), serializes each candidate at compact `"standard"` level (omitting bulky `raw_data` unless `details_level="full"` was explicitly requested with a small limit) so context is not flooded, and returns `match_type="wildcard"`, `from`, `to`, `total`, `objects`.
- **Tier 3 — Substring Candidate Fallback (when no `*`/`?` was passed and Tier 1 found no exact match)**:
  - Searches cached items where `uid_or_name.strip().lower() in candidate.name.lower()`.
  - If `total >= 1`, returns `is_error=False`, `match_type="substring_candidates"`, `object=None` (or the single item if `total == 1`), and `objects` sliced by `offset` and `limit` (default `20`, max `500`) in compact summary format (`uid`, `name`, `type`, `domain_name`, `ipv4_address`/`subnet4`/`port`, `comments`), plus a `hint` explaining that no exact match was found and showing `from..to` of `total` substring candidates.
  - Only if `total == 0` in cache (and `obj_type` or `cache_mode="live"` warrants a live fallback) does it attempt the live `show-<type>` / `show-object` API call.

### 5. Dual-Mode `show_rulebase` (Policy/Layer Discovery + Rulebase View)

`show_rulebase` accepts `rulebase_type: Literal["access", "nat", "https", "threat"] = "access"`, `package: str | None = None`, `layer: str | None = None`, `name: str | None = None`, `uid: str | None = None`, plus existing filter, format (`"markdown" | "model_friendly" | "raw" | "cpcrud"`), pagination, and live-only parameters:

- **Discovery Mode (when `package`, `layer`, `name`, and `uid` are all omitted, OR when the requested package/layer does not exist in the cached domain snapshot)**:
  - Loads the domain's rulebase snapshot (`client._rulebase_source._ensure_and_load_snapshot(...)`).
  - Returns `is_error=False` with:
    - `mode="catalog"` (or `hint` if a requested name was not found),
    - `packages`: serialized `PolicyPackageInfo` entries from `arodonata_rulebase_package_layer`,
    - `layers`: serialized `RulebaseLayerEntry` entries from `arodonata_rulebase_layer` (filtered by `rulebase_type` if specified, including inline layers with `parent_layer_uid`, `parent_rule_uid`, and `implicit_cleanup_action`),
    - `source="cache"`, `cache_age_seconds`.
- **Rulebase Inspection Mode (when a valid `package` or `layer` is provided)**:
  - Executes the existing hybrid cached/live rulebase pipeline (`_run_hybrid_rulebase_tool`).

### 6. Multi-Table `find_object` and `get_group_members` in `ArodonataClient` / `SearchService`

- `ArodonataClient.find_object(mgmt_name, domain, name_or_uid, obj_type=None, ...)`:
  - Searches `arodonata_objects` (`CPObject`), `arodonata_services` (`CPService`), and `arodonata_assets` (`Asset`), returning `CPObject | CPService | Asset | None`.
- `SearchService.get_group_members(mgmt_name, domain, group_name_or_uid, ...)`:
  - First checks `arodonata_objects` for a network `group` / `group-with-exclusion` and expands member `CPObject` items recursively.
  - If not found in `arodonata_objects`, checks `arodonata_services` for a `service-group` and expands member `CPService` items recursively.
  - If not found in `arodonata_services`, checks `arodonata_assets` for a cluster or VSX parent asset (`member_uids` / `virtual_system_uids`) and returns the child `Asset` models from `arodonata_assets`.

## Risks / Trade-offs

- **[Risk] Broad substring fallback (e.g. `show_object("a")`) matching thousands of cached objects** → Mitigation: Default `limit=20` (max `500`) with `offset=0` on `show_object`, and serialize multi-match candidates (`total > 1`) without `raw_data` so 20 candidates consume less than 2 KB of JSON while reporting `"total": <N>` so the model knows to refine its query or paginate.
- **[Risk] Callers passing `types=["tcp", "udp"]` to `list_services` with `cache_mode="live"`** → Mitigation: Normalize short aliases (`"tcp" -> "service-tcp"`) before execution; in `live` mode, fan out across the requested live service/object commands (`show-services-tcp`, `show-services-udp`) and combine the results into a single envelope.
