# Proposal: Consolidate MCP Tool Surface Around Cache Tables (`mcp-tool-consolidation`)

## Why

Exposing 24–34 fine-grained MCP tools that mirror individual Check Point Management API commands (`show_hosts`, `show_networks`, `show_address_ranges`, `show_dns_domains`, `show_groups`, four separate `show_*_rulebase` tools, duplicate `show_object`/`find_object`, etc.) consumes a disproportionate share of LLM tool limits (such as OpenAI's 128-tool cap), inflates per-turn prompt token usage with repeated JSON Schemas, and creates singular/plural (`show_*`) and subtype-guessing ambiguity for LLM agents. Furthermore, `find_object` and `show_object` currently omit `arodonata_assets` and `arodonata_rulebase_layer`, causing unnecessary live API fallbacks when inspecting cached gateways, clusters, VSX systems, or layers.

## What Changes

- **BREAKING**: Consolidate the MCP tool surface in `src/arodonata/mcp/tools.py` from 24–34 tools down to **13 base cache-aligned tools** (plus 5 opt-in CPCRUD tools when `ARODONATA_MCP_CPCRUD=true`), separating collection listing (`list_*`) from single-entity/rulebase inspection (`show_*`):
  1. `list_domains`: List cached domains and MDS server assignments from `arodonata_domains` (replaces `show_domains`).
  2. `list_objects`: List cached network objects from `arodonata_objects` with `types` filter (`"host"`, `"network"`, `"address-range"`, `"dns-domain"`, `"group"`, etc., plus short aliases), replacing `show_hosts`, `show_networks`, `show_address_ranges`, `show_dns_domains`, and `show_groups`.
  3. `list_services`: List cached services from `arodonata_services` with `types` filter (accepting both short aliases `"tcp"`, `"udp"`, `"icmp"`, `"group"`, `"other"` and canonical `"service-*"` names), replacing `show_services`.
  4. `list_assets`: List cached gateways, clusters, cluster members, VSX gateways/clusters, virtual systems, and management servers (`checkpoint-host`) from `arodonata_assets` with `types` and `parent` (cluster or VSX UID/name) filters, replacing `show_gateways_and_servers`.
  5. `show_object`: Inspect a single cached entity across `arodonata_objects`, `arodonata_services`, `arodonata_assets` (including cached `interfaces`, `network_security_blades`, `member_uids`, and `virtual_system_uids`), and `arodonata_rulebase_layer` / `arodonata_rulebase_package_layer` (replacing `show_object` and `find_object`). Supports:
     - Exact UID or case-insensitive name match (`match_type="exact"`, returning full object details).
     - Explicit wildcard patterns (`*`, `?` in `uid_or_name`, `match_type="wildcard"`, evaluated strictly via anchored `fnmatchcase` without implicit prefix/suffix wildcards).
     - Substring candidate fallback when no exact match exists (`match_type="substring_candidates"`), returning a paginated compact candidate list bounded by `limit` (default `20`, max `500`) and `offset` (default `0`) instead of an empty error.
  6. `show_rulebase`: Unified hybrid rulebase and policy catalog tool over `arodonata_rulebase_*` with `rulebase_type: Literal["access", "nat", "https", "threat"] = "access"`, replacing `show_access_rulebase`, `show_nat_rulebase`, `show_https_rulebase`, `show_threat_rulebase`, and `show_policy_packages`. When called without `package` or `layer` (or when a requested target is not found), returns the domain's cached policy packages (`arodonata_rulebase_package_layer`) and all layers including inline layers and `implicit_cleanup_action` (`arodonata_rulebase_layer`) instead of a bare error.
  7. `locate_rules`: Locate SmartConsole rule numbers and layer prefixes across cached packages and layers.
  8. `search_objects`: Search cached objects across IPv4, CIDR, range, wildcard, UID, or name with recursive parent group memberships.
  9. `get_group_members`: Expand direct and recursive members of a network group (`arodonata_objects`), service group (`arodonata_services`), or cluster / VSX container (`arodonata_assets`) from cache.
  10. `query_objects`: Execute cross-domain filtering, grouping (`group_by`), and aggregation (`aggregate: Literal["list", "count", "describe"] = "list"`) over `arodonata_objects`, `arodonata_services`, and `arodonata_assets`, folding `describe_objects` into `aggregate="describe"` (and documenting filterable/groupable fields directly in the tool schema).
  11. `cache_control`: Inspect cache freshness (`action="status"`) or trigger domain synchronization (`action="refresh"`) across scopes (`"domains"`, `"objects"`, `"services"`, `"assets"`, `"rulebase"`), replacing `cache_status` and `refresh_cache`.
  12. `change_report`: Collect and render auditable session/date-range change reports.
  13. `api_call`: Execute direct Check Point Management Web API commands (read-only by default unless `ARODONATA_MCP_ALLOW_WRITE_API=true`), superseding the separate `ARODONATA_MCP_LIVE_COMPAT` wrapper tools.
- **BREAKING**: Consolidate `cpcrud_publish_staged` and `cpcrud_discard_staged` into a single `cpcrud_staged_session(session_uid, action: Literal["publish", "discard"], ...)` tool when `ARODONATA_MCP_CPCRUD=true`.
- Enhance `ArodonataClient.find_object()` and `ArodonataClient.get_group_members()` (`SearchService.get_group_members()`) so SDK callers also resolve cached `Asset` records from `arodonata_assets` and expand `service-group` (`arodonata_services`) and cluster/VSX members (`arodonata_assets`).
- Update MCP prompt templates (`src/arodonata/mcp/prompts.py`) and unit/integration tests to reference the consolidated tool names.

## Capabilities

### New Capabilities

<!-- None: all changes refine existing capabilities under openspec/specs/. -->

### Modified Capabilities

- `mcp-server`: Consolidate the MCP tool surface into 13 cache-aligned base tools (`list_domains`, `list_objects`, `list_services`, `list_assets`, `show_object`, `show_rulebase`, `locate_rules`, `search_objects`, `get_group_members`, `query_objects`, `cache_control`, `change_report`, `api_call`) and 5 opt-in CPCRUD tools (`cpcrud_validate`, `cpcrud_plan`, `cpcrud_apply`, `cpcrud_inverse`, `cpcrud_staged_session`), adding multi-table `show_object` resolution with strict explicit wildcards and bounded substring candidates (`limit=20`), `show_rulebase` package/layer catalog discovery when `package`/`layer` is omitted or unmatched, and `query_objects(aggregate="describe")`.
- `client-and-facade`: Extend `ArodonataClient.find_object` to search `arodonata_assets` (`Asset`) in addition to `arodonata_objects` (`CPObject`) and `arodonata_services` (`CPService`), and extend `get_group_members` to resolve `service-group` members from `arodonata_services` and cluster/VSX child assets from `arodonata_assets`.

## Impact

- **Specifications**: `openspec/specs/mcp-server/spec.md`, `openspec/specs/client-and-facade/spec.md`.
- **Codebase**: `src/arodonata/mcp/tools.py`, `src/arodonata/mcp/prompts.py`, `src/arodonata/client.py`, `src/arodonata/core/services/search_service.py`.
- **Tests**: `tests/unit/test_mcp_tools.py`, `tests/unit/test_client.py`, `tests/unit/test_search_service.py`, `tests/integration/b7/test_mcp_tools.py`.
