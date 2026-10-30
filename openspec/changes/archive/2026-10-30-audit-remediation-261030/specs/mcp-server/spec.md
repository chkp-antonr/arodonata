# Spec Delta

## MODIFIED Requirements

### Requirement: Multi-Server Tool Surface and Cache-Backed Envelopes

The MCP server SHALL expose a consolidated cache-aligned tool surface (`list_domains`, `list_objects`, `list_services`, `list_assets`, `show_object`, `show_rulebase`, `locate_rules`, `search_objects`, `get_group_members`, `query_objects`, `cache_control`, `change_report`, `api_call`, and opt-in CPCRUD tools), pre-validating explicit `domain` names against `arodonata_domains` and normalizing short and canonical object/service/asset types.

#### Scenario: List tool response envelope includes source and cache age

- **WHEN** a collection listing tool (`list_domains`, `list_objects`, `list_services`, or `list_assets`) returns a page of objects (including with short or canonical `types` filters such as `types=["tcp", "udp"]` on `list_services` or `parent="..."` on `list_assets`)
- **THEN** the JSON text response SHALL include `from`, `to`, `total`, `source` (`"cache"` or `"live"`), `cache_age_seconds`, and `objects` sliced by `limit` and `offset`

#### Scenario: Single-entity show_object resolves across objects, services, assets, and layers with wildcard and substring fallback

- **WHEN** `show_object(uid_or_name=..., mgmt_name=..., domain=..., limit=20, offset=0)` is called
- **THEN** it SHALL search `arodonata_objects`, `arodonata_services`, `arodonata_assets`, and `arodonata_rulebase_layer` / `arodonata_rulebase_package_layer` (using `cache_mode="cache"` and including `"Global"` whenever `domain` is omitted):
  - if `uid_or_name` contains no `*` or `?` and matches in exactly one domain, it SHALL return that single entity with `match_type="exact"` and full details;
  - if `domain` is omitted and `uid_or_name` matches exact entities in more than one domain, it SHALL return `match_type="ambiguous"` with `object=None` and `objects` listing the matching candidates across domains so the caller can disambiguate;
  - if `uid_or_name` contains an explicit wildcard (`*` or `?`), it SHALL evaluate `fnmatchcase` strictly (`match_type="wildcard"`), returning the full object when `total == 1` or a paginated candidate slice when `total > 1`;
  - if `uid_or_name` contains no wildcard and has no exact match in cache, it SHALL return up to `limit` compact case-insensitive substring candidates (`match_type="substring_candidates"`)

#### Scenario: Rulebase tool switches between cached SmartConsole view and live query

- **WHEN** `show_rulebase(mgmt_name=..., domain=..., rulebase_type="access" | "nat" | "https" | "threat", ...)` is called
- **THEN**:
  - when neither `package` nor `layer` (`name`/`uid`) is provided (or when the requested target name is not found in the domain's cached snapshot), it SHALL return the domain's cached `packages` (`arodonata_rulebase_package_layer`) and `layers` (`arodonata_rulebase_layer`, including inline layers, parent links, and `implicit_cleanup_action`) rather than an unguided error;
  - when a valid `package` or `layer` is provided on a domain with a fresh rulebase snapshot and without live-only parameters (`show_hits`, `order`, `show_as_ranges`, `show_expiration_settings`, `filter_settings`, `hits_settings`, `dereference_group_members`, `show_membership`), it SHALL evaluate any `filter` locally against the cached rulebase and cached objects/services in `markdown`, `model_friendly`, `raw`, or `cpcrud` format;
  - when live-only parameters or `cache_mode="live"` are requested, it SHALL execute a live Management API query (`show-access-rulebase`, `show-nat-rulebase`, `show-https-rulebase`, or `show-threat-rulebase`)

#### Scenario: Unknown domain or rejected login returns actionable ToolFailure

- **WHEN** a tool is called with a `domain` not present in the `arodonata_domains` table (after a single domain-list refresh) or login raises `InvalidCredentialsError`
- **THEN** the server SHALL log the `ToolFailure` at WARNING (without arguments or secrets) and return an actionable error listing known domains on that management server rather than `"internal error: InvalidCredentialsError"`

#### Scenario: Write API protection and SID masking on error

- **WHEN** `api_call` is invoked while `ARODONATA_MCP_ALLOW_WRITE_API=false`, or invoked with a write command while `ARODONATA_MCP_ALLOW_WRITE_API=true`, or when an error message contains an active session SID
- **THEN** when `ALLOW_WRITE_API=false`, `api_call` SHALL permit ONLY commands in the explicit read-only command allowlist (rejecting path traversal, mutating commands, `publish`, `discard`, `logout`, and unlisted commands); when `ALLOW_WRITE_API=true`, mutating `api_call` invocations SHALL execute inside an isolated dedicated session (never the shared `arodonata_sid_cache` session) with bounded `timeout`; and any error text SHALL be sanitized via `redact_sid(..., known_sids=...)`

### Requirement: Tamper-Proof MCP CPCRUD Plan Execution and Staged Session Lifecycle Tools

When `ARODONATA_MCP_CPCRUD=true`, the MCP server SHALL verify that every plan passed to `cpcrud_apply` or `cpcrud_inverse` was issued/signed by `cpcrud_plan`, omit `force`, `validate_schema`, and `server_ip` from MCP CPCRUD tools, cap `retry_remaining` (`<= 3`), and restrict `cpcrud_staged_session(session_uid, action="publish" | "discard", ...)` exclusively to session UIDs staged by `cpcrud_apply(keep_session=True)` in this server process.

#### Scenario: Model-forged or modified plan rejected by cpcrud_apply

- **WHEN** `cpcrud_apply` is called with an unknown `plan_id` or a `plan` payload that was not issued/signed by this server's `cpcrud_plan` tool (or whose `command` / `object_type` / `payload` was altered)
- **THEN** `cpcrud_apply` SHALL reject the request before opening a Check Point session or executing any API call

#### Scenario: Staged CPCRUD session published or discarded via dedicated MCP tools

- **WHEN** `cpcrud_apply(..., no_publish=True, keep_session=True)` stages changes in a dedicated session (recording `(mgmt_name, domain_key, session_uid)` in the server's staged-session registry) and the caller subsequently invokes `cpcrud_staged_session(session_uid=..., action="publish" | "discard", mgmt_name=..., domain=...)`
- **THEN** the tool SHALL verify `session_uid` is registered in this MCP server's staged-session store, adopt the session non-disruptively without exposing `server_ip` or `force_disconnect`, publish (invalidating the domain cache) or discard uncommitted changes, remove the completed entry from the staged store, and log out cleanly

#### Scenario: Unregistered or foreign session UID rejected by cpcrud_staged_session

- **WHEN** `cpcrud_staged_session` is called with a `session_uid` that was not created by `cpcrud_apply(..., no_publish=True, keep_session=True)` in this MCP server instance (for example, a SmartConsole administrator's session UID discovered via `show-sessions`)
- **THEN** `cpcrud_staged_session` SHALL raise `ToolFailure` immediately without opening a Check Point session or calling `take-over-session`, `switch-session`, `publish`, or `discard`

## ADDED Requirements

### Requirement: Cache-Only Cross-Domain Group Lookup and Ambiguity Reporting in MCP

When `get_group_members` is called without `domain` (and `group_name_or_uid` is not a `mgmt:domain:name` composite ID), the MCP server SHALL resolve the target group across cached domains including `"Global"` using `cache_mode="cache"` without triggering whole-MDS logins, and SHALL return a structured `match_type="ambiguous"` candidate response when matching groups exist in more than one domain.

#### Scenario: Cross-domain MCP get_group_members reports ambiguity without whole-MDS sync

- **WHEN** `get_group_members(group_name_or_uid="SharedAdmins")` is invoked without `domain` and `"SharedAdmins"` exists in multiple cached domains
- **THEN** the tool SHALL perform zero remote domain refreshes and return `match_type="ambiguous"` with the candidate domain/composite-ID list so the caller can re-query with an explicit `domain` or `mgmt:domain:name`
