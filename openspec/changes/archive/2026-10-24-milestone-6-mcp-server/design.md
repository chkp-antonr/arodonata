# Design: Milestone 6 — Streamable-HTTP MCP Server & CLI (`milestone-6-mcp-server`)

## Context

See `proposal.md` for motivation and `openspec/specs/mcp-server/spec.md` for canonical requirements. Milestone 6 completes Arodonata v2 by implementing `src/arodonata/mcp/` (`arodonata[mcp]`), exposing `ArodonataClient` capabilities over Streamable HTTP via both a standalone CLI (`arodonata-mcp`) and embeddable ASGI/server factories (`create_mcp_server`, `create_asgi_app`).

## Goals / Non-Goals

**Goals:**

- Implement `ArodonataMCPSettings` (`src/arodonata/mcp/config.py`) supporting `ARODONATA_MCP_*` environment variables, secret masking in `__repr__`, and standalone CLI validation (`arodonata-mcp` refusing `auth_mode="host"` or `"jwt"` with exit code `2` and validating TLS trust store configuration on startup).
- Implement constant-time static bearer token authentication (`hmac.compare_digest`) mapping the matched environment variable name (`ARODONATA_MCP_TOKEN_VARS="TEAM_A_TOKEN,TEAM_B_TOKEN"`) to `client_id` in `AccessToken` and `UserContext` (`contextvars`), logging the authenticated `client_id` without ever logging the token value, and supporting `auth_mode="host"` pass-through when embedded in an authenticating ASGI host.
- Enforce DNS rebinding and browser `Origin` protection (`allowed_hosts` returning HTTP `421` and `allowed_origins` returning HTTP `403`).
- Provide cache-backed list and object tools (`show_domains`, `show_hosts`, `show_networks`, `show_address_ranges`, `show_dns_domains`, `show_services`, `show_groups`, `show_gateways_and_servers`, `show_object`, `search_objects`, `find_object`, `get_group_members`) with JSON response envelopes containing `from`, `to`, `total`, `source` (`"cache"` or `"live"`), and `cache_age_seconds`, preserving server-level fields on `show_domains` at `details_level="standard"`.
- Pre-validate target `domain` names against the cached `domains` table (with at most a single domain-list refresh on a miss) before attempting server login, translate `InvalidCredentialsError` into actionable `ToolFailure` messages listing known domains, log `ToolFailure` at `WARNING` without arguments or secrets, and return `"internal error: <ExceptionClass>"` for unexpected internal exceptions without leaking stack traces or session SIDs.
- Expose progressive-disclosure aggregation tools (`describe_objects`, `query_objects` distinguishing domain-owned vs `Global` objects via `original_domain`) and `cache_status` across `"domains"`, `"objects"`, `"services"`, `"assets"`, and `"rulebase"` from `domain_sync_state`.
- Expose hybrid rulebase tools (`show_access_rulebase`, `show_nat_rulebase`, `show_https_rulebase`, `show_threat_rulebase`, `show_policy_packages`, `locate_rules`) evaluating `filter` locally against fresh cached rulebase snapshots and cached objects/services in `markdown`, `model_friendly`, or `raw` format, and switching to live Management API queries only when live-only parameters (`show_hits`, `order`, `show_as_ranges`, `show_expiration_settings`, `filter_settings`, `hits_settings`) or `cache_mode="live"` are passed.
- Expose `change_report`, gated `api_call` (`ARODONATA_MCP_ALLOW_WRITE_API=false` rejecting non-`show-*` commands and masking any echoed SIDs), optional live-compatibility tools (`ARODONATA_MCP_LIVE_COMPAT=true`), opt-in CPCRUD tools (`ARODONATA_MCP_CPCRUD=true`), and MCP prompt templates.

**Non-Goals:**

- Implementing a full OAuth2 authorization server or external JWKS verifier inside standalone `arodonata-mcp` (external JWT/OAuth termination belongs in an enclosing ASGI host using `auth_mode="host"`).

## Decisions

### 1. Package Layout (`src/arodonata/mcp/`)

```text
src/arodonata/mcp/
├── __init__.py      # Public exports: ArodonataMCPSettings, ToolFailure, create_mcp_server, create_asgi_app, main
├── config.py        # ArodonataMCPSettings & standalone/trust validation helpers
├── errors.py        # ToolFailure, domain pre-validation, InvalidCredentialsError mapping, SID masking, error wrapper
├── security.py      # StaticTokenVerifier (hmac.compare_digest), Host/Origin ASGI guard (421/403), Bearer auth ASGI guard
├── tools.py         # Tool registration (cached listings, aggregation, cache_status, hybrid rulebase, change_report, api_call, live_compat, cpcrud)
├── prompts.py       # MCP prompt templates (rulebase audit, object search, change report review, cpcrud workflow)
├── server.py        # create_mcp_server & create_asgi_app composition
└── cli.py           # arodonata-mcp CLI entry point (argparse + TLS trust check + standalone auth check + uvicorn)
```

### 2. `ArodonataMCPSettings` & Standalone CLI Validation (`config.py`, `cli.py`)

- `ArodonataMCPSettings` inherits from `pydantic_settings.BaseSettings` with `env_prefix="ARODONATA_MCP_"`:
  - `host: str = "127.0.0.1"`
  - `port: int = 8000`
  - `path: str = "/mcp"`
  - `auth_mode: Literal["static", "host", "jwt", "none"] = "static"`
  - `token_vars: CsvStrList` (`ARODONATA_MCP_TOKEN_VARS`) — comma-separated env var names holding bearer tokens (e.g. `TEAM_A_TOKEN,TEAM_B_TOKEN`).
  - `tokens: CsvStrList` (`ARODONATA_MCP_TOKENS`, `repr=False`) — optional direct token list or `client_id=token` entries.
  - `allowed_hosts: CsvStrList` (`ARODONATA_MCP_ALLOWED_HOSTS`, defaults to `["127.0.0.1:*", "localhost:*", "[::1]:*", "127.0.0.1", "localhost", "[::1]"]`).
  - `allowed_origins: CsvStrList` (`ARODONATA_MCP_ALLOWED_ORIGINS`, defaults to `["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*", "https://127.0.0.1:*", "https://localhost:*", "https://[::1]:*"]`).
  - `enable_dns_rebinding_protection: bool = True`
  - `allow_write_api: bool = False` (`ARODONATA_MCP_ALLOW_WRITE_API`)
  - `live_compat: bool = False` (`ARODONATA_MCP_LIVE_COMPAT`)
  - `cpcrud: bool = False` (`ARODONATA_MCP_CPCRUD`)
  - `json_response: bool = False`
  - `stateless_http: bool = False`
- **Standalone CLI (`arodonata-mcp` / `cli.py:main`)**:
  1. Checks `mcp_settings.auth_mode`: if `auth_mode in ("host", "jwt")`, writes a clear configuration error message to `stderr` explaining that `host`/`jwt` authentication requires embedding inside an ASGI host (`create_mcp_server(..., auth_mode="host")`) and exits with code `2`.
  2. If `auth_mode == "static"` and no tokens are configured in `token_vars` or `tokens`, exits with code `2` and a clear error message.
  3. Instantiates `TrustPolicy(mode=core_settings.tls_trust, known_hosts_path=core_settings.tls_known_hosts_path, pinned_fingerprints=core_settings.tls_fingerprints)` and calls `trust_policy.trust_store.load()` (and in `pinned` mode verifies that at least one pinned fingerprint or known host exists) before starting `uvicorn`. Any `TrustStoreError` or `ConfigurationError` exits with code `2`.

### 3. Security Guards: Constant-Time Static Bearer Auth, `auth_mode="host"`, and DNS Rebinding (`security.py`)

- **`StaticTokenVerifier`**:
  - Resolves `token_vars` from `os.environ` into `list[tuple[str, str]]` of `(env_var_name, token_secret)`. Also supports `tokens` entries (`"client_id:secret"` or `"secret"` -> `f"static_token_{idx}"`).
  - `verify_token(token: str) -> AccessToken | None` iterates over all configured `(client_id, secret)` pairs and compares `hmac.compare_digest(token.encode("utf-8"), secret.encode("utf-8"))` without short-circuiting early so timing does not leak which token slot matched.
  - On match, logs `client_id` at `INFO` (`logger.info("MCP static bearer token verified", client_id=matched_client_id)`) — never logging the token value — and returns `AccessToken(token=REDACTED_PLACEHOLDER, client_id=matched_client_id, scopes=["mcp"])`.
- **ASGI Security Middleware (`MCPOriginHostGuardMiddleware` & `MCPBearerAuthMiddleware`)**:
  - `MCPOriginHostGuardMiddleware` runs outermost on every HTTP request when `enable_dns_rebinding_protection=True`:
    - Validates `Host` header against `allowed_hosts` (supporting exact match and `host:*` wildcard port patterns). If missing or not in `allowed_hosts`, immediately returns HTTP `421 Misdirected Request`.
    - Validates `Origin` header (when present on browser requests) against `allowed_origins` (supporting exact match and `scheme://host:*` wildcard port patterns). If not in `allowed_origins`, immediately returns HTTP `403 Forbidden`.
  - When `auth_mode == "static"`:
    - `MCPBearerAuthMiddleware` inspects `Authorization: Bearer <token>`, calls `StaticTokenVerifier.verify_token(token)`, rejects missing/invalid tokens with HTTP `401 Unauthorized` (`WWW-Authenticate: Bearer`), and binds `user_context(client_id=access_token.client_id)` in `contextvars` for the duration of the request.
  - When `auth_mode == "host"` (or `"none"`):
    - Internal token verification is disabled (`token_verifier=None`), allowing the enclosing Starlette/FastAPI host application's authentication middleware (and any `user_context` / `auth_context` it sets) to govern access.

### 4. Error Handling, Domain Pre-Validation, and SID Hygiene (`errors.py`)

- **`ToolFailure(ArodonataError)`**:
  - Raised for anticipated, actionable tool errors.
  - Logged at `WARNING` via `arlogi` (`logger.warning("MCP ToolFailure", tool=tool_name, mgmt_name=mgmt_name, domain=domain, reason=sanitized_msg)`) without logging raw tool arguments or secrets.
  - Returned to the MCP caller as `CallToolResult(content=[TextContent(type="text", text=sanitized_msg)], is_error=True)` so the LLM receives the exact actionable message without SDK prefix mangling.
- **Unexpected Internal Exceptions**:
  - Any unhandled non-`ToolFailure` exception is logged at `ERROR` (with SIDs redacted) and returns `CallToolResult(content=[TextContent(type="text", text=f"internal error: {type(exc).__name__}")], is_error=True)` without stack traces or internal details.
- **Pre-Login Domain Validation & `InvalidCredentialsError` Translation**:
  - Before executing any domain-scoped operation on `(mgmt_name, domain)`:
    1. If `domain` is provided (and not empty), checks cached `domains` via `client.get_domains(mgmt_name=mgmt_name, include_global=True, cache_mode="cache")`.
    2. If `domain` is not found in the cached domain list, performs a single refresh (`client.get_domains(mgmt_name=mgmt_name, include_global=True, cache_mode="force")`).
    3. If still not found (and the server has discovered domains), raises `ToolFailure` listing the known domains on `mgmt_name`: e.g. `f"Unknown domain {domain!r} on management server {mgmt_name!r}. Known domains: {', '.join(known_domains)}"`.
  - If an operation raises `InvalidCredentialsError`:
    - Fetches known domains from cache (`client.cache.get_domains(mgmt_name=mgmt_name, include_global=True)`) and raises `ToolFailure`:
      `f"Authentication rejected (InvalidCredentialsError) on management server {mgmt_name!r}" + (f" for domain {domain!r}" if domain else "") + f". Verify API key/credentials and domain name. Known domains on {mgmt_name!r}: {', '.join(known_domains) or 'none cached'}."`

### 5. Tool Surface & Response Envelopes (`tools.py`)

1. **Cached Listing & Lookup Tools**:
   - `show_domains(mgmt_name=None, include_global=False, details_level="standard", limit=50, offset=0, cache_mode="smart")`:
     - Returns JSON envelope with `from`, `to`, `total`, `source` (`"cache"` or `"live"`), `cache_age_seconds`, and `objects` (preserving server-level fields from `DomainInfo.raw_data` such as `servers`, `global-domain-assignments`, `domain-type`, `color`, `comments` alongside `uid`, `name`, `mgmt_name`, `active_ip`, `active_mds_ip` at `details_level="standard"` or `"full"`, or compact `uid`/`name`/`type`/`mgmt_name` at `details_level="uid"`).
   - `show_hosts`, `show_networks`, `show_address_ranges`, `show_dns_domains`, `show_groups`, `show_services`, `show_gateways_and_servers`:
     - Support `mgmt_name`, `domain`, `filter` / `names` / `uids`, `types` (for `show_services` and `show_gateways_and_servers`), `include_global`, `details_level`, `limit`, `offset`, `cache_mode` (`"cache"`, `"smart"`, `"smart-fast"`, `"force"`, or `"live"`).
     - Return JSON text envelope containing `from`, `to`, `total`, `source` (`"cache"` or `"live"`), `cache_age_seconds`, and `objects` (or `services` / `assets` + `objects` alias for uniform consumption).
   - `show_object(uid_or_name, mgmt_name=None, domain=None, obj_type=None, cache_mode="smart")`, `find_object`, `search_objects`, `get_group_members`:
     - Return JSON text envelope with `source` and `cache_age_seconds`.
2. **Progressive-Disclosure Aggregation & Cache Status Tools**:
   - `describe_objects(mgmt_name=None, domain=None, include_global=True)` -> delegates to `client.describe_objects(...)`.
   - `query_objects(mgmt_name=None, domain=None, domains=None, types=None, scope_origin="all", name_pattern=None, ip_subnet=None, port=None, protocol=None, tags=None, include_global=False, group_by=None, aggregate="list", limit=100, offset=0, cache_mode="cache")` -> delegates to `client.query_objects(...)` (distinguishing domain-owned vs `Global` objects via `original_domain`).
   - `cache_status(mgmt_name=None, domain=None, scope=None)` -> delegates to `client.get_cache_status(...)`, returning per-domain and per-`item_type` `status`, `last_published_at`, `last_session_uid`, `synced_at`, and `cache_age_seconds` across `"domains"`, `"objects"`, `"services"`, `"assets"`, and `"rulebase"`.
   - Cache refresh tools: `refresh_cache(mgmt_name=None, domain=None, scope="objects", types=None, include_global=False, mode="smart")`.
3. **Hybrid Rulebase Tools**:
   - `show_access_rulebase`, `show_nat_rulebase`, `show_https_rulebase`, `show_threat_rulebase`:
     - Parameters: `mgmt_name=None`, `domain=None`, `package=None`, `layer=None` (`name` or `uid`), `filter=""`, `format="markdown"` (`"markdown" | "model_friendly" | "raw"`), `limit=100`, `offset=0`, `cache_mode="smart"`, plus live-only parameters: `show_hits=False`, `order=None`, `show_as_ranges=False`, `show_expiration_settings=False`, `filter_settings=None`, `hits_settings=None`, `dereference_group_members=False`, `show_membership=False`.
     - **Switching logic**:
       - If `cache_mode != "live"` and NO live-only parameters are set (`not show_hits`, `order is None`, `not show_as_ranges`, `not show_expiration_settings`, `filter_settings is None`, `hits_settings is None`, `not dereference_group_members`, `not show_membership`), evaluates `filter` locally against the cached rulebase snapshot and cached objects/services via `client.filter_rulebase(...)` (refreshing rulebase first when `cache_mode in ("smart", "smart-fast", "force")`).
       - If any live-only parameter is passed or `cache_mode == "live"`, executes a live Management API query (`show-access-rulebase`, `show-nat-rulebase`, `show-https-rulebase`, `show-threat-rulebase`) via `client.api_call(...)` and returns the response with `source="live"`, `cache_age_seconds=None`.
   - `show_policy_packages` and `locate_rules`:
     - Expose `client.get_policy_packages(...)` and `client.locate_rules(...)`.
4. **Change Report & Gated `api_call` Tools**:
   - `change_report`: builds an auditable session/date-range change report via `client.build_change_report(...)` in `markdown`, `json`, or `html` format.
   - `api_call(command, payload=None, mgmt_name=None, domain=None, wait_for_task=True, timeout=None)`:
     - Checks `clean_cmd = command.strip().lower().lstrip("/")`.
     - If `not mcp_settings.allow_write_api` and not `clean_cmd.startswith("show-")`: raises `ToolFailure("Write and non-show-* commands are disabled (ARODONATA_MCP_ALLOW_WRITE_API=false). Only 'show-*' commands are permitted via api_call.")`.
     - Masks any SID in error messages or responses via `redact_sid` and `sanitize_mapping`.
5. **Optional Live-Compatibility Tools (`ARODONATA_MCP_LIVE_COMPAT=true`)**:
   - Registers direct live-API compatibility tools (`live_show_objects`, `live_show_Sessions`, `live_where_used`, `live_show_unused_objects`, `live_show_task`, `live_show_changes`, `live_show_access_layer`, `live_show_threat_profile`) that query the Management API with `source="live"`.
6. **Opt-In CPCRUD Tools (`ARODONATA_MCP_CPCRUD=true`)**:
   - Registers `cpcrud_validate`, `cpcrud_plan`, `cpcrud_apply`, and `cpcrud_inverse` delegating to `client.cpcrud`.

## Risks / Trade-offs

- **[Risk] `MCPServer` SDK wrapping exceptions in `UnexpectedToolError("Error executing tool <name>")`** → Mitigation: Wrap every registered tool handler in a decorator (`@mcp_tool_guard`) that catches `ToolFailure` (logging at `WARNING` without arguments/secrets) and returns `CallToolResult(content=[TextContent(type="text", text=err.message)], is_error=True)` directly, and catches unexpected `Exception` (logging at `ERROR` with SID redaction) and returns `CallToolResult(content=[TextContent(type="text", text=f"internal error: {type(exc).__name__}")], is_error=True)`. Because `MCPServer.convert_result` passes `CallToolResult` instances through unchanged, the caller receives the exact required text payload with `is_error=True`.
- **[Risk] `TransportSecurityMiddleware` inside `mcp` only checking `Host`/`Origin` inside `StreamableHTTPSessionManager` after routing** → Mitigation: Install `MCPOriginHostGuardMiddleware` at the outermost ASGI layer of `create_asgi_app` (in addition to passing `TransportSecuritySettings` to `MCPServer.streamable_http_app`) so any HTTP request with an unlisted `Host` is rejected with `421` and an unlisted `Origin` with `403` before hitting any route or auth handler.
