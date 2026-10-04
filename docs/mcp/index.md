# MCP Server

Arodonata can serve any MCP client over streamable HTTP, exposing the same `show_*` tools as Check Point's `@chkp/quantum-management-mcp` but answered from Arodonata's cache with automatic re-login, per-MDS login gating and rate limiting, across every configured management server and domain.
It ships as both a standalone command (`arodonata-mcp`) for a team to point clients at, and as a library (`arodonata.mcp`) for embedding the same tool set inside your own ASGI application.

## Install

```bash
uv pip install "arodonata[mcp]"
```

## Standalone server for a team

`arodonata-mcp` loads `.env.lib` then `.env.secrets` (override with `--env-file`, repeatable), builds an `ArodonataClient` from the library's usual environment variables (`DATABASE_URL`, `MGMT_NAMES`, `MGMT_SERVERS`, `API_KEY_VARS`, ...), and serves it over streamable HTTP with `uvicorn`.
It resolves API keys the same way the runnable examples do: `API_KEY_VARS` (a comma-separated list of environment variable names whose values are the actual API keys) takes priority, and a bare `API_KEYS` value is used when `API_KEY_VARS` is unset.

```bash
arodonata-mcp --host 0.0.0.0 --port 8765
```

Flags: `--env-file` (repeatable; default `.env.lib` then `.env.secrets`), `--host` (overrides `ARODONATA_MCP_HOST`), `--port` (overrides `ARODONATA_MCP_PORT`), `--ssl-certfile`, `--ssl-keyfile`, `--log-level` (one of `critical`, `error`, `warning`, `info`, `debug`; default `info`; below `debug` the SDK's per-request `Terminating session: None` line from `mcp.server.streamable_http` is hidden, its warnings and errors still show), `--shutdown-timeout` (overrides `ARODONATA_MCP_SHUTDOWN_TIMEOUT`). An invalid flag or an inconsistent configuration (for example a different number of `MGMT_NAMES`, `MGMT_SERVERS` and API keys) prints one `arodonata-mcp: configuration error: ...` line and exits with status 2.

The command refuses to start with `ARODONATA_MCP_AUTH_MODE=host` or `jwt` (exit code 2): `host` mode has no verifier at all and would serve every request anonymously if there is no authenticating host in front of it, and `jwt` is reserved and not implemented. See [Authentication](#authentication) below.

### Configuration

Every field below is read from an environment variable named `ARODONATA_MCP_<FIELD>` (case-insensitive), or passed as a constructor keyword to `ArodonataMCPSettings` when embedding.

| Variable | Default | Description |
|---|---|---|
| `ARODONATA_MCP_HOST` | `127.0.0.1` | Bind address. |
| `ARODONATA_MCP_PORT` | `8765` | Bind port (1-65535). |
| `ARODONATA_MCP_PATH` | `/mcp` | Streamable HTTP path; must start with `/`. |
| `ARODONATA_MCP_PUBLIC_URL` | `http://127.0.0.1:8765/mcp` | URL clients use; also the OAuth issuer/resource-server URL, and the basis for the default `ALLOWED_HOSTS`/`ALLOWED_ORIGINS` below. |
| `ARODONATA_MCP_STATELESS` | `true` | Streamable HTTP stateless mode. |
| `ARODONATA_MCP_JSON_RESPONSE` | `true` | Return plain JSON instead of SSE for tool responses. |
| `ARODONATA_MCP_LIVE_COMPAT` | `true` | Register the live `show_*` compatibility tools (see [Tools](#tools)). |
| `ARODONATA_MCP_CPCRUD` | `false` | Register the opt-in `cpcrud_*` tools. |
| `ARODONATA_MCP_ALLOW_WRITE_API` | `false` | Allow `api_call` to run non-`show-*` (write) commands. |
| `ARODONATA_MCP_AUTH_MODE` | `static` | `static` or `host`; `jwt` is reserved and rejected everywhere. See [Authentication](#authentication). |
| `ARODONATA_MCP_TOKEN_VARS` | `""` | Comma-separated environment variable names whose values are accepted bearer tokens (`auth_mode=static`). |
| `ARODONATA_MCP_JWT_ISSUER` | `""` | Reserved for the unimplemented `jwt` mode. |
| `ARODONATA_MCP_JWT_AUDIENCE` | `""` | Reserved for the unimplemented `jwt` mode. |
| `ARODONATA_MCP_JWT_JWKS_URL` | `""` | Reserved for the unimplemented `jwt` mode. |
| `ARODONATA_MCP_DEFAULT_LIMIT` | `50` | Default page size for list tools; `0` returns everything. |
| `ARODONATA_MCP_MAX_RESULT_CHARS` | `200000` | Truncate a tool's text result past this many characters, appending an offset/limit hint to resume. |
| `ARODONATA_MCP_SHUTDOWN_TIMEOUT` | `5` | Seconds Ctrl+C waits for open client connections (Claude Code keeps one open) and then for Check Point SDK calls stuck in network I/O; past it the server closes the connections and exits without waiting for the stuck calls, logging how many were left. |
| `ARODONATA_MCP_ALLOWED_HOSTS` | derived from `host`, `port` and `public_url` | Comma-separated Host header values accepted (DNS-rebinding protection); a request with an unlisted Host header gets HTTP 421. |
| `ARODONATA_MCP_ALLOWED_ORIGINS` | derived from `host`, `port` and `public_url` | Comma-separated Origin header values accepted; a request with an unlisted Origin gets HTTP 403 (a request with no Origin header, e.g. from a non-browser client, is accepted). |

### TLS

This section is about the MCP server's own inbound TLS, the connection from MCP clients to `arodonata-mcp`.
The connections from Arodonata to the Check Point management servers are verified separately, by certificate fingerprint; see [TLS Verification](../configuration/tls-verification.md).
`arodonata-mcp` checks the trust store at startup: with the default `tofu` mode and a store that cannot be created or written, a corrupt or unsafe store, `lab-memory` without `ARODONATA_LAB`, or an invalid `ARODONATA_TLS_TRUST` or fingerprint value, it exits with status 2 and a message naming the cause (for an unwritable store, a hint to set `ARODONATA_TLS_KNOWN_HOSTS_PATH` or use `pinned`).
When a tool hits an identity or timeout failure, the model gets the facts and "Operator action required on the MCP host; retrying will not help."; no MCP tool can change trust.

For inbound TLS, either pass `--ssl-certfile`/`--ssl-keyfile` to `arodonata-mcp`, or terminate TLS at a reverse proxy in front of it. Binding to a non-loopback address without `--ssl-certfile` logs a warning: org policy requires TLS 1.2+ for all data in transit, and bearer tokens travel in the `Authorization` header on every request.

## Authentication

`ARODONATA_MCP_AUTH_MODE=static` (the default) checks the request's bearer token with a constant-time comparison against the values of the environment variables named in `ARODONATA_MCP_TOKEN_VARS`, resolved the same way `API_KEY_VARS` resolves API keys — i.e. from `.env.secrets` or the process environment, never written into `.env.lib`. The variable name (not the token value) is what appears as the caller's identity in logs and as the tool call's `client_id`, so give each caller or team its own named variable.

`ARODONATA_MCP_AUTH_MODE=host` disables Arodonata's own token verification entirely (`create_mcp_server` builds no `TokenVerifier`) so that an authenticating ASGI host in front of `create_asgi_app`'s mount point — your own middleware, an API gateway, a service mesh sidecar — is the sole authority. The standalone `arodonata-mcp` executable has no such host, so it refuses `auth_mode=host` at startup; this mode only makes sense when [embedding](#embedding-in-your-application).

`ARODONATA_MCP_AUTH_MODE=jwt` is reserved for a future JWT-against-an-identity-provider mode and is rejected everywhere it is read — by `arodonata-mcp` at startup, and by `create_mcp_server` — because the stub verifier raises `NotImplementedError` on every call.

## Embedding in your application

Call `create_mcp_server` to build the `MCPServer` yourself (so you can register application-specific tools alongside the Arodonata ones) and `create_asgi_app` to turn it into a mountable Starlette app. You own the `ArodonataClient` and its database engine: open the client before serving and close it after, and dispose the engine yourself.

```python title="examples/09_mcp_embedded.py"
--8<-- "examples/09_mcp_embedded.py"
```

Identity follows the client, not the caller: one `ArodonataClient` means one Check Point identity (one set of API keys/credentials) for every MCP caller that reaches it, regardless of which bearer token or host-level identity they authenticated with. Give each Check Point identity that needs different access its own `ArodonataClient` and its own mounted app.

## Tools

Every tool returns plain text, not MCP structured content. That text is JSON, except for the rulebase tools with `format="markdown"` (the default, a markdown table) or `format="model_friendly"` (compact structured text); rulebase tools return JSON only for `format="raw"`. List tools return an envelope alongside the page of objects: `from`/`to`/`total` (1-based, describing that page), `source` (`"cache"` or `"live"`) and `cache_age_seconds`. A failed Management API call comes back as an error result whose text is `"<code>: <message>"`, carrying the Check Point error code and message verbatim, except that a SID the message echoes is masked. Validation problems such as a missing or unknown `mgmt_name` come back as error results naming the configured servers, e.g. `"unknown mgmt_name '<name>'; configured servers: <names>"` or `"mgmt_name is required; configured servers: <names>"`. An unexpected server-side exception never reaches the caller as a message or traceback: it comes back as an error result whose text is `"internal error: <ExceptionClass>"`, with the exception logged server-side instead.

Cache-backed tools answer from Arodonata's local cache by default; pass `cache_mode='smart'` to re-sync stale domains first or `cache_mode='force'` for a full reload from the management server. Live tools always query the management server (through Arodonata's session cache and rate limiter) and take no `cache_mode`. Live list tools currently retrieve the full collection from the management server and page it locally, so `limit` bounds the response size but not the work done on the management server. `cpcrud_*` tools are opt-in (`ARODONATA_MCP_CPCRUD=true`); `api_call` can additionally run write commands when `ARODONATA_MCP_ALLOW_WRITE_API=true`.

### Native tools

| Tool | Backing | Notes |
|---|---|---|
| `arodonata_init` | cache | Call this first: lists configured management servers, whether each is MDS, their domains, and cache age. A server whose empty object cache is being loaded in the background carries `object_cache_warm_up` (`running` with `running_seconds`, or how it ended with the refreshed and failed domain counts), and the guidance says so while it runs. |
| `search_objects` | cache | Searches cached objects across servers/domains by name, IP or pattern, following group membership; returns `results` as a list of `{mgmt_name, domain, search_term, search_type, objects, memberships}`. |
| `refresh_objects` | live | Re-syncs the object cache from the management server(s); `mode='incremental'` pulls only changes since the last publish. |
| `refresh_rulebases` | live | Re-syncs cached access, NAT, HTTPS and threat rulebases per domain; `mode='check'` re-reads only domains with a new published session; accepts `include_global`; failures (including `dirty session` while the shared session holds unpublished changes) land in `errors`. |
| `api_call` | live | Runs any Management API command through Arodonata's session handling; only `show-*` commands unless writes are enabled. |

### Cached tools

| Tool | Backing | Notes |
|---|---|---|
| `show_hosts` | cache | `filter` matches the object name (wildcards allowed). |
| `show_networks` | cache | `filter` matches the subnet in CIDR notation (e.g. `10.0.0.0/24`). |
| `show_groups` | cache | `filter` matches the group name; includes member UIDs. |
| `show_gateways_and_servers` | cache | Gateways, clusters, cluster members and management servers; no `domain` parameter (gateways live in the asset cache, not the per-domain object cache) and always reports `cache_age_seconds: null`. |
| `show_domains` | cache | Domains of a Multi-Domain server; `include_global` adds the Global domain, which `show-domains` never lists: its UID and active MDS member come from `show-global-domain`. Always reports `cache_age_seconds: null` (the domain cache keeps no timestamp). |
| `show_object` | cache | Any object by UID. |

### Rulebase tools

| Tool | Backing | Notes |
|---|---|---|
| `show_access_rulebase` | cache/live | Addressed by `name` or `uid` (plus `package`); on the cache path `package` alone is enough (the package's SmartConsole numbering), the live path needs `name` or `uid`. |
| `show_nat_rulebase` | cache/live | Addressed by `package` only — NAT has no `name`/`uid`. |
| `show_https_rulebase` | cache/live | Addressed by `name` or `uid` (plus `package`); on the cache path `package` alone is enough (the package's SmartConsole numbering), the live path needs `name` or `uid`. |
| `show_threat_rulebase` | cache/live | Addressed by `name` or `uid` (plus `package`); on the cache path `package` alone is enough (the package's SmartConsole numbering), the live path needs `name` or `uid`. |

All four are cache-backed by default and switch to a live query when any of `filter`, `filter_settings`, `show_hits`, `hits_settings`, `use_object_dictionary`, `show_as_ranges`, `show_expiration_settings` or `order` is given (`order` is a list of objects, e.g. `[{"ASC": "name"}]`, as the Management API expects). `format` selects `raw` (API shape), `markdown` (default; a table with full, non-truncated cell values) or `model_friendly` (compact structured text). On the cache path a layer (by `name` or `uid`) is shown with layer-relative hierarchical numbers (`1`, `2.1`, ...): a header row per section with its rule range, place-holders marked, and inline layers expanded beneath the rule that calls them. Passing `package` shows that package's SmartConsole numbering instead (global layer, parent rule, `2.x`, `2.2.1`); `name`/`uid` then picks one ordered layer of it, and NAT is always shown this way. A call without `domain` reads the one cached domain holding the layer (or package); when several do, it fails listing the candidates as `domain/uid` so you can pass `domain` or `uid` (only `domain` when the `uid` you passed is held by several domains, as a Global layer is). Object references are rendered as names from the layers' objects dictionaries. `cache_age_seconds` (and the footer's age) is the age of that domain's last rulebase refresh; a domain whose last refresh failed is shown from its last good snapshot, with a note naming the error. `format='raw'` returns the numbered entries (`number`, `depth`, `layer` on each rule) plus an `objects-dictionary`, and the domain's rulebase sync `status` and `last_error`. The live path reads the whole layer and numbers its rows with section rows too, naming inline layers without expanding them. On both paths `limit`/`offset` slice the rendered rows, section rows included.

### Change report tool

| Tool | Backing | Notes |
|---|---|---|
| `change_report` | live (read-only) | Evidence of what policy sessions changed, as markdown: rules with SmartConsole numbers, objects and sections, added/modified/deleted. |

Parameters: `domain` (required; `""` for an SMS), `mgmt_name` (required when several servers are configured), `session_uids` (explicit sessions, published or not), a published range with `from_session` (exclusive) / `to_session` (inclusive) and/or `from_date` / `to_date` (ISO 8601 with a UTC offset), and `max_rules` (default 100). Give `session_uids`, a range, or both.

The tool is always registered, in the cached group, although it reads the live Management API: it reads `show-changes` and `show-object` (for member names) and numbers rules from the rulebase cache, which it may refresh first with a read-only rulebase read. There is no owned session in MCP, so unpublished sessions get provisional numbers, labelled as such. Caps: 20 sessions of a range (a warning names the `from_session` to continue from), at most 200 `show-object` name lookups per report, at most 200 object rows in the markdown, and `max_rules` rule rows.

The output is markdown only; HTML and JSON evidence are available through the library, see [Change Report](../user-guide/change-report.md). Output longer than `max_result_chars` is cut at the last complete line with the marker `…output truncated at <N> characters, full report via the library`.

### Live compatibility tools

Generated from the same manifest as the reference server's tool list, one tool per `show-*` Management API command not covered above: `show_objects`, `show_access_layers`, `show_packages`, `show_mdss`, `show_simple_gateways`, `show_simple_clusters`, `show_cluster_members`, `show_lsm_gateways`, `show_lsm_clusters`, `show_unused_objects`, `show_services_tcp`, `show_services_udp`, `show_services_icmp`, `show_service_groups`, `show_application_sites`, `show_application_site_groups`, `show_application_site_categories`, `show_wildcards`, `show_security_zones`, `show_tags`, `show_address_ranges`, `show_multicast_address_ranges`, `show_dynamic_objects`, `show_dns_domains`, `show_time_groups`, `show_access_point_names`, `show_vpn_communities_star`, `show_vpn_communities_meshed`, `show_vpn_communities_remote_access`, `show_access_layer`, `show_access_section`, `show_nat_section`, `show_access_rule`, `show_vpn_community_star`, `show_vpn_community_meshed`, `show_vpn_community_remote_access`, `show_simple_gateway`, `show_simple_cluster`, `show_cluster_member`, `show_lsm_gateway`, `show_lsm_cluster`, `where_used`. All of these are live; disable the whole set with `ARODONATA_MCP_LIVE_COMPAT=false`.

### CPCRUD tools (opt-in, `ARODONATA_MCP_CPCRUD=true`)

| Tool | Backing | Notes |
|---|---|---|
| `cpcrud_validate` | none | Validates a template (a YAML/JSON string or an object) against the schema; no network I/O. A string is always parsed as YAML/JSON content, never treated as a file path on the server. |
| `cpcrud_plan` | cache | Computes the idempotent change plan without touching the management server's policy. |
| `cpcrud_apply` | live | Applies a plan or template; `dry_run=true` (default) executes nothing. |
| `cpcrud_inverse` | none | Builds the compensating template that undoes a plan. |

### Prompts

| Prompt | Purpose |
|---|---|
| `show_gateways_prompt` | Guide showing installed policies per gateway. |
| `show_policies_prompt` | Guide walking packages → layers → rulebases. |
| `show_rule_prompt` | Guide finding one rule by reference. |
| `topology_visualization_prompt` | Guide producing an SVG topology diagram for a gateway. |
| `source_to_destination_prompt` | Guide determining possible paths between two endpoints. |

## Differences from the reference server

- Multi-server: every tool takes an optional `mgmt_name` (required only when more than one server is configured), unlike the reference server's one-host-per-process model.
- List envelopes carry `source` (`"cache"` or `"live"`) and `cache_age_seconds` alongside the objects, so a client can tell whether an answer came from the cache and how stale it is.
- Cache-backed tools (including the cache path of the `show_*_rulebase` tools) take `cache_mode`: `cache` reads the cache as-is, `smart` re-syncs stale domains first, `smart-fast` re-syncs incrementally, `force` does a full reload. For the `show_*_rulebase` tools, `smart`, `smart-fast` and `force` refresh the rulebases of the named `domain` only (session-aware); without `domain` the one cached domain holding the layer or package is resolved and refreshed the same way. Omit it for the server default. Live tools and `api_call` do not take `cache_mode`.
- Rulebase tools support `format` values `raw`, `markdown` and `model_friendly`; unlike the reference server's fixed-width padded table, cells always carry full, non-truncated values.
- `find_zero_hits_rules` and `simulate_packet` from the reference server are not ported in this version.
- HTTP only: no stdio transport.

## Client configuration

Claude Code:

```bash
claude mcp add --transport http arodonata https://mcp.example.com/mcp --header "Authorization: Bearer ${ARODONATA_TOKEN}"
```

Claude Desktop (custom connector), as a JSON entry under the connector's settings:

```json
{
  "url": "https://mcp.example.com/mcp",
  "headers": {
    "Authorization": "Bearer ${ARODONATA_TOKEN}"
  }
}
```
