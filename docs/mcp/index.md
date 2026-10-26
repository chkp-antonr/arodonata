# Model Context Protocol (MCP) Server & Consolidated Tool Surface

Arodonata v2 includes a production-hardened **Streamable-HTTP Model Context Protocol (MCP) server** (`arodonata[mcp]`) that can run either as a standalone CLI (`arodonata-mcp`) or embedded as an ASGI sub-application (`create_mcp_server`, `create_asgi_app`) inside a FastAPI or Starlette host.

---

## 1. Consolidated Tool Surface Optimization (v2 Architecture)

In Arodonata v2, the MCP tool surface was redesigned and consolidated into **13 cache-aligned core tools** (plus **5 opt-in tamper-proof CPCRUD tools** when `ARODONATA_MCP_CPCRUD=true`).

### Why We Consolidated the MCP Tools

Early MCP servers often expose dozens of 1-to-1 wrappers over raw Check Point API endpoints (`show-hosts`, `show-networks`, `show-access-layers`, `show-packages`, etc.). That causes three major problems for LLM agents:

1. **Tool Selection Ambiguity & Context Bloat**: Too many overlapping tool schemas consume thousands of prompt tokens and cause models to pick the wrong endpoint.
2. **Unbounded Output Overflow**: Raw Check Point API calls or unanchored substring searches on large enterprise domains return thousands of objects and blow up the LLM context window.
3. **N+1 API Round-Trips**: Answering questions like *"How many hosts and networks exist per domain?"* or *"What packages and layers exist in Domain4?"* previously required dozens of sequential tool calls.

Arodonata v2 solves all three problems with **progressive disclosure**, **multi-table unified lookup**, **SQL-free cached aggregation**, and **hybrid cache/live execution**:

| Tool Category | Tool Name | Optimization & Key Capabilities |
| --- | --- | --- |
| **Collection Listing** | `list_domains` | Lists discovered domains (`arodonata_domains`) with `active_ip`, `active_mds_ip`, `standby_ips`, `is_global`, `source`, and `cache_age_seconds` |
| **Collection Listing** | `list_objects` | Lists cached network objects (`host`, `network`, `address-range`, `group`, `dns-domain`) with `id`, `object_id`, pagination (`from`, `to`, `total`), and type normalization |
| **Collection Listing** | `list_services` | Lists cached services (`arodonata_services` with `id` and `service_id`), accepting both short (`"tcp"`, `"udp"`, `"icmp"`, `"group"`) and canonical (`"service-tcp"`, etc.) `types` filters |
| **Collection Listing** | `list_assets` | Lists cached gateways, clusters, cluster members, VSX gateways/virtual systems, and management servers (`arodonata_assets` with `id`, `asset_id`, `parent_id`, `parent_asset_id`, `member_asset_ids`, `virtual_system_asset_ids`), with optional `parent` UID/name/`asset_id` filtering |
| **Multi-Table Entity Lookup** | `show_object` | Searches across **`arodonata_objects`**, **`arodonata_services`**, **`arodonata_assets`** (including gateway `interfaces`, `network_security_blades`, `member_uids`, `member_asset_ids`, `virtual_system_asset_ids`), and **`arodonata_rulebase_layer` / `package_layer`** by UID, exact name, or composite ID (`object_id`/`service_id`/`asset_id`) using **3-tier matching** (`exact`, strict `wildcard` via `fnmatchcase`, and paginated `substring_candidates` fallback) |
| **Structured Analytics** | `query_objects` | Executes cross-domain filtering (`name_pattern`, `ip_subnet`, `port`, `protocol`, `tags`, `scope_origin="all"\|"local"\|"global"`, `object_id`, `service_id`, `asset_id`, `parent_id`, `parent_asset_id`), `group_by`, and aggregation (`aggregate="list"\|"count"\|"describe"`) over cached SQL tables in a single tool call |
| **Cache Management** | `cache_control` | Unified cache inspection (`action="status"`, returning per-domain/per-type freshness from `arodonata_domain_sync_state`) and scoped refresh (`action="refresh"`, `scope="domains"\|"objects"\|"services"\|"assets"\|"rulebase"`) |
| **Search & Membership** | `search_objects` | Multi-term IP/CIDR/range/wildcard/UID/composite-ID/name search with `exact_match: bool = False` and recursive parent group resolution (`max_depth`, including `object_id` and `parent_object_ids`) |
| **Search & Membership** | `get_group_members` | Expands direct or recursive members of a network `group`, `service-group`, gateway cluster (`member_uids` / `member_asset_ids`), or VSX container (`virtual_system_uids` / `virtual_system_asset_ids`, including cross-domain Virtual Systems) by UID, name, or composite ID |
| **Policy & Rulebase** | `show_rulebase` | **Catalog + Rulebase Hybrid**: when `package` and `layer` are omitted (or unmatched), returns the domain's cached packages and layers catalog! When specified, evaluates `filter` locally against cached rules/objects/services (`markdown`, `model_friendly`, `raw`, `cpcrud`) or switches to live API when `show_hits` / `cache_mode="live"` is used |
| **Policy & Rulebase** | `locate_rules` | Resolves rule UIDs or layer UIDs into exact SmartConsole hierarchical rule numbers (`1`, `2.1`) and package/layer paths across a domain |
| **Audit & Compliance** | `change_report` | Collects and renders auditable session change reports (`SessionScope` or `RangeScope`) in `markdown`, `json`, or `html` with full `sid` redaction |
| **Escape Hatch** | `api_call` | Executes direct Check Point Web API commands (`where-used`, `show-sessions`, `verify-policy`). Enforces a strict read-only command allowlist when `ARODONATA_MCP_ALLOW_WRITE_API=false`, and isolates allowed write calls in a dedicated session |
| **Opt-in CPCRUD** | `cpcrud_validate` | Offline JSON Schema validation of declarative CPCRUD templates (`ARODONATA_MCP_CPCRUD=true`) |
| **Opt-in CPCRUD** | `cpcrud_plan` | Generates a deterministic CPCRUD `Plan` signed with an in-memory **HMAC-SHA256** key (`plan_signature` + `plan_id`) |
| **Opt-in CPCRUD** | `cpcrud_apply` | Verifies the `plan_id` or HMAC `plan_signature` (rejecting model-forged or modified plans), executes inside an isolated `WriteSession`, and supports staging (`no_publish=True, keep_session=True`) |
| **Opt-in CPCRUD** | `cpcrud_inverse` | Generates a compensating rollback template from a verified `Plan` and `ApplyReport` |
| **Opt-in CPCRUD** | `cpcrud_staged_session` | Adopts a staged session (`session_uid`) via `take-over-session` and either publishes (`action="publish"`, invalidating domain cache) or discards (`action="discard"`) cleanly |

---

## 2. Deep-Dive into Key Tool Behaviors

### 2.1 Three-Tier Matching in `show_object`

When an LLM calls `show_object(uid_or_name=..., mgmt_name=..., domain=..., obj_type=None, limit=20, offset=0)`:

1. **Tier 1 — Exact Match (`match_type="exact"`)**:
   - If `uid_or_name` contains no `*` or `?` wildcards and matches an exact UID or case-insensitive name in `arodonata_objects`, `arodonata_services`, `arodonata_assets`, or `arodonata_rulebase_layer` / `arodonata_rulebase_package_layer`, `show_object` returns that single entity with full details (including gateway `interfaces`, `network_security_blades`, `member_uids`, and `virtual_system_uids`).
2. **Tier 2 — Strict Explicit Wildcard (`match_type="wildcard"`)**:
   - If `uid_or_name` contains `*` or `?` (e.g. `"web-*-prod"` or `"*.example.com"`), it evaluates anchored `fnmatchcase` strictly against the pattern without adding implicit leading/trailing wildcards. If `total == 1`, it returns the full object; if `total > 1`, it returns a paginated candidate slice (`limit` default `20`, max `500`).
3. **Tier 3 — Paginated Substring Candidate Fallback (`match_type="substring_candidates"`)**:
   - If `uid_or_name` has no wildcard and no exact match exists in cache, instead of failing with a bare `"not found"` error or dumping thousands of objects, `show_object` searches for case-insensitive substring matches across cached names and returns up to `limit` (`20`) compact candidate summaries (`uid`, `name`, `type`, `domain_name`, `summary`) with `from`, `to`, and `total` so the LLM can pick the exact object on the next turn.

### 2.2 Progressive Disclosure via `query_objects` & `show_rulebase`

- **Schema & Inventory Discovery (`query_objects(aggregate="describe")`)**:
  - Calling `query_objects(mgmt_name="mdsm-prod", aggregate="describe")` returns all available domains, per-type object/service/asset counts, and the exact list of filterable and groupable fields (`domain_name`, `type`, `original_domain`, `color`, `protocol`, `port`, etc.).
- **Cross-Domain Counting (`query_objects(aggregate="count", group_by=["domain_name", "type"])`)**:
  - Counts objects and services across all domains in a single SQL query, supporting `scope_origin="local"` (domain-owned only) vs `"global"` (`original_domain == "Global"`).
- **Guided Rulebase Discovery (`show_rulebase`)**:
  - Calling `show_rulebase(mgmt_name="mdsm-prod", domain="Domain4")` **without** `package` or `layer` (or with a misspelled layer name) automatically returns `"mode": "catalog"` containing all cached `packages` (`arodonata_rulebase_package_layer`) and `layers` (`arodonata_rulebase_layer`, including inline layers and `implicit_cleanup_action`).

### 2.3 Pre-Login Domain Validation & Actionable `ToolFailure`

Every domain-scoped MCP tool validates `domain` against the cached `arodonata_domains` table (triggering a single domain-list refresh on cache miss) **before** attempting any Check Point login. If an invalid domain name is passed, the tool returns an actionable error listing the valid domain names on that server instead of triggering unnecessary failed logins.

---

## 3. Running & Embedding the MCP Server

### 3.1 Standalone CLI (`arodonata-mcp`)

```bash
# Start with static bearer token authentication (default)
export ARODONATA_MCP_AUTH_MODE=static
export ARODONATA_MCP_TOKEN_VARS=TEAM_ALPHA_MCP_TOKEN
export TEAM_ALPHA_MCP_TOKEN="a-very-long-random-secret-token-at-least-32-chars"

uv run arodonata-mcp --host 127.0.0.1 --port 8000 --path /mcp
```

### 3.2 Embedding in FastAPI / Starlette (`create_mcp_server` & `create_asgi_app`)

See [`examples/12_mcp_embedded.py`](../examples/12-mcp-embedded.md) for a complete runnable example mounting Arodonata's MCP server inside a FastAPI application with custom host-level tools:

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from arodonata import ArodonataClient, ArodonataMCPSettings, create_asgi_app, create_mcp_server

client = ArodonataClient()
mcp_settings = ArodonataMCPSettings(auth_mode="host", path="/mcp")
mcp_server = create_mcp_server(client, mcp_settings=mcp_settings)
mcp_asgi = create_asgi_app(client, mcp_settings=mcp_settings, server=mcp_server)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with client, mcp_asgi.lifespan(app):
        yield


app = FastAPI(lifespan=lifespan)
app.mount("/mcp", mcp_asgi)
```

---

## 4. MCP Configuration & Security Reference (`ArodonataMCPSettings`)

| Env Variable | Type | Default | Description |
| --- | --- | --- | --- |
| `ARODONATA_MCP_HOST` | `str` | `"127.0.0.1"` | Bind address for standalone `arodonata-mcp` |
| `ARODONATA_MCP_PORT` | `int` | `8000` | Bind TCP port (`1..65535`) |
| `ARODONATA_MCP_PATH` | `str` | `"/mcp"` | Streamable-HTTP mount path |
| `ARODONATA_MCP_AUTH_MODE` | `"static" \| "host" \| "jwt" \| "none"` | `"static"` | Authentication mode (`"host"` and `"jwt"` are for embedded ASGI mode only; standalone CLI exits with code `2` if used) |
| `ARODONATA_MCP_TOKEN_VARS` | `list[str]` (CSV) | `[]` | Env var names holding bearer tokens (`>= 32` chars); each var name becomes `client_id` in `UserContext` |
| `ARODONATA_MCP_TOKENS` | `list[str]` (CSV) | `[]` | Direct `"client_id=secret"`, `"client_id:secret"`, or bare base64 token secrets (`>= 32` chars; safe with trailing `=` base64 padding) |
| `ARODONATA_MCP_ENABLE_DNS_REBINDING_PROTECTION` | `bool` | `True` | Enforces `Host` (`HTTP 421`) and `Origin` (`HTTP 403`) header allowlists |
| `ARODONATA_MCP_ALLOWED_HOSTS` | `list[str]` (CSV) | `127.0.0.1:*,localhost:*,[::1]:*` | Permitted `Host` headers (validates numeric ports on wildcard `:port` patterns) |
| `ARODONATA_MCP_ALLOWED_ORIGINS` | `list[str]` (CSV) | `http(s)://localhost:*`, `127.0.0.1:*` | Permitted browser `Origin` headers |
| `ARODONATA_MCP_ALLOW_WRITE_API` | `bool` | `False` | When `False`, `api_call` permits only the explicit read-only allowlist (`show-*`, `where-used`, `verify-policy`); when `True`, mutating calls run in an isolated dedicated session |
| `ARODONATA_MCP_CPCRUD` | `bool` | `False` | Registers the 5 tamper-proof HMAC-signed CPCRUD tools (`cpcrud_validate`, `cpcrud_plan`, `cpcrud_apply`, `cpcrud_inverse`, `cpcrud_staged_session`) |
| `ARODONATA_MCP_JSON_RESPONSE` | `bool` | `False` | Return JSON responses instead of SSE streams on Streamable-HTTP POST |
| `ARODONATA_MCP_STATELESS_HTTP` | `bool` | `False` | Enable stateless Streamable-HTTP mode per request |
| `ARODONATA_MCP_SERVER_NAME` | `str` | `"arodonata-mcp"` | Server identifier reported in MCP initialization |
