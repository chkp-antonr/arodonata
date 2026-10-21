# Arodonata: Capabilities & Downstream Integration Guide

**Version:** 1.15.0 · **Status:** Canonical Architecture Specification · **Date:** October 2026

## 1. Executive Summary & Architectural Role

Arodonata is an async-first Python platform library and SDK for Check Point Multi-Domain Security Management (MDSM).

In the enterprise automation ecosystem, **Arodonata acts as the authoritative engine for all direct Check Point interactions**:

- API protocol handling, connection pooling, and credential lifecycle.
- High-performance database-backed caching and incremental synchronization.
- Declarative Policy-as-Code (CPCRUD): schema validation, two-phase planning (`plan`), execution (`apply`), and rollback generation (`inverse`).
- Multi-domain rulebase, package, and layer introspection.
- Auditable change evidence collection and multi-format rendering (HTML, Markdown, JSON).

### Core Architectural Principle for Downstream Consumers (FPCR v2, CLIs, Webhooks)

> **"Delegate, Never Duplicate"**
> Consumer applications MUST NOT implement custom Check Point API callers, local object/rule CRUD managers, bespoke rulebase parsers, or custom naming algorithms. Consumer applications act strictly as business workflow orchestrators, state machines, user interfaces, and authorization/audit coordinators.

---

## 2. Capability Catalog & Consumer Contracts

| Capability Area | Canonical Arodonata Module | Key Classes / Functions | Configuration Source |
| --- | --- | --- | --- |
| **Client & Sessions** | `arodonata.api.client` | `ArodonataClient`, `ArodonataSettings` | `.env` (`MGMT_SERVERS`, `API_KEYS`) |
| **Declarative CPCRUD** | `arodonata.cpcrud.service` | `CPCRUDService`, `Plan`, `ApplyReport` | `checkpoint_ops_schema.json` |
| **Object Naming** | `arodonata.cpcrud.naming` | `NamingPrefixes`, `matches_convention` | `.env` (`CPCRUD_AUTO_NAME_PREFIX_*`) |
| **Domain Topology** | `arodonata.api.services.domain_service` | `DomainService`, `domain_list_refresh` | Database cache / MDS API |
| **Rulebase & Layers** | `arodonata.api.services.rulebase_reader` | `fetch_full_rulebase`, `read_domain`, `PackageLayout` | Live API / Cache Coordinator |
| **Cache & Invalidation**| `arodonata.core.cache_refresh_coordinator` | `CacheRefreshCoordinator`, `CachePolicy` | Session UID stamping |
| **Evidence & Reports** | `arodonata.reports.changes` | `collect_change_report`, `render_change_report` | `ReportFormat` (Markdown, HTML, JSON) |
| **MCP Integration** | `arodonata.mcp` | `cached_tools`, `change_report_tools`, `rulebase_tools` | FastMCP / SSE |

---

## 3. Deep-Dive: Consumer Integration Patterns

### 3.1 Client & Connection Lifecycle

Downstream applications instantiate `ArodonataClient` using an existing async SQLAlchemy engine and configuration settings.

```python
from sqlalchemy.ext.asyncio import create_async_engine
from arodonata import ArodonataClient, ArodonataSettings

settings = ArodonataSettings.from_env()
engine = create_async_engine(settings.database_url)

client = ArodonataClient(engine=engine, settings=settings)

async with client:
    # Managed connection pooling and auto-login across MDS/CMAs
    result = await client.api_call("mgmt_name", "show-hosts", payload={"limit": 50})
```

- **Consumer Rule:** Never store Check Point session tokens (`sid`) manually. `ArodonataClient` handles session pooling, token refresh, and re-login across CMA contexts automatically.

---

### 3.2 Declarative CPCRUD (Rules & Objects Provisioning)

Consumers MUST NOT implement direct `add-host`, `add-access-rule`, or `set-access-rule` logic. Instead, assemble a YAML or dictionary template following `checkpoint_ops_schema.json` and delegate to `CPCRUDService`.

```python
from arodonata.cpcrud.service import CPCRUDService
from arodonata.cpcrud.models import NameConflictPolicy, IpConflictPolicy

service = CPCRUDService(client)

# 1. Validation (Zero API calls, pure schema validation)
errors = service.validate(template_dict)
if errors:
    raise ValueError(f"Schema violation: {errors}")

# 2. Planning (Dry-run: computes diffs, object lookups, orderings)
plan = await service.plan(
    template_dict,
    name_conflict=NameConflictPolicy.UPDATE,
    ip_conflict=IpConflictPolicy.REUSE,
)

# 3. Apply with SSE streaming progress
async for sse_event in service.apply(plan):
    yield sse_event  # Stream progress directly to WebUI or console

# 4. Compensating Rollback (Inverse template)
inverse_template = service.inverse(plan, apply_report)
```

- **Conflict Policies Supported:**
  - `NameConflictPolicy.FAIL` / `UPDATE` / `REUSE`
  - `IpConflictPolicy.FAIL` / `REUSE`

---

### 3.3 Object Naming Conventions & Prefixes

Arodonata provides standardized object naming logic with prefix customization via environment variables.

- **Module:** `arodonata.cpcrud.naming`
- **Class:** `NamingPrefixes`
- **Environment Variables:**
  - `CPCRUD_AUTO_NAME_PREFIX_HOST` (default: `Host_`)
  - `CPCRUD_AUTO_NAME_PREFIX_NETWORK` (default: `Net_`)
  - `CPCRUD_AUTO_NAME_PREFIX_RANGE` (default: `IPR_`)
  - `CPCRUD_AUTO_NAME_PREFIX_SVC_TCP` (default: `TCP_`)
  - `CPCRUD_AUTO_NAME_PREFIX_SVC_UDP` (default: `UDP_`)
  - `CPCRUD_AUTO_NAME_PREFIX_SVC_ICMP` (default: `ICMP_`)

```python
from arodonata.cpcrud.naming import DEFAULT_PREFIXES, NamingPrefixes, matches_convention

prefixes = NamingPrefixes.from_settings(settings)
is_valid_host = matches_convention("host", "Host_10.20.30.40", prefixes)
```

- **Consumer Rule:** Consumers must not hardcode prefixes or regexes. Read `NamingPrefixes` from Arodonata.

---

### 3.4 Domain Catalog, Package & Section Introspection

Consumers use Arodonata to discover domains, inspect policy packages, and determine section index ranges.

```python
from arodonata.api.services.domain_service import DomainService
from arodonata.api.services.rulebase_reader import fetch_full_rulebase, read_domain

# 1. Populate / Read cached domains from MDS
domain_service = DomainService(client)
domains = await domain_service.populate_domain_cache("mds1")

# 2. Read full package layout (layers, inline layers, sections, rule counts)
package_layout = await read_domain(
    caller=client,
    mgmt_name="mds1",
    domain_name="CMA_EUROPE",
)
```

- **Consumer Rule:** FPCR v2 only maps user requests to selected domains and packages; it never parses raw rulebase JSON or computes rule offsets by hand.

---

### 3.5 Evidence Generation (Session Changes Audit)

Consumers generate compliance and change evidence by delegating session inspection to `arodonata.reports.changes`.

```python
from arodonata.reports.changes import (
    ReportFormat,
    collect_change_report,
    render_change_report,
)

# 1. Collect structured changes from Check Point publication sessions
report = await collect_change_report(
    caller=client,
    mgmt_name="mds1",
    sessions=["session_uid_1", "session_uid_2"],
)

# 2. Render evidence artifact in desired format
markdown_evidence = render_change_report(report, format=ReportFormat.MARKDOWN)
html_evidence = render_change_report(report, format=ReportFormat.HTML)
json_evidence = render_change_report(report, format=ReportFormat.JSON)
```

- **Consumer Rule:** Store rendered evidence in the consumer's audit database (e.g. `ritm_evidence_sessions`) directly from Arodonata's output.

---

## 4. Architectural Summary for AI Coding Agents

When designing or implementing code in consumer repositories (such as `FPCR_v2`):

1. **Always Check Arodonata First:** If a requirement touches Check Point APIs, caching, schema validation, rule positioning, or change reporting, use Arodonata.
2. **Treat Arodonata as a Black-Box Service:** Interact via its public APIs and services (`ArodonataClient`, `CPCRUDService`, `DomainService`, `reports.changes`, `naming`).
3. **Keep Consumer Code Thin:** Consumer code should focus purely on business authorization (e.g. 4-eyes principle), request lifecycle (RITM state machine), WebUI/CLI representation, and persisting consumer-specific state.
