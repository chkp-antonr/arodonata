# CPCRUD — Declarative Policy-as-Code Engine (`client.cpcrud`)

`client.cpcrud` (`CPCRUDService`) provides a deterministic, two-phase (`plan` -> `apply`) Policy-as-Code CRUD engine for Check Point Security Management and MDSM servers with offline JSON Schema validation, two-axis conflict resolution, staleness guards, and compensating rollback templates (`inverse`).

## Quick Start

```bash
ARODONATA_LAB=home uv run examples/08_cpcrud_operations.py
ARODONATA_LAB=home uv run examples/09_cpcrud_inverse.py
```

- `08_cpcrud_operations.py` validates `examples/crud_example.yaml` offline, plans and applies it twice in `Domain4`, and verifies that Run 2 produces `unchanged` outcomes with zero `create` actions.
- `09_cpcrud_inverse.py` plans and applies a template, generates a compensating rollback template via `client.cpcrud.inverse(plan, report)`, and applies the rollback.

## Template Structure

Templates are validated offline against `src/arodonata/cpcrud/checkpoint_ops_schema.json` using `client.cpcrud.validate(template)` (zero network or database calls):

```yaml
version: 1
mgmt_name: "10.192.15.140"
domain: "Domain4"
on_name_conflict: "update"
on_ip_conflict: "reuse"

objects:
  - type: "host"
    name: "cpcrud-example-host-1"
    ipv4-address: "198.51.100.10"
    comments: "CPCRUD example host"
    color: "dark green"

  - type: "network"
    name: "cpcrud-example-net-1"
    subnet4: "198.51.100.0"
    mask-length4: 24

services:
  - type: "service-tcp"
    name: "cpcrud-example-tcp-8443"
    port: "8443"

groups:
  - type: "group"
    name: "cpcrud-example-group"
    members:
      - "cpcrud-example-host-1"
      - "cpcrud-example-net-1"

rules:
  - type: "access-rule"
    layer: "FPCR_UAT_Active Network"
    position: "bottom"
    name: "cpcrud-example-access-rule"
    source: ["cpcrud-example-host-1"]
    destination: ["Any"]
    service: ["cpcrud-example-tcp-8443"]
    rule_action: "Drop"
```

Multi-domain templates can also group operations under `targets:` (or `domains:`), where each item specifies its own `mgmt_name`, `domain`, and `objects` / `services` / `groups` / `rules` / `operations`.

## Two-Axis Conflict Policies

### `on_name_conflict`

Controls what happens when an object with the requested `name` already exists with different attributes:

| Value | Behavior |
| --- | --- |
| `update` (default) | Plans `Outcome.UPDATE` (`set-<type>`) with a field-level diff |
| `error` | Plans `Outcome.ERROR` and skips dependent groups/rules (`Outcome.SKIPPED_DEPENDENCY`) |

### `on_ip_conflict`

Controls what happens when no object has the requested `name`, but another object already owns the same IPv4/subnet/range or service port:

| Value | Behavior |
| --- | --- |
| `reuse` (default) | Plans `Outcome.REUSE` and maps `requested_name -> resolved_name` in `Plan.name_resolutions` so downstream groups and rules reference the existing object |
| `create_new` | Plans `Outcome.CREATE` using convention-compliant `NamingPrefixes` (`Host_<ip>`, `Net_<subnet>_<mask>`, `IPR_<first>-<last>`, `TCP_<port>`, `UDP_<port>`) |
| `error` | Plans `Outcome.ERROR` and skips dependent actions |

## Staleness Protection & Execution Options

1. **Pre-Lookup `DomainStamp`**: `client.cpcrud.plan(template)` captures `show-last-published-session` (`last_session_uid`, `last_published_at`) for every target domain BEFORE reading state.
2. **Staleness Guard on `apply()`**: `await client.cpcrud.apply(plan, force=False)` re-verifies each domain's published head before opening a write session. If another administrator published changes since `plan()`, `apply(force=False)` aborts that domain with `Outcome.PLAN_STALE`. Pass `force=True` to override.
3. **Staged Sessions (`no_publish=True, keep_session=True`)**: Leaves the dedicated write session open on the server and returns `StagedSessionInfo` in `ApplyReport.staged_sessions` (with `.sid` redacted in `repr()` and logs).
4. **Automatic Retries (`retry_remaining=N`)**: Retries failed or locked actions up to `N` additional passes.

## Compensating Rollback (`inverse`)

Always pass the original `Plan` (captured before `apply`) and the resulting `ApplyReport` to `client.cpcrud.inverse(plan, report)`:

```python
plan = await client.cpcrud.plan(template)
report = await client.cpcrud.apply(plan)

inverse_template = client.cpcrud.inverse(plan, report)
inv_plan = await client.cpcrud.plan(inverse_template)
inv_report = await client.cpcrud.apply(inv_plan)
```
