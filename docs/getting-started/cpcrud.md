# CPCRUD: Idempotent Object CRUD

`client.cpcrud` is an idempotent CRUD engine for Check Point objects and
rules. It takes a declarative YAML/dict **template**, resolves it against
live state (`plan()`), and applies it (`apply()`) — re-running the exact
same template is safe and converges to a no-op (`unchanged`/`reuse`, zero
`create`).

See [`CPCRUDService`](../api/arodonata/cpcrud/service.md) for the full API
surface, and [`examples/06_crud_operations.py`](https://github.com/chkp-antonr/arodonata/blob/master/examples/06_crud_operations.py)
/ [`examples/README_CRUD.md`](https://github.com/chkp-antonr/arodonata/blob/master/examples/README_CRUD.md)
for a runnable end-to-end script.

## Template format

A template is an envelope of management servers, each with domains, each
with a list of operations:

```yaml
management_servers:
  - mgmt_name: "10.192.15.140"
    domains:
      - name: "Domain4"
        operations:
          - type: "host"               # operation defaults to "add"
            data:
              name: "example-host-1"
              ip-address: "10.0.0.1"
              comments: "CPCRUD example host"
              color: "dark green"
              groups: ["Examples"]
            on_name_conflict: "error"
            on_ip_conflict: "error"

          - type: "access-rule"
            layer: "Network"
            position: "bottom"         # int (absolute), "top"/"bottom", or
                                        # {top|bottom|above|below: "rule-name"}
            data:
              name: "cpcrud-example-rule"
              source: ["example-host-1"]
              destination: ["any"]
              service: ["any"]
              action: "drop"
              comments: "CPCRUD example access rule"
```

`operation` defaults to `"add"` and can be omitted, as shown above. Rule
types (`access-rule`, `nat-rule`, `threat-prevention-rule`, `https-rule`)
additionally require `layer` (or `package` for NAT) and a `position` on
`add`.

## Operations and types

| `operation` | Meaning | Required fields |
|---|---|---|
| `add` (default) | Create if absent; conflict-policy governed if a match exists | `type`, `data` |
| `update` | Update an existing object/rule | `type`, `key`, `data` |
| `delete` | Delete an existing object/rule | `type`, `key` |
| `show` | Read-only lookup, no mutation | `type`, `key` |

Supported `type` values: `host`, `network`, `address-range`,
`network-group`, `tcp-service`, `udp-service`, `icmp-service`,
`service-group`, `access-rule`, `nat-rule`, `threat-prevention-rule`,
`https-rule`. Rule types need `layer` (or `package` for `nat-rule`); non-rule
types don't.

The full JSON Schema lives at `ops/checkpoint_ops_schema.json` and is what
`validate()` (see [Embedding in applications](#embedding-in-applications))
checks templates against.

## Conflict policies

Two independent policies govern `add` operations when a matching object
already exists:

| Policy | Values | Meaning |
|---|---|---|
| `on_name_conflict` | `update` (default), `error` | What to do when an object of the same name already exists |
| `on_ip_conflict` | `reuse` (default), `error`, `create_new` | What to do when another object already owns the requested IP |

Precedence, highest first: **per-operation** (`on_name_conflict`/
`on_ip_conflict` set directly on the operation) > **argument** passed to
`plan()`/`apply()` (`on_name_conflict=`/`on_ip_conflict=`) > **settings**
(`ARODONATA_CPCRUD_ON_NAME_CONFLICT`/`ARODONATA_CPCRUD_ON_IP_CONFLICT`) >
**built-in default** (`update`/`reuse`).

## Plan / apply / dry-run lifecycle

```python
plan = await client.cpcrud.plan(template)          # resolve against live state
async for event in client.cpcrud.apply(plan):       # or apply(template) directly
    ...                                              # SSEEvent per action, in-flight
report = event                                       # last yielded item is the ApplyReport
print(report.summary)                                # {"create": 2, "unchanged": 1, ...}
```

- `plan()` is read-only: it resolves names/IPs against cached+live state,
  applies conflict policy, and computes each action's `Outcome`
  (`create`/`update`/`reuse`/`unchanged`/`delete`/`conflict`/`error`) without
  writing anything.
- `apply()` accepts either a `Plan` (from `plan()`) or a template directly
  (in which case it plans first). It always yields `SSEEvent`s as it works,
  followed by a final `ApplyReport` as the last item.
- `apply(..., dry_run=True)` walks the plan and yields the same shape of
  events/report without calling any write API — useful for previewing what
  would happen.
- Other `apply()` flags: `force` (skip the "domain published since plan"
  staleness guard), `no_publish`/`discard` (control end-of-session publish
  behavior), `session_name`/`session_description` (label the dedicated
  session cpcrud opens per domain).

## Retrying partial failures

Some outcomes are retryable: `locked` (session lock held by someone else),
`error` (a write failed), and `skipped_dependency` (an action's dependency
failed first). After a pass, `ApplyReport.remaining` holds a `Plan` scoped to
just those actions (actions in domains whose plan went stale are excluded).

Pass `retry_remaining=N` to `apply()` to retry automatically, up to `N`
extra passes, invalidating each affected domain's cache before every retry:

```python
async for event in client.cpcrud.apply(template, retry_remaining=2):
    ...
report = event
```

Passes are merged with `fold_reports()`: the final report's `results` and
`summary` reflect the *last* attempt for each action, not a sum across
passes.

## Inverse templates

`client.cpcrud.inverse(plan, report=None)` builds a schema-valid template
that compensates an applied `Plan`:

- `create` → `delete` (keyed by uid from `report` when available, else by
  resolved name)
- `update` → `update` restoring each changed field's `before` value
- `delete` → `add` replaying the deleted object's `prior_state`
- `reuse`/`unchanged`/`conflict`/`error`/`show` → nothing (no-op, omitted)

Passing `report` scopes the inverse to only the actions that actually
executed in that report (apply-time outcomes like `locked` don't count).
Apply the inverse through the normal `plan()`/`apply()` pipeline — it
re-resolves, re-orders, and re-validates everything:

```python
plan = await client.cpcrud.plan(template)
events = [e async for e in client.cpcrud.apply(plan)]
report = events[-1]

inverse_template = client.cpcrud.inverse(plan, report)
events2 = [e async for e in client.cpcrud.apply(inverse_template)]
```

## Settings

All cpcrud settings live on [`ArodonataSettings`](../api/arodonata/config/settings.md)
and are configured by the calling application (arodonata does not read `.env`
files itself — see the [Configuration Guide](../configuration/index.md)).

| Env var | Field | Default | Description |
|---|---|---|---|
| `ARODONATA_CPCRUD_ON_NAME_CONFLICT` | `cpcrud_on_name_conflict` | `"update"` | Default name conflict policy: `update` \| `error` |
| `ARODONATA_CPCRUD_ON_IP_CONFLICT` | `cpcrud_on_ip_conflict` | `"reuse"` | Default IP conflict policy: `reuse` \| `error` \| `create_new` |
| `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_HOST` | `cpcrud_auto_name_prefix_host` | `"Host_"` | Naming prefix for auto-created host dependencies |
| `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_NETWORK` | `cpcrud_auto_name_prefix_network` | `"Net_"` | Naming prefix for auto-created network dependencies |
| `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_RANGE` | `cpcrud_auto_name_prefix_range` | `"IPR_"` | Naming prefix for auto-created address-range dependencies |
| `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_TCP` | `cpcrud_auto_name_prefix_svc_tcp` | `"TCP_"` | Naming prefix for auto-created TCP service dependencies |
| `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_UDP` | `cpcrud_auto_name_prefix_svc_udp` | `"UDP_"` | Naming prefix for auto-created UDP service dependencies |
| `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_ICMP` | `cpcrud_auto_name_prefix_svc_icmp` | `"ICMP_"` | Naming prefix for auto-created ICMP service dependencies |
| `ARODONATA_CPCRUD_REFRESH_MODE` | `cpcrud_refresh_mode` | `"invalidate"` | Post-publish cache refresh: `invalidate` \| `force` |
| `ARODONATA_CPCRUD_SCHEMA_PATH` | `cpcrud_schema_path` | `""` (bundled schema) | Override path to `checkpoint_ops_schema.json` |

`cpcrud_refresh_mode` is also overridable per call via `apply(..., refresh=...)`.

## Embedding in applications

CPCRUD's public surface — `CPCRUDService.validate()`/`plan()`/`apply()`/
`inverse()`, reached via `client.cpcrud` — is the stable contract embedding
applications should rely on:

- `apply()` is an async generator: it always yields zero or more `SSEEvent`s
  first, then exactly one `ApplyReport` as its final item. Consume it with
  `[e async for e in client.cpcrud.apply(...)][-1]` to get just the report,
  or stream the `SSEEvent`s through to a UI/log as they arrive.
- `validate(template)` is synchronous and side-effect-free: it loads (if
  given a path/string) and schema-validates a template, returning a list of
  error strings (empty means valid). It never touches the network.
- `plan()` and `apply()` both accept a template as **either** a `str`/`Path`
  (loaded as YAML) **or** a plain `dict` already shaped like the schema —
  useful when a caller builds/mutates templates programmatically rather than
  from a file on disk.
- `apply()` also accepts a `Plan` object directly (as returned by `plan()`),
  so callers that need to inspect or log the plan before executing it can
  split the two steps instead of calling `apply()` with a template.
