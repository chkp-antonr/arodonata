# CPCRUD - Idempotent Object CRUD Engine

The `client.cpcrud` property provides an idempotent CRUD engine that processes YAML operation templates against Check Point management servers. Apply the same template repeatedly and get deterministic, conflict-aware results.

## Quick Start

```bash
uv run examples/06_crud_operations.py
```

This loads `examples/crud_example.yaml`, applies it twice, and prints a summary. Run 2 should show `unchanged` (and `reuse` for auto-created dependencies), zero `create`, demonstrating idempotency.

## Template Format

Templates are YAML files with the following structure:

```yaml
management_servers:
  - mgmt_name: "server-name"
    domains:
      - name: "Domain-Name"
        operations:
          - type: "host"               # operation defaults to "add"
            data:
              name: "my-host"
              ip-address: "10.0.0.1"
            on_name_conflict: "error"   # default: "update"
            on_ip_conflict: "error"     # default: "reuse"
```

The `operation` field defaults to `add` and can be omitted for add operations.

## Conflict Resolution Policies

### on_name_conflict

Controls what happens when an object with the same name already exists.

| Value | Behavior |
|-------|----------|
| `update` (default) | Update the existing object with the new data |
| `error` | Raise an error and skip the operation |

### on_ip_conflict

Controls what happens when another object already uses the same IP address.

| Value | Behavior |
|-------|----------|
| `reuse` (default) | Reuse the existing IP, proceed with the operation |
| `error` | Raise an error and skip the operation |
| `create_new` | Create a new object sharing the IP address |

## Result Summary

Each `client.cpcrud.apply()` call yields SSE events and finishes with an `ApplyReport` whose `summary` attribute holds per-outcome counts, keyed by the lowercase `Outcome` values: `create`, `update`, `reuse`, `unchanged`, `delete`, `conflict`, `error`, `locked`, `drifted`, `skipped_dependency`, `plan_stale`.

## Retrying partial failures: `retry_remaining`

If a pass leaves some actions in a retryable state (`locked`, `error`, or
`skipped_dependency`), the `ApplyReport.remaining` field holds a `Plan` scoped
to just those actions. Pass `retry_remaining=N` to `apply()` to have it retry
automatically, up to `N` extra passes, invalidating the affected domains'
cache before each retry:

```python
async for event in client.cpcrud.apply(template, retry_remaining=2):
    ...
report = event  # the final yielded item is the folded ApplyReport
```

Passes are merged with `fold_reports()` (last result per action wins); the
final report's `summary` and `results` reflect the last attempt for each
action, not a naive sum across passes.

## Post-publish cache refresh: `refresh`

After a domain publishes, `apply()` invalidates that domain's cache by
default (`refresh="invalidate"` or the `ARODONATA_CPCRUD_REFRESH_MODE`
setting). Pass `refresh="force"` to additionally trigger an immediate
`refresh_objects(..., mode="force")` call against that domain right after
publish, instead of waiting for the next read to repopulate it lazily.

## Inverse (compensating) templates

`client.cpcrud.inverse(plan, report=None)` builds a schema-valid template
that undoes an applied `Plan`: created objects become `delete`s (keyed by uid
when `report` is given, else by name), updates roll back to their `before`
values, and deletes are replayed as `add`s from the deleted object's
`prior_state`. Reuse/unchanged/conflict/error actions produce nothing to
compensate. Passing `report` scopes the inverse to only the actions that
actually executed in that report:

```python
plan = await client.cpcrud.plan(template)
events = [e async for e in client.cpcrud.apply(plan)]
report = events[-1]
inverse_template = client.cpcrud.inverse(plan, report)
events2 = [e async for e in client.cpcrud.apply(inverse_template)]
```
