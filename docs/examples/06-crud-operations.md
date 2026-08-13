# Idempotent CPCRUD

Applies a declarative YAML policy template via `client.cpcrud.apply()`
twice, wrapped in `_session_guard.guarded_session` so the target domain is
snapshotted and reverted afterward regardless of success or failure. On the
second run, everything that already matches the template's intent reports
`unchanged`/`reuse` — zero new `create`s — see [CPCRUD
Engine](../user-guide/cpcrud.md) for the full outcome model.

```python title="examples/06_crud_operations.py"
--8<-- "examples/06_crud_operations.py"
```

Run it:

```bash
uv run examples/06_crud_operations.py
```
