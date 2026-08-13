# Inverse (Compensating) Templates

Demonstrates the plan → apply → inverse → apply round-trip: `plan()` once,
`apply()` that same `Plan` object, then `client.cpcrud.inverse(plan, report)`
builds a compensating template scoped to just the actions that actually ran,
and applying *that* restores prior state. See ["Inverse (compensating)
templates"](https://github.com/chkp-antonr/arodonata/blob/master/examples/README_CRUD.md#inverse-compensating-templates)
for why you must never re-`plan()` after `apply()` in this flow.

```python title="examples/07_crud_inverse.py"
--8<-- "examples/07_crud_inverse.py"
```

Run it:

```bash
uv run examples/07_crud_inverse.py
```
