# Gateway Relationships

Groups gateways by `parent_uid` to separate cluster members from standalone
gateways — see [Sessions & Multi-Domain](../architecture/sessions-and-mdm.md)
for how domain context flows through these results.

```python title="examples/03_gateway_relationships.py"
--8<-- "examples/03_gateway_relationships.py"
```

Run it:

```bash
uv run examples/03_gateway_relationships.py
```
