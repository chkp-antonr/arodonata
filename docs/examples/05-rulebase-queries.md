# Rulebase Queries

Reads access and NAT rules from the cache, filtered to enabled access rules
only as an example of the `enabled_only` filter shared by all rulebase
helper methods.

```python title="examples/05_rulebase_queries.py"
--8<-- "examples/05_rulebase_queries.py"
```

Run it:

```bash
uv run examples/05_rulebase_queries.py
```

NAT rules are cached per policy package, so filter them with `layer_name="<package name>"` (not `"NAT"`); the example script reads the package name from the `NAT_PACKAGE` environment variable (unset returns all NAT rules). Rule `action` values are Check Point names such as `"Accept"` and `"Drop"`.
