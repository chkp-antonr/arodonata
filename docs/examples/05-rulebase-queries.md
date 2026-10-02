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

## SmartConsole numbering

`get_package_rulebase`, `get_layer_rulebase` and `locate_rules` number rules exactly like SmartConsole (`1`, `2.1`, `2.2.1`, section ranges) from the rulebase cache.

```python
result = await client.get_package_rulebase("mgmt1", "Domain4", "FPCR_UAT_Active", "access", cache_mode="smart")
for ordered_layer, entries in result.layers:
    for entry in entries:
        if entry.kind != "section":
            print(entry.number, entry.name)
located = await client.locate_rules("mgmt1", "Domain4", [rule_uid], layer_uids=[layer_uid])
print(located.snapshot_session_uid, located.rules[rule_uid], located.layers[layer_uid])  # prefix + show-changes position numbers a deleted rule
```
