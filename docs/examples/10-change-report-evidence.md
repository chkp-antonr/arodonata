# Change Report Evidence

Builds change evidence for one policy change in a lab domain. A setup session creates and publishes hosts, a group and access rules in two sections and an inline layer; the change session then adds, modifies, moves, disables and deletes rules and objects. The script writes three reports (HTML and JSON) for the change session: pending, numbered live through the app's own session; pending without that session, numbered provisionally with a warning; and published, numbered from the cache. Together they show every status: `NEW`, changed cells with added and removed items, `(was N)` for a moved rule, the disabled ✗ marker and grey row, `DELETED`, section rows, the details tables and the warnings block. The script is lab only, and the session guard reverts the domain to its last published session afterwards. See [Change Report](../user-guide/change-report.md) for the feature.

HTML needs the `report` extra:

```bash
uv sync --extra report
```

```python title="examples/10_change_report_evidence.py"
--8<-- "examples/10_change_report_evidence.py"
```

Run it:

```bash
ARODONATA_LAB=home uv run examples/10_change_report_evidence.py
```
