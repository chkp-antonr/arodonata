# Change Report Evidence

Builds change evidence for one policy session in a lab domain: it creates hosts, a group and access rules (one in an inline layer) inside a guarded session, writes the pending evidence numbered live through the app's own session (HTML and JSON), publishes, then writes the published evidence numbered from the cache. The rows show `NEW`, the disabled ✗ marker and grey rows. The script is lab only, and the session guard reverts the domain to its last published session afterwards. See [Change Report](../user-guide/change-report.md) for the feature.

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
