# OTel-Traced Smart Refresh

Same cache refresh as [Smart Refresh](04-smart-refresh.md), but with
OpenTelemetry tracing enabled via `arlogi.otel.setup_tracing()` — arodonata
never owns a `TracerProvider` itself (see [Configuration
Guide](../configuration/index.md#tracing)), so a standalone script that
wants tracing sets one up itself, same as this example does. Prints the
same wall-clock total as `04_smart_refresh.py` for comparison, plus a
per-span-name timing breakdown read back from the exported trace files.

```python title="examples/08_otel_smart_refresh.py"
--8<-- "examples/08_otel_smart_refresh.py"
```

Run it:

```bash
uv run examples/08_otel_smart_refresh.py
```
