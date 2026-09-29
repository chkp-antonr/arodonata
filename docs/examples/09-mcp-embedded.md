# Embedded MCP

Serves Arodonata's MCP tool set from inside a FastAPI application, alongside a `/healthz` route and an application-specific demo tool.
This is the pattern to follow when you want to mount Arodonata's MCP endpoint in an app you already run, rather than deploying the standalone `arodonata-mcp` server.

```python title="examples/09_mcp_embedded.py"
--8<-- "examples/09_mcp_embedded.py"
```

Run it:

```bash
uv run examples/09_mcp_embedded.py
```
