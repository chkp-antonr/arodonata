# Smart Refresh

Populates the cache from a live management server and streams progress via
`SSEEvent`s. Run this once against a fresh database before any other
example — see [Caching & Sync](../architecture/caching-and-sync.md) for how
the underlying `show-changes` incremental refresh works.

```python title="examples/04_smart_refresh.py"
--8<-- "examples/04_smart_refresh.py"
```

Run it:

```bash
uv run examples/04_smart_refresh.py
```
