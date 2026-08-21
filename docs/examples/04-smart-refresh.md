# Smart Refresh

Populates the cache from a live management server and streams progress via
`SSEEvent`s. Run this once against a fresh database before any other
example — see [Caching & Sync](../architecture/caching-and-sync.md) for how
the underlying `show-changes` incremental refresh works.

By default the example uses a full refresh. For domains that are already
populated, `mode="check"` reloads only stale domains, and
`mode="incremental"` applies just the objects changed since the last
refresh (falling back to a full reload whenever that isn't safe):

```python
async for event in client.refresh_objects(mgmt_names=["mgmt1"], mode="incremental"):
    print(event.message)
```

```python title="examples/04_smart_refresh.py"
--8<-- "examples/04_smart_refresh.py"
```

Run it:

```bash
uv run examples/04_smart_refresh.py
```
