# 07 — Contexts & Session Overlay (`07_context_and_overlay.py`)

Demonstrates runtime `auth_context`, `user_context`, and isolated `write_session` with `SessionOverlay` read-your-own-writes isolation (verifying that uncommitted objects appear immediately in `get_hosts()`, `find_object()`, and `search_objects()` before discarding cleanly on exit).

## Source Code (`examples/07_context_and_overlay.py`)

```python title="examples/07_context_and_overlay.py"
--8<-- "examples/07_context_and_overlay.py"
```
