# Session Basics

A learning-oriented walkthrough of raw session management via `api_call()`
directly (no `cpcrud`): capture the current last-published session as a
baseline, create a host, publish, confirm the last-published session
changed, then revert to the saved baseline and confirm it's back — the same
save/revert pattern `cpcrud` examples use internally, shown here explicitly
step by step.

```python title="examples/07_session_basics.py"
--8<-- "examples/07_session_basics.py"
```

Run it:

```bash
uv run examples/07_session_basics.py
```
