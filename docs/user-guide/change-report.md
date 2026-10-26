# Auditable Change Reports (`arodonata.reports`)

Arodonata v2 provides a read-only change evidence collector and offline multi-format renderer (`HTML`, `Markdown`, `JSON`) in `src/arodonata/reports/` and on `ArodonataClient`.

It is designed for change-management tickets, compliance audits, and human-in-the-loop review of both **unpublished staged sessions** and **historical published sessions**.

## 1. Scopes: `SessionScope` vs `RangeScope`

You can collect change reports across one or more management servers and domains in a single call by passing `SessionScope` or `RangeScope` items:

```python
from datetime import datetime, UTC
from arodonata import ArodonataClient, RangeScope, RenderOptions, SessionScope

async with ArodonataClient() as client:
    # Option A: Inspect specific session UIDs (published or currently open)
    scope_sessions = SessionScope(
        mgmt_name="mdsm-prod",
        domain="Domain4",
        session_uids=["4a8b9c10-..."],
    )

    # Option B: Inspect all published sessions within a UTC time window or session range
    scope_range = RangeScope(
        mgmt_name="mdsm-prod",
        domain="Domain4",
        from_date=datetime(2026, 10, 25, 0, 0, tzinfo=UTC),
        to_date=datetime(2026, 10, 26, 0, 0, tzinfo=UTC),
    )

    bundle = await client.build_change_report(
        [scope_sessions, scope_range],
        formats=["html", "markdown", "json"],
        options=RenderOptions(
            title="Firewall Change Evidence — Ticket CHG-10492",
            include_object_changes=True,
            include_field_diffs=True,
            include_warnings=True,
        ),
    )

    # Save rendered outputs
    Path("report.html").write_bytes(bundle.html)
    Path("report.md").write_text(bundle.markdown, encoding="utf-8")
    Path("report.json").write_text(bundle.json_text, encoding="utf-8")
```

## 2. Unpublished Live Numbering vs Published Cached Numbering

A key capability in Arodonata v2 is accurate SmartConsole rule numbering (`1`, `2.1`, `3`) even for **uncommitted rules inside an open `WriteSession` or staged CPCRUD session**:

1. **Live Unpublished Session (`OwnedSession`)**:
   - When you pass `owned_sessions=[OwnedSession(mgmt_name=..., domain=..., session_uid=..., sid=ws.sid, server_ip=ws.server_ip)]` in `RenderOptions`, the collector reads the rulebase directly through that unpublished `sid` (strictly read-only `show-*` calls) so newly added or moved rules receive their exact post-change SmartConsole rule numbers before `publish`!
   - The `OwnedSession.sid` is never stored in `ChangeReport` and is redacted in `__repr__` and all rendered outputs.
2. **Published Session Fallback**:
   - For already-published sessions (or when no `OwnedSession` is provided), the collector resolves rule numbers and layer locations from the cached rulebase snapshot (`arodonata_rulebase_*`), complemented by bounded (`MAX_UID_LOOKUPS = 200`) live `show-object` UID resolution for referenced objects.
