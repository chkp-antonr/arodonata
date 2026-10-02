"""MCP tool change_report: read-only evidence of what policy sessions changed, as markdown (spec 7)."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Annotated

from pydantic import Field, ValidationError

from ..reports.changes import (
    ChangeReportInputError,
    RangeScope,
    RenderOptions,
    SessionScope,
    render_change_report,
)
from ._sdk import MCPServer
from .common import ToolFailure, add_guarded_tool, resolve_mgmt_name

if TYPE_CHECKING:
    from ..api.client import ArodonataClient
    from ..reports.changes import Scope
    from .registry import ToolOptions

MAX_SESSIONS = 20  # D22: fixed, not a parameter
MAX_OBJECTS = 200  # D22
_DESCRIPTION = (
    "Evidence of what Check Point policy sessions changed — rules (with SmartConsole rule numbers), objects and "
    "sections, added/modified/deleted — as markdown. Give session_uids for explicit sessions (published or not), "
    "or a published range: from_session (exclusive) / to_session (inclusive) and/or from_date / to_date (ISO 8601 "
    "with a UTC offset). Reads the live management API read-only (show-changes; show-object for member names) and "
    "numbers rules from the rulebase cache; unpublished sessions get provisional numbers. domain is required ('' "
    "for an SMS or the MDS level); mgmt_name is required when several servers are configured. Shows at most 20 "
    "range sessions and max_rules rule rows; HTML and JSON evidence are available through the arodonata library."
)


def _date(name: str, value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ToolFailure(f"{name} is not an ISO 8601 date-time: {value!r}") from None
    if parsed.tzinfo is None:
        raise ToolFailure(f"{name} needs a UTC offset, e.g. 2026-09-28T18:40:00+03:00")
    return parsed


def _invalid(kind: str, exc: ValidationError) -> ToolFailure:
    fields = sorted({".".join(str(p) for p in e["loc"]) or "bounds" for e in exc.errors(include_input=False)})
    hint = " (a range needs from_session or from_date, and from_date <= to_date)" if kind == "range" else ""
    return ToolFailure(f"invalid {kind}: {', '.join(fields)}{hint}")


def _cut(text: str, limit: int) -> str:
    """Cut at the last complete line that fits together with the truncation marker."""
    if len(text) <= limit:
        return text
    marker = f"…output truncated at {limit} characters, full report via the library"
    end = text.rfind("\n", 0, max(0, limit - len(marker)))
    return (text[: end + 1] if end >= 0 else "") + marker


def register_change_report_tools(server: MCPServer, client: ArodonataClient, opts: ToolOptions) -> list[str]:
    async def change_report(
        domain: Annotated[str, Field(description="Domain name; '' for an SMS or the MDS level")],
        mgmt_name: str | None = None,
        session_uids: list[str] | None = None,
        from_session: str | None = None,
        to_session: str | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        max_rules: int = 100,
    ) -> str:
        if max_rules < 1:
            raise ToolFailure("max_rules must be at least 1")
        mgmt = resolve_mgmt_name(client, mgmt_name)
        lo, hi = _date("from_date", from_date), _date("to_date", to_date)
        scopes: list[Scope] = []
        if session_uids:
            try:
                scopes.append(SessionScope(mgmt_name=mgmt, domain=domain, session_uids=session_uids))
            except ValidationError as exc:
                raise _invalid("session_uids", exc) from None
        if any(v is not None for v in (from_session, to_session, lo, hi)):
            try:
                scopes.append(
                    RangeScope(
                        mgmt_name=mgmt,
                        domain=domain,
                        from_session=from_session,
                        to_session=to_session,
                        from_date=lo,
                        to_date=hi,
                    )
                )
            except ValidationError as exc:
                raise _invalid("range", exc) from None
        if not scopes:
            raise ToolFailure("give session_uids or a range (from_session / to_session / from_date / to_date)")
        try:
            report = await client.collect_change_report(scopes, max_sessions=MAX_SESSIONS)
        except ChangeReportInputError as exc:
            raise ToolFailure(str(exc)) from None
        rendered = render_change_report(
            report,
            ["markdown"],
            RenderOptions(title="Change report", markdown_max_rules=max_rules, markdown_max_objects=MAX_OBJECTS),
        )
        return _cut(rendered.markdown or "", opts.max_result_chars)

    name = opts.name("change_report")
    add_guarded_tool(server, change_report, name=name, description=_DESCRIPTION)
    return [name]
