"""Tools that have no counterpart in the reference server."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any, Literal

from ..api.schemas import SSEEvent, SSEEventType
from ._sdk import Context, MCPServer
from .common import ToolFailure, add_guarded_tool, ensure_success, list_envelope, resolve_mgmt_name, to_api_payload
from .projection import cache_age_seconds

if TYPE_CHECKING:
    from ..api.client import ArodonataClient
    from .registry import ToolOptions


async def _report_log_progress(ev: SSEEvent, ctx: Context | None) -> None:
    """Forward a LOG event's ``count``/``total`` (when present) to the client as progress.

    ``ctx.warning``/``ctx.log`` are deprecated in the installed SDK (MCPDeprecationWarning); only
    ``report_progress`` is used here. Warnings are surfaced to the model through the tool's returned
    ``warnings`` list instead of the deprecated logging capability.
    """
    if ctx is not None and "count" in ev.data:
        total = ev.data.get("total")
        await ctx.report_progress(float(ev.data["count"]), float(total) if total else None, ev.message)


async def drain_events(
    events: AsyncIterator[SSEEvent], ctx: Context | None
) -> tuple[dict[str, Any], dict[str, Any], list[str], list[str]]:
    """Consume a facade event stream. Returns (result_data, complete_data, warnings, errors)."""
    result: dict[str, Any] = {}
    complete: dict[str, Any] = {}
    warnings: list[str] = []
    errors: list[str] = []
    async for ev in events:
        if ev.event_type == SSEEventType.RESULT:
            result = ev.data
        elif ev.event_type == SSEEventType.COMPLETE:
            complete = ev.data
        elif ev.event_type == SSEEventType.WARNING:
            warnings.append(ev.message or "")
        elif ev.event_type == SSEEventType.ERROR:
            errors.append(ev.message or "")
        elif ev.event_type == SSEEventType.LOG:
            await _report_log_progress(ev, ctx)
    return result, complete, warnings, errors


_SEARCH_MATCH_KEYS = ("mgmt_name", "domain", "search_term", "search_type", "objects", "memberships")


def _as_search_match(data: dict[str, Any]) -> dict[str, Any]:
    """Project an event's ``data`` onto the fixed domain-match shape ``search_objects`` returns."""
    match = {key: data.get(key) for key in _SEARCH_MATCH_KEYS}
    match["objects"] = match["objects"] or []
    return match


async def drain_search_events(
    events: AsyncIterator[SSEEvent], ctx: Context | None
) -> tuple[list[dict[str, Any]], dict[str, Any], list[str], list[str]]:
    """Consume ``search_objects``' event stream. Returns (results, complete_data, warnings, errors).

    ``search_service.search_objects`` streams each domain's matches inside ``LOG`` events' ``data``
    (keys: mgmt_name, domain, search_term, search_type, objects, memberships) rather than a single
    ``RESULT`` event, so every ``LOG`` event carrying an ``objects`` key is collected as one result
    entry. A ``RESULT`` event is still honoured if one is ever emitted and has the same shape (an
    ``objects`` key), for forward/backward compatibility with the facade.
    """
    results: list[dict[str, Any]] = []
    complete: dict[str, Any] = {}
    warnings: list[str] = []
    errors: list[str] = []
    async for ev in events:
        if ev.event_type == SSEEventType.LOG:
            if "objects" in ev.data:
                results.append(_as_search_match(ev.data))
            await _report_log_progress(ev, ctx)
        elif ev.event_type == SSEEventType.RESULT:
            if "objects" in ev.data:
                results.append(_as_search_match(ev.data))
        elif ev.event_type == SSEEventType.COMPLETE:
            complete = ev.data
        elif ev.event_type == SSEEventType.WARNING:
            warnings.append(ev.message or "")
        elif ev.event_type == SSEEventType.ERROR:
            errors.append(ev.message or "")
    return results, complete, warnings, errors


async def _run_api_call(
    client: ArodonataClient,
    opts: ToolOptions,
    command: str,
    mgmt_name: str | None,
    domain: str | None,
    payload: dict[str, Any] | None,
    paginate: bool,
    details_level: Literal["uid", "standard", "full"],
) -> dict[str, Any]:
    """Validate write-access, dispatch to ``api_call``/``api_query``, and envelope the result."""
    if not command.startswith("show-") and not opts.allow_write_api:
        raise ToolFailure(
            f"command '{command}' is not allowed: only show-* commands unless ARODONATA_MCP_ALLOW_WRITE_API=true"
        )
    mgmt = resolve_mgmt_name(client, mgmt_name)
    body = to_api_payload(payload or {})
    if paginate:
        query = await client.api_query(
            mgmt,
            command,
            domain=domain or "",
            details_level=details_level,
            payload=body,
            container_key="objects",
        )
        ensure_success(query, command)
        return list_envelope(query.objects, offset=0, limit=0, total=query.total, source="live")
    result = await client.api_call(mgmt, command, domain=domain or "", details_level=details_level, payload=body)
    ensure_success(result, command)
    return {"data": result.data, "source": "live"}


def register_native_tools(server: MCPServer, client: ArodonataClient, opts: ToolOptions) -> list[str]:
    names: list[str] = []

    async def arodonata_init() -> dict[str, Any]:
        """Call this first. Lists configured management servers, whether each is Multi-Domain (MDS), their domains, and how old the object cache is. Use the returned mgmt_name and domain values in other tools."""
        mgmt_names = client.get_mgmt_names()
        domains = await client.get_domains(include_global=False)
        servers = []
        for mgmt in mgmt_names:
            mine = [d for d in domains if d.mgmt_name == mgmt]
            servers.append(
                {"mgmt_name": mgmt, "is_mds": any(d.is_mdm for d in mine), "domains": [d.name for d in mine]}
            )
        last = await client.cache.get_objects_last_update()
        if len(mgmt_names) == 1:
            guidance = f"One management server is configured ('{mgmt_names[0]}'); the mgmt_name parameter is optional."
        else:
            guidance = "Several management servers are configured; pass mgmt_name to every tool."
        guidance += " For MDS servers pass domain; omit it for single-domain servers. Tools marked cache-backed answer from the local cache; pass cache_mode='smart' to re-sync stale data first or cache_mode='force' for a full reload from the management server."
        return {"servers": servers, "cache_age_seconds": cache_age_seconds(last), "guidance": guidance}

    add_guarded_tool(server, arodonata_init, name=opts.name("arodonata_init"))
    names.append(opts.name("arodonata_init"))

    async def search_objects(
        search_input: str,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        refresh: Literal["skip", "check", "force", "incremental"] = "skip",
        max_depth: int = 2,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Search cached objects across servers and domains by comma-separated names, IPs or patterns, following group membership up to max_depth. refresh='check' re-syncs stale domains first."""
        results, complete, warnings, errors = await drain_search_events(
            client.search_objects(
                search_input=search_input,
                mgmt_names=mgmt_names,
                domain_names=domain_names,
                refresh=refresh,
                max_depth=max_depth,
            ),
            ctx,
        )
        return {"results": results, "summary": complete, "warnings": warnings, "errors": errors}

    async def refresh_objects(
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        mode: Literal["skip", "check", "force", "incremental"] = "force",
        include_global: bool = False,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Re-sync the object cache from the management server(s). 'incremental' pulls only changes since the last publish; 'force' reloads everything. Long-running; progress is reported."""
        _, complete, warnings, errors = await drain_events(
            client.refresh_objects(
                mgmt_names=mgmt_names, domain_names=domain_names, mode=mode, include_global=include_global
            ),
            ctx,
        )
        return {"summary": complete, "warnings": warnings, "errors": errors}

    async def refresh_rulebases(
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        mode: Literal["skip", "check", "force"] = "force",
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Re-sync cached access, NAT, HTTPS and threat rulebases. Long-running; progress is reported."""
        _, complete, warnings, errors = await drain_events(
            client.refresh_rulebases(mgmt_names=mgmt_names, domain_names=domain_names, mode=mode), ctx
        )
        return {"summary": complete, "warnings": warnings, "errors": errors}

    async def api_call(
        command: str,
        mgmt_name: str | None = None,
        domain: str | None = None,
        payload: dict[str, Any] | None = None,
        paginate: bool = False,
        details_level: Literal["uid", "standard", "full"] = "standard",
    ) -> dict[str, Any]:
        """Run any Management API command through Arodonata's session handling. payload keys may be given in the API's kebab-case (e.g. 'ip-address') or in snake_case (e.g. 'ip_address'); snake_case keys, including keys of nested objects, are converted to kebab-case. Only show-* commands are allowed unless the server enables writes. paginate=true collects all pages of a list command."""
        return await _run_api_call(client, opts, command, mgmt_name, domain, payload, paginate, details_level)

    for fn, base in (
        (search_objects, "search_objects"),
        (refresh_objects, "refresh_objects"),
        (refresh_rulebases, "refresh_rulebases"),
        (api_call, "api_call"),
    ):
        add_guarded_tool(server, fn, name=opts.name(base))
        names.append(opts.name(base))

    return names
