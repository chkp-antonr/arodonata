"""MCP administrative, cache synchronization, reporting, API reference, and raw API call tools."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

import arlogi
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult

from arodonata.client import ArodonataClient
from arodonata.core.errors import ValidationError, redact_sid, sanitize_mapping
from arodonata.core.models.common import SyncScope, normalize_object_type, normalize_service_type
from arodonata.core.primitives import is_readonly_command, validate_command_name
from arodonata.mcp.config import ArodonataMCPSettings
from arodonata.mcp.errors import (
    ToolFailure,
    collect_known_sids,
    consume_live_quota_if_needed,
    json_tool_result,
    mcp_tool_guard,
    register_active_mcp_sid,
    resolve_mgmt_name,
    validate_domain_or_fail,
)
from arodonata.mcp.quota import MCPToolQuotaManager
from arodonata.mcp.tools._common import (
    MAX_MCP_API_TIMEOUT_SECONDS,
    _is_refresh_action,
    resolve_and_validate_scope,
)
from arodonata.reports import RangeScope, RenderOptions, ReportScope, SessionScope

logger = arlogi.get_logger(__name__)


def _parse_iso_datetime(
    value: str | None,
    field_name: str,
    mgmt_name: str,
    domain: str | None,
) -> datetime | None:
    """Parse an optional ISO-8601 timestamp string or raise an actionable `ToolFailure`."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ToolFailure(
            f"Invalid ISO-8601 {field_name!r} value {value!r}: expected non-empty ISO-8601 date/time string.",
            mgmt_name=mgmt_name,
            domain=domain,
        )
    try:
        return datetime.fromisoformat(value.strip())
    except ValueError as exc:
        raise ToolFailure(
            f"Invalid ISO-8601 {field_name!r} value {value!r}: {exc}. "
            "Expected ISO-8601 format such as '2026-10-24T00:00:00Z'.",
            mgmt_name=mgmt_name,
            domain=domain,
        ) from exc


def register_admin_tools(
    server: MCPServer,
    client_getter: Callable[[], ArodonataClient],
    mcp_settings: ArodonataMCPSettings,
    *,
    quota_manager: MCPToolQuotaManager | None = None,
) -> None:
    """Register `cache_control`, `change_report`, `api_call`, and `api_reference`."""

    @server.tool(
        name="cache_control",
        description=(
            "Inspect cache freshness across scopes (action='status') or trigger scoped synchronization "
            "(action='refresh', scope='domains'|'objects'|'services'|'assets'|'rulebase'|'topology', "
            "with optional gateways and collect_routes for scope='topology')."
        ),
    )
    @mcp_tool_guard("cache_control", client_getter, quota_manager=quota_manager, is_live_tool=_is_refresh_action)
    async def cache_control(
        action: Literal["status", "refresh"] = "status",
        mgmt_name: str | None = None,
        domain: str | None = None,
        domains: list[str] | None = None,
        scope: SyncScope | None = None,
        types: list[str] | None = None,
        gateways: list[str] | str | None = None,
        collect_routes: bool = False,
        include_global: bool = False,
        mode: Literal["cache", "smart", "smart-fast", "force"] = "smart",
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name) if mgmt_name else None

        if action == "status":
            status_data = await client.get_cache_status(
                mgmt_name=eff_mgmt,
                domain_name=domain.strip() if domain else None,
                scope=scope,
            )
            known_sids = await collect_known_sids(client, eff_mgmt)
            return json_tool_result(status_data, known_sids=known_sids)

        if action != "refresh":
            raise ToolFailure(f"Invalid cache_control action {action!r}. Expected 'status' or 'refresh'.")

        target_scope: SyncScope = scope or "objects"
        if target_scope == "domains":
            dom_cache_mode: Literal["cache", "smart", "force"] = (
                "force" if mode == "force" else ("cache" if mode == "cache" else "smart")
            )
            refreshed_domains = await client.get_domains(
                mgmt_name=eff_mgmt,
                include_global=include_global,
                cache_mode=dom_cache_mode,
            )
            known_sids = await collect_known_sids(client, eff_mgmt)
            return json_tool_result(
                {
                    "scope": "domains",
                    "mgmt_name": eff_mgmt,
                    "refreshed_count": len(refreshed_domains),
                    "domains": [d.name for d in refreshed_domains],
                },
                known_sids=known_sids,
            )

        clean_domain_pre = domain.strip() if domain and domain.strip() else None
        raw_domains = [d.strip() for d in domains if d and d.strip()] if domains is not None else None
        pre_target_domains = raw_domains if domains is not None else ([clean_domain_pre] if clean_domain_pre else None)
        if pre_target_domains and len(pre_target_domains) > 50:
            raise ToolFailure(
                "cache_control(action='refresh') supports at most 50 explicit domains per call.",
                mgmt_name=eff_mgmt,
            )
        explicit_quota_charged = False
        if mode != "cache" and pre_target_domains is not None and len(pre_target_domains) > 1:
            consume_live_quota_if_needed(cost=len(pre_target_domains))
            explicit_quota_charged = True

        eff_mgmt, eff_domain, clean_domains = await resolve_and_validate_scope(
            client,
            mgmt_name,
            domain=domain,
            domains=domains,
            cache_mode=mode,
        )
        target_domains = clean_domains if domains is not None else ([eff_domain] if eff_domain else None)
        if mode != "cache" and not explicit_quota_charged and target_domains is None:
            cached_doms = await client.cache.get_domains(mgmt_name=eff_mgmt, include_global=include_global)
            fanout_count = min(max(1, len(cached_doms)), 50)
            if fanout_count > 1:
                consume_live_quota_if_needed(
                    cost=fanout_count,
                    cap_at_limit_if_empty=(domain is None and domains is None),
                )
        if target_scope == "objects":
            normalized_obj_types = [normalize_object_type(t) for t in types if t and t.strip()] if types else None
            outcome = await client.refresh_objects(
                mgmt_name=eff_mgmt,
                domains=target_domains,
                types=normalized_obj_types,
                include_global=include_global,
                mode=mode,
            )
        elif target_scope == "services":
            normalized_svc_types = [normalize_service_type(t) for t in types if t and t.strip()] if types else None
            outcome = await client.refresh_services(
                mgmt_name=eff_mgmt,
                domains=target_domains,
                types=normalized_svc_types,
                include_global=include_global,
                mode=mode,
            )
        elif target_scope == "assets":
            outcome = await client.refresh_assets(
                mgmt_name=eff_mgmt,
                domains=target_domains,
                include_global=include_global,
                mode=mode,
            )
        elif target_scope == "topology":
            outcome = await client.refresh_topology(
                mgmt_name=eff_mgmt,
                domains=target_domains,
                gateways=gateways,
                collect_routes=collect_routes,
                include_global=include_global,
                mode=mode,
            )
        else:
            outcome = await client.refresh_rulebases(
                mgmt_name=eff_mgmt,
                domains=target_domains,
                include_global=include_global,
                mode=mode,
            )
        known_sids = await collect_known_sids(client, eff_mgmt)
        return json_tool_result(outcome.model_dump(mode="json"), known_sids=known_sids)

    @server.tool(
        name="change_report",
        description=(
            "Collect and render an auditable Check Point session change report across explicit session UIDs "
            "or a published date/session range in markdown, json, or html format."
        ),
    )
    @mcp_tool_guard("change_report", client_getter, quota_manager=quota_manager, is_live_tool=True)
    async def change_report(
        mgmt_name: str | None = None,
        domain: str | None = None,
        session_uids: list[str] | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        from_session: str | None = None,
        to_session: str | None = None,
        scopes: list[dict[str, Any]] | None = None,
        format: Literal["markdown", "json", "html"] = "markdown",
        title: str = "Check Point Policy Change Report",
        include_object_changes: bool = True,
        include_field_diffs: bool = True,
        include_warnings: bool = True,
        include_system_objects: bool = False,
    ) -> CallToolResult:
        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        probed_servers: set[str] = set()
        validated_dom_cache: dict[tuple[str, str], str] = {}

        async def _validate_dom_once(srv: str, dom_val: str | None) -> str | None:
            if not dom_val or not dom_val.strip():
                return None
            clean_d = dom_val.strip()
            key = (srv, clean_d)
            if key in validated_dom_cache:
                return validated_dom_cache[key]
            allow_live = srv not in probed_servers
            probed_servers.add(srv)
            res_d = await validate_domain_or_fail(client, srv, clean_d, allow_refresh=allow_live)
            if res_d is not None:
                validated_dom_cache[key] = res_d
            return res_d

        parsed_scopes: list[ReportScope | dict[str, Any]] = []
        if scopes:
            if len(scopes) > 20:
                raise ToolFailure(
                    "change_report supports at most 20 scopes per request.",
                    mgmt_name=eff_mgmt,
                    domain=domain.strip() if domain and domain.strip() else None,
                )
            if len(scopes) > 1:
                consume_live_quota_if_needed(cost=len(scopes))
            eff_domain = await _validate_dom_once(eff_mgmt, domain)
            for raw_sc in scopes:
                sc_mgmt = resolve_mgmt_name(client, raw_sc.get("mgmt_name") or eff_mgmt)
                sc_dom = await _validate_dom_once(sc_mgmt, raw_sc.get("domain") or eff_domain)
                sc_copy = dict(raw_sc)
                sc_copy["mgmt_name"] = sc_mgmt
                sc_copy["domain"] = sc_dom
                for date_field in ("from_date", "to_date"):
                    if (
                        date_field in sc_copy
                        and sc_copy[date_field] is not None
                        and not isinstance(sc_copy[date_field], datetime)
                    ):
                        sc_copy[date_field] = _parse_iso_datetime(sc_copy[date_field], date_field, sc_mgmt, sc_dom)
                parsed_scopes.append(sc_copy)
        elif session_uids:
            eff_domain = await _validate_dom_once(eff_mgmt, domain)
            parsed_scopes.append(
                SessionScope(
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                    session_uids=session_uids,
                )
            )
        elif any(x is not None for x in (from_date, to_date, from_session, to_session)):
            eff_domain = await _validate_dom_once(eff_mgmt, domain)
            parsed_from = _parse_iso_datetime(from_date, "from_date", eff_mgmt, eff_domain)
            parsed_to = _parse_iso_datetime(to_date, "to_date", eff_mgmt, eff_domain)
            parsed_scopes.append(
                RangeScope(
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                    from_date=parsed_from,
                    to_date=parsed_to,
                    from_session=from_session,
                    to_session=to_session,
                )
            )
        else:
            eff_domain = await _validate_dom_once(eff_mgmt, domain)
            raise ToolFailure(
                "Provide 'session_uids', range bounds ('from_date', 'to_date', 'from_session', 'to_session'), or 'scopes'.",
                mgmt_name=eff_mgmt,
                domain=eff_domain,
            )

        options = RenderOptions(
            title=title,
            include_object_changes=include_object_changes,
            include_field_diffs=include_field_diffs,
            include_warnings=include_warnings,
            include_system_objects=include_system_objects,
        )
        bundle = await client.build_change_report(parsed_scopes, formats=[format], options=options)
        if format == "html" and bundle.html is not None:
            rendered = bundle.html.decode("utf-8")
        elif format == "json" and bundle.json_text is not None:
            rendered = bundle.json_text
        else:
            rendered = bundle.markdown or ""

        known_sids = await collect_known_sids(client, eff_mgmt)
        return json_tool_result(
            {
                "format": format,
                "title": bundle.report.title,
                "session_count": len(bundle.report.sessions),
                "warning_count": len(bundle.report.warnings),
                "rendered": redact_sid(rendered, known_sids=known_sids),
                "report": bundle.report.model_dump(mode="json"),
            },
            known_sids=known_sids,
        )

    @server.tool(
        name="api_call",
        description=(
            "Execute a direct Check Point Management Web API command (e.g. 'where-used', 'show-sessions', "
            "'show-unused-objects', 'show-task', 'verify-policy'). By default only read-only commands "
            "('show-*', 'where-used', 'verify-policy') are permitted unless ARODONATA_MCP_ALLOW_WRITE_API=true."
        ),
    )
    @mcp_tool_guard("api_call", client_getter, quota_manager=quota_manager, is_live_tool=True)
    async def api_call(
        command: str,
        payload: dict[str, Any] | None = None,
        mgmt_name: str | None = None,
        domain: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ) -> CallToolResult:
        if not isinstance(command, str) or not command.strip():
            raise ToolFailure("Command must not be empty.")

        try:
            clean_cmd = validate_command_name(command)
        except ValidationError as exc:
            raise ToolFailure(str(exc), mgmt_name=mgmt_name, domain=domain) from exc

        if not mcp_settings.allow_write_api and not is_readonly_command(clean_cmd):
            raise ToolFailure(
                f"Write or non-read-only command {clean_cmd!r} is prohibited when "
                "ARODONATA_MCP_ALLOW_WRITE_API=false. Only read-only 'show-*', 'where-used', and 'verify-policy' "
                "commands are permitted."
            )

        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)

        eff_timeout: float | None = None
        if timeout is not None:
            if timeout <= 0:
                raise ToolFailure(
                    "timeout must be a positive number of seconds.", mgmt_name=eff_mgmt, domain=eff_domain
                )
            eff_timeout = min(float(timeout), MAX_MCP_API_TIMEOUT_SECONDS)

        dedicated_sid: str | None = None
        if is_readonly_command(clean_cmd):
            res = await client.api_call(
                eff_mgmt,
                clean_cmd,
                payload or {},
                domain=eff_domain,
                wait_for_task=wait_for_task,
                timeout=eff_timeout,
            )
        else:
            # Isolate mutating api_call inside a dedicated session so shared sid_cache is never dirtied (W25/C8)
            sid, srv_ip = await client.api.create_dedicated_session(
                eff_mgmt,
                eff_domain,
                session_name="arodonata-mcp-api-call",
                session_description=f"MCP api_call: {clean_cmd}",
            )
            dedicated_sid = sid
            register_active_mcp_sid(sid)
            try:
                res = await client.api_call(
                    eff_mgmt,
                    clean_cmd,
                    payload or {},
                    domain=eff_domain,
                    sid=sid,
                    server_ip=srv_ip,
                    wait_for_task=wait_for_task,
                    timeout=eff_timeout,
                )
            finally:
                if clean_cmd != "logout":
                    try:
                        await asyncio.shield(client.api.logout_sid(eff_mgmt, sid, server_ip=srv_ip))
                    except Exception as logout_exc:
                        logout_sids = await collect_known_sids(client, eff_mgmt)
                        logger.warning(
                            "MCP dedicated session logout failed",
                            mgmt_name=eff_mgmt,
                            domain=eff_domain,
                            error=redact_sid(str(logout_exc), known_sids=logout_sids),
                        )

        known_sids = await collect_known_sids(client, eff_mgmt)
        if dedicated_sid and dedicated_sid not in known_sids:
            known_sids.append(dedicated_sid)
        if not res.success:
            err_msg = redact_sid(res.error_message or f"API command {clean_cmd!r} failed", known_sids=known_sids)
            raise ToolFailure(
                f"{clean_cmd} failed (status {res.status_code}): {err_msg}",
                mgmt_name=eff_mgmt,
                domain=eff_domain,
                known_sids=known_sids,
            )

        return json_tool_result(
            {
                "command": clean_cmd,
                "mgmt_name": eff_mgmt,
                "domain": eff_domain,
                "status_code": res.status_code,
                "source": "live",
                "cache_age_seconds": None,
                "data": sanitize_mapping(res.data, known_sids=known_sids),
            },
            known_sids=known_sids,
        )

    @server.tool(
        name="api_reference",
        description=(
            "Offline Check Point Management & Gaia API reference discovery and request payload validator "
            "(covers Management API v1.9..v2.2 and Gaia v2.0.1). "
            "Use action='search' to find commands by keyword/category/crud_type, "
            "action='describe' to inspect version-filtered fields, field_alternatives, nested_objects, and examples "
            "(accepts a single command string or list of command names), "
            "and action='validate' to check a candidate request payload dictionary before calling api_call."
        ),
    )
    @mcp_tool_guard("api_reference", client_getter, quota_manager=quota_manager, is_live_tool=False)
    async def api_reference(
        action: Literal["search", "describe", "validate"] = "search",
        query: str | None = None,
        command: str | list[str] | None = None,
        payload: dict[str, Any] | None = None,
        category: str | None = None,
        crud_type: str | None = None,
        api_family: str | None = None,
        version: str | None = None,
        mgmt_name: str | None = None,
        resolve_nested: bool = True,
        include_examples: bool = True,
        limit: int = 15,
    ) -> CallToolResult:
        clean_action = (action or "search").strip().lower()
        if clean_action not in ("search", "describe", "validate"):
            raise ToolFailure(f"Invalid action {action!r}. Expected 'search', 'describe', or 'validate'.")

        client = client_getter()
        await client.ensure_api_reference()
        eff_version = client.resolve_api_version(version, mgmt_name=mgmt_name)

        if clean_action == "search":
            hits = client.search_api_commands(
                query or "",
                category=category,
                crud_type=crud_type,
                api_family=api_family,
                version=eff_version,
                mgmt_name=mgmt_name,
                limit=limit,
            )
            return json_tool_result(
                {
                    "action": "search",
                    "target_version": eff_version,
                    "total": len(hits),
                    "commands": hits,
                }
            )

        if clean_action == "describe":
            if (
                command is None
                or (isinstance(command, str) and not command.strip())
                or (isinstance(command, list) and not any(isinstance(c, str) and c.strip() for c in command))
            ):
                raise ToolFailure("Parameter 'command' (string or list of strings) is required for action='describe'.")
            desc = client.describe_api_command(
                command,
                version=eff_version,
                mgmt_name=mgmt_name,
                resolve_nested=resolve_nested,
                include_examples=include_examples,
            )
            if desc is None:
                suggestions = client.search_api_commands(str(command), version=eff_version, limit=5)
                raise ToolFailure(
                    f"Command {command!r} was not found or is not supported in Check Point API version {eff_version!r}. "
                    f"Similar commands: {[s['name'] for s in suggestions]}."
                )
            return json_tool_result(
                {
                    "action": "describe",
                    "target_version": eff_version,
                    **desc,
                }
            )

        # action == "validate"
        if not isinstance(command, str) or not command.strip():
            raise ToolFailure("Parameter 'command' (non-empty string) is required for action='validate'.")
        val_res = client.validate_api_payload(
            command,
            payload or {},
            version=eff_version,
            mgmt_name=mgmt_name,
        )
        return json_tool_result(
            {
                "action": "validate",
                **val_res,
            }
        )
