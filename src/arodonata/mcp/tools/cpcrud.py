"""Opt-in declarative CPCRUD MCP tools with HMAC-signed plan verification and staged session isolation."""

from __future__ import annotations

import hmac
import secrets
import uuid
from collections import OrderedDict
from collections.abc import Callable
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult

from arodonata.client import ArodonataClient
from arodonata.core.context import normalize_domain_key
from arodonata.core.errors import redact_sid, sanitize_mapping
from arodonata.cpcrud import ApplyReport, IpConflictPolicy, NameConflictPolicy, Plan, StagedSessionInfo
from arodonata.mcp.config import ArodonataMCPSettings
from arodonata.mcp.errors import (
    ToolFailure,
    collect_known_sids,
    json_tool_result,
    mcp_tool_guard,
    resolve_mgmt_name,
    validate_domain_or_fail,
)
from arodonata.mcp.quota import MCPToolQuotaManager
from arodonata.mcp.tools._common import (
    MAX_MCP_API_TIMEOUT_SECONDS,
    MAX_STORED_PLANS,
    _sign_plan,
)


def register_cpcrud_tools(
    server: MCPServer,
    client_getter: Callable[[], ArodonataClient],
    mcp_settings: ArodonataMCPSettings,
    *,
    quota_manager: MCPToolQuotaManager | None = None,
) -> None:
    """Register the five HMAC-verified CPCRUD tools when `mcp_settings.cpcrud` is `True`."""
    if not mcp_settings.cpcrud:
        return

    plan_hmac_key = secrets.token_bytes(32)
    plan_store: OrderedDict[str, tuple[Plan, ApplyReport | None]] = OrderedDict()
    staged_session_store: OrderedDict[tuple[str, str, str], StagedSessionInfo] = OrderedDict()

    def _store_plan_entry(plan_id: str, plan_obj: Plan, report_obj: ApplyReport | None = None) -> None:
        plan_store[plan_id] = (plan_obj, report_obj)
        plan_store.move_to_end(plan_id)
        while len(plan_store) > MAX_STORED_PLANS:
            plan_store.popitem(last=False)

    def _store_staged_session(info: StagedSessionInfo) -> None:
        if not info.session_uid or not info.session_uid.strip():
            return
        key = (info.mgmt_name, normalize_domain_key(info.domain_name), info.session_uid.strip())
        staged_session_store[key] = info
        staged_session_store.move_to_end(key)
        while len(staged_session_store) > MAX_STORED_PLANS:
            staged_session_store.popitem(last=False)

    def _resolve_verified_plan(
        plan: dict[str, Any] | None,
        plan_id: str | None,
    ) -> tuple[str | None, Plan, ApplyReport | None]:
        if plan_id and plan is None:
            entry = plan_store.get(plan_id)
            if entry is None:
                raise ToolFailure(f"Unknown or expired CPCRUD plan_id {plan_id!r}. Run cpcrud_plan first.")
            return plan_id, entry[0], entry[1]

        if not isinstance(plan, dict):
            raise ToolFailure("Provide a signed 'plan' dictionary returned by cpcrud_plan or a 'plan_id'.")

        sig = plan.get("plan_signature")
        embedded_id = plan.get("plan_id") if isinstance(plan.get("plan_id"), str) else plan_id

        try:
            expected_sig = _sign_plan(plan_hmac_key, plan)
            parsed_plan = Plan.model_validate({k: v for k, v in plan.items() if k not in ("plan_id", "plan_signature")})
        except Exception as exc:
            raise ToolFailure(f"Invalid or tampered CPCRUD plan payload: {exc}") from exc

        if not isinstance(sig, str) or not hmac.compare_digest(sig, expected_sig):
            raise ToolFailure(
                "Untrusted or tampered CPCRUD plan: plans passed to cpcrud_apply/cpcrud_inverse must be "
                "created and signed by cpcrud_plan on this server."
            )

        stored_report: ApplyReport | None = None
        if embedded_id and embedded_id in plan_store:
            stored_report = plan_store[embedded_id][1]
        return embedded_id, parsed_plan, stored_report

    @server.tool(
        name="cpcrud_validate",
        description="Validate a declarative CPCRUD YAML/JSON template offline against checkpoint_ops_schema.json.",
    )
    @mcp_tool_guard("cpcrud_validate", client_getter, quota_manager=quota_manager, is_live_tool=False)
    async def cpcrud_validate(
        template: dict[str, Any] | str,
    ) -> CallToolResult:
        client = client_getter()
        errors = client.cpcrud.validate(template)
        return json_tool_result(
            {
                "valid": len(errors) == 0,
                "error_count": len(errors),
                "errors": errors,
            }
        )

    @server.tool(
        name="cpcrud_plan",
        description=(
            "Plan deterministic idempotent Check Point CRUD actions from a YAML/JSON template using "
            "HybridStateReader and two-axis conflict policies."
        ),
    )
    @mcp_tool_guard("cpcrud_plan", client_getter, quota_manager=quota_manager, is_live_tool=True)
    async def cpcrud_plan(
        template: dict[str, Any] | str,
        on_name_conflict: NameConflictPolicy | None = None,
        on_ip_conflict: IpConflictPolicy | None = None,
    ) -> CallToolResult:
        client = client_getter()
        plan = await client.cpcrud.plan(
            template,
            on_name_conflict=on_name_conflict,
            on_ip_conflict=on_ip_conflict,
            validate_schema=True,
        )
        plan_id = str(uuid.uuid4())
        _store_plan_entry(plan_id, plan, None)
        plan_dict = plan.model_dump(mode="json")
        plan_dict["plan_id"] = plan_id
        plan_dict["plan_signature"] = _sign_plan(plan_hmac_key, plan_dict)
        known_sids = await collect_known_sids(client)
        return json_tool_result(plan_dict, known_sids=known_sids)

    @server.tool(
        name="cpcrud_apply",
        description=(
            "Execute a verified CPCRUD Plan inside an isolated WriteSession per domain with stale-plan "
            "verification, optional session staging, and post-publish cache invalidation."
        ),
    )
    @mcp_tool_guard("cpcrud_apply", client_getter, quota_manager=quota_manager, is_live_tool=True)
    async def cpcrud_apply(
        plan: dict[str, Any] | None = None,
        plan_id: str | None = None,
        no_publish: bool = False,
        keep_session: bool = False,
        retry_remaining: int = 0,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> CallToolResult:
        if retry_remaining < 0 or retry_remaining > 3:
            raise ToolFailure("retry_remaining must be between 0 and 3.")

        eff_plan_id, parsed_plan, _ = _resolve_verified_plan(plan, plan_id)
        client = client_getter()
        report = await client.cpcrud.apply(
            parsed_plan,
            force=False,
            no_publish=no_publish,
            keep_session=keep_session,
            retry_remaining=retry_remaining,
            session_name=session_name,
            session_description=session_description,
        )
        if eff_plan_id:
            _store_plan_entry(eff_plan_id, parsed_plan, report)
        if no_publish and keep_session:
            for st_info in report.staged_sessions:
                _store_staged_session(st_info)
        report_dict = report.model_dump(mode="json")
        if eff_plan_id:
            report_dict["plan_id"] = eff_plan_id
        known_sids = await collect_known_sids(client)
        return json_tool_result(report_dict, known_sids=known_sids)

    @server.tool(
        name="cpcrud_inverse",
        description="Generate a schema-valid compensating rollback template from a verified CPCRUD Plan and ApplyReport.",
    )
    @mcp_tool_guard("cpcrud_inverse", client_getter, quota_manager=quota_manager, is_live_tool=False)
    async def cpcrud_inverse(
        plan: dict[str, Any] | None = None,
        plan_id: str | None = None,
        report: dict[str, Any] | None = None,
    ) -> CallToolResult:
        _, parsed_plan, stored_report = _resolve_verified_plan(plan, plan_id)
        client = client_getter()
        eff_report: ApplyReport | None = None
        if isinstance(report, dict):
            eff_report = ApplyReport.model_validate(report)
        elif stored_report is not None:
            eff_report = stored_report
        elif client.cpcrud.last_report is not None:
            eff_report = client.cpcrud.last_report

        if eff_report is None:
            raise ToolFailure(
                "cpcrud_inverse requires an ApplyReport (pass 'report', use a 'plan_id' that was applied, "
                "or call cpcrud_apply before cpcrud_inverse)."
            )
        inverse_tpl = client.cpcrud.inverse(parsed_plan, eff_report)
        known_sids = await collect_known_sids(client)
        return json_tool_result(inverse_tpl, known_sids=known_sids)

    @server.tool(
        name="cpcrud_staged_session",
        description=(
            "Adopt a staged Check Point session (created by cpcrud_apply with no_publish=True, keep_session=True) "
            "and either publish (action='publish', invalidating the domain cache) or discard "
            "(action='discard') uncommitted changes before logging out cleanly."
        ),
    )
    @mcp_tool_guard("cpcrud_staged_session", client_getter, quota_manager=quota_manager, is_live_tool=True)
    async def cpcrud_staged_session(
        session_uid: str,
        action: Literal["publish", "discard"] = "publish",
        mgmt_name: str | None = None,
        domain: str | None = None,
        timeout: float | None = None,
    ) -> CallToolResult:
        if not session_uid or not session_uid.strip():
            raise ToolFailure("session_uid must not be empty.")
        if action not in ("publish", "discard"):
            raise ToolFailure(f"Invalid action {action!r}. Expected 'publish' or 'discard'.")

        client = client_getter()
        eff_mgmt = resolve_mgmt_name(client, mgmt_name)
        eff_domain = await validate_domain_or_fail(client, eff_mgmt, domain)
        target_uid = session_uid.strip()
        st_key = (eff_mgmt, normalize_domain_key(eff_domain), target_uid)
        stored_staged = staged_session_store.get(st_key)
        if stored_staged is None:
            raise ToolFailure(
                f"Unknown or foreign staged session_uid {target_uid!r} on {eff_mgmt!r} ({eff_domain or 'System Data'}). "
                "cpcrud_staged_session only operates on sessions created by cpcrud_apply(..., no_publish=True, keep_session=True) "
                "on this MCP server.",
                mgmt_name=eff_mgmt,
                domain=eff_domain,
            )

        if action == "publish":
            eff_timeout = min(float(timeout), MAX_MCP_API_TIMEOUT_SECONDS) if timeout and timeout > 0 else None
            res = await client.cpcrud.publish_staged_session(
                eff_mgmt,
                eff_domain,
                session_uid=target_uid,
                sid=stored_staged.sid,
                server_ip=stored_staged.server_ip,
                timeout=eff_timeout,
                force_disconnect=False,
            )
            known_sids = await collect_known_sids(client, eff_mgmt)
            if not res.success:
                raise ToolFailure(
                    f"cpcrud_staged_session(action='publish') failed for session {session_uid!r}: "
                    f"{redact_sid(res.error_message or 'publish failed', known_sids=known_sids)}",
                    mgmt_name=eff_mgmt,
                    domain=eff_domain,
                    known_sids=known_sids,
                )
            staged_session_store.pop(st_key, None)
            return json_tool_result(
                {
                    "mgmt_name": eff_mgmt,
                    "domain": eff_domain,
                    "session_uid": target_uid,
                    "action": "publish",
                    "published": True,
                    "discarded": False,
                    "data": sanitize_mapping(res.data, known_sids=known_sids),
                },
                known_sids=known_sids,
            )

        res = await client.cpcrud.discard_staged_session(
            eff_mgmt,
            eff_domain,
            session_uid=target_uid,
            sid=stored_staged.sid,
            server_ip=stored_staged.server_ip,
            force_disconnect=False,
        )
        known_sids = await collect_known_sids(client, eff_mgmt)
        if not res.success:
            raise ToolFailure(
                f"cpcrud_staged_session(action='discard') failed for session {session_uid!r}: "
                f"{redact_sid(res.error_message or 'discard failed', known_sids=known_sids)}",
                mgmt_name=eff_mgmt,
                domain=eff_domain,
                known_sids=known_sids,
            )
        staged_session_store.pop(st_key, None)
        return json_tool_result(
            {
                "mgmt_name": eff_mgmt,
                "domain": eff_domain,
                "session_uid": target_uid,
                "action": "discard",
                "published": False,
                "discarded": True,
                "data": sanitize_mapping(res.data, known_sids=known_sids),
            },
            known_sids=known_sids,
        )
