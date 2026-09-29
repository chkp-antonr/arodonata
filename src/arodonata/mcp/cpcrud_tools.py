"""Opt-in cpcrud tools: validate, plan, apply (dry-run by default), inverse."""

from __future__ import annotations

from collections import Counter
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import yaml

from ..api.schemas import SSEEvent
from ..cpcrud.models import ApplyReport, IpConflictPolicy, NameConflictPolicy, Plan
from ._sdk import MCPServer
from .common import ToolFailure, add_guarded_tool

if TYPE_CHECKING:
    from ..api.client import ArodonataClient
    from .registry import ToolOptions

_TEMPLATE_ERROR = "template must be a YAML or JSON object"


def template_to_dict(template: str | dict[str, Any]) -> dict[str, Any]:
    """Turn a caller-supplied template into a dict without ever touching the server's filesystem.

    cpcrud's own loader treats a ``str`` that names an existing file as a path and reads it, so a ``str`` must never
    reach cpcrud from an MCP caller: it is parsed here as YAML (a superset of JSON) instead.
    """
    if isinstance(template, dict):
        return template
    try:
        parsed = yaml.safe_load(template)
    except yaml.YAMLError:
        raise ToolFailure(_TEMPLATE_ERROR) from None
    if not isinstance(parsed, dict):
        raise ToolFailure(_TEMPLATE_ERROR)
    return parsed


def _policy[E: StrEnum](enum: type[E], value: str | None, param: str) -> E | None:
    """Map a conflict-policy string to its enum, naming the valid values on a bad one (not "internal error")."""
    if not value:
        return None
    try:
        return enum(value)
    except ValueError:
        raise ToolFailure(f"invalid {param} '{value}'; valid values: {', '.join(m.value for m in enum)}") from None


def _apply_target(plan: dict[str, Any] | None, template: str | dict[str, Any] | None) -> Plan | dict[str, Any]:
    if plan is not None:
        return Plan.model_validate(plan)
    if template is not None:
        return template_to_dict(template)
    raise ToolFailure("cpcrud_apply requires plan or template")


_CONFIRM = " Show the plan to the user and get explicit confirmation before calling cpcrud_apply with dry_run=false."


def register_cpcrud_tools(server: MCPServer, client: ArodonataClient, opts: ToolOptions) -> list[str]:
    names: list[str] = []

    async def cpcrud_validate(template: str | dict[str, Any]) -> dict[str, Any]:
        """Validate a cpcrud YAML/JSON template (string or object) against the schema. Returns a list of errors; empty means valid."""
        errors = client.cpcrud.validate(template_to_dict(template))
        return {"valid": not errors, "errors": errors}

    async def cpcrud_plan(
        template: str | dict[str, Any], on_name_conflict: str | None = None, on_ip_conflict: str | None = None
    ) -> dict[str, Any]:
        """Compute the idempotent change plan for a template without touching the management server's policy. Returns the plan JSON (pass it unchanged to cpcrud_apply) plus a per-action summary."""
        template_dict = template_to_dict(template)
        name_policy = _policy(NameConflictPolicy, on_name_conflict, "on_name_conflict")
        ip_policy = _policy(IpConflictPolicy, on_ip_conflict, "on_ip_conflict")
        plan = await client.cpcrud.plan(template_dict, on_name_conflict=name_policy, on_ip_conflict=ip_policy)
        summary = Counter(a.outcome.value for a in plan.actions)
        actions = [
            {
                "id": a.id,
                "operation": a.operation,
                "type": a.type,
                "name": a.resolved_name or a.desired.get("name", ""),
                "outcome": a.outcome.value,
                "mgmt_name": a.mgmt_name,
                "domain": a.domain_name,
            }
            for a in plan.actions
        ]
        return {"plan": plan.model_dump(mode="json"), "summary": dict(summary), "actions": actions}

    async def cpcrud_apply(
        plan: dict[str, Any] | None = None,
        template: str | dict[str, Any] | None = None,
        dry_run: bool = True,
        force: bool = False,
        no_publish: bool = False,
        discard: bool = False,
        session_name: str | None = None,
    ) -> dict[str, Any]:
        """Apply a plan (from cpcrud_plan) or a template. dry_run=true (default) executes nothing. Set dry_run=false only after the user confirmed the plan."""
        target = _apply_target(plan, template)
        events: list[str] = []
        report: ApplyReport | None = None
        async for item in client.cpcrud.apply(
            target,
            force=force,
            dry_run=dry_run,
            no_publish=no_publish,
            discard=discard,
            session_name=session_name,
            session_description="arodonata-mcp",
        ):
            if isinstance(item, ApplyReport):
                report = item
            elif isinstance(item, SSEEvent) and item.message:
                events.append(item.message)
        return {"dry_run": dry_run, "report": report.model_dump(mode="json") if report else None, "events": events}

    async def cpcrud_inverse(plan: dict[str, Any], report: dict[str, Any] | None = None) -> dict[str, Any]:
        """Build the compensating template that undoes a plan (optionally limited to what an apply report actually executed)."""
        template = client.cpcrud.inverse(
            Plan.model_validate(plan), ApplyReport.model_validate(report) if report else None
        )
        return {"template": template}

    for fn, base in (
        (cpcrud_validate, "cpcrud_validate"),
        (cpcrud_plan, "cpcrud_plan"),
        (cpcrud_apply, "cpcrud_apply"),
        (cpcrud_inverse, "cpcrud_inverse"),
    ):
        add_guarded_tool(server, fn, name=opts.name(base), description=(fn.__doc__ or "") + _CONFIRM)
        names.append(opts.name(base))
    return names
