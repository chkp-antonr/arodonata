"""CPCRUDService: public validate/plan/apply orchestration (shape v2; SSE streaming)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from arlogi.otel.decorator import traced

from ..api.schemas import SSEEvent, SSEEventType
from ..telemetry import span_attrs
from .executor import Executor, fold_reports
from .models import ApplyReport, IpConflictPolicy, NameConflictPolicy, Outcome, Plan
from .planner import Planner
from .schema import load_template, validate_template
from .statereader import HybridStateReader

if TYPE_CHECKING:
    from ..api.client import ArodonataClient


class CPCRUDService:
    def __init__(self, client: ArodonataClient) -> None:
        self._client = client
        self._reader = HybridStateReader(client)
        self._planner = Planner(self._reader, settings=client.settings)
        self._executor = Executor(client, self._reader)

    @traced
    def validate(self, template: str | Path | dict[str, Any]) -> list[str]:
        doc = load_template(template) if not isinstance(template, dict) else template
        return validate_template(doc)

    @traced
    def inverse(self, plan: Plan, report: ApplyReport | None = None) -> dict[str, Any]:
        """Compensating template for a plan (optionally filtered by what actually executed)."""
        from .inverse import build_inverse_template

        return build_inverse_template(plan, report)

    @traced
    async def plan(
        self,
        template: str | Path | dict[str, Any],
        on_name_conflict: NameConflictPolicy | None = None,
        on_ip_conflict: IpConflictPolicy | None = None,
    ) -> Plan:
        doc = load_template(template) if not isinstance(template, dict) else template
        return await self._planner.decide(doc, on_name=on_name_conflict, on_ip=on_ip_conflict)

    @traced
    async def apply(
        self,
        plan_or_template: Plan | str | Path | dict[str, Any],
        *,
        force: bool = False,
        dry_run: bool = False,
        no_publish: bool = False,
        discard: bool = False,
        session_name: str | None = None,
        session_description: str | None = None,
        on_name_conflict: NameConflictPolicy | None = None,
        on_ip_conflict: IpConflictPolicy | None = None,
        retry_remaining: int = 0,
        refresh: str | None = None,
    ) -> AsyncIterator[SSEEvent | ApplyReport]:
        plan = (
            plan_or_template
            if isinstance(plan_or_template, Plan)
            else await self.plan(
                plan_or_template,
                on_name_conflict=on_name_conflict,
                on_ip_conflict=on_ip_conflict,
            )
        )
        span_attrs(
            template_hash=plan.template_hash[:12],
            actions=len(plan.actions),
            dry_run=dry_run,
            force=force,
        )
        refresh_mode = refresh or getattr(self._client.settings, "cpcrud_refresh_mode", None) or "invalidate"
        yield SSEEvent(
            event_type=SSEEventType.START,
            message=f"applying plan {plan.template_hash[:12]}",
            data={"actions": len(plan.actions)},
        )
        report: ApplyReport | None = None
        current: Plan = plan
        attempt = 0
        while True:
            actions_by_id = {a.id: a for a in current.actions}
            pass_report: ApplyReport | None = None
            async for item in self._executor.stream(
                current,
                force=force,
                dry_run=dry_run,
                no_publish=no_publish,
                discard=discard,
                session_name=session_name,
                session_description=session_description,
                refresh=refresh_mode,
            ):
                if isinstance(item, ApplyReport):
                    pass_report = item
                    break
                action = actions_by_id.get(item.action_id)
                data = item.model_dump()
                if attempt:
                    data["attempt"] = attempt
                yield SSEEvent(
                    event_type=SSEEventType.ERROR if item.outcome == Outcome.ERROR else SSEEventType.RESULT,
                    message=item.message
                    or f"{action.operation if action else '?'} {action.resolved_name if action else item.action_id}: {item.outcome.value}",
                    data=data,
                    mgmt_name=action.mgmt_name if action else None,
                    domain=action.domain_name if action else None,
                )
            assert pass_report is not None, "Executor.stream must yield an ApplyReport before completing"
            report = pass_report if report is None else fold_reports(report, pass_report)
            remaining = report.remaining
            if dry_run or attempt >= retry_remaining or not (remaining and remaining.actions):
                break
            attempt += 1
            for mgmt, domain in remaining.domains():
                self._client._refresh_coordinator.invalidate(mgmt, domain)  # MMP parity: refresh state before retrying
            current = remaining
        yield SSEEvent(event_type=SSEEventType.COMPLETE, message="apply finished", data={"summary": report.summary})
        yield report
