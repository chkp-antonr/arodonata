"""Execute phase: walk the Plan grouped per (mgmt, domain); dedicated-session lifecycle."""

from __future__ import annotations

from collections.abc import AsyncIterator
from collections.abc import Set as AbstractSet
from typing import TYPE_CHECKING, Any

from arlogi.otel.decorator import traced

from ..telemetry import span_attrs
from ..utils.helpers import extract_data_from_response
from .models import ActionResult, ApplyReport, DomainStamp, Outcome, Plan, PlannedAction

if TYPE_CHECKING:
    from ..api.client import ArodonataClient

_WRITE_OUTCOMES = (Outcome.CREATE, Outcome.UPDATE, Outcome.DELETE)
_FAILURE_OUTCOMES = {Outcome.ERROR, Outcome.LOCKED, Outcome.CONFLICT, Outcome.SKIPPED_DEPENDENCY}


def fold_reports(first: ApplyReport, second: ApplyReport) -> ApplyReport:
    """Merge a retry pass into the prior report: last result per action_id wins."""
    by_id = {r.action_id: r for r in first.results}
    order = [r.action_id for r in first.results]
    for r in second.results:
        if r.action_id not in by_id:
            order.append(r.action_id)
        by_id[r.action_id] = r
    results = [by_id[i] for i in order]
    summary: dict[str, int] = {}
    for r in results:
        summary[r.outcome.value] = summary.get(r.outcome.value, 0) + 1
    return ApplyReport(
        results=results,
        published_domains=[*first.published_domains, *second.published_domains],
        remaining=second.remaining,
        summary=summary,
    )


def classify_api_error(message: str, code: str) -> str | None:
    """Best-effort classification of CP API write errors for drift/lock reconciliation."""
    text = f"{message} {code}".lower()
    if "lock" in text:
        return "locked"
    if "already exists" in text or "more than one object" in text or "same name" in text:
        return "exists"
    if "not found" in text or "object_not_found" in text:
        return "missing"
    return None


class Executor:
    def __init__(self, client: ArodonataClient, reader: Any) -> None:
        self._client = client
        self._reader = reader

    async def stream(
        self,
        plan: Plan,
        *,
        force: bool = False,
        dry_run: bool = False,
        no_publish: bool = False,
        discard: bool = False,
        session_name: str | None = None,
        session_description: str | None = None,
        refresh: str = "invalidate",
    ) -> AsyncIterator[ActionResult | ApplyReport]:
        if dry_run:
            dry_results = [
                ActionResult(
                    action_id=a.id,
                    outcome=a.outcome,
                    type=a.type,
                    name=a.resolved_name,
                    mgmt_name=a.mgmt_name,
                    domain_name=a.domain_name,
                    uid=a.resolved_uid,
                    message=a.message,
                )
                for a in plan.actions
            ]
            for r in dry_results:
                yield r
            yield self._report(plan, dry_results, published=[])
            return

        stamps = {(s.mgmt_name, s.domain_name): s.last_publish_session for s in plan.stamps}
        results: list[ActionResult] = []
        published: list[DomainStamp] = []
        stale_domains: set[tuple[str, str]] = set()
        for mgmt, domain in plan.domains():
            domain_actions = [a for a in plan.actions if (a.mgmt_name, a.domain_name) == (mgmt, domain)]
            stamped = stamps.get((mgmt, domain), "")
            if not force and stamped:
                current = await self._reader.get_last_publish_session(mgmt=mgmt, domain=domain)
                if current and current != stamped:
                    stale_domains.add((mgmt, domain))
                    for a in domain_actions:
                        result = ActionResult(
                            action_id=a.id,
                            outcome=Outcome.PLAN_STALE,
                            type=a.type,
                            name=a.resolved_name,
                            mgmt_name=a.mgmt_name,
                            domain_name=a.domain_name,
                            message=f"domain published since plan (was {stamped}, now {current}); re-plan or use force",
                        )
                        results.append(result)
                        yield result
                    continue
            domain_results: list[ActionResult] = []
            async for result in self._stream_domain(
                mgmt,
                domain,
                domain_actions,
                no_publish=no_publish,
                discard=discard,
                session_name=session_name,
                session_description=session_description,
            ):
                domain_results.append(result)
                results.append(result)
                yield result
            if any(r.outcome in _WRITE_OUTCOMES for r in domain_results) and not no_publish and not discard:
                published.append(
                    DomainStamp(
                        mgmt_name=mgmt,
                        domain_name=domain,
                        last_publish_session=await self._reader.get_last_publish_session(mgmt=mgmt, domain=domain),
                    )
                )
                self._client._refresh_coordinator.invalidate(mgmt, domain)
                await self._maybe_force_refresh(refresh, mgmt, domain)
        yield self._report(plan, results, published, stale_domains)

    async def _maybe_force_refresh(self, refresh: str, mgmt: str, domain: str) -> None:
        if refresh != "force":
            return
        async for _event in self._client.refresh_objects(mgmt_names=[mgmt], domain_names=[domain], mode="force"):
            pass

    async def execute(self, plan: Plan, **kwargs: Any) -> ApplyReport:
        report: ApplyReport | None = None
        async for item in self.stream(plan, **kwargs):
            if isinstance(item, ApplyReport):
                report = item
        assert report is not None
        return report

    async def _stream_domain(
        self,
        mgmt: str,
        domain: str,
        actions: list[PlannedAction],
        *,
        no_publish: bool,
        discard: bool,
        session_name: str | None,
        session_description: str | None,
    ) -> AsyncIterator[ActionResult]:
        results: list[ActionResult] = []
        sid, server_ip = "", ""
        try:
            sid, server_ip = await self._client.create_dedicated_session(
                mgmt,
                domain,
                session_name=session_name or f"cpcrud-{mgmt}-{domain}",
                session_description=session_description,
            )
            failed: set[str] = set()
            for action in actions:
                bad_deps = [d for d in action.depends_on if d in failed]
                if bad_deps:
                    result = ActionResult(
                        action_id=action.id,
                        outcome=Outcome.SKIPPED_DEPENDENCY,
                        type=action.type,
                        name=action.resolved_name,
                        mgmt_name=action.mgmt_name,
                        domain_name=action.domain_name,
                        message=f"skipped: dependency failed ({', '.join(bad_deps)})",
                    )
                else:
                    result = await self._execute_action(mgmt, sid, server_ip, action)
                if result.outcome in _FAILURE_OUTCOMES:
                    failed.add(action.id)
                results.append(result)
                yield result
            if discard:
                await self._client.api_call_with_sid(mgmt, sid, server_ip, "discard", payload={})
            elif not no_publish and any(r.outcome in _WRITE_OUTCOMES for r in results):
                await self._client.api_call_with_sid(mgmt, sid, server_ip, "publish", payload={}, wait_for_task=True)
        except Exception as exc:  # session-open failure -> every not-yet-run action errors
            done_ids = {r.action_id for r in results}
            for action in actions:
                if action.id not in done_ids:
                    yield ActionResult(
                        action_id=action.id,
                        outcome=Outcome.ERROR,
                        type=action.type,
                        name=action.resolved_name,
                        mgmt_name=action.mgmt_name,
                        domain_name=action.domain_name,
                        message=str(exc),
                    )
        finally:
            if sid:
                await self._client.logout_sid(sid, server_ip, mgmt)

    @traced
    async def _execute_action(self, mgmt: str, sid: str, server_ip: str, action: PlannedAction) -> ActionResult:
        span_attrs(
            mgmt_name=mgmt,
            domain=action.domain_name,
            **{
                "action.type": action.type,
                "action.name": action.resolved_name,
                "action.operation": action.operation,
            },
        )
        result = await self._execute_action_inner(mgmt, sid, server_ip, action)
        span_attrs(**{"action.outcome": result.outcome.value})
        return result

    async def _execute_action_inner(self, mgmt: str, sid: str, server_ip: str, action: PlannedAction) -> ActionResult:
        if action.operation == "delete" and action.command is not None and action.resolved_uid:
            total = await self._reader.where_used(action.resolved_uid, mgmt=mgmt, domain=action.domain_name)
            if total > 0:
                return ActionResult(
                    action_id=action.id,
                    outcome=Outcome.ERROR,
                    type=action.type,
                    name=action.resolved_name,
                    mgmt_name=action.mgmt_name,
                    domain_name=action.domain_name,
                    uid=action.resolved_uid,
                    message=f"delete blocked: {total} direct reference(s) still exist",
                )
        if action.command is None or action.payload is None:
            # UNCHANGED / REUSE / CONFLICT / ERROR decided at plan time -> no write
            return ActionResult(
                action_id=action.id,
                outcome=action.outcome,
                type=action.type,
                name=action.resolved_name,
                mgmt_name=action.mgmt_name,
                domain_name=action.domain_name,
                uid=action.resolved_uid,
                message=action.message,
            )
        try:
            res = await self._client.api_call_with_sid(
                mgmt, sid, server_ip, action.command, payload=action.payload, wait_for_task=True
            )
        except Exception as exc:
            return ActionResult(
                action_id=action.id,
                outcome=Outcome.ERROR,
                type=action.type,
                name=action.resolved_name,
                mgmt_name=action.mgmt_name,
                domain_name=action.domain_name,
                message=f"{action.command} raised: {exc}",
            )
        if not res.success:
            kind = classify_api_error(res.message, res.code)
            if kind == "locked":
                return ActionResult(
                    action_id=action.id,
                    outcome=Outcome.LOCKED,
                    type=action.type,
                    name=action.resolved_name,
                    mgmt_name=action.mgmt_name,
                    domain_name=action.domain_name,
                    uid=action.resolved_uid,
                    locking_session=await self._find_locking_session(mgmt, sid, server_ip),
                    message=res.message,
                )
            if kind == "exists" and action.operation == "add":
                live = await self._reader.get_by_name(
                    action.type, action.resolved_name, mgmt=mgmt, domain=action.domain_name
                )
                return ActionResult(
                    action_id=action.id,
                    outcome=Outcome.DRIFTED,
                    type=action.type,
                    name=action.resolved_name,
                    mgmt_name=action.mgmt_name,
                    domain_name=action.domain_name,
                    uid=live.uid if live else None,
                    message="drift: object appeared since plan; reusing existing",
                )
            if kind == "missing" and action.operation in ("update", "delete"):
                message = (
                    "drift: object already gone"
                    if action.operation == "delete"
                    else "drift: object vanished since plan"
                )
                return ActionResult(
                    action_id=action.id,
                    outcome=Outcome.DRIFTED,
                    type=action.type,
                    name=action.resolved_name,
                    mgmt_name=action.mgmt_name,
                    domain_name=action.domain_name,
                    uid=action.resolved_uid,
                    message=message,
                )
            return ActionResult(
                action_id=action.id,
                outcome=Outcome.ERROR,
                type=action.type,
                name=action.resolved_name,
                mgmt_name=action.mgmt_name,
                domain_name=action.domain_name,
                message=res.message or "API call failed",
            )
        data = extract_data_from_response(res)
        uid = data.get("uid") if isinstance(data, dict) else None
        return ActionResult(
            action_id=action.id,
            outcome=action.outcome,
            type=action.type,
            name=action.resolved_name,
            mgmt_name=action.mgmt_name,
            domain_name=action.domain_name,
            uid=uid or action.resolved_uid,
        )

    async def _find_locking_session(self, mgmt: str, sid: str, server_ip: str) -> dict[str, Any] | None:
        try:
            res = await self._client.api_call_with_sid(mgmt, sid, server_ip, "show-sessions", payload={"limit": 100})
        except Exception:
            return None
        if not res.success:
            return None
        from ..utils.helpers import extract_objects_from_response

        for session in extract_objects_from_response(res):
            if session.get("locks", 0) and session.get("uid") != sid:
                return {k: session.get(k) for k in ("uid", "user-name", "application", "locks")}
        return None

    def _report(
        self,
        plan: Plan,
        results: list[ActionResult],
        published: list[DomainStamp],
        stale_domains: AbstractSet[tuple[str, str]] = frozenset(),
    ) -> ApplyReport:
        summary: dict[str, int] = {}
        for r in results:
            summary[r.outcome.value] = summary.get(r.outcome.value, 0) + 1
        retry_ids = {
            r.action_id for r in results if r.outcome in (Outcome.LOCKED, Outcome.ERROR, Outcome.SKIPPED_DEPENDENCY)
        }
        remaining_actions = [
            a for a in plan.actions if a.id in retry_ids and (a.mgmt_name, a.domain_name) not in stale_domains
        ]
        remaining: Plan | None = None
        if remaining_actions:
            fresh = {(s.mgmt_name, s.domain_name): s for s in published}
            plan_stamps = {(s.mgmt_name, s.domain_name): s for s in plan.stamps}
            needed = {(a.mgmt_name, a.domain_name) for a in remaining_actions}
            remaining = Plan(
                actions=remaining_actions,
                stamps=[
                    fresh.get(pair)
                    or plan_stamps.get(pair)
                    or DomainStamp(mgmt_name=pair[0], domain_name=pair[1], last_publish_session="")
                    for pair in needed
                ],
                template_hash=plan.template_hash,
            )
        return ApplyReport(results=results, published_domains=published, remaining=remaining, summary=summary)
