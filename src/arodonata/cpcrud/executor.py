"""Execute phase: walk the Plan grouped per (mgmt, domain); dedicated-session lifecycle."""

from __future__ import annotations

from collections.abc import AsyncIterator
from collections.abc import Set as AbstractSet
from typing import TYPE_CHECKING, Any

from arlogi.otel.decorator import traced

from ..telemetry import span_attrs
from ..utils.helpers import extract_data_from_response
from .models import ActionResult, ApplyReport, DomainStamp, Outcome, Plan, PlannedAction
from .resolver import StateReadError

if TYPE_CHECKING:
    from ..api.client import ArodonataClient
    from ..api.schemas import ApiCallResult

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
        staged_sessions={**first.staged_sessions, **second.staged_sessions},
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


def _prepare_action_payload(action: PlannedAction) -> dict[str, Any] | None:
    if action.payload is None:
        return None
    if action.type == "dns-domain" and action.command == "add-dns-domain" and "is-sub-domain" not in action.payload:
        payload = dict(action.payload)
        name = payload.get("name") or action.resolved_name or ""
        payload["is-sub-domain"] = name.startswith(".")
        return payload
    if action.command in ("add-service-tcp", "add-service-udp", "add-service-other", "add-service-icmp"):
        payload = dict(action.payload)
        payload.setdefault("ignore-warnings", True)
        return payload
    return action.payload


def _extract_item_msg(item: Any, prefix: str = "") -> str | None:
    if isinstance(item, dict):
        msg = item.get("message") or item.get("description")
        obj = item.get("object")
        text = f"{obj}: {msg}" if (msg and obj and str(obj) not in str(msg)) else str(msg or "")
        return f"{prefix}{text}" if (prefix and text) else (text or None)
    return str(item) if item else None


def _format_api_failure_message(res: ApiCallResult, action: PlannedAction) -> str:
    details: list[str] = []
    if isinstance(res.data, dict):
        for key, pfx in (("errors", ""), ("blocking-errors", "Blocking: "), ("warnings", "Warning: ")):
            for item in res.data.get(key) or []:
                msg = _extract_item_msg(item, pfx)
                if msg:
                    details.append(msg)

    action_label = f"{action.operation} {action.type} '{action.resolved_name or action.id}'"
    if details:
        details_text = " | ".join(details)
        if res.message and res.message not in details_text:
            return f"{action_label}: {res.message} -> {details_text}"
        return f"{action_label}: {details_text}"

    return f"{action_label}: {res.message or 'API call failed'}"


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
        keep_session: bool = False,
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
        staged_sessions: dict[str, dict[str, Any]] = {}
        for mgmt, domain in plan.domains():
            domain_actions = [a for a in plan.actions if (a.mgmt_name, a.domain_name) == (mgmt, domain)]
            stamped = stamps.get((mgmt, domain), "")
            if not force and stamped:
                stale = await self._stale_reason(mgmt, domain, stamped)
                if stale is not None:
                    stale_domains.add((mgmt, domain))
                    for a in domain_actions:
                        result = ActionResult(
                            action_id=a.id,
                            outcome=Outcome.PLAN_STALE,
                            type=a.type,
                            name=a.resolved_name,
                            mgmt_name=a.mgmt_name,
                            domain_name=a.domain_name,
                            message=f"{stale}; re-plan or use force",
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
                keep_session=keep_session,
                staged_sessions=staged_sessions,
            ):
                domain_results.append(result)
                results.append(result)
                yield result
            if any(r.outcome in _WRITE_OUTCOMES for r in domain_results) and not no_publish and not discard:
                try:
                    after = await self._reader.get_last_publish_session(mgmt=mgmt, domain=domain)
                except StateReadError:
                    after = ""  # report-only: the publish is done either way
                published.append(DomainStamp(mgmt_name=mgmt, domain_name=domain, last_publish_session=after))
                self._client.invalidate_domain(mgmt, domain)
                await self._maybe_force_refresh(refresh, mgmt, domain)
        yield self._report(plan, results, published, stale_domains, staged_sessions=staged_sessions)

    async def _stale_reason(self, mgmt: str, domain: str, stamped: str) -> str | None:
        """Why the domain's plan may not be applied, or None when its head still is the planned one."""
        try:
            current = await self._reader.get_last_publish_session(mgmt=mgmt, domain=domain)
        except StateReadError as exc:
            # Not "unchanged": a head that cannot be read must not let the check pass (Backlog #39).
            return f"could not read the domain's last published session ({exc})"
        if current and current != stamped:
            return f"domain published since plan (was {stamped}, now {current})"
        return None

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

    async def _record_staged_session(
        self,
        mgmt: str,
        domain: str,
        sid: str,
        server_ip: str,
        sess_name: str,
        staged_sessions: dict[str, dict[str, Any]],
    ) -> None:
        sess_uid = None
        try:
            sess_res = await self._client.api_call_with_sid(
                mgmt, sid, server_ip, "show-session", payload={}, domain=domain
            )
            if sess_res.success and isinstance(sess_res.data, dict):
                sess_uid = sess_res.data.get("uid")
        except Exception:
            pass

        staged_sessions[f"{mgmt}:{domain}"] = {
            "mgmt_name": mgmt,
            "domain_name": domain,
            "session_name": sess_name,
            "session_uid": sess_uid,
            "sid": sid,
            "server_ip": server_ip,
        }

    async def _finalize_domain_session(
        self,
        mgmt: str,
        domain: str,
        sid: str,
        server_ip: str,
        results: list[ActionResult],
        *,
        discard: bool,
        no_publish: bool,
    ) -> None:
        if discard:
            await self._client.api_call_with_sid(mgmt, sid, server_ip, "discard", payload={}, domain=domain)
        elif not no_publish and any(r.outcome in _WRITE_OUTCOMES for r in results):
            await self._client.api_call_with_sid(
                mgmt, sid, server_ip, "publish", payload={}, wait_for_task=True, domain=domain
            )

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
        keep_session: bool = False,
        staged_sessions: dict[str, dict[str, Any]] | None = None,
    ) -> AsyncIterator[ActionResult]:
        results: list[ActionResult] = []
        sid, server_ip = "", ""
        try:
            sess_name = session_name or f"cpcrud-{mgmt}-{domain}"
            sid, server_ip = await self._client.create_dedicated_session(
                mgmt,
                domain,
                session_name=sess_name,
                session_description=session_description,
            )
            if (no_publish or keep_session) and staged_sessions is not None:
                await self._record_staged_session(mgmt, domain, sid, server_ip, sess_name, staged_sessions)

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
            await self._finalize_domain_session(
                mgmt, domain, sid, server_ip, results, discard=discard, no_publish=no_publish
            )
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
            if sid and not keep_session:
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

    async def _delete_blocked(self, mgmt: str, action: PlannedAction, uid: str) -> ActionResult | None:
        """An ERROR result while the object is still referenced, or when where-used cannot tell (Backlog #37)."""
        try:
            total = await self._reader.where_used(uid, mgmt=mgmt, domain=action.domain_name)
        except StateReadError as exc:
            reason = str(exc)
        else:
            if total == 0:
                return None
            reason = f"{total} direct reference(s) still exist"
        return ActionResult(
            action_id=action.id,
            outcome=Outcome.ERROR,
            type=action.type,
            name=action.resolved_name,
            mgmt_name=action.mgmt_name,
            domain_name=action.domain_name,
            uid=uid,
            message=f"delete blocked: {reason}",
        )

    async def _handle_api_failure(
        self, mgmt: str, sid: str, server_ip: str, action: PlannedAction, res: ApiCallResult
    ) -> ActionResult:
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
                locking_session=await self._find_locking_session(mgmt, sid, server_ip, action.domain_name),
                message=res.message,
            )
        if kind == "exists" and action.operation == "add":
            message = "drift: object appeared since plan; reusing existing"
            try:
                live = await self._reader.get_by_name(
                    action.type, action.resolved_name, mgmt=mgmt, domain=action.domain_name
                )
            except StateReadError as exc:  # the server said it exists; only its uid is unknown
                live = None
                message += f" (uid lookup failed: {exc})"
            return ActionResult(
                action_id=action.id,
                outcome=Outcome.DRIFTED,
                type=action.type,
                name=action.resolved_name,
                mgmt_name=action.mgmt_name,
                domain_name=action.domain_name,
                uid=live.uid if live else None,
                message=message,
            )
        if kind == "missing" and action.operation in ("update", "delete"):
            message = (
                "drift: object already gone" if action.operation == "delete" else "drift: object vanished since plan"
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
        detailed_msg = _format_api_failure_message(res, action)
        return ActionResult(
            action_id=action.id,
            outcome=Outcome.ERROR,
            type=action.type,
            name=action.resolved_name,
            mgmt_name=action.mgmt_name,
            domain_name=action.domain_name,
            message=detailed_msg,
        )

    async def _execute_action_inner(self, mgmt: str, sid: str, server_ip: str, action: PlannedAction) -> ActionResult:
        if action.operation == "delete" and action.command is not None and action.resolved_uid:
            blocked = await self._delete_blocked(mgmt, action, action.resolved_uid)
            if blocked is not None:
                return blocked
        payload = _prepare_action_payload(action)
        if action.command is None or payload is None:
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
                mgmt,
                sid,
                server_ip,
                action.command,
                payload=payload,
                wait_for_task=True,
                domain=action.domain_name,
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
            return await self._handle_api_failure(mgmt, sid, server_ip, action, res)
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

    async def _find_locking_session(self, mgmt: str, sid: str, server_ip: str, domain: str) -> dict[str, Any] | None:
        try:
            res = await self._client.api_call_with_sid(
                mgmt, sid, server_ip, "show-sessions", payload={"limit": 100}, domain=domain
            )
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
        staged_sessions: dict[str, dict[str, Any]] | None = None,
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
        return ApplyReport(
            results=results,
            published_domains=published,
            staged_sessions=staged_sessions or {},
            remaining=remaining,
            summary=summary,
        )
