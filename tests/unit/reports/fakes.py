"""ArodonataClient double for the change report: scripted show-changes per (mgmt, domain), show-object names,
locate_rules over snapshots (recording cache_mode), and api_call_with_sid per SID."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable, Collection
from typing import Any

from arodonata.api.schemas import ApiCallResult, ApiQueryResult
from arodonata.rulebase.model import DomainRulebaseSnapshot, RulebaseType
from arodonata.rulebase.source import RuleLocations, locate_rules_in_snapshot


def _uid(e: dict[str, Any]) -> str:
    return str(e["session"]["session-uid"])


def _posix(e: dict[str, Any]) -> int:
    return int((e["session"].get("publish-time") or {}).get("posix") or 0)


class FakeReportClient:
    def __init__(self, mgmt_names: Collection[str] = ("m1",)) -> None:
        self.mgmt_names = list(mgmt_names)
        self.changes: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self.query_failures: dict[tuple[str, str, str], ApiQueryResult | BaseException] = {}  # (mgmt, domain, uid|"*")
        self.query_calls: list[dict[str, Any]] = []
        self.object_names: dict[str, str] = {}
        self.object_failures: set[str] = set()
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.snapshots: dict[tuple[str, str], DomainRulebaseSnapshot] = {}
        self.forced_snapshots: dict[tuple[str, str], DomainRulebaseSnapshot] = {}
        self.locate_error: BaseException | None = None
        self.locate_error_force: BaseException | None = None  # raised only for cache_mode="force"
        self.invalidate_error: BaseException | None = None
        self.locate_calls: list[dict[str, Any]] = []
        self.invalidated: list[tuple[str, str]] = []
        self.events: list[str] = []  # "invalidate:<domain>", "locate:<domain>:<mode>" in order
        self.sid_sessions: dict[str, dict[str, Any] | BaseException] = {}  # sid -> show-session data or error
        self.sid_responder: Callable[[str, str, dict[str, Any]], ApiCallResult | Awaitable[ApiCallResult]] | None = None
        self.sid_calls: list[tuple[str, str, dict[str, Any]]] = []  # (sid, command, payload)
        self.delay = 0.0
        self.in_flight = 0
        self.max_in_flight = 0

    def get_mgmt_names(self) -> list[str]:
        return list(self.mgmt_names)

    def invalidate_domain(self, mgmt_name: str, domain_name: str) -> None:
        if self.invalidate_error is not None:
            raise self.invalidate_error
        self.invalidated.append((mgmt_name, domain_name))
        self.events.append(f"invalidate:{domain_name}")

    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        domain: str = "",
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        container_key: str = "objects",
        cache_mode: str = "auto",
    ) -> ApiQueryResult:
        body = dict(payload or {})
        self.query_calls.append(
            {
                "mgmt_name": mgmt_name,
                "command": command,
                "domain": domain,
                "details_level": details_level,
                "payload": body,
            }
        )
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            await asyncio.sleep(self.delay)
        finally:
            self.in_flight -= 1
        key_uid = str(body.get("to-session")) if set(body) == {"to-session"} else "*"
        failure = self.query_failures.get((mgmt_name, domain, key_uid)) or self.query_failures.get(
            (mgmt_name, domain, "*")
        )
        if isinstance(failure, BaseException):
            raise failure
        if failure is not None:
            return failure
        entries = self.changes.get((mgmt_name, domain), [])
        if not body:  # no parameters: the last published session
            published = sorted((e for e in entries if e["session"].get("published")), key=_posix)
            selected = published[-1:]
        elif key_uid != "*":
            selected = [e for e in entries if _uid(e) == key_uid]
        else:  # a range: everything the domain has, unpublished included (collect must filter)
            selected = list(entries)
        return ApiQueryResult(
            success=True, data={"changes": selected, "total": len(selected)}, objects=selected, total=len(selected)
        )

    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        domain: str = "",
        details_level: str | None = None,
        payload: dict[str, Any] | None = None,
        **_: Any,
    ) -> ApiCallResult:
        body = dict(payload or {})
        self.calls.append((command, {"mgmt_name": mgmt_name, "domain": domain, "details_level": details_level, **body}))
        uid = str(body.get("uid", ""))
        if command == "show-object" and uid in self.object_failures:
            return ApiCallResult(success=False, code="generic_err_object_not_found", message="not found")
        if command == "show-object" and uid in self.object_names:
            return ApiCallResult(success=True, data={"object": {"uid": uid, "name": self.object_names[uid]}})
        return ApiCallResult(success=False, code="generic_err_object_not_found", message="not found")

    async def locate_rules(
        self,
        mgmt_name: str | None,
        domain_name: str,
        rule_uids: Collection[str] = (),
        rulebase_type: RulebaseType | None = None,
        *,
        layer_uids: Collection[str] = (),
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ) -> RuleLocations:
        self.locate_calls.append(
            {
                "mgmt_name": mgmt_name,
                "domain_name": domain_name,
                "rule_uids": set(rule_uids),
                "layer_uids": set(layer_uids),
                "cache_mode": cache_mode,
            }
        )
        self.events.append(f"locate:{domain_name}:{cache_mode}")
        if self.locate_error is not None:
            raise self.locate_error
        if cache_mode == "force" and self.locate_error_force is not None:
            raise self.locate_error_force
        key = (str(mgmt_name), domain_name)
        snapshot = (self.forced_snapshots.get(key) if cache_mode == "force" else None) or self.snapshots[key]
        return locate_rules_in_snapshot(snapshot, rule_uids, rulebase_type, layer_uids=layer_uids)

    async def api_call_with_sid(
        self,
        mgmt_name: str,
        sid: str,
        server_ip: str,
        command: str,
        payload: dict[str, Any] | None = None,
        wait_for_task: bool = True,
        timeout: int = -1,
    ) -> ApiCallResult:
        body = dict(payload or {})
        self.sid_calls.append((sid, command, body))
        if command == "show-session":
            session = self.sid_sessions.get(sid)
            if isinstance(session, BaseException):
                raise session
            if session is None:
                return ApiCallResult(success=False, code="generic_err_wrong_session_id", message=f"bad session {sid}")
            return ApiCallResult(success=True, data=dict(session))
        if self.sid_responder is None:
            return ApiCallResult(success=False, code="generic_err_command_not_found", message="no responder")
        result = self.sid_responder(sid, command, body)
        return await result if inspect.isawaitable(result) else result


LISTING_KEYS = {
    "show-packages": "packages",
    "show-access-layers": "access-layers",
    "show-threat-layers": "threat-layers",
    "show-https-layers": "https-layers",
}


def live_responder(
    rulebase: Any, mgmt_name: str = "m1"
) -> Callable[[str, str, dict[str, Any]], Awaitable[ApiCallResult]]:
    """Serve SidCaller reads from a tests.unit.rulebase.fakes.FakeRulebaseClient (listings paged by limit/offset,
    rulebase reads through its api_call)."""

    async def respond(sid: str, command: str, payload: dict[str, Any]) -> ApiCallResult:
        if command in LISTING_KEYS:
            objects = rulebase.listings.get(command, [])
            offset, limit = int(payload.get("offset", 0)), int(payload.get("limit", 50))
            page = objects[offset : offset + limit]
            return ApiCallResult(
                success=True,
                data={LISTING_KEYS[command]: page, "total": len(objects), "from": offset + 1, "to": offset + len(page)},
            )
        return await rulebase.api_call(mgmt_name, command, payload=payload)

    return respond
