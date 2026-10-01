"""Recording double for the ArodonataClient facade methods the MCP tools call."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from arodonata.api.schemas import ApiCallResult, ApiQueryResult, SSEEvent, SSEEventType
from arodonata.core.cache_mode import CacheMode
from arodonata.cpcrud.models import ApplyReport, IpConflictPolicy, NameConflictPolicy, Plan
from arodonata.models import AccessRule, Domain, Gateway, Group, Host, Network


def host(name: str, ip: str, mgmt: str = "mgmt1", domain: str = "General") -> Host:
    raw = {
        "uid": f"uid-{name}",
        "name": name,
        "type": "host",
        "ipv4-address": ip,
        "domain": {"name": domain},
        "color": "black",
        "comments": "",
        "meta-info": {"creator": "admin"},
    }
    return Host(uid=raw["uid"], name=name, ip_address=ip, mgmt_name=mgmt, domain_name=domain, raw_data=raw)


def rule(number: int, name: str, layer: str = "Network", enabled: bool = True, inline: str | None = None) -> AccessRule:
    raw = {
        "uid": f"rule-{number}",
        "name": name,
        "type": "access-rule",
        "rule-number": number,
        "enabled": enabled,
        "source": ["src-uid"],
        "destination": ["dst-uid"],
        "service": ["svc-uid"],
        "action": "Accept",
        "track": {"type": "Log"},
        "comments": "c",
    }
    if inline:
        raw["inline-layer"] = {"uid": f"layer-{inline}", "name": inline}
    return AccessRule(
        uid=raw["uid"],
        rule_number=number,
        name=name,
        enabled=enabled,
        sources=["Any"],
        destinations=["web-srv"],
        services=["https"],
        action="Accept",
        track="Log",
        layer_name=layer,
        mgmt_name="mgmt1",
        domain_name="General",
        raw_data=raw,
    )


class _FakeCache:
    def __init__(self) -> None:
        now = datetime.now(UTC).replace(tzinfo=None)
        self.last_update = now - timedelta(seconds=90)
        self.rulebase_last_update = now - timedelta(seconds=600)
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def get_objects_last_update(self, mgmt_names=None, domain_names=None):
        self.calls.append(("get_objects_last_update", {"mgmt_names": mgmt_names, "domain_names": domain_names}))
        return self.last_update

    async def get_rulebase_last_update(self, rulebase_type: str, mgmt_names=None, domain_names=None):
        self.calls.append(
            (
                "get_rulebase_last_update",
                {"rulebase_type": rulebase_type, "mgmt_names": mgmt_names, "domain_names": domain_names},
            )
        )
        return self.rulebase_last_update


class FakeCPCRUD:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.plan_result = Plan(template_hash="abc123def456")
        self.report = ApplyReport(summary={"create": 1})
        self.validation_errors: list[str] = []

    def validate(self, template: str | Path | dict[str, Any]) -> list[str]:
        self.calls.append(("validate", {"template": template}))
        return self.validation_errors

    async def plan(
        self,
        template: str | Path | dict[str, Any],
        on_name_conflict: NameConflictPolicy | None = None,
        on_ip_conflict: IpConflictPolicy | None = None,
    ) -> Plan:
        self.calls.append(("plan", {"template": template}))
        return self.plan_result

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
        self.calls.append(
            (
                "apply",
                {
                    "plan_or_template": plan_or_template,
                    "force": force,
                    "dry_run": dry_run,
                    "no_publish": no_publish,
                    "discard": discard,
                    "session_name": session_name,
                    "session_description": session_description,
                    "on_name_conflict": on_name_conflict,
                    "on_ip_conflict": on_ip_conflict,
                    "retry_remaining": retry_remaining,
                    "refresh": refresh,
                },
            )
        )
        yield SSEEvent(event_type=SSEEventType.START, message="applying")
        yield self.report

    def inverse(self, plan: Plan, report: ApplyReport | None = None) -> dict[str, Any]:
        self.calls.append(("inverse", {"plan": plan, "report": report}))
        return {"management_servers": []}


class FakeArodonataClient:
    def __init__(self, mgmt_names: list[str] | None = None) -> None:
        self.mgmt_names = mgmt_names or ["mgmt1"]
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.responses: dict[str, Any] = {}
        self.cache = _FakeCache()
        self.cpcrud = FakeCPCRUD()

    def _rec(self, name: str, **kwargs: Any) -> Any:
        self.calls.append((name, kwargs))
        return self.responses.get(name)

    def _rec_rules(self, name: str, **kwargs: Any) -> Any:
        """Like ``_rec`` but a canned response keyed by ``layer_name`` is unwrapped.

        Lets a test seed ``responses["get_access_rules"] = {"Network": [...], "Inline-1": [...]}``
        and get back only the rules for the layer the tool actually asked for.
        """
        response = self._rec(name, **kwargs)
        if isinstance(response, dict):
            return response.get(kwargs.get("layer_name"), [])
        return response or []

    @staticmethod
    def _check_read_cache_mode(cache_mode: str | None) -> None:
        """Mirror ``CachePolicy.resolve``: an invalid read-cache mode raises ``ValueError`` like the real client."""
        if cache_mode is not None:
            CacheMode(cache_mode)

    @staticmethod
    def _check_session_cache_mode(cache_mode: str) -> None:
        """Mirror the real ``api_call``/``api_query`` session-cache vocabulary."""
        if cache_mode not in {"auto", "refresh", "off"}:
            raise ValueError(f"invalid session cache_mode {cache_mode!r}")

    def get_mgmt_names(self) -> list[str]:
        return list(self.mgmt_names)

    async def get_domains(
        self,
        mgmt_names: list[str] | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
        include_global: bool = False,
    ) -> list[Domain]:
        self._check_read_cache_mode(cache_mode)
        return (
            self._rec(
                "get_domains",
                mgmt_names=mgmt_names,
                cache_mode=cache_mode,
                cache_ttl=cache_ttl,
                include_global=include_global,
            )
            or []
        )

    async def get_gateways(
        self,
        mgmt_names: list[str] | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ) -> list[Gateway]:
        self._check_read_cache_mode(cache_mode)
        return self._rec("get_gateways", mgmt_names=mgmt_names, cache_mode=cache_mode, cache_ttl=cache_ttl) or []

    async def get_hosts(
        self,
        name_filter: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ) -> list[Host]:
        self._check_read_cache_mode(cache_mode)
        return (
            self._rec(
                "get_hosts",
                name_filter=name_filter,
                mgmt_names=mgmt_names,
                domain_names=domain_names,
                cache_mode=cache_mode,
                cache_ttl=cache_ttl,
            )
            or []
        )

    async def get_networks(
        self,
        subnet: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ) -> list[Network]:
        self._check_read_cache_mode(cache_mode)
        return (
            self._rec(
                "get_networks",
                subnet=subnet,
                mgmt_names=mgmt_names,
                domain_names=domain_names,
                cache_mode=cache_mode,
                cache_ttl=cache_ttl,
            )
            or []
        )

    async def get_groups(
        self,
        name_filter: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ) -> list[Group]:
        self._check_read_cache_mode(cache_mode)
        return (
            self._rec(
                "get_groups",
                name_filter=name_filter,
                mgmt_names=mgmt_names,
                domain_names=domain_names,
                cache_mode=cache_mode,
                cache_ttl=cache_ttl,
            )
            or []
        )

    async def get_object_by_uid(self, uid: str, mgmt_name: str, domain_name: str = ""):
        return self._rec("get_object_by_uid", uid=uid, mgmt_name=mgmt_name, domain_name=domain_name)

    async def get_access_rules(
        self,
        layer_name: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        enabled_only: bool | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ) -> list[AccessRule]:
        self._check_read_cache_mode(cache_mode)
        return self._rec_rules(
            "get_access_rules",
            layer_name=layer_name,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            enabled_only=enabled_only,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    async def get_nat_rules(
        self,
        layer_name: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        enabled_only: bool | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ):
        self._check_read_cache_mode(cache_mode)
        return self._rec_rules(
            "get_nat_rules",
            layer_name=layer_name,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            enabled_only=enabled_only,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    async def get_https_rules(
        self,
        layer_name: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        enabled_only: bool | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ):
        self._check_read_cache_mode(cache_mode)
        return self._rec_rules(
            "get_https_rules",
            layer_name=layer_name,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            enabled_only=enabled_only,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    async def get_threat_rules(
        self,
        layer_name: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        enabled_only: bool | None = None,
        cache_mode: str | None = None,
        cache_ttl: int | None = None,
    ):
        self._check_read_cache_mode(cache_mode)
        return self._rec_rules(
            "get_threat_rules",
            layer_name=layer_name,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            enabled_only=enabled_only,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        domain: str = "",
        details_level: Literal["uid", "standard", "full"] | None = None,
        payload: dict[str, Any] | None = None,
        wait_for_task: bool = True,
        timeout: int = -1,
        cache_mode: str = "auto",
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> ApiCallResult:
        self._check_session_cache_mode(cache_mode)
        r = self._rec(
            "api_call",
            mgmt_name=mgmt_name,
            command=command,
            domain=domain,
            details_level=details_level,
            payload=payload,
            wait_for_task=wait_for_task,
            timeout=timeout,
            cache_mode=cache_mode,
            session_name=session_name,
            session_description=session_description,
        )
        if callable(r):
            r = r(payload or {})
        return r or ApiCallResult(success=True, data={"uid": "u1", "name": "obj"})

    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        domain: str = "",
        details_level: Literal["uid", "standard", "full"] = "standard",
        payload: dict[str, Any] | None = None,
        container_key: str = "objects",
        cache_mode: str = "auto",
    ) -> ApiQueryResult:
        self._check_session_cache_mode(cache_mode)
        r = self._rec(
            "api_query",
            mgmt_name=mgmt_name,
            command=command,
            domain=domain,
            details_level=details_level,
            payload=payload,
            container_key=container_key,
            cache_mode=cache_mode,
        )
        return r or ApiQueryResult(success=True, data={"objects": []}, objects=[], total=0)

    async def _stream(self, name: str, **kw) -> AsyncIterator[SSEEvent]:
        self._rec(name, **kw)
        for ev in self.responses.get(name, []):
            yield ev

    def search_objects(
        self,
        search_input: str,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        refresh: Literal["skip", "check", "force", "incremental"] = "skip",
        max_depth: int = 2,
    ):
        return self._stream(
            "search_objects",
            search_input=search_input,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            refresh=refresh,
            max_depth=max_depth,
        )

    def refresh_objects(
        self,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        mode: Literal["skip", "check", "force", "incremental"] = "force",
        include_global: bool = False,
    ):
        return self._stream(
            "refresh_objects",
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            mode=mode,
            include_global=include_global,
        )

    def refresh_rulebases(
        self,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        mode: Literal["skip", "check", "force"] = "force",
        include_global: bool = False,
    ):
        return self._stream(
            "refresh_rulebases",
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            mode=mode,
            include_global=include_global,
        )
