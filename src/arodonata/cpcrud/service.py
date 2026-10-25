"""Unified CPCRUD service facade (`src/arodonata/cpcrud/service.py`).

Exposes:
- `validate(template, *, schema_path=None) -> list[str]`
- `await plan(template, ...) -> Plan`
- `await apply(plan, ...) -> ApplyReport`
- `stream_apply(plan, ...) -> AsyncIterator[CPCRUDEvent]`
- `inverse(plan, report=None) -> dict[str, Any]`
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext, UserContext
from arodonata.core.errors import ConfigurationError, ValidationError
from arodonata.core.events import CPCRUDEvent
from arodonata.core.models.common import ApiCallResult, utc_now
from arodonata.core.ports import ApiPort, CachePort
from arodonata.core.telemetry import span_attrs, traced
from arodonata.cpcrud.executor import Executor
from arodonata.cpcrud.inverse import build_inverse_template
from arodonata.cpcrud.models import (
    ApplyReport,
    IpConflictPolicy,
    NameConflictPolicy,
    NamingPrefixes,
    Plan,
)
from arodonata.cpcrud.planner import Planner
from arodonata.cpcrud.validator import parse_template_input, validate_template


class CPCRUDService:
    """Declarative Check Point Policy-as-Code CRUD engine (`client.cpcrud`)."""

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        api: ApiPort,
        cache: CachePort,
        on_domain_invalidated: Callable[[str, str | None], None] | None = None,
        ensure_initialized: Callable[[], Any] | None = None,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._settings = settings
        self._api = api
        self._cache = cache
        self._on_domain_invalidated = on_domain_invalidated
        self._ensure_initialized = ensure_initialized
        self._now = now_fn

        default_mgmt = self._settings.mgmt_names[0] if self._settings.mgmt_names else (self._settings.mgmt_name or "")
        self._planner = Planner(
            api=self._api,
            cache=self._cache,
            default_mgmt_name=default_mgmt,
            now_fn=self._now,
        )
        self._executor = Executor(
            api=self._api,
            on_domain_invalidated=self._on_domain_invalidated,
            now_fn=self._now,
        )

    @property
    def planner(self) -> Planner:
        """Underlying `Planner` instance."""
        return self._planner

    @property
    def executor(self) -> Executor:
        """Underlying `Executor` instance."""
        return self._executor

    @property
    def last_report(self) -> ApplyReport | None:
        """Return the `ApplyReport` from the most recent `apply` or `stream_apply` run."""
        return self._executor.last_report

    @traced
    def validate(
        self,
        template: dict[str, Any] | str,
        *,
        schema_path: str | Path | None = None,
    ) -> list[str]:
        """Validate `template` offline against `checkpoint_ops_schema.json` using `jsonschema.Draft7Validator`.

        Performs zero network or database calls.
        """
        eff_schema = schema_path if schema_path is not None else self._settings.cpcrud_schema_path
        return validate_template(template, schema_path=eff_schema)

    @traced
    async def plan(
        self,
        template: dict[str, Any] | str,
        *,
        on_name_conflict: NameConflictPolicy | None = None,
        on_ip_conflict: IpConflictPolicy | None = None,
        naming_prefixes: NamingPrefixes | Mapping[str, Any] | None = None,
        validate_schema: bool = True,
    ) -> Plan:
        """Inspect domain state via an isolated `HybridStateReader` and build a deterministic `Plan`."""
        parsed, parse_errs = parse_template_input(template)
        if parse_errs or parsed is None:
            raise ConfigurationError(f"Invalid CPCRUD template: {'; '.join(parse_errs)}")

        if validate_schema:
            schema_errs = self.validate(parsed)
            if schema_errs:
                raise ValidationError(f"CPCRUD template failed schema validation: {'; '.join(schema_errs)}")

        if self._ensure_initialized is not None:
            res = self._ensure_initialized()
            if hasattr(res, "__await__"):
                await res

        span_attrs(validate_schema=validate_schema)
        return await self._planner.decide(
            parsed,
            on_name_conflict=on_name_conflict,
            on_ip_conflict=on_ip_conflict,
            naming_prefixes=naming_prefixes,
        )

    @traced
    async def apply(
        self,
        plan: Plan,
        *,
        force: bool = False,
        no_publish: bool = False,
        keep_session: bool = False,
        retry_remaining: int = 0,
        auth: AuthContext | None = None,
        user: UserContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> ApplyReport:
        """Execute `plan` in an isolated `WriteSession` per domain and return `ApplyReport`."""
        if self._ensure_initialized is not None:
            res = self._ensure_initialized()
            if hasattr(res, "__await__"):
                await res

        return await self._executor.apply(
            plan,
            force=force,
            no_publish=no_publish,
            keep_session=keep_session,
            retry_remaining=retry_remaining,
            auth=auth,
            user=user,
            session_name=session_name,
            session_description=session_description,
        )

    async def stream_apply(
        self,
        plan: Plan,
        *,
        force: bool = False,
        no_publish: bool = False,
        keep_session: bool = False,
        retry_remaining: int = 0,
        auth: AuthContext | None = None,
        user: UserContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> AsyncIterator[CPCRUDEvent]:
        """Execute `plan` in an isolated `WriteSession` per domain and stream `CPCRUDEvent` items."""
        if self._ensure_initialized is not None:
            res = self._ensure_initialized()
            if hasattr(res, "__await__"):
                await res

        async for ev in self._executor.stream_apply(
            plan,
            force=force,
            no_publish=no_publish,
            keep_session=keep_session,
            retry_remaining=retry_remaining,
            auth=auth,
            user=user,
            session_name=session_name,
            session_description=session_description,
        ):
            yield ev

    @traced
    def inverse(
        self,
        plan: Plan,
        report: ApplyReport | None = None,
    ) -> dict[str, Any]:
        """Build a schema-valid compensating rollback template from `plan` (and optional `report`)."""
        return build_inverse_template(plan, report)

    @traced
    async def publish_staged_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        session_uid: str,
        sid: str | None = None,
        server_ip: str | None = None,
        timeout: float | None = None,
        auth: AuthContext | None = None,
    ) -> ApiCallResult:
        """Adopt `session_uid` via `take-over-session`, publish it, log out, and invalidate the domain cache."""
        if self._ensure_initialized is not None:
            res = self._ensure_initialized()
            if hasattr(res, "__await__"):
                await res

        return await self._executor.publish_staged_session(
            mgmt_name,
            domain,
            session_uid=session_uid,
            sid=sid,
            server_ip=server_ip,
            timeout=timeout,
            auth=auth,
        )

    async def stream_publish_staged_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        session_uid: str,
        sid: str | None = None,
        server_ip: str | None = None,
        timeout: float | None = None,
        auth: AuthContext | None = None,
    ) -> AsyncIterator[CPCRUDEvent]:
        """Adopt `session_uid` via `take-over-session`, publish it while streaming `CPCRUDEvent` items, log out, and invalidate the domain cache."""
        if self._ensure_initialized is not None:
            res = self._ensure_initialized()
            if hasattr(res, "__await__"):
                await res

        async for ev in self._executor.stream_publish_staged_session(
            mgmt_name,
            domain,
            session_uid=session_uid,
            sid=sid,
            server_ip=server_ip,
            timeout=timeout,
            auth=auth,
        ):
            yield ev

    @traced
    async def discard_staged_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        session_uid: str,
        sid: str | None = None,
        server_ip: str | None = None,
        auth: AuthContext | None = None,
    ) -> ApiCallResult:
        """Adopt `session_uid` via `take-over-session`, discard uncommitted changes, and log out."""
        if self._ensure_initialized is not None:
            res = self._ensure_initialized()
            if hasattr(res, "__await__"):
                await res

        return await self._executor.discard_staged_session(
            mgmt_name,
            domain,
            session_uid=session_uid,
            sid=sid,
            server_ip=server_ip,
            auth=auth,
        )


__all__ = [
    "CPCRUDService",
]
