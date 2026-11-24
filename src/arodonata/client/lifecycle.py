"""Lifecycle, context managers, raw API transport, and staged session methods for `ArodonataClient`."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Iterator
from contextlib import asynccontextmanager, contextmanager
from typing import Any, Self

from arodonata.adapters.checkpoint.pager import DEFAULT_PAGE_LIMIT
from arodonata.client._base import ClientBase
from arodonata.core.context import (
    AuthContext,
    UserContext,
    WriteSession,
    get_write_session,
    normalize_domain_key,
    open_api_write_session,
    update_overlay_from_command,
)
from arodonata.core.context import auth_context as _ctx_auth_context
from arodonata.core.context import user_context as _ctx_user_context
from arodonata.core.events import CPCRUDEvent
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.primitives import validate_command_name
from arodonata.core.telemetry import traced


class ClientLifecycleMixin(ClientBase):
    """Provides lifecycle management, context binding, raw API calls, and staged session methods."""

    # ------------------------------------------------------------------
    # Lifecycle Management
    # ------------------------------------------------------------------

    async def initialize(self, *, run_startup_cleanup: bool = True) -> None:
        """Initialize the database schema and optionally schedule startup session cleanup."""
        await self._ensure_initialized()
        if self._amgmt is not None:
            await self._amgmt.initialize(run_startup_cleanup=run_startup_cleanup)

    async def __aenter__(self) -> Self:
        await self.initialize(run_startup_cleanup=True)
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()

    @traced
    async def close(self, *, logout: bool | None = None) -> None:
        """Cancel running background warm-up tasks immediately, drain startup cleanup, close transport, and dispose owned engine."""
        # 1. Cancel any running background warm-up tasks immediately
        await self._warmup.cancel_all()

        # 2. Determine automatic logout policy: True if client auto-created in-memory DB, False if persistent DB or external engine
        is_ephemeral_db = self._owns_engine and self._db.is_in_memory
        should_logout = is_ephemeral_db if logout is None else bool(logout)

        # 3. Close AMgmtClient / ApiPort (drains startup cleanup tasks & logs out according to policy)
        await self._api.close(logout=should_logout)

        # 4. Dispose SQLAlchemy engine only if owned (`self._db.close()` checks `owns_engine`)
        await self._db.close()

    # ------------------------------------------------------------------
    # Raw API Transport Delegation (`ApiPort`)
    # ------------------------------------------------------------------

    @traced
    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ) -> ApiCallResult:
        """Execute a Check Point Management API command, updating active `WriteSession` overlay and invalidating domain on `publish`."""
        clean_cmd = validate_command_name(command)
        await self._ensure_initialized()

        dom_key = normalize_domain_key(domain)
        active_ws = get_write_session(mgmt_name=mgmt_name, domain_name=dom_key)

        eff_sid = sid
        eff_ip = server_ip
        if eff_sid is None and active_ws is not None and self._amgmt is None:
            eff_sid = active_ws.sid
            eff_ip = eff_ip or active_ws.server_ip

        res = await self._api.api_call(
            mgmt_name,
            clean_cmd,
            payload,
            domain=domain,
            sid=eff_sid,
            server_ip=eff_ip,
            wait_for_task=wait_for_task,
            timeout=timeout,
        )

        # If using a custom ApiPort implementation (not AMgmtClient), or an injected AMgmtClient
        # without our callback wired, ensure overlay updates and single-shot invalidation run.
        if self._amgmt is None:
            if active_ws is not None and (sid is None or sid == active_ws.sid):
                update_overlay_from_command(active_ws.overlay, clean_cmd, payload, res)
            if clean_cmd == "publish" and res.success:
                eff_domain = domain or (active_ws.domain_name if active_ws is not None else None)
                self.invalidate_domain(mgmt_name, eff_domain)
        elif not self._amgmt_invalidation_wired and clean_cmd == "publish" and res.success:
            eff_domain = domain or (active_ws.domain_name if active_ws is not None else None)
            self.invalidate_domain(mgmt_name, eff_domain)

        return res

    @traced
    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        *,
        domain: str | None = None,
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        limit: int = DEFAULT_PAGE_LIMIT,
    ) -> ApiQueryResult:
        """Execute a continuity-verified paginated Check Point object listing query."""
        await self._ensure_initialized()
        return await self._api.api_query(
            mgmt_name,
            command,
            domain=domain,
            details_level=details_level,
            payload=payload,
            sid=sid,
            server_ip=server_ip,
            limit=limit,
        )

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        """Open an isolated write session outside `sid_cache`, returning `(sid, server_ip)`."""
        await self._ensure_initialized()
        return await self._api.create_dedicated_session(
            mgmt_name,
            domain,
            auth=auth,
            session_name=session_name,
            session_description=session_description,
        )

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> Awaitable[bool]:
        """Log out a specific session identifier."""
        self._cpcrud.notify_sid_logged_out(mgmt_name, sid)
        return self._api.logout_sid(mgmt_name, sid, server_ip=server_ip)

    # ------------------------------------------------------------------
    # Context Managers (`auth_context`, `user_context`, `write_session`)
    # ------------------------------------------------------------------

    @contextmanager
    def auth_context(
        self,
        auth: AuthContext | None = None,
        *,
        username: str | None = None,
        password: str | None = None,
        api_key: str | None = None,
        user_id: str | None = None,
    ) -> Iterator[AuthContext]:
        """Bind runtime administrator credentials (`AuthContext`) in `contextvars`."""
        with _ctx_auth_context(
            auth,
            username=username,
            password=password,
            api_key=api_key,
            user_id=user_id,
        ) as resolved:
            yield resolved

    @contextmanager
    def user_context(
        self,
        user: UserContext | None = None,
        *,
        user_id: str | None = None,
        username: str | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
        client_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> Iterator[UserContext]:
        """Bind operator attribution metadata (`UserContext`) in `contextvars`."""
        with _ctx_user_context(
            user,
            user_id=user_id,
            username=username,
            session_name=session_name,
            session_description=session_description,
            client_id=client_id,
            extra=extra,
        ) as resolved:
            yield resolved

    @asynccontextmanager
    async def write_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        user: UserContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
        publish_on_exit: bool = True,
    ) -> AsyncIterator[WriteSession]:
        """Open a context-bound isolated `WriteSession` with `SessionOverlay` read-your-own-writes isolation."""
        await self._ensure_initialized()

        if self._amgmt is not None:
            async with self._amgmt.write_session(
                mgmt_name,
                domain,
                auth=auth,
                user=user,
                session_name=session_name,
                session_description=session_description,
                publish_on_exit=publish_on_exit,
            ) as ws:
                yield ws
            if not self._amgmt_invalidation_wired and ws.published:
                self.invalidate_domain(mgmt_name, domain)
            return

        # Fallback for custom ApiPort implementations injected in tests
        async with open_api_write_session(
            self,
            mgmt_name,
            domain,
            auth=auth,
            user=user,
            session_name=session_name,
            session_description=session_description,
            publish_on_exit=publish_on_exit,
            on_domain_invalidated=self.invalidate_domain,
        ) as ws:
            yield ws

    # ------------------------------------------------------------------
    # Staged Session Publishing & Discarding (`CPCRUDService`)
    # ------------------------------------------------------------------

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
        force_disconnect: bool = False,
        expected_session_name: str | None = None,
        allow_foreign: bool = False,
    ) -> ApiCallResult:
        """Adopt `session_uid`, publish it, log out, and invalidate the domain cache."""
        return await self._cpcrud.publish_staged_session(
            mgmt_name,
            domain,
            session_uid=session_uid,
            sid=sid,
            server_ip=server_ip,
            timeout=timeout,
            auth=auth,
            force_disconnect=force_disconnect,
            expected_session_name=expected_session_name,
            allow_foreign=allow_foreign,
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
        force_disconnect: bool = False,
        expected_session_name: str | None = None,
        allow_foreign: bool = False,
    ) -> AsyncIterator[CPCRUDEvent]:
        """Adopt `session_uid`, publish it while streaming `CPCRUDEvent` items, log out, and invalidate the domain cache."""
        async for ev in self._cpcrud.stream_publish_staged_session(
            mgmt_name,
            domain,
            session_uid=session_uid,
            sid=sid,
            server_ip=server_ip,
            timeout=timeout,
            auth=auth,
            force_disconnect=force_disconnect,
            expected_session_name=expected_session_name,
            allow_foreign=allow_foreign,
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
        force_disconnect: bool = False,
        expected_session_name: str | None = None,
        allow_foreign: bool = False,
    ) -> ApiCallResult:
        """Adopt `session_uid`, discard uncommitted changes, and log out."""
        return await self._cpcrud.discard_staged_session(
            mgmt_name,
            domain,
            session_uid=session_uid,
            sid=sid,
            server_ip=server_ip,
            auth=auth,
            force_disconnect=force_disconnect,
            expected_session_name=expected_session_name,
            allow_foreign=allow_foreign,
        )
