"""Stale and abandoned Check Point Web API session cleaner (`SessionCleaner`)."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from arodonata.adapters.checkpoint.rate_limiter import RateLimiter
from arodonata.adapters.checkpoint.target_resolver import logger
from arodonata.adapters.checkpoint.transport import ApiTransport
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext, get_auth_context, normalize_domain_key
from arodonata.core.errors import (
    ApiTimeoutError,
    AuthenticationError,
    MissingConfigurationError,
    ServerIdentityError,
    TransportError,
)
from arodonata.core.ports import SidCachePort
from arodonata.core.telemetry import span_attrs, traced

if TYPE_CHECKING:
    from arodonata.adapters.checkpoint.sessions import LoginCoordinator


class SessionCleaner:
    """Cleans up stale or abandoned Check Point API sessions on startup and max-sessions refusal.

    Invariants:
    - Opens a temporary read-write cleanup session, discards only Arodonata-owned sessions
      with `changes == 0` and `locks == 0`, and ALWAYS logs out that temporary read-write
      session via `logout_sid` without ever seeding a read-write SID into `arodonata_sid_cache`.
    - When `ArodonataClient` / `AMgmtClient` enters in `"dynamic"` auth mode before any
      administrator credentials have been supplied, startup session cleanup is skipped
      without raising an authentication error.
    """

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        login_coordinator: LoginCoordinator,
        transport: ApiTransport,
        cache: SidCachePort,
        rate_limiter: RateLimiter,
    ) -> None:
        self._settings = settings
        self._login_coordinator = login_coordinator
        self._transport = transport
        self._cache = cache
        self._rate_limiter = rate_limiter
        self._startup_tasks: set[asyncio.Task[Any]] = set()

    @property
    def startup_tasks(self) -> set[asyncio.Task[Any]]:
        """Currently running startup cleanup tasks."""
        return set(self._startup_tasks)

    def _is_cold_dynamic_mode(self, *, auth: AuthContext | None = None) -> bool:
        """Return `True` when dynamic auth mode has no explicit, contextual, or provider credentials."""
        return (
            self._settings.auth_mode == "dynamic"
            and auth is None
            and get_auth_context() is None
            and not self._login_coordinator.has_dynamic_auth_provider()
        )

    def schedule_startup_cleanup(self) -> list[asyncio.Task[bool]]:
        """Schedule startup stale-session cleanup for all configured servers when static credentials exist."""
        if self._is_cold_dynamic_mode():
            return []

        tasks: list[asyncio.Task[bool]] = []
        for mgmt_name in self._settings.servers:
            if not self._login_coordinator.has_static_credentials(mgmt_name):
                continue
            task = asyncio.create_task(self.cleanup_server_sessions(mgmt_name))
            self._startup_tasks.add(task)

            def _on_startup_done(t: asyncio.Task[bool], server: str = mgmt_name) -> None:
                self._startup_tasks.discard(t)
                if not t.cancelled():
                    exc = t.exception()
                    if exc is not None:
                        logger.warning(
                            f"Startup session cleanup failed for '{server}': {exc}",
                            mgmt_name=server,
                        )

            task.add_done_callback(_on_startup_done)
            tasks.append(task)
        return tasks

    @traced
    async def run_startup_cleanup(self) -> dict[str, bool]:
        """Run startup session cleanup across all configured servers (skipping in cold dynamic mode)."""
        if self._is_cold_dynamic_mode():
            span_attrs(startup_cleanup_skipped=True, reason="dynamic_auth_mode")
            return {}

        outcomes: dict[str, bool] = {}
        for mgmt_name in self._settings.servers:
            if not self._login_coordinator.has_static_credentials(mgmt_name):
                continue
            outcomes[mgmt_name] = await self.cleanup_server_sessions(mgmt_name)
        return outcomes

    @traced
    async def cleanup_server_sessions(
        self,
        mgmt_name: str,
        *,
        domain: str | None = None,
        auth: AuthContext | None = None,
    ) -> bool:
        """Inspect open Web API sessions on `mgmt_name` and discard stale/abandoned sessions."""
        if self._is_cold_dynamic_mode(auth=auth):
            return False

        dom_key = normalize_domain_key(domain)
        endpoint = self._login_coordinator.get_server_endpoint(mgmt_name)
        span_attrs(mgmt_name=mgmt_name, domain=dom_key)

        try:
            resolved_auth = await self._login_coordinator.resolve_credentials(
                mgmt_name,
                domain,
                explicit_auth=auth,
            )
        except (AuthenticationError, MissingConfigurationError) as exc:
            logger.warning(
                f"Session cleanup skipped for '{mgmt_name}:{dom_key}': {exc}",
                mgmt_name=mgmt_name,
                domain=dom_key,
            )
            return False
        identity = resolved_auth.identity_key

        # Open a dedicated session to inspect/discard stale sessions (never recurse on max-sessions)
        try:
            (
                sid,
                server_ip,
                session_uid,
            ) = await self._login_coordinator.create_dedicated_session(
                mgmt_name,
                domain,
                auth=resolved_auth,
                session_name="arodonata-session-cleaner",
                allow_max_sessions_cleanup=False,
            )
        except ServerIdentityError:
            raise
        except (
            AuthenticationError,
            TransportError,
            ApiTimeoutError,
        ) as exc:
            logger.warning(
                f"Session cleanup skipped for '{mgmt_name}:{dom_key}': {exc}",
                mgmt_name=mgmt_name,
                domain=dom_key,
            )
            return False

        try:
            _, mds_ip, _ = await self._login_coordinator.resolve_target_ips(
                mgmt_name,
                domain,
                explicit_server_ip=server_ip,
            )
            async with self._rate_limiter.slot(mds_ip):
                res = await self._transport.execute(
                    server_ip,
                    "show-sessions",
                    {
                        "details-level": "standard",
                        "limit": 100,
                        "view-published-sessions": False,
                    },
                    port=endpoint.port,
                    sid=sid,
                    timeout=self._settings.api_timeout,
                )

            if res.success:
                sessions_list = res.data.get("objects")
                if isinstance(sessions_list, list):
                    cached_sids = await self._cache.list_sids(mgmt_name=mgmt_name)
                    cached_by_uid = {entry.session_uid: entry for entry in cached_sids if entry.session_uid}
                    for sess_obj in sessions_list:
                        if not isinstance(sess_obj, dict):
                            continue
                        target_uid = sess_obj.get("uid")
                        if not isinstance(target_uid, str) or not target_uid or target_uid == session_uid:
                            continue
                        app_name = str(sess_obj.get("application") or "").strip().lower()
                        sess_name = str(sess_obj.get("session-name") or "").strip().lower()
                        is_arodonata_owned = app_name == "arodonata" or sess_name.startswith("arodonata")
                        has_no_changes_or_locks = (
                            int(sess_obj.get("changes") or 0) == 0 and int(sess_obj.get("locks") or 0) == 0
                        )
                        if not (is_arodonata_owned and has_no_changes_or_locks):
                            continue
                        cached_entry = cached_by_uid.get(target_uid)
                        if cached_entry is not None:
                            if self._login_coordinator.is_sid_entry_fresh(cached_entry):
                                continue
                            if cached_entry.auth_identity != identity:
                                continue
                        logger.debug(
                            f"Discarding stale session uid={target_uid} on '{mgmt_name}:{dom_key}'.",
                            mgmt_name=mgmt_name,
                            domain=dom_key,
                            session_uid=target_uid,
                        )
                        async with self._rate_limiter.slot(mds_ip):
                            await self._transport.execute(
                                server_ip,
                                "discard",
                                {"uid": target_uid},
                                port=endpoint.port,
                                sid=sid,
                                timeout=self._settings.api_timeout,
                            )
                        if cached_entry is not None:
                            logged_out = False
                            if cached_entry.sid:
                                try:
                                    logged_out = await self._login_coordinator.logout_sid(
                                        cached_entry.mgmt_name,
                                        cached_entry.sid,
                                        server_ip=cached_entry.server_ip,
                                    )
                                except ServerIdentityError:
                                    raise
                                except Exception:
                                    logged_out = False
                            if not logged_out:
                                await self._cache.evict_sid(
                                    cached_entry.mgmt_name,
                                    cached_entry.domain_name,
                                    auth_identity=cached_entry.auth_identity,
                                )

            return True
        finally:
            await asyncio.shield(self._login_coordinator.logout_sid(mgmt_name, sid, server_ip=server_ip))

    async def drain_startup_tasks(self, timeout: float = 5.0) -> None:
        """Wait up to `timeout` seconds for any background startup cleanup tasks to finish."""
        pending = [t for t in self._startup_tasks if not t.done()]
        if not pending:
            return
        _done, still_pending = await asyncio.wait(pending, timeout=timeout)
        for task in still_pending:
            task.cancel()
        if still_pending:
            await asyncio.gather(*still_pending, return_exceptions=True)


__all__ = ["SessionCleaner"]
