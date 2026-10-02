"""Rulebase refresh: per domain, every policy package, layer and NAT policy is read completely, with sections, place-holders and the global place-holder link, then the domain's snapshot and sync state are replaced in one transaction."""

from __future__ import annotations

import warnings as _warnings
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from ...cache.models import RulebaseSyncState
from ...cache.rulebase_rows import build_rulebase_rows
from ...core.domain_list_refresh import DOMAIN_LIST_REFRESH_TTL_SECONDS, DomainListRefreshTracker
from ...core.exceptions import InvalidCredentialsError, PublishedHeadError
from ...logger import lazy_logger
from ...rulebase.model import RULEBASE_CACHE_FORMAT, DomainRefreshResult, DomainRulebaseSnapshot
from .rulebase_reader import DomainReadFailed, read_domain

if TYPE_CHECKING:
    from ...cache import CacheRepository
    from ...cache.models import LastPublishedSession
    from ...cache.object_service import ObjectService
    from ...core.cache_policy import Clock
    from ..client import ArodonataClient

log = lazy_logger("arodonata.api.services.rulebase_refresh_service")


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class RulebaseRefreshService:
    """Refreshes the rulebase cache from the Check Point API, one domain snapshot at a time."""

    def __init__(
        self,
        client: ArodonataClient,
        cache: CacheRepository,
        domain_list_refresh_ttl: int = DOMAIN_LIST_REFRESH_TTL_SECONDS,
        clock: Clock | None = None,
        object_service: ObjectService | None = None,
    ) -> None:
        """Initialize rulebase refresh service.

        Args:
            client: ArodonataClient instance for API calls.
            cache: Cache repository instance.
            domain_list_refresh_ttl: Seconds between opportunistic ("check"-mode)
                re-fetches of a management server's domain list ahead of
                `refresh_all`. "force" mode ignores this and always re-fetches.
                See `arodonata.core.domain_list_refresh`.
            clock: Injectable time source for the TTL memo (tests only;
                defaults to the real wall clock).
            object_service: Reads the domain's published head (``read_last_published_session``). Optional so the
                exported class stays source-compatible; ``refresh_domain`` and ``is_rulebase_stale`` raise
                RuntimeError without it.
        """
        self._client = client
        self._cache = cache
        self._object_service = object_service
        self._domain_list_refresh = DomainListRefreshTracker(ttl_seconds=domain_list_refresh_ttl, clock=clock)

    def _require_object_service(self) -> ObjectService:
        if self._object_service is None:
            raise RuntimeError("RulebaseRefreshService needs object_service for refresh_domain and is_rulebase_stale")
        return self._object_service

    # ---- one domain ------------------------------------------------------------------------------------------

    async def refresh_domain(
        self, mgmt_name: str, domain: str, *, force: bool = False
    ) -> AsyncGenerator[dict[str, Any]]:
        """Read one domain's rulebases completely and replace its snapshot atomically.

        Steps: published head (before any rulebase read), dirty-session guard, show-packages and NAT per package,
        every layer of each type (package layers, listing, inline closure), place-holder links per package and
        global layer (skipped for the Global domain), then one replace with the sync state. Any failure keeps the
        old snapshot and marks the sync state failed. ``force`` only changes head failure: the snapshot is then
        stored unversioned instead of failing. ``asyncio.CancelledError`` is not caught.

        Yields:
            Progress events; ``warning`` events; the last event has status ``domain_refreshed`` or
            ``domain_failed`` and carries the DomainRefreshResult under ``result``.
        """
        object_service = self._require_object_service()
        scope = {"mgmt_name": mgmt_name, "domain_name": domain}
        yield {"message": f"Refreshing rulebases for {mgmt_name}:{domain}", **scope}
        warnings: list[str] = []
        error: str | None = None
        head: LastPublishedSession | None = None
        try:
            head = await self._read_head(object_service, mgmt_name, domain, force, warnings)
            await self._ensure_clean_session(mgmt_name, domain)
            packages, layers = await read_domain(self._client, mgmt_name, domain, warnings)
            snapshot = DomainRulebaseSnapshot(
                mgmt_name=mgmt_name,
                domain_name=domain,
                session_uid=(head.uid or None) if head else None,
                session_published_time=head.published_time if head else None,
                refreshed_at=_now(),
                packages=tuple(sorted(packages, key=lambda p: p.package_name)),
                layers=tuple(sorted(layers.values(), key=lambda layer: (layer.rulebase_type, layer.layer_uid))),
            )
            status: Literal["ok", "unversioned"] = "ok" if head is not None else "unversioned"
            state = RulebaseSyncState(
                id=f"{mgmt_name}:{domain}",
                mgmt_name=mgmt_name,
                domain_name=domain,
                session_uid=snapshot.session_uid,
                session_published_time=snapshot.session_published_time,
                refreshed_at=snapshot.refreshed_at,
                format_version=RULEBASE_CACHE_FORMAT,
                status=status,
                last_error=None,
            )
            await self._cache.replace_domain_rulebases(mgmt_name, domain, build_rulebase_rows(snapshot), state)
        except (DomainReadFailed, InvalidCredentialsError) as exc:
            error = str(exc)
        except Exception as exc:
            log().exception(f"Rulebase refresh of {mgmt_name}:{domain} failed")
            error = f"{type(exc).__name__}: {exc}"
        for warning in warnings:
            log().warning(warning)
            yield {"status": "warning", "message": warning, **scope}
        if error is not None:
            yield await self._failed(mgmt_name, domain, error, warnings)
            return
        counts = {
            t: sum(1 for layer in snapshot.layers if layer.rulebase_type == t for i in layer.items if i.kind == "rule")
            for t in ("access", "nat", "https", "threat")
        }
        result = DomainRefreshResult(mgmt_name, domain, status, snapshot.session_uid, counts, None, tuple(warnings))
        total = sum(counts.values())
        yield {
            "message": f"Saved {total} rules for {mgmt_name}:{domain}",
            "status": "domain_refreshed",
            "count": total,
            "result": result,
            **scope,
        }

    async def _failed(self, mgmt_name: str, domain: str, error: str, warnings: list[str]) -> dict[str, Any]:
        message = f"Rulebase refresh failed for {mgmt_name}:{domain}: {error}; cached snapshot kept"
        log().warning(message)
        # The state store may be what failed: the domain_failed event is yielded regardless (spec 2.8).
        session_uid: str | None = None
        try:
            await self._cache.mark_rulebase_sync_failed(mgmt_name, domain, error)
        except Exception:
            log().exception(f"Could not record the failed rulebase refresh of {mgmt_name}:{domain}")
        try:
            state = await self._cache.get_rulebase_sync_state(mgmt_name, domain)
            session_uid = state.session_uid if state else None
        except Exception:
            log().exception(f"Could not read the rulebase sync state of {mgmt_name}:{domain}")
        result = DomainRefreshResult(mgmt_name, domain, "failed", session_uid, {}, error, tuple(warnings))
        return {
            "message": message,
            "status": "domain_failed",
            "error": error,
            "count": 0,
            "result": result,
            "mgmt_name": mgmt_name,
            "domain_name": domain,
        }

    async def _read_head(
        self, object_service: ObjectService, mgmt_name: str, domain: str, force: bool, warnings: list[str]
    ) -> LastPublishedSession | None:
        try:
            return await object_service.read_last_published_session(mgmt_name, domain)
        except PublishedHeadError as exc:
            if not force:
                raise DomainReadFailed(f"last published session unreadable: {exc.reason}") from exc
            warnings.append(
                f"Last published session of {mgmt_name}:{domain} unreadable ({exc.reason}); "
                "snapshot stored unversioned, the next check refreshes it again"
            )
            return None

    async def _ensure_clean_session(self, mgmt_name: str, domain: str) -> None:
        """Refuse to read through a shared session that holds unpublished changes (spec 2.8: refuse, not a
        dedicated login)."""
        result = await self._client.api_call(mgmt_name=mgmt_name, command="show-session", domain=domain, payload={})
        if not result.success or not isinstance(result.data, dict):
            raise DomainReadFailed(f"show-session failed: {result.code}: {result.message}")
        if int(result.data.get("changes") or 0) > 0 or int(result.data.get("locks") or 0) > 0:
            raise DomainReadFailed("dirty session")

    async def is_rulebase_stale(self, mgmt_name: str, domain: str) -> bool:
        """Whether the domain's rulebase snapshot is older than its last published session (spec 2.9)."""
        stale, _ = await self._staleness(mgmt_name, domain)
        return stale

    async def _staleness(self, mgmt_name: str, domain: str) -> tuple[bool, str | None]:
        """(stale, warning). No usable sync state is stale without an API call; invalid credentials are stale (the
        refresh then reports the failure); an unreadable head is fresh with a warning (fail-open)."""
        object_service = self._require_object_service()
        state = await self._cache.get_rulebase_sync_state(mgmt_name, domain)
        if state is None or state.format_version < RULEBASE_CACHE_FORMAT or state.status != "ok":
            return True, None
        try:
            head = await object_service.read_last_published_session(mgmt_name, domain)
        except InvalidCredentialsError:
            return True, None
        except PublishedHeadError as exc:
            return (
                False,
                f"Rulebase staleness check for {mgmt_name}:{domain} failed ({exc.reason}); cached snapshot served",
            )
        if head.uid and state.session_uid:
            return head.uid != state.session_uid, None
        if state.session_published_time is None:
            return True, None
        return head.published_time > state.session_published_time, None

    # ---- all domains -----------------------------------------------------------------------------------------

    async def refresh_all(
        self,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        mode: Literal["skip", "check", "force"] = "force",
        include_global: bool = False,
    ) -> AsyncGenerator[dict[str, Any]]:
        """Refresh all rulebases for specified managements and domains.

        Args:
            mgmt_names: Optional management server filter.
            domain_names: Optional domain filter.
            mode: "skip" does nothing; "check" refreshes only stale domains
                (see `is_rulebase_stale`); "force" refreshes every domain. The
                mode also decides whether the domain *list* is re-fetched before
                resolving `target_domains` below - see
                `_ensure_domain_list_fresh`.
            include_global: When False (default), the "Global" domain
                is excluded so existing callers see today's behavior.

        Yields:
            Progress dictionaries.
        """
        if mode == "skip":
            yield {"message": "Rulebase refresh skipped", "status": "skipped"}
            return

        target_mgmt = mgmt_names or self._client.get_mgmt_names()

        for m_name in target_mgmt:
            # A domain created in SmartConsole after this mgmt's domains table was
            # last populated would otherwise stay invisible to `get_domains` below
            # forever - re-fetch it first (unconditionally for "force", at most
            # once per TTL for "check").
            await self._ensure_domain_list_fresh(m_name, mode)

            # Get domains for this mgmt
            # The domain list was just re-fetched above as needed; read it from the cache only.
            domains = await self._client.get_domains(
                mgmt_names=[m_name], cache_mode="cache", include_global=include_global
            )
            target_domains = [d.name for d in domains]
            if domain_names:
                target_domains = [d for d in target_domains if d in domain_names]

            for d_name in target_domains:
                scope = {"mgmt_name": m_name, "domain_name": d_name}
                if mode == "check":
                    try:
                        stale, warning = await self._staleness(m_name, d_name)
                    except Exception:
                        # refresh_domain then runs and reports its own failure as domain_failed
                        log().exception(f"Rulebase staleness check of {m_name}:{d_name} failed; treating it as stale")
                        stale, warning = True, None
                    if warning:
                        log().warning(warning)
                        yield {"status": "warning", "message": warning, **scope}
                    if not stale:
                        yield {
                            "status": "domain_fresh",
                            "message": f"Rulebases of {m_name}:{d_name} are up to date",
                            **scope,
                        }
                        continue
                async for event in self.refresh_domain(m_name, d_name, force=mode == "force"):
                    yield {k: v for k, v in event.items() if k != "result"}

    async def _ensure_domain_list_fresh(self, mgmt_name: str, mode: Literal["skip", "check", "force"]) -> None:
        """Re-fetch `mgmt_name`'s domain list from the API before `refresh_all`
        resolves which domains to refresh rulebases for.

        Mirrors `ObjectService._get_domains_to_refresh`'s fix for the identical
        underlying bug: a domain created in SmartConsole after the domains table
        was first seeded stayed invisible to every rulebase refresh forever,
        because this method previously never called `populate_domain_cache` at
        all - it only ever read whatever was already cached via
        `client.get_domains()`. "force" mode now always re-fetches
        unconditionally; "check" mode re-fetches at most once per
        `DOMAIN_LIST_REFRESH_TTL_SECONDS`, via the same `DomainListRefreshTracker`
        mechanism `ObjectService` uses, so repeated smart refreshes don't hammer
        `show-domains`.

        A failed or unavailable re-fetch is not fatal here - unlike
        `ObjectService`, this is purely an opportunistic freshening step ahead of
        the `client.get_domains()` cache read that follows, which already
        tolerates a merely-stale (or even still-empty) table the same as before
        this fix.
        """
        if mode != "force" and not self._domain_list_refresh.is_stale(mgmt_name):
            return

        if not hasattr(self._client, "_domain_service"):
            return

        try:
            await self._client._domain_service.populate_domain_cache(mgmt_name)
        except Exception as e:
            log().exception(f"Failed to refresh domain list for {mgmt_name}: {e}")
            return

        self._domain_list_refresh.mark_checked(mgmt_name)

    async def _deprecated_refresh(self, method: str, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]:
        """Shared body of the deprecated per-type wrappers: warn, then ``refresh_domain(force=True)`` without ``result``."""
        _warnings.warn(
            f"RulebaseRefreshService.{method} is deprecated and refreshes the whole domain; use refresh_domain",
            DeprecationWarning,
            stacklevel=3,
        )
        async for event in self.refresh_domain(mgmt_name, domain, force=True):
            yield {k: v for k, v in event.items() if k != "result"}

    async def refresh_access_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]:
        """Deprecated: refreshes the whole domain (every rulebase type), like ``refresh_domain(force=True)``."""
        async for event in self._deprecated_refresh("refresh_access_rulebases", mgmt_name, domain):
            yield event

    async def refresh_nat_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]:
        """Deprecated: refreshes the whole domain (every rulebase type), like ``refresh_domain(force=True)``."""
        async for event in self._deprecated_refresh("refresh_nat_rulebases", mgmt_name, domain):
            yield event

    async def refresh_https_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]:
        """Deprecated: refreshes the whole domain (every rulebase type), like ``refresh_domain(force=True)``."""
        async for event in self._deprecated_refresh("refresh_https_rulebases", mgmt_name, domain):
            yield event

    async def refresh_threat_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]:
        """Deprecated: refreshes the whole domain (every rulebase type), like ``refresh_domain(force=True)``."""
        async for event in self._deprecated_refresh("refresh_threat_rulebases", mgmt_name, domain):
            yield event


__all__ = ["RulebaseRefreshService"]
