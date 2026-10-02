"""Decides whether a named domain's rulebase snapshot is refreshed before a rule read (spec 2.10)."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from arodonata.core.cache_mode import CacheMode
from arodonata.core.cache_policy import CachePolicy, RefreshOutcome, RefreshScope, SystemClock
from arodonata.logger import lazy_logger

if TYPE_CHECKING:
    from arodonata.core.cache_policy import Clock

log = lazy_logger("arodonata.core.rulebase_refresh_coordinator")


class RulebaseRefreshCoordinator:
    """Rulebase counterpart of CacheRefreshCoordinator.

    Only explicitly named, non-empty domains are refreshed (a broad read serves the cache; ``''`` is never
    refreshed; ``Global`` only when named), on the named mgmt servers, or on the first configured one when none is
    named (an application that omits the mgmt has one server). SMART and SMART_FAST: TTL memo, then the service's session-uid check,
    then a full domain refresh. FORCE: refresh, memo ignored. CACHE: nothing. The memo is marked after every
    outcome, failures included, so a failing domain is retried at most once per TTL.
    """

    def __init__(
        self,
        refresh_service: Any,
        api: Any,
        default_mode: CacheMode = CacheMode.SMART,
        default_ttl: int = 300,
        clock: Clock | None = None,
    ) -> None:
        self._service = refresh_service
        self._api = api
        self.default_policy = CachePolicy(mode=default_mode, ttl=default_ttl)
        self._clock: Clock = clock or SystemClock()
        self._checked_at: dict[tuple[str, str], Any] = {}
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}

    async def ensure(self, scope: RefreshScope, policy: CachePolicy) -> RefreshOutcome:
        """Refresh the named domains of ``scope`` that ``policy`` says are due."""
        outcome = RefreshOutcome(mode_used=policy.mode)
        if policy.mode == CacheMode.CACHE:
            outcome.skipped_reason = "cache-mode"
            return outcome
        domains = [d for d in scope.domain_names or [] if d]
        if not domains:
            outcome.skipped_reason = "no-named-domain"
            return outcome
        # No mgmt given means a single-server application: refresh on the first configured server only, never on
        # every server (a domain lives on one of them; the others would each cost a failed login per TTL).
        mgmt_names = scope.mgmt_names or list(self._api.get_mgmt_names())[:1]
        for mgmt in mgmt_names:
            for domain in domains:
                await self._ensure_one(mgmt, domain, policy, outcome)
        return outcome

    def invalidate(self, mgmt_name: str, domain_name: str) -> None:
        """Drop the TTL memo for a domain so the next smart read re-checks it."""
        self._checked_at.pop((mgmt_name, domain_name), None)

    async def _ensure_one(self, mgmt: str, domain: str, policy: CachePolicy, outcome: RefreshOutcome) -> None:
        key = (mgmt, domain)
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            force = policy.mode == CacheMode.FORCE
            if not force and self._ttl_fresh(key, policy.ttl):
                return
            try:
                if not force and not await self._service.is_rulebase_stale(mgmt, domain):
                    return
                ok = await self._refresh(mgmt, domain, force)
            except Exception:
                log().exception(f"Rulebase refresh check of {mgmt}/{domain} failed; serving the cached snapshot")
                ok = False
            finally:
                self._checked_at[key] = self._clock.now()
            (outcome.refreshed_domains if ok else outcome.failed_domains).append(key)

    async def _refresh(self, mgmt: str, domain: str, force: bool) -> bool:
        result = None
        async for event in self._service.refresh_domain(mgmt, domain, force=force):
            result = event.get("result", result)
        return result is not None and result.status != "failed"

    def _ttl_fresh(self, key: tuple[str, str], ttl: int | None) -> bool:
        checked = self._checked_at.get(key)
        if not ttl or checked is None:
            return False
        return (self._clock.now() - checked).total_seconds() < ttl
