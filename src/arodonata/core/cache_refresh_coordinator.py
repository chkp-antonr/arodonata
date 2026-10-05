"""Coordinates cache freshness/refresh decisions ahead of reads."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from arodonata.core.cache_mode import CacheMode
from arodonata.core.cache_policy import CachePolicy, RefreshOutcome, RefreshScope, SystemClock
from arodonata.core.incremental_refresh import FallbackToFull, IncrementalRefresher
from arodonata.logger import lazy_logger

if TYPE_CHECKING:
    from arodonata.core.cache_policy import Clock

log = lazy_logger("arodonata.core.cache_refresh_coordinator")

#: Resolves (mgmt, domain) to the MDS member serving it (LoginCoordinator.mds_host).
MemberOf = Callable[[str, str], Awaitable[str]]


class CacheRefreshCoordinator:
    """Decides whether/how to refresh cache before a read, per CachePolicy."""

    def __init__(
        self,
        cache: Any,
        api: Any,
        object_service: Any,
        session_tracker: Any = None,
        default_mode: CacheMode = CacheMode.SMART,
        default_ttl: int = 300,
        clock: Clock | None = None,
        max_incremental_changes: int = 500,
        member_of: MemberOf | None = None,
        domain_concurrency: int = 1,
    ) -> None:
        """Create the coordinator.

        Args:
            cache: Cache repository.
            api: API facade used for change and head lookups.
            object_service: Object service that performs the reloads.
            session_tracker: Optional session tracker.
            default_mode: Cache mode used when a read names none.
            default_ttl: Freshness window in seconds for the smart modes.
            clock: Clock for freshness checks (tests inject one).
            max_incremental_changes: Largest change set applied incrementally before a full reload.
            member_of: Resolver `(mgmt, domain) -> MDS member`; `ensure` refreshes members in parallel and at most
                `domain_concurrency` domains of one member at once. Without it, domains group by management server
                name, so different servers refresh in parallel (previously they refreshed one after another) and
                the domains of one server share one `domain_concurrency` budget.
            domain_concurrency: Domain refreshes started at once per member per `ensure` call.
        """
        self._cache = cache
        self._api = api
        self._object_service = object_service
        self._session_tracker = session_tracker
        self.default_policy = CachePolicy(mode=default_mode, ttl=default_ttl)
        self._clock: Clock = clock or SystemClock()
        # (mgmt, domain) -> checked_at (from clock)
        self._checked_at: dict[tuple[str, str], Any] = {}
        # per-(mgmt, domain) locks to collapse concurrent refreshes in-process
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}
        self.max_incremental_changes = max_incremental_changes
        self._member_of = member_of
        # Domain refreshes started at once per member *per ensure call* (concurrent_limit - 1 from the client).
        # Overlapping ensure calls each get their own budget, so the member-keyed RateLimiter is the real bound
        # on the load a member sees.
        self._domain_concurrency = max(1, domain_concurrency)

    # ---- public API ------------------------------------------------------

    async def ensure(self, scope: RefreshScope, policy: CachePolicy) -> RefreshOutcome:
        """Ensure cache satisfies `policy` over `scope` before a read."""
        outcome = RefreshOutcome(mode_used=policy.mode)

        if policy.mode == CacheMode.CACHE:
            outcome.skipped_reason = "cache-mode"
            return outcome

        await self._ensure_pairs(await self._resolve_pairs(scope), policy, outcome)

        return outcome

    def invalidate(self, mgmt_name: str, domain_name: str) -> None:
        """Drop the TTL memo for a domain so the next check cannot be skipped."""
        self._checked_at.pop((mgmt_name, domain_name), None)

    # ---- fan-out ---------------------------------------------------------

    async def _ensure_pairs(self, pairs: list[tuple[str, str]], policy: CachePolicy, outcome: RefreshOutcome) -> None:
        """Ensure every pair: members in parallel, at most `domain_concurrency` domains of one member at once.

        Per-domain locks (`_ensure_one`) still collapse concurrent refreshes of one domain. Every domain runs
        to the end even when another raises; the first exception is re-raised once all have finished. The
        outcome lists keep scope order.
        """
        by_member: dict[str, list[tuple[str, str]]] = {}
        for mgmt, domain in pairs:
            by_member.setdefault(await self._member_key(mgmt, domain), []).append((mgmt, domain))
        results = await asyncio.gather(
            *(self._ensure_member(group, policy, outcome) for group in by_member.values()), return_exceptions=True
        )
        order = {pair: i for i, pair in enumerate(pairs)}
        outcome.refreshed_domains.sort(key=lambda pair: order.get(pair, len(order)))
        outcome.failed_domains.sort(key=lambda pair: order.get(pair, len(order)))
        _raise_first(results, [f"member {key}" for key in by_member])

    async def _ensure_member(self, pairs: list[tuple[str, str]], policy: CachePolicy, outcome: RefreshOutcome) -> None:
        slots = asyncio.Semaphore(self._domain_concurrency)

        async def one(mgmt: str, domain: str) -> None:
            async with slots:
                await self._ensure_one(mgmt, domain, policy, outcome)

        results = await asyncio.gather(*(one(m, d) for m, d in pairs), return_exceptions=True)
        _raise_first(results, [f"{m}/{d}" for m, d in pairs])

    async def _member_key(self, mgmt: str, domain: str) -> str:
        """The MDS member serving the domain; without a resolver, the management server stands in for it."""
        if self._member_of is None:
            return mgmt
        return await self._member_of(mgmt, domain)

    # ---- per-domain logic ------------------------------------------------

    async def _ensure_one(
        self,
        mgmt: str,
        domain: str,
        policy: CachePolicy,
        outcome: RefreshOutcome,
    ) -> None:
        key = (mgmt, domain)
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        async with lock:
            if policy.mode == CacheMode.FORCE:
                await self._full_reload(mgmt, domain, outcome)
                return

            # smart / smart-fast
            if self._ttl_fresh(mgmt, domain, policy.ttl):
                return  # within freshness window: serve cache

            if await self._is_empty(mgmt, domain):
                await self._full_reload(mgmt, domain, outcome)
                return

            self._mark_checked(mgmt, domain)

            if not await self._object_service._is_domain_stale(mgmt, domain):
                return  # up to date: serve cache

            if policy.mode == CacheMode.SMART_FAST:
                await self._incremental_reload(mgmt, domain, policy, outcome)
            else:
                await self._full_reload(mgmt, domain, outcome)

    async def _full_reload(self, mgmt: str, domain: str, outcome: RefreshOutcome) -> None:
        failed = False
        # The coordinator already knows its domains, and many reloads run at once: without this every one of them
        # would issue show-domains/show-mdss and rewrite every domain row of the server.
        async for event in self._object_service.refresh_objects(
            mgmt_names=[mgmt], domain_names=[domain], mode="force", refresh_domain_list=False
        ):
            if event.get("status") == "domain_failed":
                failed = True

        if failed:
            log().warning(f"Refresh of {mgmt}/{domain} failed; keeping stale cache unmarked")
            outcome.failed_domains.append((mgmt, domain))
            return

        outcome.refreshed_domains.append((mgmt, domain))
        self._mark_checked(mgmt, domain)

    def _make_refresher(self) -> IncrementalRefresher:
        # Built per-apply so runtime mutation of max_incremental_changes
        # (tests, operators) always takes effect.
        from arodonata.cache.object_service import api_object_to_cpobject  # lazy: avoid core->cache import cycle

        return IncrementalRefresher(
            api=self._api,
            cache=self._cache,
            fetch_full_object=self._object_service.fetch_full_object,
            to_cpobject=api_object_to_cpobject,
            # Read-only on purpose: refresh_last_published_session would advance
            # the baseline before the apply and empty the diff window.
            fetch_head=self._object_service.fetch_last_published_session,
            max_changes=self.max_incremental_changes,
        )

    async def _incremental_reload(self, mgmt: str, domain: str, policy: CachePolicy, outcome: RefreshOutcome) -> None:
        try:
            result = await self._make_refresher().apply(mgmt, domain)
        except FallbackToFull as exc:
            log().debug(f"smart-fast fallback for {mgmt}/{domain}: {exc}")
            outcome.fell_back = True
            await self._full_reload(mgmt, domain, outcome)
            return
        # Success: advance the baseline to the head read before the diff (a publish after that read stays after
        # the stamp) and record the refresh (only if something was actually applied).
        if result.head is not None:
            await self._object_service.store_last_published_session(result.head)
        if result.applied > 0:
            outcome.refreshed_domains.append((mgmt, domain))
        self._mark_checked(mgmt, domain)

    # ---- helpers ---------------------------------------------------------

    async def _resolve_pairs(self, scope: RefreshScope) -> list[tuple[str, str]]:
        """Resolve scope to concrete (mgmt, domain) pairs.

        When both mgmt_names and domain_names are provided (the common read-helper
        case), use their product. Otherwise fall back to cached domains for broad
        scope.
        """
        mgmt_names = scope.mgmt_names
        if scope.domain_names and mgmt_names:
            return [(m, d) for m in mgmt_names for d in scope.domain_names]

        # Fall back to cached domains for broad scope.
        domains = await self._cache.get_domains(mgmt_names=mgmt_names)

        # If no cached domains, get server list from API adapter
        # This handles the chicken-and-egg problem when domains table is empty
        if not domains:
            # Use provided mgmt_names or fall back to configured servers
            servers = mgmt_names if mgmt_names else self._api.get_mgmt_names()
            if servers:
                return [(s, "") for s in servers]

        pairs = [(d.mgmt_name, d.domain_name) for d in domains]
        if scope.domain_names:
            wanted = set(scope.domain_names)
            pairs = [(m, d) for (m, d) in pairs if d in wanted]
        return pairs

    async def _is_empty(self, mgmt: str, domain: str) -> bool:
        objs = await self._cache.get_objects(object_type=None, mgmt_names=[mgmt], domain_names=[domain], filters=None)
        return len(objs) == 0

    def _ttl_fresh(self, mgmt: str, domain: str, ttl: int | None) -> bool:
        if not ttl:
            return False
        checked = self._checked_at.get((mgmt, domain))
        if checked is None:
            return False
        age = (self._clock.now() - checked).total_seconds()
        return age < ttl

    def _mark_checked(self, mgmt: str, domain: str) -> None:
        self._checked_at[(mgmt, domain)] = self._clock.now()


def _raise_first(results: list[Any], labels: list[str]) -> None:
    """Re-raise the first exception `asyncio.gather(..., return_exceptions=True)` collected.

    Each further exception is logged with its label and type name (never its message) before the first is raised.
    """
    errors = [
        (label, result) for label, result in zip(labels, results, strict=True) if isinstance(result, BaseException)
    ]
    for label, error in errors[1:]:
        log().warning(f"Refresh of {label} also failed: {type(error).__name__}")
    if errors:
        raise errors[0][1]
