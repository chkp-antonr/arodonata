"""Coordinates cache freshness/refresh decisions ahead of reads."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from arodonata.core.cache_mode import CacheMode
from arodonata.core.cache_policy import CachePolicy, RefreshOutcome, RefreshScope, SystemClock
from arodonata.logger import lazy_logger

if TYPE_CHECKING:
    from arodonata.core.cache_policy import Clock

log = lazy_logger("arodonata.core.cache_refresh_coordinator")


class _FallbackToFull(Exception):
    """Signal that smart-fast must fall back to a full reload."""


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
    ) -> None:
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
        self.max_incremental_changes = 500

    # ---- public API ------------------------------------------------------

    async def ensure(self, scope: RefreshScope, policy: CachePolicy) -> RefreshOutcome:
        """Ensure cache satisfies `policy` over `scope` before a read."""
        outcome = RefreshOutcome(mode_used=policy.mode)

        if policy.mode == CacheMode.CACHE:
            outcome.skipped_reason = "cache-mode"
            return outcome

        for mgmt, domain in await self._resolve_pairs(scope):
            await self._ensure_one(mgmt, domain, policy, outcome)

        return outcome

    def invalidate(self, mgmt_name: str, domain_name: str) -> None:
        """Drop the TTL memo for a domain so the next check cannot be skipped."""
        self._checked_at.pop((mgmt_name, domain_name), None)

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
        async for event in self._object_service.refresh_objects(mgmt_names=[mgmt], domain_names=[domain], mode="force"):
            if event.get("status") == "domain_failed":
                failed = True

        if failed:
            log().warning(f"Refresh of {mgmt}/{domain} failed; keeping stale cache unmarked")
            return

        outcome.refreshed_domains.append((mgmt, domain))
        self._mark_checked(mgmt, domain)

    async def _incremental_reload(self, mgmt: str, domain: str, policy: CachePolicy, outcome: RefreshOutcome) -> None:
        try:
            applied = await self._apply_changes(mgmt, domain)
        except _FallbackToFull as exc:
            log().debug(f"smart-fast fallback for {mgmt}/{domain}: {exc}")
            outcome.fell_back = True
            await self._full_reload(mgmt, domain, outcome)
            return
        # Success: advance baseline + record (only if something was actually applied).
        await self._object_service.refresh_last_published_session(mgmt, domain)
        if applied > 0:
            outcome.refreshed_domains.append((mgmt, domain))
        self._mark_checked(mgmt, domain)

    async def _apply_changes(self, mgmt: str, domain: str) -> int:
        from datetime import UTC, datetime

        from arodonata.cache.models import CPObject
        from arodonata.core.change_processor import ChangeProcessor, ChangeType

        baseline = await self._cache.get_last_published_session(mgmt, domain)
        if baseline is None or not getattr(baseline, "published_time", None):
            raise _FallbackToFull("no baseline session")

        changes = await self._fetch_parsed_changes(mgmt, domain, baseline)
        processor = ChangeProcessor()

        if not changes:
            return 0  # nothing changed since baseline

        if len(changes) > self.max_incremental_changes:
            raise _FallbackToFull(f"too many changes ({len(changes)})")

        adds_updates = processor.get_adds_and_updates(changes)
        deletes = processor.filter_by_change_type(changes, ChangeType.DELETE)

        objects_to_upsert = []
        for change in adds_updates:
            raw = change.raw_data or {}
            objects_to_upsert.append(
                CPObject(
                    id=f"{mgmt}:{domain}:{change.uid}",
                    uid=change.uid,
                    name=change.name,
                    type=change.object_type,
                    mgmt_name=mgmt,
                    domain_name=domain,
                    ipv4_address=raw.get("ipv4-address", ""),
                    subnet4=raw.get("subnet4", ""),
                    subnet_mask=raw.get("subnet-mask", ""),
                    members=_extract_members_from_raw(raw),
                    update_time=datetime.now(UTC).replace(tzinfo=None),
                    raw_data=raw,
                )
            )

        applied = 0
        if objects_to_upsert:
            await self._cache.upsert_objects(objects_to_upsert)
            applied += len(objects_to_upsert)

        for change in deletes:
            await self._cache.delete_object(change.uid, mgmt, domain)
            applied += 1

        return applied

    async def _fetch_parsed_changes(self, mgmt: str, domain: str, baseline: Any) -> list:
        """Fetch and parse the show-changes diff since baseline.

        Raises _FallbackToFull on any condition that would make an
        incremental apply unsafe: API failure, truncated (paged) diff,
        unparseable payload, or entries the parser had to drop.
        """
        from arodonata.core.change_processor import ChangeProcessor

        try:
            api_domain = "" if domain in ("SMC User", "System Data") else domain
            response = await self._api.show_changes(
                mgmt_name=mgmt,
                domain=api_domain,
                from_date=baseline.published_time.isoformat(),
            )
        except Exception as exc:  # noqa: BLE001 - fall back on any API failure
            raise _FallbackToFull(f"show-changes failed: {exc}") from exc

        response = _normalize_changes_response(response)
        if _changes_truncated(response):
            raise _FallbackToFull("show-changes truncated (more sessions than one page)")

        try:
            changes = ChangeProcessor().parse_changes(response)
        except Exception as exc:  # noqa: BLE001
            raise _FallbackToFull(f"unparseable changes: {exc}") from exc

        # Detect changes the processor silently dropped (unknown change-type,
        # uid-less objects) -> fall back rather than advance the baseline
        # past a lost change.
        raw_count = _raw_change_count(response)
        if raw_count > len(changes):
            raise _FallbackToFull(f"unhandled change type(s): parsed {len(changes)} of {raw_count}")
        return changes

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


def _normalize_changes_response(response: Any) -> dict:
    """Coerce a show-changes result (ApiCallResult or dict) into a plain dict.

    Raises _FallbackToFull when the API reported failure — an unsuccessful
    diff must never advance the baseline.
    """
    if isinstance(response, dict):
        return response
    if response is None:
        raise _FallbackToFull("show-changes returned no response")
    if getattr(response, "success", None) is False:
        message = getattr(response, "message", "") or "unknown error"
        raise _FallbackToFull(f"show-changes unsuccessful: {message}")
    data = getattr(response, "data", None)
    if not isinstance(data, dict):
        raise _FallbackToFull("show-changes response has no data payload")
    return {"data": data}


def _iter_task_details(data: Any) -> list[dict]:
    """All task-detail dicts from a task-wrapped show-changes payload."""
    details: list[dict] = []
    if not isinstance(data, dict):
        return details
    for task in data.get("tasks") or []:
        if not isinstance(task, dict):
            continue
        details.extend(d for d in task.get("task-details") or [] if isinstance(d, dict))
    return details


def _changes_truncated(response: dict) -> bool:
    """True when CP returned fewer change sessions than exist (paged diff).

    A truncated diff cannot be applied safely — advancing the baseline would
    skip the sessions beyond the first page.
    """
    for detail in _iter_task_details(response.get("data")):
        total = detail.get("total")
        to = detail.get("to")
        if isinstance(total, int) and isinstance(to, int) and to < total:
            return True
    return False


def _operations_count(operations: dict) -> int:
    """Count object entries across a session's operations arrays."""
    count = 0
    for key in ("added-objects", "modified-objects", "deleted-objects"):
        value = operations.get(key)
        if isinstance(value, list):
            count += sum(1 for obj in value if isinstance(obj, dict))
    return count


def _raw_change_count(response: Any) -> int:
    """Count raw change entries in a show-changes response, defensively.

    Handles both the real task-wrapped shape (counting every object in each
    session's operations arrays) and the legacy flat shape. Used to detect
    when ChangeProcessor.parse_changes silently dropped entries (unknown
    change-type, uid-less objects), so the caller falls back instead of
    advancing the baseline past a lost change.
    """
    if not isinstance(response, dict):
        return 0
    data = response.get("data")
    if not isinstance(data, dict):
        return 0

    count = 0
    for detail in _iter_task_details(data):
        for entry in detail.get("changes") or []:
            if isinstance(entry, dict) and isinstance(entry.get("operations"), dict):
                count += _operations_count(entry["operations"])
            elif not isinstance(entry, dict):
                count += 1  # unparseable entry: must trip the guard

    flat = data.get("changes")
    if isinstance(flat, list):
        for entry in flat:
            if isinstance(entry, dict) and isinstance(entry.get("operations"), dict):
                count += _operations_count(entry["operations"])
            else:
                count += 1  # legacy entry, or unparseable: one unit each
    return count


def _extract_members_from_raw(raw_data: dict) -> str:
    """Extract member UIDs from raw API data.

    Args:
        raw_data: Raw API response data.

    Returns:
        Comma-separated member UIDs.
    """
    members = raw_data.get("members", {})
    if isinstance(members, dict):
        member_objs = members.get("objects", [])
        member_uids = [m.get("uid", "") for m in member_objs if isinstance(m, dict)]
        return ",".join(filter(None, member_uids))
    elif isinstance(members, list):
        member_uids = [m.get("uid", "") for m in members if isinstance(m, dict)]
        return ",".join(filter(None, member_uids))
    return ""
