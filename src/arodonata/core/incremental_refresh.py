"""Shared show-changes incremental refresh engine.

One implementation used by both consumers:
- CacheRefreshCoordinator._incremental_reload (smart-fast read path)
- ObjectService.refresh_objects(mode="incremental") (bulk refresh path)

Semantics: the show-changes diff is only a CHANGE LIST. Every added or
modified in-scope object is re-fetched in full via show-object and converted
by the canonical full-reload converter — diff payload bodies are never
written to the cache. Any condition that would make the apply unsafe raises
FallbackToFull; the caller performs an atomic full-domain reload instead.
The engine never advances the LastPublishedSession baseline — callers do,
and only on success.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from arodonata.core.change_processor import ChangeProcessor, ChangeType, ObjectChange
from arodonata.logger import lazy_logger

if TYPE_CHECKING:
    from arodonata.cache.models import CPObject

log = lazy_logger("arodonata.core.incremental_refresh")

# Must match ObjectService.OBJECT_TYPES — the object kinds the cache holds.
DEFAULT_IN_SCOPE_TYPES: frozenset[str] = frozenset({"host", "network", "address-range", "group"})
DEFAULT_MAX_CHANGES = 500


class FallbackToFull(Exception):
    """Incremental apply would be unsafe; the caller must do a full reload."""


class IncrementalRefresher:
    """Applies a show-changes diff for one domain with re-fetch-in-full semantics."""

    def __init__(
        self,
        *,
        api: Any,
        cache: Any,
        fetch_full_object: Callable[[str, str, str], Awaitable[dict[str, Any] | None]],
        to_cpobject: Callable[[dict[str, Any], str, str], CPObject | None],
        fetch_head: Callable[[str, str], Awaitable[Any]] | None = None,
        in_scope_types: frozenset[str] = DEFAULT_IN_SCOPE_TYPES,
        max_changes: int = DEFAULT_MAX_CHANGES,
    ) -> None:
        self._api = api
        self._cache = cache
        self._fetch_full_object = fetch_full_object
        self._to_cpobject = to_cpobject
        self._fetch_head = fetch_head
        self._in_scope_types = in_scope_types
        self._max_changes = max_changes

    async def apply(self, mgmt: str, domain: str) -> int:
        """Apply all in-scope changes since the stored baseline.

        Returns the number of rows written (upserts + deletes); 0 means the
        publish touched nothing the object cache holds. Raises FallbackToFull
        whenever an incremental apply would be unsafe. Never advances the
        baseline stamp — that is the caller's responsibility.
        """
        baseline = await self._cache.get_last_published_session(mgmt, domain)
        if baseline is None or not getattr(baseline, "published_time", None):
            raise FallbackToFull("no baseline session")

        await self._require_forward_history(mgmt, domain, baseline)

        response = await self._fetch_changes(mgmt, domain, baseline)
        changes = self._parse_in_scope(response)
        if not changes:
            return 0
        if len(changes) > self._max_changes:
            raise FallbackToFull(f"too many changes ({len(changes)})")

        refetch_uids, deleted_uids = self._classify_changes(changes)
        to_upsert = await self._refetch_and_convert(mgmt, domain, refetch_uids, deleted_uids)
        return await self._write_results(mgmt, domain, to_upsert, deleted_uids)

    @staticmethod
    def _classify_changes(changes: list[ObjectChange]) -> tuple[list[str], set[str]]:
        """Split changes into uids to re-fetch and uids to delete.

        A uid both deleted and (re)added within the diff window is resolved
        by the live re-fetch: found -> upsert, clean not-found -> delete.
        """
        refetch_uids: list[str] = []
        seen: set[str] = set()
        deleted_uids: set[str] = set()
        for change in changes:
            if change.change_type in (ChangeType.ADD, ChangeType.UPDATE):
                if change.uid not in seen:
                    seen.add(change.uid)
                    refetch_uids.append(change.uid)
            else:
                deleted_uids.add(change.uid)
        deleted_uids -= seen
        return refetch_uids, deleted_uids

    async def _refetch_and_convert(
        self, mgmt: str, domain: str, refetch_uids: list[str], deleted_uids: set[str]
    ) -> list[CPObject]:
        """Re-fetch each changed uid in full and convert it; not-found uids become deletes."""
        to_upsert: list[CPObject] = []
        for uid in refetch_uids:
            try:
                raw = await self._fetch_full_object(mgmt, domain, uid)
            except Exception as exc:  # noqa: BLE001 - any fetch failure is unsafe
                raise FallbackToFull(f"show-object re-fetch of {uid} failed: {exc}") from exc
            if raw is None:
                deleted_uids.add(uid)
                continue
            if raw.get("type") not in self._in_scope_types:
                raise FallbackToFull(f"re-fetched {uid} has out-of-scope type {raw.get('type')!r}")
            obj = self._to_cpobject(raw, mgmt, domain)
            if obj is None:
                raise FallbackToFull(f"conversion failed for {uid}")
            to_upsert.append(obj)
        return to_upsert

    async def _write_results(self, mgmt: str, domain: str, to_upsert: list[CPObject], deleted_uids: set[str]) -> int:
        applied = 0
        if to_upsert:
            await self._cache.upsert_objects(to_upsert)
            applied += len(to_upsert)
        for uid in sorted(deleted_uids):
            await self._cache.delete_object(uid, mgmt, domain)
            applied += 1
        log().debug(f"Incremental apply for {mgmt}/{domain}: {len(to_upsert)} upsert(s), {len(deleted_uids)} delete(s)")
        return applied

    async def _require_forward_history(self, mgmt: str, domain: str, baseline: Any) -> None:
        """Raise FallbackToFull unless the domain's head is later than the baseline.

        A diff is a forward change list, so it only describes reality when the
        domain's head is a later revision than the one the cache was built from.
        A `revert-to-revision` moves the head BACKWARDS and discards the sessions
        in between: the objects it restores were deleted in sessions that no
        longer exist, and the ones it removes were added in sessions that no
        longer exist. Nothing in a change list describes that, so applying one
        across a revert leaves removed objects sitting in the cache and drops
        restored ones — they "disappear" from the caller's point of view.

        Until this check existed, the full reload after a revert happened only
        because Check Point refused the `show-changes` call and `_fetch_changes`
        turned every failure into FallbackToFull — the right outcome by luck
        rather than by design, and dependent on a server-side behaviour nothing
        here controls.

        Only a head that is STRICTLY earlier counts as reverted. Requiring it to
        be strictly *later* was tried first and was too strict to live with:
        Check Point publish-times have MINUTE resolution, so a publish read back
        in the same minute has a head timestamp equal to the baseline's, and
        every prompt publish-then-read fell back to a full reload — which is what
        `test_bulk_incremental_mode_applies_publish_without_full_reload` exists to
        catch, and did.

        The residual gap is narrow and worth naming: reverting to a revision
        published in the same minute as the cache baseline is invisible here, and
        falls back to the `show-changes` failure path that this check exists to
        stop relying on. Closing it properly means diffing by `from-session`
        rather than `from-date`, so the server itself rejects a baseline that is
        no longer in history.
        """
        if self._fetch_head is None:
            return  # caller opted out; the show-changes failure path still applies

        head = await self._fetch_head(mgmt, domain)
        if head is None or not getattr(head, "published_time", None):
            raise FallbackToFull("current head unknown")

        if head.published_time < baseline.published_time:
            raise FallbackToFull(
                f"history moved backwards (head {head.published_time}, baseline {baseline.published_time}) - reverted"
            )

    # ---- diff fetching / parsing ------------------------------------------

    async def _fetch_changes(self, mgmt: str, domain: str, baseline: Any) -> dict:
        try:
            api_domain = "" if domain in ("SMC User", "System Data") else domain
            response = await self._api.show_changes(
                mgmt_name=mgmt,
                domain=api_domain,
                from_date=baseline.published_time.isoformat(),
            )
        except Exception as exc:  # noqa: BLE001 - fall back on any API failure
            raise FallbackToFull(f"show-changes failed: {exc}") from exc

        response = _normalize_changes_response(response)
        if _changes_truncated(response):
            raise FallbackToFull("show-changes truncated (more sessions than one page)")
        return response

    def _parse_in_scope(self, response: dict) -> list[ObjectChange]:
        try:
            parsed = ChangeProcessor().parse_changes(response)
        except Exception as exc:  # noqa: BLE001
            raise FallbackToFull(f"unparseable changes: {exc}") from exc

        in_scope = [c for c in parsed if c.object_type in self._in_scope_types]
        # Detect in-scope changes the processor silently dropped (unknown
        # change-type, uid-less objects) -> fall back rather than advance the
        # baseline past a lost change. Out-of-scope drops are irrelevant.
        raw_in_scope = _raw_in_scope_change_count(response, self._in_scope_types)
        if raw_in_scope > len(in_scope):
            raise FallbackToFull(f"unhandled change type(s): parsed {len(in_scope)} of {raw_in_scope} in-scope")
        return in_scope


# ---- moved verbatim from cache_refresh_coordinator.py ----------------------
# (_normalize_changes_response, _iter_task_details, _changes_truncated —
#  identical bodies, with _FallbackToFull renamed to FallbackToFull)


def _normalize_changes_response(response: Any) -> dict:
    """Coerce a show-changes result (ApiCallResult or dict) into a plain dict.

    Raises FallbackToFull when the API reported failure — an unsuccessful
    diff must never advance the baseline.
    """
    if isinstance(response, dict):
        return response
    if response is None:
        raise FallbackToFull("show-changes returned no response")
    if getattr(response, "success", None) is False:
        message = getattr(response, "message", "") or "unknown error"
        raise FallbackToFull(f"show-changes unsuccessful: {message}")
    data = getattr(response, "data", None)
    if not isinstance(data, dict):
        raise FallbackToFull("show-changes response has no data payload")
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


# ---- scope-aware raw counting (replaces _raw_change_count/_operations_count)


def _entry_in_scope(obj: Any, in_scope: frozenset[str]) -> bool:
    """Conservative scope test for a raw diff entry.

    Non-dict or type-less entries count as in-scope so they trip the
    dropped-entry guard rather than being silently skipped.
    """
    if not isinstance(obj, dict):
        return True
    obj_type = obj.get("type")
    if not obj_type:
        return True
    return obj_type in in_scope


def _operations_count(operations: dict, in_scope: frozenset[str]) -> int:
    """Count in-scope object entries across a session's operations arrays."""
    count = 0
    for key in ("added-objects", "modified-objects", "deleted-objects"):
        value = operations.get(key)
        if isinstance(value, list):
            count += sum(1 for obj in value if _entry_in_scope(obj, in_scope))
    return count


def _task_details_in_scope_count(data: dict, in_scope: frozenset[str]) -> int:
    """Count in-scope change entries across all task-wrapped sessions."""
    count = 0
    for detail in _iter_task_details(data):
        for entry in detail.get("changes") or []:
            if isinstance(entry, dict) and isinstance(entry.get("operations"), dict):
                count += _operations_count(entry["operations"], in_scope)
            elif not isinstance(entry, dict):
                count += 1  # unparseable entry: must trip the guard
    return count


def _flat_in_scope_count(data: dict, in_scope: frozenset[str]) -> int:
    """Count in-scope change entries in the legacy flat `data.changes` shape."""
    flat = data.get("changes")
    if not isinstance(flat, list):
        return 0
    count = 0
    for entry in flat:
        if isinstance(entry, dict) and isinstance(entry.get("operations"), dict):
            count += _operations_count(entry["operations"], in_scope)
        elif _entry_in_scope(entry, in_scope):
            count += 1  # legacy flat entry (or unparseable): one unit
    return count


def _raw_in_scope_change_count(response: Any, in_scope: frozenset[str]) -> int:
    """Count raw in-scope change entries in a show-changes response.

    Same traversal as the coordinator's old _raw_change_count, restricted to
    entries whose type is in scope (indeterminable types count as in-scope,
    conservatively).
    """
    if not isinstance(response, dict):
        return 0
    data = response.get("data")
    if not isinstance(data, dict):
        return 0
    return _task_details_in_scope_count(data, in_scope) + _flat_in_scope_count(data, in_scope)


__all__ = [
    "DEFAULT_IN_SCOPE_TYPES",
    "DEFAULT_MAX_CHANGES",
    "FallbackToFull",
    "IncrementalRefresher",
]
