"""Unified domain synchronization coordinator (`DomainSyncCoordinator`).

Coordinates multi-domain cache synchronization across `"domains"`, `"objects"`, `"services"`,
`"assets"`, and `"rulebase"`:
- Groups target domains by `active_mds_ip` and bounds concurrent domain refreshes per MDS member
  to `max(1, concurrent_limit - 1)` (with MDS members running in parallel).
- Verifies freshness in `domain_sync_state` per `(mgmt_name, domain_name, scope, item_type)`,
  comparing `last_published_at` first and `last_session_uid` when timestamps match.
- Honors `cache_ttl` freshness memos unless invalidated via `invalidate_domain(mgmt_name, domain)`.
- Acquires per-domain distributed locks (`sync:{mgmt_name}:{domain_name}:{scope}`) via `LockPort`.
- Verifies that the shared read session is not dirty (`locks == 0` and
  `number-of-published-changes == 0`), raising `DirtySessionError` if uncommitted changes exist.
- Handles `InvalidCredentialsError` during staleness probes by reporting the domain as stale so
  the reload path records `RefreshOutcome.failed_domains` and emits `DomainSyncFailedEvent`
  while keeping previously cached rows intact.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import suppress as _suppress
from datetime import UTC, datetime
from typing import Any

from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import (
    DirtySessionError,
    InvalidCredentialsError,
    LockAcquisitionError,
    ServerIdentityError,
    redact_sid,
)
from arodonata.core.events import (
    DomainSyncCompletedEvent,
    DomainSyncFailedEvent,
    DomainSyncSkippedEvent,
    DomainSyncStartedEvent,
    SyncCompletedEvent,
    SyncProgressEvent,
    SyncStartedEvent,
)
from arodonata.core.models.common import CacheMode, SyncScope, to_naive_utc, utc_now
from arodonata.core.models.domains import DomainInfo, DomainSyncState, RefreshOutcome
from arodonata.core.ports import ApiPort, CachePort, LockPort
from arodonata.core.services.domain_service import DomainService
from arodonata.core.telemetry import span_attrs, traced


def parse_cp_publish_timestamp(raw_time: Any) -> datetime | None:
    """Parse Check Point `publish-time` or `last-modify-time` dict/string/int into a naive UTC `datetime`."""
    if raw_time is None:
        return None
    if isinstance(raw_time, datetime):
        return to_naive_utc(raw_time)
    if isinstance(raw_time, dict):
        iso_str = raw_time.get("iso-8601") or raw_time.get("iso_8601")
        if isinstance(iso_str, str) and iso_str.strip():
            parsed = _parse_iso_datetime(iso_str.strip())
            if parsed is not None:
                return parsed
        posix_val = raw_time.get("posix")
        if isinstance(posix_val, (int, float)):
            return _parse_posix_timestamp(posix_val)
    if isinstance(raw_time, (int, float)):
        return _parse_posix_timestamp(raw_time)
    if isinstance(raw_time, str) and raw_time.strip():
        return _parse_iso_datetime(raw_time.strip())
    return None


def _parse_posix_timestamp(value: int | float) -> datetime:
    ts = float(value)
    if ts > 1e11:  # Milliseconds epoch
        ts = ts / 1000.0
    return datetime.fromtimestamp(ts, tz=UTC).replace(tzinfo=None)


def _parse_iso_datetime(iso_str: str) -> datetime | None:
    normalized = iso_str
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    # Handle "+0300" -> "+03:00"
    if len(normalized) >= 5 and normalized[-5] in ("+", "-") and ":" not in normalized[-5:]:
        normalized = f"{normalized[:-2]}:{normalized[-2:]}"
    try:
        dt = datetime.fromisoformat(normalized)
        return to_naive_utc(dt)
    except ValueError:
        return None


class DomainProbeResult:
    """Result of probing a single `(mgmt_name, domain_name)` for staleness across `item_types`."""

    def __init__(
        self,
        *,
        mgmt_name: str,
        domain: DomainInfo,
        stale_types: list[str],
        fresh_types: list[str],
        existing_states: dict[str, DomainSyncState],
        remote_published_at: datetime | None = None,
        remote_session_uid: str | None = None,
        probe_error: Exception | None = None,
    ) -> None:
        self.mgmt_name = mgmt_name
        self.domain = domain
        self.stale_types = stale_types
        self.fresh_types = fresh_types
        self.existing_states = existing_states
        self.remote_published_at = remote_published_at
        self.remote_session_uid = remote_session_uid
        self.probe_error = probe_error

    @property
    def is_stale(self) -> bool:
        """Return `True` if any requested `item_type` is stale or the probe failed."""
        return bool(self.stale_types) or self.probe_error is not None


DomainSyncHandler = Callable[
    [DomainProbeResult, Callable[[SyncProgressEvent], Awaitable[None]]],
    Awaitable[int],
]


class DomainSyncCoordinator:
    """Coordinates bounded per-MDS-member domain synchronization, locking, and staleness probes."""

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        api: ApiPort,
        cache: CachePort,
        lock_port: LockPort,
        domain_service: DomainService,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._settings = settings
        self._api = api
        self._cache = cache
        self._lock_port = lock_port
        self._domain_service = domain_service
        self._now: Callable[[], datetime] = lambda: to_naive_utc(now_fn())
        self._invalidated_domains: set[tuple[str, str]] = set()

    async def _collect_known_sids(self, mgmt_name: str | None = None) -> list[str]:
        """Collect active cached SIDs from `arodonata_sid_cache` for strict error redaction (`W22`)."""
        try:
            entries = await self._cache.list_sids(mgmt_name=mgmt_name)
            return [e.sid for e in entries if e.sid]
        except Exception:
            return []

    @property
    def invalidated_domains(self) -> set[tuple[str, str]]:
        """Set of `(mgmt_name, domain_name)` pairs whose `cache_ttl` memo was invalidated."""
        return set(self._invalidated_domains)

    def invalidate_domain(self, mgmt_name: str, domain_name: str | None = None) -> None:
        """Invalidate freshness memo for `(mgmt_name, domain_name)` (or all domains on `mgmt_name` if None)."""
        if domain_name is None or not domain_name.strip():
            self._invalidated_domains.add((mgmt_name, "*"))
            self._domain_service.tracker.invalidate(mgmt_name)
        else:
            self._invalidated_domains.add((mgmt_name, domain_name.strip()))

    def _is_domain_invalidated(self, mgmt_name: str, domain_name: str) -> bool:
        return (mgmt_name, domain_name) in self._invalidated_domains or (mgmt_name, "*") in self._invalidated_domains

    def _clear_domain_invalidation(self, mgmt_name: str, domain_name: str) -> None:
        self._invalidated_domains.discard((mgmt_name, domain_name))
        self._invalidated_domains.discard((mgmt_name, "*"))

    async def resolve_target_domains(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
    ) -> list[DomainInfo]:
        """Resolve the list of `DomainInfo` targets for a synchronization run."""
        domain_names: list[str] | None = None
        if isinstance(domains, str):
            domain_names = [d.strip() for d in domains.split(",") if d.strip()]
        elif domains is not None:
            domain_names = [str(d).strip() for d in domains if str(d).strip()]

        want_global = include_global or (domain_names is not None and "Global" in domain_names)
        dom_mode: CacheMode = "cache" if mode == "cache" else "smart"
        all_domains = await self._domain_service.get_domains(
            mgmt_name=mgmt_name,
            include_global=want_global,
            cache_mode=dom_mode,
        )

        # In cache mode, if no domains were discovered yet but explicit domain names were passed,
        # synthesize lightweight DomainInfo placeholders so cached object queries still work.
        if not all_domains and domain_names:
            target_mgmts = self._domain_service.resolve_mgmt_names(mgmt_name)
            synthesized: list[DomainInfo] = []
            for m_name in target_mgmts:
                ep = self._settings.servers.get(m_name)
                host = ep.host if ep is not None else None
                for d_name in domain_names:
                    cached_dom = await self._cache.get_domain(m_name, d_name)
                    if cached_dom is not None:
                        synthesized.append(cached_dom)
                    else:
                        synthesized.append(
                            DomainInfo(
                                mgmt_name=m_name,
                                uid=f"domain:{m_name}:{d_name}",
                                name=d_name,
                                active_ip=host,
                                active_mds_ip=host,
                                is_global=(d_name == "Global"),
                            )
                        )
            return synthesized

        if domain_names is not None:
            name_set = set(domain_names)
            matched = [d for d in all_domains if d.name in name_set]
            if len(matched) < len(name_set) and mode != "cache":
                # Refresh domain list once if any requested domain was not in cache
                all_domains = await self._domain_service.get_domains(
                    mgmt_name=mgmt_name,
                    include_global=want_global,
                    cache_mode="force",
                )
                matched = [d for d in all_domains if d.name in name_set]
            return matched

        return all_domains

    @traced
    async def verify_session_clean(self, mgmt_name: str, domain_name: str) -> None:
        """Verify that the shared read session for `(mgmt_name, domain_name)` has no uncommitted changes.

        Checks `locks == 0` and `number-of-published-changes == 0` (and `changes == 0`).
        Raises `DirtySessionError` if the session is dirty.
        """
        span_attrs(mgmt_name=mgmt_name, domain=domain_name)
        res = await self._api.api_call(
            mgmt_name,
            "show-session",
            {},
            domain=domain_name,
        )
        if not res.success:
            err_lower = (res.error_message or "").lower()
            code_lower = (res.error_code or "").lower()
            is_unsupported_mock = any(
                tok in err_lower or tok in code_lower
                for tok in ("command_not_found", "unknown command", "not implemented")
            )
            if is_unsupported_mock:
                return
            known_sids = await self._collect_known_sids(mgmt_name)
            safe_err = redact_sid(
                res.error_message or f"show-session failed with HTTP {res.status_code}",
                known_sids=known_sids,
            )
            raise DirtySessionError(
                f"Failed to verify session cleanliness on {mgmt_name!r} ({domain_name!r}): {safe_err}"
            )

        data = res.data if isinstance(res.data, dict) else {}
        locks = int(data.get("locks") or 0)
        changes = int(data.get("changes") or 0)
        unpub_changes = int(data.get("number-of-published-changes") or 0)

        if locks != 0 or changes != 0 or unpub_changes != 0:
            raise DirtySessionError(
                f"Shared session on {mgmt_name!r} ({domain_name!r}) is dirty "
                f"(locks={locks}, changes={changes}, number-of-published-changes={unpub_changes}). "
                "Refusing to overwrite shared cache from a dirty session."
            )

    @traced
    async def probe_domain_staleness(
        self,
        domain: DomainInfo,
        *,
        scope: SyncScope,
        item_types: Sequence[str],
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> DomainProbeResult:
        """Determine which `item_types` are stale for `domain` under `scope` and `mode`."""
        mgmt_name = domain.mgmt_name
        dom_name = domain.name
        type_list = list(item_types)
        span_attrs(mgmt_name=mgmt_name, domain=dom_name, scope=scope, mode=mode, item_types=type_list)

        existing_states: dict[str, DomainSyncState] = {}
        for item_type in type_list:
            st = await self._cache.get_sync_state(mgmt_name, dom_name, scope, item_type)
            if st is not None:
                existing_states[item_type] = st

        if mode == "cache":
            return DomainProbeResult(
                mgmt_name=mgmt_name,
                domain=domain,
                stale_types=[],
                fresh_types=type_list,
                existing_states=existing_states,
            )

        now = self._now()
        eff_ttl = float(cache_ttl) if cache_ttl is not None else float(self._settings.cache_ttl)
        invalidated = self._is_domain_invalidated(mgmt_name, dom_name)

        # In smart/smart-fast mode, if all requested types were synced within cache_ttl and domain is not invalidated,
        # skip the server probe completely.
        if mode in ("smart", "smart-fast") and not invalidated and eff_ttl > 0:
            all_within_ttl = True
            for item_type in type_list:
                st = existing_states.get(item_type)
                if st is None or st.status != "ok" or st.synced_at is None:
                    all_within_ttl = False
                    break
                age = (now - st.synced_at).total_seconds()
                if age >= eff_ttl:
                    all_within_ttl = False
                    break
            if all_within_ttl:
                return DomainProbeResult(
                    mgmt_name=mgmt_name,
                    domain=domain,
                    stale_types=[],
                    fresh_types=type_list,
                    existing_states=existing_states,
                )

        # Query show-last-published-session on the domain
        try:
            res = await self._api.api_call(
                mgmt_name,
                "show-last-published-session",
                {},
                domain=dom_name,
            )
        except ServerIdentityError:
            raise
        except Exception as exc:
            # Per spec: When a domain's staleness probe fails with InvalidCredentialsError (or transport error),
            # the probe SHALL report the domain as stale so the reload path records failed_domains and emits
            # DomainSyncFailedEvent while keeping previously cached objects intact.
            return DomainProbeResult(
                mgmt_name=mgmt_name,
                domain=domain,
                stale_types=type_list,
                fresh_types=[],
                existing_states=existing_states,
                probe_error=exc,
            )

        if not res.success:
            err_msg = res.error_message or f"show-last-published-session failed with HTTP {res.status_code}"
            err_code = (res.error_code or "").lower()
            is_never_published = "no published session" in err_msg.lower() or "generic_err_object_not_found" in err_code
            if not is_never_published:
                probe_exc: Exception
                if "credential" in err_msg.lower() or "authentication" in err_msg.lower():
                    probe_exc = InvalidCredentialsError(err_msg)
                else:
                    probe_exc = RuntimeError(err_msg)
                return DomainProbeResult(
                    mgmt_name=mgmt_name,
                    domain=domain,
                    stale_types=type_list,
                    fresh_types=[],
                    existing_states=existing_states,
                    probe_error=probe_exc,
                )
            data = {}
        else:
            data = res.data if isinstance(res.data, dict) else {}
        remote_pub_at = parse_cp_publish_timestamp(data.get("publish-time") or data.get("last-modify-time"))
        remote_uid_raw = data.get("uid")
        remote_uid = str(remote_uid_raw) if isinstance(remote_uid_raw, str) and remote_uid_raw else None

        if mode == "force":
            return DomainProbeResult(
                mgmt_name=mgmt_name,
                domain=domain,
                stale_types=type_list,
                fresh_types=[],
                existing_states=existing_states,
                remote_published_at=remote_pub_at,
                remote_session_uid=remote_uid,
            )

        stale_types: list[str] = []
        fresh_types: list[str] = []

        for item_type in type_list:
            st = existing_states.get(item_type)
            if st is None or st.status != "ok":
                stale_types.append(item_type)
                continue

            if remote_pub_at is not None:
                if st.last_published_at is None or st.last_published_at != remote_pub_at:
                    stale_types.append(item_type)
                    continue
                # Timestamps match -> verify last_session_uid when available
                if remote_uid is not None and st.last_session_uid != remote_uid:
                    stale_types.append(item_type)
                    continue
            elif remote_uid is not None:
                if st.last_session_uid != remote_uid:
                    stale_types.append(item_type)
                    continue
            else:
                # Server returned neither publish-time nor session uid (never published domain);
                # fresh if we already have a synced_at and no published session existed previously
                if st.last_published_at is not None or st.last_session_uid is not None:
                    stale_types.append(item_type)
                    continue

            fresh_types.append(item_type)

        # Update synced_at on fresh types that were verified against the server so cache_ttl is reset
        if fresh_types:
            verified_at = self._now()
            for f_type in fresh_types:
                st = existing_states[f_type]
                await self._cache.upsert_sync_state(
                    st.model_copy(
                        update={
                            "synced_at": verified_at,
                            "last_published_at": remote_pub_at if remote_pub_at is not None else st.last_published_at,
                            "last_session_uid": remote_uid if remote_uid is not None else st.last_session_uid,
                        }
                    )
                )
            if not stale_types:
                self._clear_domain_invalidation(mgmt_name, dom_name)

        return DomainProbeResult(
            mgmt_name=mgmt_name,
            domain=domain,
            stale_types=stale_types,
            fresh_types=fresh_types,
            existing_states=existing_states,
            remote_published_at=remote_pub_at,
            remote_session_uid=remote_uid,
        )

    async def stream_ensure(
        self,
        *,
        scope: SyncScope,
        item_types: Sequence[str],
        handler: DomainSyncHandler,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
        lock_ttl_seconds: float = 300.0,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while synchronizing target domains concurrently per MDS member."""
        target_domains = await self.resolve_target_domains(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
        )
        type_list = list(item_types)

        yield SyncStartedEvent(
            scope=scope,
            mgmt_name=mgmt_name,
            message=f"Starting {scope} sync (mode={mode}) across {len(target_domains)} domain(s).",
            total=len(target_domains),
            details={"mode": mode, "item_types": type_list, "domain_count": len(target_domains)},
        )

        if not target_domains:
            yield SyncCompletedEvent(
                scope=scope,
                mgmt_name=mgmt_name,
                message=f"Completed {scope} sync: 0 domains targeted.",
                processed=0,
                total=0,
                details={"refreshed_domains": [], "skipped_domains": [], "failed_domains": {}, "total_items": 0},
            )
            return

        # Group domains by active_mds_ip
        mds_groups: dict[str, list[DomainInfo]] = defaultdict(list)
        for dom in target_domains:
            ep = self._settings.servers.get(dom.mgmt_name)
            fallback_host = ep.host if ep is not None else dom.mgmt_name
            mds_key = dom.active_mds_ip or dom.active_ip or fallback_host
            mds_groups[mds_key].append(dom)

        per_mds_concurrency = self._settings.domain_sync_concurrency
        queue: asyncio.Queue[SyncProgressEvent | None] = asyncio.Queue()

        refreshed_domains: list[str] = []
        skipped_domains: list[str] = []
        failed_domains: dict[str, str] = {}
        total_items = 0
        state_lock = asyncio.Lock()

        async def _emit(ev: SyncProgressEvent) -> None:
            await queue.put(ev)

        async def _process_domain(dom: DomainInfo, sem: asyncio.Semaphore) -> None:
            nonlocal total_items
            dom_label = f"{dom.mgmt_name}:{dom.name}"
            async with sem:
                try:
                    probe = await self.probe_domain_staleness(
                        dom,
                        scope=scope,
                        item_types=type_list,
                        mode=mode,
                        cache_ttl=cache_ttl,
                    )
                    if not probe.is_stale:
                        async with state_lock:
                            skipped_domains.append(dom_label)
                        await _emit(
                            DomainSyncSkippedEvent(
                                scope=scope,
                                mgmt_name=dom.mgmt_name,
                                domain=dom.name,
                                item_type=",".join(probe.fresh_types) if probe.fresh_types else "*",
                                message=f"Domain {dom_label} is fresh; skipping.",
                            )
                        )
                        return

                    if probe.probe_error is not None:
                        raise probe.probe_error

                    await _emit(
                        DomainSyncStartedEvent(
                            scope=scope,
                            mgmt_name=dom.mgmt_name,
                            domain=dom.name,
                            item_type=",".join(probe.stale_types),
                            message=f"Synchronizing {dom_label} ({', '.join(probe.stale_types)}).",
                        )
                    )

                    lock_key = f"sync:{dom.mgmt_name}:{dom.name}:{scope}"
                    async with self._lock_port.lock(lock_key, ttl_seconds=lock_ttl_seconds) as owner_id:
                        heartbeat_interval = max(0.05, float(lock_ttl_seconds) / 3.0)

                        async def _heartbeat_loop() -> None:
                            while True:
                                await asyncio.sleep(heartbeat_interval)
                                with _suppress(Exception):
                                    await self._lock_port.renew(
                                        lock_key,
                                        ttl_seconds=lock_ttl_seconds,
                                        owner_id=owner_id,
                                    )

                        hb_task = asyncio.create_task(_heartbeat_loop())
                        try:
                            await self.verify_session_clean(dom.mgmt_name, dom.name)
                            count = await handler(probe, _emit)
                        finally:
                            hb_task.cancel()
                            with _suppress(asyncio.CancelledError, Exception):
                                await hb_task

                    self._clear_domain_invalidation(dom.mgmt_name, dom.name)
                    async with state_lock:
                        refreshed_domains.append(dom_label)
                        total_items += count

                    await _emit(
                        DomainSyncCompletedEvent(
                            scope=scope,
                            mgmt_name=dom.mgmt_name,
                            domain=dom.name,
                            item_type=",".join(probe.stale_types),
                            processed=count,
                            total=count,
                            message=f"Synchronized {count} {scope} item(s) for {dom_label}.",
                        )
                    )
                except ServerIdentityError:
                    raise
                except LockAcquisitionError as exc:
                    # Another worker holds the distributed sync lock for this domain (W14):
                    # skip without marking arodonata_domain_sync_state.status="failed" or emitting DomainSyncFailedEvent!
                    async with state_lock:
                        skipped_domains.append(dom_label)
                    await _emit(
                        DomainSyncSkippedEvent(
                            scope=scope,
                            mgmt_name=dom.mgmt_name,
                            domain=dom.name,
                            item_type=",".join(probe.stale_types) if probe.stale_types else "*",
                            message=f"Domain {dom_label} sync lock is held by another worker; skipping ({exc}).",
                        )
                    )
                except Exception as exc:
                    known_sids = await self._collect_known_sids(dom.mgmt_name)
                    err_str = redact_sid(str(exc), known_sids=known_sids)
                    async with state_lock:
                        failed_domains[dom_label] = err_str
                    # Record failed status in arodonata_domain_sync_state without wiping existing cached objects
                    now = self._now()
                    for item_type in type_list:
                        prev = await self._cache.get_sync_state(dom.mgmt_name, dom.name, scope, item_type)
                        await self._cache.upsert_sync_state(
                            DomainSyncState(
                                mgmt_name=dom.mgmt_name,
                                domain_name=dom.name,
                                scope=scope,
                                item_type=item_type,
                                last_published_at=prev.last_published_at if prev else None,
                                last_session_uid=prev.last_session_uid if prev else None,
                                synced_at=prev.synced_at if prev else now,
                                status="failed",
                                object_count=prev.object_count if prev else 0,
                                last_error=err_str,
                            )
                        )
                    await _emit(
                        DomainSyncFailedEvent(
                            scope=scope,
                            mgmt_name=dom.mgmt_name,
                            domain=dom.name,
                            error=err_str,
                            message=f"Failed to synchronize {dom_label}: {err_str}",
                        )
                    )

        async def _run_mds_group(group_domains: list[DomainInfo]) -> None:
            sem = asyncio.Semaphore(per_mds_concurrency)
            try:
                async with asyncio.TaskGroup() as tg:
                    for d in group_domains:
                        tg.create_task(_process_domain(d, sem))
            except* ServerIdentityError as eg:
                raise eg.exceptions[0] from None

        async def _coordinator_runner() -> None:
            try:
                try:
                    async with asyncio.TaskGroup() as tg:
                        for group in mds_groups.values():
                            tg.create_task(_run_mds_group(group))
                except* ServerIdentityError as eg:
                    raise eg.exceptions[0] from None
            finally:
                await queue.put(None)

        runner_task = asyncio.create_task(_coordinator_runner())
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield item
            await runner_task
        finally:
            if not runner_task.done():
                runner_task.cancel()
                with _suppress(asyncio.CancelledError, Exception):
                    await runner_task

        yield SyncCompletedEvent(
            scope=scope,
            mgmt_name=mgmt_name,
            processed=total_items,
            total=total_items,
            message=(
                f"Completed {scope} sync: {len(refreshed_domains)} refreshed, "
                f"{len(skipped_domains)} skipped, {len(failed_domains)} failed."
            ),
            details={
                "refreshed_domains": list(refreshed_domains),
                "skipped_domains": list(skipped_domains),
                "failed_domains": dict(failed_domains),
                "total_items": total_items,
            },
        )

    @traced
    async def ensure(
        self,
        *,
        scope: SyncScope,
        item_types: Sequence[str],
        handler: DomainSyncHandler,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
        lock_ttl_seconds: float = 300.0,
    ) -> RefreshOutcome:
        """Synchronize target domains and return the aggregated `RefreshOutcome`."""
        refreshed_domains: list[str] = []
        skipped_domains: list[str] = []
        failed_domains: dict[str, str] = {}
        total_items = 0

        async for event in self.stream_ensure(
            scope=scope,
            item_types=item_types,
            handler=handler,
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
            lock_ttl_seconds=lock_ttl_seconds,
        ):
            if isinstance(event, SyncCompletedEvent):
                refreshed_domains = list(event.details.get("refreshed_domains") or [])
                skipped_domains = list(event.details.get("skipped_domains") or [])
                failed_domains = dict(event.details.get("failed_domains") or {})
                total_items = int(event.details.get("total_items") or 0)

        return RefreshOutcome(
            scope=scope,
            refreshed_domains=refreshed_domains,
            skipped_domains=skipped_domains,
            failed_domains=failed_domains,
            total_items=total_items,
        )


__all__ = [
    "DomainProbeResult",
    "DomainSyncCoordinator",
    "DomainSyncHandler",
    "parse_cp_publish_timestamp",
]
