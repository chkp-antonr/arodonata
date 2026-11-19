"""Single-flight background object and service cache warm-up coordinator."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from contextlib import suppress
from datetime import datetime
from typing import Any

import arlogi

from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import redact_sid
from arodonata.core.models.common import CacheMode, normalize_object_type
from arodonata.core.models.domains import RefreshOutcome, WarmupStatusEntry

# Canonical client logger shared across all `arodonata.client.*` submodules so monkeypatching
# `arodonata.client.logger` intercepts warnings and logs from warmup and facade operations.
logger = arlogi.get_logger("arodonata.client")

_MAX_WARMUP_STATUS_ENTRIES = 128
_WarmupFlightKey = tuple[str, tuple[str, ...], tuple[str, ...], bool, bool, bool]


class CacheWarmupCoordinator:
    """Manages single-flight deduplicated background object/service cache warm-up tasks."""

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        now_fn: Callable[[], datetime],
        ensure_initialized: Callable[[], Awaitable[None]],
    ) -> None:
        self._settings = settings
        self._now = now_fn
        self._ensure_initialized = ensure_initialized
        self._tasks: set[asyncio.Task[Any]] = set()
        self._flights: dict[_WarmupFlightKey, asyncio.Task[RefreshOutcome]] = {}
        self._status: dict[_WarmupFlightKey, WarmupStatusEntry] = {}

    @property
    def warmup_tasks(self) -> set[asyncio.Task[Any]]:
        """Currently running background warm-up tasks."""
        return {t for t in self._tasks if not t.done()}

    def _resolve_mgmt_key(self, mgmt_name: str | None) -> str:
        clean = (mgmt_name or "").strip()
        if clean:
            return clean
        if self._settings.mgmt_name:
            return self._settings.mgmt_name
        if len(self._settings.mgmt_names) == 1:
            return self._settings.mgmt_names[0]
        return "*"

    def _evict_status_if_needed(self) -> None:
        while len(self._status) > _MAX_WARMUP_STATUS_ENTRIES:
            evict_key: _WarmupFlightKey | None = None
            for k, entry in self._status.items():
                if entry.status != "running":
                    evict_key = k
                    break
            if evict_key is None:
                break
            self._status.pop(evict_key, None)

    def get_warmup_status(self, mgmt_name: str | None = None) -> list[WarmupStatusEntry]:
        """Return structured status entries for active and recent background warm-up flights."""
        filter_mgmt = mgmt_name.strip() if isinstance(mgmt_name, str) and mgmt_name.strip() else None
        return [
            entry.model_copy(deep=True)
            for entry in self._status.values()
            if filter_mgmt is None or entry.mgmt_name == filter_mgmt
        ]

    def start_object_cache_warmup(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        include_services: bool = False,
        mode: CacheMode = "smart",
        refresh_objects_fn: Callable[..., Awaitable[RefreshOutcome]],
        refresh_services_fn: Callable[..., Awaitable[RefreshOutcome]],
    ) -> asyncio.Task[RefreshOutcome]:
        """Explicitly schedule single-flight deduplicated background object (and optional service) cache warm-up."""
        eff_mgmt = self._resolve_mgmt_key(mgmt_name)
        raw_domains: Sequence[str] = [domains] if isinstance(domains, str) else (domains or ())
        norm_domains = tuple(sorted({d.strip() for d in raw_domains if d and d.strip()}))
        norm_types = (
            tuple(sorted({normalize_object_type(str(t)) for t in types if t and str(t).strip()}))
            if types is not None
            else ()
        )
        flight_key: _WarmupFlightKey = (
            eff_mgmt,
            norm_domains,
            norm_types,
            bool(include_global),
            bool(include_services),
            bool(mode == "force"),
        )

        existing = self._flights.get(flight_key)
        if existing is not None and not existing.done():
            return existing

        status_entry = WarmupStatusEntry(
            mgmt_name=eff_mgmt,
            domains=list(norm_domains),
            types=list(norm_types),
            include_global=bool(include_global),
            include_services=bool(include_services),
            status="running",
            started_at=self._now(),
        )
        self._status[flight_key] = status_entry
        self._evict_status_if_needed()

        async def _run_warmup() -> RefreshOutcome:
            try:
                await self._ensure_initialized()
                obj_outcome = await refresh_objects_fn(
                    mgmt_name=mgmt_name,
                    domains=domains,
                    types=types,
                    include_global=include_global,
                    mode=mode,
                )
                merged_refreshed = list(obj_outcome.refreshed_domains)
                merged_skipped = list(obj_outcome.skipped_domains)
                merged_failed = {k: redact_sid(str(v)) for k, v in obj_outcome.failed_domains.items()}
                total_items = obj_outcome.total_items

                if include_services:
                    svc_outcome = await refresh_services_fn(
                        mgmt_name=mgmt_name,
                        domains=domains,
                        include_global=include_global,
                        mode=mode,
                    )
                    for d in svc_outcome.refreshed_domains:
                        if d not in merged_refreshed:
                            merged_refreshed.append(d)
                    for d in svc_outcome.skipped_domains:
                        if d not in merged_skipped and d not in merged_refreshed:
                            merged_skipped.append(d)
                    for k, v in svc_outcome.failed_domains.items():
                        merged_failed[k] = redact_sid(str(v))
                    total_items += svc_outcome.total_items

                status_entry.refreshed_domains = merged_refreshed
                status_entry.failed_domains = merged_failed
                status_entry.completed_at = self._now()
                if merged_failed:
                    err_summary = "; ".join(f"{k}: {v}" for k, v in merged_failed.items())
                    status_entry.error = err_summary
                    if not merged_refreshed:
                        status_entry.status = "failed"
                        logger.warning(
                            "background_object_cache_warmup_failed",
                            mgmt_name=eff_mgmt,
                            domains=list(norm_domains),
                            error=err_summary,
                        )
                    else:
                        status_entry.status = "completed"
                else:
                    status_entry.status = "completed"

                return RefreshOutcome(
                    scope="objects",
                    refreshed_domains=merged_refreshed,
                    skipped_domains=merged_skipped,
                    failed_domains=merged_failed,
                    total_items=total_items,
                )
            except asyncio.CancelledError:
                status_entry.status = "cancelled"
                status_entry.completed_at = self._now()
                raise
            except Exception as exc:
                err_msg = redact_sid(str(exc))
                failed_map = {f"{eff_mgmt}:{d}": err_msg for d in norm_domains} if norm_domains else {eff_mgmt: err_msg}
                status_entry.status = "failed"
                status_entry.error = err_msg
                status_entry.failed_domains = dict(failed_map)
                status_entry.completed_at = self._now()
                logger.warning(
                    "background_object_cache_warmup_failed",
                    mgmt_name=eff_mgmt,
                    domains=list(norm_domains),
                    error=err_msg,
                )
                return RefreshOutcome(scope="objects", failed_domains=dict(failed_map))

        task = asyncio.create_task(_run_warmup())
        self._tasks.add(task)
        self._flights[flight_key] = task

        def _on_warmup_done(done_task: asyncio.Task[RefreshOutcome]) -> None:
            self._tasks.discard(done_task)
            if self._flights.get(flight_key) is done_task:
                self._flights.pop(flight_key, None)
            if not done_task.cancelled():
                with suppress(BaseException):
                    _ = done_task.exception()

        task.add_done_callback(_on_warmup_done)
        return task

    async def cancel_all(self) -> None:
        """Cancel all running background warm-up tasks immediately and clear flight tracking."""
        active_warmups = [t for t in self._tasks if not t.done()]
        for task in active_warmups:
            task.cancel()
        if active_warmups:
            await asyncio.gather(*active_warmups, return_exceptions=True)
        self._tasks.clear()
        self._flights.clear()


__all__ = [
    "_MAX_WARMUP_STATUS_ENTRIES",
    "CacheWarmupCoordinator",
    "_WarmupFlightKey",
    "logger",
]
