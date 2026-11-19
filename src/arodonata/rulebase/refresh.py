"""Atomic multi-domain rulebase snapshot refresh (`RulebaseRefreshService`).

Implements `refresh_rulebases` and `stream_refresh_rulebases`:
- Refuses to proceed if the shared read session is dirty (`locks != 0` or
  `number-of-published-changes != 0`), preserving any existing cached snapshot and
  marking `domain_sync_state.status = "failed"` (`scope="rulebase"`) with `last_error`.
- Fetches `show-packages`, NAT rulebases for packages with `nat-policy`, ordered
  access/HTTPS/threat layers, standalone layer listings (`show-access-layers`,
  `show-https-layers`, `show-threat-layers`), inline layers referenced by rules, and
  resolves Global layer `place-holder` rules in `package` context.
- Replaces the domain's entire rulebase snapshot atomically under the per-domain
  distributed lock (`sync:{mgmt_name}:{domain_name}:rulebase`).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from datetime import datetime
from typing import Protocol

from arodonata.core.config import ArodonataSettings
from arodonata.core.events import (
    DomainSyncProgressEvent,
    DomainSyncSkippedEvent,
    SyncCompletedEvent,
    SyncProgressEvent,
    SyncStartedEvent,
)
from arodonata.core.models.common import CacheMode, to_naive_utc, utc_now
from arodonata.core.models.domains import DomainInfo, DomainSyncState, RefreshOutcome
from arodonata.core.models.rulebase import RulebaseType
from arodonata.core.ports import ApiPort, RulebaseCachePort, SyncStatePort
from arodonata.core.services.sync_coordinator import DomainProbeResult, DomainSyncCoordinator
from arodonata.core.telemetry import span_attrs, traced
from arodonata.rulebase.collector import (
    _extract_ordered_layers_from_package,
    _fetch_domain_packages_raw,
    _has_nat_policy,
    _is_global_layer,
    collect_domain_rulebase_snapshot,
    collect_package_rulebase_slice,
    extract_package_layer_entries,
)
from arodonata.rulebase.models import PolicyPackageInfo
from arodonata.rulebase.numbering import extract_policy_packages


class _RulebaseRefreshCachePort(RulebaseCachePort, SyncStatePort, Protocol):
    """Cache capabilities required by `RulebaseRefreshService`."""


class RulebaseRefreshService:
    """Session-aware atomic rulebase snapshot refresh service (`refresh_rulebases`, `stream_refresh_rulebases`)."""

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        api: ApiPort,
        cache: _RulebaseRefreshCachePort,
        coordinator: DomainSyncCoordinator,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._settings = settings
        self._api = api
        self._cache = cache
        self._coordinator = coordinator
        self._now: Callable[[], datetime] = lambda: to_naive_utc(now_fn())

    async def _sync_domain_rulebase(
        self,
        probe: DomainProbeResult,
        emit: Callable[[SyncProgressEvent], Awaitable[None]],
    ) -> int:
        mgmt_name = probe.mgmt_name
        dom_name = probe.domain.name

        snapshot = await collect_domain_rulebase_snapshot(
            self._api,
            mgmt_name,
            dom_name,
            emit=emit,
        )

        total_rules = (
            len(snapshot.access_rules)
            + len(snapshot.nat_rules)
            + len(snapshot.https_rules)
            + len(snapshot.threat_rules)
        )
        now = self._now()
        sync_state = DomainSyncState(
            mgmt_name=mgmt_name,
            domain_name=dom_name,
            scope="rulebase",
            item_type="*",
            last_published_at=probe.remote_published_at,
            last_session_uid=probe.remote_session_uid,
            synced_at=now,
            status="ok",
            object_count=total_rules,
            last_error=None,
        )
        await self._cache.replace_domain_rulebase(snapshot, sync_state=sync_state)
        return total_rules

    async def stream_refresh_rulebases(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while refreshing domain rulebase snapshots."""
        async for event in self._coordinator.stream_ensure(
            scope="rulebase",
            item_types=["*"],
            handler=self._sync_domain_rulebase,
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield event

    @traced
    async def refresh_rulebases(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Refresh domain rulebase snapshots and return `RefreshOutcome`."""
        span_attrs(mgmt_name=mgmt_name, mode=mode, include_global=include_global)
        return await self._coordinator.ensure(
            scope="rulebase",
            item_types=["*"],
            handler=self._sync_domain_rulebase,
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    async def _sync_domain_packages(
        self,
        probe: DomainProbeResult,
        emit: Callable[[SyncProgressEvent], Awaitable[None]],
    ) -> int:
        mgmt_name = probe.mgmt_name
        dom_name = probe.domain.name
        now = self._now()

        packages = await _fetch_domain_packages_raw(
            self._api,
            mgmt_name,
            dom_name,
        )
        package_layers = extract_package_layer_entries(
            mgmt_name,
            dom_name,
            packages,
            now=now,
        )
        sync_state = DomainSyncState(
            mgmt_name=mgmt_name,
            domain_name=dom_name,
            scope="rulebase",
            item_type="packages",
            last_published_at=probe.remote_published_at,
            last_session_uid=probe.remote_session_uid,
            synced_at=now,
            status="ok",
            object_count=len(packages),
            last_error=None,
        )
        await self._cache.replace_domain_package_catalog(
            mgmt_name,
            dom_name,
            package_layers,
            sync_states=[sync_state],
        )
        await emit(
            DomainSyncProgressEvent(
                scope="rulebase",
                mgmt_name=mgmt_name,
                domain=dom_name,
                item_type="packages",
                processed=len(packages),
                total=len(packages),
                message=f"Fetched {len(packages)} policy package(s) for {mgmt_name}:{dom_name}.",
            )
        )
        return len(packages)

    async def _is_full_rulebase_fresh(
        self,
        dom: DomainInfo,
        *,
        mode: CacheMode,
        cache_ttl: float | None,
    ) -> bool:
        """Return `True` when `(dom.mgmt_name, dom.name)` already has a fresh `item_type='*'` rulebase snapshot."""
        if mode not in ("smart", "smart-fast"):
            return False
        st_full = await self._cache.get_sync_state(dom.mgmt_name, dom.name, "rulebase", "*")
        if st_full is None or st_full.status != "ok":
            return False
        probe_full = await self._coordinator.probe_domain_staleness(
            dom,
            scope="rulebase",
            item_types=["*"],
            mode=mode,
            cache_ttl=cache_ttl,
        )
        return not probe_full.is_stale

    async def stream_refresh_policy_packages(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
        _skip_full_fresh_check: bool = False,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while refreshing lightweight policy package catalogs (`item_type='packages'`)."""
        if mode in ("smart", "smart-fast") and not _skip_full_fresh_check:
            target_domains = await self._coordinator.resolve_target_domains(
                mgmt_name=mgmt_name,
                domains=domains,
                include_global=include_global,
                mode=mode,
            )
            fresh_flags = await asyncio.gather(
                *(self._is_full_rulebase_fresh(dom, mode=mode, cache_ttl=cache_ttl) for dom in target_domains)
            )
            full_fresh: list[DomainInfo] = []
            remaining: list[DomainInfo] = []
            for dom, is_fresh in zip(target_domains, fresh_flags, strict=True):
                if is_fresh:
                    full_fresh.append(dom)
                else:
                    remaining.append(dom)

            if full_fresh and not remaining:
                skipped_labels = [f"{d.mgmt_name}:{d.name}" for d in full_fresh]
                yield SyncStartedEvent(
                    scope="rulebase",
                    mgmt_name=mgmt_name,
                    message=f"Starting rulebase sync (mode={mode}) across {len(full_fresh)} domain(s).",
                    total=len(full_fresh),
                    details={"mode": mode, "item_types": ["packages"], "domain_count": len(full_fresh)},
                )
                for d in full_fresh:
                    yield DomainSyncSkippedEvent(
                        scope="rulebase",
                        mgmt_name=d.mgmt_name,
                        domain=d.name,
                        item_type="*",
                        message=f"Domain {d.mgmt_name}:{d.name} full rulebase snapshot is fresh; skipping.",
                    )
                yield SyncCompletedEvent(
                    scope="rulebase",
                    mgmt_name=mgmt_name,
                    processed=0,
                    total=0,
                    message=f"Completed rulebase sync: 0 refreshed, {len(skipped_labels)} skipped, 0 failed.",
                    details={
                        "refreshed_domains": [],
                        "skipped_domains": skipped_labels,
                        "failed_domains": {},
                        "total_items": 0,
                    },
                )
                return

            if full_fresh and remaining:
                skipped_labels = [f"{d.mgmt_name}:{d.name}" for d in full_fresh]
                by_mgmt: dict[str, list[str]] = {}
                for d in remaining:
                    by_mgmt.setdefault(d.mgmt_name, []).append(d.name)
                agg_refreshed: list[str] = []
                agg_skipped: list[str] = list(skipped_labels)
                agg_failed: dict[str, str] = {}
                agg_total = 0
                for d in full_fresh:
                    yield DomainSyncSkippedEvent(
                        scope="rulebase",
                        mgmt_name=d.mgmt_name,
                        domain=d.name,
                        item_type="*",
                        message=f"Domain {d.mgmt_name}:{d.name} full rulebase snapshot is fresh; skipping.",
                    )
                for m_name, d_names in by_mgmt.items():
                    async for ev in self._coordinator.stream_ensure(
                        scope="rulebase",
                        item_types=["packages"],
                        handler=self._sync_domain_packages,
                        mgmt_name=m_name,
                        domains=d_names,
                        include_global=("Global" in d_names),
                        mode=mode,
                        cache_ttl=cache_ttl,
                    ):
                        if isinstance(ev, SyncCompletedEvent):
                            agg_refreshed.extend(ev.details.get("refreshed_domains") or [])
                            agg_skipped.extend(ev.details.get("skipped_domains") or [])
                            agg_failed.update(ev.details.get("failed_domains") or {})
                            agg_total += int(ev.details.get("total_items") or 0)
                        elif not isinstance(ev, SyncStartedEvent):
                            yield ev
                yield SyncCompletedEvent(
                    scope="rulebase",
                    mgmt_name=mgmt_name,
                    processed=agg_total,
                    total=agg_total,
                    message=(
                        f"Completed rulebase sync: {len(agg_refreshed)} refreshed, "
                        f"{len(agg_skipped)} skipped, {len(agg_failed)} failed."
                    ),
                    details={
                        "refreshed_domains": agg_refreshed,
                        "skipped_domains": agg_skipped,
                        "failed_domains": agg_failed,
                        "total_items": agg_total,
                    },
                )
                return

        async for event in self._coordinator.stream_ensure(
            scope="rulebase",
            item_types=["packages"],
            handler=self._sync_domain_packages,
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield event

    @traced
    async def refresh_policy_packages(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
        _skip_full_fresh_check: bool = False,
    ) -> RefreshOutcome:
        """Synchronize lightweight policy package catalogs (`item_type='packages'`) without downloading rulebases."""
        span_attrs(mgmt_name=mgmt_name, mode=mode, include_global=include_global)
        refreshed_domains: list[str] = []
        skipped_domains: list[str] = []
        failed_domains: dict[str, str] = {}
        total_items = 0

        async for event in self.stream_refresh_policy_packages(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
            _skip_full_fresh_check=_skip_full_fresh_check,
        ):
            if isinstance(event, SyncCompletedEvent):
                refreshed_domains = list(event.details.get("refreshed_domains") or [])
                skipped_domains = list(event.details.get("skipped_domains") or [])
                failed_domains = dict(event.details.get("failed_domains") or {})
                total_items = int(event.details.get("total_items") or 0)

        return RefreshOutcome(
            scope="rulebase",
            refreshed_domains=refreshed_domains,
            skipped_domains=skipped_domains,
            failed_domains=failed_domains,
            total_items=total_items,
        )

    @traced
    async def refresh_package_rulebase(
        self,
        mgmt_name: str,
        domain_name: str,
        package: str,
        *,
        rulebase_type: RulebaseType = "access",
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Synchronize only the layers belonging to `(package, rulebase_type)` (`item_type='package:<type>:<uid>'`)."""
        clean_dom = domain_name.strip()
        clean_pkg = package.strip()
        span_attrs(
            mgmt_name=mgmt_name,
            domain=clean_dom,
            package=clean_pkg,
            rulebase_type=rulebase_type,
            mode=mode,
        )

        if mode == "cache":
            return RefreshOutcome(
                scope="rulebase",
                skipped_domains=[f"{mgmt_name}:{clean_dom}"],
            )

        if mode in ("smart", "smart-fast"):
            dom_targets = await self._coordinator.resolve_target_domains(
                mgmt_name=mgmt_name,
                domains=[clean_dom],
                include_global=(clean_dom == "Global"),
                mode=mode,
            )
            if dom_targets and await self._is_full_rulebase_fresh(
                dom_targets[0],
                mode=mode,
                cache_ttl=cache_ttl,
            ):
                return RefreshOutcome(
                    scope="rulebase",
                    skipped_domains=[f"{mgmt_name}:{clean_dom}"],
                )

        was_invalidated = self._coordinator.is_domain_invalidated(mgmt_name, clean_dom)
        pkg_outcome = await self.refresh_policy_packages(
            mgmt_name=mgmt_name,
            domains=[clean_dom],
            include_global=(clean_dom == "Global"),
            mode=mode,
            cache_ttl=cache_ttl,
            _skip_full_fresh_check=True,
        )
        if pkg_outcome.failed_domains:
            return pkg_outcome

        eff_slice_ttl = 0.0 if (was_invalidated or bool(pkg_outcome.refreshed_domains)) else cache_ttl

        pkg_snap = await self._cache.get_domain_rulebase_packages(mgmt_name, clean_dom)
        pkgs = extract_policy_packages(pkg_snap)
        matched_pkg: PolicyPackageInfo | None = None
        for p in pkgs:
            if p.uid == clean_pkg or p.name == clean_pkg:
                matched_pkg = p
                break
        if matched_pkg is None:
            needle_lower = clean_pkg.lower()
            for p in pkgs:
                if p.uid.lower() == needle_lower or p.name.lower() == needle_lower:
                    matched_pkg = p
                    break

        pkg_uid = matched_pkg.uid if matched_pkg is not None else clean_pkg
        slice_item_type = f"package:{rulebase_type}:{pkg_uid}"

        async def _sync_single_package(
            probe: DomainProbeResult,
            emit: Callable[[SyncProgressEvent], Awaitable[None]],
        ) -> int:
            now = self._now()
            if matched_pkg is None:
                empty_state = DomainSyncState(
                    mgmt_name=probe.mgmt_name,
                    domain_name=probe.domain.name,
                    scope="rulebase",
                    item_type=slice_item_type,
                    last_published_at=probe.remote_published_at,
                    last_session_uid=probe.remote_session_uid,
                    synced_at=now,
                    status="ok",
                    object_count=0,
                    last_error=None,
                )
                await self._cache.upsert_domain_rulebase_layers(
                    probe.mgmt_name,
                    probe.domain.name,
                    sync_states=[empty_state],
                )
                return 0

            slice_snap, replaced_layer_uids, replaced_nat_uids = await collect_package_rulebase_slice(
                self._api,
                probe.mgmt_name,
                probe.domain.name,
                matched_pkg,
                rulebase_type=rulebase_type,
                emit=emit,
            )
            total_rules = (
                len(slice_snap.access_rules)
                + len(slice_snap.nat_rules)
                + len(slice_snap.https_rules)
                + len(slice_snap.threat_rules)
            )
            sync_state = DomainSyncState(
                mgmt_name=probe.mgmt_name,
                domain_name=probe.domain.name,
                scope="rulebase",
                item_type=slice_item_type,
                last_published_at=probe.remote_published_at,
                last_session_uid=probe.remote_session_uid,
                synced_at=now,
                status="ok",
                object_count=total_rules,
                last_error=None,
            )
            await self._cache.upsert_domain_rulebase_layers(
                probe.mgmt_name,
                probe.domain.name,
                layers=slice_snap.layers,
                sections=slice_snap.sections,
                access_rules=slice_snap.access_rules,
                nat_rules=slice_snap.nat_rules,
                https_rules=slice_snap.https_rules,
                threat_rules=slice_snap.threat_rules,
                replaced_layer_uids=replaced_layer_uids,
                replaced_nat_package_uids=replaced_nat_uids,
                sync_states=[sync_state],
            )
            return total_rules

        return await self._coordinator.ensure(
            scope="rulebase",
            item_types=[slice_item_type],
            handler=_sync_single_package,
            mgmt_name=mgmt_name,
            domains=[clean_dom],
            include_global=(clean_dom == "Global"),
            mode=mode,
            cache_ttl=eff_slice_ttl,
        )


__all__ = [
    "RulebaseRefreshService",
    "_extract_ordered_layers_from_package",
    "_fetch_domain_packages_raw",
    "_has_nat_policy",
    "_is_global_layer",
    "collect_domain_rulebase_snapshot",
    "collect_package_rulebase_slice",
    "extract_package_layer_entries",
]
