"""Cached rulebase introspection source (`CachedRulebaseSource`).

Provides:
- `get_policy_packages(mgmt_name, domain_name, ...)`
- `get_package_rulebase(mgmt_name, domain_name, package, rulebase_type=..., ...)`
- `get_layer_rulebase(mgmt_name, domain_name, layer, rulebase_type=..., ...)`
- `locate_rules(mgmt_name, domain_name, rule_uids=..., layer_uids=..., ...)`
- `filter_rulebase(...)`
- Automatic domain resolution when `domain_name` is `None` or `""`, raising
  `AmbiguousLayerName` listing all `(domain, uid)` candidates when multiple cached
  domains match.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Literal

from arodonata.core.errors import AmbiguousLayerName, DomainNotFoundError
from arodonata.core.models.common import CacheMode, SyncStatus, to_naive_utc, utc_now
from arodonata.core.models.rulebase import DomainRulebaseSnapshot, RulebaseType
from arodonata.core.ports import CachePort
from arodonata.core.services.object_service import ObjectService
from arodonata.core.services.service_cache import ServiceCacheService
from arodonata.core.telemetry import span_attrs, traced
from arodonata.rulebase.filter import filter_numbered_rulebase
from arodonata.rulebase.models import (
    FilteredRulebaseResult,
    NumberedLayerRulebase,
    PackageRulebase,
    PolicyPackageInfo,
    RuleFormat,
    RuleLocations,
)
from arodonata.rulebase.numbering import (
    extract_policy_packages,
    locate_rules_in_snapshot,
    number_layer_rulebase,
    number_package_rulebase,
)
from arodonata.rulebase.refresh import RulebaseRefreshService


class CachedRulebaseSource:
    """High-level cached rulebase introspection, SmartConsole numbering, and local filtering engine."""

    def __init__(
        self,
        *,
        cache: CachePort,
        refresh_service: RulebaseRefreshService | None = None,
        object_service: ObjectService | None = None,
        service_cache: ServiceCacheService | None = None,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._cache = cache
        self._refresh_service = refresh_service
        self._object_service = object_service
        self._service_cache = service_cache
        self._now: Callable[[], datetime] = lambda: to_naive_utc(now_fn())

    async def _list_candidate_domains(self, mgmt_name: str) -> list[str]:
        """List all known domain names on `mgmt_name` from `domains` and `domain_sync_state`."""
        seen: list[str] = []
        domains = await self._cache.get_domains(mgmt_name=mgmt_name, include_global=True)
        for d in domains:
            if d.name not in seen:
                seen.append(d.name)
        sync_states = await self._cache.list_sync_states(mgmt_name=mgmt_name, scope="rulebase")
        for st in sync_states:
            if st.domain_name not in seen:
                seen.append(st.domain_name)
        return seen

    async def _resolve_domain_for_target(
        self,
        mgmt_name: str,
        domain_name: str | None,
        target_name_or_uid: str,
        *,
        kind: Literal["package", "layer"],
        rulebase_type: RulebaseType | None = None,
    ) -> str:
        """Resolve `domain_name` when `None` or `""`, raising `AmbiguousLayerName` if multiple domains match."""
        if domain_name is not None and domain_name.strip():
            return domain_name.strip()

        candidate_domains = await self._list_candidate_domains(mgmt_name)
        non_global = [d for d in candidate_domains if d != "Global"]

        target = target_name_or_uid.strip()
        matches: list[tuple[str, str]] = []

        for dom in candidate_domains:
            snap = await self._cache.get_domain_rulebase(mgmt_name, dom)
            if kind == "package":
                pkg_uid_found: str | None = None
                for pl in snap.package_layers:
                    if pl.package_uid == target or pl.package_name == target:
                        pkg_uid_found = pl.package_uid
                        break
                if pkg_uid_found is None:
                    for nr in snap.nat_rules:
                        if nr.package_uid == target or nr.package_name == target:
                            pkg_uid_found = nr.package_uid
                            break
                if pkg_uid_found is not None:
                    matches.append((dom, pkg_uid_found))
            else:
                layer_uid_found: str | None = None
                for l_entry in snap.layers:
                    if rulebase_type is not None and l_entry.rulebase_type != rulebase_type:
                        continue
                    if l_entry.uid == target or l_entry.name == target:
                        layer_uid_found = l_entry.uid
                        break
                if layer_uid_found is None:
                    for pl in snap.package_layers:
                        if rulebase_type is not None and pl.rulebase_type != rulebase_type:
                            continue
                        if pl.layer_uid == target or pl.layer_name == target:
                            layer_uid_found = pl.layer_uid
                            break
                if layer_uid_found is not None:
                    matches.append((dom, layer_uid_found))

        if len(matches) == 1:
            return matches[0][0]
        if len(matches) > 1:
            raise AmbiguousLayerName(target, matches)

        # If no snapshot matched yet, check if there is a single unambiguous domain on this server
        if len(non_global) == 1:
            return non_global[0]
        if len(candidate_domains) == 1:
            return candidate_domains[0]

        raise DomainNotFoundError(f"Could not resolve domain for {kind} {target!r} on management server {mgmt_name!r}.")

    async def _ensure_and_load_snapshot(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> tuple[DomainRulebaseSnapshot, str | None, datetime | None, SyncStatus, float | None]:
        """Optionally refresh rulebase for `(mgmt_name, domain_name)` and return snapshot + sync metadata."""
        if cache_mode != "cache" and self._refresh_service is not None:
            await self._refresh_service.refresh_rulebases(
                mgmt_name=mgmt_name,
                domains=[domain_name],
                include_global=(domain_name == "Global"),
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        snapshot = await self._cache.get_domain_rulebase(mgmt_name, domain_name)
        st = await self._cache.get_sync_state(mgmt_name, domain_name, "rulebase", "*")
        if st is None:
            return snapshot, None, None, "idle", None

        age: float | None = None
        if st.synced_at is not None:
            age = max(0.0, (self._now() - st.synced_at).total_seconds())
        return snapshot, st.last_session_uid, st.last_published_at, st.status, age

    @traced
    async def get_policy_packages(
        self,
        mgmt_name: str,
        domain_name: str | None = None,
        *,
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> list[PolicyPackageInfo]:
        """Return cached `PolicyPackageInfo` entries for `(mgmt_name, domain_name)`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, cache_mode=cache_mode)
        if domain_name is None or not domain_name.strip():
            domains = await self._list_candidate_domains(mgmt_name)
            non_global = [d for d in domains if d != "Global"]
            target_domains = non_global or domains
            results: list[PolicyPackageInfo] = []
            for dom in target_domains:
                snap, _, _, _, _ = await self._ensure_and_load_snapshot(
                    mgmt_name,
                    dom,
                    cache_mode=cache_mode,
                    cache_ttl=cache_ttl,
                )
                results.extend(extract_policy_packages(snap))
            return results

        snap, _, _, _, _ = await self._ensure_and_load_snapshot(
            mgmt_name,
            domain_name.strip(),
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )
        return extract_policy_packages(snap)

    @traced
    async def get_package_rulebase(
        self,
        mgmt_name: str,
        domain_name: str | None,
        package: str,
        *,
        rulebase_type: RulebaseType = "access",
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> PackageRulebase:
        """Return a SmartConsole-numbered `PackageRulebase` for `package` in `(mgmt_name, domain_name)`."""
        resolved_domain = await self._resolve_domain_for_target(
            mgmt_name,
            domain_name,
            package,
            kind="package",
            rulebase_type=rulebase_type,
        )
        span_attrs(
            mgmt_name=mgmt_name,
            domain=resolved_domain,
            package=package,
            rulebase_type=rulebase_type,
            cache_mode=cache_mode,
        )
        snap, session_uid, published_at, status, _ = await self._ensure_and_load_snapshot(
            mgmt_name,
            resolved_domain,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )
        return number_package_rulebase(
            snap,
            package,
            rulebase_type=rulebase_type,
            snapshot_session_uid=session_uid,
            snapshot_published_at=published_at,
            sync_status=status,
        )

    @traced
    async def get_layer_rulebase(
        self,
        mgmt_name: str,
        domain_name: str | None,
        layer: str,
        *,
        rulebase_type: RulebaseType | None = None,
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> NumberedLayerRulebase:
        """Return a SmartConsole-numbered `NumberedLayerRulebase` for `layer` in `(mgmt_name, domain_name)`."""
        resolved_domain = await self._resolve_domain_for_target(
            mgmt_name,
            domain_name,
            layer,
            kind="layer",
            rulebase_type=rulebase_type,
        )
        span_attrs(
            mgmt_name=mgmt_name,
            domain=resolved_domain,
            layer=layer,
            rulebase_type=rulebase_type,
            cache_mode=cache_mode,
        )
        snap, session_uid, published_at, status, _ = await self._ensure_and_load_snapshot(
            mgmt_name,
            resolved_domain,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )
        return number_layer_rulebase(
            snap,
            layer,
            rulebase_type=rulebase_type,
            prefix="",
            expand_placeholders=False,
            expand_inline_layers=True,
            snapshot_session_uid=session_uid,
            snapshot_published_at=published_at,
            sync_status=status,
        )

    @traced
    async def locate_rules(
        self,
        mgmt_name: str,
        domain_name: str | None = None,
        *,
        rule_uids: Sequence[str] | None = None,
        layer_uids: Sequence[str] | None = None,
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> RuleLocations:
        """Locate SmartConsole rule numbers and layer prefixes across all packages and layers of a domain."""
        if domain_name is None or not domain_name.strip():
            domains = await self._list_candidate_domains(mgmt_name)
            non_global = [d for d in domains if d != "Global"]
            if len(non_global) == 1:
                resolved_domain = non_global[0]
            elif len(domains) == 1:
                resolved_domain = domains[0]
            else:
                raise DomainNotFoundError(
                    f"Domain name is required for locate_rules on multi-domain server {mgmt_name!r}."
                )
        else:
            resolved_domain = domain_name.strip()

        span_attrs(
            mgmt_name=mgmt_name,
            domain=resolved_domain,
            rule_count=len(rule_uids) if rule_uids else 0,
            layer_count=len(layer_uids) if layer_uids else 0,
        )
        snap, session_uid, published_at, status, _ = await self._ensure_and_load_snapshot(
            mgmt_name,
            resolved_domain,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )
        return locate_rules_in_snapshot(
            snap,
            rule_uids=rule_uids,
            layer_uids=layer_uids,
            snapshot_session_uid=session_uid,
            snapshot_published_at=published_at,
            sync_status=status,
        )

    @traced
    async def filter_rulebase(
        self,
        mgmt_name: str,
        domain_name: str | None = None,
        *,
        package: str | None = None,
        layer: str | None = None,
        rulebase_type: RulebaseType = "access",
        filter_query: str = "",
        output_format: RuleFormat = "model_friendly",
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> FilteredRulebaseResult:
        """Evaluate `filter_query` locally against cached rulebase and cached objects/services."""
        if not package and not layer:
            raise ValueError("Either 'package' or 'layer' must be specified for filter_rulebase.")

        if package is not None:
            resolved_domain = await self._resolve_domain_for_target(
                mgmt_name,
                domain_name,
                package,
                kind="package",
                rulebase_type=rulebase_type,
            )
            snap, session_uid, published_at, status, age = await self._ensure_and_load_snapshot(
                mgmt_name,
                resolved_domain,
                cache_mode=cache_mode,
                cache_ttl=cache_ttl,
            )
            rb: PackageRulebase | NumberedLayerRulebase = number_package_rulebase(
                snap,
                package,
                rulebase_type=rulebase_type,
                snapshot_session_uid=session_uid,
                snapshot_published_at=published_at,
                sync_status=status,
            )
        else:
            assert layer is not None
            resolved_domain = await self._resolve_domain_for_target(
                mgmt_name,
                domain_name,
                layer,
                kind="layer",
                rulebase_type=rulebase_type,
            )
            snap, session_uid, published_at, status, age = await self._ensure_and_load_snapshot(
                mgmt_name,
                resolved_domain,
                cache_mode=cache_mode,
                cache_ttl=cache_ttl,
            )
            rb = number_layer_rulebase(
                snap,
                layer,
                rulebase_type=rulebase_type,
                prefix="",
                expand_placeholders=False,
                expand_inline_layers=True,
                snapshot_session_uid=session_uid,
                snapshot_published_at=published_at,
                sync_status=status,
            )

        # Load cached objects and services for rich IP/CIDR/group/port filter matching
        if self._object_service is not None:
            objects = await self._object_service.get_objects(
                mgmt_name=mgmt_name,
                domain=resolved_domain,
                include_global=True,
                cache_mode="cache",
            )
        else:
            objects = await self._cache.get_objects(mgmt_name=mgmt_name, domain_name=resolved_domain)

        if self._service_cache is not None:
            services = await self._service_cache.get_services(
                mgmt_name=mgmt_name,
                domain=resolved_domain,
                include_global=True,
                cache_mode="cache",
            )
        else:
            services = await self._cache.get_services(mgmt_name=mgmt_name, domain_name=resolved_domain)

        return filter_numbered_rulebase(
            rb,
            filter_query=filter_query,
            output_format=output_format,
            objects=objects,
            services=services,
            cache_age_seconds=age,
        )


__all__ = [
    "CachedRulebaseSource",
]
