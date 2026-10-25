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

from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from datetime import datetime
from typing import Any

from arodonata.core.config import ArodonataSettings
from arodonata.core.events import DomainSyncProgressEvent, SyncProgressEvent
from arodonata.core.models.common import CacheMode, to_naive_utc, utc_now
from arodonata.core.models.domains import DomainSyncState, RefreshOutcome
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    DomainRulebaseSnapshot,
    HttpsRuleEntry,
    NatRuleEntry,
    RulebaseLayerEntry,
    RulebasePackageLayerEntry,
    RulebaseSectionEntry,
    RulebaseType,
    ThreatRuleEntry,
)
from arodonata.core.ports import ApiPort, CachePort
from arodonata.core.services.sync_coordinator import DomainProbeResult, DomainSyncCoordinator
from arodonata.core.telemetry import span_attrs, traced
from arodonata.rulebase.pager import (
    MAX_RULEBASE_PAGE_LIMIT,
    PagedRulebaseResult,
    fetch_paged_rulebase,
)


def _extract_ordered_layers_from_package(
    pkg: dict[str, Any],
    key: str,
) -> list[dict[str, Any]]:
    """Extract ordered layer dicts from a `show-packages` item under `key` (e.g. `access-layers`)."""
    val = pkg.get(key)
    if isinstance(val, list):
        return [item for item in val if isinstance(item, dict)]
    if isinstance(val, dict):
        for sub_key in ("layers", "objects", "value"):
            sub = val.get(sub_key)
            if isinstance(sub, list):
                return [item for item in sub if isinstance(item, dict)]
    return []


def _has_nat_policy(pkg: dict[str, Any]) -> bool:
    """Return `True` if a package dict indicates an enabled/present NAT policy."""
    if "nat-policy" in pkg:
        val = pkg["nat-policy"]
        if isinstance(val, bool):
            return val
        return bool(val)
    if "nat_policy" in pkg:
        return bool(pkg["nat_policy"])
    return False


def _is_global_layer(raw_layer: dict[str, Any], domain_name: str) -> bool:
    """Determine whether a layer dict belongs to the `Global` domain."""
    if domain_name == "Global":
        return True
    if bool(raw_layer.get("is-global") or raw_layer.get("is_global")):
        return True
    dom_meta = raw_layer.get("domain")
    if isinstance(dom_meta, dict):
        d_type = str(dom_meta.get("domain-type") or dom_meta.get("type") or "").lower()
        d_name = str(dom_meta.get("name") or "")
        if "global" in d_type or d_name == "Global":
            return True
    name = str(raw_layer.get("name") or "")
    return name.lower().startswith("global")


async def collect_domain_rulebase_snapshot(
    api: ApiPort,
    mgmt_name: str,
    domain_name: str,
    *,
    sid: str | None = None,
    server_ip: str | None = None,
    page_limit: int = MAX_RULEBASE_PAGE_LIMIT,
    emit: Callable[[SyncProgressEvent], Awaitable[None]] | None = None,
) -> DomainRulebaseSnapshot:
    """Traverse all packages, NAT policies, ordered/standalone/inline layers, and Global placeholders for a domain."""
    now = utc_now()
    package_layers: list[RulebasePackageLayerEntry] = []
    layers_by_key: dict[tuple[RulebaseType, str], RulebaseLayerEntry] = {}
    sections_by_key: dict[tuple[str, str], RulebaseSectionEntry] = {}
    access_rules_by_key: dict[tuple[str, str], AccessRuleEntry] = {}
    nat_rules_by_key: dict[tuple[str, str], NatRuleEntry] = {}
    https_rules_by_key: dict[tuple[str, str], HttpsRuleEntry] = {}
    threat_rules_by_key: dict[tuple[str, str], ThreatRuleEntry] = {}

    # 1. Fetch show-packages
    pkg_query = await api.api_query(
        mgmt_name,
        "show-packages",
        domain=domain_name,
        details_level="full",
        sid=sid,
        server_ip=server_ip,
    )
    packages: list[dict[str, Any]] = []
    if pkg_query.success and pkg_query.objects:
        packages = [p for p in pkg_query.objects if isinstance(p, dict)]
    else:
        # Fallback to single api_call("show-packages") if api_query wasn't mocked in minimal test setups
        pkg_call = await api.api_call(
            mgmt_name,
            "show-packages",
            {"details-level": "full"},
            domain=domain_name,
            sid=sid,
            server_ip=server_ip,
        )
        if pkg_call.success and isinstance(pkg_call.data, dict):
            raw_pkgs = pkg_call.data.get("packages") or pkg_call.data.get("objects") or []
            if isinstance(raw_pkgs, list):
                packages = [p for p in raw_pkgs if isinstance(p, dict)]

    # Track queued layers to fetch: (rulebase_type, layer_uid, layer_name, parent_layer_uid, parent_rule_uid, raw_meta, package_context)
    layer_queue: list[
        tuple[RulebaseType, str, str, str | None, str | None, dict[str, Any], str | None, str | None]
    ] = []
    queued_layer_ids: set[tuple[RulebaseType, str]] = set()

    # Map package_name -> list of domain access layer UIDs in that package (to help resolve Global placeholders)
    pkg_domain_layers: dict[str, list[tuple[str, str]]] = {}

    def _enqueue_layer(
        rb_type: RulebaseType,
        l_uid: str,
        l_name: str,
        *,
        parent_layer_uid: str | None = None,
        parent_rule_uid: str | None = None,
        raw_meta: dict[str, Any] | None = None,
        pkg_uid: str | None = None,
        pkg_name: str | None = None,
    ) -> None:
        key_id = l_uid or l_name
        if not key_id:
            return
        if (rb_type, key_id) in queued_layer_ids:
            # Update parent links if newly discovered as an inline/child layer
            existing = layers_by_key.get((rb_type, key_id))
            if existing is not None and parent_rule_uid and not existing.parent_rule_uid:
                existing.parent_layer_uid = parent_layer_uid
                existing.parent_rule_uid = parent_rule_uid
            return
        queued_layer_ids.add((rb_type, key_id))
        layer_queue.append(
            (rb_type, l_uid, l_name, parent_layer_uid, parent_rule_uid, dict(raw_meta or {}), pkg_uid, pkg_name)
        )

    for pkg in packages:
        pkg_uid = str(pkg.get("uid") or pkg.get("name") or "")
        pkg_name = str(pkg.get("name") or pkg_uid)
        if not pkg_uid:
            continue

        # NAT policy for package
        if _has_nat_policy(pkg):
            nat_layer_uid = f"nat:{pkg_uid}"
            package_layers.append(
                RulebasePackageLayerEntry(
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    package_uid=pkg_uid,
                    package_name=pkg_name,
                    rulebase_type="nat",
                    layer_uid=nat_layer_uid,
                    layer_name=f"{pkg_name} NAT",
                    position=1,
                    raw_data=dict(pkg),
                    updated_at=now,
                )
            )
            nat_paged = await fetch_paged_rulebase(
                api,
                mgmt_name,
                domain_name,
                rulebase_type="nat",
                layer_uid=nat_layer_uid,
                layer_name=pkg_name,
                package_uid=pkg_uid,
                package_name=pkg_name,
                limit=page_limit,
                sid=sid,
                server_ip=server_ip,
            )
            for sec in nat_paged.sections:
                sections_by_key[(sec.layer_uid, sec.uid)] = sec
            for nr in nat_paged.nat_rules:
                nat_rules_by_key[(nr.package_uid, nr.uid)] = nr

            if emit is not None:
                await emit(
                    DomainSyncProgressEvent(
                        scope="rulebase",
                        mgmt_name=mgmt_name,
                        domain=domain_name,
                        item_type="nat",
                        processed=len(nat_paged.nat_rules),
                        total=len(nat_paged.nat_rules),
                        message=f"Fetched {len(nat_paged.nat_rules)} NAT rule(s) for package {pkg_name!r}.",
                    )
                )

        # Ordered access, HTTPS, and threat layers in package
        for rb_type, pkg_field in (
            ("access", "access-layers"),
            ("https", "https-layers"),
            ("threat", "threat-layers"),
        ):
            r_type: RulebaseType = rb_type  # type: ignore[assignment]
            ordered = _extract_ordered_layers_from_package(pkg, pkg_field)
            for idx, l_dict in enumerate(ordered, start=1):
                l_uid = str(l_dict.get("uid") or l_dict.get("name") or "")
                l_name = str(l_dict.get("name") or l_uid)
                if not l_uid:
                    continue
                pos = int(l_dict.get("position") or idx)
                package_layers.append(
                    RulebasePackageLayerEntry(
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        package_uid=pkg_uid,
                        package_name=pkg_name,
                        rulebase_type=r_type,
                        layer_uid=l_uid,
                        layer_name=l_name,
                        position=pos,
                        raw_data=dict(pkg),
                        updated_at=now,
                    )
                )
                if r_type == "access" and not _is_global_layer(l_dict, domain_name):
                    pkg_domain_layers.setdefault(pkg_name, []).append((l_uid, l_name))
                _enqueue_layer(
                    r_type,
                    l_uid,
                    l_name,
                    raw_meta=l_dict,
                    pkg_uid=pkg_uid,
                    pkg_name=pkg_name,
                )

    # 2. Also query standalone layer listings (show-access-layers, show-https-layers, show-threat-layers)
    for rb_type, list_cmd, list_key in (
        ("access", "show-access-layers", "access-layers"),
        ("https", "show-https-layers", "https-layers"),
        ("threat", "show-threat-layers", "threat-layers"),
    ):
        r_type = rb_type  # type: ignore[assignment]
        l_res = await api.api_call(
            mgmt_name,
            list_cmd,
            {"details-level": "full"},
            domain=domain_name,
            sid=sid,
            server_ip=server_ip,
        )
        if l_res.success and isinstance(l_res.data, dict):
            raw_list = l_res.data.get(list_key) or l_res.data.get("objects") or l_res.data.get("layers") or []
            if isinstance(raw_list, list):
                for l_dict in raw_list:
                    if not isinstance(l_dict, dict):
                        continue
                    l_uid = str(l_dict.get("uid") or l_dict.get("name") or "")
                    l_name = str(l_dict.get("name") or l_uid)
                    if l_uid:
                        _enqueue_layer(r_type, l_uid, l_name, raw_meta=l_dict)

    # 3. Process layer queue (including inline layers and Global placeholder resolution)
    cursor = 0
    while cursor < len(layer_queue):
        q_rb_type, q_l_uid, q_l_name, parent_l_uid, parent_r_uid, raw_meta, q_pkg_uid, q_pkg_name = layer_queue[cursor]
        cursor += 1

        is_global = _is_global_layer(raw_meta, domain_name)
        paged: PagedRulebaseResult = await fetch_paged_rulebase(
            api,
            mgmt_name,
            domain_name,
            rulebase_type=q_rb_type,
            layer_uid=q_l_uid,
            layer_name=q_l_name,
            package_uid=q_pkg_uid if is_global else None,
            package_name=q_pkg_name if is_global else None,
            limit=page_limit,
            sid=sid,
            server_ip=server_ip,
        )

        eff_uid = paged.layer_uid or q_l_uid or q_l_name
        eff_name = paged.layer_name or q_l_name or eff_uid

        # If this layer contains a `place-holder` rule without a resolved `placeholder_domain_layer_uid`
        # and wasn't yet queried with `package` context, query it with `package` context now!
        has_unresolved_placeholder = any(
            r.rule_type == "place-holder" and not r.placeholder_domain_layer_uid for r in paged.access_rules
        )
        if has_unresolved_placeholder and q_pkg_name and not is_global:
            pkg_paged = await fetch_paged_rulebase(
                api,
                mgmt_name,
                domain_name,
                rulebase_type=q_rb_type,
                layer_uid=eff_uid,
                layer_name=eff_name,
                package_uid=q_pkg_uid,
                package_name=q_pkg_name,
                limit=page_limit,
                sid=sid,
                server_ip=server_ip,
            )
            if pkg_paged.access_rules:
                paged = pkg_paged
                is_global = True

        layer_entry = RulebaseLayerEntry(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            uid=eff_uid,
            name=eff_name,
            rulebase_type=q_rb_type,
            parent_layer_uid=parent_l_uid or (str(raw_meta["parent-layer"]) if raw_meta.get("parent-layer") else None),
            parent_rule_uid=parent_r_uid,
            is_global=is_global,
            shared=bool(raw_meta.get("shared", False)),
            implicit_cleanup_action=(
                str(raw_meta["implicit-cleanup-action"]) if raw_meta.get("implicit-cleanup-action") else None
            ),
            raw_data=dict(raw_meta),
            updated_at=now,
        )
        layers_by_key[(q_rb_type, eff_uid)] = layer_entry

        for sec in paged.sections:
            sections_by_key[(sec.layer_uid, sec.uid)] = sec

        for ar in paged.access_rules:
            # Resolve Global place-holder to nested domain layer
            if ar.rule_type == "place-holder":
                dom_layer_uid = ar.placeholder_domain_layer_uid
                dom_layer_name: str | None = None
                if dom_layer_uid and dom_layer_uid in paged.objects_dictionary:
                    dom_obj = paged.objects_dictionary[dom_layer_uid]
                    dom_layer_name = str(dom_obj.get("name") or dom_layer_uid)
                elif not dom_layer_uid and q_pkg_name and pkg_domain_layers.get(q_pkg_name):
                    dom_layer_uid, dom_layer_name = pkg_domain_layers[q_pkg_name][0]
                    ar = ar.model_copy(update={"placeholder_domain_layer_uid": dom_layer_uid})

                if dom_layer_uid:
                    _enqueue_layer(
                        "access",
                        dom_layer_uid,
                        dom_layer_name or dom_layer_uid,
                        parent_layer_uid=eff_uid,
                        parent_rule_uid=ar.uid,
                        pkg_uid=q_pkg_uid,
                        pkg_name=q_pkg_name,
                    )
                    existing_dom_layer = layers_by_key.get(("access", dom_layer_uid))
                    if existing_dom_layer is not None:
                        existing_dom_layer.parent_layer_uid = eff_uid
                        existing_dom_layer.parent_rule_uid = ar.uid

            # Enqueue any referenced inline layer
            if ar.inline_layer_uid and ar.rule_type != "place-holder":
                inline_meta = paged.objects_dictionary.get(ar.inline_layer_uid, {})
                inline_name = ar.inline_layer_name or str(inline_meta.get("name") or ar.inline_layer_uid)
                _enqueue_layer(
                    "access",
                    ar.inline_layer_uid,
                    inline_name,
                    parent_layer_uid=eff_uid,
                    parent_rule_uid=ar.uid,
                    raw_meta=inline_meta if isinstance(inline_meta, dict) else None,
                    pkg_uid=q_pkg_uid,
                    pkg_name=q_pkg_name,
                )
                existing_inline = layers_by_key.get(("access", ar.inline_layer_uid))
                if existing_inline is not None:
                    existing_inline.parent_layer_uid = eff_uid
                    existing_inline.parent_rule_uid = ar.uid

            access_rules_by_key[(ar.layer_uid, ar.uid)] = ar

        for hr in paged.https_rules:
            if hr.inline_layer_uid:
                inline_meta = paged.objects_dictionary.get(hr.inline_layer_uid, {})
                inline_name = str(inline_meta.get("name") or hr.inline_layer_uid)
                _enqueue_layer(
                    "https",
                    hr.inline_layer_uid,
                    inline_name,
                    parent_layer_uid=eff_uid,
                    parent_rule_uid=hr.uid,
                    raw_meta=inline_meta if isinstance(inline_meta, dict) else None,
                    pkg_uid=q_pkg_uid,
                    pkg_name=q_pkg_name,
                )
            https_rules_by_key[(hr.layer_uid, hr.uid)] = hr

        for tr in paged.threat_rules:
            threat_rules_by_key[(tr.layer_uid, tr.uid)] = tr

        if emit is not None:
            rule_count = len(paged.access_rules) + len(paged.https_rules) + len(paged.threat_rules)
            await emit(
                DomainSyncProgressEvent(
                    scope="rulebase",
                    mgmt_name=mgmt_name,
                    domain=domain_name,
                    item_type=q_rb_type,
                    processed=rule_count,
                    total=rule_count,
                    message=f"Fetched {rule_count} {q_rb_type} rule(s) from layer {eff_name!r}.",
                )
            )

    return DomainRulebaseSnapshot(
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        package_layers=package_layers,
        layers=list(layers_by_key.values()),
        sections=list(sections_by_key.values()),
        access_rules=list(access_rules_by_key.values()),
        nat_rules=list(nat_rules_by_key.values()),
        https_rules=list(https_rules_by_key.values()),
        threat_rules=list(threat_rules_by_key.values()),
    )


class RulebaseRefreshService:
    """Session-aware atomic rulebase snapshot refresh service (`refresh_rulebases`, `stream_refresh_rulebases`)."""

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        api: ApiPort,
        cache: CachePort,
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


__all__ = [
    "RulebaseRefreshService",
    "collect_domain_rulebase_snapshot",
]
