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
from typing import Any

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
from arodonata.rulebase.models import PolicyPackageInfo
from arodonata.rulebase.numbering import extract_policy_packages
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


async def _fetch_domain_packages_raw(
    api: ApiPort,
    mgmt_name: str,
    domain_name: str,
    *,
    sid: str | None = None,
    server_ip: str | None = None,
    strict: bool = True,
) -> list[dict[str, Any]]:
    """Fetch policy packages (`show-packages`, `details-level='full'`) for `(mgmt_name, domain_name)`."""
    pkg_query = await api.api_query(
        mgmt_name,
        "show-packages",
        domain=domain_name,
        details_level="full",
        sid=sid,
        server_ip=server_ip,
    )
    if pkg_query.success and pkg_query.objects:
        return [p for p in pkg_query.objects if isinstance(p, dict)]

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
            return [p for p in raw_pkgs if isinstance(p, dict)]

    if strict and not pkg_query.success and not pkg_call.success:
        err = pkg_query.error_message or pkg_call.error_message or pkg_call.error_code or "show-packages failed"
        raise RuntimeError(f"Failed to fetch show-packages on {mgmt_name}:{domain_name}: {err}")
    return []


def extract_package_layer_entries(
    mgmt_name: str,
    domain_name: str,
    packages: Sequence[dict[str, Any]],
    *,
    now: datetime | None = None,
) -> list[RulebasePackageLayerEntry]:
    """Build `RulebasePackageLayerEntry` catalog rows from raw `show-packages` dictionaries."""
    ts = now or utc_now()
    package_layers: list[RulebasePackageLayerEntry] = []
    for pkg in packages:
        pkg_uid = str(pkg.get("uid") or pkg.get("name") or "")
        pkg_name = str(pkg.get("name") or pkg_uid)
        if not pkg_uid:
            continue

        if _has_nat_policy(pkg):
            package_layers.append(
                RulebasePackageLayerEntry(
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    package_uid=pkg_uid,
                    package_name=pkg_name,
                    rulebase_type="nat",
                    layer_uid=f"nat:{pkg_uid}",
                    layer_name=f"{pkg_name} NAT",
                    position=1,
                    raw_data=dict(pkg),
                    updated_at=ts,
                )
            )

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
                        updated_at=ts,
                    )
                )
    return package_layers


def _find_layer_dict_in_package_raw(
    pkg_raw: dict[str, Any],
    rulebase_type: RulebaseType,
    layer_uid: str,
    layer_name: str,
) -> dict[str, Any]:
    """Extract the layer metadata dict embedded inside `pkg_raw[<type>-layers]` when available."""
    field_map: dict[RulebaseType, str] = {
        "access": "access-layers",
        "https": "https-layers",
        "threat": "threat-layers",
        "nat": "nat-policy",
    }
    ordered = _extract_ordered_layers_from_package(pkg_raw, field_map.get(rulebase_type, ""))
    for item in ordered:
        i_uid = str(item.get("uid") or "")
        i_name = str(item.get("name") or "")
        if (layer_uid and i_uid == layer_uid) or (layer_name and i_name == layer_name):
            return dict(item)
    return {"uid": layer_uid, "name": layer_name}


async def collect_package_rulebase_slice(
    api: ApiPort,
    mgmt_name: str,
    domain_name: str,
    package_info: PolicyPackageInfo,
    *,
    rulebase_type: RulebaseType = "access",
    sid: str | None = None,
    server_ip: str | None = None,
    page_limit: int = MAX_RULEBASE_PAGE_LIMIT,
    emit: Callable[[SyncProgressEvent], Awaitable[None]] | None = None,
) -> tuple[DomainRulebaseSnapshot, list[str], list[str]]:
    """Fetch only the layers reachable for `(package_info, rulebase_type)`, skipping unrelated packages and types."""
    now = utc_now()
    pkg_uid = package_info.uid
    pkg_name = package_info.name

    if rulebase_type == "nat":
        nat_layer_uid = f"nat:{pkg_uid}"
        if not package_info.has_nat_policy:
            return (
                DomainRulebaseSnapshot(mgmt_name=mgmt_name, domain_name=domain_name),
                [nat_layer_uid],
                [pkg_uid],
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
        return (
            DomainRulebaseSnapshot(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                sections=list({(s.layer_uid, s.uid): s for s in nat_paged.sections}.values()),
                nat_rules=list({(nr.package_uid, nr.uid): nr for nr in nat_paged.nat_rules}.values()),
            ),
            [nat_layer_uid],
            [pkg_uid],
        )

    layers_by_key: dict[tuple[RulebaseType, str], RulebaseLayerEntry] = {}
    sections_by_key: dict[tuple[str, str], RulebaseSectionEntry] = {}
    access_rules_by_key: dict[tuple[str, str], AccessRuleEntry] = {}
    https_rules_by_key: dict[tuple[str, str], HttpsRuleEntry] = {}
    threat_rules_by_key: dict[tuple[str, str], ThreatRuleEntry] = {}

    layer_queue: list[
        tuple[RulebaseType, str, str, str | None, str | None, dict[str, Any], str | None, str | None]
    ] = []
    queued_layer_ids: set[tuple[RulebaseType, str]] = set()
    replaced_uids: set[str] = set()
    pkg_domain_layers: list[tuple[str, str]] = []

    def _enqueue_layer(
        rb_type: RulebaseType,
        l_uid: str,
        l_name: str,
        *,
        parent_layer_uid: str | None = None,
        parent_rule_uid: str | None = None,
        raw_meta: dict[str, Any] | None = None,
    ) -> None:
        key_id = l_uid or l_name
        if not key_id:
            return
        replaced_uids.add(key_id)
        if (rb_type, key_id) in queued_layer_ids:
            existing = layers_by_key.get((rb_type, key_id))
            if existing is not None and parent_rule_uid and not existing.parent_rule_uid:
                existing.parent_layer_uid = parent_layer_uid
                existing.parent_rule_uid = parent_rule_uid
            return
        queued_layer_ids.add((rb_type, key_id))
        layer_queue.append(
            (rb_type, l_uid, l_name, parent_layer_uid, parent_rule_uid, dict(raw_meta or {}), pkg_uid, pkg_name)
        )

    ordered_links: list[RulebasePackageLayerEntry]
    if rulebase_type == "access":
        ordered_links = list(package_info.access_layers)
    elif rulebase_type == "https":
        ordered_links = list(package_info.https_layers)
    else:
        ordered_links = list(package_info.threat_layers)

    for link in sorted(ordered_links, key=lambda e: e.position):
        l_meta = _find_layer_dict_in_package_raw(
            link.raw_data or package_info.raw_data,
            rulebase_type,
            link.layer_uid,
            link.layer_name,
        )
        if rulebase_type == "access" and not _is_global_layer(l_meta, domain_name):
            pkg_domain_layers.append((link.layer_uid, link.layer_name))
        _enqueue_layer(
            rulebase_type,
            link.layer_uid,
            link.layer_name,
            raw_meta=l_meta,
        )

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
        replaced_uids.add(eff_uid)

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
            if ar.rule_type == "place-holder":
                dom_layer_uid = ar.placeholder_domain_layer_uid
                dom_layer_name: str | None = None
                if dom_layer_uid and dom_layer_uid in paged.objects_dictionary:
                    dom_obj = paged.objects_dictionary[dom_layer_uid]
                    dom_layer_name = str(dom_obj.get("name") or dom_layer_uid)
                elif not dom_layer_uid and pkg_domain_layers:
                    dom_layer_uid, dom_layer_name = pkg_domain_layers[0]
                    ar = ar.model_copy(update={"placeholder_domain_layer_uid": dom_layer_uid})

                if dom_layer_uid:
                    _enqueue_layer(
                        "access",
                        dom_layer_uid,
                        dom_layer_name or dom_layer_uid,
                        parent_layer_uid=eff_uid,
                        parent_rule_uid=ar.uid,
                    )
                    existing_dom_layer = layers_by_key.get(("access", dom_layer_uid))
                    if existing_dom_layer is not None:
                        existing_dom_layer.parent_layer_uid = eff_uid
                        existing_dom_layer.parent_rule_uid = ar.uid

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

    return (
        DomainRulebaseSnapshot(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            layers=list(layers_by_key.values()),
            sections=list(sections_by_key.values()),
            access_rules=list(access_rules_by_key.values()),
            https_rules=list(https_rules_by_key.values()),
            threat_rules=list(threat_rules_by_key.values()),
        ),
        sorted(replaced_uids),
        [],
    )


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

    # 1. Fetch show-packages (non-strict so full snapshot collection still falls back to standalone layers)
    packages = await _fetch_domain_packages_raw(
        api,
        mgmt_name,
        domain_name,
        sid=sid,
        server_ip=server_ip,
        strict=False,
    )

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
    "collect_domain_rulebase_snapshot",
    "collect_package_rulebase_slice",
    "extract_package_layer_entries",
]
