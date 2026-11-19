"""Raw Check Point rulebase collection and shared BFS layer traversal (`arodonata.rulebase.collector`)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from arodonata.core.events import DomainSyncProgressEvent, SyncProgressEvent
from arodonata.core.models.common import utc_now
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
from arodonata.core.ports import ApiPort
from arodonata.rulebase.models import PolicyPackageInfo
from arodonata.rulebase.pager import MAX_RULEBASE_PAGE_LIMIT, PagedRulebaseResult, fetch_paged_rulebase


def _extract_ordered_layers_from_package(pkg: dict[str, Any], key: str) -> list[dict[str, Any]]:
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
        return val if isinstance(val, bool) else bool(val)
    if "nat_policy" in pkg:
        return bool(pkg["nat_policy"])
    return False


def _is_global_layer(raw_layer: dict[str, Any], domain_name: str) -> bool:
    """Determine whether a layer dict belongs to the `Global` domain."""
    if domain_name == "Global" or bool(raw_layer.get("is-global") or raw_layer.get("is_global")):
        return True
    dom_meta = raw_layer.get("domain")
    if isinstance(dom_meta, dict):
        d_type = str(dom_meta.get("domain-type") or dom_meta.get("type") or "").lower()
        d_name = str(dom_meta.get("name") or "")
        if "global" in d_type or d_name == "Global":
            return True
    return str(raw_layer.get("name") or "").lower().startswith("global")


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
            for idx, l_dict in enumerate(_extract_ordered_layers_from_package(pkg, pkg_field), start=1):
                l_uid = str(l_dict.get("uid") or l_dict.get("name") or "")
                l_name = str(l_dict.get("name") or l_uid)
                if not l_uid:
                    continue
                package_layers.append(
                    RulebasePackageLayerEntry(
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        package_uid=pkg_uid,
                        package_name=pkg_name,
                        rulebase_type=r_type,
                        layer_uid=l_uid,
                        layer_name=l_name,
                        position=int(l_dict.get("position") or idx),
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
    for item in _extract_ordered_layers_from_package(pkg_raw, field_map.get(rulebase_type, "")):
        i_uid = str(item.get("uid") or "")
        i_name = str(item.get("name") or "")
        if (layer_uid and i_uid == layer_uid) or (layer_name and i_name == layer_name):
            return dict(item)
    return {"uid": layer_uid, "name": layer_name}


@dataclass(slots=True)
class _QueuedLayer:
    """Layer traversal work item queued for BFS rulebase collection."""

    rulebase_type: RulebaseType
    layer_uid: str
    layer_name: str
    parent_layer_uid: str | None = None
    parent_rule_uid: str | None = None
    raw_meta: dict[str, Any] = field(default_factory=dict)
    package_uid: str | None = None
    package_name: str | None = None


@dataclass(slots=True)
class _LayerTraversalResult:
    """Aggregated layers, sections, typed rules, and visited UIDs from BFS traversal."""

    layers: list[RulebaseLayerEntry]
    sections: list[RulebaseSectionEntry]
    access_rules: list[AccessRuleEntry]
    https_rules: list[HttpsRuleEntry]
    threat_rules: list[ThreatRuleEntry]
    visited_layer_uids: set[str]


async def _fetch_nat_package_rules(
    api: ApiPort,
    mgmt_name: str,
    domain_name: str,
    *,
    pkg_uid: str,
    pkg_name: str,
    page_limit: int,
    sid: str | None,
    server_ip: str | None,
    emit: Callable[[SyncProgressEvent], Awaitable[None]] | None,
) -> PagedRulebaseResult:
    """Fetch NAT rulebase for a single policy package and emit `DomainSyncProgressEvent`."""
    nat_paged = await fetch_paged_rulebase(
        api,
        mgmt_name,
        domain_name,
        rulebase_type="nat",
        layer_uid=f"nat:{pkg_uid}",
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
    return nat_paged


async def _traverse_rulebase_layers(
    api: ApiPort,
    mgmt_name: str,
    domain_name: str,
    *,
    initial_layers: Sequence[_QueuedLayer],
    pkg_domain_layers: dict[str, list[tuple[str, str]]],
    now: datetime,
    sid: str | None = None,
    server_ip: str | None = None,
    page_limit: int = MAX_RULEBASE_PAGE_LIMIT,
    emit: Callable[[SyncProgressEvent], Awaitable[None]] | None = None,
) -> _LayerTraversalResult:
    """BFS-traverse rulebase layers, Global placeholders, and inline sub-layers."""
    layers_by_key: dict[tuple[RulebaseType, str], RulebaseLayerEntry] = {}
    sections_by_key: dict[tuple[str, str], RulebaseSectionEntry] = {}
    access_rules_by_key: dict[tuple[str, str], AccessRuleEntry] = {}
    https_rules_by_key: dict[tuple[str, str], HttpsRuleEntry] = {}
    threat_rules_by_key: dict[tuple[str, str], ThreatRuleEntry] = {}

    layer_queue: list[_QueuedLayer] = []
    queued_by_key: dict[tuple[RulebaseType, str], _QueuedLayer] = {}
    visited_layer_uids: set[str] = set()

    def _enqueue_layer(item: _QueuedLayer) -> None:
        key_id = item.layer_uid or item.layer_name
        if not key_id:
            return
        visited_layer_uids.add(key_id)
        q_key = (item.rulebase_type, key_id)
        if q_key in queued_by_key:
            existing_entry = layers_by_key.get(q_key)
            if existing_entry is not None and item.parent_rule_uid and not existing_entry.parent_rule_uid:
                existing_entry.parent_layer_uid = item.parent_layer_uid
                existing_entry.parent_rule_uid = item.parent_rule_uid
            elif item.parent_rule_uid and not queued_by_key[q_key].parent_rule_uid:
                queued_by_key[q_key].parent_layer_uid = item.parent_layer_uid
                queued_by_key[q_key].parent_rule_uid = item.parent_rule_uid
            return
        queued_item = _QueuedLayer(
            rulebase_type=item.rulebase_type,
            layer_uid=item.layer_uid,
            layer_name=item.layer_name,
            parent_layer_uid=item.parent_layer_uid,
            parent_rule_uid=item.parent_rule_uid,
            raw_meta=dict(item.raw_meta),
            package_uid=item.package_uid,
            package_name=item.package_name,
        )
        queued_by_key[q_key] = queued_item
        layer_queue.append(queued_item)

    for seed in initial_layers:
        _enqueue_layer(seed)

    cursor = 0
    while cursor < len(layer_queue):
        q = layer_queue[cursor]
        cursor += 1

        is_global = _is_global_layer(q.raw_meta, domain_name)
        paged = await fetch_paged_rulebase(
            api,
            mgmt_name,
            domain_name,
            rulebase_type=q.rulebase_type,
            layer_uid=q.layer_uid,
            layer_name=q.layer_name,
            package_uid=q.package_uid if is_global else None,
            package_name=q.package_name if is_global else None,
            limit=page_limit,
            sid=sid,
            server_ip=server_ip,
        )

        eff_uid = paged.layer_uid or q.layer_uid or q.layer_name
        eff_name = paged.layer_name or q.layer_name or eff_uid
        visited_layer_uids.add(eff_uid)

        # Re-fetch unresolved Global placeholder layers in package context when metadata omitted is-global.
        has_unresolved_placeholder = any(
            r.rule_type == "place-holder" and not r.placeholder_domain_layer_uid for r in paged.access_rules
        )
        if has_unresolved_placeholder and q.package_name and not is_global:
            pkg_paged = await fetch_paged_rulebase(
                api,
                mgmt_name,
                domain_name,
                rulebase_type=q.rulebase_type,
                layer_uid=eff_uid,
                layer_name=eff_name,
                package_uid=q.package_uid,
                package_name=q.package_name,
                limit=page_limit,
                sid=sid,
                server_ip=server_ip,
            )
            if pkg_paged.access_rules:
                paged = pkg_paged
                is_global = True

        layers_by_key[(q.rulebase_type, eff_uid)] = RulebaseLayerEntry(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            uid=eff_uid,
            name=eff_name,
            rulebase_type=q.rulebase_type,
            parent_layer_uid=q.parent_layer_uid
            or (str(q.raw_meta["parent-layer"]) if q.raw_meta.get("parent-layer") else None),
            parent_rule_uid=q.parent_rule_uid,
            is_global=is_global,
            shared=bool(q.raw_meta.get("shared", False)),
            implicit_cleanup_action=(
                str(q.raw_meta["implicit-cleanup-action"]) if q.raw_meta.get("implicit-cleanup-action") else None
            ),
            raw_data=dict(q.raw_meta),
            updated_at=now,
        )

        for sec in paged.sections:
            sections_by_key[(sec.layer_uid, sec.uid)] = sec

        pkg_lookup_key = q.package_name or q.package_uid or ""
        for ar in paged.access_rules:
            if ar.rule_type == "place-holder":
                dom_layer_uid = ar.placeholder_domain_layer_uid
                dom_layer_name: str | None = None
                if dom_layer_uid and dom_layer_uid in paged.objects_dictionary:
                    dom_layer_name = str(paged.objects_dictionary[dom_layer_uid].get("name") or dom_layer_uid)
                elif not dom_layer_uid and pkg_lookup_key and pkg_domain_layers.get(pkg_lookup_key):
                    dom_layer_uid, dom_layer_name = pkg_domain_layers[pkg_lookup_key][0]
                    ar = ar.model_copy(update={"placeholder_domain_layer_uid": dom_layer_uid})

                if dom_layer_uid:
                    _enqueue_layer(
                        _QueuedLayer(
                            rulebase_type="access",
                            layer_uid=dom_layer_uid,
                            layer_name=dom_layer_name or dom_layer_uid,
                            parent_layer_uid=eff_uid,
                            parent_rule_uid=ar.uid,
                            package_uid=q.package_uid,
                            package_name=q.package_name,
                        )
                    )
                    existing_dom_layer = layers_by_key.get(("access", dom_layer_uid))
                    if existing_dom_layer is not None:
                        existing_dom_layer.parent_layer_uid = eff_uid
                        existing_dom_layer.parent_rule_uid = ar.uid

            if ar.inline_layer_uid and ar.rule_type != "place-holder":
                inline_meta = paged.objects_dictionary.get(ar.inline_layer_uid, {})
                inline_name = ar.inline_layer_name or str(inline_meta.get("name") or ar.inline_layer_uid)
                _enqueue_layer(
                    _QueuedLayer(
                        rulebase_type="access",
                        layer_uid=ar.inline_layer_uid,
                        layer_name=inline_name,
                        parent_layer_uid=eff_uid,
                        parent_rule_uid=ar.uid,
                        raw_meta=dict(inline_meta) if isinstance(inline_meta, dict) else {},
                        package_uid=q.package_uid,
                        package_name=q.package_name,
                    )
                )
                existing_inline = layers_by_key.get(("access", ar.inline_layer_uid))
                if existing_inline is not None:
                    existing_inline.parent_layer_uid = eff_uid
                    existing_inline.parent_rule_uid = ar.uid

            access_rules_by_key[(ar.layer_uid, ar.uid)] = ar

        for hr in paged.https_rules:
            if hr.inline_layer_uid:
                inline_meta = paged.objects_dictionary.get(hr.inline_layer_uid, {})
                _enqueue_layer(
                    _QueuedLayer(
                        rulebase_type="https",
                        layer_uid=hr.inline_layer_uid,
                        layer_name=str(inline_meta.get("name") or hr.inline_layer_uid),
                        parent_layer_uid=eff_uid,
                        parent_rule_uid=hr.uid,
                        raw_meta=dict(inline_meta) if isinstance(inline_meta, dict) else {},
                        package_uid=q.package_uid,
                        package_name=q.package_name,
                    )
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
                    item_type=q.rulebase_type,
                    processed=rule_count,
                    total=rule_count,
                    message=f"Fetched {rule_count} {q.rulebase_type} rule(s) from layer {eff_name!r}.",
                )
            )

    return _LayerTraversalResult(
        layers=list(layers_by_key.values()),
        sections=list(sections_by_key.values()),
        access_rules=list(access_rules_by_key.values()),
        https_rules=list(https_rules_by_key.values()),
        threat_rules=list(threat_rules_by_key.values()),
        visited_layer_uids=visited_layer_uids,
    )


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
            return DomainRulebaseSnapshot(mgmt_name=mgmt_name, domain_name=domain_name), [nat_layer_uid], [pkg_uid]
        nat_paged = await _fetch_nat_package_rules(
            api,
            mgmt_name,
            domain_name,
            pkg_uid=pkg_uid,
            pkg_name=pkg_name,
            page_limit=page_limit,
            sid=sid,
            server_ip=server_ip,
            emit=emit,
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

    ordered_links = (
        package_info.access_layers
        if rulebase_type == "access"
        else (package_info.https_layers if rulebase_type == "https" else package_info.threat_layers)
    )
    pkg_domain_layers: dict[str, list[tuple[str, str]]] = {}
    pkg_key = pkg_name or pkg_uid
    initial_layers: list[_QueuedLayer] = []
    for link in sorted(ordered_links, key=lambda e: e.position):
        l_meta = _find_layer_dict_in_package_raw(
            link.raw_data or package_info.raw_data, rulebase_type, link.layer_uid, link.layer_name
        )
        if rulebase_type == "access" and not _is_global_layer(l_meta, domain_name):
            pkg_domain_layers.setdefault(pkg_key, []).append((link.layer_uid, link.layer_name))
        initial_layers.append(
            _QueuedLayer(
                rulebase_type=rulebase_type,
                layer_uid=link.layer_uid,
                layer_name=link.layer_name,
                raw_meta=l_meta,
                package_uid=pkg_uid,
                package_name=pkg_name,
            )
        )

    traversed = await _traverse_rulebase_layers(
        api,
        mgmt_name,
        domain_name,
        initial_layers=initial_layers,
        pkg_domain_layers=pkg_domain_layers,
        now=now,
        sid=sid,
        server_ip=server_ip,
        page_limit=page_limit,
        emit=emit,
    )
    return (
        DomainRulebaseSnapshot(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            layers=traversed.layers,
            sections=traversed.sections,
            access_rules=traversed.access_rules,
            https_rules=traversed.https_rules,
            threat_rules=traversed.threat_rules,
        ),
        sorted(traversed.visited_layer_uids),
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
    packages = await _fetch_domain_packages_raw(api, mgmt_name, domain_name, sid=sid, server_ip=server_ip, strict=False)
    package_layers = extract_package_layer_entries(mgmt_name, domain_name, packages, now=now)

    sections_by_key: dict[tuple[str, str], RulebaseSectionEntry] = {}
    nat_rules_by_key: dict[tuple[str, str], NatRuleEntry] = {}
    initial_layers: list[_QueuedLayer] = []
    pkg_domain_layers: dict[str, list[tuple[str, str]]] = {}

    for pkg in packages:
        pkg_uid = str(pkg.get("uid") or pkg.get("name") or "")
        pkg_name = str(pkg.get("name") or pkg_uid)
        if not pkg_uid:
            continue

        if _has_nat_policy(pkg):
            nat_paged = await _fetch_nat_package_rules(
                api,
                mgmt_name,
                domain_name,
                pkg_uid=pkg_uid,
                pkg_name=pkg_name,
                page_limit=page_limit,
                sid=sid,
                server_ip=server_ip,
                emit=emit,
            )
            for sec in nat_paged.sections:
                sections_by_key[(sec.layer_uid, sec.uid)] = sec
            for nr in nat_paged.nat_rules:
                nat_rules_by_key[(nr.package_uid, nr.uid)] = nr

        for rb_type, pkg_field in (("access", "access-layers"), ("https", "https-layers"), ("threat", "threat-layers")):
            r_type: RulebaseType = rb_type  # type: ignore[assignment]
            for l_dict in _extract_ordered_layers_from_package(pkg, pkg_field):
                l_uid = str(l_dict.get("uid") or l_dict.get("name") or "")
                l_name = str(l_dict.get("name") or l_uid)
                if not l_uid:
                    continue
                if r_type == "access" and not _is_global_layer(l_dict, domain_name):
                    pkg_domain_layers.setdefault(pkg_name, []).append((l_uid, l_name))
                initial_layers.append(
                    _QueuedLayer(
                        rulebase_type=r_type,
                        layer_uid=l_uid,
                        layer_name=l_name,
                        raw_meta=dict(l_dict),
                        package_uid=pkg_uid,
                        package_name=pkg_name,
                    )
                )

    for rb_type, list_cmd, list_key in (
        ("access", "show-access-layers", "access-layers"),
        ("https", "show-https-layers", "https-layers"),
        ("threat", "show-threat-layers", "threat-layers"),
    ):
        r_type = rb_type  # type: ignore[assignment]
        l_res = await api.api_call(
            mgmt_name, list_cmd, {"details-level": "full"}, domain=domain_name, sid=sid, server_ip=server_ip
        )
        if l_res.success and isinstance(l_res.data, dict):
            raw_list = l_res.data.get(list_key) or l_res.data.get("objects") or l_res.data.get("layers") or []
            if isinstance(raw_list, list):
                for l_dict in raw_list:
                    if not isinstance(l_dict, dict):
                        continue
                    l_uid = str(l_dict.get("uid") or l_dict.get("name") or "")
                    if l_uid:
                        initial_layers.append(
                            _QueuedLayer(
                                rulebase_type=r_type,
                                layer_uid=l_uid,
                                layer_name=str(l_dict.get("name") or l_uid),
                                raw_meta=dict(l_dict),
                            )
                        )

    traversed = await _traverse_rulebase_layers(
        api,
        mgmt_name,
        domain_name,
        initial_layers=initial_layers,
        pkg_domain_layers=pkg_domain_layers,
        now=now,
        sid=sid,
        server_ip=server_ip,
        page_limit=page_limit,
        emit=emit,
    )
    for sec in traversed.sections:
        sections_by_key[(sec.layer_uid, sec.uid)] = sec

    return DomainRulebaseSnapshot(
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        package_layers=package_layers,
        layers=traversed.layers,
        sections=list(sections_by_key.values()),
        access_rules=traversed.access_rules,
        nat_rules=list(nat_rules_by_key.values()),
        https_rules=traversed.https_rules,
        threat_rules=traversed.threat_rules,
    )
