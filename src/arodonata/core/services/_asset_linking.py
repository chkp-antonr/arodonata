"""Cluster and VSX topology relationship enrichment helpers for `AssetRefreshService`."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from arodonata.core.errors import ServerIdentityError
from arodonata.core.models.assets import Asset, classify_asset
from arodonata.core.ports import ApiPort

CLUSTER_PARENT_TYPES: frozenset[str] = frozenset(
    {
        "simple-cluster",
        "cluster",
        "vsx-cluster",
        "CpmiGatewayCluster",
        "CpmiVsxClusterNetobj",
    }
)

CLUSTER_MEMBER_TYPES: frozenset[str] = frozenset(
    {
        "cluster-member",
        "vsx-cluster-member",
        "CpmiClusterMember",
        "CpmiVsxClusterMember",
    }
)

VSX_PARENT_TYPES: frozenset[str] = frozenset(
    {
        "vsx-gateway",
        "vsx-cluster",
        "CpmiVsxNetobj",
        "CpmiVsxClusterNetobj",
    }
)

VSX_CHILD_TYPES: frozenset[str] = frozenset(
    {
        "virtual-system",
        "vs-netobj",
        "CpmiVsNetobj",
        "CpmiVsClusterNetobj",
    }
)

VSX_GENERIC_OBJECT_CLASSES: tuple[str, ...] = (
    "com.checkpoint.objects.classes.dummy.CpmiVsxNetobj",
    "com.checkpoint.objects.classes.dummy.CpmiVsxClusterNetobj",
    "com.checkpoint.objects.classes.dummy.CpmiVsNetobj",
    "com.checkpoint.objects.classes.dummy.CpmiVsClusterNetobj",
    "com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj",
    "com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj",
)

_VS_SLOT_MERGE_KEYS: tuple[str, ...] = (
    "interfaces",
    "interfaces_installed",
    "routes",
    "routes_installed",
    "routing_table",
    "vsid",
    "targetCustomer",
    "target-customer",
    "target_customer",
    "vsxGateway",
    "vsx-gateway",
    "vsx_gateway",
    "parent",
    "contained-in",
)

_GENERIC_TOPOLOGY_MERGE_KEYS: tuple[str, ...] = (
    "virtual-systems",
    "virtual_systems",
    "virtualSystems",
    "vsx-gateway",
    "vsx_gateway",
    "vsxGateway",
    "parent",
    "contained-in",
    *_VS_SLOT_MERGE_KEYS,
)


def _unwrap_object_list(val: Any) -> list[Any]:
    """Unwrap either a raw list or a `{'objects': [...]}` container into a list."""
    if isinstance(val, dict) and isinstance(val.get("objects"), list):
        return list(val["objects"])
    return val if isinstance(val, list) else []


def _extract_vsx_parent_ref(raw: Mapping[str, Any], *, is_vs: bool) -> Any:
    """Return the parent VSX reference object/string from a Virtual System's `raw_data`."""
    return (
        raw.get("vsx-gateway")
        or raw.get("vsx_gateway")
        or raw.get("vsxGateway")
        or raw.get("vsx-cluster")
        or raw.get("contained-in")
        or (raw.get("parent") if is_vs else None)
    )


def _parse_vs_slot_metadata(slot_obj: Mapping[str, Any]) -> tuple[str, str]:
    """Extract normalized `(slot_name, target_domain)` metadata from a VS slot dict."""
    slot_name = str(slot_obj.get("name") or slot_obj.get("vsName") or slot_obj.get("vs-name") or "")
    target_cust = (
        slot_obj.get("targetCustomer")
        or slot_obj.get("target-customer")
        or slot_obj.get("target_customer")
        or slot_obj.get("customer")
        or slot_obj.get("domain")
    )
    target_domain = (
        str(target_cust.get("name") or target_cust.get("uid") or "")
        if isinstance(target_cust, dict)
        else str(target_cust or "")
    )
    return slot_name, target_domain


def _is_excluded_cluster_member(asset: Asset) -> bool:
    """Return `True` if `asset` is a Virtual System that must never be linked as a cluster member."""
    return asset.type in VSX_CHILD_TYPES or "virtual-system" in asset.type.lower()


def _link_parent_and_child_assets(
    parent: Asset,
    child: Asset,
    *,
    list_kind: str,
) -> tuple[Asset, Asset, bool]:
    """Bidirectionally link `child` -> `parent` and register `child` on `parent`'s member/VS list."""
    if parent.uid == child.uid or parent.id == child.id:
        return parent, child, False
    if list_kind == "cluster" and _is_excluded_cluster_member(child):
        return parent, child, False
    if list_kind == "vsx" and (
        _is_excluded_vsx_child(child) or parent.type in CLUSTER_MEMBER_TYPES or "member" in parent.type.lower()
    ):
        return parent, child, False
    changed = False
    updated_child = child
    if (
        child.parent_uid != parent.uid
        or child.parent_name != parent.name
        or child.parent_id != parent.id
        or child.parent_asset_id != parent.asset_id
    ):
        updated_child = child.model_copy(
            update={
                "parent_uid": parent.uid,
                "parent_name": parent.name,
                "parent_id": parent.id,
                "parent_asset_id": parent.asset_id,
            }
        )
        changed = True

    uids_attr = "member_uids" if list_kind == "cluster" else "virtual_system_uids"
    aids_attr = "member_asset_ids" if list_kind == "cluster" else "virtual_system_asset_ids"
    cur_uids = list(getattr(parent, uids_attr))
    cur_aids = list(getattr(parent, aids_attr))
    new_uids = list(cur_uids)
    new_aids = list(cur_aids)
    if updated_child.uid not in new_uids:
        new_uids.append(updated_child.uid)
    if updated_child.asset_id not in new_aids:
        new_aids.append(updated_child.asset_id)

    updated_parent = parent
    if new_uids != cur_uids or new_aids != cur_aids:
        updated_parent = parent.model_copy(update={uids_attr: new_uids, aids_attr: new_aids})
        changed = True
    return updated_parent, updated_child, changed


def _is_excluded_vsx_child(asset: Asset) -> bool:
    """Return `True` if `asset` must never be linked into a VSX parent's `virtual_system_uids`."""
    return asset.type in CLUSTER_MEMBER_TYPES or "member" in asset.type.lower() or asset.type in VSX_PARENT_TYPES


def _extract_interfaces_from_generic(raw_obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract a list of interface dicts from `interfaces` or `interfaces_installed` on a generic/slot object."""
    for key in ("interfaces", "interfaces_installed"):
        val = raw_obj.get(key)
        if isinstance(val, dict) and isinstance(val.get("objects"), list):
            val = val["objects"]
        if isinstance(val, list):
            extracted: list[dict[str, Any]] = []
            for item in val:
                if isinstance(item, dict):
                    owned = item.get("owned-object") or item.get("owned_object")
                    if isinstance(owned, dict):
                        merged_if = dict(item)
                        merged_if.update(owned)
                        extracted.append(merged_if)
                    else:
                        extracted.append(item)
            if extracted:
                return extracted
    return []


def _is_slot_object(g_obj: dict[str, Any]) -> bool:
    """Return `True` if `g_obj` is a `CpmiVsxSlotObj` or `CpmiVsSlotObj` record."""
    cls_or_type = f"{g_obj.get('class-name') or ''} {g_obj.get('type') or ''} {g_obj.get('objtype') or ''}"
    if "CpmiVsxSlotObj" in cls_or_type or "CpmiVsSlotObj" in cls_or_type or "SlotObj" in cls_or_type:
        return True
    if any(t in cls_or_type for t in (*VSX_PARENT_TYPES, *VSX_CHILD_TYPES)):
        return False
    return not cls_or_type.strip() and "vsid" in g_obj and ("targetCustomer" in g_obj or "vsxGateway" in g_obj)


def _is_vsx_slot0_object(g_obj: dict[str, Any]) -> bool:
    """Return `True` if `g_obj` represents `VS0` (`CpmiVsxSlotObj` or `vsid == 0`)."""
    cls_or_type = f"{g_obj.get('class-name') or ''} {g_obj.get('type') or ''} {g_obj.get('objtype') or ''}"
    if "CpmiVsxSlotObj" in cls_or_type:
        return True
    if not _is_slot_object(g_obj):
        return False
    vsid = g_obj.get("vsid")
    if vsid is None:
        return False
    try:
        return int(vsid) == 0
    except (TypeError, ValueError):
        return False


def _merge_vs_slot_data(asset: Asset, source_obj: dict[str, Any]) -> tuple[Asset, bool]:
    """Merge VS generic/slot `interfaces`, `interfaces_installed`, `routes`, and `routes_installed` onto `asset`."""
    merged_raw = dict(asset.raw_data)
    changed = False

    for key in _VS_SLOT_MERGE_KEYS:
        if key in source_obj and source_obj[key] is not None:
            existing_val = merged_raw.get(key)
            if existing_val is None or existing_val == [] or existing_val == {}:
                merged_raw[key] = source_obj[key]
                changed = True

    extracted_ifs = _extract_interfaces_from_generic(source_obj)
    new_interfaces = list(asset.interfaces)
    if not new_interfaces and extracted_ifs:
        new_interfaces = extracted_ifs
        merged_raw["interfaces"] = extracted_ifs
        changed = True

    if not changed:
        return asset, False
    return asset.model_copy(update={"interfaces": new_interfaces, "raw_data": merged_raw}), True


def _resolve_local_asset_ref(
    ref: Any,
    by_uid: Mapping[str, Asset],
    by_name: Mapping[str, Asset],
) -> Asset | None:
    """Resolve a string or dict `(uid, name)` reference against local `by_uid`/`by_name` maps."""
    if isinstance(ref, str) and ref:
        return by_uid.get(ref) or by_name.get(ref)
    if isinstance(ref, dict):
        r_uid = str(ref.get("uid") or "")
        r_name = str(ref.get("name") or "")
        return (by_uid.get(r_uid) if r_uid else None) or (by_name.get(r_name) if r_name else None)
    return None


def _enrich_cluster_member_from_parent(parent: Asset, member: Asset) -> Asset:
    """Inherit missing `hardware`, `os_name`, and `version` from `parent` and re-classify `member`."""
    updates: dict[str, Any] = {}
    for field_name in ("hardware", "os_name", "version"):
        member_val = getattr(member, field_name)
        parent_val = getattr(parent, field_name)
        if not str(member_val or "").strip() and str(parent_val or "").strip():
            updates[field_name] = parent_val
    updated_member = member.model_copy(update=updates) if updates else member
    return classify_asset(updated_member, parent_type=parent.type)


class ClusterRelationshipManager:
    """Enriches parent-child relationships between Check Point clusters and cluster members."""

    def enrich(self, assets: Sequence[Asset]) -> list[Asset]:
        """Link cluster members to their parent clusters and return updated `Asset` models."""
        by_uid: dict[str, Asset] = {a.uid: a for a in assets}
        by_name: dict[str, Asset] = {a.name: a for a in assets}

        def _store_cluster(a: Asset) -> None:
            by_uid[a.uid] = a
            by_name[a.name] = a

        for asset in list(by_uid.values()):
            raw = asset.raw_data
            raw_members = _unwrap_object_list(
                raw.get("cluster-member-names")
                or raw.get("cluster-members")
                or raw.get("members")
                or raw.get("cluster_members")
            )
            discovered_member_uids: list[str] = list(asset.member_uids)
            discovered_member_asset_ids: list[str] = list(asset.member_asset_ids)

            for item in raw_members:
                if isinstance(item, dict):
                    raw_item_type = str(item.get("type") or "")
                    if raw_item_type in VSX_CHILD_TYPES or "virtual-system" in raw_item_type.lower():
                        continue
                member_asset = _resolve_local_asset_ref(item, by_uid, by_name)
                if member_asset is None and isinstance(item, dict):
                    m_uid = str(item.get("uid") or "")
                    m_name = str(item.get("name") or "")
                    if m_uid and m_name:
                        member_asset = Asset.from_cp_dict(
                            asset.mgmt_name,
                            asset.domain_name,
                            {
                                **item,
                                "type": str(item.get("type") or "cluster-member"),
                                "parent_uid": asset.uid,
                                "parent_name": asset.name,
                            },
                        )
                        _store_cluster(member_asset)

                if member_asset is not None and not _is_excluded_cluster_member(member_asset):
                    upd_parent, upd_member, _ = _link_parent_and_child_assets(
                        by_uid[asset.uid], member_asset, list_kind="cluster"
                    )
                    _store_cluster(upd_member)
                    _store_cluster(upd_parent)
                    discovered_member_uids = list(upd_parent.member_uids)
                    discovered_member_asset_ids = list(upd_parent.member_asset_ids)

            for m_uid in discovered_member_uids:
                m_obj = by_uid.get(m_uid)
                if m_obj is not None and not _is_excluded_cluster_member(m_obj):
                    if not m_obj.parent_uid:
                        upd_parent, upd_member, changed = _link_parent_and_child_assets(
                            by_uid[asset.uid], m_obj, list_kind="cluster"
                        )
                        if changed:
                            _store_cluster(upd_member)
                            _store_cluster(upd_parent)
                            m_obj = upd_member
                    if m_obj.asset_id not in discovered_member_asset_ids:
                        discovered_member_asset_ids.append(m_obj.asset_id)

            curr_asset = by_uid[asset.uid]
            if (
                discovered_member_uids != curr_asset.member_uids
                or discovered_member_asset_ids != curr_asset.member_asset_ids
            ):
                _store_cluster(
                    curr_asset.model_copy(
                        update={
                            "member_uids": discovered_member_uids,
                            "member_asset_ids": discovered_member_asset_ids,
                        }
                    )
                )

        for asset in list(by_uid.values()):
            curr_asset = by_uid[asset.uid]
            parent_asset: Asset | None = by_uid.get(curr_asset.parent_uid) if curr_asset.parent_uid else None
            if parent_asset is None and not curr_asset.parent_uid:
                raw = curr_asset.raw_data
                cluster_ref = raw.get("cluster") or raw.get("cluster-uid") or raw.get("parent-cluster")
                parent_asset = _resolve_local_asset_ref(cluster_ref, by_uid, by_name)

            if (
                parent_asset is not None
                and curr_asset.type not in VSX_CHILD_TYPES
                and parent_asset.uid != curr_asset.uid
                and parent_asset.id != curr_asset.id
            ):
                upd_parent, upd_member, changed = _link_parent_and_child_assets(
                    by_uid[parent_asset.uid], curr_asset, list_kind="cluster"
                )
                if changed:
                    _store_cluster(upd_member)
                    _store_cluster(upd_parent)

        for asset in list(by_uid.values()):
            curr_asset = by_uid[asset.uid]
            if not curr_asset.parent_uid or curr_asset.type in VSX_CHILD_TYPES:
                continue
            parent_asset = by_uid.get(curr_asset.parent_uid)
            if parent_asset is None:
                continue
            if (
                curr_asset.uid in parent_asset.member_uids
                or curr_asset.type in CLUSTER_MEMBER_TYPES
                or "member" in curr_asset.type.lower()
            ):
                enriched_member = _enrich_cluster_member_from_parent(parent_asset, curr_asset)
                if enriched_member is not curr_asset:
                    _store_cluster(enriched_member)

        return list(by_uid.values())


class VSXRelationshipManager:
    """Resolves VSX gateway/cluster and virtual system relationships using encapsulated `generic-object` queries."""

    def __init__(self, api: ApiPort) -> None:
        self._api = api

    def _merge_generic_vsx_objects(
        self,
        mgmt_name: str,
        domain_name: str,
        non_slot_objects: Sequence[dict[str, Any]],
        by_uid: dict[str, Asset],
        by_name: dict[str, Asset],
    ) -> None:
        """Merge non-slot generic VSX objects onto existing assets or synthesize missing VS assets."""
        for g_obj in non_slot_objects:
            g_uid = str(g_obj.get("uid") or "")
            g_name = str(g_obj.get("name") or "")
            if not g_uid:
                continue
            existing = by_uid.get(g_uid) or (by_name.get(g_name) if g_name else None)
            if existing is not None:
                merged_raw = dict(g_obj)
                merged_raw.update(existing.raw_data)
                for key in _GENERIC_TOPOLOGY_MERGE_KEYS:
                    if key in g_obj and g_obj[key] is not None and merged_raw.get(key) in (None, [], {}, ""):
                        merged_raw[key] = g_obj[key]
                updated = existing.model_copy(update={"raw_data": merged_raw})
                updated, _ = _merge_vs_slot_data(updated, g_obj)
                by_uid[updated.uid] = updated
                by_name[updated.name] = updated
            elif g_name:
                g_type = str(g_obj.get("type") or g_obj.get("class-name") or "virtual-system")
                if "CpmiVsNetobj" in g_type or "CpmiVsClusterNetobj" in g_type:
                    g_type = "virtual-system"
                synthesized = Asset.from_cp_dict(mgmt_name, domain_name, {**g_obj, "type": g_type})
                synthesized, _ = _merge_vs_slot_data(synthesized, g_obj)
                by_uid[synthesized.uid] = synthesized
                by_name[synthesized.name] = synthesized

    def _attach_vsx_slot_objects(
        self,
        domain_name: str,
        slot_objects: Sequence[dict[str, Any]],
        by_uid: dict[str, Asset],
        by_name: dict[str, Asset],
    ) -> None:
        """Attach `CpmiVsxSlotObj` (`vsid == 0`) and `CpmiVsSlotObj` (`vsid > 0`) records to VSX/VS assets."""
        slot0_uid_to_parent_uid: dict[str, str] = {}

        def _resolve_slot_parent(slot_obj: dict[str, Any]) -> Asset | None:
            vsx_ref = (
                slot_obj.get("vsxGateway")
                or slot_obj.get("vsx-gateway")
                or slot_obj.get("vsx_gateway")
                or slot_obj.get("parent")
                or slot_obj.get("contained-in")
            )
            if isinstance(vsx_ref, str) and vsx_ref:
                if vsx_ref in by_uid:
                    return by_uid[vsx_ref]
                if vsx_ref in slot0_uid_to_parent_uid:
                    return by_uid.get(slot0_uid_to_parent_uid[vsx_ref])
                if vsx_ref in by_name:
                    return by_name[vsx_ref]
            elif isinstance(vsx_ref, dict):
                p_uid = str(vsx_ref.get("uid") or "")
                p_name = str(vsx_ref.get("name") or "")
                if p_uid and p_uid in by_uid:
                    return by_uid[p_uid]
                if p_uid and p_uid in slot0_uid_to_parent_uid:
                    return by_uid.get(slot0_uid_to_parent_uid[p_uid])
                if p_name and p_name in by_name:
                    return by_name[p_name]
            slot_name = str(slot_obj.get("name") or "")
            if _is_vsx_slot0_object(slot_obj) and slot_name and slot_name in by_name:
                return by_name[slot_name]
            vsx_parents = [
                a
                for a in by_uid.values()
                if a.type in VSX_PARENT_TYPES or ("vsx" in a.type.lower() and "member" not in a.type.lower())
            ]
            return vsx_parents[0] if len(vsx_parents) == 1 else None

        for slot_obj in slot_objects:
            if not _is_vsx_slot0_object(slot_obj):
                continue
            parent_vsx = _resolve_slot_parent(slot_obj)
            if parent_vsx is not None:
                s_uid = str(slot_obj.get("uid") or "")
                if s_uid:
                    slot0_uid_to_parent_uid[s_uid] = parent_vsx.uid
                curr_parent = by_uid[parent_vsx.uid]
                raw_copy = dict(curr_parent.raw_data)
                raw_copy["vsx_slot0"] = slot_obj
                updated_parent = curr_parent.model_copy(update={"raw_data": raw_copy})
                by_uid[updated_parent.uid] = updated_parent
                by_name[updated_parent.name] = updated_parent

        for slot_obj in slot_objects:
            if _is_vsx_slot0_object(slot_obj):
                continue
            parent_vsx = _resolve_slot_parent(slot_obj)
            slot_name, target_domain = _parse_vs_slot_metadata(slot_obj)

            if parent_vsx is not None:
                curr_parent = by_uid[parent_vsx.uid]
                raw_copy = dict(curr_parent.raw_data)
                existing_slots = list(raw_copy.get("vs_slots") or [])
                slot_key = str(slot_obj.get("uid") or slot_name)
                if not any(str(s.get("uid") or s.get("name") or "") == slot_key for s in existing_slots):
                    existing_slots.append(slot_obj)
                raw_copy["vs_slots"] = existing_slots
                updated_parent = curr_parent.model_copy(update={"raw_data": raw_copy})
                by_uid[updated_parent.uid] = updated_parent
                by_name[updated_parent.name] = updated_parent

            if not target_domain or target_domain == domain_name:
                vs_candidate = by_name.get(slot_name) if slot_name else None
                if vs_candidate is None and parent_vsx is not None and slot_name.startswith(f"{parent_vsx.name}_"):
                    vs_candidate = by_name.get(slot_name[len(parent_vsx.name) + 1 :])
                if (
                    vs_candidate is not None
                    and not _is_excluded_vsx_child(vs_candidate)
                    and (
                        parent_vsx is None or (vs_candidate.uid != parent_vsx.uid and vs_candidate.id != parent_vsx.id)
                    )
                ):
                    merged_vs, _ = _merge_vs_slot_data(by_uid[vs_candidate.uid], slot_obj)
                    if parent_vsx is not None:
                        updated_parent, merged_vs, _ = _link_parent_and_child_assets(
                            by_uid[parent_vsx.uid], merged_vs, list_kind="vsx"
                        )
                        by_uid[updated_parent.uid] = updated_parent
                        by_name[updated_parent.name] = updated_parent
                    by_uid[merged_vs.uid] = merged_vs
                    by_name[merged_vs.name] = merged_vs

    def _link_vsx_parents_to_children(
        self,
        mgmt_name: str,
        domain_name: str,
        by_uid: dict[str, Asset],
        by_name: dict[str, Asset],
    ) -> None:
        """Link VSX parents to listed virtual systems and populate `virtual_system_asset_ids`."""
        for asset in list(by_uid.values()):
            curr_asset = by_uid[asset.uid]
            raw = curr_asset.raw_data
            raw_vs_list = _unwrap_object_list(
                raw.get("virtual-systems") or raw.get("virtual_systems") or raw.get("virtualSystems")
            )

            for item in raw_vs_list:
                vs_asset = _resolve_local_asset_ref(item, by_uid, by_name)
                if vs_asset is None and isinstance(item, dict):
                    v_uid = str(item.get("uid") or "")
                    v_name = str(item.get("name") or "")
                    item_domain = item.get("domain")
                    item_domain_name = (
                        str(item_domain.get("name") or "") if isinstance(item_domain, dict) else str(item_domain or "")
                    )
                    is_same_domain = not item_domain_name or item_domain_name == domain_name
                    if v_uid and v_name and is_same_domain and v_uid != curr_asset.uid:
                        synthesized = Asset.from_cp_dict(
                            mgmt_name,
                            domain_name,
                            {
                                **item,
                                "type": str(item.get("type") or "virtual-system"),
                                "parent_uid": curr_asset.uid,
                                "parent_name": curr_asset.name,
                            },
                        )
                        if (
                            not _is_excluded_vsx_child(synthesized)
                            and synthesized.uid != curr_asset.uid
                            and synthesized.id != curr_asset.id
                        ):
                            by_uid[synthesized.uid] = synthesized
                            by_name[synthesized.name] = synthesized
                            vs_asset = synthesized

                if (
                    vs_asset is not None
                    and vs_asset.uid != curr_asset.uid
                    and vs_asset.id != curr_asset.id
                    and not _is_excluded_vsx_child(vs_asset)
                ):
                    updated_parent, updated_vs, _ = _link_parent_and_child_assets(
                        by_uid[curr_asset.uid], vs_asset, list_kind="vsx"
                    )
                    by_uid[updated_vs.uid] = updated_vs
                    by_name[updated_vs.name] = updated_vs
                    by_uid[updated_parent.uid] = updated_parent
                    by_name[updated_parent.name] = updated_parent

            curr_parent = by_uid[asset.uid]
            vs_asset_ids = list(curr_parent.virtual_system_asset_ids)
            for v_uid in curr_parent.virtual_system_uids:
                v_obj = by_uid.get(v_uid)
                if v_obj is not None and v_obj.asset_id not in vs_asset_ids:
                    vs_asset_ids.append(v_obj.asset_id)

            if vs_asset_ids != curr_parent.virtual_system_asset_ids:
                updated_parent = curr_parent.model_copy(update={"virtual_system_asset_ids": vs_asset_ids})
                by_uid[updated_parent.uid] = updated_parent
                by_name[updated_parent.name] = updated_parent

    def _link_vsx_children_to_parents(
        self,
        by_uid: dict[str, Asset],
        by_name: dict[str, Asset],
    ) -> None:
        """Link virtual system assets back to their local VSX parent when present."""
        for asset in list(by_uid.values()):
            curr_asset = by_uid[asset.uid]
            if _is_excluded_vsx_child(curr_asset):
                continue
            is_vs = curr_asset.type in VSX_CHILD_TYPES or "virtual-system" in curr_asset.type.lower()
            vsx_ref = _extract_vsx_parent_ref(curr_asset.raw_data, is_vs=is_vs)
            parent_asset: Asset | None = None
            if curr_asset.parent_uid and is_vs:
                parent_asset = by_uid.get(curr_asset.parent_uid)
            if parent_asset is None:
                parent_asset = _resolve_local_asset_ref(vsx_ref, by_uid, by_name)

            if parent_asset is not None and parent_asset.uid != curr_asset.uid and parent_asset.id != curr_asset.id:
                updated_parent, updated_vs, _ = _link_parent_and_child_assets(
                    by_uid[parent_asset.uid], curr_asset, list_kind="vsx"
                )
                by_uid[updated_vs.uid] = updated_vs
                by_name[updated_vs.name] = updated_vs
                by_uid[updated_parent.uid] = updated_parent
                by_name[updated_parent.name] = updated_parent

    async def enrich(
        self,
        mgmt_name: str,
        domain_name: str,
        assets: Sequence[Asset],
    ) -> list[Asset]:
        """Resolve VSX parent-child topology for `assets` in `(mgmt_name, domain_name)`."""
        by_uid: dict[str, Asset] = {a.uid: a for a in assets}
        by_name: dict[str, Asset] = {a.name: a for a in assets}

        has_vsx_candidate = any(
            a.type in VSX_PARENT_TYPES
            or a.type in VSX_CHILD_TYPES
            or "vsx" in a.type.lower()
            or "virtual-system" in a.type.lower()
            or bool(a.raw_data.get("virtual-systems"))
            or bool(a.raw_data.get("vsx-gateway"))
            or bool(a.raw_data.get("vsx"))
            for a in by_uid.values()
        )

        generic_objects: list[dict[str, Any]] = []
        if has_vsx_candidate:
            generic_objects = await self._fetch_vsx_generic_objects(mgmt_name, domain_name)

        non_slot_objects = [g for g in generic_objects if not _is_slot_object(g)]
        slot_objects = [g for g in generic_objects if _is_slot_object(g)]

        self._merge_generic_vsx_objects(mgmt_name, domain_name, non_slot_objects, by_uid, by_name)
        self._attach_vsx_slot_objects(domain_name, slot_objects, by_uid, by_name)
        self._link_vsx_parents_to_children(mgmt_name, domain_name, by_uid, by_name)
        self._link_vsx_children_to_parents(by_uid, by_name)

        return list(by_uid.values())

    def _build_cross_domain_find_by_ref(
        self,
        by_id: dict[str, Asset],
        by_asset_id: dict[str, Asset],
        by_mgmt_uid: dict[tuple[str, str], Asset],
        by_name: dict[str, list[Asset]],
    ) -> Any:
        """Return a lookup closure resolving asset string/dict references within a management server."""

        def _find_by_ref(ref: Any, mgmt_name: str, prefer_vsx_parent: bool = False) -> Asset | None:
            if isinstance(ref, str) and ref:
                if ref in by_id:
                    return by_id[ref]
                if ref in by_asset_id:
                    return by_asset_id[ref]
                if (mgmt_name, ref) in by_mgmt_uid:
                    return by_mgmt_uid[(mgmt_name, ref)]
                candidates = [c for c in by_name.get(ref, []) if c.mgmt_name == mgmt_name]
                if prefer_vsx_parent:
                    vsx_candidates = [
                        c
                        for c in candidates
                        if c.type in VSX_PARENT_TYPES or ("vsx" in c.type.lower() and "member" not in c.type.lower())
                    ]
                    if vsx_candidates:
                        return vsx_candidates[0]
                return candidates[0] if candidates else None
            if isinstance(ref, dict):
                r_uid = str(ref.get("uid") or "")
                r_name = str(ref.get("name") or "")
                r_dom = ref.get("domain")
                r_dom_name = str(r_dom.get("name") or "") if isinstance(r_dom, dict) else str(r_dom or "")
                if r_uid and (mgmt_name, r_uid) in by_mgmt_uid:
                    return by_mgmt_uid[(mgmt_name, r_uid)]
                if r_dom_name and r_name:
                    comp_asset_id = f"{mgmt_name}:{r_dom_name}:{r_name}"
                    if comp_asset_id in by_asset_id:
                        return by_asset_id[comp_asset_id]
                if r_name:
                    return _find_by_ref(r_name, mgmt_name, prefer_vsx_parent=prefer_vsx_parent)
            return None

        return _find_by_ref

    @staticmethod
    def _link_cross_domain_pair(
        by_id: dict[str, Asset],
        by_mgmt_uid: dict[tuple[str, str], Asset],
        by_asset_id: dict[str, Asset],
        modified_ids: set[str],
        parent_id_key: str,
        child_id_key: str,
    ) -> None:
        """Link two indexed assets across domains and record any modified IDs."""
        parent_obj = by_id[parent_id_key]
        child_obj = by_id[child_id_key]
        upd_parent, upd_child, _ = _link_parent_and_child_assets(parent_obj, child_obj, list_kind="vsx")
        if upd_child is not by_id[child_id_key]:
            by_id[upd_child.id] = upd_child
            by_mgmt_uid[(upd_child.mgmt_name, upd_child.uid)] = upd_child
            by_asset_id[upd_child.asset_id] = upd_child
            modified_ids.add(upd_child.id)
        if upd_parent is not by_id[parent_id_key]:
            by_id[upd_parent.id] = upd_parent
            by_mgmt_uid[(upd_parent.mgmt_name, upd_parent.uid)] = upd_parent
            by_asset_id[upd_parent.asset_id] = upd_parent
            modified_ids.add(upd_parent.id)

    def _reconcile_vsx_parents(
        self,
        *,
        by_id: dict[str, Asset],
        by_mgmt_uid: dict[tuple[str, str], Asset],
        by_asset_id: dict[str, Asset],
        modified_ids: set[str],
        find_by_ref: Any,
    ) -> None:
        for asset in list(by_id.values()):
            curr = by_id[asset.id]
            raw = curr.raw_data
            raw_vs_list = _unwrap_object_list(
                raw.get("virtual-systems") or raw.get("virtual_systems") or raw.get("virtualSystems")
            )
            for item in raw_vs_list:
                vs_asset = find_by_ref(item, curr.mgmt_name, prefer_vsx_parent=False)
                if vs_asset is not None and vs_asset.mgmt_name == curr.mgmt_name:
                    self._link_cross_domain_pair(by_id, by_mgmt_uid, by_asset_id, modified_ids, curr.id, vs_asset.id)
            for v_uid in list(by_id[curr.id].virtual_system_uids):
                vs_asset = by_mgmt_uid.get((curr.mgmt_name, v_uid))
                if vs_asset is not None and vs_asset.mgmt_name == curr.mgmt_name:
                    self._link_cross_domain_pair(by_id, by_mgmt_uid, by_asset_id, modified_ids, curr.id, vs_asset.id)

    def _reconcile_vsx_children(
        self,
        *,
        by_id: dict[str, Asset],
        by_mgmt_uid: dict[tuple[str, str], Asset],
        by_asset_id: dict[str, Asset],
        modified_ids: set[str],
        find_by_ref: Any,
    ) -> None:
        for asset in list(by_id.values()):
            curr = by_id[asset.id]
            if _is_excluded_vsx_child(curr):
                continue
            is_vs = curr.type in VSX_CHILD_TYPES or "virtual-system" in curr.type.lower()
            vsx_ref = _extract_vsx_parent_ref(curr.raw_data, is_vs=is_vs)
            parent_asset: Asset | None = None
            if curr.parent_uid and is_vs:
                parent_asset = by_mgmt_uid.get((curr.mgmt_name, curr.parent_uid))
            if parent_asset is None and vsx_ref is not None:
                parent_asset = find_by_ref(vsx_ref, curr.mgmt_name, prefer_vsx_parent=True)
            if parent_asset is None and curr.parent_name and is_vs:
                parent_asset = find_by_ref(curr.parent_name, curr.mgmt_name, prefer_vsx_parent=True)
            if parent_asset is not None and parent_asset.mgmt_name == curr.mgmt_name:
                self._link_cross_domain_pair(by_id, by_mgmt_uid, by_asset_id, modified_ids, parent_asset.id, curr.id)

    def _reconcile_vs_slots(
        self,
        *,
        by_id: dict[str, Asset],
        by_mgmt_uid: dict[tuple[str, str], Asset],
        by_asset_id: dict[str, Asset],
        by_name: dict[str, list[Asset]],
        modified_ids: set[str],
    ) -> None:
        for asset in list(by_id.values()):
            curr_gw = by_id[asset.id]
            vs_slots = curr_gw.raw_data.get("vs_slots")
            if not isinstance(vs_slots, list):
                continue
            for slot in vs_slots:
                if not isinstance(slot, dict):
                    continue
                slot_name, target_domain = _parse_vs_slot_metadata(slot)
                slot_vs_asset: Asset | None = None
                candidate_names = [slot_name] if slot_name else []
                if slot_name.startswith(f"{curr_gw.name}_"):
                    candidate_names.append(slot_name[len(curr_gw.name) + 1 :])

                if target_domain:
                    for cand_name in candidate_names:
                        comp_key = f"{curr_gw.mgmt_name}:{target_domain}:{cand_name}"
                        if comp_key in by_asset_id:
                            slot_vs_asset = by_asset_id[comp_key]
                            break

                if slot_vs_asset is None:
                    for cand_name in candidate_names:
                        matches = [
                            c
                            for c in by_name.get(cand_name, [])
                            if c.mgmt_name == curr_gw.mgmt_name and c.id != curr_gw.id
                        ]
                        if target_domain:
                            dom_matches = [
                                c
                                for c in matches
                                if c.domain_name == target_domain
                                or (
                                    isinstance(c.raw_data.get("domain"), dict)
                                    and str(c.raw_data["domain"].get("uid") or "") == target_domain
                                )
                            ]
                            if dom_matches:
                                slot_vs_asset = dom_matches[0]
                                break
                        elif matches:
                            vs_matches = [
                                c
                                for c in matches
                                if c.type in VSX_CHILD_TYPES or "vs" in c.type.lower() or "virtual" in c.type.lower()
                            ]
                            slot_vs_asset = vs_matches[0] if vs_matches else matches[0]
                            break

                if (
                    slot_vs_asset is not None
                    and slot_vs_asset.mgmt_name == curr_gw.mgmt_name
                    and not _is_excluded_vsx_child(slot_vs_asset)
                    and slot_vs_asset.id != curr_gw.id
                    and slot_vs_asset.uid != curr_gw.uid
                ):
                    self._link_cross_domain_pair(
                        by_id, by_mgmt_uid, by_asset_id, modified_ids, curr_gw.id, slot_vs_asset.id
                    )
                    curr_vs = by_id[slot_vs_asset.id]
                    merged_vs, changed = _merge_vs_slot_data(curr_vs, slot)
                    if changed:
                        by_id[merged_vs.id] = merged_vs
                        by_mgmt_uid[(merged_vs.mgmt_name, merged_vs.uid)] = merged_vs
                        by_asset_id[merged_vs.asset_id] = merged_vs
                        modified_ids.add(merged_vs.id)

    def reconcile_cross_domain(self, assets: Sequence[Asset]) -> list[Asset]:
        """Reconcile VSX parent-child relationships across domains within the same `mgmt_name`.

        Returns only the `Asset` instances whose `parent_uid`, `parent_name`, `parent_id`,
        `parent_asset_id`, `virtual_system_uids`, `virtual_system_asset_ids`, `interfaces`,
        or `raw_data` changed.
        """
        by_id: dict[str, Asset] = {a.id: a for a in assets}
        by_mgmt_uid: dict[tuple[str, str], Asset] = {(a.mgmt_name, a.uid): a for a in assets}
        by_asset_id: dict[str, Asset] = {a.asset_id: a for a in assets}
        by_name: dict[str, list[Asset]] = {}
        for a in assets:
            by_name.setdefault(a.name, []).append(a)

        modified_ids: set[str] = set()
        find_by_ref = self._build_cross_domain_find_by_ref(by_id, by_asset_id, by_mgmt_uid, by_name)

        self._reconcile_vsx_parents(
            by_id=by_id,
            by_mgmt_uid=by_mgmt_uid,
            by_asset_id=by_asset_id,
            modified_ids=modified_ids,
            find_by_ref=find_by_ref,
        )
        self._reconcile_vsx_children(
            by_id=by_id,
            by_mgmt_uid=by_mgmt_uid,
            by_asset_id=by_asset_id,
            modified_ids=modified_ids,
            find_by_ref=find_by_ref,
        )
        self._reconcile_vs_slots(
            by_id=by_id, by_mgmt_uid=by_mgmt_uid, by_asset_id=by_asset_id, by_name=by_name, modified_ids=modified_ids
        )
        return [by_id[mid] for mid in modified_ids]

    async def _fetch_vsx_generic_objects(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> list[dict[str, Any]]:
        """Query encapsulated `show-generic-objects` for VSX classes, ignoring unsupported errors gracefully."""
        collected: list[dict[str, Any]] = []
        for class_name in VSX_GENERIC_OBJECT_CLASSES:
            try:
                q_res = await self._api.api_query(
                    mgmt_name,
                    "show-generic-objects",
                    domain=domain_name,
                    details_level="full",
                    payload={"class-name": class_name},
                )
                if q_res.success and q_res.objects:
                    for obj in q_res.objects:
                        if isinstance(obj, dict):
                            collected.append(obj)
            except ServerIdentityError:
                raise
            except Exception:
                continue
        return collected
