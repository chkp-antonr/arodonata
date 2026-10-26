"""Asset and gateway cache synchronization service (`AssetRefreshService`).

Provides:
- Paired `await refresh_assets(...)` and `stream_refresh_assets(...)` methods.
- Concurrent per-MDS-member domain asset collection via `DomainSyncCoordinator` (`scope="assets"`, `item_type="*"`).
- `ClusterRelationshipManager`: links cluster members (`cluster-member` / `CpmiClusterMember`) to their
  parent cluster (`simple-cluster` / `CpmiGatewayCluster` / `CpmiVsxClusterNetobj`), populating
  `parent_uid`, `parent_name`, `parent_id`, `parent_asset_id`, `member_uids`, and `member_asset_ids`.
- `VSXRelationshipManager`: resolves VSX gateways/clusters and virtual systems (`virtual-system` /
  `CpmiVsNetobj` / `CpmiVsClusterNetobj`) via encapsulated `generic-object` topology queries
  (`show-generic-objects`) and cross-domain MDS reconciliation, populating `parent_uid`, `parent_name`,
  `parent_id`, `parent_asset_id`, `virtual_system_uids`, and `virtual_system_asset_ids`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from datetime import datetime
from typing import Any

from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import ServerIdentityError
from arodonata.core.events import DomainSyncProgressEvent, SyncProgressEvent
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CacheMode, to_naive_utc, utc_now
from arodonata.core.models.domains import DomainSyncState, RefreshOutcome
from arodonata.core.ports import ApiPort, CachePort
from arodonata.core.services.sync_coordinator import DomainProbeResult, DomainSyncCoordinator
from arodonata.core.telemetry import span_attrs, traced

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
)


class ClusterRelationshipManager:
    """Enriches parent-child relationships between Check Point clusters and cluster members."""

    def enrich(self, assets: Sequence[Asset]) -> list[Asset]:
        """Link cluster members to their parent clusters and return updated `Asset` models."""
        by_uid: dict[str, Asset] = {a.uid: a for a in assets}
        by_name: dict[str, Asset] = {a.name: a for a in assets}

        # First pass: inspect parent clusters that list their members in raw_data or member_uids
        for asset in list(by_uid.values()):
            raw = asset.raw_data
            raw_members = (
                raw.get("cluster-member-names")
                or raw.get("cluster-members")
                or raw.get("members")
                or raw.get("cluster_members")
            )
            discovered_member_uids: list[str] = list(asset.member_uids)
            discovered_member_asset_ids: list[str] = list(asset.member_asset_ids)

            if isinstance(raw_members, dict) and isinstance(raw_members.get("objects"), list):
                raw_members = raw_members["objects"]

            if isinstance(raw_members, list):
                for item in raw_members:
                    member_asset: Asset | None = None
                    if isinstance(item, str):
                        member_asset = by_uid.get(item) or by_name.get(item)
                    elif isinstance(item, dict):
                        m_uid = str(item.get("uid") or "")
                        m_name = str(item.get("name") or "")
                        member_asset = (by_uid.get(m_uid) if m_uid else None) or (
                            by_name.get(m_name) if m_name else None
                        )
                        if member_asset is None and m_uid and m_name:
                            # Synthesize a cluster-member asset if embedded inside the cluster payload
                            synthesized = Asset.from_cp_dict(
                                asset.mgmt_name,
                                asset.domain_name,
                                {
                                    **item,
                                    "type": str(item.get("type") or "cluster-member"),
                                    "parent_uid": asset.uid,
                                    "parent_name": asset.name,
                                },
                            )
                            by_uid[synthesized.uid] = synthesized
                            by_name[synthesized.name] = synthesized
                            member_asset = synthesized

                    if member_asset is not None:
                        if member_asset.uid not in discovered_member_uids:
                            discovered_member_uids.append(member_asset.uid)
                        if member_asset.asset_id not in discovered_member_asset_ids:
                            discovered_member_asset_ids.append(member_asset.asset_id)
                        updated_member = member_asset.model_copy(
                            update={
                                "parent_uid": asset.uid,
                                "parent_name": asset.name,
                                "parent_id": asset.id,
                                "parent_asset_id": asset.asset_id,
                            }
                        )
                        by_uid[updated_member.uid] = updated_member
                        by_name[updated_member.name] = updated_member

            for m_uid in discovered_member_uids:
                m_obj = by_uid.get(m_uid)
                if m_obj is not None and m_obj.asset_id not in discovered_member_asset_ids:
                    discovered_member_asset_ids.append(m_obj.asset_id)

            if discovered_member_uids != asset.member_uids or discovered_member_asset_ids != asset.member_asset_ids:
                updated_cluster = by_uid[asset.uid].model_copy(
                    update={
                        "member_uids": discovered_member_uids,
                        "member_asset_ids": discovered_member_asset_ids,
                    }
                )
                by_uid[updated_cluster.uid] = updated_cluster
                by_name[updated_cluster.name] = updated_cluster

        # Second pass: inspect cluster members that reference their parent cluster in raw_data
        for asset in list(by_uid.values()):
            if asset.parent_uid:
                parent = by_uid.get(asset.parent_uid)
                if parent is not None:
                    if asset.parent_id != parent.id or asset.parent_asset_id != parent.asset_id:
                        updated_member = asset.model_copy(
                            update={
                                "parent_name": parent.name,
                                "parent_id": parent.id,
                                "parent_asset_id": parent.asset_id,
                            }
                        )
                        by_uid[updated_member.uid] = updated_member
                        by_name[updated_member.name] = updated_member
                    new_member_uids = list(parent.member_uids)
                    new_member_asset_ids = list(parent.member_asset_ids)
                    if asset.uid not in new_member_uids:
                        new_member_uids.append(asset.uid)
                    if asset.asset_id not in new_member_asset_ids:
                        new_member_asset_ids.append(asset.asset_id)
                    if new_member_uids != parent.member_uids or new_member_asset_ids != parent.member_asset_ids:
                        updated_parent = parent.model_copy(
                            update={
                                "member_uids": new_member_uids,
                                "member_asset_ids": new_member_asset_ids,
                            }
                        )
                        by_uid[updated_parent.uid] = updated_parent
                        by_name[updated_parent.name] = updated_parent
                continue

            raw = asset.raw_data
            cluster_ref = raw.get("cluster") or raw.get("cluster-uid") or raw.get("parent-cluster")
            parent_asset: Asset | None = None
            if isinstance(cluster_ref, str) and cluster_ref:
                parent_asset = by_uid.get(cluster_ref) or by_name.get(cluster_ref)
            elif isinstance(cluster_ref, dict):
                c_uid = str(cluster_ref.get("uid") or "")
                c_name = str(cluster_ref.get("name") or "")
                parent_asset = (by_uid.get(c_uid) if c_uid else None) or (by_name.get(c_name) if c_name else None)

            if parent_asset is not None:
                updated_member = asset.model_copy(
                    update={
                        "parent_uid": parent_asset.uid,
                        "parent_name": parent_asset.name,
                        "parent_id": parent_asset.id,
                        "parent_asset_id": parent_asset.asset_id,
                    }
                )
                by_uid[updated_member.uid] = updated_member
                by_name[updated_member.name] = updated_member
                curr_parent = by_uid[parent_asset.uid]
                new_member_uids = list(curr_parent.member_uids)
                new_member_asset_ids = list(curr_parent.member_asset_ids)
                if updated_member.uid not in new_member_uids:
                    new_member_uids.append(updated_member.uid)
                if updated_member.asset_id not in new_member_asset_ids:
                    new_member_asset_ids.append(updated_member.asset_id)
                if new_member_uids != curr_parent.member_uids or new_member_asset_ids != curr_parent.member_asset_ids:
                    updated_parent = curr_parent.model_copy(
                        update={
                            "member_uids": new_member_uids,
                            "member_asset_ids": new_member_asset_ids,
                        }
                    )
                    by_uid[updated_parent.uid] = updated_parent
                    by_name[updated_parent.name] = updated_parent

        return list(by_uid.values())


class VSXRelationshipManager:
    """Resolves VSX gateway/cluster and virtual system relationships using encapsulated `generic-object` queries."""

    def __init__(self, api: ApiPort) -> None:
        self._api = api

    async def enrich(
        self,
        mgmt_name: str,
        domain_name: str,
        assets: Sequence[Asset],
    ) -> list[Asset]:
        """Resolve VSX parent-child topology for `assets` in `(mgmt_name, domain_name)`."""
        by_uid: dict[str, Asset] = {a.uid: a for a in assets}
        by_name: dict[str, Asset] = {a.name: a for a in assets}

        # Check if any VSX gateway/cluster or virtual system exists or if generic-objects provide VSX links
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

        # Merge any generic-object VSX metadata onto matching assets (or create missing virtual system assets)
        for g_obj in generic_objects:
            g_uid = str(g_obj.get("uid") or "")
            g_name = str(g_obj.get("name") or "")
            if not g_uid:
                continue
            existing = by_uid.get(g_uid)
            if existing is not None:
                merged_raw = dict(g_obj)
                merged_raw.update(existing.raw_data)
                # Keep generic-object topology keys if missing in standard show-gateways-and-servers
                for k in ("virtual-systems", "virtual_systems", "vsx-gateway", "vsx_gateway", "parent", "contained-in"):
                    if k in g_obj and k not in merged_raw:
                        merged_raw[k] = g_obj[k]
                updated = existing.model_copy(update={"raw_data": merged_raw})
                by_uid[g_uid] = updated
                by_name[updated.name] = updated
            elif g_name:
                g_type = str(g_obj.get("type") or g_obj.get("class-name") or "virtual-system")
                if "CpmiVsNetobj" in g_type or "CpmiVsClusterNetobj" in g_type:
                    g_type = "virtual-system"
                synthesized = Asset.from_cp_dict(
                    mgmt_name,
                    domain_name,
                    {**g_obj, "type": g_type},
                )
                by_uid[synthesized.uid] = synthesized
                by_name[synthesized.name] = synthesized

        # First pass: link from VSX parent (`virtual-systems` / `virtual_system_uids`) -> virtual systems
        for asset in list(by_uid.values()):
            raw = asset.raw_data
            raw_vs_list = raw.get("virtual-systems") or raw.get("virtual_systems") or raw.get("virtualSystems")
            vs_uids: list[str] = list(asset.virtual_system_uids)
            vs_asset_ids: list[str] = list(asset.virtual_system_asset_ids)

            if isinstance(raw_vs_list, dict) and isinstance(raw_vs_list.get("objects"), list):
                raw_vs_list = raw_vs_list["objects"]

            if isinstance(raw_vs_list, list):
                for item in raw_vs_list:
                    vs_asset: Asset | None = None
                    if isinstance(item, str):
                        vs_asset = by_uid.get(item) or by_name.get(item)
                    elif isinstance(item, dict):
                        v_uid = str(item.get("uid") or "")
                        v_name = str(item.get("name") or "")
                        vs_asset = (by_uid.get(v_uid) if v_uid else None) or (by_name.get(v_name) if v_name else None)
                        item_domain = item.get("domain")
                        item_domain_name = (
                            str(item_domain.get("name") or "")
                            if isinstance(item_domain, dict)
                            else str(item_domain or "")
                        )
                        is_same_domain = not item_domain_name or item_domain_name == domain_name
                        if vs_asset is None and v_uid and v_name and is_same_domain:
                            synthesized = Asset.from_cp_dict(
                                mgmt_name,
                                domain_name,
                                {
                                    **item,
                                    "type": str(item.get("type") or "virtual-system"),
                                    "parent_uid": asset.uid,
                                    "parent_name": asset.name,
                                },
                            )
                            by_uid[synthesized.uid] = synthesized
                            by_name[synthesized.name] = synthesized
                            vs_asset = synthesized

                    if vs_asset is not None:
                        if vs_asset.uid not in vs_uids:
                            vs_uids.append(vs_asset.uid)
                        if vs_asset.asset_id not in vs_asset_ids:
                            vs_asset_ids.append(vs_asset.asset_id)
                        updated_vs = vs_asset.model_copy(
                            update={
                                "parent_uid": asset.uid,
                                "parent_name": asset.name,
                                "parent_id": asset.id,
                                "parent_asset_id": asset.asset_id,
                            }
                        )
                        by_uid[updated_vs.uid] = updated_vs
                        by_name[updated_vs.name] = updated_vs

            for v_uid in vs_uids:
                v_obj = by_uid.get(v_uid)
                if v_obj is not None and v_obj.asset_id not in vs_asset_ids:
                    vs_asset_ids.append(v_obj.asset_id)

            if vs_uids != asset.virtual_system_uids or vs_asset_ids != asset.virtual_system_asset_ids:
                updated_parent = by_uid[asset.uid].model_copy(
                    update={
                        "virtual_system_uids": vs_uids,
                        "virtual_system_asset_ids": vs_asset_ids,
                    }
                )
                by_uid[updated_parent.uid] = updated_parent
                by_name[updated_parent.name] = updated_parent

        # Second pass: link from virtual system (`vsx-gateway` / `parent` / `contained-in`) -> VSX parent
        for asset in list(by_uid.values()):
            is_vs = asset.type in VSX_CHILD_TYPES or "virtual-system" in asset.type.lower()
            raw = asset.raw_data
            vsx_ref = (
                raw.get("vsx-gateway")
                or raw.get("vsx_gateway")
                or raw.get("vsx-cluster")
                or raw.get("contained-in")
                or (raw.get("parent") if is_vs else None)
            )
            parent_asset: Asset | None = None
            if asset.parent_uid and is_vs:
                parent_asset = by_uid.get(asset.parent_uid)
            elif isinstance(vsx_ref, str) and vsx_ref:
                parent_asset = by_uid.get(vsx_ref) or by_name.get(vsx_ref)
            elif isinstance(vsx_ref, dict):
                p_uid = str(vsx_ref.get("uid") or "")
                p_name = str(vsx_ref.get("name") or "")
                parent_asset = (by_uid.get(p_uid) if p_uid else None) or (by_name.get(p_name) if p_name else None)

            if parent_asset is not None:
                updated_vs = asset.model_copy(
                    update={
                        "parent_uid": parent_asset.uid,
                        "parent_name": parent_asset.name,
                        "parent_id": parent_asset.id,
                        "parent_asset_id": parent_asset.asset_id,
                    }
                )
                by_uid[updated_vs.uid] = updated_vs
                by_name[updated_vs.name] = updated_vs
                curr_parent = by_uid[parent_asset.uid]
                new_vs_uids = list(curr_parent.virtual_system_uids)
                new_vs_asset_ids = list(curr_parent.virtual_system_asset_ids)
                if updated_vs.uid not in new_vs_uids:
                    new_vs_uids.append(updated_vs.uid)
                if updated_vs.asset_id not in new_vs_asset_ids:
                    new_vs_asset_ids.append(updated_vs.asset_id)
                if (
                    new_vs_uids != curr_parent.virtual_system_uids
                    or new_vs_asset_ids != curr_parent.virtual_system_asset_ids
                ):
                    updated_parent = curr_parent.model_copy(
                        update={
                            "virtual_system_uids": new_vs_uids,
                            "virtual_system_asset_ids": new_vs_asset_ids,
                        }
                    )
                    by_uid[updated_parent.uid] = updated_parent
                    by_name[updated_parent.name] = updated_parent

        return list(by_uid.values())

    def reconcile_cross_domain(self, assets: Sequence[Asset]) -> list[Asset]:
        """Reconcile VSX parent-child relationships across domains within the same `mgmt_name`.

        Returns only the `Asset` instances whose `parent_uid`, `parent_name`, `parent_id`,
        `parent_asset_id`, `virtual_system_uids`, or `virtual_system_asset_ids` changed.
        """
        by_id: dict[str, Asset] = {a.id: a for a in assets}
        by_uid: dict[str, Asset] = {a.uid: a for a in assets}
        by_asset_id: dict[str, Asset] = {a.asset_id: a for a in assets}
        by_name: dict[str, list[Asset]] = {}
        for a in assets:
            by_name.setdefault(a.name, []).append(a)

        modified_ids: set[str] = set()

        def _find_by_ref(ref: Any, mgmt_name: str, prefer_vsx_parent: bool = False) -> Asset | None:
            if isinstance(ref, str) and ref:
                if ref in by_id:
                    return by_id[ref]
                if ref in by_asset_id:
                    return by_asset_id[ref]
                if ref in by_uid:
                    return by_uid[ref]
                candidates = [c for c in by_name.get(ref, []) if c.mgmt_name == mgmt_name]
                if prefer_vsx_parent:
                    vsx_candidates = [c for c in candidates if c.type in VSX_PARENT_TYPES or "vsx" in c.type.lower()]
                    if vsx_candidates:
                        return vsx_candidates[0]
                return candidates[0] if candidates else None
            if isinstance(ref, dict):
                r_uid = str(ref.get("uid") or "")
                r_name = str(ref.get("name") or "")
                r_dom = ref.get("domain")
                r_dom_name = str(r_dom.get("name") or "") if isinstance(r_dom, dict) else str(r_dom or "")
                if r_uid and r_uid in by_uid:
                    return by_uid[r_uid]
                if r_dom_name and r_name:
                    comp_asset_id = f"{mgmt_name}:{r_dom_name}:{r_name}"
                    if comp_asset_id in by_asset_id:
                        return by_asset_id[comp_asset_id]
                if r_name:
                    return _find_by_ref(r_name, mgmt_name, prefer_vsx_parent=prefer_vsx_parent)
            return None

        def _link(parent_id_key: str, child_id_key: str) -> None:
            parent = by_id[parent_id_key]
            child = by_id[child_id_key]
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
                by_id[updated_child.id] = updated_child
                by_uid[updated_child.uid] = updated_child
                by_asset_id[updated_child.asset_id] = updated_child
                modified_ids.add(updated_child.id)
                child = updated_child

            new_vs_uids = list(parent.virtual_system_uids)
            new_vs_asset_ids = list(parent.virtual_system_asset_ids)
            if child.uid not in new_vs_uids:
                new_vs_uids.append(child.uid)
            if child.asset_id not in new_vs_asset_ids:
                new_vs_asset_ids.append(child.asset_id)
            if new_vs_uids != parent.virtual_system_uids or new_vs_asset_ids != parent.virtual_system_asset_ids:
                updated_parent = parent.model_copy(
                    update={
                        "virtual_system_uids": new_vs_uids,
                        "virtual_system_asset_ids": new_vs_asset_ids,
                    }
                )
                by_id[updated_parent.id] = updated_parent
                by_uid[updated_parent.uid] = updated_parent
                by_asset_id[updated_parent.asset_id] = updated_parent
                modified_ids.add(updated_parent.id)

        # Pass 1: VSX parent -> virtual systems across domains
        for asset in list(by_id.values()):
            raw = asset.raw_data
            raw_vs_list = raw.get("virtual-systems") or raw.get("virtual_systems") or raw.get("virtualSystems")
            if isinstance(raw_vs_list, dict) and isinstance(raw_vs_list.get("objects"), list):
                raw_vs_list = raw_vs_list["objects"]
            if isinstance(raw_vs_list, list):
                for item in raw_vs_list:
                    vs_asset = _find_by_ref(item, asset.mgmt_name, prefer_vsx_parent=False)
                    if vs_asset is not None and vs_asset.mgmt_name == asset.mgmt_name:
                        _link(asset.id, vs_asset.id)
            for v_uid in list(asset.virtual_system_uids):
                vs_asset = by_uid.get(v_uid)
                if vs_asset is not None and vs_asset.mgmt_name == asset.mgmt_name:
                    _link(asset.id, vs_asset.id)

        # Pass 2: Virtual system -> VSX parent across domains
        for asset in list(by_id.values()):
            is_vs = asset.type in VSX_CHILD_TYPES or "virtual-system" in asset.type.lower()
            raw = asset.raw_data
            vsx_ref = (
                raw.get("vsx-gateway")
                or raw.get("vsx_gateway")
                or raw.get("vsx-cluster")
                or raw.get("contained-in")
                or (raw.get("parent") if is_vs else None)
            )
            parent_asset: Asset | None = None
            if asset.parent_uid and is_vs:
                parent_asset = by_uid.get(asset.parent_uid)
            if parent_asset is None and vsx_ref is not None:
                parent_asset = _find_by_ref(vsx_ref, asset.mgmt_name, prefer_vsx_parent=True)
            if parent_asset is None and asset.parent_name and is_vs:
                parent_asset = _find_by_ref(asset.parent_name, asset.mgmt_name, prefer_vsx_parent=True)

            if parent_asset is not None and parent_asset.mgmt_name == asset.mgmt_name:
                _link(parent_asset.id, asset.id)

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


class AssetRefreshService:
    """Synchronizes and queries cached gateway, cluster, VSX, and management server assets (`assets`)."""

    def __init__(
        self,
        *,
        settings: ArodonataSettings,
        api: ApiPort,
        cache: CachePort,
        coordinator: DomainSyncCoordinator,
        cluster_manager: ClusterRelationshipManager | None = None,
        vsx_manager: VSXRelationshipManager | None = None,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._settings = settings
        self._api = api
        self._cache = cache
        self._coordinator = coordinator
        self._cluster_manager = cluster_manager or ClusterRelationshipManager()
        self._vsx_manager = vsx_manager or VSXRelationshipManager(api)
        self._now: Callable[[], datetime] = lambda: to_naive_utc(now_fn())

    @property
    def cluster_manager(self) -> ClusterRelationshipManager:
        """Return the `ClusterRelationshipManager`."""
        return self._cluster_manager

    @property
    def vsx_manager(self) -> VSXRelationshipManager:
        """Return the `VSXRelationshipManager`."""
        return self._vsx_manager

    async def _reconcile_cross_domain_vsx(self, mgmt_name: str | None) -> None:
        """Reconcile cross-domain VSX parent/child relationships across cached domains."""
        all_assets = await self._cache.get_assets(mgmt_name=mgmt_name)
        if not all_assets:
            return
        modified = self._vsx_manager.reconcile_cross_domain(all_assets)
        if modified:
            await self._cache.upsert_assets(modified)

    async def stream_refresh_assets(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while refreshing gateway/cluster/VSX assets across domains."""
        async for event in self._coordinator.stream_ensure(
            scope="assets",
            item_types=["*"],
            handler=self._sync_domain_assets,
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            if event.event_type == "sync_completed":
                await self._reconcile_cross_domain_vsx(mgmt_name)
            yield event

    @traced
    async def refresh_assets(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Refresh gateway/cluster/VSX assets across domains and return `RefreshOutcome`."""
        span_attrs(mgmt_name=mgmt_name, mode=mode, include_global=include_global)
        outcome = await self._coordinator.ensure(
            scope="assets",
            item_types=["*"],
            handler=self._sync_domain_assets,
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )
        await self._reconcile_cross_domain_vsx(mgmt_name)
        return outcome

    async def _sync_domain_assets(
        self,
        probe: DomainProbeResult,
        emit: Callable[[SyncProgressEvent], Awaitable[None]],
    ) -> int:
        mgmt_name = probe.mgmt_name
        dom_name = probe.domain.name

        q_res = await self._api.api_query(
            mgmt_name,
            "show-gateways-and-servers",
            domain=dom_name,
            details_level="full",
        )
        if not q_res.success:
            raise RuntimeError(
                f"Failed to query gateways and servers on {mgmt_name}:{dom_name}: "
                f"{q_res.error_message or q_res.code or 'query failed'}"
            )

        raw_assets: list[Asset] = []
        for raw in q_res.objects:
            if isinstance(raw, dict) and raw.get("uid"):
                raw_assets.append(Asset.from_cp_dict(mgmt_name, dom_name, raw))

        await emit(
            DomainSyncProgressEvent(
                scope="assets",
                mgmt_name=mgmt_name,
                domain=dom_name,
                item_type="gateways-and-servers",
                processed=len(raw_assets),
                total=len(raw_assets),
                message=f"Fetched {len(raw_assets)} raw asset(s) from {mgmt_name}:{dom_name}; resolving relationships.",
            )
        )

        # Enrich cluster and VSX relationships
        cluster_enriched = self._cluster_manager.enrich(raw_assets)
        fully_enriched = await self._vsx_manager.enrich(mgmt_name, dom_name, cluster_enriched)

        now = self._now()
        sync_state = DomainSyncState(
            mgmt_name=mgmt_name,
            domain_name=dom_name,
            scope="assets",
            item_type="*",
            last_published_at=probe.remote_published_at,
            last_session_uid=probe.remote_session_uid,
            synced_at=now,
            status="ok",
            object_count=len(fully_enriched),
            last_error=None,
        )
        await self._cache.replace_domain_assets(
            mgmt_name,
            dom_name,
            fully_enriched,
            sync_states=[sync_state],
        )
        await self._reconcile_cross_domain_vsx(mgmt_name)
        return len(fully_enriched)

    @traced
    async def get_assets(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        types: Sequence[str] | None = None,
        include_global: bool = False,
        cache_mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> list[Asset]:
        """Ensure assets are fresh (unless `cache_mode="cache"`), then return cached `Asset` models."""
        if cache_mode != "cache":
            await self.refresh_assets(
                mgmt_name=mgmt_name,
                domains=[domain] if domain else None,
                include_global=include_global or (domain == "Global"),
                mode=cache_mode,
                cache_ttl=cache_ttl,
            )

        assets = await self._cache.get_assets(
            mgmt_name=mgmt_name,
            domain_name=domain,
            types=types,
        )
        if not include_global and domain is None:
            assets = [a for a in assets if a.domain_name != "Global"]
        return assets


__all__ = [
    "AssetRefreshService",
    "ClusterRelationshipManager",
    "VSXRelationshipManager",
]
