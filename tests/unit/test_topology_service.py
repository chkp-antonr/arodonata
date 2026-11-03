"""Unit tests for `TopologyService`: interface topology extraction, group expansion, VS static routes, and affected gateway candidate matching."""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainInfo
from arodonata.core.models.rulebase import (
    DomainRulebaseSnapshot,
    RulebaseLayerEntry,
    RulebasePackageLayerEntry,
)
from arodonata.core.services import (
    AssetRefreshService,
    DomainService,
    DomainSyncCoordinator,
    ObjectService,
    SearchService,
    TopologyService,
)


class TopologyFakeApi:
    """In-memory `ApiPort` double for `TopologyService` unit tests."""

    def __init__(self) -> None:
        self.gateways_by_domain: dict[str, list[dict[str, Any]]] = {
            "Corp": [
                # Cluster object (policy-enforcing) with interfaces omitted in summary to test on-demand detail call
                {
                    "uid": "cl-corp-1",
                    "name": "corp-perimeter-cluster",
                    "type": "CpmiGatewayCluster",
                    "ipv4-address": "10.10.0.1",
                    "policy": {
                        "access-policy-installed": True,
                        "access-policy-name": "Perimeter_Pkg",
                    },
                },
                # Cluster member (must be skipped!)
                {
                    "uid": "cm-corp-1a",
                    "name": "corp-perimeter-1a",
                    "type": "cluster-member",
                    "ipv4-address": "10.10.0.2",
                    "interfaces": [
                        {
                            "interface-name": "eth1",
                            "ipv4-address": "10.99.99.2",
                            "ipv4-mask-length": 24,
                            "topology": {
                                "leads-to-internet": False,
                                "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                            },
                        }
                    ],
                },
                # Management host (must be skipped!)
                {
                    "uid": "mgmt-host-1",
                    "name": "mds-corp",
                    "type": "checkpoint-host",
                    "ipv4-address": "10.0.0.1",
                },
                # Unrelated branch gateway (has internal 192.168.50.0/24 on eth1 and external on eth0)
                {
                    "uid": "gw-branch-1",
                    "name": "branch-gw-01",
                    "type": "simple-gateway",
                    "ipv4-address": "192.168.50.1",
                    "policy": {
                        "access-policy-installed": True,
                        "access-policy-name": "Branch_Pkg",
                    },
                    "interfaces": [
                        {
                            "interface-name": "eth0",
                            "ipv4-address": "198.51.100.2",
                            "ipv4-mask-length": 29,
                            "topology": {
                                "leads-to-internet": True,
                                "ip-address-behind-this-interface": "not defined",
                            },
                        },
                        {
                            "interface-name": "eth1",
                            "ipv4-address": "192.168.50.1",
                            "ipv4-mask-length": 24,
                            "topology": {
                                "leads-to-internet": False,
                                "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                            },
                        },
                    ],
                },
            ],
            "DC": [
                # Physical VSX host VS0 (must be skipped!)
                {
                    "uid": "vsx-dc-1",
                    "name": "dc-vsx-chassis",
                    "type": "CpmiVsxNetobj",
                    "ipv4-address": "172.16.0.10",
                    "interfaces": [
                        {
                            "interface-name": "eth0",
                            "ipv4-address": "172.16.0.10",
                            "ipv4-mask-length": 24,
                            "topology": {
                                "leads-to-internet": False,
                                "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                            },
                        }
                    ],
                },
                # Core internal gateway with two internal interfaces and one routing-defined interface
                {
                    "uid": "gw-dc-core",
                    "name": "dc-core-gw",
                    "type": "simple-gateway",
                    "ipv4-address": "10.20.0.1",
                    "policy": {
                        "access-policy-installed": True,
                        "access-policy-name": "Core_Pkg",
                    },
                    "interfaces": [
                        {
                            "interface-name": "bond0.10",
                            "ipv4-address": "10.10.1.254",
                            "ipv4-mask-length": 24,
                            "topology": {
                                "leads-to-internet": False,
                                "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                            },
                        },
                        {
                            "interface-name": "bond0.20",
                            "ipv4-address": "10.20.0.1",
                            "ipv4-mask-length": 24,
                            "topology": {
                                "leads-to-internet": False,
                                "ip-address-behind-this-interface": "specific",
                                "specific-network": "G_DC_Apps",
                            },
                        },
                        {
                            "interface-name": "bond0.99",
                            "ipv4-address": "10.99.0.1",
                            "ipv4-mask-length": 30,
                            "topology": {
                                "leads-to-internet": False,
                                "ip-address-behind-this-interface": "network defined by routing",
                            },
                        },
                    ],
                },
            ],
            "TenantVS": [
                # VSX Virtual System with static routes via CpmiVsSlotObj in DC domain
                {
                    "uid": "vs-tenant-1",
                    "name": "vsx1_VS_Tenant",
                    "type": "CpmiVsNetobj",
                    "ipv4-address": "10.50.0.1",
                    "policy": {
                        "access-policy-installed": True,
                        "access-policy-name": "Tenant_VS_Policy",
                    },
                }
            ],
        }

        self.cluster_details_by_uid: dict[str, dict[str, Any]] = {
            "cl-corp-1": {
                "uid": "cl-corp-1",
                "name": "corp-perimeter-cluster",
                "type": "simple-cluster",
                "interfaces": {
                    "objects": [
                        {
                            "name": "eth0",
                            "ipv4-address": "203.0.113.5",
                            "ipv4-mask-length": 29,
                            "topology": "external",
                            "topology-settings": {
                                "ip-address-behind-this-interface": "not defined",
                                "interface-leads-to-dmz": False,
                            },
                        },
                        {
                            "name": "eth1",
                            "ipv4-address": "10.10.1.1",
                            "ipv4-network-mask": "255.255.255.0",
                            "topology": "internal",
                            "topology-settings": {
                                "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                                "interface-leads-to-dmz": False,
                            },
                        },
                        {
                            "name": "eth2",
                            "ipv4-address": "172.16.1.1",
                            "ipv4-mask-length": 24,
                            "topology": "internal",
                            "topology-settings": {
                                "ip-address-behind-this-interface": "specific",
                                "specific-network": "G_Global_DMZ",
                                "interface-leads-to-dmz": True,
                            },
                        },
                    ]
                },
            }
        }

        self.generic_objects_by_class: dict[tuple[str, str], list[dict[str, Any]]] = {
            ("DC", "com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj"): [
                {
                    "uid": "slot0-dc",
                    "name": "dc-vsx-chassis",
                    "class-name": "com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj",
                    "vsid": 0,
                    "vsxGateway": "vsx-dc-1",
                }
            ],
            ("DC", "com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj"): [
                {
                    "uid": "slot1-tenant",
                    "name": "vsx1_VS_Tenant",
                    "class-name": "com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj",
                    "vsid": 1,
                    "vsxGateway": "slot0-dc",
                    "targetCustomer": "TenantVS",
                    "interfaces_installed": [
                        {
                            "officialname": "wrp128",
                            "ipaddr": "192.168.100.2",
                            "netmask": "255.255.255.252",
                        },
                        {
                            "officialname": "eth1.50",
                            "ipaddr": "10.50.0.1",
                            "netmask": "255.255.255.0",
                        },
                    ],
                    "routes_installed": [
                        {
                            "dest": "172.16.80.0",
                            "mask": "255.255.255.0",
                            "nexthop": "10.50.0.254",
                        },
                        {
                            "dest": "0.0.0.0",
                            "mask": "0.0.0.0",
                            "nexthop": "192.168.100.1",
                        },
                    ],
                }
            ],
        }

        self.objects_by_domain_and_cmd: dict[tuple[str, str], list[dict[str, Any]]] = {
            ("Global", "show-networks"): [
                {
                    "uid": "g-net-dmz",
                    "name": "N_Global_DMZ_Sub",
                    "type": "network",
                    "subnet4": "172.16.10.0",
                    "mask-length4": 24,
                }
            ],
            ("Global", "show-groups"): [
                {
                    "uid": "g-grp-dmz",
                    "name": "G_Global_DMZ",
                    "type": "group",
                    "members": ["g-net-dmz"],
                }
            ],
            ("Corp", "show-hosts"): [
                {
                    "uid": "corp-h-1",
                    "name": "H_Corp_Workstation_1",
                    "type": "host",
                    "ipv4-address": "10.10.1.25",
                }
            ],
            ("DC", "show-hosts"): [
                {
                    "uid": "dc-h-1",
                    "name": "H_App_Server_1",
                    "type": "host",
                    "ipv4-address": "10.20.1.5",
                }
            ],
            ("DC", "show-networks"): [
                {
                    "uid": "dc-n-1",
                    "name": "N_App_Net",
                    "type": "network",
                    "subnet4": "10.20.2.0",
                    "mask-length4": 24,
                }
            ],
            ("DC", "show-address-ranges"): [
                {
                    "uid": "dc-r-1",
                    "name": "R_App_Pool",
                    "type": "address-range",
                    "ipv4-address-first": "10.20.3.10",
                    "ipv4-address-last": "10.20.3.20",
                }
            ],
            ("DC", "show-groups"): [
                # Nested group with a deliberate cycle (`dc-g-parent` <-> `dc-g-child`) to test cycle protection
                {
                    "uid": "dc-g-parent",
                    "name": "G_DC_Apps",
                    "type": "group",
                    "members": ["dc-h-1", "dc-n-1", "dc-g-child"],
                },
                {
                    "uid": "dc-g-child",
                    "name": "G_DC_Apps_Sub",
                    "type": "group",
                    "members": ["dc-r-1", "dc-g-parent"],
                },
            ],
        }

    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ) -> ApiCallResult:
        if command == "show-last-published-session":
            return ApiCallResult(
                success=True,
                data={"uid": f"sess-{domain}", "publish-time": {"iso-8601": "2026-11-03T12:00:00Z"}},
            )
        if command == "show-session":
            return ApiCallResult(success=True, data={"locks": 0, "changes": 0, "number-of-published-changes": 0})
        if command == "show-simple-cluster" and payload:
            uid = str(payload.get("uid") or "")
            if uid in self.cluster_details_by_uid:
                return ApiCallResult(success=True, data=self.cluster_details_by_uid[uid])
        return ApiCallResult(success=True, data={})

    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        *,
        domain: str | None = None,
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        limit: int = 300,
    ) -> ApiQueryResult:
        dom = domain or "Corp"
        if command == "show-gateways-and-servers":
            objs = self.gateways_by_domain.get(dom, [])
            return ApiQueryResult(success=True, objects=objs, total=len(objs))
        if command == "show-generic-objects" and payload:
            cls_name = str(payload.get("class-name") or "")
            objs = self.generic_objects_by_class.get((dom, cls_name), [])
            return ApiQueryResult(success=True, objects=objs, total=len(objs))
        objs = self.objects_by_domain_and_cmd.get((dom, command), [])
        return ApiQueryResult(success=True, objects=objs, total=len(objs))

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        return "ded-sid", "10.0.0.1"

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> Awaitable[bool]:
        async def _noop() -> bool:
            return True

        return _noop()

    async def close(self, *, logout: bool | None = None) -> None:
        return None


@pytest.mark.asyncio
async def test_topology_extraction_group_expansion_vs_routes_and_candidate_matching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify `TopologyService` extracts connected/specific/VS-routed/external intervals, skips VS0 & members, emits warnings on routing-defined interfaces, and matches affected gateways."""
    from arodonata.core.services import topology_service as topo_mod

    warning_calls: list[tuple[str, dict[str, Any]]] = []
    orig_warning = topo_mod.logger.warning

    def _spy_warning(msg: str, *args: Any, **kwargs: Any) -> None:
        warning_calls.append((msg, kwargs))
        orig_warning(msg, *args, **kwargs)

    monkeypatch.setattr(topo_mod.logger, "warning", _spy_warning)

    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = TopologyFakeApi()

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    domain_service.tracker.mark_refreshed("mds1")
    await cache.upsert_domains(
        [
            DomainInfo(mgmt_name="mds1", uid="d-global", name="Global", active_ip="10.0.0.1", is_global=True),
            DomainInfo(mgmt_name="mds1", uid="d-corp", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1"),
            DomainInfo(mgmt_name="mds1", uid="d-dc", name="DC", active_ip="10.2.0.1", active_mds_ip="10.0.0.1"),
            DomainInfo(
                mgmt_name="mds1",
                uid="d-tenant",
                name="TenantVS",
                active_ip="10.3.0.1",
                active_mds_ip="10.0.0.1",
            ),
        ]
    )

    # Seed a cached rulebase snapshot in DC to test policy package & access layer enrichment
    await cache.replace_domain_rulebase(
        DomainRulebaseSnapshot(
            mgmt_name="mds1",
            domain_name="DC",
            package_layers=[
                RulebasePackageLayerEntry(
                    mgmt_name="mds1",
                    domain_name="DC",
                    package_uid="pkg-core-uid",
                    package_name="Core_Pkg",
                    rulebase_type="access",
                    layer_uid="layer-net-uid",
                    layer_name="Core_Pkg Network",
                    position=1,
                    raw_data={"installation-targets": ["dc-core-gw"]},
                )
            ],
            layers=[
                RulebaseLayerEntry(
                    mgmt_name="mds1",
                    domain_name="DC",
                    uid="layer-net-uid",
                    name="Core_Pkg Network",
                    rulebase_type="access",
                )
            ],
        )
    )

    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    asset_service = AssetRefreshService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )
    object_service = ObjectService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )
    topology_service = TopologyService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
        asset_service=asset_service,
        object_service=object_service,
    )
    search_service = SearchService(
        cache=cache,
        object_service=object_service,
        asset_service=asset_service,
    )

    # 1. Refresh topology across all domains
    outcome = await topology_service.refresh_topology(mgmt_name="mds1", mode="force")
    assert set(outcome.refreshed_domains) == {"mds1:Corp", "mds1:DC", "mds1:TenantVS"}

    # Verify structured warning was emitted for bond0.99 ("network defined by routing") on dc-core-gw
    assert any(
        "mds1:DC:dc-core-gw :: bond0.99" in msg
        and kw.get("gateway_name") == "dc-core-gw"
        and kw.get("interface_name") == "bond0.99"
        and kw.get("behind_mode") == "network defined by routing"
        for msg, kw in warning_calls
    )

    # Verify SearchService.get_cache_status includes "topology" scope
    status = await search_service.get_cache_status(mgmt_name="mds1", scope="topology")
    assert status["total_entries"] == 3
    assert "topology" in status["by_scope"]

    # 2. Verify target filtering: cluster-member ("cm-corp-1a"), checkpoint-host ("mgmt-host-1"),
    # and physical VSX ("vsx-dc-1") must NOT have any entries in arodonata_gateway_topology
    all_entries = await topology_service.get_gateway_topology(mgmt_name="mds1", cache_mode="cache")
    indexed_gw_uids = {e.gateway_uid for e in all_entries}
    assert indexed_gw_uids == {"cl-corp-1", "gw-branch-1", "gw-dc-core", "vs-tenant-1"}
    assert "cm-corp-1a" not in indexed_gw_uids
    assert "vsx-dc-1" not in indexed_gw_uids
    assert "mgmt-host-1" not in indexed_gw_uids

    # 3. Verify on-demand cluster detail fallback & Global group expansion on "cl-corp-1"
    corp_cl_entries = await topology_service.get_gateway_topology(
        mgmt_name="mds1",
        domain="Corp",
        gateway="corp-perimeter-cluster",
        cache_mode="cache",
    )
    corp_by_if = {(e.interface_name, e.cidr_or_range): e for e in corp_cl_entries}
    assert ("eth0", "0.0.0.0/0") in corp_by_if
    assert corp_by_if[("eth0", "0.0.0.0/0")].topology_zone == "external"
    assert corp_by_if[("eth0", "0.0.0.0/0")].source_type == "external_interface"
    assert ("eth1", "10.10.1.0/24") in corp_by_if
    assert corp_by_if[("eth1", "10.10.1.0/24")].source_type == "interface_connected"
    assert ("eth2", "172.16.10.0/24") in corp_by_if
    assert corp_by_if[("eth2", "172.16.10.0/24")].source_type == "interface_specific"
    assert corp_by_if[("eth2", "172.16.10.0/24")].leads_to_dmz is True

    # 4. Verify recursive group expansion with cycle protection on "gw-dc-core"
    dc_entries = await topology_service.get_gateway_topology(
        mgmt_name="mds1",
        domain="DC",
        gateway="dc-core-gw",
        cache_mode="cache",
    )
    dc_cidrs_by_if = {(e.interface_name, e.cidr_or_range): e.source_type for e in dc_entries}
    assert dc_cidrs_by_if == {
        ("bond0.10", "10.10.1.0/24"): "interface_connected",
        ("bond0.20", "10.20.1.5/32"): "interface_specific",
        ("bond0.20", "10.20.2.0/24"): "interface_specific",
        ("bond0.20", "10.20.3.10-10.20.3.20"): "interface_specific",
    }

    # 5. Verify VS static route extraction on "vs-tenant-1" in TenantVS domain
    vs_entries = await topology_service.get_gateway_topology(
        mgmt_name="mds1",
        domain="TenantVS",
        gateway="vsx1_VS_Tenant",
        cache_mode="cache",
    )
    vs_by_if_cidr = {(e.interface_name, e.cidr_or_range): e for e in vs_entries}
    assert ("eth1.50", "10.50.0.0/24") in vs_by_if_cidr
    assert ("eth1.50", "172.16.80.0/24") in vs_by_if_cidr
    assert vs_by_if_cidr[("eth1.50", "172.16.80.0/24")].source_type == "vs_static_route"
    assert vs_by_if_cidr[("eth1.50", "172.16.80.0/24")].topology_zone == "internal"
    assert ("wrp128", "0.0.0.0/0") in vs_by_if_cidr
    assert vs_by_if_cidr[("wrp128", "0.0.0.0/0")].source_type == "vs_static_route"
    assert vs_by_if_cidr[("wrp128", "0.0.0.0/0")].topology_zone == "external"

    summaries = topology_service.summarize_gateway_interfaces(vs_entries)
    sum_by_if = {s.interface_name: s for s in summaries}
    assert sum_by_if["wrp128"].topology_zone == "external"
    assert sum_by_if["eth1.50"].topology_zone == "internal"
    assert "172.16.80.0/24" in sum_by_if["eth1.50"].cidrs_and_ranges

    # 6. Test `find_affected_gateways`:
    # Flow 1: 10.10.1.25 -> 10.20.2.50
    # - On `dc-core-gw` (DC): 10.10.1.25 is on `bond0.10` (internal), 10.20.2.50 is on `bond0.20` (internal)
    #   -> MATCH (`internal_to_internal`, `bond0.10 -> bond0.20`, package `Core_Pkg`, layer `Core_Pkg Network`)
    # - On `corp-perimeter-cluster` (Corp): 10.10.1.25 is on `eth1` (internal), 10.20.2.50 is not behind any
    #   internal interface so falls back to `eth0` (external)
    #   -> MATCH (`internal_to_external`, `eth1 -> eth0`, package `Perimeter_Pkg`)
    # - On `branch-gw-01` (Corp): neither 10.10.1.25 nor 10.20.2.50 is behind `eth1` (192.168.50.0/24),
    #   so BOTH fall back to `eth0` (external == external)
    #   -> EXCLUDED!
    # - On `vsx1_VS_Tenant` (TenantVS): neither is behind `eth1.50`, so both fall back to `wrp128` (external == external)
    #   -> EXCLUDED!
    candidates = await topology_service.find_affected_gateways(
        sources=["10.10.1.25"],
        destinations=["10.20.2.50"],
        mgmt_name="mds1",
        cache_mode="cache",
    )
    assert [c.gateway_name for c in candidates] == ["dc-core-gw", "corp-perimeter-cluster"]

    dc_cand = candidates[0]
    assert dc_cand.domain_name == "DC"
    assert dc_cand.installed_access_policy == "Core_Pkg"
    assert dc_cand.policy_packages == ["Core_Pkg"]
    assert dc_cand.access_layers == ["Core_Pkg Network"]
    assert dc_cand.match_types == ["internal_to_internal"]
    assert len(dc_cand.matched_flows) == 1
    assert dc_cand.matched_flows[0].src_interface == "bond0.10"
    assert dc_cand.matched_flows[0].dst_interface == "bond0.20"

    corp_cand = candidates[1]
    assert corp_cand.domain_name == "Corp"
    assert corp_cand.installed_access_policy == "Perimeter_Pkg"
    assert corp_cand.policy_packages == ["Perimeter_Pkg"]
    assert corp_cand.match_types == ["internal_to_external"]
    assert corp_cand.matched_flows[0].src_interface == "eth1"
    assert corp_cand.matched_flows[0].dst_interface == "eth0"

    # 7. Test same-interface exclusion: 10.10.1.10 -> 10.10.1.99
    # Both sit behind `eth1` on `corp-perimeter-cluster` and `bond0.10` on `dc-core-gw`,
    # and both fall back to external on `branch-gw-01` and `vsx1_VS_Tenant` -> ZERO affected gateways!
    same_if_candidates = await topology_service.find_affected_gateways(
        sources=["10.10.1.10"],
        destinations=["10.10.1.99"],
        mgmt_name="mds1",
        cache_mode="cache",
    )
    assert same_if_candidates == []

    # 8. Test VS static route matching and external_to_internal flow:
    # 8.8.8.8 -> 172.16.80.45 (routed via static route on `eth1.50` of `vsx1_VS_Tenant`, external via `wrp128`)
    vs_candidates = await topology_service.find_affected_gateways(
        sources=["8.8.8.8"],
        destinations=["172.16.80.45"],
        mgmt_name="mds1",
        cache_mode="cache",
    )
    assert len(vs_candidates) == 1
    vs_cand = vs_candidates[0]
    assert vs_cand.gateway_name == "vsx1_VS_Tenant"
    assert vs_cand.domain_name == "TenantVS"
    assert vs_cand.parent_asset_id == "mds1:DC:dc-vsx-chassis"
    assert vs_cand.installed_access_policy == "Tenant_VS_Policy"
    assert vs_cand.match_types == ["external_to_internal"]
    assert vs_cand.matched_flows[0].src_interface == "wrp128"
    assert vs_cand.matched_flows[0].dst_interface == "eth1.50"
    assert vs_cand.matched_flows[0].dst_source_type == "vs_static_route"

    # 9. Test resolving by Check Point object/group name ("H_Corp_Workstation_1" -> "N_Global_DMZ_Sub")
    # Also verify domain-scoped name isolation (T7): "H_App_Server_1" is defined only in "DC", so it must
    # NOT resolve on "Corp" gateways!
    named_candidates = await topology_service.find_affected_gateways(
        sources=["H_Corp_Workstation_1"],
        destinations=["N_Global_DMZ_Sub"],
        mgmt_name="mds1",
        cache_mode="cache",
    )
    assert {c.gateway_name for c in named_candidates} == {"corp-perimeter-cluster"}
    assert named_candidates[0].matched_flows[0].src_interface == "eth1"
    assert named_candidates[0].matched_flows[0].dst_interface == "eth2"
    assert named_candidates[0].matched_flows[0].match_type == "internal_to_internal"

    cross_domain_isolated = await topology_service.find_affected_gateways(
        sources=["H_App_Server_1"],
        destinations=["N_Global_DMZ_Sub"],
        mgmt_name="mds1",
        cache_mode="cache",
    )
    assert cross_domain_isolated == []

    # 10. Test broad CIDR / Any (0.0.0.0/0) multi-interface and external fallback matching (T1):
    # From 10.10.1.25 (behind `eth1` on `corp-perimeter-cluster` and `bond0.10` on `dc-core-gw`,
    # and external on `branch-gw-01` and `vsx1_VS_Tenant`) to 0.0.0.0/0:
    # - On `dc-core-gw` (no external interface): matches `bond0.10` -> `bond0.20` (`internal_to_internal`).
    # - On `corp-perimeter-cluster`: matches `eth1` -> `eth2` (`internal_to_internal`) AND `eth1` -> `eth0` (`internal_to_external`).
    # - On `branch-gw-01`: matches `eth0` (`external`) -> `eth1` (`internal`, `192.168.50.0/24`) while `eth0` -> `eth0` (`external_to_external`) is excluded!
    # - On `vsx1_VS_Tenant`: matches `wrp128` (`external`) -> `eth1.50` (`internal`, `10.50.0.0/24` / `172.16.80.0/24`) while `wrp128` -> `wrp128` (`external_to_external`) is excluded!
    any_dst_candidates = await topology_service.find_affected_gateways(
        sources=["10.10.1.25"],
        destinations=["0.0.0.0/0"],
        mgmt_name="mds1",
        cache_mode="cache",
    )
    by_gw = {c.gateway_name: c for c in any_dst_candidates}
    assert set(by_gw.keys()) == {"dc-core-gw", "corp-perimeter-cluster", "branch-gw-01", "vsx1_VS_Tenant"}
    assert {(f.src_interface, f.dst_interface, f.match_type) for f in by_gw["dc-core-gw"].matched_flows} == {
        ("bond0.10", "bond0.20", "internal_to_internal")
    }
    assert {
        (f.src_interface, f.dst_interface, f.match_type) for f in by_gw["corp-perimeter-cluster"].matched_flows
    } == {
        ("eth1", "eth2", "internal_to_internal"),
        ("eth1", "eth0", "internal_to_external"),
    }
    assert {(f.src_interface, f.dst_interface, f.match_type) for f in by_gw["branch-gw-01"].matched_flows} == {
        ("eth0", "eth1", "external_to_internal")
    }
    assert {(f.src_interface, f.dst_interface, f.match_type) for f in by_gw["vsx1_VS_Tenant"].matched_flows} == {
        ("wrp128", "eth1.50", "external_to_internal")
    }

    await db.close()


@pytest.mark.asyncio
async def test_topology_cache_only_mode_never_calls_live_api_and_host_ckp_firewall_blade_filter() -> None:
    """Verify `cache_mode='cache'` does not trigger live detail API calls when topology table is cold (T2) and `CpmiHostCkp` requires `firewall=True` (T6)."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = TopologyFakeApi()
    api_calls: list[str] = []
    orig_api_call = api.api_call

    async def _spy_api_call(mgmt_name: str, command: str, *args: Any, **kwargs: Any) -> ApiCallResult:
        api_calls.append(command)
        return await orig_api_call(mgmt_name, command, *args, **kwargs)

    api.api_call = _spy_api_call  # type: ignore[method-assign]

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    asset_service = AssetRefreshService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )
    object_service = ObjectService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )
    topology_service = TopologyService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
        asset_service=asset_service,
        object_service=object_service,
    )

    # Seed cached assets in Corp:
    # 1) `corp-perimeter-cluster` with empty interfaces (normally triggers on-demand `show-simple-cluster`)
    # 2) `mgmt-host-ckp` (`CpmiHostCkp` with `firewall=False`, which must be excluded by `is_policy_enforcing_gateway`)
    # 3) `fw-host-ckp` (`CpmiHostCkp` with `firewall=True`, which must be included)
    await cache.replace_domain_assets(
        "mds1",
        "Corp",
        [
            Asset(
                uid="cl-corp-1",
                name="corp-perimeter-cluster",
                type="simple-cluster",
                mgmt_name="mds1",
                domain_name="Corp",
                interfaces=[],
            ),
            Asset(
                uid="host-mgmt-1",
                name="mgmt-host-ckp",
                type="CpmiHostCkp",
                mgmt_name="mds1",
                domain_name="Corp",
                network_security_blades={"firewall": False},
                interfaces=[
                    {
                        "name": "eth0",
                        "ipv4-address": "10.10.1.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask"
                        },
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": "10.20.1.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask"
                        },
                    },
                ],
            ),
            Asset(
                uid="host-fw-1",
                name="fw-host-ckp",
                type="CpmiHostCkp",
                mgmt_name="mds1",
                domain_name="Corp",
                network_security_blades={"firewall": True},
                interfaces=[
                    {
                        "name": "eth0",
                        "ipv4-address": "10.10.1.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask"
                        },
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": "10.20.1.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask"
                        },
                    },
                ],
            ),
        ],
    )

    # With cold `arodonata_gateway_topology` cache and `cache_mode="cache"`, `find_affected_gateways`
    # derives topology in-memory from cached assets/objects WITHOUT calling `show-simple-cluster`!
    candidates = await topology_service.find_affected_gateways(
        sources=["10.10.1.10"],
        destinations=["10.20.1.20"],
        mgmt_name="mds1",
        domain="Corp",
        cache_mode="cache",
    )
    assert api_calls == []
    assert [c.gateway_name for c in candidates] == ["fw-host-ckp"]

    await db.close()
