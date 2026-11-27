"""Unit and OpenSpec tests for vendor-neutral Asset role/platform classification, inheritance, and querying."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp.types import CallToolResult, TextContent
from sqlalchemy import inspect, text

import arodonata
from arodonata import (
    EXECUTION_TARGET_ROLES,
    POLICY_TARGET_ROLES,
    ArodonataClient,
    ArodonataSettings,
    Asset,
    AssetPlatform,
    AssetRole,
    ClusterRelationshipManager,
    DomainInfo,
    classify_asset,
    classify_asset_platform,
    classify_asset_role,
)
from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.models.common import ApiCallResult, ApiQueryResult, expand_asset_types, utc_now
from arodonata.core.models.domains import DomainSyncState
from arodonata.core.services import (
    AssetRefreshService,
    DomainService,
    DomainSyncCoordinator,
    ObjectService,
    SearchService,
    VSXRelationshipManager,
)
from arodonata.core.services.search.query import resolve_query_scopes
from arodonata.core.services.topology._shared import is_policy_enforcing_gateway
from arodonata.mcp import MCPToolQuotaManager, create_mcp_server


@pytest.mark.spec("SCN-CACHE-019-1")
def test_vendor_neutral_role_classification_and_target_parity() -> None:
    """SCN-CACHE-019-1: Verify deterministic AssetRole, target flags, exports, and topology parity."""
    # Verify top-level exports exist and match expected sets
    assert arodonata.AssetRole is AssetRole
    assert arodonata.AssetPlatform is AssetPlatform
    assert POLICY_TARGET_ROLES == frozenset({"gateway", "cluster", "virtual_system"})
    assert EXECUTION_TARGET_ROLES == frozenset(
        {
            "gateway",
            "cluster_member",
            "vsx_gateway",
            "vsx_cluster_member",
            "management_server",
            "mds",
            "log_server",
        }
    )

    cases: list[tuple[dict[str, Any], AssetRole, bool, bool]] = [
        ({"uid": "u1", "name": "gw-1", "type": "simple-gateway"}, "gateway", True, True),
        ({"uid": "u2", "name": "gw-2", "type": "gateway"}, "gateway", True, True),
        ({"uid": "u3", "name": "gw-3", "type": "CpmiGatewayPlain"}, "gateway", True, True),
        ({"uid": "u4", "name": "cl-1", "type": "simple-cluster"}, "cluster", True, False),
        ({"uid": "u5", "name": "cl-2", "type": "cluster"}, "cluster", True, False),
        ({"uid": "u6", "name": "cl-3", "type": "CpmiGatewayCluster"}, "cluster", True, False),
        ({"uid": "u7", "name": "cm-1", "type": "cluster-member"}, "cluster_member", False, True),
        ({"uid": "u8", "name": "cm-2", "type": "CpmiClusterMember"}, "cluster_member", False, True),
        ({"uid": "u9", "name": "vsx-1", "type": "vsx-gateway"}, "vsx_gateway", False, True),
        ({"uid": "u10", "name": "vsx-2", "type": "CpmiVsxNetobj"}, "vsx_gateway", False, True),
        ({"uid": "u11", "name": "vsxcl-1", "type": "vsx-cluster"}, "vsx_cluster", False, False),
        ({"uid": "u12", "name": "vsxcl-2", "type": "CpmiVsxClusterNetobj"}, "vsx_cluster", False, False),
        ({"uid": "u13", "name": "vsxcm-1", "type": "vsx-cluster-member"}, "vsx_cluster_member", False, True),
        ({"uid": "u14", "name": "vsxcm-2", "type": "CpmiVsxClusterMember"}, "vsx_cluster_member", False, True),
        (
            {
                "uid": "u15",
                "name": "vsxcm-hint",
                "type": "cluster-member",
                "cluster": {"uid": "vsxcl-2", "type": "CpmiVsxClusterNetobj"},
            },
            "vsx_cluster_member",
            False,
            True,
        ),
        ({"uid": "u16", "name": "vs-1", "type": "virtual-system"}, "virtual_system", True, False),
        ({"uid": "u17", "name": "vs-2", "type": "vs-netobj"}, "virtual_system", True, False),
        ({"uid": "u18", "name": "vs-3", "type": "CpmiVsNetobj"}, "virtual_system", True, False),
        ({"uid": "u19", "name": "vs-4", "type": "CpmiVsClusterNetobj"}, "virtual_system", True, False),
        ({"uid": "u20", "name": "mds-1", "type": "mds"}, "mds", False, True),
        ({"uid": "u21", "name": "mds-2", "type": "CpmiMds"}, "mds", False, True),
        (
            {
                "uid": "u22",
                "name": "mds-host",
                "type": "checkpoint-host",
                "management-blades": {"multi-domain-server": True, "network-policy-management": True},
            },
            "mds",
            False,
            True,
        ),
        (
            {
                "uid": "u23",
                "name": "sms-1",
                "type": "checkpoint-host",
                "management-blades": {"network-policy-management": True, "logging-and-status": True},
            },
            "management_server",
            False,
            True,
        ),
        (
            {
                "uid": "u24",
                "name": "sms-plain",
                "type": "CpmiHostCkp",
            },
            "management_server",
            False,
            True,
        ),
        (
            {
                "uid": "u25",
                "name": "hostckp-fw",
                "type": "CpmiHostCkp",
                "network-security-blades": {"firewall": True},
            },
            "gateway",
            True,
            True,
        ),
        (
            {
                "uid": "u26",
                "name": "chost-fw",
                "type": "checkpoint-host",
                "network-security-blades": {"firewall": True},
                "management-blades": {"primary": True},
            },
            "management_server",
            False,
            True,
        ),
        (
            {
                "uid": "u27",
                "name": "log-1",
                "type": "checkpoint-host",
                "management-blades": {"logging-and-status": True},
            },
            "log_server",
            False,
            True,
        ),
        ({"uid": "u28", "name": "interop-1", "type": "interoperable-device"}, "interoperable_device", False, False),
        ({"uid": "u29", "name": "mystery-1", "type": "custom-vendor-object"}, "unknown", False, False),
    ]

    for payload, expected_role, expected_policy, expected_exec in cases:
        assert classify_asset_role(payload) == expected_role, f"Raw role mismatch for {payload}"
        asset = Asset.from_cp_dict("mds1", "Corp", payload)
        assert asset.asset_role == expected_role, f"Asset role mismatch for {payload}"
        assert asset.is_policy_target is expected_policy, f"Policy flag mismatch for {payload}"
        assert asset.is_execution_target is expected_exec, f"Execution flag mismatch for {payload}"
        assert is_policy_enforcing_gateway(asset) is expected_policy, f"Topology parity mismatch for {payload}"

    # Verify parent_type hint works directly in classify_asset_role() and classify_asset()
    plain_member = Asset.from_cp_dict("mds1", "VSX", {"uid": "m-plain", "name": "vsx-m1", "type": "CpmiClusterMember"})
    assert plain_member.asset_role == "cluster_member"
    assert classify_asset_role(plain_member, parent_type="CpmiVsxClusterNetobj") == "vsx_cluster_member"
    promoted = classify_asset(plain_member, parent_type="vsx-cluster")
    assert promoted.asset_role == "vsx_cluster_member"
    assert promoted.is_execution_target is True
    assert promoted.is_policy_target is False


@pytest.mark.spec("SCN-CACHE-019-2")
def test_vendor_neutral_platform_classification_and_customer_field_isolation() -> None:
    """SCN-CACHE-019-2: Classify Gaia, Gaia Embedded, Maestro, CloudGuard, Open Server, and ignore customer strings."""
    platform_cases: list[tuple[dict[str, Any], AssetPlatform]] = [
        ({"uid": "p1", "name": "fw-1", "type": "simple-gateway", "os-name": "Gaia Embedded"}, "gaia_embedded"),
        (
            {
                "uid": "p2",
                "name": "fw-2",
                "type": "simple-gateway",
                "os-name": "Gaia",
                "hardware": "Quantum Spark 1590",
            },
            "gaia_embedded",
        ),
        (
            {
                "uid": "p3",
                "name": "fw-3",
                "type": "simple-gateway",
                "os-name": "Gaia",
                "appliance": "SMB 1550",
            },
            "gaia_embedded",
        ),
        (
            {
                "uid": "p4",
                "name": "fw-4",
                "type": "simple-cluster",
                "os-name": "Gaia",
                "hardware": "Maestro MHO-175",
            },
            "maestro",
        ),
        (
            {
                "uid": "p5",
                "name": "fw-5",
                "type": "cluster-member",
                "os-name": "Gaia",
                "platform": "Scalable Platform SGM",
            },
            "maestro",
        ),
        (
            {
                "uid": "p6",
                "name": "fw-6",
                "type": "simple-gateway",
                "os-name": "Gaia",
                "hardware": "SMO Orchestrator",
            },
            "maestro",
        ),
        (
            {
                "uid": "p7",
                "name": "fw-7",
                "type": "simple-gateway",
                "os-name": "Gaia",
                "hardware": "CloudGuard IaaS",
            },
            "cloudguard",
        ),
        (
            {
                "uid": "p8",
                "name": "fw-8",
                "type": "simple-gateway",
                "os-name": "Gaia",
                "deployment-type": "AWS",
            },
            "cloudguard",
        ),
        (
            {
                "uid": "p9",
                "name": "fw-9",
                "type": "simple-gateway",
                "os-name": "Gaia",
                "cloud-provider": "Azure VMSS",
            },
            "cloudguard",
        ),
        (
            {
                "uid": "p10",
                "name": "fw-10",
                "type": "simple-gateway",
                "os-name": "Gaia",
                "hardware": "VE-Series",
                "platform": "GCP",
            },
            "cloudguard",
        ),
        (
            {
                "uid": "p11",
                "name": "fw-11",
                "type": "simple-gateway",
                "os-name": "Gaia",
                "hardware": "Open server",
            },
            "open_server",
        ),
        (
            {
                "uid": "p12",
                "name": "fw-12",
                "type": "simple-gateway",
                "os-name": "Gaia",
                "hardware": "Quantum 6900",
            },
            "gaia",
        ),
        ({"uid": "p13", "name": "fw-13", "type": "simple-gateway"}, "unknown"),
    ]

    for payload, expected_platform in platform_cases:
        assert classify_asset_platform(payload) == expected_platform, f"Raw platform mismatch for {payload}"
        asset = Asset.from_cp_dict("mds1", "Corp", payload)
        assert asset.platform_family == expected_platform, f"Asset platform mismatch for {payload}"

    # Customer-controlled name, comments, and tags must NEVER affect platform classification
    misleading = Asset.from_cp_dict(
        "mds1",
        "Corp",
        {
            "uid": "p-cust",
            "name": "maestro-aws-smb-open-server-gaia",
            "type": "simple-gateway",
            "comments": "CloudGuard Gaia Embedded MHO-140 Azure GCP",
            "tags": ["maestro", "cloudguard", "gaia"],
        },
    )
    assert misleading.platform_family == "unknown"


@pytest.mark.spec("SCN-CACHE-019-3")
def test_cluster_member_metadata_inheritance_and_reclassification() -> None:
    """SCN-CACHE-019-3: ClusterRelationshipManager inherits missing hardware/os/version and promotes VSX members."""
    manager = ClusterRelationshipManager()

    cluster = Asset.from_cp_dict(
        "mds1",
        "Corp",
        {
            "uid": "cl-1",
            "name": "corp-cl-01",
            "type": "CpmiGatewayCluster",
            "hardware": "Quantum 6900",
            "os-name": "Gaia",
            "version": "R81.20",
            "cluster-member-names": [
                {"uid": "cm-1", "name": "corp-gw-01a", "type": "CpmiClusterMember"},
                {"uid": "cm-2", "name": "corp-gw-01b", "type": "CpmiClusterMember"},
            ],
        },
    )
    member_missing_all = Asset.from_cp_dict(
        "mds1",
        "Corp",
        {
            "uid": "cm-1",
            "name": "corp-gw-01a",
            "type": "CpmiClusterMember",
            "os-name": "   ",
        },
    )
    member_explicit_hw = Asset.from_cp_dict(
        "mds1",
        "Corp",
        {
            "uid": "cm-2",
            "name": "corp-gw-01b",
            "type": "CpmiClusterMember",
            "hardware": "Open server",
            "version": "R82",
        },
    )

    vsx_cluster = Asset.from_cp_dict(
        "mds1",
        "Corp",
        {
            "uid": "vsx-cl-1",
            "name": "maestro-vsx-cl",
            "type": "CpmiVsxClusterNetobj",
            "hardware": "Maestro MHO-175",
            "os-name": "Gaia",
            "version": "R82",
            "cluster-member-names": ["vsx-cm-1"],
        },
    )
    vsx_member = Asset.from_cp_dict(
        "mds1",
        "Corp",
        {
            "uid": "vsx-cm-1",
            "name": "maestro-vsx-m1",
            "type": "cluster-member",
        },
    )

    enriched = {
        a.uid: a for a in manager.enrich([cluster, member_missing_all, member_explicit_hw, vsx_cluster, vsx_member])
    }

    m1 = enriched["cm-1"]
    assert m1.hardware == "Quantum 6900"
    assert m1.os_name == "Gaia"
    assert m1.version == "R81.20"
    assert m1.asset_role == "cluster_member"
    assert m1.platform_family == "gaia"
    assert m1.is_policy_target is False
    assert m1.is_execution_target is True

    m2 = enriched["cm-2"]
    assert m2.hardware == "Open server"
    assert m2.os_name == "Gaia"
    assert m2.version == "R82"
    assert m2.platform_family == "open_server"

    vm1 = enriched["vsx-cm-1"]
    assert vm1.parent_uid == "vsx-cl-1"
    assert vm1.hardware == "Maestro MHO-175"
    assert vm1.os_name == "Gaia"
    assert vm1.version == "R82"
    assert vm1.asset_role == "vsx_cluster_member"
    assert vm1.platform_family == "maestro"
    assert vm1.is_policy_target is False
    assert vm1.is_execution_target is True


class _NoopApi:
    """Minimal `ApiPort` double for offline cache-backed filtering and query tests."""

    async def api_call(
        self, mgmt_name: str, command: str, payload: dict[str, Any] | None = None, **kw: Any
    ) -> ApiCallResult:
        return ApiCallResult(success=True, data={})

    async def api_query(self, mgmt_name: str, command: str, **kw: Any) -> ApiQueryResult:
        return ApiQueryResult(success=True, objects=[], total=0)

    async def create_dedicated_session(self, mgmt_name: str, domain: str | None = None, **kw: Any) -> tuple[str, str]:
        return "ded-sid", "10.0.0.1"

    async def logout_sid(self, mgmt_name: str, sid: str, **kw: Any) -> bool:
        return True

    async def close(self, *, logout: bool | None = None) -> None:
        return None


@pytest.mark.spec("SCN-CACHE-019-4")
@pytest.mark.asyncio
async def test_sqlite_in_place_migration_hydration_and_role_platform_queries(tmp_path: Path) -> None:
    """SCN-CACHE-019-4: Verify nullable schema migration, NULL read-time auto-classification, and filtering/grouping."""
    db_file = tmp_path / "legacy_assets.sqlite"
    db_url = f"sqlite+aiosqlite:///{db_file}"

    # 1. Seed a legacy `arodonata_assets` table without the 5 classification columns
    legacy_db = DatabaseManager(engine=db_url)
    try:
        async with legacy_db.engine.begin() as conn:
            await conn.execute(
                text(
                    """
                    CREATE TABLE arodonata_assets (
                        id TEXT PRIMARY KEY,
                        asset_id TEXT NOT NULL,
                        uid TEXT NOT NULL,
                        name TEXT NOT NULL,
                        type TEXT NOT NULL,
                        mgmt_name TEXT NOT NULL,
                        domain_name TEXT NOT NULL,
                        ipv4_address TEXT,
                        ipv6_address TEXT,
                        version TEXT,
                        os_name TEXT,
                        hardware TEXT,
                        sic_status TEXT,
                        parent_uid TEXT,
                        parent_name TEXT,
                        parent_id TEXT,
                        parent_asset_id TEXT,
                        member_uids TEXT NOT NULL,
                        member_asset_ids TEXT NOT NULL,
                        virtual_system_uids TEXT NOT NULL,
                        virtual_system_asset_ids TEXT NOT NULL,
                        interfaces TEXT NOT NULL,
                        network_security_blades TEXT NOT NULL,
                        comments TEXT NOT NULL,
                        color TEXT,
                        raw_data TEXT NOT NULL,
                        updated_at DATETIME NOT NULL
                    )
                    """
                )
            )
            await conn.execute(
                text(
                    """
                    INSERT INTO arodonata_assets (
                        id, asset_id, uid, name, type, mgmt_name, domain_name,
                        ipv4_address, os_name, hardware, member_uids, member_asset_ids,
                        virtual_system_uids, virtual_system_asset_ids, interfaces,
                        network_security_blades, comments, raw_data, updated_at
                    ) VALUES (
                        'mds1:Corp:legacy-log-1',
                        'mds1:Corp:log-srv-legacy',
                        'legacy-log-1',
                        'log-srv-legacy',
                        'CpmiHostCkp',
                        'mds1',
                        'Corp',
                        '10.0.0.50',
                        'Gaia',
                        'Open server',
                        '[]', '[]', '[]', '[]', '[]',
                        '{}',
                        '',
                        '{"uid": "legacy-log-1", "name": "log-srv-legacy", "type": "CpmiHostCkp", "os-name": "Gaia", "hardware": "Open server", "management-blades": {"logging-and-status": true}}',
                        '2026-11-25 10:00:00'
                    )
                    """
                )
            )
    finally:
        await legacy_db.close()

    # 2. Evolve schema in place and confirm legacy row survives with NULL columns and auto-classifies on read
    db = DatabaseManager(engine=db_url)
    await db.initialize()
    try:
        async with db.engine.begin() as conn:
            col_names = await conn.run_sync(lambda sc: {c["name"] for c in inspect(sc).get_columns("arodonata_assets")})
            assert {
                "management_blades",
                "asset_role",
                "platform_family",
                "is_policy_target",
                "is_execution_target",
            } <= col_names

            raw_row = (
                await conn.execute(
                    text(
                        "SELECT asset_role, platform_family, is_policy_target, is_execution_target "
                        "FROM arodonata_assets WHERE uid = 'legacy-log-1'"
                    )
                )
            ).one()
            assert raw_row == (None, None, None, None)

        cache = SqlCacheAdapter(db)
        hydrated = await cache.get_assets(mgmt_name="mds1", domain_name="Corp")
        assert len(hydrated) == 1
        legacy_asset = hydrated[0]
        assert legacy_asset.management_blades == {"logging-and-status": True}
        assert legacy_asset.asset_role == "log_server"
        assert legacy_asset.platform_family == "open_server"
        assert legacy_asset.is_policy_target is False
        assert legacy_asset.is_execution_target is True

        # 3. Round-trip newly classified assets and verify filtering + structured query grouping
        lock_port = SqlLockAdapter(db)
        settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")
        api = _NoopApi()
        domain_svc = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
        domain_svc.tracker.mark_refreshed("mds1")
        await cache.upsert_domains(
            [DomainInfo(mgmt_name="mds1", uid="d1", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1")]
        )
        coordinator = DomainSyncCoordinator(
            settings=settings,
            api=api,
            cache=cache,
            lock_port=lock_port,
            domain_service=domain_svc,
        )
        asset_svc = AssetRefreshService(settings=settings, api=api, cache=cache, coordinator=coordinator)
        obj_svc = ObjectService(settings=settings, api=api, cache=cache, coordinator=coordinator)
        search_svc = SearchService(
            cache=cache,
            object_service=obj_svc,
            asset_service=asset_svc,
        )

        extra_assets = [
            legacy_asset,
            Asset.from_cp_dict(
                "mds1",
                "Corp",
                {
                    "uid": "gw-maestro",
                    "name": "gw-mho-01",
                    "type": "simple-gateway",
                    "os-name": "Gaia",
                    "hardware": "Maestro MHO-175",
                },
            ),
            Asset.from_cp_dict(
                "mds1",
                "Corp",
                {
                    "uid": "cl-cloud",
                    "name": "cl-aws-01",
                    "type": "CpmiGatewayCluster",
                    "os-name": "Gaia",
                    "deployment-type": "AWS",
                },
            ),
            Asset.from_cp_dict(
                "mds1",
                "Corp",
                {
                    "uid": "gw-smb",
                    "name": "branch-smb-01",
                    "type": "simple-gateway",
                    "os-name": "Gaia Embedded",
                    "hardware": "Quantum Spark 1550",
                },
            ),
        ]
        await cache.replace_domain_assets("mds1", "Corp", extra_assets)

        # Short-circuit empty roles/platforms before refresh
        assert await asset_svc.get_assets("mds1", "Corp", roles=[], cache_mode="force") == []
        assert await asset_svc.get_assets("mds1", "Corp", platforms=[], cache_mode="force") == []

        maestro_gws = await asset_svc.get_assets(
            "mds1", "Corp", roles=["gateway"], platforms=["maestro"], cache_mode="cache"
        )
        assert [a.uid for a in maestro_gws] == ["gw-maestro"]

        # ArodonataClient.get_gateways + query_objects + describe_objects
        async with ArodonataClient(settings, api=api, db_manager=db) as client:
            client_gws = await client.get_gateways(
                "mds1", "Corp", roles=["cluster"], platforms=["cloudguard"], cache_mode="cache"
            )
            assert [a.uid for a in client_gws] == ["cl-cloud"]

            q_exec = await client.query_objects(
                mgmt_name="mds1",
                domain_name="Corp",
                is_execution_target=True,
                cache_mode="cache",
            )
            assert {o["uid"] for o in q_exec["objects"]} == {"legacy-log-1", "gw-maestro", "gw-smb"}

            q_policy_cloud = await client.query_objects(
                mgmt_name="mds1",
                domain_name="Corp",
                platforms=["cloudguard", "gaia_embedded"],
                is_policy_target=True,
                cache_mode="cache",
            )
            assert {o["uid"] for o in q_policy_cloud["objects"]} == {"cl-cloud", "gw-smb"}

            q_grouped = await client.query_objects(
                mgmt_name="mds1",
                domain_name="Corp",
                group_by=["role", "platform"],
                aggregate="count",
                cache_mode="cache",
            )
            assert q_grouped["total"] == 4
            assert q_grouped["group_by"] == ["asset_role", "platform_family"]
            assert any(
                g["role"] == "gateway"
                and g["asset_role"] == "gateway"
                and g["platform"] == "maestro"
                and g["platform_family"] == "maestro"
                and g["count"] == 1
                for g in q_grouped["groups"]
            )

            desc = await search_svc.describe_objects(mgmt_name="mds1", domain_name="Corp")
            assert desc["asset_roles"] == {"cluster": 1, "gateway": 2, "log_server": 1}
            assert desc["asset_platforms"] == {"cloudguard": 1, "gaia_embedded": 1, "maestro": 1, "open_server": 1}
            for field_name in ("asset_role", "platform_family", "is_policy_target", "is_execution_target"):
                assert field_name in desc["filterable_fields"]
                assert field_name in desc["groupable_fields"]
    finally:
        await db.close()


class _AssetScopeMcpApi(_NoopApi):
    """Fake API returning gateways and domains to verify MCP asset-scope parity."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.queries: list[str] = []

    async def api_call(
        self, mgmt_name: str, command: str, payload: dict[str, Any] | None = None, **kw: Any
    ) -> ApiCallResult:
        self.calls.append(command)
        if command == "show-domains":
            return ApiCallResult(
                success=True,
                data={
                    "objects": [
                        {
                            "uid": "d-corp",
                            "name": "Corp",
                            "type": "domain",
                            "servers": [
                                {
                                    "name": "corp-cma",
                                    "ipv4-address": "10.1.0.1",
                                    "active": True,
                                    "multi-domain-server": {"ipv4-address": "10.0.0.1"},
                                }
                            ],
                        }
                    ]
                },
            )
        return ApiCallResult(success=True, data={})

    async def api_query(self, mgmt_name: str, command: str, **kw: Any) -> ApiQueryResult:
        self.queries.append(command)
        if command == "show-gateways-and-servers":
            objs = [
                {
                    "uid": "gw-1",
                    "name": "gw-maestro-1",
                    "type": "simple-gateway",
                    "os-name": "Gaia",
                    "hardware": "Maestro MHO-175",
                    "ipv4-address": "10.1.0.10",
                },
                {
                    "uid": "mds-1",
                    "name": "prod-mds-1",
                    "type": "mds",
                    "os-name": "Gaia",
                    "hardware": "Open server",
                    "ipv4-address": "10.0.0.1",
                },
            ]
            return ApiQueryResult(success=True, objects=objs, total=len(objs))
        return ApiQueryResult(success=True, objects=[], total=0)


@pytest.mark.spec("SCN-CACHE-019-5")
@pytest.mark.asyncio
async def test_mcp_query_objects_asset_grouping_scope_parity_and_quota(tmp_path: Path) -> None:
    """SCN-CACHE-019-5: MCP query_objects grouping by role/platform routes cold upgrade, quota, and age to assets."""
    import json
    from datetime import timedelta

    db = DatabaseManager(engine=f"sqlite+aiosqlite:///{tmp_path / 'mcp_scope_parity.sqlite'}")
    await db.initialize()
    try:
        api = _AssetScopeMcpApi()
        settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")
        async with ArodonataClient(settings, api=api, db_manager=db) as client:
            await client.cache.upsert_domains(
                [
                    DomainInfo(
                        mgmt_name="mds1", uid="d-corp", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1"
                    )
                ]
            )
            # Pre-seed a stale `objects` sync state (1000s old) so any accidental fallback to scope="objects" is obvious
            stale_obj_ts = utc_now() - timedelta(seconds=1000)
            await client.cache.upsert_sync_state(
                DomainSyncState(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    scope="objects",
                    item_type="host",
                    synced_at=stale_obj_ts,
                    status="ok",
                    object_count=0,
                )
            )

            server = create_mcp_server(client, auth_mode="host")
            res = await server.call_tool(
                "query_objects",
                {
                    "mgmt_name": "mds1",
                    "domain": "Corp",
                    "group_by": ["role", "platform"],
                    "aggregate": "count",
                    "cache_mode": "cache",
                },
            )
            assert isinstance(res, CallToolResult)
            assert res.is_error is False
            assert "show-gateways-and-servers" in api.queries
            assert "show-hosts" not in api.queries
            first_block = res.content[0]
            assert isinstance(first_block, TextContent)
            payload = json.loads(first_block.text)
            assert payload["total"] == 2
            assert payload["group_by"] == ["asset_role", "platform_family"]
            # Newly synced assets state must be recent (< 60s), NOT the 1000s stale objects state
            assert payload["cache_age_seconds"] is not None
            assert payload["cache_age_seconds"] < 60.0

            # Now test live quota enforcement on scope="assets" when objects is fresh and assets is cold
            db2 = DatabaseManager(engine=f"sqlite+aiosqlite:///{tmp_path / 'mcp_quota_parity.sqlite'}")
            await db2.initialize()
            try:
                api2 = _AssetScopeMcpApi()
                async with ArodonataClient(settings, api=api2, db_manager=db2) as client2:
                    await client2.cache.upsert_domains(
                        [
                            DomainInfo(
                                mgmt_name="mds1",
                                uid="d-corp",
                                name="Corp",
                                active_ip="10.1.0.1",
                                active_mds_ip="10.0.0.1",
                            )
                        ]
                    )
                    # Mark objects as fresh so scope="objects" would NOT consume live quota
                    await client2.cache.upsert_sync_state(
                        DomainSyncState(
                            mgmt_name="mds1",
                            domain_name="Corp",
                            scope="objects",
                            item_type="*",
                            synced_at=utc_now(),
                            status="ok",
                            object_count=0,
                        )
                    )
                    quota_mgr = MCPToolQuotaManager(live_rate_limit_per_minute=1)
                    quota_mgr.check_and_consume("anonymous", is_live=True)
                    server2 = create_mcp_server(client2, auth_mode="host", quota_manager=quota_mgr)
                    for gb_field in (["is_policy_target"], ["is_execution_target"], ["platform"]):
                        q_res = await server2.call_tool(
                            "query_objects",
                            {
                                "mgmt_name": "mds1",
                                "domain": "Corp",
                                "group_by": gb_field,
                                "aggregate": "count",
                                "cache_mode": "smart",
                            },
                        )
                        assert q_res.is_error is True
                        err_block = q_res.content[0]
                        assert isinstance(err_block, TextContent)
                        assert "quota" in err_block.text.lower() or "rate limit" in err_block.text.lower()
            finally:
                await db2.close()
    finally:
        await db.close()


@pytest.mark.spec("SCN-CACHE-019-5")
@pytest.mark.asyncio
async def test_canonical_mds_asset_routing_and_lookup(tmp_path: Path) -> None:
    """SCN-CACHE-019-5: Verify canonical mds/CpmiMds routing across gateways, query, find, search, and show_object."""
    import json

    assert expand_asset_types(["mds"]) == ["mds", "CpmiMds"]
    assert expand_asset_types(["CpmiMds"]) == ["mds", "CpmiMds"]
    assert expand_asset_types(["checkpoint-host"]) == ["checkpoint-host", "CpmiHostCkp"]
    assert resolve_query_scopes(["mds"]) == (["mds", "cpmimds"], False, False, True)
    assert resolve_query_scopes(["CpmiMds"]) == (["mds", "cpmimds"], False, False, True)

    db = DatabaseManager(engine=f"sqlite+aiosqlite:///{tmp_path / 'mds_routing.sqlite'}")
    await db.initialize()
    try:
        api = _NoopApi()
        settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")
        async with ArodonataClient(settings, api=api, db_manager=db) as client:
            await client.cache.upsert_domains(
                [
                    DomainInfo(
                        mgmt_name="mds1", uid="d-corp", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1"
                    )
                ]
            )
            mds_rest = Asset.from_cp_dict(
                "mds1",
                "Corp",
                {"uid": "mds-u1", "name": "mds-rest-node", "type": "mds", "ipv4-address": "10.0.0.1"},
            )
            mds_cpmi = Asset.from_cp_dict(
                "mds1",
                "Corp",
                {"uid": "mds-u2", "name": "mds-cpmi-node", "type": "CpmiMds", "ipv4-address": "10.0.0.2"},
            )
            sms_host = Asset.from_cp_dict(
                "mds1",
                "Corp",
                {"uid": "sms-u1", "name": "sms-host", "type": "checkpoint-host", "ipv4-address": "10.0.0.3"},
            )
            await client.cache.replace_domain_assets("mds1", "Corp", [mds_rest, mds_cpmi, sms_host])

            # 1. get_gateways
            gws_rest = await client.get_gateways("mds1", "Corp", types=["mds"], cache_mode="cache")
            gws_cpmi = await client.get_gateways("mds1", "Corp", types=["CpmiMds"], cache_mode="cache")
            assert {a.uid for a in gws_rest} == {"mds-u1", "mds-u2"}
            assert {a.uid for a in gws_cpmi} == {"mds-u1", "mds-u2"}

            # 2. query_objects
            q_rest = await client.query_objects(mgmt_name="mds1", domain_name="Corp", types=["mds"], cache_mode="cache")
            q_cpmi = await client.query_objects(
                mgmt_name="mds1", domain_name="Corp", types=["CpmiMds"], cache_mode="cache"
            )
            assert {o["uid"] for o in q_rest["objects"]} == {"mds-u1", "mds-u2"}
            assert {o["uid"] for o in q_cpmi["objects"]} == {"mds-u1", "mds-u2"}

            # 3. find_object (cross-type equivalence)
            found_1 = await client.find_object("mds1", "Corp", "mds-rest-node", obj_type="CpmiMds", cache_mode="cache")
            found_2 = await client.find_object("mds1", "Corp", "mds-cpmi-node", obj_type="mds", cache_mode="cache")
            assert found_1 is not None and found_1.uid == "mds-u1"
            assert found_2 is not None and found_2.uid == "mds-u2"

            # 4. search_objects
            s_rest = await client.search_objects(
                "mds-", mgmt_name="mds1", domains=["Corp"], types=["mds"], cache_mode="cache"
            )
            s_cpmi = await client.search_objects(
                "mds-", mgmt_name="mds1", domains=["Corp"], types=["CpmiMds"], cache_mode="cache"
            )
            assert {m.uid for m in s_rest.matches} == {"mds-u1", "mds-u2"}
            assert {m.uid for m in s_cpmi.matches} == {"mds-u1", "mds-u2"}

            # 5. MCP show_object
            server = create_mcp_server(client, auth_mode="host")
            show_1 = await server.call_tool(
                "show_object",
                {
                    "uid_or_name": "mds-rest-node",
                    "mgmt_name": "mds1",
                    "domain": "Corp",
                    "obj_type": "cpmimds",
                    "cache_mode": "cache",
                },
            )
            show_2 = await server.call_tool(
                "show_object",
                {
                    "uid_or_name": "mds-cpmi-node",
                    "mgmt_name": "mds1",
                    "domain": "Corp",
                    "obj_type": "mds",
                    "cache_mode": "cache",
                },
            )
            for res in (show_1, show_2):
                assert res.is_error is False
                block = res.content[0]
                assert isinstance(block, TextContent)
                data = json.loads(block.text)
                assert data["object"]["uid"] in {"mds-u1", "mds-u2"}
    finally:
        await db.close()


@pytest.mark.spec("SCN-CACHE-019-5")
@pytest.mark.asyncio
async def test_vsx_relationship_manager_excludes_members_parents_and_self_links() -> None:
    """SCN-CACHE-019-5: VSXRelationshipManager excludes cluster members, VSX parents, and self-links from virtual_system_uids."""
    api = _NoopApi()
    vsx_mgr = VSXRelationshipManager(api)

    vsx_cluster = Asset.from_cp_dict(
        "mds1",
        "VSX-Dom",
        {
            "uid": "vsx-cl-1",
            "name": "vsx-cluster-main",
            "type": "CpmiVsxClusterNetobj",
            "contained-in": {"uid": "vsx-cl-1", "name": "vsx-cluster-main"},
        },
    )
    vsx_member_1 = Asset.from_cp_dict(
        "mds1",
        "VSX-Dom",
        {
            "uid": "vsx-mem-1",
            "name": "vsx-member-a",
            "type": "CpmiVsxClusterMember",
            "vsx-cluster": {"uid": "vsx-cl-1", "name": "vsx-cluster-main"},
        },
    )
    vsx_member_2 = Asset.from_cp_dict(
        "mds1",
        "VSX-Dom",
        {
            "uid": "vsx-mem-2",
            "name": "vsx-member-b",
            "type": "cluster-member",
            "contained-in": {"uid": "vsx-cl-1", "name": "vsx-cluster-main"},
        },
    )
    other_vsx_parent = Asset.from_cp_dict(
        "mds1",
        "VSX-Dom",
        {
            "uid": "vsx-gw-other",
            "name": "vsx-gw-secondary",
            "type": "vsx-gateway",
            "vsx-gateway": {"uid": "vsx-cl-1", "name": "vsx-cluster-main"},
        },
    )
    real_vs = Asset.from_cp_dict(
        "mds1",
        "VSX-Dom",
        {
            "uid": "vs-real-1",
            "name": "vs-corp-1",
            "type": "CpmiVsNetobj",
            "vsx-cluster": {"uid": "vsx-cl-1", "name": "vsx-cluster-main"},
        },
    )

    # 1. Local enrich()
    enriched = {
        a.uid: a
        for a in await vsx_mgr.enrich(
            "mds1", "VSX-Dom", [vsx_cluster, vsx_member_1, vsx_member_2, other_vsx_parent, real_vs]
        )
    }
    assert enriched["vsx-cl-1"].virtual_system_uids == ["vs-real-1"]
    assert enriched["vsx-cl-1"].virtual_system_asset_ids == ["mds1:VSX-Dom:vs-corp-1"]
    assert enriched["vsx-cl-1"].parent_uid is None
    assert enriched["vsx-mem-1"].parent_uid is None
    assert enriched["vsx-mem-2"].parent_uid is None
    assert enriched["vsx-gw-other"].parent_uid is None
    assert enriched["vs-real-1"].parent_uid == "vsx-cl-1"

    # 2. Cross-domain reconcile_cross_domain()
    real_vs_cross = Asset.from_cp_dict(
        "mds1",
        "Customer-Dom",
        {
            "uid": "vs-cross-1",
            "name": "vs-customer-1",
            "type": "virtual-system",
            "vsx-cluster": {"uid": "vsx-cl-1", "name": "vsx-cluster-main"},
        },
    )
    vsx_member_cross = Asset.from_cp_dict(
        "mds1",
        "Customer-Dom",
        {
            "uid": "vsx-mem-cross",
            "name": "vsx-member-cross",
            "type": "vsx-cluster-member",
            "vsx-gateway": {"uid": "vsx-cl-1", "name": "vsx-cluster-main"},
        },
    )
    modified = {
        a.uid: a
        for a in vsx_mgr.reconcile_cross_domain(
            [vsx_cluster, vsx_member_1, vsx_member_2, other_vsx_parent, real_vs_cross, vsx_member_cross]
        )
    }
    assert modified["vsx-cl-1"].virtual_system_uids == ["vs-cross-1"]
    assert "vsx-mem-1" not in modified["vsx-cl-1"].virtual_system_uids
    assert "vsx-mem-cross" not in modified["vsx-cl-1"].virtual_system_uids
    assert "vsx-gw-other" not in modified["vsx-cl-1"].virtual_system_uids
    assert "vsx-cl-1" not in modified["vsx-cl-1"].virtual_system_uids
    assert modified["vs-cross-1"].parent_uid == "vsx-cl-1"
    assert "vsx-mem-cross" not in modified


@pytest.mark.spec("SCN-CACHE-019-5")
def test_asset_type_equivalents_all_normalize_to_canonical_asset_types() -> None:
    """DA-010: Every key in ASSET_TYPE_EQUIVALENTS normalizes via normalize_any_type() to CANONICAL_ASSET_TYPES."""
    from arodonata.core.models.common import ASSET_TYPE_EQUIVALENTS, CANONICAL_ASSET_TYPES, normalize_any_type

    canon_lower = {c.lower() for c in CANONICAL_ASSET_TYPES}
    for alias in ASSET_TYPE_EQUIVALENTS:
        assert normalize_any_type(alias) in canon_lower
    assert normalize_any_type("vsx_cluster_member") == "vsx-cluster-member"
    assert normalize_any_type("vs_netobj") == "vs-netobj"


@pytest.mark.spec("SCN-CACHE-019-5")
async def test_vsx_parent_list_slot_objects_and_cluster_pass2_exclude_members_and_self_links() -> None:
    """DA-039: Parent virtual-systems list, slot objects, and ClusterRelationshipManager pass 2 exclude invalid links."""
    from arodonata.core.services._asset_linking import ClusterRelationshipManager

    api = _NoopApi()
    vsx_mgr = VSXRelationshipManager(api)
    cluster_mgr = ClusterRelationshipManager()

    parent = Asset.from_cp_dict(
        "mds1",
        "VSX-Dom",
        {
            "uid": "vsx-parent-1",
            "name": "vsx-parent",
            "type": "vsx-cluster",
            "virtual-systems": [
                {"uid": "vsx-parent-1", "name": "vsx-parent", "type": "vsx-cluster"},
                {"uid": "mem-in-list", "name": "mem-in-list", "type": "vsx-cluster-member"},
                {"uid": "gw-in-list", "name": "gw-in-list", "type": "vsx-gateway"},
                {"uid": "vs-valid-2", "name": "vs-valid-2", "type": "virtual-system"},
            ],
        },
    )
    mem_in_list = Asset.from_cp_dict(
        "mds1", "VSX-Dom", {"uid": "mem-in-list", "name": "mem-in-list", "type": "vsx-cluster-member"}
    )
    gw_in_list = Asset.from_cp_dict(
        "mds1", "VSX-Dom", {"uid": "gw-in-list", "name": "gw-in-list", "type": "vsx-gateway"}
    )
    enriched = {a.uid: a for a in await vsx_mgr.enrich("mds1", "VSX-Dom", [parent, mem_in_list, gw_in_list])}
    assert enriched["vsx-parent-1"].virtual_system_uids == ["vs-valid-2"]
    assert enriched["mem-in-list"].parent_uid is None
    assert enriched["gw-in-list"].parent_uid is None

    # ClusterRelationshipManager pass 2 must not link VS child or self
    cluster = Asset.from_cp_dict("mds1", "VSX-Dom", {"uid": "cl-1", "name": "cl-main", "type": "simple-cluster"})
    vs_pointing_cluster = Asset.from_cp_dict(
        "mds1",
        "VSX-Dom",
        {"uid": "vs-cl-1", "name": "vs-cl-1", "type": "virtual-system", "cluster": {"uid": "cl-1", "name": "cl-main"}},
    )
    self_member = Asset.from_cp_dict(
        "mds1",
        "VSX-Dom",
        {"uid": "cl-1", "name": "cl-main", "type": "simple-cluster", "cluster": {"uid": "cl-1", "name": "cl-main"}},
    )
    c_enriched = {a.uid: a for a in cluster_mgr.enrich([cluster, vs_pointing_cluster, self_member])}
    assert "vs-cl-1" not in c_enriched["cl-1"].member_uids
    assert "cl-1" not in c_enriched["cl-1"].member_uids
