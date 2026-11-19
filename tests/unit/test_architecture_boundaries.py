"""Architectural AST layer-boundary checks and Wave 1 core primitive regression tests."""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any

import pytest

from arodonata.adapters.checkpoint import client as checkpoint_client
from arodonata.adapters.checkpoint import tls as checkpoint_tls
from arodonata.adapters.checkpoint import transport as checkpoint_transport
from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core import context as core_context
from arodonata.core import ports as core_ports
from arodonata.core import primitives as core_primitives
from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import ValidationError
from arodonata.core.models import common as core_common
from arodonata.core.models import rulebase as core_rulebase
from arodonata.core.models import sentinels as core_sentinels
from arodonata.core.models.assets import Asset
from arodonata.core.models.domains import DomainSyncState
from arodonata.core.models.objects import CPObject
from arodonata.core.ports import (
    AssetCachePort,
    CachePort,
    DomainCachePort,
    ObjectCachePort,
    RulebaseCachePort,
    RulebaseRefreshPort,
    ServiceCachePort,
    SidCachePort,
    SyncStatePort,
    TopologyCachePort,
)
from arodonata.core.primitives import (
    MAX_IPV4_INT,
    effective_range_prefix_len,
    format_composite_id,
    is_uuid,
    mask_to_prefix_len,
    normalize_str_sequence,
    object_ipv4_bounds,
    parse_cidr_or_range_bounds,
    parse_composite_id,
    prefix_len_to_mask,
)
from arodonata.core.services import sync_coordinator
from arodonata.core.services.asset_service import AssetRefreshService
from arodonata.core.services.domain_service import DomainService
from arodonata.core.services.object_service import ObjectService
from arodonata.core.services.sync_coordinator import DomainSyncCoordinator
from arodonata.core.services.topology_service import TopologyService
from arodonata.cpcrud import rule_identity
from arodonata.cpcrud.differ import compute_object_diff
from arodonata.cpcrud.state_reader import normalize_mask_length
from arodonata.rulebase import models as rulebase_models
from arodonata.rulebase import numbering as rulebase_numbering
from arodonata.rulebase.refresh import RulebaseRefreshService
from arodonata.testing import _emulator_models
from arodonata.testing._emulator_crud import _normalize_subnet_fields

_SRC_ROOT = Path(__file__).resolve().parents[2] / "src"
_ARODONATA_ROOT = _SRC_ROOT / "arodonata"

_LAYER_FORBIDDEN_IMPORTS: dict[str, tuple[str, ...]] = {
    "core": (
        "arodonata.adapters",
        "arodonata.client",
        "arodonata.mcp",
        "arodonata.cpcrud",
        "arodonata.reports",
        "arodonata.rulebase",
        "arodonata.testing",
        "cpapi",
        "aiohttp",
        "sqlalchemy",
        "sqlmodel",
        "asyncpg",
        "aiosqlite",
    ),
    "adapters": (
        "arodonata.client",
        "arodonata.mcp",
        "arodonata.cpcrud",
        "arodonata.reports",
        "arodonata.rulebase",
        "arodonata.testing",
    ),
    "cpcrud": (
        "arodonata.adapters",
        "arodonata.client",
    ),
    "rulebase": (
        "arodonata.cpcrud",
        "arodonata.adapters",
        "arodonata.client",
    ),
    "reports": (
        "arodonata.adapters",
        "arodonata.client",
        "arodonata.mcp",
        "arodonata.testing",
    ),
    "mcp": (
        "arodonata.adapters",
        "arodonata.testing",
    ),
}


def _matches_forbidden(module_name: str, forbidden: tuple[str, ...]) -> str | None:
    for prefix in forbidden:
        if module_name == prefix or module_name.startswith(f"{prefix}."):
            return prefix
    return None


def _resolve_import_targets(file_path: Path, node: ast.Import | ast.ImportFrom) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]

    rel_parts = file_path.relative_to(_SRC_ROOT).parent.parts
    if node.level > 0:
        keep_len = len(rel_parts) - (node.level - 1)
        base_parts = rel_parts[: max(0, keep_len)]
        base_mod = ".".join(base_parts)
        if node.module:
            mod_name = f"{base_mod}.{node.module}" if base_mod else node.module
        else:
            return [f"{base_mod}.{alias.name}" if base_mod else alias.name for alias in node.names]
    else:
        mod_name = node.module or ""

    targets = [mod_name] if mod_name else []
    for alias in node.names:
        if alias.name != "*" and mod_name:
            targets.append(f"{mod_name}.{alias.name}")
    return targets


@pytest.mark.spec("SCN-CLIENT-018-1")
@pytest.mark.parametrize("layer", ["core", "adapters", "cpcrud", "rulebase", "reports", "mcp"])
def test_layer_ast_import_boundaries(layer: str) -> None:
    """SCN-CLIENT-018-1: Enforce hexagonal layer import boundaries via AST traversal (including lazy and TYPE_CHECKING imports)."""
    layer_dir = _ARODONATA_ROOT / layer
    py_files = sorted(layer_dir.rglob("*.py"))
    assert py_files, f"Expected Python source files under {layer_dir}"

    forbidden = _LAYER_FORBIDDEN_IMPORTS[layer]
    violations: list[str] = []

    for py_file in py_files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            for target in _resolve_import_targets(py_file, node):
                matched = _matches_forbidden(target, forbidden)
                if matched is not None:
                    rel_file = py_file.relative_to(_ARODONATA_ROOT.parent.parent)
                    violations.append(f"{rel_file}:{node.lineno}: forbidden import '{target}' (rule: {matched})")

    assert not violations, "Architectural layer boundary violations detected:\n" + "\n".join(violations)


@pytest.mark.spec("SCN-CLIENT-018-3")
def test_sentinel_uid_conflict_resolution_and_reexports() -> None:
    """SCN-CLIENT-018-3: Verify `6c488338-8eec-4103-ad21-cd461ac2c476` is Policy Targets and re-exports stay intact."""
    policy_targets_uid = "6c488338-8eec-4103-ad21-cd461ac2c476"
    drop_uid = "6c488338-8eec-4103-ad21-cd461ac2c473"

    assert core_sentinels.POLICY_TARGETS_UID == policy_targets_uid
    assert policy_targets_uid in core_sentinels.POLICY_TARGETS_TOKENS
    assert core_sentinels.BUILTIN_SENTINELS[policy_targets_uid] == {
        "uid": policy_targets_uid,
        "name": "Policy Targets",
        "type": "Global",
    }
    assert policy_targets_uid not in core_sentinels.ACTION_UID_TO_NAME
    assert core_sentinels.DROP_UID == drop_uid
    assert core_sentinels.ACTION_UID_TO_NAME[drop_uid] == "Drop"

    # Backward-compatible re-exports
    assert rule_identity.NAT_ANY_OBJECT_UID == core_sentinels.NAT_ANY_OBJECT_UID
    assert rule_identity.NAT_ORIGINAL_OBJECT_UID == core_sentinels.NAT_ORIGINAL_OBJECT_UID
    assert rule_identity.normalize_any_sentinel is core_sentinels.normalize_any_sentinel
    assert rule_identity.normalize_nat_original_sentinel is core_sentinels.normalize_nat_original_sentinel

    assert _emulator_models.POLICY_TARGETS_UID == policy_targets_uid
    assert _emulator_models.DROP_UID == drop_uid
    assert _emulator_models.BUILTIN_SENTINELS is core_sentinels.BUILTIN_SENTINELS
    assert not hasattr(_emulator_models, "DROP_UID_ALT")


@pytest.mark.spec("SCN-CLIENT-018-3")
def test_core_primitives_and_strict_cpcrud_mask_validation() -> None:
    """SCN-CLIENT-018-3: Verify shared UUID, composite ID, sequence, IPv4, and strict CPCRUD mask validation."""
    valid_uid = "6c488338-8eec-4103-ad21-cd461ac2c476"
    assert is_uuid(f" {valid_uid} ")
    assert not is_uuid("not-a-uuid-with-length-thirty-six!!!")
    assert len("not-a-uuid-with-length-thirty-six!!!") == 36
    assert not is_uuid(None)
    assert not is_uuid(123)

    assert format_composite_id("mds1", "Corp", "uid-1") == "mds1:Corp:uid-1"
    assert parse_composite_id(" mds1 : Corp : a:b ", expected_parts=3) == ("mds1", "Corp", "a:b")
    assert parse_composite_id("mds1:Corp", expected_parts=3) is None
    assert parse_composite_id("mds1::uid-1", expected_parts=3) is None
    assert parse_composite_id("single", expected_parts=1) == ("single",)
    assert parse_composite_id("   ", expected_parts=1) is None

    assert normalize_str_sequence(" GW1 , gw2 , , GW1 ", lowercase=True, deduplicate=True) == ["gw1", "gw2"]
    assert normalize_str_sequence([" a ", "", "b"], split_csv=False) == ["a", "b"]
    assert normalize_str_sequence(None) == []

    assert mask_to_prefix_len(24) == 24
    assert mask_to_prefix_len(24.0) == 24
    assert mask_to_prefix_len(24.5) is None
    assert mask_to_prefix_len("255.255.255.0") == 24
    assert mask_to_prefix_len("0.0.0.0") == 0
    assert mask_to_prefix_len("255.255.255.255") == 32
    assert mask_to_prefix_len("255.0.255.0") is None
    assert mask_to_prefix_len("0.0.0.255") is None
    assert mask_to_prefix_len("0.0.0.255", allow_hostmask=True) == 24
    assert mask_to_prefix_len("24", allow_prefix_int=False) is None
    assert mask_to_prefix_len(True) is None
    assert mask_to_prefix_len(33) is None
    assert prefix_len_to_mask(24) == "255.255.255.0"
    assert prefix_len_to_mask(0) == "0.0.0.0"
    assert prefix_len_to_mask(True) is None
    assert prefix_len_to_mask(33) is None
    assert effective_range_prefix_len(100, 100) == 32

    # Emulator subnet-mask normalization must not interpret bare digits like "24" as a dotted-quad subnet mask
    emu_target: dict[str, Any] = {}
    _normalize_subnet_fields(emu_target, {"subnet4": "10.0.0.0", "subnet-mask": "24"})
    assert "mask-length4" not in emu_target

    # CPCRUD strict mask validation accepts integral floats and rejects out-of-range / hostmask values
    assert normalize_mask_length(24.0, strict=True) == 24
    with pytest.raises(ValidationError):
        normalize_mask_length(33, strict=True)
    with pytest.raises(ValidationError):
        normalize_mask_length(None, "0.0.0.255", strict=True)

    existing_net = CPObject(
        uid="n-exist",
        name="N1",
        type="network",
        mgmt_name="m",
        domain_name="d",
        subnet4="10.0.0.0",
        mask_length4=24,
    )
    with pytest.raises(ValidationError):
        compute_object_diff({"type": "network", "name": "N1", "subnet4": "10.0.0.0", "mask_length4": 33}, existing_net)

    host = CPObject(uid="h1", name="H1", type="host", mgmt_name="m", domain_name="d", ipv4_address="10.0.0.5")
    net = CPObject(
        uid="n1", name="N1", type="network", mgmt_name="m", domain_name="d", subnet4="10.0.0.0", mask_length4=24
    )
    rng = CPObject(
        uid="r1",
        name="R1",
        type="address-range",
        mgmt_name="m",
        domain_name="d",
        ipv4_address_first="10.0.0.10",
        ipv4_address_last="10.0.0.20",
    )
    assert object_ipv4_bounds(host) == (167772165, 167772165)
    assert object_ipv4_bounds(net) == (167772160, 167772415)
    assert object_ipv4_bounds(rng) == (167772170, 167772180)
    assert parse_cidr_or_range_bounds("0.0.0.0/0") == (0, MAX_IPV4_INT, 0)
    assert parse_cidr_or_range_bounds("10.0.0.1-10.0.0.4") == (167772161, 167772164, 30)


@pytest.mark.spec("SCN-CLIENT-018-3")
def test_wave1_backward_compatible_reexports() -> None:
    """SCN-CLIENT-018-3: Verify moved core functions keep exact object identity across legacy module imports."""
    import arodonata.rulebase as rulebase_pkg

    assert sync_coordinator.parse_cp_publish_timestamp is core_common.parse_cp_publish_timestamp
    assert checkpoint_client._update_overlay_from_command is core_context.update_overlay_from_command
    assert checkpoint_client.is_readonly_command is core_primitives.is_readonly_command
    assert checkpoint_client.READONLY_EXACT_COMMANDS is core_primitives.READONLY_EXACT_COMMANDS
    assert checkpoint_transport.validate_command_name is core_primitives.validate_command_name
    assert checkpoint_tls.format_host_attr_for_url is core_primitives.format_host_attr_for_url
    assert rulebase_numbering.extract_policy_packages is core_rulebase.extract_policy_packages
    assert rulebase_pkg.extract_policy_packages is core_rulebase.extract_policy_packages
    assert rulebase_models.PolicyPackageInfo is core_rulebase.PolicyPackageInfo
    assert rulebase_pkg.PolicyPackageInfo is core_rulebase.PolicyPackageInfo


@pytest.mark.asyncio
@pytest.mark.spec("SCN-CLIENT-018-2")
async def test_cache_port_subprotocols_narrowed_consumers_and_rulebase_refresh_port(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """SCN-CLIENT-018-2: Verify ISP sub-protocols, RulebaseRefreshPort, minimal sub-port double, and TopologyService warning."""
    expected_ports = (
        DomainCachePort,
        SidCachePort,
        SyncStatePort,
        ObjectCachePort,
        ServiceCachePort,
        AssetCachePort,
        TopologyCachePort,
        RulebaseCachePort,
        CachePort,
        RulebaseRefreshPort,
    )
    for port in expected_ports:
        assert port.__name__ in core_ports.__all__

    class _MinimalAssetOnlyCache:
        async def get_assets(
            self,
            mgmt_name: str | None = None,
            domain_name: str | None = None,
            *,
            types: Any = None,
        ) -> list[Asset]:
            return []

        async def replace_domain_assets(
            self,
            mgmt_name: str,
            domain_name: str,
            assets: Any,
            *,
            sync_states: list[DomainSyncState] | None = None,
        ) -> int:
            return len(assets)

        async def upsert_assets(self, assets: Any) -> int:
            return len(assets)

    minimal_asset_cache = _MinimalAssetOnlyCache()
    assert isinstance(minimal_asset_cache, AssetCachePort)
    assert not isinstance(minimal_asset_cache, CachePort)

    db = DatabaseManager(engine="sqlite+aiosqlite:///:memory:")
    await db.initialize()
    try:
        adapter = SqlCacheAdapter(db)
        lock_port = SqlLockAdapter(db)
        for cache_proto in (
            DomainCachePort,
            SidCachePort,
            SyncStatePort,
            ObjectCachePort,
            ServiceCachePort,
            AssetCachePort,
            TopologyCachePort,
            RulebaseCachePort,
            CachePort,
        ):
            assert isinstance(adapter, cache_proto)

        settings = ArodonataSettings(servers={"m1": {"host": "127.0.0.1", "api_key": "dummy"}})
        domain_svc = DomainService(settings=settings, api=None, cache=adapter, lock_port=lock_port)  # type: ignore[arg-type]
        coord = DomainSyncCoordinator(
            settings=settings,
            api=None,  # type: ignore[arg-type]
            cache=adapter,
            lock_port=lock_port,
            domain_service=domain_svc,
        )
        asset_svc = AssetRefreshService(
            settings=settings,
            api=None,  # type: ignore[arg-type]
            cache=minimal_asset_cache,
            coordinator=coord,
        )
        assert await asset_svc.get_assets(mgmt_name="m1", cache_mode="cache") == []

        refresh_svc = RulebaseRefreshService(settings=settings, api=None, cache=adapter, coordinator=coord)  # type: ignore[arg-type]
        assert isinstance(refresh_svc, RulebaseRefreshPort)

        obj_svc = ObjectService(settings=settings, api=None, cache=adapter, coordinator=coord)  # type: ignore[arg-type]
        topo_svc = TopologyService(
            settings=settings,
            api=None,  # type: ignore[arg-type]
            cache=adapter,
            coordinator=coord,
            asset_service=asset_svc,
            object_service=obj_svc,
            rulebase_refresh=None,
        )
        with caplog.at_level(logging.WARNING):
            cold_snap = await topo_svc._load_domain_package_snapshot("m1", "Corp", allow_refresh=True)
        assert cold_snap.package_layers == []
        assert any("without rulebase_refresh" in rec.message for rec in caplog.records)
    finally:
        await db.close()
