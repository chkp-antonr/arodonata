"""Architectural AST layer-boundary checks and Wave 1 core primitive regression tests."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from arodonata.adapters.checkpoint import client as checkpoint_client
from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter
from arodonata.core import context as core_context
from arodonata.core import ports as core_ports
from arodonata.core.config import ArodonataSettings
from arodonata.core.models import common as core_common
from arodonata.core.models import rulebase as core_rulebase
from arodonata.core.models import sentinels as core_sentinels
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
from arodonata.core.services.domain_service import DomainService
from arodonata.core.services.sync_coordinator import DomainSyncCoordinator
from arodonata.cpcrud import rule_identity
from arodonata.rulebase import models as rulebase_models
from arodonata.rulebase import numbering as rulebase_numbering
from arodonata.rulebase.refresh import RulebaseRefreshService
from arodonata.testing import _emulator_models

_SRC_ROOT = Path(__file__).resolve().parents[2] / "src"
_ARODONATA_ROOT = _SRC_ROOT / "arodonata"

_LAYER_FORBIDDEN_IMPORTS: dict[str, tuple[str, ...]] = {
    "core": (
        "arodonata.adapters",
        "arodonata.mcp",
        "arodonata.cpcrud",
        "arodonata.reports",
        "arodonata.rulebase",
        "arodonata.testing",
        "aiohttp",
        "sqlalchemy",
        "sqlmodel",
        "asyncpg",
        "aiosqlite",
    ),
    "cpcrud": ("arodonata.adapters",),
    "rulebase": (
        "arodonata.cpcrud",
        "arodonata.adapters",
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


@pytest.mark.parametrize("layer", ["core", "cpcrud", "rulebase"])
def test_layer_ast_import_boundaries(layer: str) -> None:
    """Enforce hexagonal layer import boundaries via AST traversal (including lazy and TYPE_CHECKING imports)."""
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


def test_sentinel_uid_conflict_resolution_and_reexports() -> None:
    """Verify `6c488338-8eec-4103-ad21-cd461ac2c476` is Policy Targets and re-exports stay intact."""
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


def test_core_primitives_behaviour() -> None:
    """Verify shared UUID, composite ID, sequence, and IPv4 primitive utilities."""
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
    assert mask_to_prefix_len("255.255.255.0") == 24
    assert mask_to_prefix_len("0.0.0.255") is None
    assert mask_to_prefix_len(True) is None
    assert mask_to_prefix_len(33) is None
    assert prefix_len_to_mask(24) == "255.255.255.0"
    assert prefix_len_to_mask(0) == "0.0.0.0"
    assert prefix_len_to_mask(True) is None
    assert prefix_len_to_mask(33) is None
    assert effective_range_prefix_len(100, 100) == 32

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


def test_wave1_backward_compatible_reexports() -> None:
    """Verify moved core functions keep exact object identity across legacy module imports."""
    import arodonata.rulebase as rulebase_pkg

    assert sync_coordinator.parse_cp_publish_timestamp is core_common.parse_cp_publish_timestamp
    assert checkpoint_client._update_overlay_from_command is core_context.update_overlay_from_command
    assert rulebase_numbering.extract_policy_packages is core_rulebase.extract_policy_packages
    assert rulebase_pkg.extract_policy_packages is core_rulebase.extract_policy_packages
    assert rulebase_models.PolicyPackageInfo is core_rulebase.PolicyPackageInfo
    assert rulebase_pkg.PolicyPackageInfo is core_rulebase.PolicyPackageInfo


def test_cache_port_subprotocols_and_rulebase_refresh_port() -> None:
    """Verify ISP sub-protocols of `CachePort` and `RulebaseRefreshPort` runtime checkability."""
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

    db = DatabaseManager(engine="sqlite+aiosqlite:///:memory:")
    adapter = SqlCacheAdapter(db)
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
    domain_svc = DomainService(settings=settings, api=None, cache=adapter, lock_port=None)  # type: ignore[arg-type]
    coord = DomainSyncCoordinator(
        settings=settings,
        api=None,  # type: ignore[arg-type]
        cache=adapter,
        lock_port=None,  # type: ignore[arg-type]
        domain_service=domain_svc,
    )
    refresh_svc = RulebaseRefreshService(settings=settings, api=None, cache=adapter, coordinator=coord)  # type: ignore[arg-type]
    assert isinstance(refresh_svc, RulebaseRefreshPort)
