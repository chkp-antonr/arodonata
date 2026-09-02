"""Unit tests for ArodonataClient cache-mode configuration and the V2 typed
read-helper delegation.

Covers:
* default cache policy built onto the refresh coordinator from constructor args
* per-call vs client-default cache-mode/ttl merge semantics (CachePolicy.resolve
  applied against the coordinator's default policy)
* every ``get_*`` helper forwarding its arguments (including cache_mode/cache_ttl)
  through to the orchestration service
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from arodonata.core.cache_mode import CacheMode
from arodonata.core.cache_policy import CachePolicy

from .client_test_helpers import (
    CLOSED_CLIENT_MATCH,
    coordinator_default_policy,
    make_client,
)

# --------------------------------------------------------------------------- #
# Coordinator default policy from constructor
# --------------------------------------------------------------------------- #


def test_default_policy_is_smart_300():
    client = make_client()
    policy = coordinator_default_policy(client)
    assert policy is not None
    assert policy.mode == CacheMode.SMART
    assert policy.ttl == 300


def test_custom_cache_mode_and_ttl_flow_into_coordinator_policy():
    client = make_client(cache_mode="smart-fast", cache_ttl=42)
    policy = coordinator_default_policy(client)
    assert policy.mode == CacheMode.SMART_FAST
    assert policy.ttl == 42


def test_force_cache_mode_flows_into_coordinator_policy():
    client = make_client(cache_mode="force", cache_ttl=10)
    policy = coordinator_default_policy(client)
    assert policy.mode == CacheMode.FORCE
    assert policy.ttl == 10


# --------------------------------------------------------------------------- #
# Per-call vs default merge behavior
# --------------------------------------------------------------------------- #


def test_none_per_call_args_fall_back_to_client_default():
    client = make_client(cache_mode="smart-fast", cache_ttl=77)
    default = coordinator_default_policy(client)

    resolved = CachePolicy.resolve(None, None, default)

    assert resolved.mode == CacheMode.SMART_FAST
    assert resolved.ttl == 77


def test_explicit_per_call_mode_overrides_default():
    client = make_client(cache_mode="smart", cache_ttl=300)
    default = coordinator_default_policy(client)

    resolved = CachePolicy.resolve("force", None, default)

    # mode overridden, ttl still falls back to the client default
    assert resolved.mode == CacheMode.FORCE
    assert resolved.ttl == 300


def test_explicit_per_call_ttl_overrides_default():
    client = make_client(cache_mode="smart", cache_ttl=300)
    default = coordinator_default_policy(client)

    resolved = CachePolicy.resolve(None, 5, default)

    assert resolved.mode == CacheMode.SMART
    assert resolved.ttl == 5


# --------------------------------------------------------------------------- #
# V2 helper delegation (no cache-mode args)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_get_domains_delegates_to_orchestration():
    client = make_client()
    client._orchestration.get_domains = AsyncMock(return_value=["d"])
    result = await client.get_domains(mgmt_names=["mgmt1"])
    assert result == ["d"]
    client._orchestration.get_domains.assert_awaited_once_with(
        mgmt_names=["mgmt1"], cache_mode=None, cache_ttl=None, include_global=False
    )


@pytest.mark.asyncio
async def test_get_gateways_delegates_to_orchestration():
    client = make_client()
    client._orchestration.get_gateways = AsyncMock(return_value=["gw"])
    result = await client.get_gateways(mgmt_names=["mgmt1"])
    assert result == ["gw"]
    client._orchestration.get_gateways.assert_awaited_once_with(mgmt_names=["mgmt1"], cache_mode="cache")


@pytest.mark.asyncio
async def test_get_object_by_uid_delegates_to_orchestration():
    client = make_client()
    client._orchestration.get_object_by_uid = AsyncMock(return_value="obj")
    result = await client.get_object_by_uid("uid-1", "mgmt1", "domainA")
    assert result == "obj"
    client._orchestration.get_object_by_uid.assert_awaited_once_with(
        uid="uid-1", mgmt_name="mgmt1", domain_name="domainA"
    )


# --------------------------------------------------------------------------- #
# V2 object helpers with cache-mode forwarding
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_get_hosts_forwards_all_args_including_cache_mode():
    client = make_client()
    client._orchestration.get_hosts = AsyncMock(return_value=["h"])
    result = await client.get_hosts(
        name_filter="web*",
        mgmt_names=["mgmt1"],
        domain_names=["domainA"],
        cache_mode="force",
        cache_ttl=15,
    )
    assert result == ["h"]
    client._orchestration.get_hosts.assert_awaited_once_with(
        name_filter="web*",
        mgmt_names=["mgmt1"],
        domain_names=["domainA"],
        cache_mode="force",
        cache_ttl=15,
    )


@pytest.mark.asyncio
async def test_get_hosts_defaults_cache_mode_to_none():
    client = make_client()
    client._orchestration.get_hosts = AsyncMock(return_value=[])
    await client.get_hosts()
    # per-call overrides default to None so orchestration applies the client default
    client._orchestration.get_hosts.assert_awaited_once_with(
        name_filter=None,
        mgmt_names=None,
        domain_names=None,
        cache_mode=None,
        cache_ttl=None,
    )


@pytest.mark.asyncio
async def test_get_networks_forwards_all_args():
    client = make_client()
    client._orchestration.get_networks = AsyncMock(return_value=["n"])
    result = await client.get_networks(
        subnet="10.0.0.0/8",
        mgmt_names=["mgmt1"],
        domain_names=["domainA"],
        cache_mode="cache",
        cache_ttl=1,
    )
    assert result == ["n"]
    client._orchestration.get_networks.assert_awaited_once_with(
        subnet="10.0.0.0/8",
        mgmt_names=["mgmt1"],
        domain_names=["domainA"],
        cache_mode="cache",
        cache_ttl=1,
    )


@pytest.mark.asyncio
async def test_get_groups_forwards_all_args():
    client = make_client()
    client._orchestration.get_groups = AsyncMock(return_value=["g"])
    result = await client.get_groups(
        name_filter="fw*",
        mgmt_names=["mgmt1"],
        domain_names=["domainA"],
        cache_mode="smart-fast",
        cache_ttl=8,
    )
    assert result == ["g"]
    client._orchestration.get_groups.assert_awaited_once_with(
        name_filter="fw*",
        mgmt_names=["mgmt1"],
        domain_names=["domainA"],
        cache_mode="smart-fast",
        cache_ttl=8,
    )


# --------------------------------------------------------------------------- #
# V2 rulebase helpers with cache-mode forwarding
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_get_access_rules_forwards_all_args():
    client = make_client()
    client._orchestration.get_access_rules = AsyncMock(return_value=["r"])
    result = await client.get_access_rules(
        layer_name="Network",
        mgmt_names=["mgmt1"],
        domain_names=["domainA"],
        enabled_only=True,
        cache_mode="force",
        cache_ttl=3,
    )
    assert result == ["r"]
    client._orchestration.get_access_rules.assert_awaited_once_with(
        layer_name="Network",
        mgmt_names=["mgmt1"],
        domain_names=["domainA"],
        enabled_only=True,
        cache_mode="force",
        cache_ttl=3,
    )


@pytest.mark.asyncio
async def test_get_nat_rules_forwards_all_args():
    client = make_client()
    client._orchestration.get_nat_rules = AsyncMock(return_value=["r"])
    result = await client.get_nat_rules(layer_name="NAT", enabled_only=False)
    assert result == ["r"]
    client._orchestration.get_nat_rules.assert_awaited_once_with(
        layer_name="NAT",
        mgmt_names=None,
        domain_names=None,
        enabled_only=False,
        cache_mode=None,
        cache_ttl=None,
    )


@pytest.mark.asyncio
async def test_get_https_rules_forwards_all_args():
    client = make_client()
    client._orchestration.get_https_rules = AsyncMock(return_value=["r"])
    result = await client.get_https_rules(
        layer_name="CVD",
        mgmt_names=["mgmt1"],
        enabled_only=True,
        cache_mode="smart",
        cache_ttl=2,
    )
    assert result == ["r"]
    client._orchestration.get_https_rules.assert_awaited_once_with(
        layer_name="CVD",
        mgmt_names=["mgmt1"],
        domain_names=None,
        enabled_only=True,
        cache_mode="smart",
        cache_ttl=2,
    )


@pytest.mark.asyncio
async def test_get_threat_rules_forwards_all_args():
    client = make_client()
    client._orchestration.get_threat_rules = AsyncMock(return_value=["r"])
    result = await client.get_threat_rules(
        layer_name="Threat",
        domain_names=["domainA"],
        enabled_only=None,
    )
    assert result == ["r"]
    client._orchestration.get_threat_rules.assert_awaited_once_with(
        layer_name="Threat",
        mgmt_names=None,
        domain_names=["domainA"],
        enabled_only=None,
        cache_mode=None,
        cache_ttl=None,
    )


# --------------------------------------------------------------------------- #
# Closed-client guard on a representative V2 helper
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_v2_helper_on_closed_client_raises():
    client = make_client()
    await client.close()
    with pytest.raises(RuntimeError, match=CLOSED_CLIENT_MATCH):
        await client.get_hosts()


# --------------------------------------------------------------------------- #
# max_incremental_changes plumbing
# --------------------------------------------------------------------------- #


def test_max_incremental_changes_threads_to_coordinator_and_object_service():
    client = make_client(max_incremental_changes=42)

    assert client._refresh_coordinator.max_incremental_changes == 42
    assert client._object_service.max_incremental_changes == 42


def test_max_incremental_changes_default_is_500():
    client = make_client()

    assert client._refresh_coordinator.max_incremental_changes == 500
    assert client._object_service.max_incremental_changes == 500
