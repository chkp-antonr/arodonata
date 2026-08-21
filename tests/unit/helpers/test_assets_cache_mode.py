"""Tests that helpers never leak cache-coordinator refreshes into gateway reads."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from arodonata.helpers.assets import get_gateways


def _make_client(gateways_result: list) -> MagicMock:
    client = MagicMock()
    client._orchestration.get_gateways = AsyncMock(return_value=gateways_result)

    async def _empty_refresh(*args, **kwargs):
        yield {"status": "done"}

    client.build_refresh_assets_cache = _empty_refresh
    return client


@pytest.mark.asyncio
async def test_get_gateways_smart_passes_cache_to_orchestration():
    """The inner orchestration read must never trigger the object coordinator."""
    client = _make_client([MagicMock()])

    await get_gateways(client, mgmt_names=["mgmt1"], cache_mode="smart")

    client._orchestration.get_gateways.assert_awaited_with(mgmt_names=["mgmt1"], cache_mode="cache")


@pytest.mark.asyncio
async def test_get_gateways_cache_mode_cache_never_refreshes():
    client = _make_client([])
    refresh_called = False

    async def _tracking_refresh(*args, **kwargs):
        nonlocal refresh_called
        refresh_called = True
        yield {"status": "done"}

    client.build_refresh_assets_cache = _tracking_refresh

    result = await get_gateways(client, mgmt_names=["mgmt1"], cache_mode="cache")

    assert result == []
    assert not refresh_called


@pytest.mark.asyncio
async def test_get_gateways_smart_empty_cache_retries_after_asset_refresh():
    client = _make_client([])
    calls: list[str] = []

    async def _tracking_refresh(*args, **kwargs):
        calls.append("asset_refresh")
        yield {"status": "done"}

    client.build_refresh_assets_cache = _tracking_refresh

    await get_gateways(client, mgmt_names=["mgmt1"], cache_mode="smart")

    assert calls == ["asset_refresh"]
    assert client._orchestration.get_gateways.await_count == 2
    for c in client._orchestration.get_gateways.await_args_list:
        assert c.kwargs["cache_mode"] == "cache"
