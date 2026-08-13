"""Unit tests for arodonata.helpers.assets (gateway/server cache-first helpers)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from arodonata.helpers._context import UserContext
from arodonata.helpers.assets import get_gateways, refresh_assets
from arodonata.models import Gateway

_USER = UserContext(username="admin", source="test")


def _gateway(uid: str = "uid-1", name: str = "gw-1", mgmt_name: str = "mgmt1") -> Gateway:
    return Gateway(
        uid=uid,
        name=name,
        type="CpmiGateway",
        ip_address="10.0.0.1",
        mgmt_name=mgmt_name,
    )


class TestGetGateways:
    """Tests for get_gateways() cache_mode dispatch."""

    @pytest.mark.asyncio
    async def test_force_mode_refreshes_before_reading_cache(self):
        mock_client = MagicMock()
        mock_orchestration = AsyncMock()
        mock_client._orchestration = mock_orchestration

        called = []

        async def mock_generator(*args, **kwargs):
            called.append(kwargs)
            yield "event"

        mock_client.build_refresh_assets_cache = mock_generator

        expected = [_gateway()]
        mock_orchestration.get_gateways.return_value = expected

        result = await get_gateways(client=mock_client, mgmt_names=["mgmt1"], cache_mode="force")

        assert result == expected
        mock_orchestration.get_gateways.assert_called_once_with(mgmt_names=["mgmt1"])
        assert len(called) == 1
        assert called[0]["mgmt_names"] == ["mgmt1"]

    @pytest.mark.asyncio
    async def test_force_mode_with_no_mgmt_names_passes_empty_string(self):
        mock_client = MagicMock()
        mock_orchestration = AsyncMock()
        mock_client._orchestration = mock_orchestration

        called = []

        async def mock_generator(*args, **kwargs):
            called.append(kwargs)
            yield "event"

        mock_client.build_refresh_assets_cache = mock_generator
        mock_orchestration.get_gateways.return_value = []

        await get_gateways(client=mock_client, cache_mode="force")

        assert called[0]["mgmt_names"] == ""

    @pytest.mark.asyncio
    async def test_smart_mode_non_empty_cache_skips_refresh(self):
        mock_client = MagicMock()
        mock_orchestration = AsyncMock()
        mock_client._orchestration = mock_orchestration
        mock_client.build_refresh_assets_cache = AsyncMock()

        expected = [_gateway()]
        mock_orchestration.get_gateways.return_value = expected

        result = await get_gateways(client=mock_client, mgmt_names=["mgmt1"], cache_mode="smart")

        assert result == expected
        mock_orchestration.get_gateways.assert_called_once_with(mgmt_names=["mgmt1"])
        mock_client.build_refresh_assets_cache.assert_not_called()

    @pytest.mark.asyncio
    async def test_smart_mode_empty_cache_triggers_populate_then_rereads(self):
        mock_client = MagicMock()
        mock_orchestration = AsyncMock()
        mock_client._orchestration = mock_orchestration

        called = []

        async def mock_generator(*args, **kwargs):
            called.append(kwargs)
            yield "event"

        mock_client.build_refresh_assets_cache = mock_generator

        expected = [_gateway()]
        mock_orchestration.get_gateways.side_effect = [[], expected]

        result = await get_gateways(client=mock_client, mgmt_names=["mgmt1"], cache_mode="smart")

        assert result == expected
        assert len(called) == 1
        assert called[0]["cache_mode"] == "auto"
        assert called[0]["mgmt_names"] == ["mgmt1"]
        assert mock_orchestration.get_gateways.call_count == 2

    @pytest.mark.asyncio
    async def test_smart_mode_stays_empty_after_populate_attempt(self):
        """Even if the populate attempt doesn't help, smart mode returns whatever came back."""
        mock_client = MagicMock()
        mock_orchestration = AsyncMock()
        mock_client._orchestration = mock_orchestration

        async def mock_generator(*args, **kwargs):
            yield "event"

        mock_client.build_refresh_assets_cache = mock_generator
        mock_orchestration.get_gateways.side_effect = [[], []]

        result = await get_gateways(client=mock_client, mgmt_names=["mgmt1"], cache_mode="smart")

        assert result == []
        assert mock_orchestration.get_gateways.call_count == 2

    @pytest.mark.asyncio
    async def test_cache_mode_reads_cache_only(self):
        mock_client = MagicMock()
        mock_orchestration = AsyncMock()
        mock_client._orchestration = mock_orchestration
        mock_client.build_refresh_assets_cache = AsyncMock()

        mock_orchestration.get_gateways.return_value = []

        result = await get_gateways(client=mock_client, mgmt_names=["mgmt1"], cache_mode="cache")

        assert result == []
        mock_orchestration.get_gateways.assert_called_once_with(mgmt_names=["mgmt1"])
        mock_client.build_refresh_assets_cache.assert_not_called()

    @pytest.mark.asyncio
    async def test_logs_when_user_context_provided(self):
        mock_client = MagicMock()
        mock_orchestration = AsyncMock()
        mock_client._orchestration = mock_orchestration
        mock_orchestration.get_gateways.return_value = []

        result = await get_gateways(client=mock_client, mgmt_names=["mgmt1"], cache_mode="cache", user_context=_USER)

        assert result == []

    @pytest.mark.asyncio
    async def test_defaults_to_smart_mode(self):
        mock_client = MagicMock()
        mock_orchestration = AsyncMock()
        mock_client._orchestration = mock_orchestration
        mock_client.build_refresh_assets_cache = AsyncMock()

        expected = [_gateway()]
        mock_orchestration.get_gateways.return_value = expected

        result = await get_gateways(client=mock_client, mgmt_names=["mgmt1"])

        assert result == expected
        mock_client.build_refresh_assets_cache.assert_not_called()


class TestRefreshAssets:
    """Tests for refresh_assets() cache_mode dispatch."""

    @pytest.mark.asyncio
    async def test_force_mode_refreshes_every_mgmt(self):
        mock_client = MagicMock()
        mock_orchestration = AsyncMock()
        mock_client._orchestration = mock_orchestration

        called = []

        async def mock_generator(*args, **kwargs):
            called.append(kwargs)
            yield "event"

        mock_client.build_refresh_assets_cache = mock_generator

        result = await refresh_assets(client=mock_client, mgmt_names=["mgmt1", "mgmt2"], cache_mode="force")

        assert result == {
            "total": 2,
            "refreshed": 2,
            "skipped": 0,
            "details": [
                {"mgmt_name": "mgmt1", "status": "refreshed"},
                {"mgmt_name": "mgmt2", "status": "refreshed"},
            ],
        }
        assert len(called) == 2
        assert called[0]["mgmt_names"] == ["mgmt1"]
        assert called[1]["mgmt_names"] == ["mgmt2"]
        mock_orchestration._is_cache_fresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_smart_mode_skips_fresh_mgmt(self):
        mock_client = MagicMock()
        mock_orchestration = AsyncMock()
        mock_client._orchestration = mock_orchestration
        mock_client.build_refresh_assets_cache = AsyncMock()

        mock_orchestration._is_cache_fresh.return_value = True

        result = await refresh_assets(client=mock_client, mgmt_names=["mgmt1"], cache_mode="smart")

        assert result["total"] == 1
        assert result["refreshed"] == 0
        assert result["skipped"] == 1
        assert result["details"] == [{"mgmt_name": "mgmt1", "status": "skipped", "reason": "fresh"}]
        mock_orchestration._is_cache_fresh.assert_called_once_with(table="assets", mgmt_name="mgmt1", domain="")
        mock_client.build_refresh_assets_cache.assert_not_called()

    @pytest.mark.asyncio
    async def test_smart_mode_refreshes_stale_mgmt(self):
        mock_client = MagicMock()
        mock_orchestration = AsyncMock()
        mock_client._orchestration = mock_orchestration
        mock_orchestration._is_cache_fresh.return_value = False

        called = []

        async def mock_generator(*args, **kwargs):
            called.append(kwargs)
            yield "event"

        mock_client.build_refresh_assets_cache = mock_generator

        result = await refresh_assets(client=mock_client, mgmt_names=["mgmt1"], cache_mode="smart")

        assert result["total"] == 1
        assert result["refreshed"] == 1
        assert result["skipped"] == 0
        assert len(called) == 1
        assert called[0]["mgmt_names"] == ["mgmt1"]

    @pytest.mark.asyncio
    async def test_mixed_fresh_and_stale_mgmts(self):
        mock_client = MagicMock()
        mock_orchestration = AsyncMock()
        mock_client._orchestration = mock_orchestration
        mock_orchestration._is_cache_fresh.side_effect = [True, False]

        async def mock_generator(*args, **kwargs):
            yield "event"

        mock_client.build_refresh_assets_cache = mock_generator

        result = await refresh_assets(client=mock_client, mgmt_names=["mgmt1", "mgmt2"], cache_mode="smart")

        assert result["total"] == 2
        assert result["refreshed"] == 1
        assert result["skipped"] == 1

    @pytest.mark.asyncio
    async def test_defaults_to_force_mode(self):
        mock_client = MagicMock()
        mock_orchestration = AsyncMock()
        mock_client._orchestration = mock_orchestration

        async def mock_generator(*args, **kwargs):
            yield "event"

        mock_client.build_refresh_assets_cache = mock_generator

        result = await refresh_assets(client=mock_client, mgmt_names=["mgmt1"])

        assert result["refreshed"] == 1
        mock_orchestration._is_cache_fresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_logs_when_user_context_provided(self):
        mock_client = MagicMock()
        mock_orchestration = AsyncMock()
        mock_client._orchestration = mock_orchestration

        async def mock_generator(*args, **kwargs):
            yield "event"

        mock_client.build_refresh_assets_cache = mock_generator

        result = await refresh_assets(client=mock_client, mgmt_names=["mgmt1"], cache_mode="force", user_context=_USER)

        assert result["refreshed"] == 1

    @pytest.mark.asyncio
    async def test_empty_mgmt_names_returns_zero_totals(self):
        mock_client = MagicMock()
        mock_orchestration = AsyncMock()
        mock_client._orchestration = mock_orchestration

        result = await refresh_assets(client=mock_client, mgmt_names=[], cache_mode="force")

        assert result == {"total": 0, "refreshed": 0, "skipped": 0, "details": []}
