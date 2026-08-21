"""ArodonataClient.get_gateways must not run the object-cache coordinator."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from .client_test_helpers import make_client


@pytest.mark.asyncio
async def test_client_get_gateways_inner_reads_use_cache_mode_cache():
    """Both orchestration reads (initial + empty-retry) pass cache_mode='cache'."""
    client = make_client()
    client._orchestration = MagicMock()
    client._orchestration.get_gateways = AsyncMock(return_value=[])

    async def _empty_refresh(*args, **kwargs):
        yield {"status": "done"}

    client.build_refresh_assets_cache = _empty_refresh

    await client.get_gateways(mgmt_names=["mgmt1"], cache_mode="smart")

    assert client._orchestration.get_gateways.await_count == 2
    for c in client._orchestration.get_gateways.await_args_list:
        assert c.kwargs["cache_mode"] == "cache"
