"""Rule-getter helpers must pass cache_mode/cache_ttl through to orchestration."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from arodonata.helpers.policy import (
    get_access_rules,
    get_https_rules,
    get_nat_rules,
    get_threat_rules,
)

HELPERS_AND_ORCH_METHODS = [
    (get_access_rules, "get_access_rules"),
    (get_nat_rules, "get_nat_rules"),
    (get_https_rules, "get_https_rules"),
    (get_threat_rules, "get_threat_rules"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("helper,orch_method", HELPERS_AND_ORCH_METHODS)
async def test_rule_helper_passes_cache_mode(helper, orch_method):
    client = MagicMock()
    mock_method = AsyncMock(return_value=[])
    setattr(client._orchestration, orch_method, mock_method)

    await helper(
        client,
        layer_name="Network",
        mgmt_name="mgmt1",
        domain_name="dom1",
        cache_mode="cache",
        cache_ttl=60,
    )

    call = mock_method.await_args
    assert call.kwargs["cache_mode"] == "cache"
    assert call.kwargs["cache_ttl"] == 60
