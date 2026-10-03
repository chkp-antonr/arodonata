"""Domains on one MDS member share the member's RateLimiter slots (real RateLimiter, fake lock store)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from arodonata.asdk.client import AMgmtClient
from arodonata.asdk.rate_limiter import RateLimiter
from tests.unit.asdk.test_rate_limiter import FakeLockManager

MEMBER = {"Domain4": "192.168.5.170", "Domain5": "192.168.5.170", "Domain6": "192.168.5.171"}
DOMAIN_IP = {"Domain4": "192.168.5.184", "Domain5": "192.168.5.185", "Domain6": "192.168.5.186"}


def _client(limit: int):
    limiter = RateLimiter(concurrent_limit=limit, lock_manager=FakeLockManager(), slot_timeout=5)
    lc = AsyncMock()
    lc._credential_username = None
    lc.login = AsyncMock(side_effect=lambda mgmt, domain, **kw: ("sid", DOMAIN_IP[domain]))
    lc.mds_host = AsyncMock(side_effect=lambda mgmt, domain: MEMBER[domain])
    lc.maintain_keepalives = AsyncMock()
    lc.close = AsyncMock()
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(port=None)
    release = asyncio.Event()
    in_flight: list[str] = []

    async def api_call(**kw):
        in_flight.append(kw["server_ip"])
        await release.wait()
        return {"success": True, "data": {}}

    transport = AsyncMock()
    transport.api_call = AsyncMock(side_effect=api_call)
    return AMgmtClient(registry, transport, limiter, lc), release, in_flight


async def _run(domains: list[str], limit: int) -> list[str]:
    client, release, in_flight = _client(limit)
    calls = [asyncio.create_task(client.api_call("home", "show-hosts", domain=d)) for d in domains]
    await asyncio.sleep(0.3)
    started = sorted(in_flight)
    release.set()
    await asyncio.gather(*calls)
    assert len(in_flight) == len(domains)
    await client.close()
    return started


async def test_domains_on_one_member_share_its_slots():
    # limit 2 per member: the third call to member .170 waits, whichever of its domains it targets
    assert await _run(["Domain4", "Domain5", "Domain4"], limit=2) == ["192.168.5.184", "192.168.5.185"]


async def test_domains_on_different_members_do_not_block_each_other():
    started = await _run(["Domain4", "Domain5", "Domain6"], limit=2)
    assert started == ["192.168.5.184", "192.168.5.185", "192.168.5.186"]
