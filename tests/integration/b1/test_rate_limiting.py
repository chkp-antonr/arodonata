"""Bucket 1 — Per-MDS-server rate limiting against the live MDSM.

Covers:
1. 12 concurrent ``api_call`` invocations on a client with ``concurrent_limit=2`` all succeed
   (queued through ``RateLimiter.slot`` without Check Point errors).
2. ``RateLimiter`` slot exhaustion raises ``RateLimitTimeoutError`` when slots are held longer
   than ``rate_limit_slot_timeout``.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from arodonata import (
    ArodonataClient,
    ArodonataSettings,
    RateLimitTimeoutError,
)


async def test_12_concurrent_calls_throttled_by_rate_limiter(
    mgmt_name: str,
    mgmt_ip: str,
    api_key: str,
    test_domain_a: str,
    db_engine: AsyncEngine,
) -> None:
    """Verify 12 concurrent calls queue cleanly through ``concurrent_limit=2``."""
    cfg = ArodonataSettings(
        mgmt_names=[mgmt_name],
        mgmt_servers=[mgmt_ip],
        api_keys=[api_key],
        concurrent_limit=2,
    )
    client = ArodonataClient(settings=cfg, engine=db_engine)
    await client.initialize(run_startup_cleanup=False)
    try:
        # Warm the domain SID first so the 12 calls measure RateLimiter, not login serialization
        warm = await client.api_call(mgmt_name, "show-session", {}, domain=test_domain_a)
        assert warm.success

        results = await asyncio.gather(
            *(client.api_call(mgmt_name, "show-session", {}, domain=test_domain_a) for _ in range(12))
        )
        assert all(r.success for r in results)
    finally:
        await client.close(logout=False)


async def test_rate_limiter_slot_timeout_raises(
    mgmt_name: str,
    mgmt_ip: str,
    api_key: str,
    db_engine: AsyncEngine,
) -> None:
    """Verify ``RateLimiter`` raises ``RateLimitTimeoutError`` when all slots remain held."""
    cfg = ArodonataSettings(
        mgmt_names=[mgmt_name],
        mgmt_servers=[mgmt_ip],
        api_keys=[api_key],
        concurrent_limit=1,
        rate_limit_slot_timeout=0.3,
    )
    client = ArodonataClient(settings=cfg, engine=db_engine)
    await client.initialize(run_startup_cleanup=False)
    try:
        assert client.amgmt is not None
        rl = client.amgmt.rate_limiter
        async with rl.slot(mgmt_ip):
            with pytest.raises(RateLimitTimeoutError):
                async with rl.slot(mgmt_ip):
                    pass
    finally:
        await client.close(logout=False)
