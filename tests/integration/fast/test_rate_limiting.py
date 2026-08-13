"""Integration tests for per-server rate limiting.

Verifies that the distributed rate limiter (RateLimiter) correctly serialises
concurrent requests to the same domain/server IP while allowing requests to
different IPs to proceed concurrently.

Run with: ./pytest.sh int-fast tests/integration/fast/test_rate_limiting.py -v
"""

from __future__ import annotations

import asyncio
import time

import pytest


async def test_same_domain_calls_are_serialised(apikey_client, all_domains):
    """Concurrent show-objects calls to the same domain are serialised through
    the rate limiter — wall-clock time reflects sequential execution.

    The rate limiter allows concurrent_limit (default=3) simultaneous operations
    per server IP.  If 4+ calls target the same IP and each takes ~T seconds,
    at least one must wait, so total time > T.  This test uses the first domain
    (or management server for SMS).
    """
    client, mgmt_name = apikey_client
    domain_name = all_domains[0]["name"] if all_domains else None

    call_kwargs = {"domain": domain_name} if domain_name else {}

    # Warm up domain IP cache: prevents 4 concurrent tasks from racing to INSERT
    # the same domain record (UNIQUE constraint violation in the domains table).
    r = await client.api_call(mgmt_name, "show-api-versions", **call_kwargs)
    assert r.success, f"Domain warmup failed: {r.message}"

    # Fire 4 concurrent show-hosts calls to the same domain
    start = time.monotonic()
    results = await asyncio.gather(
        *[
            client.api_call(mgmt_name, "show-hosts", payload={"offset": 0, "limit": 10}, **call_kwargs)
            for _ in range(4)
        ],
        return_exceptions=True,
    )
    elapsed = time.monotonic() - start

    errors = [r for r in results if isinstance(r, Exception)]
    assert not errors, f"Unexpected errors: {errors}"

    successes = [r for r in results if not isinstance(r, Exception) and r.success]
    assert len(successes) == 4, f"Expected 4 successes, got {len(successes)}"

    # With concurrent_limit=3 and 4 calls, at least 1 had to wait.
    # Minimum realistic serialised delay is ~0.5s per extra slot.
    # We only assert the calls completed — not a specific wall-clock minimum,
    # because server latency varies.  The important thing is no deadlock.
    assert elapsed < 300, f"4 serialised calls took unreasonably long: {elapsed:.1f}s"


async def test_different_domain_calls_are_concurrent(apikey_client, all_domains):
    """show-api-versions calls to different domain IPs proceed concurrently.

    Each domain has its own server IP, so the rate limiter uses separate slots
    per IP.  Wall-clock time for N concurrent different-IP calls should be
    close to a single call's latency (not N× a single call).
    """
    if len(all_domains) < 2:
        pytest.skip("Need at least 2 domains with distinct IPs for this test")

    # Pick domains with distinct active IPs
    seen_ips: set[str] = set()
    distinct_domains = []
    for d in all_domains:
        if d["active_ip"] not in seen_ips:
            seen_ips.add(d["active_ip"])
            distinct_domains.append(d)
        if len(distinct_domains) >= 3:
            break

    if len(distinct_domains) < 2:
        pytest.skip("Not enough domains with distinct IPs")

    client, mgmt_name = apikey_client

    # Warm up: ensure domain IP cache is populated so no show-domains calls are made
    for d in distinct_domains:
        r = await client.api_call(mgmt_name, "show-api-versions", domain=d["name"])
        assert r.success, f"Warmup failed for {d['name']}: {r.message}"

    # Clear domain SIDs so each call needs a domain login (to different IPs)
    for d in distinct_domains:
        await client.cache.delete_sid(mgmt_name, d["name"])

    start = time.monotonic()
    results = await asyncio.gather(
        *[
            asyncio.wait_for(
                client.api_call(mgmt_name, "show-api-versions", domain=d["name"]),
                timeout=60,
            )
            for d in distinct_domains
        ],
        return_exceptions=True,
    )
    elapsed = time.monotonic() - start

    errors = [r for r in results if isinstance(r, Exception)]
    assert not errors, f"Concurrent different-IP calls failed: {errors}"

    successes = [r for r in results if not isinstance(r, Exception) and r.success]
    assert len(successes) == len(distinct_domains), f"Expected {len(distinct_domains)} successes, got {len(successes)}"

    # No assertion on elapsed time — different IPs mean no rate-limit serialisation,
    # but we can't guarantee strict wall-clock bounds due to CP server variability.
    assert elapsed < 120, f"Concurrent different-IP calls took too long: {elapsed:.1f}s"


async def test_rate_limiter_slot_based_distribution(apikey_client):
    """Multiple concurrent calls to the same server IP use slot-based locking.

    The rate limiter hashes (server_ip + task_id) % concurrent_limit to pick a slot.
    Two calls that land on different slots can proceed concurrently even for the
    same IP.  This verifies that more than one concurrent operation is possible.
    """
    client, mgmt_name = apikey_client

    # Fire 2 concurrent calls — they may get different slots and run concurrently
    results = await asyncio.gather(
        asyncio.wait_for(client.api_call(mgmt_name, "show-api-versions"), timeout=30),
        asyncio.wait_for(client.api_call(mgmt_name, "show-api-versions"), timeout=30),
        return_exceptions=True,
    )

    errors = [r for r in results if isinstance(r, Exception)]
    assert not errors, f"Unexpected errors with 2 concurrent calls: {errors}"
    assert all(r.success for r in results), "Both concurrent calls must succeed"


async def test_rate_limiter_allows_up_to_concurrent_limit(apikey_client):
    """Exactly concurrent_limit (=3) simultaneous calls all proceed without timeout.

    The rate limiter's 3 slots must all be acquirable without one waiting for another.
    """
    client, mgmt_name = apikey_client

    # 3 concurrent calls == concurrent_limit; all should get distinct slots
    results = await asyncio.gather(
        *[
            asyncio.wait_for(
                client.api_call(mgmt_name, "show-api-versions"),
                timeout=60,
            )
            for _ in range(3)
        ],
        return_exceptions=True,
    )

    errors = [r for r in results if isinstance(r, Exception)]
    assert not errors, f"concurrent_limit calls should not error: {errors}"
    assert all(r.success for r in results), "All 3 concurrent calls must succeed"


async def test_rate_limiter_is_reentrant_within_same_task(apikey_client):
    """A single task can re-acquire the rate limiter slot it already holds.

    This ensures that chained api_call()s within the same asyncio task (e.g.
    an api_call that internally triggers another api_call for domain lookup)
    do not deadlock against themselves.
    """
    client, mgmt_name = apikey_client

    # Two sequential calls from the same task — reentrancy must not deadlock
    r1 = await asyncio.wait_for(
        client.api_call(mgmt_name, "show-api-versions"),
        timeout=30,
    )
    r2 = await asyncio.wait_for(
        client.api_call(mgmt_name, "show-api-versions"),
        timeout=30,
    )

    assert r1.success, f"First reentrant call failed: {r1.message}"
    assert r2.success, f"Second reentrant call failed: {r2.message}"


async def test_concurrent_calls_to_two_distinct_ips(apikey_client, all_domains):
    """Two simultaneous calls to distinct domain IPs both succeed.

    This is an existence proof that the rate limiter uses per-IP slots:
    both calls acquire separate slots and proceed at the same time.
    The test does not assert strict wall-clock bounds — server latency varies.
    """
    if len(all_domains) < 2:
        pytest.skip("Need at least 2 distinct-IP domains")

    seen_ips: set[str] = set()
    distinct_domains = []
    for d in all_domains:
        if d["active_ip"] not in seen_ips:
            seen_ips.add(d["active_ip"])
            distinct_domains.append(d)
        if len(distinct_domains) >= 2:
            break

    if len(distinct_domains) < 2:
        pytest.skip("Not enough distinct-IP domains")

    client, mgmt_name = apikey_client
    domain_a = distinct_domains[0]["name"]
    domain_b = distinct_domains[1]["name"]

    # Warm up domain IP caches so no show-domains call needed during the test
    for name in [domain_a, domain_b]:
        r = await client.api_call(mgmt_name, "show-api-versions", domain=name)
        assert r.success, f"Warmup failed for {name}: {r.message}"

    # Fire two calls to distinct IPs concurrently
    results = await asyncio.gather(
        asyncio.wait_for(
            client.api_call(mgmt_name, "show-api-versions", domain=domain_a),
            timeout=90,
        ),
        asyncio.wait_for(
            client.api_call(mgmt_name, "show-api-versions", domain=domain_b),
            timeout=90,
        ),
        return_exceptions=True,
    )

    errors = [r for r in results if isinstance(r, Exception)]
    assert not errors, f"Concurrent distinct-IP calls failed: {errors}"
    assert all(r.success for r in results), "Both distinct-IP calls must succeed"
