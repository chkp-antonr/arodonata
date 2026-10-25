"""Bucket 6 — Bounded soak test (`CYCLES = 8` publish -> `smart-fast` -> revert loop).

Verifies stability of the full write/diff/apply/revert loop under repetition:
- No SID leakage or session exhaustion.
- ``smart-fast`` picks up the published host incrementally in each cycle.
- ``revert_domain_to`` restores ``TEST_DOMAIN_A`` cleanly to its baseline revision.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from arodonata import ArodonataClient
from tests.integration.cp_revision import (
    BaselineSnapshot,
    last_published_session,
    revert_domain_to,
)

pytestmark = pytest.mark.cp_mutates

CYCLES = 8


async def test_publish_smartfast_revert_soak(
    antonr_client: ArodonataClient,
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
    cp_baseline_snapshot: BaselineSnapshot,
) -> None:
    """Verify 8 repeated publish -> ``smart-fast`` -> revert cycles complete cleanly."""
    base_a = cp_baseline_snapshot.domains[test_domain_a]

    await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="force",
    )

    incremental_adds = 0
    try:
        for cycle in range(1, CYCLES + 1):
            host_name = f"it-b6-soak-{cycle}-{uuid.uuid4().hex[:6]}"
            ip_addr = f"198.51.100.{100 + cycle}"

            async with antonr_client.write_session(
                mgmt_name,
                test_domain_a,
                session_name=f"b6-soak-{cycle}",
                publish_on_exit=True,
            ):
                res = await antonr_client.add_object(
                    mgmt_name,
                    "host",
                    {"name": host_name, "ipv4-address": ip_addr},
                    domain=test_domain_a,
                )
                assert res.success, f"cycle {cycle} add-host failed: {res.error_message}"

            # smart-fast pickup of the newly published host
            hosts = await apikey_client.get_hosts(
                mgmt_name=mgmt_name,
                domain=test_domain_a,
                names=[host_name],
                cache_mode="smart-fast",
                cache_ttl=0.0,
            )
            if hosts:
                incremental_adds += 1

            await asyncio.sleep(2.0)
            await revert_domain_to(apikey_client, mgmt_name, base_a)

            # Force-align cache after revert so next cycle starts from baseline
            await apikey_client.refresh_objects(
                mgmt_name=mgmt_name,
                domains=[test_domain_a],
                types=["host"],
                mode="force",
            )
            hosts_after = await apikey_client.get_hosts(
                mgmt_name=mgmt_name,
                domain=test_domain_a,
                names=[host_name],
                cache_mode="cache",
            )
            assert not hosts_after, f"cycle {cycle}: reverted host {host_name} still in cache"
    finally:
        current = await last_published_session(apikey_client, mgmt_name, test_domain_a)
        if current.session_uid != base_a.session_uid:
            await revert_domain_to(apikey_client, mgmt_name, base_a)

    assert incremental_adds >= CYCLES - 1, f"smart-fast picked up only {incremental_adds}/{CYCLES} published adds"
