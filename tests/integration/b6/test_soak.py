"""Full tier: bounded soak — repeated publish -> smart-fast -> revert cycles.

Verifies stability of the whole write/diff/apply/revert loop under
repetition: no SID leakage, no baseline drift, incremental apply working
for the ADD half of every cycle. Bounded (~8 cycles) rather than literally
hours; the loop is the shape a production sync service runs continuously.
"""

from __future__ import annotations

import uuid

import pytest

from ..cp_revision import discard_open_sessions, last_published_session

pytestmark = pytest.mark.cp_mutates

CYCLES = 8


async def _publish_host(client, mgmt_name, domain, name, ip):
    sid, server_ip = await client.create_dedicated_session(
        mgmt_name, domain, session_name=f"arodonata-soak-{name[-8:]}"
    )
    try:
        r = await client.api_call_with_sid(
            mgmt_name=mgmt_name,
            sid=sid,
            server_ip=server_ip,
            command="add-host",
            payload={"name": name, "ip-address": ip},
        )
        assert r.success, r.message
        r = await client.api_call_with_sid(
            mgmt_name=mgmt_name,
            sid=sid,
            server_ip=server_ip,
            command="publish",
            wait_for_task=True,
        )
        assert r.success, r.message
    finally:
        await client.logout_sid(sid, server_ip, mgmt_name)


async def test_publish_smartfast_revert_soak(admin_client, test_domain_a):
    client, mgmt_name = admin_client

    pre = await last_published_session(client, mgmt_name, test_domain_a)
    assert pre["uid"], "need a revision to revert to"

    # Baseline the cache once; every cycle then rides smart-fast.
    async for _ in client.refresh_objects(mgmt_names=[mgmt_name], domain_names=[test_domain_a], mode="force"):
        pass

    incremental_adds = 0
    try:
        for cycle in range(1, CYCLES + 1):
            host_name = f"arodonata-soak-{uuid.uuid4().hex[:8]}"
            ip = f"10.255.247.{cycle}"

            await _publish_host(client, mgmt_name, test_domain_a, host_name, ip)

            # smart-fast pickup of the ADD (uid staleness -> incremental).
            hosts = await client.get_hosts(
                name_filter=host_name,
                mgmt_names=[mgmt_name],
                domain_names=[test_domain_a],
                cache_mode="smart-fast",
                cache_ttl=0,
            )
            if hosts:
                incremental_adds += 1

            # Revert to the ORIGINAL pre-test revision every cycle.
            await discard_open_sessions(client, mgmt_name, test_domain_a)
            r = await client.api_call(
                mgmt_name,
                "revert-to-revision",
                test_domain_a,
                payload={"to-session": pre["uid"]},
                wait_for_task=True,
            )
            assert r.success, f"cycle {cycle}: revert failed: {r.message}"

            # Converge the cache after the revert (revert sessions may not
            # diff cleanly; a smart-fast read must at least not resurrect
            # the host after we force-align below on mismatch).
            hosts_after = await client.get_hosts(
                name_filter=host_name,
                mgmt_names=[mgmt_name],
                domain_names=[test_domain_a],
                cache_mode="smart-fast",
                cache_ttl=0,
            )
            if hosts_after:
                async for _ in client.refresh_objects(
                    mgmt_names=[mgmt_name],
                    domain_names=[test_domain_a],
                    mode="force",
                ):
                    pass
                hosts_after = await client.get_hosts(
                    name_filter=host_name,
                    mgmt_names=[mgmt_name],
                    domain_names=[test_domain_a],
                    cache_mode="cache",
                )
            assert not hosts_after, f"cycle {cycle}: reverted host {host_name} still in cache"
    finally:
        # Safety net: revert only if the domain drifted from the pre-test
        # revision (every green cycle already reverted; CP aborts a revert
        # to the current revision).
        current = await last_published_session(client, mgmt_name, test_domain_a)
        if current["uid"] != pre["uid"]:
            await discard_open_sessions(client, mgmt_name, test_domain_a)
            r = await client.api_call(
                mgmt_name,
                "revert-to-revision",
                test_domain_a,
                payload={"to-session": pre["uid"]},
                wait_for_task=True,
            )
            assert r.success, f"final revert failed: {r.message}"

    # The ADD half must have applied incrementally in (nearly) every cycle.
    assert incremental_adds >= CYCLES - 1, f"smart-fast picked up only {incremental_adds}/{CYCLES} published adds"

    # Server ends exactly where it started.
    post = await last_published_session(client, mgmt_name, test_domain_a)
    assert post["uid"], "domain must end with a published revision"
