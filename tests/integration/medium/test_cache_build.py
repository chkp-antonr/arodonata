"""Medium tier: single-domain object-cache build and check-mode partial refresh.

Non-mutating: only the local cache changes; CP state is read-only.
"""

from __future__ import annotations

from arodonata.api.schemas import SSEEventType


async def _drain(gen) -> list:
    return [event async for event in gen]


async def test_force_build_populates_single_domain_cache(apikey_client, test_domain_a):
    """A force refresh scoped to TEST_DOMAIN_A fills the cache for that domain."""
    client, mgmt_name = apikey_client

    events = await _drain(client.refresh_objects(mgmt_names=[mgmt_name], domain_names=[test_domain_a], mode="force"))

    types = [e.event_type for e in events]
    assert types[0] == SSEEventType.START
    assert types[-1] == SSEEventType.COMPLETE, f"Last event: {events[-1].message}"

    hosts = await client.get_hosts(mgmt_names=[mgmt_name], domain_names=[test_domain_a], cache_mode="cache")
    objects = await client.cache.get_objects(mgmt_names=[mgmt_name], domain_names=[test_domain_a])
    assert objects, f"Cache must contain objects for {test_domain_a} after force build"
    # hosts may legitimately be empty if the domain has no host objects,
    # but the generic object cache must not be.
    assert isinstance(hosts, list)

    lps = await client.cache.get_last_published_session(mgmt_name, test_domain_a)
    assert lps is not None, "Force build must record the last published session"


async def test_check_mode_skips_fresh_domain(apikey_client, test_domain_a):
    """check-mode immediately after a force build refreshes nothing (fresh)."""
    client, mgmt_name = apikey_client

    # Ensure freshness marker exists (cheap if the previous test just built it).
    await _drain(client.refresh_objects(mgmt_names=[mgmt_name], domain_names=[test_domain_a], mode="force"))

    events = await _drain(client.refresh_objects(mgmt_names=[mgmt_name], domain_names=[test_domain_a], mode="check"))

    refreshed = [e for e in events if (e.data or {}).get("status") == "refreshing_domain"]
    assert not refreshed, (
        f"check-mode must skip a just-built domain, but refreshed: "
        f"{[(e.data or {}).get('domain_name') for e in refreshed]}"
    )
