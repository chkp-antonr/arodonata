"""Medium tier: cache-first reads and search against a freshly built domain cache.

Non-mutating. One force build per module, then everything reads from cache.
"""

from __future__ import annotations

import os

import pytest

from arodonata import ArodonataClient, ArodonataSettings
from arodonata.api.schemas import SSEEventType
from arodonata.models import Host, Network


@pytest.fixture(scope="module")
async def built_domain(db_engine):
    """(mgmt_name, domain_name) with TEST_DOMAIN_A force-built once per module."""
    mgmt_ip = os.getenv("API_MGMT")
    api_key = os.getenv("APIKEY")
    domain = os.getenv("TEST_DOMAIN_A")
    if not mgmt_ip or not api_key or not domain:
        pytest.skip("API_MGMT/APIKEY/TEST_DOMAIN_A not set")

    settings = ArodonataSettings(mgmt_names=mgmt_ip, mgmt_servers=mgmt_ip, api_keys=api_key)
    async with ArodonataClient(engine=db_engine, settings=settings) as client:
        if client._login_coordinator:
            client._login_coordinator._session_cleaner = None
        async for _ in client.refresh_objects(mgmt_names=[mgmt_ip], domain_names=[domain], mode="force"):
            pass
    return mgmt_ip, domain


async def _cached_hosts(client, mgmt_name, domain) -> list[Host]:
    return await client.get_hosts(mgmt_names=[mgmt_name], domain_names=[domain], cache_mode="cache")


async def test_get_hosts_returns_typed_models(apikey_client, built_domain):
    client, _ = apikey_client
    mgmt_name, domain = built_domain

    hosts = await _cached_hosts(client, mgmt_name, domain)
    if not hosts:
        pytest.skip(f"{domain} has no host objects")
    h = hosts[0]
    assert isinstance(h, Host)
    assert h.uid and h.name and h.mgmt_name == mgmt_name


async def test_get_hosts_wildcard_filter(apikey_client, built_domain):
    """A wildcard built from a real host's name prefix matches that host."""
    client, _ = apikey_client
    mgmt_name, domain = built_domain

    hosts = await _cached_hosts(client, mgmt_name, domain)
    if not hosts:
        pytest.skip(f"{domain} has no host objects")
    target = hosts[0]
    pattern = target.name[: max(1, len(target.name) - 1)] + "*"

    filtered = await client.get_hosts(
        name_filter=pattern,
        mgmt_names=[mgmt_name],
        domain_names=[domain],
        cache_mode="cache",
    )
    assert any(h.uid == target.uid for h in filtered), f"Wildcard {pattern!r} must match {target.name!r}"


async def test_get_networks_returns_typed_models(apikey_client, built_domain):
    client, _ = apikey_client
    mgmt_name, domain = built_domain

    networks = await client.get_networks(mgmt_names=[mgmt_name], domain_names=[domain], cache_mode="cache")
    if not networks:
        pytest.skip(f"{domain} has no network objects")
    assert isinstance(networks[0], Network)
    assert networks[0].uid and networks[0].name


async def test_search_by_name_finds_cached_host(apikey_client, built_domain):
    client, _ = apikey_client
    mgmt_name, domain = built_domain

    hosts = await _cached_hosts(client, mgmt_name, domain)
    if not hosts:
        pytest.skip(f"{domain} has no host objects")
    target = hosts[0]

    events = [e async for e in client.search_objects(target.name, mgmt_names=[mgmt_name], domain_names=[domain])]
    assert events[-1].event_type == SSEEventType.COMPLETE
    # Search results are emitted as LOG events carrying data["objects"].
    found_names = [obj.get("name") for e in events for obj in (e.data or {}).get("objects", [])]
    assert target.name in found_names, f"search must find {target.name!r} by name"


async def test_search_by_ip_finds_cached_host(apikey_client, built_domain):
    client, _ = apikey_client
    mgmt_name, domain = built_domain

    hosts = [h for h in await _cached_hosts(client, mgmt_name, domain) if h.ip_address]
    if not hosts:
        pytest.skip(f"{domain} has no hosts with IPs")
    target = hosts[0]

    events = [e async for e in client.search_objects(target.ip_address, mgmt_names=[mgmt_name], domain_names=[domain])]
    found_uids = [obj.get("uid") for e in events for obj in (e.data or {}).get("objects", [])]
    assert target.uid in found_uids, f"search by IP {target.ip_address} must find {target.name!r}"


async def test_get_object_by_uid_roundtrip(apikey_client, built_domain):
    client, _ = apikey_client
    mgmt_name, domain = built_domain

    objects = await client.cache.get_objects(mgmt_names=[mgmt_name], domain_names=[domain])
    if not objects:
        pytest.skip(f"{domain} cache is empty")
    target = objects[0]

    fetched = await client.get_object_by_uid(target.uid, mgmt_name=mgmt_name, domain_name=domain)
    assert fetched is not None
    assert fetched.name == target.name
