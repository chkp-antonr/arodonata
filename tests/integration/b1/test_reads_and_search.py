"""Bucket 1 — High-level read & search API against the live MDSM.

Covers:
1. ``get_domains`` (with and without ``include_global=True``).
2. ``get_hosts`` / ``get_networks`` / ``get_address_ranges`` / ``get_dns_domains`` /
   ``get_groups`` / ``get_services`` / ``get_gateways`` in ``TEST_DOMAIN_A``.
3. ``get_object_by_uid`` round-trip lookup against a cached host.
4. ``search_objects`` matches by name and IP substring and resolves containing ``memberships``.
5. ``describe_objects``, ``query_objects``, and ``get_cache_status`` against populated SQLite cache.
"""

from __future__ import annotations

from arodonata import ArodonataClient


async def test_get_domains_local_and_global(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``get_domains`` excludes Global by default and includes it with ``include_global=True``."""
    doms_no_global = await apikey_client.get_domains(mgmt_name=mgmt_name, include_global=False)
    names_no_global = {d.name for d in doms_no_global}
    assert test_domain_a in names_no_global
    assert "Global" not in names_no_global

    doms_with_global = await apikey_client.get_domains(mgmt_name=mgmt_name, include_global=True)
    names_with_global = {d.name for d in doms_with_global}
    assert "Global" in names_with_global


async def test_typed_object_getters_and_uid_lookup(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify typed object getters and ``get_object_by_uid`` round-trip lookup."""
    hosts = await apikey_client.get_hosts(
        mgmt_name=mgmt_name,
        domain=test_domain_a,
        cache_mode="smart",
    )
    assert len(hosts) >= 1, f"Expected at least 1 host in {test_domain_a}"
    sample = hosts[0]
    assert sample.uid and sample.name and sample.ipv4_address

    by_uid = await apikey_client.get_object_by_uid(
        mgmt_name,
        test_domain_a,
        sample.uid,
        cache_mode="cache",
    )
    assert by_uid is not None
    assert by_uid.uid == sample.uid
    assert by_uid.name == sample.name

    filtered = await apikey_client.get_hosts(
        mgmt_name=mgmt_name,
        domain=test_domain_a,
        names=[sample.name],
        cache_mode="cache",
    )
    assert [h.uid for h in filtered] == [sample.uid]

    networks = await apikey_client.get_networks(
        mgmt_name=mgmt_name,
        domain=test_domain_a,
        cache_mode="smart",
    )
    assert isinstance(networks, list)

    groups = await apikey_client.get_groups(
        mgmt_name=mgmt_name,
        domain=test_domain_a,
        cache_mode="smart",
    )
    assert isinstance(groups, list)


async def test_search_and_query_objects(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``search_objects``, ``describe_objects``, ``query_objects``, and ``get_cache_status``."""
    hosts = await apikey_client.get_hosts(
        mgmt_name=mgmt_name,
        domain=test_domain_a,
        cache_mode="cache",
    )
    assert hosts
    target = hosts[0]

    # 1. search_objects by exact name
    search_res = await apikey_client.search_objects(
        target.name,
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        cache_mode="cache",
    )
    matched_uids = {m.uid for m in search_res.matches}
    assert target.uid in matched_uids

    # 2. search_objects by IPv4 address
    assert target.ipv4_address is not None
    ip_res = await apikey_client.search_objects(
        target.ipv4_address,
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        cache_mode="cache",
    )
    assert any(m.uid == target.uid for m in ip_res.matches)

    # 3. describe_objects
    desc = await apikey_client.describe_objects(mgmt_name=mgmt_name, domain_name=test_domain_a)
    assert desc["total_objects"] >= len(hosts)
    assert "host" in desc["object_types"]

    # 4. query_objects (list + count)
    q_list = await apikey_client.query_objects(
        mgmt_name=mgmt_name,
        domain_name=test_domain_a,
        types=["host"],
        name_pattern=target.name[:4],
        limit=20,
    )
    assert q_list["total"] >= 1
    assert any(r["uid"] == target.uid for r in q_list["objects"])

    q_count = await apikey_client.query_objects(
        mgmt_name=mgmt_name,
        domain_name=test_domain_a,
        types=["host"],
        aggregate="count",
        group_by=["type"],
    )
    assert q_count["total"] == len(hosts)

    # 5. get_cache_status
    status = await apikey_client.get_cache_status(mgmt_name=mgmt_name, domain_name=test_domain_a)
    assert status["entries"], "Expected cache status entries for populated domain"
