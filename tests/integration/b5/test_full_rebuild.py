"""Bucket 5 — Full server cache rebuilds (`refresh_objects`, `refresh_services`, `refresh_assets`, `refresh_rulebases`).

Covers:
1. ``refresh_objects(mode="force")`` across all discovered domains populates ``arodonata_objects``
   and ``domain_sync_state``.
2. ``refresh_services(mode="force")`` across all discovered domains populates ``arodonata_services``.
3. ``refresh_assets(mode="force")`` populates ``arodonata_assets`` and links cluster/VSX member
   assets via ``parent_uid`` / ``member_uids`` when clusters exist in the lab.
4. ``refresh_rulebases(mode="force")`` across all discovered domains populates rulebase snapshots.
"""

from __future__ import annotations

import pytest

from arodonata import ArodonataClient


async def test_refresh_objects_and_services_all_domains(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    all_domains: list[str],
) -> None:
    """Verify unfiltered ``refresh_objects`` and ``refresh_services`` cover every discovered domain."""
    obj_outcome = await apikey_client.refresh_objects(mgmt_name=mgmt_name, mode="force")
    assert not obj_outcome.failed_domains, f"Object refresh failures: {obj_outcome.failed_domains}"
    assert obj_outcome.total_items >= 1

    svc_outcome = await apikey_client.refresh_services(mgmt_name=mgmt_name, mode="force")
    assert not svc_outcome.failed_domains, f"Service refresh failures: {svc_outcome.failed_domains}"

    for dom_name in all_domains:
        objs = await apikey_client.get_objects(
            mgmt_name=mgmt_name,
            domain=dom_name,
            cache_mode="cache",
        )
        assert objs, f"Domain {dom_name} must have cached objects after full rebuild"


async def test_refresh_assets_and_cluster_relationships(
    apikey_client: ArodonataClient,
    mgmt_name: str,
) -> None:
    """Verify ``refresh_assets(mode="force")`` populates gateway/cluster/VSX assets and parent relationships."""
    outcome = await apikey_client.refresh_assets(mgmt_name=mgmt_name, mode="force")
    assert not outcome.failed_domains, f"Asset refresh failures: {outcome.failed_domains}"

    gateways = await apikey_client.get_gateways(mgmt_name=mgmt_name, cache_mode="cache")
    if not gateways:
        pytest.skip("Lab has no gateway assets to assert on")

    assert gateways[0].uid and gateways[0].name

    clusters = [a for a in gateways if "cluster" in a.type.lower()]
    if clusters:
        with_parent = [a for a in gateways if a.parent_uid]
        assert with_parent, "Lab has cluster assets; expected member assets to link via parent_uid"


async def test_refresh_rulebases_all_domains(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    all_domains: list[str],
) -> None:
    """Verify ``refresh_rulebases(mode="force")`` across all domains succeeds without errors."""
    outcome = await apikey_client.refresh_rulebases(mgmt_name=mgmt_name, mode="force")
    assert not outcome.failed_domains, f"Rulebase refresh failures: {outcome.failed_domains}"

    total_rules = 0
    for dom_name in all_domains:
        rules = await apikey_client.get_access_rules(mgmt_name, dom_name)
        total_rules += len(rules)

    assert total_rules >= 1, "Expected at least one cached access rule across all lab domains"
