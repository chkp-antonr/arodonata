"""Medium tier: rulebase refresh and cache-first rulebase reads.

Non-mutating: rulebase collection reads policy, never publishes.
"""

from __future__ import annotations

import pytest

from arodonata.api.schemas import SSEEventType
from arodonata.models import AccessRule
from arodonata.rulebase.numbering import number_package
from tests.unit.rulebase.golden import FPCR_UAT_ACTIVE_ACCESS, summarize

from ..cp_revision import last_published_session


async def _refresh_rulebases(client, mgmt_name: str, domain: str) -> list:
    return [e async for e in client.refresh_rulebases(mgmt_names=[mgmt_name], domain_names=[domain], mode="force")]


def _errors_by_type(events: list) -> dict[str, list[str]]:
    """ERROR event messages grouped by rulebase type, so a failing type (e.g. threat via the shared IPS layer) stands out."""
    grouped: dict[str, list[str]] = {}
    for e in events:
        if e.event_type == SSEEventType.ERROR:
            grouped.setdefault(str((e.data or {}).get("rulebase_type", "?")), []).append(e.message)
    return grouped


async def test_refresh_rulebases_single_domain(apikey_client, test_domain_a):
    """Rulebase refresh scoped to TEST_DOMAIN_A completes without errors."""
    client, mgmt_name = apikey_client

    events = await _refresh_rulebases(client, mgmt_name, test_domain_a)
    assert events[0].event_type == SSEEventType.START
    assert events[-1].event_type == SSEEventType.COMPLETE, events[-1].message
    errors = _errors_by_type(events)
    assert not errors, f"Rulebase refresh errors by type: {errors}"


async def test_get_access_rules_from_cache(apikey_client, test_domain_a):
    """Access rules land in the cache as typed models with layer + number."""
    client, mgmt_name = apikey_client

    await _refresh_rulebases(client, mgmt_name, test_domain_a)
    rules = await client.get_access_rules(mgmt_names=[mgmt_name], domain_names=[test_domain_a], cache_mode="cache")
    if not rules:
        pytest.skip(f"{test_domain_a} has no access rules (no policy package?)")

    rule = rules[0]
    assert isinstance(rule, AccessRule)
    assert rule.uid
    assert rule.rule_number is not None
    assert rule.action, "Cached rules must carry an action"


async def test_layer_name_persisted(apikey_client, test_domain_a):
    """Cached access rules carry the name of the layer they were read from (rulebase cache v2, phase 1)."""
    client, mgmt_name = apikey_client
    await _refresh_rulebases(client, mgmt_name, test_domain_a)
    rules = await client.get_access_rules(mgmt_names=[mgmt_name], domain_names=[test_domain_a], cache_mode="cache")
    if not rules:
        pytest.skip(f"{test_domain_a} has no access rules")
    assert all(r.layer_name for r in rules)
    for layer in {r.layer_name for r in rules}:
        by_layer = await client.get_access_rules(
            layer_name=layer, mgmt_names=[mgmt_name], domain_names=[test_domain_a], cache_mode="cache"
        )
        assert by_layer and {r.layer_name for r in by_layer} == {layer}


async def test_domain4_network_layer_has_six_named_rules(apikey_client, test_domain_a):
    """Home-lab Domain4: FPCR_UAT_Active Network is cached completely with action names; NAT keyed by package."""
    if test_domain_a != "Domain4":
        pytest.skip("asserts the home-lab Domain4 shape")
    client, mgmt_name = apikey_client
    events = await _refresh_rulebases(client, mgmt_name, test_domain_a)
    assert not _errors_by_type(events), _errors_by_type(events)
    rules = await client.get_access_rules(
        layer_name="FPCR_UAT_Active Network", mgmt_names=[mgmt_name], domain_names=[test_domain_a], cache_mode="cache"
    )
    assert [r.rule_number for r in rules] == [1, 2, 3, 4, 5, 6]
    assert [r.action for r in rules] == ["Accept", "Inner Layer", "Accept", "Accept", "Accept", "Drop"]
    nat = await client.get_nat_rules(mgmt_names=[mgmt_name], domain_names=[test_domain_a], cache_mode="cache")
    assert all(r.layer_name != "NAT" for r in nat)
    assert any(r.layer_name == "FPCR_UAT_Active" for r in nat), "NAT rules of package FPCR_UAT_Active not cached"


async def test_enabled_only_filter(apikey_client, test_domain_a):
    """enabled_only=True returns a subset of all rules (all of them enabled)."""
    client, mgmt_name = apikey_client

    all_rules = await client.get_access_rules(mgmt_names=[mgmt_name], domain_names=[test_domain_a], cache_mode="cache")
    if not all_rules:
        pytest.skip(f"{test_domain_a} has no access rules")

    enabled = await client.get_access_rules(
        mgmt_names=[mgmt_name],
        domain_names=[test_domain_a],
        enabled_only=True,
        cache_mode="cache",
    )
    assert len(enabled) <= len(all_rules)
    assert all(r.enabled for r in enabled)


async def test_domain4_snapshot_numbers_match_smartconsole(apikey_client, test_domain_a):
    """Home-lab Domain4: the cached snapshot numbers FPCR_UAT_Active exactly like SmartConsole (rulebase cache v2, phase 2)."""
    if test_domain_a != "Domain4":
        pytest.skip("asserts the home-lab Domain4 shape")
    client, mgmt_name = apikey_client
    events = await _refresh_rulebases(client, mgmt_name, test_domain_a)
    assert not _errors_by_type(events), _errors_by_type(events)
    snapshot = await client.cache.load_domain_rulebase_snapshot(mgmt_name, test_domain_a)
    layout = next(p for p in snapshot.packages if p.package_name == "FPCR_UAT_Active")
    numbered = number_package(layout, "access", {layer.layer_uid: layer for layer in snapshot.layers})
    assert summarize(numbered[0]) == FPCR_UAT_ACTIVE_ACCESS
    assert [o.layer_name for o in layout.layers if o.rulebase_type == "access"] == [
        "arod-global-pkg Network",
        "FPCR_UAT_Active AppControl",
    ]
    assert numbered[1] and numbered[1][0].number == "1"
    state = await client.cache.get_rulebase_sync_state(mgmt_name, test_domain_a)
    head = await last_published_session(client, mgmt_name, test_domain_a)
    assert (state.status, state.session_uid) == ("ok", head["uid"])
