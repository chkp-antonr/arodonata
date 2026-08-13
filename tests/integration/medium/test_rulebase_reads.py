"""Medium tier: rulebase refresh and cache-first rulebase reads.

Non-mutating: rulebase collection reads policy, never publishes.
"""

from __future__ import annotations

import pytest

from arodonata.api.schemas import SSEEventType
from arodonata.models import AccessRule


async def _refresh_rulebases(client, mgmt_name: str, domain: str) -> list:
    return [e async for e in client.refresh_rulebases(mgmt_names=[mgmt_name], domain_names=[domain], mode="force")]


async def test_refresh_rulebases_single_domain(apikey_client, test_domain_a):
    """Rulebase refresh scoped to TEST_DOMAIN_A completes without errors."""
    client, mgmt_name = apikey_client

    events = await _refresh_rulebases(client, mgmt_name, test_domain_a)
    assert events[0].event_type == SSEEventType.START
    assert events[-1].event_type == SSEEventType.COMPLETE, events[-1].message
    errors = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert not errors, f"Rulebase refresh errors: {[e.message for e in errors]}"


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


async def test_layer_name_not_persisted_src_bug(apikey_client, test_domain_a):
    """SRC BUG (pinned): cached access rules have an empty layer_name.

    RulebaseRefreshService knows the layer name (it embeds it in the row id
    'mgmt:domain:layer:uid') but never injects it into the extracted rule
    dict; the extractor only reads raw_data['layer'], which CP's
    show-access-rulebase rules don't carry as a named field. Consequence:
    the get_access_rules(layer_name=...) filter can never match. When the
    service is fixed to backfill rule_dict['layer_name'], flip this test to
    assert rules DO carry their layer name.
    """
    client, mgmt_name = apikey_client

    rules = await client.get_access_rules(mgmt_names=[mgmt_name], domain_names=[test_domain_a], cache_mode="cache")
    if not rules:
        pytest.skip(f"{test_domain_a} has no access rules")

    assert all(r.layer_name == "" for r in rules), (
        "layer_name is now populated — the src bug was fixed; update this test "
        "and test_get_access_rules_from_cache to assert non-empty layer names"
    )


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
