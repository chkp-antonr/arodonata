"""Bucket 5 — Smart rulebase refresh follows publishes and skips unchanged revisions.

Mutating (`cp_mutates`) in ``TEST_DOMAIN_A``:
1. ``refresh_rulebases(mode="force")`` builds initial baseline.
2. ``refresh_rulebases(mode="smart", cache_ttl=0)`` skips the domain when no publish occurred.
3. Adding a rule to ``TEST_DOMAIN_A``'s access layer and publishing causes
   ``refresh_rulebases(mode="smart", cache_ttl=0)`` to detect the new published session and
   refresh the rulebase cache, shifting downstream rule numbers.
4. Reverting ``TEST_DOMAIN_A`` restores the baseline rulebase.
"""

from __future__ import annotations

import uuid

import pytest

from arodonata import ArodonataClient
from tests.integration.cp_revision import BaselineSnapshot, revert_domain_to

pytestmark = pytest.mark.cp_mutates


async def test_smart_rulebase_refresh_follows_publishes(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
    cp_baseline_snapshot: BaselineSnapshot,
) -> None:
    """Verify ``refresh_rulebases(mode='smart')`` skips fresh domains and refreshes on publish."""
    dom_label = f"{mgmt_name}:{test_domain_a}"

    # 1. Force baseline rulebase sync
    first = await apikey_client.refresh_rulebases(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        mode="force",
    )
    assert dom_label in first.refreshed_domains

    # 2. Smart check with ttl=0 skips because published session has not changed
    second = await apikey_client.refresh_rulebases(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        mode="smart",
        cache_ttl=0.0,
    )
    assert dom_label in second.skipped_domains

    packages = await apikey_client.get_policy_packages(mgmt_name, test_domain_a, cache_mode="cache")
    assert packages, f"Expected policy package in {test_domain_a}"
    pkg = packages[0]
    assert pkg.access_layers, f"Expected access layer in {pkg.name}"
    target_layer = "FPCR_UAT_Active Network" if test_domain_a == "Domain4" else pkg.access_layers[-1].layer_name

    rule_name = f"it-b5-rb-smart-{uuid.uuid4().hex[:6]}"
    try:
        # 3. Publish a new rule at the top of the access layer
        async with apikey_client.write_session(
            mgmt_name,
            test_domain_a,
            session_name=f"{rule_name}-add",
            publish_on_exit=True,
        ):
            r = await apikey_client.api_call(
                mgmt_name,
                "add-access-rule",
                {
                    "layer": target_layer,
                    "name": rule_name,
                    "position": "top",
                    "action": "Accept",
                },
                domain=test_domain_a,
            )
            assert r.success, r.error_message

        # 4. Smart refresh with ttl=0 detects the new publish and reloads
        third = await apikey_client.refresh_rulebases(
            mgmt_name=mgmt_name,
            domains=[test_domain_a],
            mode="smart",
            cache_ttl=0.0,
        )
        assert dom_label in third.refreshed_domains

        rules_after = await apikey_client.get_access_rules(
            mgmt_name,
            test_domain_a,
            layer_name=target_layer,
        )
        assert any(r.name == rule_name for r in rules_after)
    finally:
        base_a = cp_baseline_snapshot.domains[test_domain_a]
        await revert_domain_to(apikey_client, mgmt_name, base_a)
        await apikey_client.refresh_rulebases(
            mgmt_name=mgmt_name,
            domains=[test_domain_a],
            mode="force",
        )
