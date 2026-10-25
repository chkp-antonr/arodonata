"""Bucket 1 — Rulebase cache & read-only introspection against the live MDSM.

Covers:
1. ``refresh_rulebases`` populates the rulebase cache for ``TEST_DOMAIN_A``.
2. ``get_policy_packages`` returns the domain's policy packages.
3. ``get_access_rules`` and ``get_nat_rules`` return cached rule rows.
4. ``get_package_rulebase`` returns hierarchical SmartConsole rule numbering.
5. ``locate_rules`` resolves rule UIDs and layer UIDs to their SmartConsole numbers.
6. ``filter_rulebase`` renders ``markdown``, ``model_friendly``, and ``raw`` formats.
"""

from __future__ import annotations

from arodonata import ArodonataClient


async def test_rulebase_refresh_and_introspection(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify rulebase refresh, policy package listing, numbering, locate_rules, and filter_rulebase."""
    outcome = await apikey_client.refresh_rulebases(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        mode="force",
    )
    assert f"{mgmt_name}:{test_domain_a}" in outcome.refreshed_domains

    packages = await apikey_client.get_policy_packages(
        mgmt_name,
        test_domain_a,
        cache_mode="cache",
    )
    assert packages, f"Expected at least 1 policy package in {test_domain_a} (run lab_build)"
    pkg = packages[0]
    assert pkg.uid and pkg.name

    access_rules = await apikey_client.get_access_rules(mgmt_name, test_domain_a)
    nat_rules = await apikey_client.get_nat_rules(mgmt_name, test_domain_a)
    assert isinstance(access_rules, list)
    assert isinstance(nat_rules, list)
    assert access_rules, f"Expected access rules in {test_domain_a} (run lab_build)"

    pkg_rb = await apikey_client.get_package_rulebase(
        mgmt_name,
        test_domain_a,
        pkg.name,
        rulebase_type="access",
        cache_mode="cache",
    )
    assert pkg_rb.package_name == pkg.name
    assert len(pkg_rb.layers) >= 1

    sample_rule = access_rules[0]
    locs = await apikey_client.locate_rules(
        mgmt_name,
        test_domain_a,
        rule_uids=[sample_rule.uid],
        layer_uids=[sample_rule.layer_uid],
        cache_mode="cache",
    )
    assert sample_rule.uid in locs.rule_locations
    assert sample_rule.layer_uid in locs.layer_prefixes

    for fmt in ("markdown", "model_friendly", "raw"):
        filtered = await apikey_client.filter_rulebase(
            mgmt_name,
            test_domain_a,
            package=pkg.name,
            rulebase_type="access",
            output_format=fmt,
            cache_mode="cache",
        )
        assert filtered.total_rules >= 1
