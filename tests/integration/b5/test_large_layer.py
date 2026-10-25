"""Bucket 5 — Large rulebase layer pagination (>1 page: 120 rules across 3 sections).

Mutating (`cp_mutates`) in ``TEST_DOMAIN_B``: creates an unattached access layer with 3 sections
of 40 rules each (120 rules total), publishes, runs ``refresh_rulebases(mode="force")``, verifies
all 120 rules and their sequential SmartConsole numbering ``1..120`` are cached, and reverts the
domain back to its baseline revision.
"""

from __future__ import annotations

import uuid

import pytest

from arodonata import ArodonataClient
from tests.integration.cp_revision import BaselineSnapshot, revert_domain_to

pytestmark = pytest.mark.cp_mutates

SECTIONS = 3
RULES_PER_SECTION = 40


async def test_layer_with_120_rules_cached_completely(
    antonr_client: ArodonataClient,
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_b: str,
    cp_baseline_snapshot: BaselineSnapshot,
) -> None:
    """Verify a 120-rule access layer across 3 sections paginates and numbers completely."""
    layer_name = f"it-b5-biglayer-{uuid.uuid4().hex[:6]}"
    try:
        async with antonr_client.write_session(
            mgmt_name,
            test_domain_b,
            session_name=f"{layer_name}-seed",
            publish_on_exit=True,
        ):
            r = await antonr_client.api_call(
                mgmt_name,
                "add-access-layer",
                {"name": layer_name, "add-default-rule": False},
                domain=test_domain_b,
            )
            assert r.success, r.error_message

            for s_idx in range(SECTIONS):
                section = f"{layer_name}-s{s_idx}"
                r = await antonr_client.api_call(
                    mgmt_name,
                    "add-access-section",
                    {"layer": layer_name, "name": section, "position": "bottom"},
                    domain=test_domain_b,
                )
                assert r.success, r.error_message

                for r_idx in range(RULES_PER_SECTION):
                    r = await antonr_client.api_call(
                        mgmt_name,
                        "add-access-rule",
                        {
                            "layer": layer_name,
                            "name": f"r{s_idx}-{r_idx}",
                            "position": {"bottom": section},
                            "action": "Accept",
                        },
                        domain=test_domain_b,
                    )
                    assert r.success, r.error_message

        outcome = await apikey_client.refresh_rulebases(
            mgmt_name=mgmt_name,
            domains=[test_domain_b],
            mode="force",
        )
        assert f"{mgmt_name}:{test_domain_b}" in outcome.refreshed_domains

        rules = await apikey_client.get_access_rules(
            mgmt_name,
            test_domain_b,
            layer_name=layer_name,
        )
        assert len(rules) == SECTIONS * RULES_PER_SECTION

        numbered_layer = await apikey_client.get_layer_rulebase(
            mgmt_name,
            test_domain_b,
            layer_name,
            rulebase_type="access",
            cache_mode="cache",
        )
        assert len(numbered_layer.rules) == SECTIONS * RULES_PER_SECTION
        expected_nums = [str(i) for i in range(1, SECTIONS * RULES_PER_SECTION + 1)]
        assert [nr.rule_number for nr in numbered_layer.rules] == expected_nums
    finally:
        base_b = cp_baseline_snapshot.domains[test_domain_b]
        await revert_domain_to(apikey_client, mgmt_name, base_b)
        await apikey_client.refresh_rulebases(
            mgmt_name=mgmt_name,
            domains=[test_domain_b],
            mode="force",
        )
