"""Bucket 2 — Declarative CPCRUD engine against the live MDSM (``TEST_DOMAIN_A``).

All mutations run in ``TEST_DOMAIN_A`` and are rolled back at session teardown by
``cp_baseline_snapshot`` (plus each test cleans up or uses ``inverse()``).

Covers:
1. ``cpcrud.validate`` + ``cpcrud.plan`` + ``cpcrud.apply`` for hosts, networks, services,
   groups, and access rules.
2. Idempotency: re-planning the same template immediately after ``apply`` produces
   ``Outcome.UNCHANGED`` for every action.
3. ``cpcrud.inverse(plan, report)`` generates a compensating rollback template that
   deletes created objects/rules and restores updated objects to their prior state.
4. Two-axis conflict policy:
   - ``on_name_conflict="error"`` emits ``Outcome.ERROR`` when an existing object differs.
   - ``on_ip_conflict="reuse"`` emits ``Outcome.REUSE`` when another host already owns the IP.
   - ``on_ip_conflict="create_new"`` renames the host using ``NamingPrefixes`` (`Host_<ip>`).
5. Staleness guard: if a domain is published between ``plan()`` and ``apply()``,
   ``apply(force=False)`` refuses with ``Outcome.PLAN_STALE`` while ``apply(force=True)`` proceeds.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from arodonata import ArodonataClient, Outcome

pytestmark = pytest.mark.cp_mutates


async def test_cpcrud_end_to_end_apply_idempotency_and_inverse(
    antonr_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify CPCRUD validate -> plan -> apply -> idempotent re-plan -> inverse rollback."""
    tag = uuid.uuid4().hex[:6]
    host_name = f"it-b2-host-{tag}"
    net_name = f"it-b2-net-{tag}"
    svc_name = f"it-b2-svc-{tag}"
    grp_name = f"it-b2-grp-{tag}"

    template: dict[str, Any] = {
        "mgmt_name": mgmt_name,
        "domain": test_domain_a,
        "objects": [
            {
                "type": "host",
                "name": host_name,
                "ipv4-address": "198.51.100.201",
                "comments": "CPCRUD B2 integration host",
            },
            {
                "type": "network",
                "name": net_name,
                "subnet4": "198.51.100.0",
                "mask-length4": 24,
                "comments": "CPCRUD B2 integration network",
            },
        ],
        "services": [
            {
                "type": "service-tcp",
                "name": svc_name,
                "port": "18443",
                "comments": "CPCRUD B2 integration TCP service",
            }
        ],
        "groups": [
            {
                "type": "group",
                "name": grp_name,
                "members": [host_name, net_name],
                "comments": "CPCRUD B2 integration group",
            }
        ],
    }

    # 1. Offline validation
    errors = antonr_client.cpcrud.validate(template)
    assert errors == []

    # 2. Plan -> all 4 actions should be CREATE
    plan = await antonr_client.cpcrud.plan(template)
    assert not plan.has_errors, [a.error for a in plan.actions if a.error]
    assert [a.outcome for a in plan.actions] == [
        Outcome.CREATE,
        Outcome.CREATE,
        Outcome.CREATE,
        Outcome.CREATE,
    ]

    # 3. Apply and publish
    report = await antonr_client.cpcrud.apply(
        plan,
        session_name=f"cpcrud-b2-{tag}",
        session_description="CPCRUD B2 integration test",
    )
    assert report.success, [r.error for r in report.results if r.error]
    assert report.created_count == 4
    assert f"{mgmt_name}:{test_domain_a}" in report.published_domains

    # 4. Re-plan same template -> all 4 actions must be UNCHANGED
    replan = await antonr_client.cpcrud.plan(template)
    assert [a.outcome for a in replan.actions] == [
        Outcome.UNCHANGED,
        Outcome.UNCHANGED,
        Outcome.UNCHANGED,
        Outcome.UNCHANGED,
    ]

    # 5. Generate compensating inverse template and apply rollback
    inv_template = antonr_client.cpcrud.inverse(plan, report)
    inv_errors = antonr_client.cpcrud.validate(inv_template)
    assert inv_errors == []

    inv_plan = await antonr_client.cpcrud.plan(inv_template)
    assert not inv_plan.has_errors
    assert all(a.outcome == Outcome.DELETE for a in inv_plan.actions)

    inv_report = await antonr_client.cpcrud.apply(
        inv_plan,
        session_name=f"cpcrud-b2-inv-{tag}",
    )
    assert inv_report.success
    assert inv_report.deleted_count == 4


async def test_cpcrud_conflict_policies(
    eng1_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify two-axis conflict policies (on_name_conflict and on_ip_conflict)."""
    hosts = await eng1_client.get_hosts(
        mgmt_name=mgmt_name,
        domain=test_domain_a,
        cache_mode="smart",
    )
    assert hosts, f"Expected at least 1 baseline host in {test_domain_a}"
    existing = hosts[0]
    assert existing.ipv4_address is not None

    # 1. Same name, different IP + on_name_conflict="error" -> Outcome.ERROR
    t_name_err: dict[str, Any] = {
        "mgmt_name": mgmt_name,
        "domain": test_domain_a,
        "on_name_conflict": "error",
        "objects": [
            {
                "type": "host",
                "name": existing.name,
                "ipv4-address": "198.51.100.254",
            }
        ],
    }
    p_name_err = await eng1_client.cpcrud.plan(t_name_err)
    assert p_name_err.has_errors
    assert p_name_err.actions[0].outcome == Outcome.ERROR

    # 2. Different name, same IP + on_ip_conflict="reuse" -> Outcome.REUSE
    t_ip_reuse: dict[str, Any] = {
        "mgmt_name": mgmt_name,
        "domain": test_domain_a,
        "on_ip_conflict": "reuse",
        "objects": [
            {
                "type": "host",
                "name": "alias-for-existing-host",
                "ipv4-address": existing.ipv4_address,
            }
        ],
    }
    p_ip_reuse = await eng1_client.cpcrud.plan(t_ip_reuse)
    assert not p_ip_reuse.has_errors
    assert p_ip_reuse.actions[0].outcome == Outcome.REUSE
    assert p_ip_reuse.actions[0].resolved_name == existing.name

    # 3. Different name, same IP + on_ip_conflict="create_new" -> Outcome.CREATE with NamingPrefixes
    t_ip_new: dict[str, Any] = {
        "mgmt_name": mgmt_name,
        "domain": test_domain_a,
        "on_ip_conflict": "create_new",
        "naming_prefixes": {"host": "H_"},
        "objects": [
            {
                "type": "host",
                "name": "conflict-new-host",
                "ipv4-address": existing.ipv4_address,
            }
        ],
    }
    p_ip_new = await eng1_client.cpcrud.plan(t_ip_new)
    assert not p_ip_new.has_errors
    assert p_ip_new.actions[0].outcome == Outcome.CREATE
    assert p_ip_new.actions[0].resolved_name == f"H_{existing.ipv4_address}"


async def test_cpcrud_staleness_guard_and_force_override(
    eng2_client: ArodonataClient,
    antonr_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``apply(force=False)`` rejects stale plans and ``apply(force=True)`` overrides."""
    tag = uuid.uuid4().hex[:6]
    host_name = f"it-b2-stale-{tag}"
    concurrent_host = f"it-b2-bump-{tag}"

    template: dict[str, Any] = {
        "mgmt_name": mgmt_name,
        "domain": test_domain_a,
        "objects": [
            {
                "type": "host",
                "name": host_name,
                "ipv4-address": "198.51.100.202",
            }
        ],
    }

    plan = await eng2_client.cpcrud.plan(template)
    assert not plan.has_errors

    # Advance the domain's published head via another administrator session
    async with antonr_client.write_session(
        mgmt_name,
        test_domain_a,
        session_name=f"bump-{tag}",
        publish_on_exit=True,
    ):
        res = await antonr_client.add_object(
            mgmt_name,
            "host",
            {"name": concurrent_host, "ipv4-address": "198.51.100.203"},
            domain=test_domain_a,
        )
        assert res.success

    try:
        # 1. apply(force=False) must refuse with PLAN_STALE
        stale_report = await eng2_client.cpcrud.apply(plan, force=False)
        assert not stale_report.success
        assert f"{mgmt_name}:{test_domain_a}" in stale_report.stale_domains
        assert any(r.outcome == Outcome.PLAN_STALE for r in stale_report.results)

        # 2. apply(force=True) must succeed despite the moved head
        forced_report = await eng2_client.cpcrud.apply(plan, force=True, session_name=f"forced-{tag}")
        assert forced_report.success
        assert forced_report.created_count == 1
    finally:
        # Clean up both hosts
        async with antonr_client.write_session(
            mgmt_name,
            test_domain_a,
            session_name=f"cleanup-{tag}",
            publish_on_exit=True,
        ):
            await antonr_client.delete_object(mgmt_name, "host", name=host_name, domain=test_domain_a)
            await antonr_client.delete_object(mgmt_name, "host", name=concurrent_host, domain=test_domain_a)


async def test_cpcrud_application_site_and_access_rule_negate(
    antonr_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify live CPCRUD creation, idempotency, conflict error, negate access-rule, and inverse rollback for application-site."""
    tag = uuid.uuid4().hex[:6]
    site_name = f"Site_b2_{tag}.example.com"
    host_name = f"it-b2-neg-host-{tag}"
    svc_grp_name = f"it-b2-svcgrp-{tag}"
    rule_name = f"it-b2-neg-rule-{tag}"

    # Resolve a writable access layer in test_domain_a
    layers_resp = await antonr_client.api_call(
        mgmt_name,
        "show-access-layers",
        domain=test_domain_a,
        payload={"limit": 50},
    )
    assert layers_resp.success, layers_resp.message
    layers = (layers_resp.data or {}).get("access-layers") or []
    local_layers = [lyr for lyr in layers if (lyr.get("domain") or {}).get("domain-type") != "global domain"]
    layer_name = (local_layers[0] if local_layers else layers[0])["name"]

    template: dict[str, Any] = {
        "mgmt_name": mgmt_name,
        "domain": test_domain_a,
        "on_name_conflict": "error",
        "objects": [
            {
                "type": "host",
                "name": host_name,
                "ipv4-address": "198.51.100.211",
                "comments": "CPCRUD B2 negate host",
            }
        ],
        "services": [
            {
                "type": "application-site",
                "name": site_name,
                "primary-category": "Custom_Application_Site",
                "url-list": [f"\\/{tag}\\.example\\.com", f"\\.{tag}\\.example\\.com"],
                "urls-defined-as-regular-expression": True,
                "comments": "CPCRUD B2 application-site test",
            }
        ],
        "groups": [
            {
                "type": "service-group",
                "name": svc_grp_name,
                "members": ["https"],
                "comments": "CPCRUD B2 service-group test",
            }
        ],
        "rules": [
            {
                "type": "access-rule",
                "name": rule_name,
                "layer": layer_name,
                "position": "bottom",
                "source": [host_name],
                "source-negate": True,
                "destination": ["Any"],
                "destination-negate": False,
                "service": [site_name],
                "service-negate": True,
                "action": "Drop",
                "track": "Log",
                "comments": "CPCRUD B2 negate + application-site rule",
            }
        ],
    }

    # 1. Validate schema
    errors = antonr_client.cpcrud.validate(template)
    assert errors == []

    # 2. Plan -> all 4 actions should be CREATE
    plan = await antonr_client.cpcrud.plan(template)
    assert not plan.has_errors, [a.error for a in plan.actions if a.error]
    assert [a.outcome for a in plan.actions] == [
        Outcome.CREATE,
        Outcome.CREATE,
        Outcome.CREATE,
        Outcome.CREATE,
    ]

    # 3. Apply and publish
    report = await antonr_client.cpcrud.apply(
        plan,
        session_name=f"cpcrud-b2-appsite-{tag}",
        session_description="CPCRUD B2 application-site + negate test",
    )
    assert report.success, [r.error for r in report.results if r.error]
    assert report.created_count == 4

    try:
        # 4. Verify on server that application-site and access-rule negate flags exist
        shown_site = await antonr_client.api_call(
            mgmt_name,
            "show-application-site",
            domain=test_domain_a,
            payload={"name": site_name},
        )
        assert shown_site.success, shown_site.message
        site_data = shown_site.data or {}
        assert set(site_data.get("url-list") or []) == {
            f"\\/{tag}\\.example\\.com",
            f"\\.{tag}\\.example\\.com",
        }
        assert site_data.get("urls-defined-as-regular-expression") is True

        shown_rule = await antonr_client.api_call(
            mgmt_name,
            "show-access-rule",
            domain=test_domain_a,
            payload={"layer": layer_name, "name": rule_name, "details-level": "full"},
        )
        assert shown_rule.success, shown_rule.message
        rule_data = shown_rule.data or {}
        assert rule_data.get("source-negate") is True
        assert rule_data.get("destination-negate") is False
        assert rule_data.get("service-negate") is True

        # 5. Re-plan same template -> all 4 actions must be UNCHANGED
        replan = await antonr_client.cpcrud.plan(template)
        assert [a.outcome for a in replan.actions] == [
            Outcome.UNCHANGED,
            Outcome.UNCHANGED,
            Outcome.UNCHANGED,
            Outcome.UNCHANGED,
        ]

        # 6. Conflict check: different url-list with on_name_conflict="error" -> Outcome.ERROR
        conflict_template: dict[str, Any] = {
            "mgmt_name": mgmt_name,
            "domain": test_domain_a,
            "on_name_conflict": "error",
            "services": [
                {
                    "type": "application-site",
                    "name": site_name,
                    "primary-category": "Custom_Application_Site",
                    "url-list": ["\\/different\\.example\\.com"],
                    "urls-defined-as-regular-expression": True,
                }
            ],
        }
        conflict_plan = await antonr_client.cpcrud.plan(conflict_template)
        assert conflict_plan.has_errors
        assert conflict_plan.actions[0].outcome == Outcome.ERROR
    finally:
        # 7. Compensating inverse rollback
        inv_template = antonr_client.cpcrud.inverse(plan, report)
        inv_plan = await antonr_client.cpcrud.plan(inv_template)
        inv_report = await antonr_client.cpcrud.apply(
            inv_plan,
            session_name=f"cpcrud-b2-appsite-inv-{tag}",
        )
        assert inv_report.success, [r.error for r in inv_report.results if r.error]
