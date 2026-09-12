"""Live integration tests for client.cpcrud (idempotency, staleness/force).

CPCRUDService.apply() is an async generator that streams SSEEvent objects and
yields the final ApplyReport as its last item — it must be consumed as
`[i async for i in client.cpcrud.apply(...)][-1]` (never awaited directly).

Skipped automatically when API_MGMT / APIKEY / USER_admin / TEST_DOMAIN_A env
vars are missing (via the apikey_client/admin_client/test_domain_a fixtures ->
_require_env).
"""

from __future__ import annotations

import asyncio

import pytest

from arodonata.cpcrud.models import Outcome
from arodonata.cpcrud.statereader import LiveStateReader


def _host_template(mgmt_name: str, domain: str, *, name: str, ip: str) -> dict:
    return {
        "management_servers": [
            {
                "mgmt_name": mgmt_name,
                "domains": [
                    {
                        "name": domain,
                        "operations": [
                            {"type": "host", "data": {"name": name, "ip-address": ip}},
                        ],
                    },
                ],
            },
        ]
    }


def _tcp_service_template(mgmt_name: str, domain: str, *, name: str, port: str) -> dict:
    return {
        "management_servers": [
            {
                "mgmt_name": mgmt_name,
                "domains": [
                    {
                        "name": domain,
                        "operations": [
                            {"type": "tcp-service", "data": {"name": name, "port": port}},
                        ],
                    },
                ],
            },
        ]
    }


@pytest.mark.cp_mutates
async def test_apply_twice_is_idempotent(apikey_client, test_domain_a):
    """Applying the same template twice is idempotent: run 2 creates nothing (API-key auth path).

    Uses a real publish on both runs (relies on the session-level baseline-revert
    fixture for cleanup) rather than discard=True — discard fully removes objects
    created earlier in the same session (confirmed against the Check Point
    Management API's own docs), so a discard-then-discard pair can never
    demonstrate idempotency: nothing ever persists between the two calls, and
    run 2 would "create" the object fresh every time regardless of the engine's
    actual idempotency logic.
    """
    client, mgmt_name = apikey_client
    template = _host_template(mgmt_name, test_domain_a, name="cpcrud-live-idempotency-01", ip="10.99.99.1")

    r1 = [i async for i in client.cpcrud.apply(template)][-1]
    assert r1.summary.get("create", 0) >= 1, f"Run 1 should create >= 1 object, got: {r1.summary}"

    r2 = [i async for i in client.cpcrud.apply(template)][-1]
    assert r2.summary.get("create", 0) == 0, f"Run 2 should create 0 objects (idempotent), got: {r2.summary}"
    for outcome in ("error", "conflict"):
        assert r2.summary.get(outcome, 0) == 0, f"Run 2 should have no {outcome} outcomes, got: {r2.summary}"


@pytest.mark.cp_mutates
async def test_apply_twice_is_silent_noop(admin_client, test_domain_a):
    client, mgmt_name = admin_client
    template = _host_template(mgmt_name, test_domain_a, name="cpcrud-live-noop", ip="10.199.99.10")

    first = [i async for i in client.cpcrud.apply(template)][-1]
    assert first.summary.get("create") == 1

    second = [i async for i in client.cpcrud.apply(template)][-1]
    assert second.summary == {"unchanged": 1}
    assert second.remaining is None


@pytest.mark.cp_mutates
async def test_stale_plan_blocked_and_force_overrides(admin_client, test_domain_a):
    client, mgmt_name = admin_client
    template = _host_template(mgmt_name, test_domain_a, name="cpcrud-live-stale", ip="10.199.99.11")
    plan = await client.cpcrud.plan(template)

    # out-of-band publish moves last-publish-session
    other = _host_template(mgmt_name, test_domain_a, name="cpcrud-live-outofband", ip="10.199.99.12")
    [_ async for _ in client.cpcrud.apply(other)]

    stale_report = [i async for i in client.cpcrud.apply(plan)][-1]
    assert stale_report.summary == {"plan_stale": 1}

    forced = [i async for i in client.cpcrud.apply(plan, force=True)][-1]
    assert forced.summary.get("create") == 1


@pytest.mark.cp_mutates
async def test_apply_twice_tcp_service_is_silent_noop(admin_client, test_domain_a):
    client, mgmt_name = admin_client
    template = _tcp_service_template(mgmt_name, test_domain_a, name="cpcrud-live-svc-noop", port="28080")

    first = [i async for i in client.cpcrud.apply(template)][-1]
    assert first.summary.get("create") == 1

    second = [i async for i in client.cpcrud.apply(template)][-1]
    assert second.summary == {"unchanged": 1}
    assert second.remaining is None


@pytest.mark.cp_mutates
async def test_service_group_references_existing_service(admin_client, test_domain_a):
    client, mgmt_name = admin_client
    member_template = _tcp_service_template(mgmt_name, test_domain_a, name="cpcrud-live-svc-member", port="28081")
    [_ async for _ in client.cpcrud.apply(member_template)]

    group_template = {
        "management_servers": [
            {
                "mgmt_name": mgmt_name,
                "domains": [
                    {
                        "name": test_domain_a,
                        "operations": [
                            {
                                "type": "service-group",
                                "data": {"name": "cpcrud-live-svc-group", "members": ["cpcrud-live-svc-member"]},
                            },
                        ],
                    }
                ],
            }
        ],
    }
    report = [i async for i in client.cpcrud.apply(group_template)][-1]
    assert report.summary.get("create") == 1


def _access_rule_template(
    mgmt_name: str, domain: str, *, layer: str, name: str, position, source, destination, service, action: str
) -> dict:
    return {
        "management_servers": [
            {
                "mgmt_name": mgmt_name,
                "domains": [
                    {
                        "name": domain,
                        "operations": [
                            {
                                "type": "access-rule",
                                "layer": layer,
                                "position": position,
                                "data": {
                                    "name": name,
                                    "source": source,
                                    "destination": destination,
                                    "service": service,
                                    "action": action,
                                },
                            },
                        ],
                    }
                ],
            }
        ],
    }


@pytest.mark.cp_mutates
async def test_access_rule_apply_twice_is_idempotent(admin_client, test_domain_a):
    client, mgmt_name = admin_client
    # service is deliberately a distinctive auto-created TCP port, not "any" like the brief's
    # literal sketch: the "Network" layer's real implicit Cleanup rule already has
    # source=Any/destination=Any/service=Any, so an all-"any" traffic tuple here would
    # traffic-tuple-match that PRE-EXISTING rule (correct per spec identity semantics -- traffic
    # tuple, not name -- but it defeats this test's own "starts absent, gets created" premise).
    template = _access_rule_template(
        mgmt_name,
        test_domain_a,
        layer="Network",
        name="cpcrud-live-rule-noop",
        position="bottom",
        source=["any"],
        destination=["any"],
        service=["TCP/58001"],
        action="accept",
    )
    first = [i async for i in client.cpcrud.apply(template)][-1]
    # 2, not 1: the rule itself + the auto-created TCP_58001 service dependency (Task 10).
    assert first.summary.get("create") == 2

    second = [i async for i in client.cpcrud.apply(template)][-1]
    # reuse, not omitted: per the MMP-readiness design's symmetric-REUSE decision
    # (docs/_AI_/2608/260802-cpcrud-mmp-readiness-design.md), an already-existing
    # auto-created dependency now synthesizes its own REUSE PlannedAction instead of
    # resolving silently -- so the TCP_58001 dependency reports alongside the rule.
    assert second.summary == {"reuse": 1, "unchanged": 1}


@pytest.mark.cp_mutates
async def test_access_rule_rename_updates_not_duplicates(admin_client, test_domain_a):
    client, mgmt_name = admin_client
    # distinct port from the idempotency test above -- both tests' rules coexist in the same
    # "Network" layer within one pytest session (the baseline-revert safety net only reverts at
    # session teardown), so an identical traffic tuple between the two tests would collide too.
    template = _access_rule_template(
        mgmt_name,
        test_domain_a,
        layer="Network",
        name="cpcrud-live-rule-v1",
        position="bottom",
        source=["any"],
        destination=["any"],
        service=["TCP/58002"],
        action="accept",
    )
    first = [i async for i in client.cpcrud.apply(template)][-1]
    # 2, not 1: the rule itself + the auto-created TCP_58002 service dependency (Task 10).
    assert first.summary.get("create") == 2

    renamed = _access_rule_template(
        mgmt_name,
        test_domain_a,
        layer="Network",
        name="cpcrud-live-rule-v2",
        position="bottom",
        source=["any"],
        destination=["any"],
        service=["TCP/58002"],
        action="accept",
    )
    second = [i async for i in client.cpcrud.apply(renamed)][-1]
    # reuse, not omitted: same symmetric-REUSE decision as the idempotency test above --
    # the already-existing TCP_58002 dependency now reports its own REUSE action too.
    assert second.summary == {"reuse": 1, "update": 1}  # renamed, not duplicated -- traffic tuple matched


@pytest.mark.cp_mutates
async def test_access_rule_with_bare_ip_creates_host_dependency(admin_client, test_domain_a):
    client, mgmt_name = admin_client
    template = _access_rule_template(
        mgmt_name,
        test_domain_a,
        layer="Network",
        name="cpcrud-live-rule-bare-ip",
        position="bottom",
        source=["10.199.100.5"],
        destination=["any"],
        service=["any"],
        action="accept",
    )
    report = [i async for i in client.cpcrud.apply(template)][-1]
    assert report.summary.get("create", 0) >= 2  # the auto-created host + the rule itself


# ---------------------------------------------------------------------------
# Task 14's own live-verify caveats (Tasks 4, 5, 7, 11, 12) -- beyond the 3 scenarios above.
# ---------------------------------------------------------------------------


async def test_get_layer_resolves_inline_parent_layer_uid(admin_client, test_domain_a):
    """Task 4's caveat: `get_layer`'s `"parent-layer"` field name was a plan-time best guess.

    Read-only (no @cp_mutates) -- this only reads existing lab layers, never writes. Confirmed
    directly against the live lab that "FPCR_UAT_Active Inline" is a real inline (Application
    Control) sub-layer of "FPCR_UAT_Active Network", and that the live API's field really is
    named "parent-layer" (also cross-checked against Check Point's own API docs) -- the plan-time
    guess was correct, not one of the caveats that needed a fix.
    """
    client, mgmt_name = admin_client
    reader = LiveStateReader(client)

    parent = await reader.get_layer("FPCR_UAT_Active Network", "access", mgmt=mgmt_name, domain=test_domain_a)
    assert parent is not None

    inline = await reader.get_layer("FPCR_UAT_Active Inline", "access", mgmt=mgmt_name, domain=test_domain_a)
    assert inline is not None
    assert inline.parent_layer_uid == parent.uid


@pytest.mark.cp_mutates
async def test_access_rule_section_relative_position_resolves_to_owning_section(admin_client, test_domain_a):
    """Task 5's caveat: whether `show-access-rulebase` accepts a `uid`-keyed payload for section
    lookup (the brief's own fake test used `uid`; the real API might have needed `name`
    instead). Confirmed both work against the live lab; `get_section`'s `uid` choice is correct.

    Exercises `position_helper.resolve_position`'s section-relative branch (Task 8) end-to-end
    for the first time: "FPCR_UAT_Active Network" has real pre-existing sections
    (FPCR_UAT_Section_1..4, Cleanup), unlike "Network" (no sections at all), so this is the only
    layer in this lab that can prove `{"top": "<section>"}` actually resolves to that section's
    owning layer and lands the rule there, not just validates the schema shape.
    """
    client, mgmt_name = admin_client
    template = _access_rule_template(
        mgmt_name,
        test_domain_a,
        layer="FPCR_UAT_Active Network",
        name="cpcrud-live-rule-section",
        position={"top": "FPCR_UAT_Section_1"},
        source=["any"],
        destination=["any"],
        service=["TCP/58003"],
        action="accept",
    )
    report = [i async for i in client.cpcrud.apply(template)][-1]
    assert report.summary.get("create", 0) >= 1
    for outcome in ("error", "conflict"):
        assert report.summary.get(outcome, 0) == 0, (
            f"section-relative position should resolve cleanly, got: {report.summary}"
        )


def _nat_rule_template(
    mgmt_name: str,
    domain: str,
    *,
    package: str,
    name: str,
    position,
    source,
    destination,
    service,
    xlate_source,
    method: str,
    xlate_destination=None,
    xlate_service=None,
) -> dict:
    """Build a nat-rule op. `xlate_destination`/`xlate_service` default to omitted, i.e. "=
    Original" (no translation on that side) -- Check Point has no concept of "translate to Any"
    and rejects it at publish time, only a real translated-source is ever meaningful (see
    resolver.py's `_nat_payload_any_fix`)."""
    data = {
        "name": name,
        "source": source,
        "destination": destination,
        "service": service,
        "translated-source": xlate_source,
        "method": method,
    }
    if xlate_destination is not None:
        data["translated-destination"] = xlate_destination
    if xlate_service is not None:
        data["translated-service"] = xlate_service
    return {
        "management_servers": [
            {
                "mgmt_name": mgmt_name,
                "domains": [
                    {
                        "name": domain,
                        "operations": [
                            {"type": "nat-rule", "package": package, "position": position, "data": data},
                        ],
                    }
                ],
            }
        ],
    }


@pytest.mark.cp_mutates
async def test_nat_rule_apply_twice_is_idempotent(admin_client, test_domain_a):
    """Task 12's caveat (NAT rulebase shape): Task 14's live run found NAT rules on this lab
    nest inside `nat-section` items exactly like access rules nest inside access-sections --
    `find_nat_rules_by_tuple`/`get_last_nat_rule`/`get_nat_rule_by_key`'s original flat top-level
    scan never matched anything real, silently breaking NAT idempotency (every re-apply
    duplicated the rule). Fixed in statereader.py by reusing `_flatten_rulebase`. This is the
    first-ever live exercise of `resolve_nat_rule`/`find_nat_rules_by_tuple` end to end.

    Also the first-ever live exercise of the "Any" literal in a NAT payload: unlike access-rule,
    add-nat-rule/set-nat-rule reject the literal name "Any" outright and need its real system
    uid (a separate Task 14 fix in resolver.py's `_nat_payload_any_fix`).

    Uses package "FPCR_UAT_Active", not "Standard" like this lab's other packages: "Standard"'s
    NAT rulebase is genuinely, persistently locked on this lab (confirmed with raw,
    cpcrud-bypassing add-nat-rule calls at both "top" and "bottom" positions -- an environmental
    fact about this specific shared lab, likely another session/admin holding a lock, not a
    cpcrud defect). "FPCR_UAT_Active" is unaffected and used by other tests in this file already.

    A NAT rule with every field set to "any" (including translated-*) is not a real-world rule
    and, worse, `publish` rejects "Any" as a translated-* value outright ("Field Translated
    Source/Destination/Services references invalid objects") -- so this uses concrete
    source/destination hosts (auto-created bare-IP dependencies, same mechanism as the
    access-rule tests above) with a real hide-behind host for translated-source, and leaves
    translated-destination/translated-service omitted (= Original: this Hide NAT only rewrites
    the source, destination/service pass through unchanged).
    """
    client, mgmt_name = admin_client
    template = _nat_rule_template(
        mgmt_name,
        test_domain_a,
        package="FPCR_UAT_Active",
        name="cpcrud-live-nat-noop",
        position="top",
        source=["198.51.100.11"],
        destination=["198.51.100.12"],
        service=["any"],
        xlate_source="198.51.100.13",
        method="hide",
    )
    first = [i async for i in client.cpcrud.apply(template)][-1]
    # >= 1, not == 1: the bare-IP source/destination/translated-source each auto-create a host
    # dependency the first time round (same mechanism as test_access_rule_with_bare_ip_creates_
    # host_dependency above), so this counts the NAT rule plus up to 3 auto-created hosts.
    assert first.summary.get("create", 0) >= 1
    for outcome in ("error", "locked", "conflict"):
        assert first.summary.get(outcome, 0) == 0, f"NAT rule creation should succeed cleanly, got: {first.summary}"

    # A short buffer before the second apply: on this lab, a NAT rulebase publish is sometimes
    # followed by brief residual server-side locking (observed even independent of this test's
    # own timing -- see Task 14's report for the full investigation). This does not eliminate
    # genuine external contention on a shared lab, just a same-process race.
    await asyncio.sleep(5)

    second = [i async for i in client.cpcrud.apply(template)][-1]
    assert second.summary.get("create", 0) == 0
    assert second.summary.get("unchanged", 0) >= 1
    for outcome in ("error", "locked", "conflict"):
        assert second.summary.get(outcome, 0) == 0, (
            f"NAT rule idempotency should show no changes, got: {second.summary}"
        )


# ---------------------------------------------------------------------------
# Task 11: inverse templates + symmetric re-apply reporting (live).
# ---------------------------------------------------------------------------


@pytest.mark.cp_mutates
async def test_apply_inverse_roundtrip(admin_client, test_domain_a):
    """plan() -> apply(plan) -> inverse(plan, report) -> apply(inverse) round-trips cleanly,
    and re-applying the same inverse template a second time is itself idempotent (nothing
    left to delete -- the host is already absent).

    Deliberately plans ONCE up front and reuses that same `Plan` object for `inverse()`: a
    fresh `plan()` call after `apply()` would resolve against the post-apply state (object now
    exists) rather than the pre-apply intent the report describes, which is exactly the
    footgun this test guards against.
    """
    client, mgmt_name = admin_client
    template = _host_template(mgmt_name, test_domain_a, name="cpcrud-live-inverse-roundtrip", ip="10.199.100.60")

    plan = await client.cpcrud.plan(template)
    report = [i async for i in client.cpcrud.apply(plan)][-1]
    assert report.summary.get("create") == 1, f"expected the host to be created, got: {report.summary}"

    inverse_tpl = client.cpcrud.inverse(plan, report)
    report2 = [i async for i in client.cpcrud.apply(inverse_tpl)][-1]
    for outcome in ("error", "conflict"):
        assert report2.summary.get(outcome, 0) == 0, f"inverse apply should be clean, got: {report2.summary}"
    assert report2.summary.get("delete") == 1, f"inverse should delete the created host, got: {report2.summary}"

    # Re-applying the same inverse template must be a no-op: the host is already gone, so any
    # delete outcome present must be the idempotent "already absent" no-op, not a real deletion.
    report3 = [i async for i in client.cpcrud.apply(inverse_tpl)][-1]
    assert report3.summary.get("delete", 0) == 0 or all(
        r.message == "already absent" for r in report3.results if r.outcome == Outcome.DELETE
    )


@pytest.mark.cp_mutates
async def test_reapply_reports_symmetric_counts(admin_client, test_domain_a):
    """Closes the 260727 bug: applying a template with auto-created dependencies twice must
    yield the same result count both times, not fewer results on the second pass.

    Before Task 5's symmetric REUSE reporting, an already-existing auto-created dependency
    (a bare-IP host or bare service reference) produced no `PlannedAction` at all on the
    second apply -- only the rule's own action remained, so re-applying an access-rule
    template with N auto-created dependencies went from (N + 1) results on pass 1 down to
    just 1 result on pass 2 (the historical "8 vs 4" asymmetry). With REUSE reporting, the
    already-existing dependencies now surface as `REUSE` actions instead of vanishing, so the
    result count is symmetric across re-applies.
    """
    client, mgmt_name = admin_client
    # Two bare-IP endpoints (auto-created hosts) + one bare TCP service (auto-created
    # service), distinct from every other IP/port used elsewhere in this file, so pass 1
    # creates 4 actions total: 2 hosts + 1 service + the rule itself.
    template = _access_rule_template(
        mgmt_name,
        test_domain_a,
        layer="Network",
        name="cpcrud-live-rule-symmetric",
        position="bottom",
        source=["10.199.100.61"],
        destination=["10.199.100.62"],
        service=["TCP/58010"],
        action="accept",
    )

    first = [i async for i in client.cpcrud.apply(template)][-1]
    n1 = len(first.results)
    for outcome in ("error", "conflict"):
        assert first.summary.get(outcome, 0) == 0, f"first apply should be clean, got: {first.summary}"

    second = [i async for i in client.cpcrud.apply(template)][-1]
    n2 = len(second.results)
    for outcome in ("error", "conflict"):
        assert second.summary.get(outcome, 0) == 0, f"second apply should be clean, got: {second.summary}"

    assert n1 == n2, f"re-apply result count must be symmetric (260727 asymmetry regressed): {n1} vs {n2}"
