"""Unit tests for CPCRUD `Planner`, `Differ`, `position_helper`, and `rule_identity`."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter
from arodonata.core.errors import ValidationError
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainSyncState, SIDCacheEntry
from arodonata.core.models.objects import CPObject
from arodonata.core.models.services import CPService
from arodonata.cpcrud.models import NamingPrefixes, Outcome
from arodonata.cpcrud.planner import LOOKUP_ERROR_PREFIX, Planner
from arodonata.cpcrud.rule_identity import NAT_ANY_OBJECT_UID, NAT_ORIGINAL_OBJECT_UID
from arodonata.cpcrud.state_reader import HybridStateReader


class PlannerFakeApi:
    """Configurable `ApiPort` double for `Planner` tests."""

    def __init__(self) -> None:
        self.published_uid: str = "pub-head-1"
        self.published_iso: str = "2026-10-24T08:00:00Z"
        self.fail_head: bool = False
        self.fail_commands: set[str] = set()
        self.access_rulebase_payload: dict[str, Any] = {
            "uid": "layer-net-1",
            "name": "Network",
            "rulebase": [
                {
                    "type": "access-section",
                    "uid": "sec-app-1",
                    "name": "App Section",
                    "from": 1,
                    "to": 2,
                    "rulebase": [
                        {
                            "uid": "rule-web-1",
                            "name": "Allow Web",
                            "type": "access-rule",
                            "rule-number": 1,
                            "enabled": True,
                            "source": [{"uid": "h-web", "name": "Host_10.1.1.10"}],
                            "destination": [{"uid": "any-uid", "name": "Any"}],
                            "service": [{"uid": "s-http", "name": "TCP_80"}],
                            "action": {"name": "Accept"},
                            "track": {"type": {"name": "Log"}},
                            "comments": "prod web",
                        },
                        {
                            "uid": "rule-cleanup-99",
                            "name": "Cleanup rule",
                            "type": "access-rule",
                            "rule-number": 2,
                            "enabled": True,
                            "source": [{"uid": "any-uid", "name": "Any"}],
                            "destination": [{"uid": "any-uid", "name": "Any"}],
                            "service": [{"uid": "any-uid", "name": "Any"}],
                            "action": {"name": "Drop"},
                            "track": {"type": {"name": "None"}},
                        },
                    ],
                }
            ],
            "to": 2,
            "total": 2,
        }
        self.nat_rulebase_payload: dict[str, Any] = {
            "uid": "pkg-std-1",
            "name": "Standard",
            "rulebase": [
                {
                    "uid": "nat-rule-1",
                    "name": "Hide App Outbound",
                    "type": "nat-rule",
                    "rule-number": 1,
                    "enabled": True,
                    "method": "hide",
                    "original-source": {"uid": "h-web", "name": "Host_10.1.1.10"},
                    "original-destination": {"uid": NAT_ANY_OBJECT_UID, "name": "Any"},
                    "original-service": {"uid": NAT_ANY_OBJECT_UID, "name": "Any"},
                    "translated-source": {"uid": "h-nat", "name": "nat-gw-ip"},
                    "translated-destination": {"uid": NAT_ORIGINAL_OBJECT_UID, "name": "Original"},
                    "translated-service": {"uid": NAT_ORIGINAL_OBJECT_UID, "name": "Original"},
                    "comments": "outbound hide",
                }
            ],
            "to": 1,
            "total": 1,
        }

    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ) -> ApiCallResult:
        if command == "show-last-published-session":
            if self.fail_head:
                return ApiCallResult(success=False, status_code=503, error_message="Management head unavailable")
            return ApiCallResult(
                success=True,
                data={"uid": self.published_uid, "publish-time": {"iso-8601": self.published_iso}},
            )
        if command in self.fail_commands:
            return ApiCallResult(success=False, status_code=500, error_message=f"Simulated failure on {command}")
        if command == "show-access-rulebase":
            return ApiCallResult(success=True, data=self.access_rulebase_payload)
        if command == "show-nat-rulebase":
            return ApiCallResult(success=True, data=self.nat_rulebase_payload)
        if command == "where-used":
            return ApiCallResult(success=True, data={"used-directly": {"total": 0}})
        return ApiCallResult(
            success=False,
            status_code=404,
            error_code="generic_err_object_not_found",
            error_message="Requested object not found",
        )

    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        *,
        domain: str | None = None,
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        limit: int = 300,
    ) -> ApiQueryResult:
        if command in self.fail_commands:
            return ApiQueryResult(
                success=False, code="api_error", error_message=f"Simulated query failure on {command}"
            )
        return ApiQueryResult(success=True, objects=[], total=0)

    async def create_dedicated_session(self, *args: Any, **kwargs: Any) -> tuple[str, str]:
        return "sid", "10.0.0.1"

    async def logout_sid(self, *args: Any, **kwargs: Any) -> bool:
        return True

    async def close(self, *, logout: bool | None = None) -> None:
        return None


async def _seed_fresh_cache(
    cache: SqlCacheAdapter,
    *,
    objects: list[CPObject] | None = None,
    services: list[CPService] | None = None,
    session_uid: str = "pub-head-1",
) -> None:
    pub_at = datetime(2026, 10, 24, 8, 0, 0)
    if objects:
        await cache.upsert_objects(objects)
    if services:
        await cache.upsert_services(services)

    for obj_type in ("host", "network", "address-range", "dns-domain", "group", "application-site"):
        await cache.upsert_sync_state(
            DomainSyncState(
                mgmt_name="mds1",
                domain_name="Corp",
                scope="objects",
                item_type=obj_type,
                last_session_uid=session_uid,
                last_published_at=pub_at,
                status="ok",
            )
        )
    for svc_type in ("service-tcp", "service-udp", "service-icmp", "service-group"):
        await cache.upsert_sync_state(
            DomainSyncState(
                mgmt_name="mds1",
                domain_name="Corp",
                scope="services",
                item_type=svc_type,
                last_session_uid=session_uid,
                last_published_at=pub_at,
                status="ok",
            )
        )


@pytest.mark.spec("SCN-CPCRUD-003-1")
@pytest.mark.asyncio
async def test_planner_idempotent_replan_yields_unchanged_or_reuse_with_zero_writes() -> None:
    """Re-planning an already-applied template produces `Outcome.UNCHANGED` or `Outcome.REUSE` and zero write actions."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = PlannerFakeApi()

    await _seed_fresh_cache(
        cache,
        objects=[
            CPObject(
                mgmt_name="mds1",
                domain_name="Corp",
                uid="h-web",
                name="Host_10.1.1.10",
                type="host",
                ipv4_address="10.1.1.10",
                comments="web server",
            ),
            CPObject(
                mgmt_name="mds1",
                domain_name="Corp",
                uid="g-web",
                name="grp-web",
                type="group",
                members=["h-web"],
                raw_data={"members": [{"uid": "h-web", "name": "Host_10.1.1.10"}]},
            ),
        ],
        services=[
            CPService(
                mgmt_name="mds1",
                domain_name="Corp",
                uid="s-http",
                name="TCP_80",
                type="service-tcp",
                port="80",
                protocol="tcp",
            )
        ],
    )

    planner = Planner(api=api, cache=cache, default_mgmt_name="mds1")
    template: dict[str, Any] = {
        "version": 1,
        "mgmt_name": "mds1",
        "domain": "Corp",
        "objects": [
            # Exact name + IP match -> UNCHANGED
            {"type": "host", "name": "Host_10.1.1.10", "ipv4-address": "10.1.1.10", "comments": "web server"},
            # Different name, same IP with default on_ip_conflict="reuse" -> REUSE
            {"type": "host", "name": "alias-web", "ipv4-address": "10.1.1.10"},
        ],
        "services": [
            {"type": "service-tcp", "name": "TCP_80", "port": "80"},
        ],
        "groups": [
            {"type": "group", "name": "grp-web", "members": ["alias-web"]},
        ],
        "rules": [
            {
                "type": "access-rule",
                "layer": "Network",
                "name": "Allow Web",
                "source": ["alias-web"],
                "destination": ["Any"],
                "service": ["TCP_80"],
                "rule_action": "Accept",
                "track": "Log",
                "comments": "prod web",
            },
            # NAT rule matching by traffic tuple with Check Point "Any" and "Original" sentinels
            {
                "type": "nat-rule",
                "package": "Standard",
                "method": "hide",
                "original-source": "alias-web",
                "original-destination": "Any",
                "original-service": "Any",
                "translated-source": "nat-gw-ip",
                "translated-destination": "Original",
                "translated-service": "Original",
                "comments": "outbound hide",
            },
        ],
    }

    plan = await planner.decide(template)
    assert plan.write_actions == []
    assert plan.has_errors is False
    assert plan.actions[0].requested_name == "Host_10.1.1.10"
    assert plan.actions[0].outcome == Outcome.UNCHANGED
    assert plan.actions[1].requested_name == "alias-web"
    assert plan.actions[1].outcome == Outcome.REUSE
    assert plan.actions[1].resolved_name == "Host_10.1.1.10"

    outcomes = {a.requested_name or a.name: a.outcome for a in plan.actions}
    assert outcomes["grp-web"] == Outcome.UNCHANGED
    assert outcomes["TCP_80"] == Outcome.UNCHANGED
    assert outcomes["Allow Web"] == Outcome.UNCHANGED
    assert outcomes["Hide App Outbound"] == Outcome.UNCHANGED

    await db.close()


@pytest.mark.asyncio
async def test_planner_two_axis_conflict_resolution_and_naming_prefixes() -> None:
    """`Planner` evaluates `NameConflictPolicy` (`update` | `error`) x `IpConflictPolicy` (`reuse` | `create_new` | `error`) and applies `NamingPrefixes`."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = PlannerFakeApi()

    await _seed_fresh_cache(
        cache,
        objects=[
            CPObject(
                mgmt_name="mds1",
                domain_name="Corp",
                uid="h-existing",
                name="custom-host",
                type="host",
                ipv4_address="10.50.0.10",
            ),
            CPObject(
                mgmt_name="mds1",
                domain_name="Corp",
                uid="n-existing",
                name="legacy-net",
                type="network",
                subnet4="10.60.0.0",
                mask_length4=24,
            ),
            CPObject(
                mgmt_name="mds1",
                domain_name="Corp",
                uid="r-existing",
                name="legacy-range",
                type="address-range",
                ipv4_address_first="10.70.0.1",
                ipv4_address_last="10.70.0.10",
            ),
        ],
        services=[
            CPService(
                mgmt_name="mds1",
                domain_name="Corp",
                uid="s-existing",
                name="legacy-https",
                type="service-tcp",
                port="443",
                protocol="tcp",
            )
        ],
    )

    planner = Planner(api=api, cache=cache, default_mgmt_name="mds1")

    # 1. on_name_conflict="error" when existing object has different attributes -> Outcome.ERROR
    plan_name_err = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "on_name_conflict": "error",
            "objects": [
                {"type": "host", "name": "custom-host", "ipv4-address": "10.50.0.99"},
            ],
        }
    )
    assert plan_name_err.actions[0].outcome == Outcome.ERROR
    assert "Name conflict" in (plan_name_err.actions[0].error or "")

    # 2. on_name_conflict="update" when existing object has different attributes -> Outcome.UPDATE
    plan_name_upd = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "on_name_conflict": "update",
            "objects": [
                {"type": "host", "name": "custom-host", "ipv4-address": "10.50.0.99"},
            ],
        }
    )
    assert plan_name_upd.actions[0].outcome == Outcome.UPDATE
    assert plan_name_upd.actions[0].command == "set-host"
    assert "ipv4-address" in plan_name_upd.actions[0].diffs

    # 3. on_ip_conflict="error" when another object already holds the IP/subnet/port -> Outcome.ERROR
    plan_ip_err = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "on_ip_conflict": "error",
            "objects": [
                {"type": "host", "name": "new-host-name", "ipv4-address": "10.50.0.10"},
            ],
        }
    )
    assert plan_ip_err.actions[0].outcome == Outcome.ERROR
    assert "conflict" in (plan_ip_err.actions[0].error or "")
    assert "on_ip_conflict='error'" in (plan_ip_err.actions[0].error or "")

    # 4. on_ip_conflict="create_new" generates convention-compliant names via NamingPrefixes
    #    and propagates resolved names into dependent groups and rules
    plan_create_new = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "on_ip_conflict": "create_new",
            "objects": [
                {"type": "host", "name": "req-host", "ipv4-address": "10.50.0.10"},
                {"type": "network", "name": "req-net", "subnet4": "10.60.0.0", "mask-length4": 24},
                {
                    "type": "address-range",
                    "name": "req-rng",
                    "ipv4-address-first": "10.70.0.1",
                    "ipv4-address-last": "10.70.0.10",
                },
            ],
            "services": [
                {"type": "service-tcp", "name": "req-svc", "port": "443"},
            ],
            "groups": [
                {"type": "group", "name": "grp-auto", "members": ["req-host", "req-net", "req-rng"]},
            ],
        },
        naming_prefixes=NamingPrefixes(),
    )
    by_req = {a.requested_name: a for a in plan_create_new.actions}
    assert by_req["req-host"].outcome == Outcome.CREATE
    assert by_req["req-host"].resolved_name == "Host_10.50.0.10"
    assert by_req["req-net"].outcome == Outcome.CREATE
    assert by_req["req-net"].resolved_name == "Net_10.60.0.0_24"
    assert by_req["req-rng"].outcome == Outcome.CREATE
    assert by_req["req-rng"].resolved_name == "IPR_10.70.0.1-10.70.0.10"
    assert by_req["req-svc"].outcome == Outcome.CREATE
    assert by_req["req-svc"].resolved_name == "TCP_443"

    grp_act = by_req["grp-auto"]
    assert grp_act.outcome == Outcome.CREATE
    assert grp_act.payload["members"] == [
        "Host_10.50.0.10",
        "Net_10.60.0.0_24",
        "IPR_10.70.0.1-10.70.0.10",
    ]

    await db.close()


@pytest.mark.asyncio
async def test_planner_failed_lookup_emits_error_and_skips_dependents_never_false_create() -> None:
    """Any failed state lookup produces `Outcome.ERROR` (`lookup failed, nothing planned...`) and marks dependent groups/rules `Outcome.SKIPPED_DEPENDENCY`."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = PlannerFakeApi()

    # Do NOT seed cache so planner uses live API calls, then fail `show-host`
    api.fail_commands.add("show-host")
    planner = Planner(api=api, cache=cache, default_mgmt_name="mds1")

    plan = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "objects": [
                {"type": "host", "name": "db-primary", "ipv4-address": "10.99.1.1"},
            ],
            "groups": [
                {"type": "group", "name": "grp-db", "members": ["db-primary"]},
            ],
            "rules": [
                {
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "Allow DB",
                    "source": ["grp-db"],
                    "destination": ["Any"],
                    "service": ["Any"],
                    "rule_action": "Accept",
                }
            ],
        }
    )

    assert len(plan.actions) == 3
    host_act, grp_act, rule_act = plan.actions

    # Host step must be Outcome.ERROR with required prefix, NEVER Outcome.CREATE
    assert host_act.outcome == Outcome.ERROR
    assert host_act.message.startswith(LOOKUP_ERROR_PREFIX)
    assert host_act.is_write_action is False

    # Group and rule steps referencing the failed host/group must be SKIPPED_DEPENDENCY
    assert grp_act.outcome == Outcome.SKIPPED_DEPENDENCY
    assert grp_act.status == "skipped_dependency"
    assert "db-primary" in (grp_act.error or "")

    assert rule_act.outcome == Outcome.SKIPPED_DEPENDENCY
    assert rule_act.status == "skipped_dependency"
    assert "grp-db" in (rule_act.error or "")

    # Also test unreadable domain head (`show-last-published-session` failure)
    api.fail_head = True
    plan_head_fail = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "objects": [{"type": "host", "name": "h1", "ipv4-address": "10.1.1.1"}],
        }
    )
    assert plan_head_fail.actions[0].outcome == Outcome.ERROR
    assert plan_head_fail.actions[0].message.startswith(LOOKUP_ERROR_PREFIX)

    await db.close()


@pytest.mark.spec("SCN-CPCRUD-008-1")
@pytest.mark.asyncio
async def test_planner_cleanup_rule_aware_bottom_positioning() -> None:
    """`Planner` anchors `position="bottom"` and `position={"bottom": "App Section"}` at `{"above": "<cleanup_rule_uid>"}`."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = PlannerFakeApi()
    await _seed_fresh_cache(cache)

    planner = Planner(api=api, cache=cache, default_mgmt_name="mds1")
    plan = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "rules": [
                {
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "New Bottom Rule",
                    "position": "bottom",
                    "source": ["Host_10.1.1.10"],
                    "destination": ["Any"],
                    "service": ["Any"],
                    "rule_action": "Accept",
                },
                {
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "New Section Bottom Rule",
                    "position": {"bottom": "App Section"},
                    "source": ["Host_10.1.1.10"],
                    "destination": ["Any"],
                    "service": ["Any"],
                    "rule_action": "Accept",
                },
            ],
        }
    )

    assert len(plan.actions) == 2
    assert plan.actions[0].outcome == Outcome.CREATE
    assert plan.actions[0].payload["position"] == {"above": "rule-cleanup-99"}
    assert plan.actions[1].outcome == Outcome.CREATE
    assert plan.actions[1].payload["position"] == {"above": "rule-cleanup-99"}

    await db.close()


@pytest.mark.spec("SCN-CPCRUD-003-5")
@pytest.mark.asyncio
async def test_planner_rejects_unknown_object_types_duplicate_ids_wraps_dns_dot_retry_and_redacts_sids() -> None:
    """Adversarial test for C1, C2, W22, I17: validate object_type allowlist, reject duplicate operation IDs, wrap dns-domain dot-retry exceptions in StateLookupError, and redact SIDs in DomainStamp.error."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = PlannerFakeApi()
    planner = Planner(api=api, cache=cache, default_mgmt_name="mds1")

    # 1. C1 / C2: Unknown object_type in Planner and HybridStateReader raises ValidationError
    with pytest.raises(ValidationError, match="Unsupported CPCRUD"):
        await planner.decide(
            {
                "mgmt_name": "mds1",
                "domain": "Corp",
                "objects": [{"type": "run-script", "name": "evil"}],
            }
        )

    reader = HybridStateReader(api=api, cache=cache)
    with pytest.raises(ValidationError, match="Unsupported CPCRUD object type"):
        await reader.get_object_by_name("mds1", "Corp", "administrator", "admin")
    with pytest.raises(ValidationError, match="Unsupported CPCRUD service type"):
        await reader.get_service_by_name("mds1", "Corp", "generic-object", "svc1")

    # 2. I17: Duplicate explicit operation id raises ValidationError
    with pytest.raises(ValidationError, match="Duplicate CPCRUD operation id"):
        await planner.decide(
            {
                "mgmt_name": "mds1",
                "domain": "Corp",
                "objects": [
                    {"id": "dup-1", "type": "host", "name": "h1", "ipv4-address": "10.0.0.1"},
                    {"id": "dup-1", "type": "host", "name": "h2", "ipv4-address": "10.0.0.2"},
                ],
            }
        )

    # 3. I17: dns-domain dot-prefixed retry raising transport exception is caught and converted to Outcome.ERROR
    orig_api_call = api.api_call

    async def dot_raising_api_call(
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ApiCallResult:
        if command == "show-dns-domain" and payload and str(payload.get("name")).startswith("."):
            raise RuntimeError("Socket reset on dot-retry with token sid_leak_777")
        return await orig_api_call(mgmt_name, command, payload, **kwargs)

    await cache.upsert_sid(
        SIDCacheEntry(
            mgmt_name="mds1",
            domain_name="Corp",
            auth_identity="fp1",
            sid="sid_leak_777",
            server_ip="10.0.0.1",
        )
    )
    api.api_call = dot_raising_api_call  # type: ignore[method-assign]
    dns_plan = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "objects": [{"type": "dns-domain", "name": "example.com", "is-sub-domain": False}],
        }
    )
    assert len(dns_plan.actions) == 1
    assert dns_plan.actions[0].outcome == Outcome.ERROR
    assert dns_plan.actions[0].message.startswith(LOOKUP_ERROR_PREFIX)
    assert "sid_leak_777" not in (dns_plan.actions[0].error or "")
    assert "***REDACTED***" in (dns_plan.actions[0].error or "")

    # 4. W22: DomainStamp.error redacts known SIDs when show-last-published-session fails
    async def head_leaking_api_call(
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ApiCallResult:
        if command == "show-last-published-session":
            return ApiCallResult(
                success=False,
                status_code=500,
                error_message="Session sid_leak_777 rejected on head read",
            )
        return await orig_api_call(mgmt_name, command, payload, **kwargs)

    api.api_call = head_leaking_api_call  # type: ignore[method-assign]
    stamp_plan = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "objects": [{"type": "host", "name": "h1", "ipv4-address": "10.0.0.1"}],
        }
    )
    stamp = stamp_plan.domain_stamps["mds1:Corp"]
    assert stamp.readable is False
    assert "sid_leak_777" not in (stamp.error or "")
    assert "***REDACTED***" in (stamp.error or "")

    await db.close()


@pytest.mark.spec("SCN-CPCRUD-006-2", "SCN-CPCRUD-006-3", "SCN-CPCRUD-006-4")
@pytest.mark.asyncio
async def test_planner_application_site_create_unchanged_update_delete_and_error() -> None:
    """`Planner` handles `application-site` in `objects:`, `services:`, and `operations:` across CREATE, UNCHANGED, UPDATE, DELETE, and ERROR outcomes."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = PlannerFakeApi()

    await _seed_fresh_cache(
        cache,
        objects=[
            CPObject.from_cp_dict(
                "mds1",
                "Corp",
                {
                    "uid": "site-existing-1",
                    "name": "Site_baidu.com",
                    "type": "application-site",
                    "primary-category": "Custom_Application_Site",
                    "url-list": [r"\.baidu\.com", r"\/baidu\.com"],
                    "urls-defined-as-regular-expression": True,
                    "description": "Baidu custom site",
                },
            )
        ],
    )

    planner = Planner(api=api, cache=cache, default_mgmt_name="mds1")

    # 1. CREATE new application-site (in services:) + UNCHANGED existing application-site (with reordered url-list) + access-rule referencing it
    plan_1 = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "objects": [
                {
                    "type": "application-site",
                    "name": "Site_baidu.com",
                    "primary-category": "Custom_Application_Site",
                    "url-list": [r"\/baidu\.com", r"\.baidu\.com"],
                    "urls-defined-as-regular-expression": True,
                }
            ],
            "services": [
                {
                    "type": "application-site",
                    "name": "Site_new_regex",
                    "primary-category": "Custom_Application_Site",
                    "url-list": [r"\/example\.org"],
                    "urls-defined-as-regular-expression": True,
                    "description": "New regex site",
                }
            ],
            "rules": [
                {
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "Allow Baidu",
                    "position": "bottom",
                    "source": ["Any"],
                    "destination": ["Any"],
                    "service": ["Site_baidu.com", "Site_new_regex"],
                    "rule_action": "Accept",
                }
            ],
        }
    )
    by_name = {a.name: a for a in plan_1.actions}
    assert by_name["Site_baidu.com"].outcome == Outcome.UNCHANGED
    assert by_name["Site_new_regex"].outcome == Outcome.CREATE
    assert by_name["Site_new_regex"].command == "add-application-site"
    assert by_name["Site_new_regex"].payload == {
        "name": "Site_new_regex",
        "primary-category": "Custom_Application_Site",
        "url-list": [r"\/example\.org"],
        "urls-defined-as-regular-expression": True,
        "description": "New regex site",
    }
    assert by_name["Allow Baidu"].outcome == Outcome.CREATE
    assert by_name["Allow Baidu"].payload["service"] == ["Site_baidu.com", "Site_new_regex"]

    # 2. Name conflict with on_name_conflict="error" -> Outcome.ERROR reporting differs on [url-list]
    plan_err = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "on_name_conflict": "error",
            "objects": [
                {
                    "type": "application-site",
                    "name": "Site_baidu.com",
                    "primary-category": "Custom_Application_Site",
                    "url-list": [r"\/baidu\.com", r"\.baidu\.cn"],
                    "urls-defined-as-regular-expression": True,
                }
            ],
        }
    )
    assert plan_err.actions[0].outcome == Outcome.ERROR
    assert "differs on [url-list]" in (plan_err.actions[0].error or "")

    # 3. Name conflict with on_name_conflict="update" -> Outcome.UPDATE with set-application-site
    plan_upd = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "on_name_conflict": "update",
            "objects": [
                {
                    "type": "application-site",
                    "name": "Site_baidu.com",
                    "primary-category": "Custom_Application_Site",
                    "url-list": [r"\/baidu\.com", r"\.baidu\.cn"],
                    "urls-defined-as-regular-expression": True,
                }
            ],
        }
    )
    assert plan_upd.actions[0].outcome == Outcome.UPDATE
    assert plan_upd.actions[0].command == "set-application-site"
    assert plan_upd.actions[0].payload["url-list"] == [r"\/baidu\.com", r"\.baidu\.cn"]

    # 4. DELETE existing application-site -> Outcome.DELETE with delete-application-site and prior_state
    plan_del = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "operations": [
                {
                    "operation": "delete",
                    "type": "application-site",
                    "name": "Site_baidu.com",
                }
            ],
        }
    )
    assert plan_del.actions[0].outcome == Outcome.DELETE
    assert plan_del.actions[0].command == "delete-application-site"
    assert plan_del.actions[0].prior_state is not None
    assert plan_del.actions[0].prior_state["primary-category"] == "Custom_Application_Site"
    assert set(plan_del.actions[0].prior_state["url-list"]) == {r"\/baidu\.com", r"\.baidu\.com"}
    assert plan_del.actions[0].prior_state["urls-defined-as-regular-expression"] is True

    # 5. R5: action="present" updating only description/comments on existing application-site without url-list -> Outcome.UPDATE
    plan_meta_upd = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "on_name_conflict": "update",
            "objects": [
                {
                    "type": "application-site",
                    "name": "Site_baidu.com",
                    "description": "Updated metadata only",
                    "comments": "Ticket-123",
                }
            ],
        }
    )
    assert plan_meta_upd.actions[0].outcome == Outcome.UPDATE
    assert plan_meta_upd.actions[0].command == "set-application-site"
    assert plan_meta_upd.actions[0].payload["description"] == "Updated metadata only"
    assert plan_meta_upd.actions[0].payload["comments"] == "Ticket-123"
    assert "url-list" not in plan_meta_upd.actions[0].payload

    # 6. R5: action="present" for a non-existent application-site without url-list or application-signature -> Outcome.ERROR
    plan_missing_create = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "objects": [
                {
                    "type": "application-site",
                    "name": "Site_does_not_exist",
                    "description": "Missing url-list on create",
                }
            ],
        }
    )
    assert plan_missing_create.actions[0].outcome == Outcome.ERROR
    assert "url-list" in (plan_missing_create.actions[0].error or "")

    # 7. R5: signature-only application-site creation without primary-category defaults primary-category to "Custom_Application_Site"
    plan_sig_create = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "objects": [
                {
                    "type": "application-site",
                    "name": "Site_sig_only",
                    "application-signature": "http-header:X-Test",
                }
            ],
        }
    )
    assert plan_sig_create.actions[0].outcome == Outcome.CREATE
    assert plan_sig_create.actions[0].payload["primary-category"] == "Custom_Application_Site"
    assert plan_sig_create.actions[0].payload["application-signature"] == "http-header:X-Test"

    # 8. R10: duplicate url-list under a different name is detected via find_objects_by_value
    plan_dup_urls = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "on_ip_conflict": "reuse",
            "objects": [
                {
                    "type": "application-site",
                    "name": "Site_baidu_alias",
                    "url-list": [r"\/baidu\.com", r"\.baidu\.com"],
                    "urls-defined-as-regular-expression": True,
                }
            ],
        }
    )
    assert plan_dup_urls.actions[0].outcome == Outcome.REUSE
    assert plan_dup_urls.actions[0].resolved_name == "Site_baidu.com"

    await db.close()


@pytest.mark.spec("SCN-CPCRUD-004-1", "SCN-CPCRUD-004-2", "SCN-CPCRUD-005-1")
@pytest.mark.asyncio
async def test_planner_cold_cache_uses_show_objects_without_full_show_hosts_or_services() -> None:
    """Cold-cache `Planner.decide()` queries `show-objects` with exact candidate verification and zero `show-hosts` / `show-services-*` calls."""
    from arodonata.testing.replay_mock import FileReplayApiMock

    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api_mock = FileReplayApiMock()

    branch_files = api_mock._domain_data["Branch"]
    branch_files["show-hosts"] = {
        "objects": [
            {
                "uid": "h-existing-10",
                "name": "Host_Existing_10_20_30_40",
                "type": "host",
                "ipv4-address": "10.20.30.40",
            },
            {
                "uid": "h-prefix-collision",
                "name": "Host_Prefix_10_20_30_400_Fake",
                "type": "host",
                "ipv4-address": "10.20.30.41",
                "comments": "mentions 10.20.30.40 in comments",
            },
        ]
    }
    branch_files["show-networks"] = {
        "objects": [
            {
                "uid": "net-16",
                "name": "Net_10_10_0_0_16",
                "type": "network",
                "subnet4": "10.10.0.0",
                "mask-length4": 16,
            },
            {
                "uid": "net-24",
                "name": "Net_10_10_0_0_24",
                "type": "network",
                "subnet4": "10.10.0.0",
                "mask-length4": 24,
            },
        ]
    }
    branch_files["show-address-ranges"] = {
        "objects": [
            {
                "uid": "rng-wide",
                "name": "Range_10_50_0_100_120",
                "type": "address-range",
                "ipv4-address-first": "10.50.0.100",
                "ipv4-address-last": "10.50.0.120",
            },
            {
                "uid": "rng-exact",
                "name": "Range_10_50_0_10_20",
                "type": "address-range",
                "ipv4-address-first": "10.50.0.10",
                "ipv4-address-last": "10.50.0.20",
            },
        ]
    }
    branch_files["show-services-tcp"] = {
        "objects": [
            {
                "uid": "svc-8080",
                "name": "TCP_8080",
                "type": "service-tcp",
                "port": "8080",
            },
            {
                "uid": "svc-80",
                "name": "TCP_80",
                "type": "service-tcp",
                "port": "80",
            },
        ]
    }
    branch_files["show-services-icmp"] = {
        "objects": [
            {
                "uid": "icmp-8",
                "name": "echo-request",
                "type": "service-icmp",
                "icmp-type": 8,
                "icmp-code": 0,
            }
        ]
    }
    api_mock.reset_counters()

    planner = Planner(api=api_mock, cache=cache)
    plan_res = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Branch",
            "on_ip_conflict": "reuse",
            "objects": [
                {"type": "host", "name": "New_Host_Alias", "ipv4-address": "10.20.30.40"},
                {"type": "host", "name": "Brand_New_Host", "ipv4-address": "10.99.88.77"},
                {"type": "host", "name": "Intra_Plan_Dup_Host", "ipv4-address": "10.99.88.77"},
                {"type": "network", "name": "New_Net_24_Alias", "subnet4": "10.10.0.0", "mask-length4": 24},
                {
                    "type": "address-range",
                    "name": "New_Range_Alias",
                    "ipv4-address-first": "10.50.0.10",
                    "ipv4-address-last": "10.50.0.20",
                },
            ],
            "services": [
                {"type": "service-tcp", "name": "New_HTTP_Alias", "port": "80"},
                {"type": "service-icmp", "name": "New_ICMP_Alias", "icmp-type": 8, "icmp-code": 0},
            ],
        }
    )

    outcomes_by_name = {a.requested_name: (a.outcome, a.resolved_name) for a in plan_res.actions}
    assert outcomes_by_name["New_Host_Alias"] == (Outcome.REUSE, "Host_Existing_10_20_30_40")
    assert outcomes_by_name["Brand_New_Host"] == (Outcome.CREATE, "Brand_New_Host")
    assert outcomes_by_name["Intra_Plan_Dup_Host"] == (Outcome.REUSE, "Brand_New_Host")
    assert outcomes_by_name["New_Net_24_Alias"] == (Outcome.REUSE, "Net_10_10_0_0_24")
    assert outcomes_by_name["New_Range_Alias"] == (Outcome.REUSE, "Range_10_50_0_10_20")
    assert outcomes_by_name["New_HTTP_Alias"] == (Outcome.REUSE, "TCP_80")
    assert outcomes_by_name["New_ICMP_Alias"] == (Outcome.REUSE, "echo-request")

    # Verify targeted `show-objects` was used for IP/subnet/range/port and single-page `show-services-icmp` for ICMP
    assert api_mock.api_call_counts.get(("Branch", "show-objects"), 0) == 5
    assert api_mock.api_call_counts.get(("Branch", "show-hosts"), 0) == 0
    assert api_mock.api_call_counts.get(("Branch", "show-networks"), 0) == 0
    assert api_mock.api_call_counts.get(("Branch", "show-address-ranges"), 0) == 0
    assert api_mock.api_call_counts.get(("Branch", "show-services-tcp"), 0) == 0
    assert api_mock.api_call_counts.get(("Branch", "show-services-icmp"), 0) == 1

    await db.close()


@pytest.mark.spec("SCN-CONFIG-006-3")
@pytest.mark.asyncio
async def test_cpcrud_service_plan_uses_settings_naming_prefixes_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """`CPCRUDService.plan()` uses `settings.cpcrud_naming_prefixes` by default and honors template/arg overrides."""
    from arodonata import ArodonataClient, ArodonataSettings
    from arodonata.testing.replay_mock import FileReplayApiMock

    monkeypatch.setenv("ARODONATA_CPCRUD_AUTO_NAME_PREFIX_RANGE", "Range_")
    monkeypatch.setenv("ARODONATA_CPCRUD_RANGE_SEPARATOR", "_")
    monkeypatch.setenv("ARODONATA_CPCRUD_RANGE_COMPRESS_OCTETS", "true")

    api_mock = FileReplayApiMock()
    branch_files = api_mock._domain_data["Branch"]
    branch_files["show-address-ranges"] = {
        "objects": [
            {
                "uid": "rng-legacy-1",
                "name": "Legacy_Range_10_1_1_1_9",
                "type": "address-range",
                "ipv4-address-first": "10.1.1.1",
                "ipv4-address-last": "10.1.1.9",
            }
        ]
    }

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="127.0.0.1", api_key="mock-key")
    async with ArodonataClient(settings=settings, api=api_mock) as client:
        template = {
            "version": 1,
            "mgmt_name": "mds1",
            "domain": "Branch",
            "on_ip_conflict": "create_new",
            "objects": [
                {
                    "type": "address-range",
                    "name": "req_rng",
                    "ipv4-address-first": "10.1.1.1",
                    "ipv4-address-last": "10.1.1.9",
                }
            ],
        }
        plan_default = await client.cpcrud.plan(template)
        assert plan_default.actions[0].outcome == Outcome.CREATE
        assert plan_default.actions[0].resolved_name == "Range_10.1.1.1_9"

        plan_tpl_override = await client.cpcrud.plan(
            {
                **template,
                "naming_prefixes": {
                    "address-range": "TplRng_",
                    "compress-range-same-subnet": False,
                    "range-separator": "-",
                },
            }
        )
        assert plan_tpl_override.actions[0].outcome == Outcome.CREATE
        assert plan_tpl_override.actions[0].resolved_name == "TplRng_10.1.1.1-10.1.1.9"

        plan_arg_override = await client.cpcrud.plan(
            template,
            naming_prefixes={"address-range": "ArgRng_"},
        )
        assert plan_arg_override.actions[0].outcome == Outcome.CREATE
        assert plan_arg_override.actions[0].resolved_name == "ArgRng_10.1.1.1_9"


@pytest.mark.spec("SCN-CPCRUD-009-5", "SCN-CPCRUD-009-6")
@pytest.mark.asyncio
async def test_planner_strict_set_missing_targets_fail_closed() -> None:
    """`operation='set'` or `'update'` targeting absent object, service, group, or rule fails closed with `Outcome.ERROR`."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = PlannerFakeApi()
    await _seed_fresh_cache(cache)

    planner = Planner(api=api, cache=cache, default_mgmt_name="mds1")
    plan = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "objects": [
                {"operation": "set", "type": "host", "name": "Missing_Host", "ipv4-address": "10.9.9.9"},
            ],
            "services": [
                {"operation": "update", "type": "service-tcp", "name": "Missing_TCP", "port": "9443"},
            ],
            "groups": [
                {"operation": "set", "type": "group", "name": "Missing_Grp", "members": ["Any"]},
                {"operation": "update", "type": "service-group", "name": "Missing_SvcGrp", "members": ["TCP_80"]},
            ],
            "rules": [
                # Even if traffic matches an existing rule, strict_name=True must NOT hijack it when name doesn't match
                {
                    "operation": "set",
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "Missing Rule Name",
                    "source": ["Host_10.1.1.10"],
                    "destination": ["Any"],
                    "service": ["TCP_80"],
                    "rule_action": "Accept",
                }
            ],
        }
    )

    assert len(plan.actions) == 5
    for act in plan.actions:
        assert act.outcome == Outcome.ERROR
        assert act.is_write_action is False
        assert "not found for update" in (act.error or "")

    await db.close()


@pytest.mark.spec(
    "SCN-CPCRUD-007-1",
    "SCN-CPCRUD-007-2",
    "SCN-CPCRUD-007-3",
    "SCN-CPCRUD-009-1",
    "SCN-CPCRUD-009-2",
    "SCN-CPCRUD-009-3",
    "SCN-CPCRUD-009-5",
)
@pytest.mark.asyncio
async def test_planner_incremental_url_list_and_rule_cell_updates_with_depends_on_and_guards() -> None:
    """`Planner` handles incremental `url-list` and rule cell `{add, remove}` patches, `depends_on`, UID dereferencing, and safety errors."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = PlannerFakeApi()

    # Use raw UIDs in rulebase + objects-dictionary to verify `_build_prior_rule_state` dereferencing
    api.access_rulebase_payload["objects-dictionary"] = [
        {"uid": "h-old-5", "name": "Host_10.0.0.5", "type": "host"},
        {"uid": NAT_ANY_OBJECT_UID, "name": "Any", "type": "CpmiAnyObject"},
        {"uid": "s-http", "name": "TCP_80", "type": "service-tcp"},
    ]
    api.access_rulebase_payload["rulebase"][0]["rulebase"][0]["source"] = ["h-old-5"]
    api.access_rulebase_payload["rulebase"][0]["rulebase"][0]["destination"] = [NAT_ANY_OBJECT_UID]
    api.access_rulebase_payload["rulebase"][0]["rulebase"][0]["service"] = ["s-http"]

    await _seed_fresh_cache(
        cache,
        objects=[
            CPObject.from_cp_dict(
                "mds1",
                "Corp",
                {
                    "uid": "site-cc-1",
                    "name": "Site__chinacloudapi.cn",
                    "type": "application-site",
                    "primary-category": "Custom_Application_Site",
                    "url-list": [r"\/chinacloudapi\.cn", r"\.chinacloudapi\.cn"],
                    "urls-defined-as-regular-expression": True,
                },
            ),
            CPObject.from_cp_dict(
                "mds1",
                "Corp",
                {"uid": "h-old-5", "name": "Host_10.0.0.5", "type": "host", "ipv4-address": "10.0.0.5"},
            ),
            CPObject.from_cp_dict(
                "mds1",
                "Corp",
                {
                    "uid": "site-legacy-cc",
                    "name": "Custom_Legacy_Static",
                    "type": "application-site",
                    "primary-category": "Custom_Application_Site",
                    "url-list": ["HTTPS://Partner.Example.com"],
                    "urls-defined-as-regular-expression": False,
                },
            ),
        ],
    )

    planner = Planner(api=api, cache=cache, default_mgmt_name="mds1")
    plan = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "on_ip_conflict": "reuse",
            "objects": [
                {"id": "create-h1", "type": "host", "name": "Host_10.1.1.1", "ipv4-address": "10.1.1.1"},
                {
                    "operation": "set",
                    "type": "application-site",
                    "name": "Site__chinacloudapi.cn",
                    "url-list": {"add": [r"\.partner\.cn"], "remove": [r"\/chinacloudapi\.cn"]},
                },
                {
                    "type": "application-site",
                    "name": "Site_partner_alias",
                    "url-list": ["https://partner.example.com"],
                    "urls-defined-as-regular-expression": False,
                },
            ],
            "services": [
                {"id": "create-8443", "type": "service-tcp", "name": "TCP_8443", "port": "8443"},
            ],
            "rules": [
                {
                    "operation": "set",
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "Allow Web",
                    "source": {"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]},
                    "service": {"add": ["TCP_8443"]},
                }
            ],
        }
    )

    by_name = {a.requested_name: a for a in plan.actions}
    assert by_name["Site__chinacloudapi.cn"].outcome == Outcome.UPDATE
    assert by_name["Site__chinacloudapi.cn"].payload["url-list"] == [r"\.chinacloudapi\.cn", r"\.partner\.cn"]
    assert by_name["Site_partner_alias"].outcome == Outcome.REUSE
    assert by_name["Site_partner_alias"].resolved_name == "Custom_Legacy_Static"

    rule_act = by_name["Allow Web"]
    assert rule_act.outcome == Outcome.UPDATE
    assert rule_act.command == "set-access-rule"
    assert "create-h1" in rule_act.depends_on
    assert "create-8443" in rule_act.depends_on
    assert rule_act.payload["source"] == {"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]}
    assert rule_act.payload["service"] == {"add": ["TCP_8443"]}
    assert rule_act.prior_state is not None
    assert rule_act.prior_state["source"] == ["Host_10.0.0.5"]
    assert rule_act.prior_state["destination"] == ["Any"]
    assert rule_act.prior_state["service"] == ["TCP_80"]

    # Safety errors surface as Outcome.ERROR
    err_plan = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "objects": [
                {
                    "operation": "set",
                    "type": "application-site",
                    "name": "Site__chinacloudapi.cn",
                    "url-list": {"remove": [r"\/chinacloudapi\.cn", r"\.chinacloudapi\.cn"]},
                }
            ],
            "rules": [
                {
                    "operation": "set",
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "Allow Web",
                    "source": {"remove": ["Host_10.0.0.5"]},
                },
                {
                    "operation": "set",
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "Allow Web",
                    "destination": {"add": ["Host_10.0.0.5"]},
                },
                {
                    # Unmatched rule with delta cell under default 'present' verb must NOT create Any rule
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "Typo Missing Rule",
                    "source": {"add": ["Host_10.1.1.1"]},
                },
                {
                    # Unnamed rule with delta cell under default 'present' verb must fail closed
                    "type": "access-rule",
                    "layer": "Network",
                    "source": {"add": ["Host_10.1.1.1"]},
                },
            ],
        }
    )
    assert err_plan.actions[0].outcome == Outcome.ERROR
    assert "empty url-list" in (err_plan.actions[0].error or "")
    assert err_plan.actions[1].outcome == Outcome.ERROR
    assert err_plan.actions[1].requested_name == "Allow Web"
    assert err_plan.actions[1].resolved_name == "Allow Web"
    assert "widens to 'Any'" in (err_plan.actions[1].error or "")
    assert err_plan.actions[2].outcome == Outcome.ERROR
    assert "include 'Any' in 'remove'" in (err_plan.actions[2].error or "")
    assert err_plan.actions[3].outcome == Outcome.ERROR
    assert "Cannot create access-rule" in (err_plan.actions[3].error or "")
    assert err_plan.actions[4].outcome == Outcome.ERROR
    assert "Cannot create access-rule" in (err_plan.actions[4].error or "")

    # Positional rule_number update + rename works even under strict_name
    rename_by_num_plan = await planner.decide(
        {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "rules": [
                {
                    "operation": "set",
                    "type": "access-rule",
                    "layer": "Network",
                    "rule_number": 1,
                    "name": "Allow Web v2",
                    "source": {"add": ["Host_10.0.0.5"]},
                }
            ],
        }
    )
    assert rename_by_num_plan.actions[0].outcome == Outcome.UPDATE
    assert rename_by_num_plan.actions[0].payload["new-name"] == "Allow Web v2"

    await db.close()


@pytest.mark.spec("SCN-CPCRUD-016-2")
@pytest.mark.asyncio
async def test_single_pass_planner_steps_and_split_diff_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify `_collect_ordered_steps` runs once per target and split diff helpers preserve diff parity."""
    from arodonata.core.models.rulebase import AccessRuleEntry, NatRuleEntry
    from arodonata.cpcrud.differ import (
        _diff_address_range,
        _diff_application_site,
        _diff_host,
        _diff_nat_rule,
        _diff_network,
        _diff_policy_rule,
        compute_object_diff,
        compute_rule_diff,
    )

    for fn in (
        _diff_host,
        _diff_network,
        _diff_address_range,
        _diff_application_site,
        _diff_nat_rule,
        _diff_policy_rule,
    ):
        assert callable(fn)

    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = PlannerFakeApi()
    await _seed_fresh_cache(cache)

    planner = Planner(api=api, cache=cache, default_mgmt_name="mds1")
    collect_calls = 0
    orig_collect = planner._collect_ordered_steps

    def _counting_collect(target: Any) -> list[tuple[str, dict[str, Any]]]:
        nonlocal collect_calls
        collect_calls += 1
        return orig_collect(target)

    monkeypatch.setattr(planner, "_collect_ordered_steps", _counting_collect)

    plan = await planner.decide(
        {
            "mgmt_name": "mds1",
            "targets": [
                {
                    "domain": "Corp",
                    "objects": [{"type": "host", "name": "New_SinglePass_1", "ipv4-address": "10.9.8.1"}],
                },
                {
                    "domain": "Corp",
                    "objects": [{"type": "host", "name": "New_SinglePass_2", "ipv4-address": "10.9.8.2"}],
                },
            ],
        }
    )
    assert collect_calls == 2
    assert len(plan.actions) == 2

    # Split object diff helpers
    net_obj = CPObject.from_cp_dict(
        "mds1",
        "Corp",
        {"uid": "net-1", "name": "Net_10_1", "type": "network", "subnet4": "10.1.0.0", "mask-length4": 24},
    )
    net_diffs, net_payload = compute_object_diff({"subnet4": "10.2.0.0", "mask-length4": 16}, net_obj)
    assert set(net_diffs) == {"subnet4", "mask-length4"}
    assert net_payload == {"subnet4": "10.2.0.0", "mask-length4": 16}

    rng_obj = CPObject.from_cp_dict(
        "mds1",
        "Corp",
        {
            "uid": "rng-1",
            "name": "Rng_1",
            "type": "address-range",
            "ipv4-address-first": "10.1.1.1",
            "ipv4-address-last": "10.1.1.10",
        },
    )
    rng_diffs, _ = compute_object_diff({"ipv4-address-last": "10.1.1.20"}, rng_obj)
    assert set(rng_diffs) == {"ipv4-address-last"}

    # Split rule diff helpers (NAT + policy rule)
    nat_rule = NatRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        package_name="Standard",
        package_uid="pkg-1",
        layer_name="NAT",
        uid="nr-1",
        rule_number="1",
        name="Nat1",
        method="static",
        original_source="Host_A",
        translated_source="Original",
    )
    nat_diffs, _ = compute_rule_diff({"translated-source": "Host_NAT"}, nat_rule, rulebase_type="nat")
    assert set(nat_diffs) == {"translated-source"}

    acc_rule = AccessRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        package_name="Standard",
        package_uid="pkg-1",
        layer_name="Network",
        layer_uid="layer-1",
        uid="ar-1",
        rule_number="1",
        name="Allow1",
        action="Accept",
        source=["Any"],
        destination=["Any"],
        service=["Any"],
        install_on=["Policy Targets"],
    )
    acc_diffs, _ = compute_rule_diff({"rule_action": "Drop"}, acc_rule, rulebase_type="access")
    assert set(acc_diffs) == {"action"}

    await db.close()


def test_resolve_domain_name_treats_none_as_empty() -> None:
    """DA-014: `_resolve_domain_name` must treat `{'domain': None}` as default rather than `'None'`."""
    from arodonata.cpcrud.planner import _resolve_domain_name

    assert _resolve_domain_name({"domain": None}, default="Corp") == "Corp"
    assert _resolve_domain_name({"domain": None}, default="") == ""
    assert _resolve_domain_name({"domain": "Global"}, default="Corp") == "Global"


@pytest.mark.spec("SCN-CPCRUD-017-2")
@pytest.mark.asyncio
async def test_check_where_used_blocks_referenced_entities_and_ignores_deleted_siblings() -> None:
    """SCN-CPCRUD-017-2 (DA-014, DA-051): Block delete with check_where_used=True when active refs exist across host/service/group/service-group."""
    db = DatabaseManager("sqlite+aiosqlite:///:memory:")
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = PlannerFakeApi()

    await _seed_fresh_cache(
        cache,
        objects=[
            CPObject.from_cp_dict(
                "mds1", "Corp", {"uid": "u-h1", "name": "H_Used", "type": "host", "ipv4-address": "10.1.1.1"}
            ),
            CPObject.from_cp_dict(
                "mds1", "Corp", {"uid": "u-g1", "name": "G_Used", "type": "group", "members": ["H_Used"]}
            ),
            CPObject.from_cp_dict(
                "mds1", "Corp", {"uid": "u-g-ref", "name": "G_Holder", "type": "group", "members": ["H_Dead"]}
            ),
        ],
        services=[
            CPService.from_cp_dict(
                "mds1", "Corp", {"uid": "u-s1", "name": "S_Used", "type": "service-tcp", "port": "8080"}
            ),
            CPService.from_cp_dict(
                "mds1", "Corp", {"uid": "u-sg1", "name": "SG_Used", "type": "service-group", "members": []}
            ),
        ],
    )

    orig_call = api.api_call

    async def _where_used_call(
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        wait_for_task: bool = True,
    ) -> ApiCallResult:
        if command == "where-used":
            target = (payload or {}).get("uid") or (payload or {}).get("name")
            if target in ("u-h1", "H_Used"):
                return ApiCallResult(
                    success=True,
                    data={
                        "used-directly": {
                            "objects": [{"uid": "u-g1", "name": "G_Used", "type": "group"}],
                            "access-control-rules": [],
                        },
                        "used-indirectly": {"objects": []},
                    },
                )
            if target in ("u-s1", "S_Used", "u-g1", "G_Used", "u-sg1", "SG_Used"):
                return ApiCallResult(
                    success=True,
                    data={
                        "used-directly": {
                            "objects": [{"uid": "u-g-ref", "name": "G_Holder", "type": "group"}],
                        },
                        "used-indirectly": {"objects": []},
                    },
                )
            return ApiCallResult(success=True, data={"used-directly": {}, "used-indirectly": {}})
        return await orig_call(
            mgmt_name,
            command,
            payload,
            domain=domain,
            sid=sid,
            server_ip=server_ip,
            wait_for_task=wait_for_task,
        )

    api.api_call = _where_used_call  # type: ignore[method-assign]
    planner = Planner(api=api, cache=cache)
    try:
        # 1. Referenced host, service-tcp, group, and service-group all fail with Outcome.ERROR
        blocked_plan = await planner.decide(
            {
                "mgmt_name": "mds1",
                "domain": "Corp",
                "operations": [
                    {"operation": "delete", "type": "host", "name": "H_Used", "check_where_used": True},
                    {"operation": "delete", "type": "service-tcp", "name": "S_Used", "check_where_used": True},
                    {"operation": "delete", "type": "group", "name": "G_Used", "check_where_used": True},
                    {"operation": "delete", "type": "service-group", "name": "SG_Used", "check_where_used": True},
                ],
            }
        )
        assert len(blocked_plan.actions) == 4
        assert all(act.outcome == Outcome.ERROR for act in blocked_plan.actions)
        assert all("where" in (act.error or "").lower() for act in blocked_plan.actions)

        # 2. Deleting referencing sibling G_Used first allows H_Used delete in the same plan
        unblocked_plan = await planner.decide(
            {
                "mgmt_name": "mds1",
                "domain": "Corp",
                "operations": [
                    {"operation": "delete", "type": "group", "name": "G_Used", "check_where_used": False},
                    {"operation": "delete", "type": "host", "name": "H_Used", "check_where_used": True},
                ],
            }
        )
        assert [a.outcome for a in unblocked_plan.actions] == [Outcome.DELETE, Outcome.DELETE]
    finally:
        await db.close()


@pytest.mark.spec("SCN-CPCRUD-018-1")
async def test_planner_explicit_id_collision_virtual_rule_overlay_protocol_zero_and_https_inline() -> None:
    """DA-005, DA-027, DA-045, DA-047: Explicit act-N skipping, intra-plan virtual rule overlay, protocol=0, and HTTPS inline-layer omission."""
    from arodonata.core.errors import ValidationError
    from arodonata.core.models.common import ApiCallResult
    from arodonata.core.models.rulebase import (
        DomainRulebaseSnapshot,
    )
    from arodonata.cpcrud.planner import Planner

    class _MinApi:
        async def api_call(
            self, mgmt: str, cmd: str, payload: dict[str, Any] | None = None, **_k: Any
        ) -> ApiCallResult:
            if cmd == "show-last-published-session":
                return ApiCallResult(success=True, data={"uid": "s-1", "publish-time": {"posix": 1700000000000}})
            if cmd in ("show-access-rulebase", "show-https-rulebase"):
                return ApiCallResult(success=True, data={"uid": "l-1", "name": "Network", "rulebase": [], "total": 0})
            return ApiCallResult(success=False, status_code=404, error_code="generic_err_object_not_found")

        async def api_query(self, *_a: Any, **_k: Any) -> ApiQueryResult:
            return ApiQueryResult(success=True, objects=[], total=0)

    class _MinCache:
        async def get_sync_state(self, *_a: Any, **_k: Any) -> DomainSyncState | None:
            return None

        async def get_objects(self, **_k: Any) -> list[CPObject]:
            return []

        async def get_object_by_uid(self, *_a: Any) -> CPObject | None:
            return None

        async def get_services(self, **_k: Any) -> list[CPService]:
            return []

        async def get_service_by_uid(self, *_a: Any) -> CPService | None:
            return None

        async def get_rulebase_snapshot(self, *_a: Any, **_k: Any) -> DomainRulebaseSnapshot | None:
            return None

    planner = Planner(api=_MinApi(), cache=_MinCache(), default_mgmt_name="mds1")  # type: ignore[arg-type]

    # DA-005: Reject blank/duplicate IDs
    with pytest.raises(ValidationError):
        await planner.decide(
            {"domain_name": "Corp", "objects": [{"id": "  ", "type": "host", "name": "h0", "ipv4-address": "1.1.1.1"}]}
        )
    with pytest.raises(ValidationError):
        await planner.decide(
            {
                "domain_name": "Corp",
                "objects": [
                    {"id": "dup", "type": "host", "name": "h1", "ipv4-address": "1.1.1.1"},
                    {"id": "dup", "type": "host", "name": "h2", "ipv4-address": "1.1.1.2"},
                ],
            }
        )

    # DA-005 + DA-027 + DA-045 + DA-047 combined plan
    plan = await planner.decide(
        {
            "domain_name": "Corp",
            "services": [
                {"id": "act-1", "type": "service-other", "name": "hopopt-0", "ip_protocol": 0},
            ],
            "rules": [
                {
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "r-chain",
                    "action": "Accept",
                    "source": ["Any"],
                    "destination": ["Any"],
                    "service": ["Any"],
                },
                {
                    "operation": "set",
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "r-chain",
                    "comments": "updated in-plan",
                },
                {
                    "type": "https-rule",
                    "layer": "HTTPS Inspection",
                    "name": "https-r1",
                    "inline_layer": "should-not-send",
                },
            ],
        }
    )
    ids = [a.action_id for a in plan.actions]
    assert len(set(ids)) == len(ids)
    assert ids[0] == "act-1"
    assert ids[1] == "act-2"
    svc_act, r_add, r_set, https_add = plan.actions
    assert svc_act.payload["ip-protocol"] == 0
    assert r_add.outcome == Outcome.CREATE
    assert r_set.outcome == Outcome.UPDATE
    assert "uid" not in r_set.payload
    assert r_set.payload["name"] == "r-chain"
    assert r_add.action_id in r_set.depends_on
    assert "inline-layer" not in https_add.payload


@pytest.mark.spec("SCN-CPCRUD-019-1")
@pytest.mark.asyncio
async def test_scn_cpcrud_019_1_virtual_rule_ordering_delta_safety_unnamed_guard_and_where_used() -> None:
    """SCN-CPCRUD-019-1: multi-create & rename above cleanup, sequential delta widening guard, unnamed rule fail-closed, and active where-used overlay."""
    from arodonata.core.models.rulebase import AccessRuleEntry, DomainRulebaseSnapshot

    cleanup_rule = AccessRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        layer_uid="l-net",
        layer_name="Network",
        uid="uid-cleanup",
        name="Cleanup rule",
        position=2,
        action="Drop",
        source=["Any"],
        destination=["Any"],
        service=["Any"],
    )
    existing_rule = AccessRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        layer_uid="l-net",
        layer_name="Network",
        uid="uid-allow-web",
        name="AllowWeb",
        position=1,
        action="Accept",
        source=["h-a", "h-b"],
        destination=["Any"],
        service=["Any"],
        raw_data={
            "uid": "uid-allow-web",
            "name": "AllowWeb",
            "action": {"name": "Accept"},
            "source": ["h-a", "h-b"],
            "destination": ["Any"],
            "service": ["Any"],
        },
    )
    objs_dict = {
        "h-a": {"uid": "h-a", "name": "Host_A", "type": "host"},
        "h-b": {"uid": "h-b", "name": "Host_B", "type": "host"},
        "g-1": {"uid": "g-1", "name": "OldGrp", "type": "group"},
        "h-del": {"uid": "h-del", "name": "H_Decom", "type": "host"},
        "any": {"uid": "97aeb369-9aea-11d5-bd16-0090272ccb30", "name": "Any", "type": "CpmiAnyObject"},
    }
    snap = DomainRulebaseSnapshot(
        mgmt_name="mds1",
        domain_name="Corp",
        access_rules=[existing_rule, cleanup_rule],
    )

    class _OverlayApi:
        async def api_call(self, _m: str, cmd: str, payload: dict[str, Any] | None = None, **_kw: Any) -> Any:
            if cmd == "show-last-published-session":
                return ApiCallResult(success=True, data={"session-uid": "s-1"})
            if cmd == "show-access-rulebase":
                return ApiCallResult(
                    success=True,
                    data={
                        "uid": "l-net",
                        "name": "Network",
                        "total": 2,
                        "to": 2,
                        "objects-dictionary": list(objs_dict.values()),
                        "rulebase": [
                            existing_rule.raw_data,
                            {
                                "uid": "uid-cleanup",
                                "name": "Cleanup rule",
                                "action": {"name": "Drop"},
                                "source": ["Any"],
                                "destination": ["Any"],
                                "service": ["Any"],
                            },
                        ],
                    },
                )
            if cmd in {"show-object", "show-host", "show-group"}:
                n = str((payload or {}).get("name") or "")
                u = str((payload or {}).get("uid") or "")
                obj_match = objs_dict.get(u) if u else None
                if obj_match is None and n:
                    for v in objs_dict.values():
                        if v["name"] == n:
                            obj_match = v
                            break
                if obj_match is not None:
                    if cmd == "show-object":
                        return ApiCallResult(success=True, data={"object": obj_match})
                    return ApiCallResult(success=True, data=obj_match)
                return ApiCallResult(success=False, status_code=404, error_code="generic_err_object_not_found")
            if cmd == "where-used":
                n = str((payload or {}).get("name") or "")
                u = str((payload or {}).get("uid") or "")
                if n == "H_Decom" or u == "h-del":
                    return ApiCallResult(
                        success=True,
                        data={
                            "used-directly": {
                                "total": 2,
                                "access-control-rules": [
                                    {"rule": {"uid": "uid-allow-web", "name": "AllowWeb"}, "position": 1}
                                ],
                                "objects": [{"uid": "g-1", "name": "OldGrp", "type": "group"}],
                            },
                            "used-indirectly": {"total": 0},
                        },
                    )
                return ApiCallResult(
                    success=True, data={"used-directly": {"total": 0}, "used-indirectly": {"total": 0}}
                )
            return ApiCallResult(success=True, data={})

    class _OverlayCache:
        async def get_sync_state(self, *_a: Any) -> None:
            return None

        async def get_objects(self, **_k: Any) -> list[CPObject]:
            return [
                CPObject(
                    mgmt_name="mds1", domain_name="Corp", uid="h-a", name="Host_A", type="host", ipv4_address="10.0.0.1"
                ),
                CPObject(
                    mgmt_name="mds1", domain_name="Corp", uid="h-b", name="Host_B", type="host", ipv4_address="10.0.0.2"
                ),
                CPObject(mgmt_name="mds1", domain_name="Corp", uid="g-1", name="OldGrp", type="group"),
                CPObject(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    uid="h-del",
                    name="H_Decom",
                    type="host",
                    ipv4_address="10.0.0.9",
                ),
            ]

        async def get_object_by_uid(self, *_a: Any) -> None:
            return None

        async def get_object_by_name(self, _m: str, _d: str, name: str) -> CPObject | None:
            for o in await self.get_objects():
                if o.name == name:
                    return o
            return None

        async def get_services(self, **_k: Any) -> list[CPService]:
            return []

        async def get_service_by_uid(self, *_a: Any) -> None:
            return None

        async def get_rulebase_snapshot(self, *_a: Any, **_k: Any) -> DomainRulebaseSnapshot | None:
            return snap

    planner = Planner(api=_OverlayApi(), cache=_OverlayCache(), default_mgmt_name="mds1")  # type: ignore[arg-type]

    # 1. Rename existing rule + create two position="bottom" rules -> BOTH stay above uid-cleanup!
    plan_order = await planner.decide(
        {
            "domain_name": "Corp",
            "operations": [
                {
                    "operation": "set",
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "AllowWeb",
                    "new-name": "AllowWebRenamed",
                },
                {
                    "operation": "add",
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "Rule_1",
                    "action": "Accept",
                    "source": ["Host_A"],
                },
                {
                    "operation": "add",
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "Rule_2",
                    "action": "Accept",
                    "source": ["Host_B"],
                },
            ],
        }
    )
    add1, add2 = plan_order.actions[1], plan_order.actions[2]
    assert add1.outcome == Outcome.CREATE, add1.error
    assert add2.outcome == Outcome.CREATE, add2.error
    assert add1.payload["position"] == {"above": "uid-cleanup"}
    assert add2.payload["position"] == {"above": "uid-cleanup"}

    # 2. Sequential {remove: [Host_A]} then {remove: [Host_B]} MUST fail closed with DiffSafetyError (no silent Any widening)
    plan_widen = await planner.decide(
        {
            "domain_name": "Corp",
            "operations": [
                {
                    "operation": "set",
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "AllowWeb",
                    "source": {"remove": ["Host_A"]},
                },
                {
                    "operation": "set",
                    "type": "access-rule",
                    "layer": "Network",
                    "name": "AllowWeb",
                    "source": {"remove": ["Host_B"]},
                },
            ],
        }
    )
    assert plan_widen.actions[0].outcome == Outcome.UPDATE
    assert plan_widen.actions[1].outcome == Outcome.ERROR
    assert "Any" in (plan_widen.actions[1].error or "")

    # 3. Unnamed virtual rule created in Step 1 fails closed on Step 2 match instead of sending "planned:" UID
    plan_unnamed = await planner.decide(
        {
            "domain_name": "Corp",
            "operations": [
                {
                    "id": "u1",
                    "operation": "add",
                    "type": "access-rule",
                    "layer": "Network",
                    "action": "Accept",
                    "source": ["Host_A"],
                },
                {
                    "operation": "set",
                    "type": "access-rule",
                    "layer": "Network",
                    "source": ["Host_A"],
                    "action": "Accept",
                    "comments": "v2",
                },
            ],
        }
    )
    assert plan_unnamed.actions[0].outcome == Outcome.CREATE
    assert plan_unnamed.actions[1].outcome == Outcome.ERROR
    assert "planned:" not in str(plan_unnamed.actions[1].payload)

    # 4. Renamed group OldGrp->NewGrp does NOT count as virtually deleted for H_Decom check_where_used;
    #    whereas deleting AllowWeb + keeping NewGrp renamed still blocks via OldGrp!
    plan_wu = await planner.decide(
        {
            "domain_name": "Corp",
            "operations": [
                {"operation": "delete", "type": "access-rule", "layer": "Network", "name": "AllowWeb"},
                {"operation": "set", "type": "group", "name": "OldGrp", "new-name": "NewGrp"},
                {"operation": "delete", "type": "host", "name": "H_Decom", "check_where_used": True},
            ],
        }
    )
    del_host_act = plan_wu.actions[2]
    assert del_host_act.outcome == Outcome.ERROR
    assert "OldGrp" in (del_host_act.error or "")
    assert "AllowWeb" not in (del_host_act.error or "")
