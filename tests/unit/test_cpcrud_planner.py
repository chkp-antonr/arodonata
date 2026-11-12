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
