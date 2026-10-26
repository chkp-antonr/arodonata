"""Unit tests for `ArodonataClient` composition root and facade."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from typing import Any

import pytest

from arodonata import (
    ArodonataClient,
    SessionScope,
)
from arodonata.adapters.storage import DatabaseManager
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext, get_auth_context
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    DomainRulebaseSnapshot,
    HttpsRuleEntry,
    NatRuleEntry,
    ThreatRuleEntry,
)


class FacadeFakeApi:
    """In-memory `ApiPort` double for `ArodonataClient` facade tests."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any] | None, str | None, str | None]] = []
        self.queries: list[tuple[str, str, str | None]] = []
        self.close_logout_args: list[bool | None] = []
        self.logged_out_sids: list[str] = []
        self.published_uid = "pub-sess-1"
        self.published_iso = "2026-10-23T18:00:00Z"
        self.slow_query_delay: float = 0.0

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
        self.calls.append((mgmt_name, command, payload, domain, sid))
        if command == "show-domains":
            return ApiCallResult(
                success=True,
                data={
                    "objects": [
                        {
                            "uid": "dom-corp",
                            "name": "Corp",
                            "type": "domain",
                            "servers": [
                                {
                                    "ipv4-address": "10.1.0.1",
                                    "active": True,
                                    "multi-domain-server": {"ipv4-address": "10.0.0.1"},
                                }
                            ],
                        }
                    ]
                },
            )
        if command == "show-global-domain":
            return ApiCallResult(success=True, data={"uid": "dom-global", "name": "Global", "type": "global"})
        if command == "show-last-published-session":
            return ApiCallResult(
                success=True,
                data={"uid": self.published_uid, "publish-time": {"iso-8601": self.published_iso}},
            )
        if command == "show-session":
            if payload and payload.get("uid") == "sess-rep-1":
                return ApiCallResult(
                    success=True,
                    data={
                        "uid": "sess-rep-1",
                        "name": "CHG-1",
                        "user-name": "admin",
                        "state": "published",
                        "publish-time": {"iso-8601": "2026-10-23T18:00:00Z"},
                    },
                )
            return ApiCallResult(success=True, data={"locks": 0, "changes": 0, "number-of-published-changes": 0})
        if command == "show-changes":
            return ApiCallResult(success=True, data={"tasks": [{"task-details": [{"operations": {}}]}]})
        if command == "show-packages":
            return ApiCallResult(
                success=True,
                data={
                    "packages": [
                        {
                            "uid": "p1",
                            "name": "Standard",
                            "access": True,
                            "access-layers": [{"uid": "l1", "name": "Network", "position": 1}],
                        }
                    ],
                    "to": 1,
                    "total": 1,
                },
            )
        if command == "show-access-rulebase":
            return ApiCallResult(
                success=True,
                data={
                    "uid": "l1",
                    "name": "Network",
                    "rulebase": [
                        {
                            "uid": "ar1",
                            "name": "Allow Web",
                            "type": "access-rule",
                            "rule-number": 1,
                            "enabled": True,
                            "action": {"name": "Accept"},
                        }
                    ],
                    "to": 1,
                    "total": 1,
                },
            )
        if command.startswith(("add-", "set-")) and payload:
            _, _, obj_type = command.partition("-")
            name = str(payload.get("name") or payload.get("new-name") or "unnamed")
            uid = str(payload.get("uid") or f"uid-{obj_type}-{name}")
            return ApiCallResult(success=True, data={**payload, "uid": uid, "name": name, "type": obj_type})
        if command.startswith("delete-"):
            return ApiCallResult(success=True, data={"message": "OK"})
        if command in ("publish", "discard"):
            return ApiCallResult(success=True, data={"message": "OK"})
        return ApiCallResult(success=True, data={})

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
        if self.slow_query_delay > 0:
            await asyncio.sleep(self.slow_query_delay)
        self.queries.append((mgmt_name, command, domain))
        if command == "show-hosts":
            return ApiQueryResult(
                success=True,
                objects=[
                    {"uid": "h-base-1", "name": "host-base-1", "type": "host", "ipv4-address": "10.1.1.1"},
                    {"uid": "h-base-2", "name": "host-base-2", "type": "host", "ipv4-address": "10.1.1.2"},
                ],
                total=2,
            )
        if command == "show-networks":
            return ApiQueryResult(
                success=True,
                objects=[
                    {
                        "uid": "n-base-1",
                        "name": "net-base-1",
                        "type": "network",
                        "subnet4": "10.1.1.0",
                        "mask-length4": 24,
                    }
                ],
                total=1,
            )
        if command == "show-address-ranges":
            return ApiQueryResult(
                success=True,
                objects=[
                    {
                        "uid": "r-base-1",
                        "name": "rng-base-1",
                        "type": "address-range",
                        "ipv4-address-first": "10.1.1.10",
                        "ipv4-address-last": "10.1.1.20",
                    }
                ],
                total=1,
            )
        if command == "show-dns-domains":
            return ApiQueryResult(
                success=True,
                objects=[{"uid": "d-base-1", "name": ".corp.local", "type": "dns-domain", "is-sub-domain": True}],
                total=1,
            )
        if command == "show-groups":
            return ApiQueryResult(
                success=True,
                objects=[{"uid": "g-base-1", "name": "grp-base-1", "type": "group", "members": ["h-base-1"]}],
                total=1,
            )
        if command == "show-services-tcp":
            return ApiQueryResult(
                success=True,
                objects=[{"uid": "s-tcp-1", "name": "http", "type": "service-tcp", "port": "80", "protocol": "tcp"}],
                total=1,
            )
        if command == "show-gateways-and-servers":
            return ApiQueryResult(
                success=True,
                objects=[{"uid": "gw-1", "name": "corp-fw-01", "type": "simple-gateway", "ipv4-address": "10.1.0.254"}],
                total=1,
            )
        return ApiQueryResult(success=True, objects=[], total=0)

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        return "ws-sid-123", "10.1.0.1"

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> Awaitable[bool]:
        self.logged_out_sids.append(sid)

        async def _done() -> bool:
            return True

        return _done()

    async def close(self, *, logout: bool | None = None) -> None:
        self.close_logout_args.append(logout)


@pytest.mark.asyncio
async def test_client_typed_getters_and_no_implicit_warmup_on_get_domains() -> None:
    """`ArodonataClient` exposes typed getters and `get_domains()` never starts implicit object warm-up."""
    fake_api = FacadeFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=300)

    async with ArodonataClient(settings, api=fake_api) as client:
        assert client.owns_engine is True

        # get_domains() fetches domains without querying objects
        domains = await client.get_domains("mds1")
        assert [d.name for d in domains] == ["Corp"]
        assert client.warmup_tasks == set()
        assert fake_api.queries == []

        # Typed getters
        hosts = await client.get_hosts("mds1", "Corp")
        assert [h.name for h in hosts] == ["host-base-1", "host-base-2"]

        nets = await client.get_networks("mds1", "Corp")
        assert [n.name for n in nets] == ["net-base-1"]

        ranges = await client.get_address_ranges("mds1", "Corp")
        assert [r.name for r in ranges] == ["rng-base-1"]

        dns_doms = await client.get_dns_domains("mds1", "Corp")
        assert [d.name for d in dns_doms] == [".corp.local"]

        groups = await client.get_groups("mds1", "Corp")
        assert [g.name for g in groups] == ["grp-base-1"]

        services = await client.get_services("mds1", "Corp", types=["service-tcp"])
        assert [s.name for s in services] == ["http"]

        gateways = await client.get_gateways("mds1", "Corp")
        assert [gw.name for gw in gateways] == ["corp-fw-01"]

        by_uid = await client.get_object_by_uid("mds1", "Corp", "h-base-1")
        assert by_uid is not None and by_uid.name == "host-base-1"

        found_svc = await client.find_object("mds1", "Corp", "http", obj_type="service-tcp")
        assert found_svc is not None and found_svc.uid == "s-tcp-1"

        found_svc_alias = await client.find_object("mds1", "Corp", "http", obj_type="tcp")
        assert found_svc_alias is not None and found_svc_alias.uid == "s-tcp-1"

        found_gw = await client.find_object("mds1", "Corp", "corp-fw-01")
        assert found_gw is not None and found_gw.uid == "gw-1" and found_gw.type == "simple-gateway"

        found_gw_alias = await client.find_object("mds1", "Corp", "gw-1", obj_type="gateway")
        assert found_gw_alias is not None and found_gw_alias.name == "corp-fw-01"

        grp_members = await client.get_group_members("mds1", "Corp", "grp-base-1")
        assert [m.uid for m in grp_members] == ["h-base-1"]

    # Auto-created in-memory engine -> logout=True on close
    assert fake_api.close_logout_args == [True]


@pytest.mark.asyncio
async def test_client_write_session_overlay_and_publish_invalidation() -> None:
    """`write_session` overlays uncommitted `add_object` / `set_object` / `delete_object` onto reads, auto-publishes on clean exit, invalidates domain memo, and discards on exception."""
    fake_api = FacadeFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=300)

    async with ArodonataClient(settings, api=fake_api) as client:
        # Initial read warms the cache and sets cache_ttl memo
        initial_hosts = await client.get_hosts("mds1", "Corp")
        assert {h.name for h in initial_hosts} == {"host-base-1", "host-base-2"}

        # Open a WriteSession: add a host, update host-base-1, delete host-base-2, and add a service
        async with client.write_session("mds1", "Corp") as ws:
            await client.add_object(
                "mds1",
                "host",
                {"name": "host-staged-3", "ipv4-address": "10.1.1.3"},
                domain="Corp",
            )
            await client.set_object(
                "mds1",
                "host",
                {"uid": "h-base-1", "name": "host-base-1", "ipv4-address": "10.1.1.111"},
                domain="Corp",
            )
            await client.delete_object("mds1", "host", uid="h-base-2", domain="Corp")
            await client.add_object(
                "mds1",
                "service-tcp",
                {"name": "https-alt", "port": "8443"},
                domain="Corp",
            )

            # Inside WriteSession, get_hosts() and get_services() reflect uncommitted overlay without mutating DB
            session_hosts = await client.get_hosts("mds1", "Corp", cache_mode="cache")
            by_name = {h.name: h for h in session_hosts}
            assert set(by_name.keys()) == {"host-base-1", "host-staged-3"}
            assert by_name["host-base-1"].ipv4_address == "10.1.1.111"

            session_svcs = await client.get_services("mds1", "Corp", types=["service-tcp"], cache_mode="cache")
            assert any(s.name == "https-alt" for s in session_svcs)

            # Underlying shared SQLite cache is untouched prior to publish
            raw_db_hosts = await client.cache.get_objects("mds1", "Corp", types=["host"])
            assert {h.name for h in raw_db_hosts} == {"host-base-1", "host-base-2"}

        # Clean exit published the session and invalidated ("mds1", "Corp")
        assert ws.published is True
        assert ("mds1", "Corp") in client.sync_coordinator.invalidated_domains
        assert "ws-sid-123" in fake_api.logged_out_sids

        # Test WriteSession exception path -> discards session and clears overlay
        with pytest.raises(RuntimeError, match="abort write"):
            async with client.write_session("mds1", "Corp") as ws_fail:
                await client.add_object("mds1", "host", {"name": "never-published"}, domain="Corp")
                raise RuntimeError("abort write")

        assert ws_fail.discarded is True
        discard_calls = [c for c in fake_api.calls if c[1] == "discard"]
        assert len(discard_calls) == 1


@pytest.mark.asyncio
async def test_client_external_engine_logout_policy_warmup_cancellation_and_rulebase_getters() -> None:
    """External engine preserves sessions on `close(logout=None)`, running warm-up tasks are cancelled on `close()`, and rulebase getters filter properly."""
    ext_db = DatabaseManager()
    await ext_db.initialize()
    fake_api = FacadeFakeApi()
    fake_api.slow_query_delay = 5.0
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")

    client = ArodonataClient(settings, engine=ext_db.engine, api=fake_api)
    await client.initialize(run_startup_cleanup=False)
    assert client.owns_engine is False

    # Seed rulebase snapshot and verify getters
    await client.cache.replace_domain_rulebase(
        DomainRulebaseSnapshot(
            mgmt_name="mds1",
            domain_name="Corp",
            access_rules=[
                AccessRuleEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    layer_uid="l1",
                    layer_name="Network",
                    uid="ar1",
                    name="Allow Web",
                )
            ],
            nat_rules=[
                NatRuleEntry(mgmt_name="mds1", domain_name="Corp", package_uid="p1", package_name="Standard", uid="nr1")
            ],
            https_rules=[
                HttpsRuleEntry(
                    mgmt_name="mds1", domain_name="Corp", layer_uid="hl1", layer_name="HTTPS Layer", uid="hr1"
                )
            ],
            threat_rules=[
                ThreatRuleEntry(
                    mgmt_name="mds1", domain_name="Corp", layer_uid="tl1", layer_name="Threat Layer", uid="tr1"
                )
            ],
        )
    )
    assert len(await client.get_access_rules("mds1", "Corp", layer_name="Network")) == 1
    assert len(await client.get_nat_rules("mds1", "Corp", package_name="Standard")) == 1
    assert len(await client.get_https_rules("mds1", "Corp", layer_uid="hl1")) == 1
    assert len(await client.get_threat_rules("mds1", "Corp", layer_uid="tl1")) == 1

    with client.auth_context(username="admin1", password="pw1") as actx:
        assert get_auth_context() == actx

    # Start explicit background warm-up (which sleeps 5s per query) and immediately close client
    warmup_task = client.start_object_cache_warmup(mgmt_name="mds1")
    await asyncio.sleep(0.02)
    assert len(client.warmup_tasks) == 1

    await client.close()
    assert warmup_task.cancelled() or warmup_task.done()
    # Because an external engine was passed (`owns_engine == False`), `logout` defaulted to `False`
    assert fake_api.close_logout_args == [False]

    await ext_db.close()


@pytest.mark.asyncio
async def test_client_rulebase_and_change_report_facade_methods() -> None:
    """`ArodonataClient` delegates rulebase refresh, numbering, locate, filter, and change report methods."""
    fake_api = FacadeFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")

    async with ArodonataClient(settings, api=fake_api) as client:
        # Refresh rulebases via client
        outcome = await client.refresh_rulebases(mgmt_name="mds1", domains=["Corp"])
        assert "mds1:Corp" in outcome.refreshed_domains

        pkgs = await client.get_policy_packages("mds1", "Corp")
        assert len(pkgs) == 1 and pkgs[0].name == "Standard"

        pkg_rb = await client.get_package_rulebase("mds1", "Corp", "Standard")
        assert pkg_rb.package_name == "Standard"
        assert len(pkg_rb.layers) == 1

        layer_rb = await client.get_layer_rulebase("mds1", "Corp", "Network")
        assert layer_rb.layer_name == "Network"
        assert layer_rb.rules[0].rule_number == "1"

        locs = await client.locate_rules("mds1", "Corp", rule_uids=["ar1"])
        assert len(locs.rule_locations["ar1"]) == 1

        filtered = await client.filter_rulebase(
            "mds1",
            "Corp",
            layer="Network",
            filter_query="Allow Web",
        )
        assert filtered.matched_count == 1 and filtered.rules[0].uid == "ar1"

        # Change report collection & rendering via client
        bundle = await client.build_change_report(
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["sess-rep-1"])],
            formats=("markdown", "json"),
        )
        assert bundle.markdown is not None
        assert "CHG-1" in bundle.markdown
        re_rendered = client.render_change_report(bundle.report, formats=("json",))
        assert re_rendered.json_text is not None
        assert '"format_version": 1' in re_rendered.json_text


@pytest.mark.asyncio
async def test_client_cpcrud_facade_validate_plan_apply_and_inverse() -> None:
    """`client.cpcrud` exposes `validate`, `plan`, `apply`, `stream_apply`, and `inverse` end-to-end."""
    fake_api = FacadeFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")

    async with ArodonataClient(settings, api=fake_api) as client:
        # Warm host cache so HybridStateReader has a fresh slice matching `pub-sess-1`
        await client.get_hosts("mds1", "Corp")

        template: dict[str, Any] = {
            "version": 1,
            "mgmt_name": "mds1",
            "domain": "Corp",
            "objects": [
                # Existing host-base-1 (10.1.1.1) -> UNCHANGED
                {"type": "host", "name": "host-base-1", "ipv4-address": "10.1.1.1"},
                # New host -> CREATE
                {"type": "host", "name": "host-cpcrud-new", "ipv4-address": "10.1.1.99"},
            ],
        }

        assert client.cpcrud.validate(template) == []

        plan = await client.cpcrud.plan(template)
        assert len(plan.actions) == 2
        assert plan.actions[0].outcome.value == "unchanged"
        assert plan.actions[1].outcome.value == "create"

        report = await client.cpcrud.apply(plan)
        assert report.has_failures is False
        assert report.published_domains == ["mds1:Corp"]
        assert ("mds1", "Corp") in client.sync_coordinator.invalidated_domains

        inv = client.cpcrud.inverse(plan, report)
        assert client.cpcrud.validate(inv) == []
        assert len(inv["operations"]) == 1
        assert inv["operations"][0]["operation"] == "delete"
        assert inv["operations"][0]["name"] == "host-cpcrud-new"


@pytest.mark.asyncio
async def test_standalone_mutation_helpers_auto_wrap_in_isolated_write_session() -> None:
    """Adversarial test for C8:
    - Calling client.add_object / set_object / delete_object outside an explicit write_session
      automatically opens an isolated WriteSession, publishes on success, and logs out the dedicated SID.
    """
    fake_api = FacadeFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")

    async with ArodonataClient(settings, api=fake_api) as client:
        res = await client.add_object(
            "mds1", "host", {"name": "standalone-host", "ipv4-address": "10.9.9.9"}, domain="Corp"
        )
        assert res.success is True

        # Verify add-host used dedicated session sid ("ws-sid-123"), followed by publish and logout
        add_calls = [c for c in fake_api.calls if c[1] == "add-host"]
        pub_calls = [c for c in fake_api.calls if c[1] == "publish"]
        assert len(add_calls) == 1
        assert add_calls[0][4] == "ws-sid-123"
        assert len(pub_calls) == 1
        assert pub_calls[0][4] == "ws-sid-123"
        assert "ws-sid-123" in fake_api.logged_out_sids
