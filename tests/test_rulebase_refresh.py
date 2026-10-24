"""Unit tests for `RulebaseRefreshService` (`arodonata.rulebase.refresh`)."""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainInfo
from arodonata.core.models.rulebase import AccessRuleEntry, DomainRulebaseSnapshot
from arodonata.core.services import DomainService, DomainSyncCoordinator
from arodonata.rulebase.refresh import RulebaseRefreshService


class RulebaseRefreshFakeApi:
    """In-memory `ApiPort` double for `RulebaseRefreshService` tests."""

    def __init__(self) -> None:
        self.session_locks = 0
        self.session_changes = 0
        self.published_uid = "sess-rb-100"
        self.published_iso = "2026-10-24T06:00:00Z"
        self.calls: list[tuple[str, dict[str, Any]]] = []

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
        req = dict(payload or {})
        self.calls.append((command, req))

        if command == "show-last-published-session":
            return ApiCallResult(
                success=True,
                data={"uid": self.published_uid, "publish-time": {"iso-8601": self.published_iso}},
            )

        if command == "show-session":
            return ApiCallResult(
                success=True,
                data={
                    "locks": self.session_locks,
                    "changes": self.session_changes,
                    "number-of-published-changes": self.session_changes,
                },
            )

        if command == "show-nat-rulebase":
            return ApiCallResult(
                success=True,
                data={
                    "package": req.get("package"),
                    "total": 1,
                    "to": 1,
                    "objects-dictionary": [
                        {"uid": "h-int", "name": "internal-web"},
                        {"uid": "h-pub", "name": "public-vip"},
                    ],
                    "rulebase": [
                        {
                            "uid": "nat-sec-1",
                            "name": "Manual NAT",
                            "type": "nat-section",
                            "from": 1,
                            "to": 1,
                            "rulebase": [
                                {
                                    "uid": "nat-r1",
                                    "name": "Publish Web",
                                    "type": "nat-rule",
                                    "rule-number": 1,
                                    "enabled": True,
                                    "method": "static",
                                    "original-source": "Any",
                                    "original-destination": "h-pub",
                                    "translated-destination": "h-int",
                                }
                            ],
                        }
                    ],
                },
            )

        if command == "show-access-rulebase":
            target_uid = req.get("uid") or req.get("name")
            pkg_ctx = req.get("package")

            if target_uid == "layer-global-acc":
                # Global layer containing a top-level rule and a domain place-holder!
                # When queried with `package` context, Check Point resolves `domain-layer`.
                ph_rule: dict[str, Any] = {
                    "uid": "r-global-ph",
                    "name": "Placeholder for domain rules",
                    "type": "place-holder",
                    "rule-number": 2,
                }
                obj_dict: list[dict[str, Any]] = []
                if pkg_ctx:
                    ph_rule["domain-layer"] = "layer-corp-net"
                    obj_dict.append({"uid": "layer-corp-net", "name": "Corp Network", "type": "access-layer"})
                return ApiCallResult(
                    success=True,
                    data={
                        "uid": "layer-global-acc",
                        "name": "Global Access",
                        "total": 2,
                        "to": 2,
                        "objects-dictionary": obj_dict,
                        "rulebase": [
                            {
                                "uid": "r-global-1",
                                "name": "Global DNS Allow",
                                "type": "access-rule",
                                "rule-number": 1,
                                "action": "Accept",
                            },
                            ph_rule,
                        ],
                    },
                )

            if target_uid == "layer-corp-net":
                return ApiCallResult(
                    success=True,
                    data={
                        "uid": "layer-corp-net",
                        "name": "Corp Network",
                        "total": 2,
                        "to": 2,
                        "objects-dictionary": [
                            {"uid": "layer-inline-web", "name": "Web Inline Layer", "type": "access-layer"},
                        ],
                        "rulebase": [
                            {
                                "uid": "sec-corp-1",
                                "name": "Core Rules",
                                "type": "access-section",
                                "from": 1,
                                "to": 2,
                                "rulebase": [
                                    {
                                        "uid": "r-corp-1",
                                        "name": "Allow SSH",
                                        "type": "access-rule",
                                        "rule-number": 1,
                                        "action": "Accept",
                                    },
                                    {
                                        "uid": "r-corp-2",
                                        "name": "Web Inspection",
                                        "type": "access-rule",
                                        "rule-number": 2,
                                        "action": "Apply Layer",
                                        "inline-layer": "layer-inline-web",
                                    },
                                ],
                            }
                        ],
                    },
                )

            if target_uid == "layer-inline-web":
                return ApiCallResult(
                    success=True,
                    data={
                        "uid": "layer-inline-web",
                        "name": "Web Inline Layer",
                        "total": 1,
                        "to": 1,
                        "rulebase": [
                            {
                                "uid": "r-inline-1",
                                "name": "Allow HTTPS",
                                "type": "access-rule",
                                "rule-number": 1,
                                "action": "Accept",
                            }
                        ],
                    },
                )

        if command == "show-https-rulebase":
            return ApiCallResult(
                success=True,
                data={
                    "uid": "layer-https-1",
                    "name": "Corp HTTPS",
                    "total": 1,
                    "to": 1,
                    "rulebase": [
                        {
                            "uid": "hr-1",
                            "name": "Inspect Outbound",
                            "type": "https-rule",
                            "rule-number": 1,
                            "action": "Inspect",
                        }
                    ],
                },
            )

        if command == "show-threat-rulebase":
            return ApiCallResult(
                success=True,
                data={
                    "uid": "layer-threat-1",
                    "name": "Corp Threat",
                    "total": 1,
                    "to": 1,
                    "rulebase": [
                        {
                            "uid": "tr-1",
                            "name": "Optimized Profile",
                            "type": "threat-rule",
                            "rule-number": 1,
                            "action": "Optimized",
                        }
                    ],
                },
            )

        if command in ("show-access-layers", "show-https-layers", "show-threat-layers"):
            return ApiCallResult(success=True, data={"objects": []})

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
        if command == "show-packages":
            return ApiQueryResult(
                success=True,
                objects=[
                    {
                        "uid": "pkg-corp",
                        "name": "Corp_Standard",
                        "nat-policy": True,
                        "access-layers": [
                            {
                                "uid": "layer-global-acc",
                                "name": "Global Access",
                                "position": 1,
                                "domain": {"name": "Global", "domain-type": "global domain"},
                            },
                            {
                                "uid": "layer-corp-net",
                                "name": "Corp Network",
                                "position": 2,
                            },
                        ],
                        "https-layers": [
                            {"uid": "layer-https-1", "name": "Corp HTTPS", "position": 1},
                        ],
                        "threat-layers": [
                            {"uid": "layer-threat-1", "name": "Corp Threat", "position": 1},
                        ],
                    }
                ],
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
        return "sid", "10.0.0.1"

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> Awaitable[bool]:
        async def _done() -> bool:
            return True

        return _done()

    async def close(self, *, logout: bool | None = None) -> None:
        return None


@pytest.mark.asyncio
async def test_rulebase_refresh_refuses_dirty_session_and_preserves_existing_snapshot() -> None:
    """When the shared session has unpublished changes/locks, `refresh_rulebases` refuses with a dirty session error, preserves the cached snapshot, and marks `domain_sync_state.status = 'failed'`."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = RulebaseRefreshFakeApi()
    api.session_locks = 2
    api.session_changes = 1

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    domain_service.tracker.mark_refreshed("mds1")
    await cache.upsert_domains(
        [DomainInfo(mgmt_name="mds1", uid="dom1", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1")]
    )

    # Pre-seed an existing cached rulebase snapshot
    await cache.replace_domain_rulebase(
        DomainRulebaseSnapshot(
            mgmt_name="mds1",
            domain_name="Corp",
            access_rules=[
                AccessRuleEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    layer_uid="l-existing",
                    layer_name="Existing",
                    uid="r-existing-1",
                    name="Existing Rule",
                )
            ],
        )
    )

    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    refresh_svc = RulebaseRefreshService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )

    outcome = await refresh_svc.refresh_rulebases(mgmt_name="mds1", mode="force")
    assert "mds1:Corp" in outcome.failed_domains
    assert "dirty" in outcome.failed_domains["mds1:Corp"].lower()

    # Existing cached rulebase snapshot is preserved untouched
    snap = await cache.get_domain_rulebase("mds1", "Corp")
    assert [r.uid for r in snap.access_rules] == ["r-existing-1"]

    # domain_sync_state marked status="failed" with last_error
    st = await cache.get_sync_state("mds1", "Corp", "rulebase", "*")
    assert st is not None
    assert st.status == "failed"
    assert st.last_error is not None and "dirty" in st.last_error.lower()

    await db.close()


@pytest.mark.asyncio
async def test_rulebase_refresh_traverses_packages_nat_inline_layers_and_global_placeholders() -> None:
    """`refresh_rulebases` traverses `show-packages`, NAT rulebases, ordered layers, inline layers, and Global `place-holder` in `package` context, replacing the snapshot atomically."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = RulebaseRefreshFakeApi()

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    domain_service.tracker.mark_refreshed("mds1")
    await cache.upsert_domains(
        [DomainInfo(mgmt_name="mds1", uid="dom1", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1")]
    )

    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    refresh_svc = RulebaseRefreshService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )

    events = [ev async for ev in refresh_svc.stream_refresh_rulebases(mgmt_name="mds1", mode="smart")]
    assert any(ev.event_type == "domain_sync_completed" for ev in events)

    snap = await cache.get_domain_rulebase("mds1", "Corp")
    # 5 access rules (2 in global, 2 in corp-net, 1 in inline-web) + 1 NAT + 1 HTTPS + 1 Threat
    assert len(snap.access_rules) == 5
    assert len(snap.nat_rules) == 1
    assert len(snap.https_rules) == 1
    assert len(snap.threat_rules) == 1

    # Verify Global placeholder rule resolved placeholder_domain_layer_uid == "layer-corp-net"
    ph_rules = [r for r in snap.access_rules if r.uid == "r-global-ph"]
    assert len(ph_rules) == 1
    assert ph_rules[0].placeholder_domain_layer_uid == "layer-corp-net"

    # Verify inline layer has parent_layer_uid and parent_rule_uid recorded
    layers_by_uid = {l_entry.uid: l_entry for l_entry in snap.layers}
    assert "layer-inline-web" in layers_by_uid
    assert layers_by_uid["layer-inline-web"].parent_layer_uid == "layer-corp-net"
    assert layers_by_uid["layer-inline-web"].parent_rule_uid == "r-corp-2"

    # Verify domain_sync_state updated with session UID
    st = await cache.get_sync_state("mds1", "Corp", "rulebase", "*")
    assert st is not None
    assert st.status == "ok"
    assert st.last_session_uid == "sess-rb-100"
    assert st.object_count == 8

    await db.close()
