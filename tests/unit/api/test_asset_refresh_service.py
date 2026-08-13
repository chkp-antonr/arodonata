"""Unit tests for AssetRefreshService."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from arodonata.api.asset_transformer import AssetTransformer
from arodonata.api.schemas import SSEEventType
from arodonata.api.services.asset_refresh_service import AssetRefreshService


def _api_result(objects=None, success=True, message="", code=None):
    return SimpleNamespace(
        success=success,
        message=message,
        code=code,
        objects=objects if objects is not None else [],
    )


def _make_service(
    *,
    api_query_result=None,
    api_query_side_effect=None,
    mgmt_names=None,
    is_mdm=False,
    domains_by_mgmt=None,
    cache=None,
    domain_service=None,
    cluster_manager_class=None,
    vsx_manager_class=None,
):
    mgmt_client = MagicMock()
    mgmt_client.get_mgmt_names.return_value = mgmt_names or ["mgmt1"]

    async def _get_server(mgmt_name):
        return SimpleNamespace(is_mdm=is_mdm)

    mgmt_client.get_server = AsyncMock(side_effect=_get_server)

    if domain_service is None:
        domain_service = AsyncMock()
        domains_by_mgmt = domains_by_mgmt or {}

        async def _populate(mgmt_name, cache_mode="auto"):
            return domains_by_mgmt.get(mgmt_name, ["domainA"])

        domain_service.populate_domain_cache = AsyncMock(side_effect=_populate)
        domain_service.get_domain_uid.return_value = "domain-uid-1"

    if cache is None:
        cache = AsyncMock()
        cache.delete_assets.return_value = 0
        cache.get_domains.return_value = []

    if api_query_side_effect is not None:
        api_query = AsyncMock(side_effect=api_query_side_effect)
    else:
        api_query = AsyncMock(return_value=api_query_result or _api_result())

    cluster_manager_instance = MagicMock()
    vsx_manager_instance = MagicMock()

    service = AssetRefreshService(
        mgmt_client=mgmt_client,
        cache=cache,
        domain_service=domain_service,
        cluster_manager=cluster_manager_class() if cluster_manager_class else cluster_manager_instance,
        vsx_manager=vsx_manager_class() if vsx_manager_class else vsx_manager_instance,
        settings=MagicMock(),
        api_query_method=api_query,
    )
    return service, mgmt_client, domain_service, cache, api_query


# ---------------------------------------------------------------------------
# refresh_domain_assets / _refresh_domain_assets_impl
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_domain_assets_upserts_and_yields_result(monkeypatch):
    api_result = _api_result(objects=[{"uid": "gw-uid-1", "name": "gw1"}])
    service, _mgmt, domain_service, cache, api_query = _make_service(api_query_result=api_result)

    fake_asset = SimpleNamespace(asset_id="mgmt1:domainA:gw1")
    monkeypatch.setattr(AssetTransformer, "transform_to_asset", MagicMock(return_value=fake_asset))

    events = [event async for event in service.refresh_domain_assets("mgmt1", "domainA")]

    api_query.assert_awaited_once_with(
        mgmt_name="mgmt1",
        command="show-gateways-and-servers",
        domain="domainA",
        details_level="full",
        cache_mode="auto",
    )
    cache.upsert_assets.assert_awaited_once_with([fake_asset])

    result_events = [e for e in events if e.event_type == SSEEventType.RESULT]
    assert len(result_events) == 1
    assert result_events[0].data["count"] == 1
    assert result_events[0].mgmt_name == "mgmt1"
    assert result_events[0].domain == "domainA"


@pytest.mark.asyncio
async def test_refresh_domain_assets_yields_error_on_api_failure():
    api_result = _api_result(success=False, message="boom", code="E1", objects=None)
    service, _mgmt, _domain_service, cache, _api_query = _make_service(api_query_result=api_result)

    events = [event async for event in service.refresh_domain_assets("mgmt1", "domainA")]

    error_events = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert len(error_events) == 1
    assert error_events[0].data["error_message"] == "boom"
    assert error_events[0].data["error_code"] == "E1"
    cache.upsert_assets.assert_not_awaited()


@pytest.mark.asyncio
async def test_refresh_domain_assets_skips_upsert_when_no_objects():
    api_result = _api_result(objects=[])
    service, _mgmt, _domain_service, cache, _api_query = _make_service(api_query_result=api_result)

    events = [event async for event in service.refresh_domain_assets("mgmt1", "domainA")]

    cache.upsert_assets.assert_not_awaited()
    result_events = [e for e in events if e.event_type == SSEEventType.RESULT]
    assert result_events[0].data["count"] == 0


@pytest.mark.asyncio
async def test_refresh_domain_assets_skips_transform_failures(monkeypatch):
    api_result = _api_result(objects=[{"uid": "gw-uid-1", "name": "gw1"}, {"bad": "object"}])
    service, _mgmt, _domain_service, cache, _api_query = _make_service(api_query_result=api_result)

    fake_asset = SimpleNamespace(asset_id="mgmt1:domainA:gw1")
    monkeypatch.setattr(AssetTransformer, "transform_to_asset", MagicMock(side_effect=[fake_asset, None]))

    events = [event async for event in service.refresh_domain_assets("mgmt1", "domainA")]

    cache.upsert_assets.assert_awaited_once_with([fake_asset])
    result_events = [e for e in events if e.event_type == SSEEventType.RESULT]
    assert result_events[0].data["count"] == 1


@pytest.mark.asyncio
async def test_refresh_domain_assets_catches_unexpected_exception():
    service, _mgmt, _domain_service, cache, _api_query = _make_service(
        api_query_side_effect=RuntimeError("connection lost")
    )

    events = [event async for event in service.refresh_domain_assets("mgmt1", "domainA")]

    error_events = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert len(error_events) == 1
    assert "connection lost" in error_events[0].data["error_message"]
    cache.upsert_assets.assert_not_awaited()


# ---------------------------------------------------------------------------
# _collect_mds_assets / MDS phase across MDM servers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_collect_mds_assets_upserts_with_domain_from_object(monkeypatch):
    api_result = _api_result(
        objects=[{"uid": "mds-uid-1", "name": "mds1", "domain": {"name": "System Data", "uid": "sys-uid"}}]
    )
    service, _mgmt, _domain_service, cache, api_query = _make_service(api_query_result=api_result)

    fake_asset = SimpleNamespace(asset_id="mgmt1:System Data:mds1")
    transform_mock = MagicMock(return_value=fake_asset)
    monkeypatch.setattr(AssetTransformer, "transform_to_asset", transform_mock)

    events = [event async for event in service._collect_mds_assets("mgmt1")]

    api_query.assert_awaited_once_with(
        mgmt_name="mgmt1",
        command="show-mdss",
        details_level="full",
        payload={"show-domains": False},
        cache_mode="auto",
    )
    transform_mock.assert_called_once_with(
        obj=api_result.objects[0], mgmt_name="mgmt1", domain_name="System Data", domain_uid="sys-uid"
    )
    cache.upsert_assets.assert_awaited_once_with([fake_asset])
    result_events = [e for e in events if e.event_type == SSEEventType.RESULT]
    assert result_events[0].data["result_type"] == "mds_assets"
    assert result_events[0].data["count"] == 1


@pytest.mark.asyncio
async def test_collect_mds_assets_defaults_domain_when_not_a_dict(monkeypatch):
    api_result = _api_result(objects=[{"uid": "mds-uid-1", "name": "mds1", "domain": "unexpected-string"}])
    service, _mgmt, _domain_service, cache, _api_query = _make_service(api_query_result=api_result)

    fake_asset = SimpleNamespace(asset_id="mgmt1:System Data:mds1")
    transform_mock = MagicMock(return_value=fake_asset)
    monkeypatch.setattr(AssetTransformer, "transform_to_asset", transform_mock)

    async for _event in service._collect_mds_assets("mgmt1"):
        pass

    transform_mock.assert_called_once_with(
        obj=api_result.objects[0], mgmt_name="mgmt1", domain_name="System Data", domain_uid=""
    )


@pytest.mark.asyncio
async def test_collect_mds_assets_yields_error_on_api_failure():
    api_result = _api_result(success=False, message="mds boom", code="E2", objects=None)
    service, _mgmt, _domain_service, cache, _api_query = _make_service(api_query_result=api_result)

    events = [event async for event in service._collect_mds_assets("mgmt1")]

    error_events = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert len(error_events) == 1
    assert error_events[0].data["error_message"] == "mds boom"
    cache.upsert_assets.assert_not_awaited()


@pytest.mark.asyncio
async def test_collect_mds_assets_catches_unexpected_exception():
    service, _mgmt, _domain_service, cache, _api_query = _make_service(api_query_side_effect=RuntimeError("mds crash"))

    events = [event async for event in service._collect_mds_assets("mgmt1")]

    error_events = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert len(error_events) == 1
    assert "mds crash" in error_events[0].data["error_message"]


@pytest.mark.asyncio
async def test_collect_mds_phase_accumulates_across_multiple_mdm_servers(monkeypatch):
    """MDS collection should run for every MDM server in scope and accumulate
    the total_collected count across all of them."""

    async def _api_query_side_effect(mgmt_name, **kwargs):
        return _api_result(objects=[{"uid": f"{mgmt_name}-mds", "name": f"{mgmt_name}-mds"}])

    service, mgmt_client, _domain_service, cache, api_query = _make_service(
        mgmt_names=["mdm1", "mdm2"],
        is_mdm=True,
        api_query_side_effect=_api_query_side_effect,
    )

    fake_asset = MagicMock()
    monkeypatch.setattr(AssetTransformer, "transform_to_asset", MagicMock(return_value=fake_asset))

    stats = {"total_collected": 0, "errors": [], "aborted": False}
    events = [event async for event in service._collect_mds_phase(["mdm1", "mdm2"], "auto", stats)]

    assert api_query.await_count == 2
    assert stats["total_collected"] == 2
    result_events = [e for e in events if e.event_type == SSEEventType.RESULT]
    assert {e.mgmt_name for e in result_events} == {"mdm1", "mdm2"}


@pytest.mark.asyncio
async def test_collect_mds_phase_skips_non_mdm_servers():
    service, mgmt_client, _domain_service, cache, api_query = _make_service(mgmt_names=["mgmt1"], is_mdm=False)

    stats = {"total_collected": 0, "errors": [], "aborted": False}
    events = [event async for event in service._collect_mds_phase(["mgmt1"], "auto", stats)]

    api_query.assert_not_awaited()
    assert events == []
    assert stats["total_collected"] == 0


@pytest.mark.asyncio
async def test_collect_mds_phase_records_error_for_one_server_without_affecting_others(monkeypatch):
    """If get_server (or MDS collection) raises for one mgmt_name, the error is
    recorded in stats and other servers still get processed."""
    mgmt_client = MagicMock()

    async def _get_server(mgmt_name):
        if mgmt_name == "mdm-bad":
            raise RuntimeError("server unreachable")
        return SimpleNamespace(is_mdm=True)

    mgmt_client.get_server = AsyncMock(side_effect=_get_server)
    mgmt_client.get_mgmt_names.return_value = ["mdm-bad", "mdm-good"]

    domain_service = AsyncMock()
    cache = AsyncMock()
    cache.delete_assets.return_value = 0
    cache.get_domains.return_value = []

    api_result = _api_result(objects=[{"uid": "mds-uid", "name": "mds-good"}])
    api_query = AsyncMock(return_value=api_result)

    service = AssetRefreshService(
        mgmt_client=mgmt_client,
        cache=cache,
        domain_service=domain_service,
        cluster_manager=MagicMock(),
        vsx_manager=MagicMock(),
        settings=MagicMock(),
        api_query_method=api_query,
    )

    fake_asset = MagicMock()
    monkeypatch.setattr(AssetTransformer, "transform_to_asset", MagicMock(return_value=fake_asset))

    stats = {"total_collected": 0, "errors": [], "aborted": False}
    events = [event async for event in service._collect_mds_phase(["mdm-bad", "mdm-good"], "auto", stats)]

    assert any("mdm-bad MDS collection" in err for err in stats["errors"])
    assert stats["total_collected"] == 1
    result_events = [e for e in events if e.event_type == SSEEventType.RESULT]
    assert len(result_events) == 1
    assert result_events[0].mgmt_name == "mdm-good"
    error_events = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert any(e.mgmt_name == "mdm-bad" for e in error_events)


# ---------------------------------------------------------------------------
# _prepare_scope / domain filtering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_prepare_scope_filters_to_requested_domains():
    domain_service = AsyncMock()
    domain_service.populate_domain_cache.return_value = ["domainA", "domainB", "domainC"]

    service, _mgmt, _domain_service, _cache, _api_query = _make_service(domain_service=domain_service)

    target_servers_and_domains: dict[str, list[str]] = {}
    all_domains_to_delete: set[str] = set()

    events = [
        event
        async for event in service._prepare_scope(
            ["mgmt1"], ["domainA", "domainC"], "auto", target_servers_and_domains, all_domains_to_delete
        )
    ]

    assert target_servers_and_domains == {"mgmt1": ["domainA", "domainC"]}
    assert all_domains_to_delete == {"domainA", "domainC"}
    warning_events = [e for e in events if e.event_type == SSEEventType.WARNING]
    assert warning_events == []


@pytest.mark.asyncio
async def test_prepare_scope_warns_about_missing_domains():
    domain_service = AsyncMock()
    domain_service.populate_domain_cache.return_value = ["domainA"]

    service, _mgmt, _domain_service, _cache, _api_query = _make_service(domain_service=domain_service)

    target_servers_and_domains: dict[str, list[str]] = {}
    all_domains_to_delete: set[str] = set()

    events = [
        event
        async for event in service._prepare_scope(
            ["mgmt1"], ["domainA", "missing-domain"], "auto", target_servers_and_domains, all_domains_to_delete
        )
    ]

    warning_events = [e for e in events if e.event_type == SSEEventType.WARNING]
    assert len(warning_events) == 1
    assert warning_events[0].data["missing_domains"] == ["missing-domain"]
    assert target_servers_and_domains == {"mgmt1": ["domainA"]}


@pytest.mark.asyncio
async def test_prepare_scope_no_domain_filter_keeps_all_domains_and_no_delete_set():
    domain_service = AsyncMock()
    domain_service.populate_domain_cache.return_value = ["domainA", "domainB"]

    service, _mgmt, _domain_service, _cache, _api_query = _make_service(domain_service=domain_service)

    target_servers_and_domains: dict[str, list[str]] = {}
    all_domains_to_delete = None

    events = [
        event
        async for event in service._prepare_scope(
            ["mgmt1"], [], "auto", target_servers_and_domains, all_domains_to_delete
        )
    ]

    assert target_servers_and_domains == {"mgmt1": ["domainA", "domainB"]}
    log_events = [e for e in events if e.event_type == SSEEventType.LOG]
    assert log_events[0].data["domains_count"] == 2


@pytest.mark.asyncio
async def test_prepare_scope_continues_when_one_mgmt_name_fails():
    domain_service = AsyncMock()

    async def _populate(mgmt_name, cache_mode="auto"):
        if mgmt_name == "bad-mgmt":
            raise RuntimeError("connection refused")
        return ["domainA"]

    domain_service.populate_domain_cache = AsyncMock(side_effect=_populate)

    service, _mgmt, _domain_service, _cache, _api_query = _make_service(domain_service=domain_service)

    target_servers_and_domains: dict[str, list[str]] = {}
    all_domains_to_delete: set[str] = set()

    events = [
        event
        async for event in service._prepare_scope(
            ["bad-mgmt", "good-mgmt"], [], "auto", target_servers_and_domains, all_domains_to_delete
        )
    ]

    error_events = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert len(error_events) == 1
    assert error_events[0].mgmt_name == "bad-mgmt"
    assert "Failed to populate domains" in error_events[0].data["error_message"]
    # good-mgmt should still be processed
    assert target_servers_and_domains == {"good-mgmt": ["domainA"]}


# ---------------------------------------------------------------------------
# _delete_existing_assets scoping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_existing_assets_no_filters_deletes_everything():
    cache = AsyncMock()
    cache.delete_assets.return_value = 5
    service, _mgmt, _domain_service, _cache, _api_query = _make_service(cache=cache)

    result = await service._delete_existing_assets(["mgmt1", "mgmt2"], [], None)

    assert result is None
    cache.delete_assets.assert_awaited_once_with(mgmt_names=None, domain_names=None)


@pytest.mark.asyncio
async def test_delete_existing_assets_scoped_to_mgmt_names_only():
    cache = AsyncMock()
    cache.delete_assets.return_value = 3
    service, _mgmt, _domain_service, _cache, _api_query = _make_service(cache=cache)

    result = await service._delete_existing_assets(["mgmt1"], ["mgmt1"], None)

    assert result is None
    cache.delete_assets.assert_awaited_once_with(mgmt_names=["mgmt1"], domain_names=None)


@pytest.mark.asyncio
async def test_delete_existing_assets_scoped_to_domains():
    cache = AsyncMock()
    cache.delete_assets.return_value = 1
    service, _mgmt, _domain_service, _cache, _api_query = _make_service(cache=cache)

    result = await service._delete_existing_assets(["mgmt1"], ["mgmt1"], {"domainA", "domainB"})

    assert result is None
    call_kwargs = cache.delete_assets.call_args.kwargs
    assert call_kwargs["mgmt_names"] == ["mgmt1"]
    assert set(call_kwargs["domain_names"]) == {"domainA", "domainB"}


@pytest.mark.asyncio
async def test_delete_existing_assets_returns_error_event_on_failure():
    cache = AsyncMock()
    cache.delete_assets.side_effect = RuntimeError("db down")
    service, _mgmt, _domain_service, _cache, _api_query = _make_service(cache=cache)

    result = await service._delete_existing_assets(["mgmt1"], ["mgmt1"], None)

    assert result is not None
    assert result.event_type == SSEEventType.ERROR
    assert "db down" in result.data["error_message"]


# ---------------------------------------------------------------------------
# _collect_domain_phase: lock renewal
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_collect_domain_phase_renews_lock_per_mgmt_and_per_domain(monkeypatch):
    lock_context = MagicMock()
    lock_context.renew_if_needed = AsyncMock()
    monkeypatch.setattr(
        "arodonata.api.services.asset_refresh_service.get_current_lock_context",
        lambda: lock_context,
    )

    api_result = _api_result(objects=[{"uid": "gw-uid-1", "name": "gw1"}])
    service, _mgmt, _domain_service, cache, _api_query = _make_service(api_query_result=api_result)

    fake_asset = SimpleNamespace(asset_id="mgmt1:domainA:gw1")
    monkeypatch.setattr(AssetTransformer, "transform_to_asset", MagicMock(return_value=fake_asset))

    stats = {"total_collected": 0, "errors": [], "aborted": False}
    target_servers_and_domains = {"mgmt1": ["domainA", "domainB"]}

    events = [event async for event in service._collect_domain_phase(target_servers_and_domains, "auto", stats)]

    # Renewed once per mgmt_name, plus once per domain (2 domains) = 3 calls.
    assert lock_context.renew_if_needed.await_count == 3
    assert stats["aborted"] is False
    assert stats["total_collected"] == 2
    assert not stats["errors"]
    assert any(e.event_type == SSEEventType.RESULT for e in events)


@pytest.mark.asyncio
async def test_collect_domain_phase_aborts_when_lock_renewal_fails_per_mgmt(monkeypatch):
    lock_context = MagicMock()
    lock_context.renew_if_needed = AsyncMock(side_effect=RuntimeError("lock expired"))
    monkeypatch.setattr(
        "arodonata.api.services.asset_refresh_service.get_current_lock_context",
        lambda: lock_context,
    )

    service, _mgmt, _domain_service, cache, api_query = _make_service()

    stats = {"total_collected": 0, "errors": [], "aborted": False}
    target_servers_and_domains = {"mgmt1": ["domainA"]}

    events = [event async for event in service._collect_domain_phase(target_servers_and_domains, "auto", stats)]

    assert stats["aborted"] is True
    error_events = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert len(error_events) == 1
    assert "Lock lost during operation" in error_events[0].data["error_message"]
    api_query.assert_not_awaited()


@pytest.mark.asyncio
async def test_collect_domain_phase_aborts_when_lock_renewal_fails_per_domain(monkeypatch):
    lock_context = MagicMock()
    # Succeed on the per-mgmt renewal, fail on the per-domain renewal.
    lock_context.renew_if_needed = AsyncMock(side_effect=[None, RuntimeError("lock expired")])
    monkeypatch.setattr(
        "arodonata.api.services.asset_refresh_service.get_current_lock_context",
        lambda: lock_context,
    )

    service, _mgmt, _domain_service, cache, api_query = _make_service()

    stats = {"total_collected": 0, "errors": [], "aborted": False}
    target_servers_and_domains = {"mgmt1": ["domainA"]}

    events = [event async for event in service._collect_domain_phase(target_servers_and_domains, "auto", stats)]

    assert stats["aborted"] is True
    error_events = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert len(error_events) == 1
    assert error_events[0].domain == "domainA"
    api_query.assert_not_awaited()


@pytest.mark.asyncio
async def test_collect_domain_phase_skips_renewal_when_no_lock_context(monkeypatch):
    monkeypatch.setattr(
        "arodonata.api.services.asset_refresh_service.get_current_lock_context",
        lambda: None,
    )

    api_result = _api_result(objects=[{"uid": "gw-uid-1", "name": "gw1"}])
    service, _mgmt, _domain_service, cache, _api_query = _make_service(api_query_result=api_result)

    fake_asset = SimpleNamespace(asset_id="mgmt1:domainA:gw1")
    monkeypatch.setattr(AssetTransformer, "transform_to_asset", MagicMock(return_value=fake_asset))

    stats = {"total_collected": 0, "errors": [], "aborted": False}
    target_servers_and_domains = {"mgmt1": ["domainA"]}

    events = [event async for event in service._collect_domain_phase(target_servers_and_domains, "auto", stats)]

    assert stats["aborted"] is False
    assert stats["total_collected"] == 1
    assert any(e.event_type == SSEEventType.RESULT for e in events)


@pytest.mark.asyncio
async def test_collect_domain_phase_records_domain_error_without_aborting():
    api_result = _api_result(success=False, message="domain boom", code="E3", objects=None)
    service, _mgmt, _domain_service, cache, _api_query = _make_service(api_query_result=api_result)

    stats = {"total_collected": 0, "errors": [], "aborted": False}
    target_servers_and_domains = {"mgmt1": ["domainA"]}

    events = [event async for event in service._collect_domain_phase(target_servers_and_domains, "auto", stats)]

    assert stats["aborted"] is False
    assert len(stats["errors"]) == 1
    assert "mgmt1:domainA" in stats["errors"][0]
    error_events = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert len(error_events) == 1


@pytest.mark.asyncio
async def test_collect_domain_phase_error_in_one_domain_does_not_corrupt_other_domains(monkeypatch):
    """A failure while collecting one domain must not stop collection of
    other domains under the same or different mgmt servers."""

    async def _api_query_side_effect(mgmt_name, domain, **kwargs):
        if domain == "bad-domain":
            return _api_result(success=False, message="bad domain boom", code="E4", objects=None)
        return _api_result(objects=[{"uid": f"{domain}-uid", "name": f"{domain}-gw"}])

    service, _mgmt, _domain_service, cache, api_query = _make_service(api_query_side_effect=_api_query_side_effect)

    fake_asset = MagicMock()
    monkeypatch.setattr(AssetTransformer, "transform_to_asset", MagicMock(return_value=fake_asset))

    stats = {"total_collected": 0, "errors": [], "aborted": False}
    target_servers_and_domains = {"mgmt1": ["bad-domain", "good-domain"]}

    events = [event async for event in service._collect_domain_phase(target_servers_and_domains, "auto", stats)]

    assert stats["aborted"] is False
    assert stats["total_collected"] == 1
    assert len(stats["errors"]) == 1
    assert "bad-domain" in stats["errors"][0]
    result_events = [e for e in events if e.event_type == SSEEventType.RESULT]
    assert len(result_events) == 1
    assert result_events[0].domain == "good-domain"


@pytest.mark.asyncio
async def test_collect_domain_phase_filters_out_falsy_domain_names():
    api_result = _api_result(objects=[])
    service, _mgmt, _domain_service, cache, api_query = _make_service(api_query_result=api_result)

    stats = {"total_collected": 0, "errors": [], "aborted": False}
    target_servers_and_domains = {"mgmt1": ["", "domainA", None]}

    events = [event async for event in service._collect_domain_phase(target_servers_and_domains, "auto", stats)]

    # api_query should only be invoked once, for the truthy "domainA".
    assert api_query.await_count == 1
    log_events = [e for e in events if e.event_type == SSEEventType.LOG]
    assert any("domainA" in e.data.get("message", "") for e in log_events)


# ---------------------------------------------------------------------------
# _process_relationships_phase / cluster & vsx sub-phases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_relationships_phase_accumulates_cluster_and_vsx_counts():
    cluster_manager_instance = MagicMock()
    cluster_manager_instance.build_cluster_member_mappings = AsyncMock(return_value={"member1": "cluster1"})
    cluster_manager_instance.update_cluster_member_parent_asset_ids = AsyncMock(return_value=2)

    vsx_manager_instance = MagicMock()
    vsx_manager_instance.build_cross_domain_vsx_vs_mapping = AsyncMock(return_value={"vs1": "vsx1"})
    vsx_manager_instance.update_vs_parent_asset_ids = AsyncMock(return_value=3)

    cache = AsyncMock()
    cache.get_domains.return_value = []

    service, _mgmt, _domain_service, _cache, _api_query = _make_service(cache=cache)
    # Patch the manager classes used internally to return our instances
    # (the constructor only captures .__class__ from passed instances, so
    # direct patching is the only injection seam).
    service._cluster_manager_class = MagicMock(return_value=cluster_manager_instance)
    service._vsx_manager_class = MagicMock(return_value=vsx_manager_instance)

    stats = {"cluster_relationships_count": 0, "vsx_relationships_count": 0}
    target_servers_and_domains = {"mgmt1": ["domainA"]}

    events = [
        event
        async for event in service._process_relationships_phase(
            target_servers_and_domains, client_wrapper=MagicMock(), stats=stats
        )
    ]

    assert stats["cluster_relationships_count"] == 2
    assert stats["vsx_relationships_count"] == 3
    cluster_manager_instance.update_cluster_member_parent_asset_ids.assert_awaited_once()
    vsx_manager_instance.update_vs_parent_asset_ids.assert_awaited_once()
    assert any(e.data.get("phase") == "cluster_processing" for e in events if e.data)
    assert any(e.data.get("phase") == "vsx_processing" for e in events if e.data)


@pytest.mark.asyncio
async def test_process_cluster_relationships_skips_update_when_no_mappings():
    cluster_manager_instance = MagicMock()
    cluster_manager_instance.build_cluster_member_mappings = AsyncMock(return_value={})
    cluster_manager_instance.update_cluster_member_parent_asset_ids = AsyncMock()

    service, _mgmt, _domain_service, _cache, _api_query = _make_service()
    service._cluster_manager_class = MagicMock(return_value=cluster_manager_instance)

    events = [event async for event in service._process_cluster_relationships({"mgmt1": ["domainA"]}, MagicMock())]

    cluster_manager_instance.update_cluster_member_parent_asset_ids.assert_not_awaited()
    assert not any(e.data.get("relationships_updated") for e in events if e.data)


@pytest.mark.asyncio
async def test_process_cluster_relationships_error_for_one_mgmt_does_not_stop_others():
    good_manager = MagicMock()
    good_manager.build_cluster_member_mappings = AsyncMock(return_value={"m1": "c1"})
    good_manager.update_cluster_member_parent_asset_ids = AsyncMock(return_value=1)

    def _cluster_manager_class(client):
        return good_manager

    service, _mgmt, _domain_service, _cache, _api_query = _make_service()

    call_count = {"n": 0}

    def _class_side_effect(client):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("cluster manager init failed")
        return good_manager

    service._cluster_manager_class = _class_side_effect

    events = [
        event
        async for event in service._process_cluster_relationships(
            {"bad-mgmt": ["domainA"], "good-mgmt": ["domainA"]}, MagicMock()
        )
    ]

    error_events = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert len(error_events) == 1
    assert error_events[0].mgmt_name == "bad-mgmt"
    log_events = [e for e in events if e.event_type == SSEEventType.LOG]
    assert any(e.data.get("relationships_updated") == 1 for e in log_events)


@pytest.mark.asyncio
async def test_process_vsx_relationships_uses_all_cached_domains_not_filtered_ones():
    vsx_manager_instance = MagicMock()
    vsx_manager_instance.build_cross_domain_vsx_vs_mapping = AsyncMock(return_value={"vs1": "vsx1"})
    vsx_manager_instance.update_vs_parent_asset_ids = AsyncMock(return_value=5)

    cache = AsyncMock()
    cache.get_domains.return_value = [
        SimpleNamespace(domain_name="domainA"),
        SimpleNamespace(domain_name="domainB"),
        SimpleNamespace(domain_name=None),
    ]

    service, _mgmt, _domain_service, _cache, _api_query = _make_service(cache=cache)
    service._vsx_manager_class = MagicMock(return_value=vsx_manager_instance)

    events = [event async for event in service._process_vsx_relationships({"mgmt1": ["domainA"]}, MagicMock())]

    vsx_manager_instance.build_cross_domain_vsx_vs_mapping.assert_awaited_once_with(
        mgmt_name="mgmt1", domains=["domainA", "domainB", ""]
    )
    assert any(e.data.get("relationships_updated") == 5 for e in events if e.data)


@pytest.mark.asyncio
async def test_process_vsx_relationships_error_does_not_stop_other_servers():
    good_vsx_manager = MagicMock()
    good_vsx_manager.build_cross_domain_vsx_vs_mapping = AsyncMock(return_value={"vs1": "vsx1"})
    good_vsx_manager.update_vs_parent_asset_ids = AsyncMock(return_value=1)

    cache = AsyncMock()

    async def _get_domains(mgmt_name):
        if mgmt_name == "bad-mgmt":
            raise RuntimeError("cache failure")
        return []

    cache.get_domains = AsyncMock(side_effect=_get_domains)

    service, _mgmt, _domain_service, _cache, _api_query = _make_service(cache=cache)
    service._vsx_manager_class = MagicMock(return_value=good_vsx_manager)

    events = [
        event
        async for event in service._process_vsx_relationships(
            {"bad-mgmt": ["domainA"], "good-mgmt": ["domainA"]}, MagicMock()
        )
    ]

    error_events = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert len(error_events) == 1
    assert error_events[0].mgmt_name == "bad-mgmt"
    log_events = [e for e in events if e.event_type == SSEEventType.LOG]
    assert any(e.data.get("relationships_updated") == 1 for e in log_events)


# ---------------------------------------------------------------------------
# _generate_summary
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_summary_yields_complete_event_with_stats():
    service, _mgmt, _domain_service, _cache, _api_query = _make_service()

    events = [
        event
        async for event in service._generate_summary(
            {"mgmt1": ["domainA", "domainB"]},
            cluster_relationships_count=2,
            vsx_relationships_count=1,
            total_collected=10,
            errors=["some error"],
        )
    ]

    assert len(events) == 1
    assert events[0].event_type == SSEEventType.COMPLETE
    assert events[0].data == {
        "total_results": 10,
        "servers_processed": 1,
        "domains_processed": 2,
        "cluster_relationships_established": 2,
        "vsx_relationships_established": 1,
        "errors": ["some error"],
    }


# ---------------------------------------------------------------------------
# build_refresh_assets_cache: end-to-end orchestration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_build_refresh_assets_cache_single_domain_no_lock_collision(monkeypatch, mock_lock_manager):
    """build_refresh_assets_cache scoped to one mgmt_name/domain must not
    re-acquire the lock via refresh_domain_assets in its per-domain loop."""
    api_result = _api_result(objects=[{"uid": "gw-uid-1", "name": "gw1"}])
    service, mgmt_client, _domain_service, cache, _api_query = _make_service(api_query_result=api_result)

    fake_asset = SimpleNamespace(asset_id="mgmt1:domainA:gw1")
    monkeypatch.setattr(AssetTransformer, "transform_to_asset", MagicMock(return_value=fake_asset))

    events = [
        event
        async for event in service.build_refresh_assets_cache(mgmt_names="mgmt1", domains="domainA", cache_mode="auto")
    ]

    result_events = [e for e in events if e.event_type == SSEEventType.RESULT and e.data.get("result_type") == "assets"]
    assert len(result_events) == 1
    assert result_events[0].data["count"] == 1
    assert mock_lock_manager.acquire_lock.call_count == 1


@pytest.mark.asyncio
async def test_build_refresh_assets_cache_deletes_before_recollecting():
    api_result = _api_result(objects=[])
    cache = AsyncMock()
    cache.delete_assets.return_value = 0
    cache.get_domains.return_value = []
    service, _mgmt, _domain_service, _cache, _api_query = _make_service(api_query_result=api_result, cache=cache)

    async for _event in service.build_refresh_assets_cache(mgmt_names="mgmt1", domains="domainA"):
        pass

    cache.delete_assets.assert_awaited_once()
    call_kwargs = cache.delete_assets.call_args.kwargs
    assert call_kwargs["mgmt_names"] == ["mgmt1"]
    assert call_kwargs["domain_names"] == ["domainA"]


@pytest.mark.asyncio
async def test_build_refresh_assets_cache_aborts_on_lock_loss(mock_lock_manager):
    """If the distributed lock is lost mid-collection, the per-domain phase
    yields an ERROR and stops the whole generator before relationship
    processing or the summary event."""
    service, _mgmt, _domain_service, cache, _api_query = _make_service()

    mock_lock_manager.acquire_lock.return_value.renew_if_needed = AsyncMock(side_effect=RuntimeError("lock expired"))

    events = [event async for event in service.build_refresh_assets_cache(mgmt_names="mgmt1", domains="domainA")]

    error_events = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert any("Lock lost during operation" in e.data.get("error_message", "") for e in error_events)
    assert not any(e.event_type == SSEEventType.COMPLETE for e in events)
    assert not any(e.data.get("phase") in ("cluster_processing", "vsx_processing") for e in events if e.data)


@pytest.mark.asyncio
async def test_build_refresh_assets_cache_continues_after_one_mgmt_name_domain_population_fails(
    monkeypatch,
):
    domain_service = AsyncMock()

    async def _populate_domain_cache(mgmt_name, cache_mode="auto"):
        if mgmt_name == "bad-mgmt":
            raise RuntimeError("connection refused")
        return ["domainA"]

    domain_service.populate_domain_cache = AsyncMock(side_effect=_populate_domain_cache)
    domain_service.get_domain_uid.return_value = "domain-uid-1"

    api_result = _api_result(objects=[{"uid": "gw-uid-1", "name": "gw1"}])
    service, mgmt_client, _domain_service, cache, _api_query = _make_service(
        mgmt_names=["bad-mgmt", "good-mgmt"],
        domain_service=domain_service,
        api_query_result=api_result,
    )

    fake_asset = SimpleNamespace(asset_id="good-mgmt:domainA:gw1")
    monkeypatch.setattr(AssetTransformer, "transform_to_asset", MagicMock(return_value=fake_asset))

    events = [event async for event in service.build_refresh_assets_cache(mgmt_names=["bad-mgmt", "good-mgmt"])]

    error_events = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert any(
        e.mgmt_name == "bad-mgmt" and "Failed to populate domains" in e.data.get("error_message", "")
        for e in error_events
    )
    result_events = [e for e in events if e.event_type == SSEEventType.RESULT and e.data.get("result_type") == "assets"]
    assert len(result_events) == 1
    assert result_events[0].mgmt_name == "good-mgmt"
    complete_events = [e for e in events if e.event_type == SSEEventType.COMPLETE]
    assert len(complete_events) == 1
    assert complete_events[0].data["servers_processed"] == 1


@pytest.mark.asyncio
async def test_build_refresh_assets_cache_stops_when_delete_fails():
    cache = AsyncMock()
    cache.delete_assets.side_effect = RuntimeError("db down")
    service, _mgmt, _domain_service, _cache, api_query = _make_service(cache=cache)

    events = [event async for event in service.build_refresh_assets_cache(mgmt_names="mgmt1", domains="domainA")]

    error_events = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert len(error_events) == 1
    assert "db down" in error_events[0].data["error_message"]
    # Should stop immediately after the delete failure - no collection attempted.
    api_query.assert_not_awaited()
    assert not any(e.event_type == SSEEventType.COMPLETE for e in events)


@pytest.mark.asyncio
async def test_build_local_fields_snapshot_only_includes_assets_with_a_value_set():
    with_fields = SimpleNamespace(asset_id="a1", path="/ssot/a1", ip_address="1.2.3.4", ssh_ip="1.2.3.4")
    blank = SimpleNamespace(asset_id="a2", path="", ip_address="", ssh_ip="")
    partial = SimpleNamespace(asset_id="a3", path="", ip_address="5.6.7.8", ssh_ip="")

    snapshot = AssetRefreshService._build_local_fields_snapshot([with_fields, blank, partial])

    assert snapshot == {
        "a1": {"path": "/ssot/a1", "ip_address": "1.2.3.4", "ssh_ip": "1.2.3.4"},
        "a3": {"path": "", "ip_address": "5.6.7.8", "ssh_ip": ""},
    }


@pytest.mark.asyncio
async def test_build_refresh_assets_cache_snapshots_before_delete_and_restores_after():
    """The raw delete+recollect in build_refresh_assets_cache has no notion of
    path/ip_address/ssh_ip, which are owned by the consuming app's own
    disk-sync - it must snapshot them before the delete and restore
    whatever comes back blank once collection finishes."""
    cache = AsyncMock()
    cache.delete_assets.return_value = 0
    cache.get_domains.return_value = []
    cache.get_assets.return_value = [
        SimpleNamespace(asset_id="mgmt1:domainA:gw1", path="/ssot/mgmt1/gw1", ip_address="1.2.3.4", ssh_ip="1.2.3.4")
    ]
    service, _mgmt, _domain_service, _cache, _api_query = _make_service(
        api_query_result=_api_result(objects=[]), cache=cache
    )

    async for _event in service.build_refresh_assets_cache(mgmt_names="mgmt1", domains="domainA"):
        pass

    cache.get_assets.assert_awaited_once_with(mgmt_names=["mgmt1"], domain_names=["domainA"])
    cache.restore_asset_local_fields.assert_awaited_once_with(
        {"mgmt1:domainA:gw1": {"path": "/ssot/mgmt1/gw1", "ip_address": "1.2.3.4", "ssh_ip": "1.2.3.4"}}
    )
    # Snapshot must be taken before the assets are deleted, not after.
    call_names = [c[0] for c in cache.mock_calls]
    assert call_names.index("get_assets") < call_names.index("delete_assets")


@pytest.mark.asyncio
async def test_build_refresh_assets_cache_restores_local_fields_even_when_delete_fails():
    cache = AsyncMock()
    cache.delete_assets.side_effect = RuntimeError("db down")
    cache.get_assets.return_value = [
        SimpleNamespace(asset_id="mgmt1:domainA:gw1", path="/ssot/mgmt1/gw1", ip_address="", ssh_ip="")
    ]
    service, _mgmt, _domain_service, _cache, _api_query = _make_service(cache=cache)

    async for _event in service.build_refresh_assets_cache(mgmt_names="mgmt1", domains="domainA"):
        pass

    cache.restore_asset_local_fields.assert_awaited_once_with(
        {"mgmt1:domainA:gw1": {"path": "/ssot/mgmt1/gw1", "ip_address": "", "ssh_ip": ""}}
    )


@pytest.mark.asyncio
async def test_build_refresh_assets_cache_restores_local_fields_on_lock_loss(mock_lock_manager):
    cache = AsyncMock()
    cache.get_assets.return_value = []
    service, _mgmt, _domain_service, _cache, _api_query = _make_service(cache=cache)

    mock_lock_manager.acquire_lock.return_value.renew_if_needed = AsyncMock(side_effect=RuntimeError("lock expired"))

    async for _event in service.build_refresh_assets_cache(mgmt_names="mgmt1", domains="domainA"):
        pass

    cache.restore_asset_local_fields.assert_awaited_once_with({})


@pytest.mark.asyncio
async def test_build_refresh_assets_cache_emits_progress_events_for_full_run(monkeypatch):
    """End-to-end smoke test: verify SSE progress events are emitted across
    the full pipeline (prepare -> mds -> domain collection -> relationships
    -> summary) with expected phases and a final COMPLETE event."""
    cluster_manager_instance = MagicMock()
    cluster_manager_instance.build_cluster_member_mappings = AsyncMock(return_value={})
    vsx_manager_instance = MagicMock()
    vsx_manager_instance.build_cross_domain_vsx_vs_mapping = AsyncMock(return_value={})

    cache = AsyncMock()
    cache.delete_assets.return_value = 0
    cache.get_domains.return_value = []

    api_result = _api_result(objects=[{"uid": "gw-uid-1", "name": "gw1"}])
    service, _mgmt, _domain_service, _cache, _api_query = _make_service(api_query_result=api_result, cache=cache)
    service._cluster_manager_class = MagicMock(return_value=cluster_manager_instance)
    service._vsx_manager_class = MagicMock(return_value=vsx_manager_instance)

    fake_asset = SimpleNamespace(asset_id="mgmt1:domainA:gw1")
    monkeypatch.setattr(AssetTransformer, "transform_to_asset", MagicMock(return_value=fake_asset))

    events = [event async for event in service.build_refresh_assets_cache(mgmt_names="mgmt1", domains="domainA")]

    phases = [e.data.get("phase") for e in events if e.data.get("phase")]
    assert "preparation" in phases
    assert "collecting" in phases
    assert "cluster_processing" in phases
    assert "vsx_processing" in phases
    complete_events = [e for e in events if e.event_type == SSEEventType.COMPLETE]
    assert len(complete_events) == 1
    assert complete_events[0].data["total_results"] == 1
