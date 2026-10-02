"""get_domains refreshes only the domain list (show-domains), never every domain's objects; on first use it warms an
empty object cache in the background instead."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from arodonata.config import ArodonataSettings
from tests.unit.api.client_test_helpers import make_client

CACHED = [SimpleNamespace(domain_name="Domain4")]


def domain_client(*, warm: bool = False, cached_rows=CACHED, objects_last_update=None, mgmt_names=("m1", "m2")):
    client = make_client(settings=ArodonataSettings(warm_object_cache_on_first_use=warm))
    client.get_mgmt_names = lambda: list(mgmt_names)  # type: ignore[method-assign]
    client._orchestration.get_domains = AsyncMock(return_value=["domain"])  # type: ignore[method-assign]
    client._domain_service.populate_domain_cache = AsyncMock(return_value=["Domain4"])  # type: ignore[method-assign]
    client._refresh_coordinator.ensure = AsyncMock()  # type: ignore[method-assign]
    client._cache.get_domains = AsyncMock(return_value=list(cached_rows))
    client._cache.get_objects_last_update = AsyncMock(return_value=objects_last_update)
    return client


async def test_get_domains_refreshes_only_the_domain_list_not_objects():
    client = domain_client(cached_rows=[])
    assert await client.get_domains(mgmt_names=["m1"]) == ["domain"]
    client._domain_service.populate_domain_cache.assert_awaited_once()
    assert client._domain_service.populate_domain_cache.await_args.args[0] == "m1"
    client._refresh_coordinator.ensure.assert_not_awaited()


async def test_get_domains_cache_mode_reads_only():
    client = domain_client(cached_rows=[])
    await client.get_domains(mgmt_names=["m1"], cache_mode="cache")
    client._domain_service.populate_domain_cache.assert_not_awaited()
    client._refresh_coordinator.ensure.assert_not_awaited()


async def test_get_domains_smart_refreshes_list_once_per_ttl():
    client = domain_client()
    await client.get_domains(mgmt_names=["m1"])
    await client.get_domains(mgmt_names=["m1"])
    assert client._domain_service.populate_domain_cache.await_count == 1


async def test_get_domains_smart_refreshes_an_empty_domain_table_again():
    client = domain_client(cached_rows=[])
    await client.get_domains(mgmt_names=["m1"])
    await client.get_domains(mgmt_names=["m1"])
    assert client._domain_service.populate_domain_cache.await_count == 2


async def test_get_domains_force_refreshes_list_every_time():
    client = domain_client()
    await client.get_domains(mgmt_names=["m1"], cache_mode="force")
    await client.get_domains(mgmt_names=["m1"], cache_mode="force")
    assert client._domain_service.populate_domain_cache.await_count == 2
    client._refresh_coordinator.ensure.assert_not_awaited()


async def test_get_domains_without_mgmt_refreshes_first_server_only():
    client = domain_client(cached_rows=[])
    await client.get_domains()
    assert [c.args[0] for c in client._domain_service.populate_domain_cache.await_args_list] == ["m1"]
    client._orchestration.get_domains.assert_awaited_once_with(mgmt_names=None, include_global=False)


async def test_get_domains_domain_list_failure_still_reads_the_cache():
    client = domain_client()
    client._domain_service.populate_domain_cache = AsyncMock(side_effect=RuntimeError("show-domains failed"))
    assert await client.get_domains(mgmt_names=["m1"]) == ["domain"]


async def test_first_get_domains_warms_empty_object_cache_in_background():
    client = domain_client(warm=True, objects_last_update=None)
    release = asyncio.Event()

    async def slow_ensure(scope, policy):
        await release.wait()

    client._refresh_coordinator.ensure = AsyncMock(side_effect=slow_ensure)
    assert await client.get_domains(mgmt_names=["m1"]) == ["domain"]  # returns before the warm-up finishes
    await asyncio.sleep(0)
    client._refresh_coordinator.ensure.assert_awaited_once()
    scope = client._refresh_coordinator.ensure.await_args.args[0]
    assert scope.mgmt_names == ["m1"] and not scope.domain_names
    await client.get_domains(mgmt_names=["m1"])  # a second call does not start another warm-up
    release.set()
    await asyncio.gather(*client._background_tasks)
    assert client._refresh_coordinator.ensure.await_count == 1


async def test_no_warm_up_when_object_cache_not_empty():
    client = domain_client(warm=True, objects_last_update=datetime(2026, 10, 2, tzinfo=UTC))
    await client.get_domains(mgmt_names=["m1"])
    await asyncio.sleep(0)
    client._refresh_coordinator.ensure.assert_not_awaited()


async def test_warm_up_disabled_by_setting():
    client = domain_client(warm=False, objects_last_update=None)
    await client.get_domains(mgmt_names=["m1"])
    await asyncio.sleep(0)
    client._refresh_coordinator.ensure.assert_not_awaited()


async def test_cache_mode_never_warms():
    client = domain_client(warm=True, objects_last_update=None)
    await client.get_domains(mgmt_names=["m1"], cache_mode="cache")
    await asyncio.sleep(0)
    client._refresh_coordinator.ensure.assert_not_awaited()


async def test_warm_up_failure_is_logged_not_raised(caplog):
    client = domain_client(warm=True, objects_last_update=None)
    client._refresh_coordinator.ensure = AsyncMock(side_effect=RuntimeError("login refused"))
    await client.get_domains(mgmt_names=["m1"])
    [task] = list(client._background_tasks)
    await asyncio.gather(task, return_exceptions=True)
    assert task.exception() is None
    assert any("warm-up of m1 failed: RuntimeError" in r.getMessage() for r in caplog.records)


async def test_warm_up_logs_the_refresh_outcome(caplog):
    from arodonata.core.cache_mode import CacheMode
    from arodonata.core.cache_policy import RefreshOutcome

    client = domain_client(warm=True, objects_last_update=None)
    outcome = RefreshOutcome(
        mode_used=CacheMode.SMART, refreshed_domains=[("m1", "a"), ("m1", "b")], failed_domains=[("m1", "c")]
    )
    client._refresh_coordinator.ensure = AsyncMock(return_value=outcome)
    with caplog.at_level("INFO"):
        await client.get_domains(mgmt_names=["m1"])
        await asyncio.gather(*list(client._background_tasks))
    assert any("warm-up of m1 finished: 2 domains refreshed, 1 failed" in r.getMessage() for r in caplog.records)


async def test_warm_up_runs_smart_even_when_the_client_default_is_cache():
    from arodonata.core.cache_mode import CacheMode

    client = domain_client(warm=True, objects_last_update=None)
    client._refresh_coordinator.default_policy = client._refresh_coordinator.default_policy.__class__(
        mode=CacheMode.CACHE, ttl=300
    )
    await client.get_domains(mgmt_names=["m1"], cache_mode="smart")
    await asyncio.gather(*list(client._background_tasks))
    policy = client._refresh_coordinator.ensure.await_args.args[1]
    assert policy.mode == CacheMode.SMART


async def test_concurrent_first_calls_start_one_warm_up():
    client = domain_client(warm=True, objects_last_update=None)

    async def slow_probe(**_):
        await asyncio.sleep(0.01)
        return None

    client._cache.get_objects_last_update = AsyncMock(side_effect=slow_probe)
    await asyncio.gather(client.get_domains(mgmt_names=["m1"]), client.get_domains(mgmt_names=["m1"]))
    await asyncio.gather(*list(client._background_tasks))
    assert client._refresh_coordinator.ensure.await_count == 1


async def test_no_warm_up_while_the_domain_table_is_empty():
    client = domain_client(warm=True, objects_last_update=None, cached_rows=[])
    client._domain_service.populate_domain_cache = AsyncMock(side_effect=RuntimeError("show-domains failed"))
    await client.get_domains(mgmt_names=["m1"])
    await asyncio.sleep(0)
    client._refresh_coordinator.ensure.assert_not_awaited()
    assert "m1" not in client._object_warm_up_started  # a later call can still warm up


async def test_failed_list_refresh_with_cached_list_backs_off_until_the_ttl():
    client = domain_client()
    client._domain_service.populate_domain_cache = AsyncMock(side_effect=ConnectionError("down"))
    await client.get_domains(mgmt_names=["m1"])
    await client.get_domains(mgmt_names=["m1"])
    assert client._domain_service.populate_domain_cache.await_count == 1


async def test_failed_list_refresh_of_an_empty_table_is_retried():
    client = domain_client(cached_rows=[])
    client._domain_service.populate_domain_cache = AsyncMock(side_effect=ConnectionError("down"))
    await client.get_domains(mgmt_names=["m1"])
    await client.get_domains(mgmt_names=["m1"])
    assert client._domain_service.populate_domain_cache.await_count == 2


async def test_domain_list_ttl_expiry_triggers_a_refresh():
    from arodonata.core.domain_list_refresh import DomainListRefreshTracker

    client = domain_client()
    client._domain_list_refresh = DomainListRefreshTracker(ttl_seconds=0)
    await client.get_domains(mgmt_names=["m1"])
    await client.get_domains(mgmt_names=["m1"])
    assert client._domain_service.populate_domain_cache.await_count == 2


async def test_without_mgmt_only_the_first_server_is_warmed():
    client = domain_client(warm=True, objects_last_update=None)
    await client.get_domains()
    await asyncio.gather(*list(client._background_tasks))
    assert [c.args[0].mgmt_names for c in client._refresh_coordinator.ensure.await_args_list] == [["m1"]]


async def test_close_cancels_a_running_warm_up_immediately():
    client = domain_client(warm=True, objects_last_update=None)

    async def endless(scope, policy):
        await asyncio.sleep(3600)

    client._refresh_coordinator.ensure = AsyncMock(side_effect=endless)
    client._close_grace_seconds = 30  # the warm-up must not get the grace: close() cancels it at once
    await client.get_domains(mgmt_names=["m1"])
    [task] = list(client._background_tasks)
    await asyncio.sleep(0)
    await asyncio.wait_for(client.close(), timeout=2)
    assert task.cancelled()


def test_warm_up_setting_defaults_on_and_reads_env(monkeypatch):
    monkeypatch.delenv("ARODONATA_WARM_OBJECT_CACHE_ON_FIRST_USE", raising=False)
    assert ArodonataSettings(_env_file=None).warm_object_cache_on_first_use is True
    monkeypatch.setenv("ARODONATA_WARM_OBJECT_CACHE_ON_FIRST_USE", "false")
    assert ArodonataSettings().warm_object_cache_on_first_use is False


@pytest.mark.parametrize("mode", ["smart", "smart-fast"])
async def test_get_domains_smart_modes_refresh_the_list(mode):
    client = domain_client(cached_rows=[])
    await client.get_domains(mgmt_names=["m1"], cache_mode=mode)
    client._domain_service.populate_domain_cache.assert_awaited_once()
