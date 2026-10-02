"""RulebaseRefreshCoordinator: named domains only, TTL memo marked after every outcome, session-aware via the service."""

from __future__ import annotations

from datetime import datetime, timedelta

from arodonata.core.cache_mode import CacheMode
from arodonata.core.cache_policy import CachePolicy, RefreshScope
from arodonata.core.rulebase_refresh_coordinator import RulebaseRefreshCoordinator
from arodonata.rulebase.model import DomainRefreshResult


class Clock:
    def __init__(self):
        self.t = datetime(2026, 10, 1, 8, 0)

    def now(self):
        return self.t


class FakeService:
    def __init__(self, stale=True, status="ok"):
        self.stale, self.status = stale, status
        self.checked: list[tuple[str, str]] = []
        self.refreshed: list[tuple[str, str, bool]] = []
        self.error: Exception | None = None

    async def is_rulebase_stale(self, mgmt, domain):
        self.checked.append((mgmt, domain))
        if self.error:
            raise self.error
        return self.stale

    async def refresh_domain(self, mgmt, domain, *, force=False):
        self.refreshed.append((mgmt, domain, force))
        yield {"message": "start"}
        yield {
            "status": "domain_failed" if self.status == "failed" else "domain_refreshed",
            "result": DomainRefreshResult(mgmt, domain, self.status, None, {}, None, ()),
        }


class Api:
    def get_mgmt_names(self):
        return ["m1", "m2"]


SMART = CachePolicy(mode=CacheMode.SMART, ttl=300)


def make(service=None, clock=None):
    service = service or FakeService()
    return RulebaseRefreshCoordinator(refresh_service=service, api=Api(), clock=clock or Clock()), service


async def test_smart_stale_named_domain_is_refreshed():
    coordinator, service = make()
    outcome = await coordinator.ensure(RefreshScope(mgmt_names=["m1"], domain_names=["Domain4"]), SMART)
    assert service.refreshed == [("m1", "Domain4", False)] and outcome.refreshed_domains == [("m1", "Domain4")]


async def test_smart_fresh_domain_is_not_refreshed():
    coordinator, service = make(FakeService(stale=False))
    await coordinator.ensure(RefreshScope(mgmt_names=["m1"], domain_names=["Domain4"]), SMART)
    assert service.checked == [("m1", "Domain4")] and service.refreshed == []


async def test_broad_smart_read_does_not_refresh_all_domains():
    coordinator, service = make()
    outcome = await coordinator.ensure(RefreshScope(mgmt_names=["m1"], domain_names=None), SMART)
    assert service.checked == [] and service.refreshed == [] and outcome.refreshed_domains == []


async def test_system_domain_fallback_not_refreshed():
    coordinator, service = make()
    await coordinator.ensure(RefreshScope(mgmt_names=["m1"], domain_names=[""]), SMART)
    assert service.checked == [] and service.refreshed == []


async def test_global_refreshed_only_when_named():
    coordinator, service = make()
    await coordinator.ensure(RefreshScope(mgmt_names=["m1"], domain_names=["Domain4"]), SMART)
    await coordinator.ensure(RefreshScope(mgmt_names=["m1"], domain_names=["Global"]), SMART)
    assert [d for _, d, _ in service.refreshed] == ["Domain4", "Global"]


async def test_failed_refresh_marks_memo_no_retry_within_ttl():
    clock = Clock()
    coordinator, service = make(FakeService(status="failed"), clock)
    scope = RefreshScope(mgmt_names=["m1"], domain_names=["Domain4"])
    outcome = await coordinator.ensure(scope, SMART)
    assert outcome.failed_domains == [("m1", "Domain4")]
    await coordinator.ensure(scope, SMART)
    assert len(service.refreshed) == 1
    clock.t += timedelta(seconds=301)
    await coordinator.ensure(scope, SMART)
    assert len(service.refreshed) == 2


async def test_force_ignores_memo():
    coordinator, service = make(FakeService(stale=False))
    scope = RefreshScope(mgmt_names=["m1"], domain_names=["Domain4"])
    await coordinator.ensure(scope, SMART)
    await coordinator.ensure(scope, CachePolicy(mode=CacheMode.FORCE, ttl=300))
    assert service.refreshed == [("m1", "Domain4", True)] and service.checked == [("m1", "Domain4")]


async def test_cache_mode_does_nothing():
    coordinator, service = make()
    outcome = await coordinator.ensure(
        RefreshScope(mgmt_names=["m1"], domain_names=["Domain4"]), CachePolicy(mode=CacheMode.CACHE)
    )
    assert outcome.skipped_reason == "cache-mode" and service.checked == []


async def test_coordinator_without_mgmt_uses_first_configured_server():
    """No mgmt given means a single-server application: only the first configured server is refreshed."""
    coordinator, service = make()
    await coordinator.ensure(RefreshScope(mgmt_names=None, domain_names=["Domain4"]), SMART)
    assert [(m, d) for m, d, _ in service.refreshed] == [("m1", "Domain4")]


async def test_coordinator_explicit_mgmts_are_all_refreshed():
    coordinator, service = make()
    await coordinator.ensure(RefreshScope(mgmt_names=["m1", "m2"], domain_names=["Domain4"]), SMART)
    assert [(m, d) for m, d, _ in service.refreshed] == [("m1", "Domain4"), ("m2", "Domain4")]


async def test_invalidate_drops_memo():
    coordinator, service = make(FakeService(stale=False))
    scope = RefreshScope(mgmt_names=["m1"], domain_names=["Domain4"])
    await coordinator.ensure(scope, SMART)
    coordinator.invalidate("m1", "Domain4")
    await coordinator.ensure(scope, SMART)
    assert service.checked == [("m1", "Domain4")] * 2


async def test_staleness_exception_is_failed_domain():
    service = FakeService()
    service.error = RuntimeError("db down")
    coordinator, _ = make(service)
    outcome = await coordinator.ensure(RefreshScope(mgmt_names=["m1"], domain_names=["Domain4"]), SMART)
    assert outcome.failed_domains == [("m1", "Domain4")] and service.refreshed == []
