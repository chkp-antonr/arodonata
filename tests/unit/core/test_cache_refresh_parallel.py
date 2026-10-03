"""CacheRefreshCoordinator.ensure refreshes a scope's domains concurrently, bounded per MDS member."""

from __future__ import annotations

import asyncio
from datetime import datetime
from unittest.mock import patch

import pytest

from arodonata.core.cache_mode import CacheMode
from arodonata.core.cache_policy import CachePolicy, RefreshScope
from arodonata.core.cache_refresh_coordinator import CacheRefreshCoordinator
from tests.unit.core.test_cache_refresh_coordinator import FakeClock, FakeObjectService, StatefulCache

MEMBER = {"d1": "A", "d2": "A", "d3": "A", "d4": "A", "e1": "B", "e2": "B"}
SMART = CachePolicy(CacheMode.SMART, 300)


class GatedObjectService(FakeObjectService):
    """Full reloads block until `release` is set; tracks in-flight reloads per member.

    Domains named in `gated` additionally wait for their own `gates[domain]` event after `release`, so a test
    can finish domains in an order of its choosing.
    """

    def __init__(self, fail=(), raise_on=(), gated=()) -> None:
        super().__init__(stale=True)
        self.fail, self.raise_on = set(fail), set(raise_on)
        self.gates = {domain: asyncio.Event() for domain in gated}
        self.in_flight: dict[str, int] = {}
        self.peak: dict[str, int] = {}
        self.completed: list[str] = []
        self.release = asyncio.Event()

    async def refresh_objects(self, mgmt_names=None, domain_names=None, mode="force", *, refresh_domain_list=True):
        domain = domain_names[0]
        self.full_reloads.append((mgmt_names[0], domain))
        member = MEMBER[domain]
        self.in_flight[member] = self.in_flight.get(member, 0) + 1
        self.peak[member] = max(self.peak.get(member, 0), self.in_flight[member])
        try:
            await self.release.wait()
            if domain in self.gates:
                await self.gates[domain].wait()
            if domain in self.raise_on:
                raise RuntimeError(f"boom {domain}")
            yield {"status": "domain_failed"} if domain in self.fail else {"status": "domain_complete"}
            self.completed.append(domain)
        finally:
            self.in_flight[member] -= 1


async def _member_of(mgmt: str, domain: str) -> str:
    return MEMBER[domain]


def _coord(obj, *, concurrency: int, member_of=_member_of) -> CacheRefreshCoordinator:
    return CacheRefreshCoordinator(
        cache=StatefulCache(),  # empty: every domain needs a full reload
        api=None,
        object_service=obj,
        clock=FakeClock(datetime(2026, 10, 3)),
        member_of=member_of,
        domain_concurrency=concurrency,
    )


def _scope(*domains: str) -> RefreshScope:
    return RefreshScope(["m1"], list(domains))


async def test_a_members_domains_refresh_concurrently_up_to_the_bound():
    obj = GatedObjectService()
    task = asyncio.create_task(_coord(obj, concurrency=2).ensure(_scope("d1", "d2", "d3", "d4"), SMART))
    await asyncio.sleep(0.05)
    assert obj.in_flight["A"] == 2

    obj.release.set()
    outcome = await task

    assert obj.peak["A"] == 2
    assert outcome.refreshed_domains == [("m1", "d1"), ("m1", "d2"), ("m1", "d3"), ("m1", "d4")]


async def test_members_refresh_independently():
    obj = GatedObjectService()
    task = asyncio.create_task(_coord(obj, concurrency=1).ensure(_scope("d1", "d2", "e1", "e2"), SMART))
    await asyncio.sleep(0.05)
    assert (obj.in_flight["A"], obj.in_flight["B"]) == (1, 1)

    obj.release.set()
    await task
    assert (obj.peak["A"], obj.peak["B"]) == (1, 1)


async def test_a_read_of_a_domain_being_refreshed_waits_for_it_and_starts_no_second_refresh():
    obj = GatedObjectService()
    coord = _coord(obj, concurrency=3)
    warm_up = asyncio.create_task(coord.ensure(_scope("d1", "d2"), SMART))
    await asyncio.sleep(0.05)
    read = asyncio.create_task(coord.ensure(_scope("d1"), SMART))
    await asyncio.sleep(0.05)
    assert not read.done()  # waiting on d1's lock

    obj.release.set()
    await asyncio.gather(warm_up, read)
    assert obj.full_reloads.count(("m1", "d1")) == 1


async def test_every_refreshed_and_failed_domain_is_recorded_in_scope_order():
    obj = GatedObjectService(fail={"d2", "e1"})
    obj.release.set()
    outcome = await _coord(obj, concurrency=3).ensure(_scope("d1", "d2", "e1", "d3", "e2"), SMART)

    assert outcome.refreshed_domains == [("m1", "d1"), ("m1", "d3"), ("m1", "e2")]
    assert outcome.failed_domains == [("m1", "d2"), ("m1", "e1")]


async def test_outcome_lists_keep_scope_order_when_a_later_domain_finishes_first():
    obj = GatedObjectService(gated={"d1", "e1"})
    obj.release.set()
    task = asyncio.create_task(_coord(obj, concurrency=3).ensure(_scope("d1", "e1"), SMART))
    await asyncio.sleep(0.05)
    obj.gates["e1"].set()
    await asyncio.sleep(0.05)
    assert obj.completed == ["e1"]  # e1 (second in scope) is done before d1 starts to finish
    obj.gates["d1"].set()
    outcome = await task

    assert obj.completed == ["e1", "d1"]
    assert outcome.refreshed_domains == [("m1", "d1"), ("m1", "e1")]


async def test_failed_domains_keep_scope_order_when_a_later_domain_finishes_first():
    obj = GatedObjectService(fail={"d1", "e1"}, gated={"d1", "e1"})
    obj.release.set()
    task = asyncio.create_task(_coord(obj, concurrency=3).ensure(_scope("d1", "e1"), SMART))
    await asyncio.sleep(0.05)
    obj.gates["e1"].set()
    await asyncio.sleep(0.05)
    assert obj.completed == ["e1"]
    obj.gates["d1"].set()
    outcome = await task

    assert outcome.failed_domains == [("m1", "d1"), ("m1", "e1")]


async def test_a_raising_domain_does_not_stop_or_cancel_the_others():
    obj = GatedObjectService(raise_on={"d1"})
    obj.release.set()

    with pytest.raises(RuntimeError, match="boom d1"):
        await _coord(obj, concurrency=3).ensure(_scope("d1", "d2", "d3", "e1"), SMART)

    assert sorted(obj.completed) == ["d2", "d3", "e1"]


async def test_further_exceptions_are_logged_by_domain_and_type_while_the_first_is_raised():
    obj = GatedObjectService(raise_on={"d1", "d2", "e1"})
    obj.release.set()

    with patch("arodonata.core.cache_refresh_coordinator.log") as mock_log:
        with pytest.raises(RuntimeError, match="boom d1"):
            await _coord(obj, concurrency=3).ensure(_scope("d1", "d2", "e1"), SMART)

    warnings = [call.args[0] for call in mock_log.return_value.warning.call_args_list]
    assert any("m1/d2" in w and "RuntimeError" in w for w in warnings)
    assert not any("boom" in w for w in warnings)  # the type name only, never message text
    assert not any("m1/d1" in w for w in warnings)  # the re-raised one is not logged twice


async def test_cancelling_ensure_cancels_the_refreshes_in_flight():
    obj = GatedObjectService()
    task = asyncio.create_task(_coord(obj, concurrency=2).ensure(_scope("d1", "d2", "e1", "e2"), SMART))
    await asyncio.sleep(0.05)
    assert obj.in_flight == {"A": 2, "B": 2}

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert obj.in_flight == {"A": 0, "B": 0}
    assert obj.completed == []


async def test_without_a_member_resolver_one_servers_domains_refresh_one_at_a_time():
    obj = GatedObjectService()
    coord = CacheRefreshCoordinator(cache=StatefulCache(), api=None, object_service=obj)  # defaults
    task = asyncio.create_task(coord.ensure(_scope("d1", "d2", "d3"), SMART))
    await asyncio.sleep(0.05)
    assert obj.in_flight["A"] == 1
    obj.release.set()
    await task
    assert obj.peak["A"] == 1
