"""Tests for CacheRefreshCoordinator (freshness/refresh decisions before reads).

Covers every CacheMode, the TTL-throttled staleness memo (via an injected fake
Clock), per-(mgmt, domain) concurrency collapse, each smart-fast fallback-to-full
trigger, incremental delete propagation + baseline advance, and scope resolution.
"""

from datetime import datetime, timedelta

from arodonata.core.cache_mode import CacheMode
from arodonata.core.cache_policy import CachePolicy, RefreshScope, SystemClock
from arodonata.core.cache_refresh_coordinator import (
    CacheRefreshCoordinator,
    _extract_members_from_raw,
    _raw_change_count,
)
from tests.unit.doubles import FakeApi, FakeCache

# --------------------------------------------------------------------------- #
# Test doubles                                                                 #
# --------------------------------------------------------------------------- #


class FakeClock:
    """Deterministic, advanceable time source implementing the Clock protocol."""

    def __init__(self, start: datetime) -> None:
        self._t = start

    def now(self) -> datetime:
        return self._t

    def advance(self, seconds: int) -> None:
        self._t = self._t + timedelta(seconds=seconds)


class _Baseline:
    """Stand-in for a LastPublishedSession with a published_time."""

    def __init__(self, published_time: datetime | None = datetime(2026, 7, 1)) -> None:
        self.published_time = published_time


class StatefulCache(FakeCache):
    """FakeCache extended with per-domain objects, a baseline, and mutation tracking."""

    def __init__(self, objects_by_domain=None, baseline=None, domains=None) -> None:
        self._objs = objects_by_domain or {}
        self._baseline = baseline
        self._domains = domains or []
        self.upserted: list[str] = []
        self.deleted: list[str] = []

    async def get_objects(self, object_type=None, mgmt_names=None, domain_names=None, filters=None):
        out = []
        for (m, d), objs in self._objs.items():
            if mgmt_names and m not in mgmt_names:
                continue
            if domain_names and d not in domain_names:
                continue
            out.extend(objs)
        return out

    async def get_last_published_session(self, mgmt_name, domain_name):
        return self._baseline

    async def upsert_objects(self, objects):
        self.upserted.extend(o.uid for o in objects)
        return len(objects)

    async def delete_object(self, uid, mgmt_name, domain_name):
        self.deleted.append(uid)
        return 1

    async def get_domains(self, mgmt_names=None):
        if mgmt_names:
            return [d for d in self._domains if d.mgmt_name in mgmt_names]
        return list(self._domains)


class FakeObjectService:
    """Collaborator the coordinator drives for staleness + reloads."""

    def __init__(self, stale=False) -> None:
        self.stale = stale
        self.full_reloads: list[tuple[str, str]] = []
        self.baseline_refreshes: list[tuple[str, str]] = []
        self.stale_checks = 0

    async def _is_domain_stale(self, mgmt, domain):
        self.stale_checks += 1
        return self.stale

    async def refresh_objects(self, mgmt_names=None, domain_names=None, mode="force"):
        self.full_reloads.append((mgmt_names[0], domain_names[0]))
        yield {"progress": 1}  # coordinator drains this generator

    async def refresh_last_published_session(self, mgmt, domain):
        self.baseline_refreshes.append((mgmt, domain))


class RecordingApi(FakeApi):
    """FakeApi whose show_changes returns a scripted response and records calls."""

    def __init__(self, response=None, error=False) -> None:
        self._response = response
        self._error = error
        self.calls: list[dict] = []

    async def show_changes(
        self,
        mgmt_name,
        domain="",
        from_session=None,
        from_date=None,
        to_session=None,
        to_date=None,
    ):
        self.calls.append({"mgmt": mgmt_name, "domain": domain, "from_date": from_date})
        if self._error:
            raise RuntimeError("boom")
        return self._response


class _Domain:
    def __init__(self, mgmt_name, domain_name) -> None:
        self.mgmt_name = mgmt_name
        self.domain_name = domain_name


def _changes_response(adds=(), deletes=(), extra=()):
    changes = []
    for uid in adds:
        changes.append({"uid": uid, "type": "host", "change-type": "add", "name": uid})
    for uid in deletes:
        changes.append({"uid": uid, "type": "host", "change-type": "delete", "name": uid})
    changes.extend(extra)
    return {"success": True, "data": {"changes": changes}}


DEFAULT_START = datetime(2026, 7, 15)


def make_coord(cache, obj_svc, *, api=None, mode=CacheMode.SMART, clock=None):
    return CacheRefreshCoordinator(
        cache=cache,
        api=api,
        object_service=obj_svc,
        session_tracker=None,
        default_mode=mode,
        default_ttl=300,
        clock=clock or FakeClock(DEFAULT_START),
    )


# --------------------------------------------------------------------------- #
# CacheMode coverage                                                           #
# --------------------------------------------------------------------------- #


async def test_cache_mode_is_noop():
    obj = FakeObjectService(stale=True)
    coord = make_coord(StatefulCache(), obj)

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.CACHE, None))

    assert obj.full_reloads == []
    assert obj.stale_checks == 0
    assert outcome.skipped_reason == "cache-mode"
    assert outcome.mode_used == CacheMode.CACHE


async def test_force_reloads_unconditionally_ignoring_ttl_and_staleness():
    obj = FakeObjectService(stale=False)
    cache = StatefulCache({("m1", "d1"): ["x"]})  # non-empty, not stale
    coord = make_coord(cache, obj, mode=CacheMode.FORCE)

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.FORCE, 300))

    assert obj.full_reloads == [("m1", "d1")]
    assert obj.stale_checks == 0  # FORCE never checks staleness
    assert outcome.refreshed_domains == [("m1", "d1")]


async def test_smart_stale_triggers_full_reload():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"]})
    coord = make_coord(cache, obj, mode=CacheMode.SMART)

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART, 300))

    assert obj.full_reloads == [("m1", "d1")]
    assert outcome.fell_back is False
    assert outcome.refreshed_domains == [("m1", "d1")]


async def test_smart_not_stale_serves_cache():
    obj = FakeObjectService(stale=False)
    cache = StatefulCache({("m1", "d1"): ["x"]})
    coord = make_coord(cache, obj, mode=CacheMode.SMART)

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART, 300))

    assert obj.full_reloads == []
    assert obj.stale_checks == 1
    assert outcome.refreshed_domains == []


async def test_empty_domain_populates_even_when_not_stale():
    obj = FakeObjectService(stale=False)
    cache = StatefulCache({})  # empty cache -> must reload regardless of staleness
    coord = make_coord(cache, obj, mode=CacheMode.SMART)

    await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART, 300))

    assert obj.full_reloads == [("m1", "d1")]
    assert obj.stale_checks == 0  # short-circuited by the empty check


# --------------------------------------------------------------------------- #
# TTL-throttled staleness memo (fake clock; no sleeping)                       #
# --------------------------------------------------------------------------- #


async def test_ttl_memo_throttles_staleness_check_within_window():
    obj = FakeObjectService(stale=False)
    cache = StatefulCache({("m1", "d1"): ["x"]})
    clock = FakeClock(DEFAULT_START)
    coord = make_coord(cache, obj, clock=clock)

    await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART, 300))
    assert obj.stale_checks == 1

    clock.advance(100)  # still inside the 300s TTL
    await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART, 300))
    assert obj.stale_checks == 1  # memo short-circuited the second check
    assert obj.full_reloads == []


async def test_ttl_memo_expires_and_rechecks():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"]})
    clock = FakeClock(DEFAULT_START)
    coord = make_coord(cache, obj, clock=clock)

    await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART, 300))
    assert obj.full_reloads == [("m1", "d1")]

    clock.advance(100)  # within TTL: skipped
    await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART, 300))
    assert obj.full_reloads == [("m1", "d1")]

    clock.advance(300)  # past TTL: rechecks, stale again -> reload
    await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART, 300))
    assert obj.full_reloads == [("m1", "d1"), ("m1", "d1")]


async def test_ttl_zero_never_memoizes():
    obj = FakeObjectService(stale=False)
    cache = StatefulCache({("m1", "d1"): ["x"]})
    coord = make_coord(cache, obj)

    # ttl falsy -> _ttl_fresh always False -> staleness checked every time.
    await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART, 0))
    await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART, 0))

    assert obj.stale_checks == 2


async def test_invalidate_drops_memo_forcing_recheck():
    obj = FakeObjectService(stale=False)
    cache = StatefulCache({("m1", "d1"): ["x"]})
    coord = make_coord(cache, obj)

    await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART, 300))
    assert obj.stale_checks == 1

    coord.invalidate("m1", "d1")

    await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART, 300))
    assert obj.stale_checks == 2  # memo dropped -> rechecked despite TTL


# --------------------------------------------------------------------------- #
# Concurrency collapse                                                         #
# --------------------------------------------------------------------------- #


async def test_concurrent_ensure_collapses_to_one_full_reload():
    import asyncio

    class SlowObjectService(FakeObjectService):
        async def _is_domain_stale(self, mgmt, domain):
            self.stale_checks += 1
            await asyncio.sleep(0)  # yield so both tasks race for the lock
            return self.stale

    obj = SlowObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"]})
    coord = make_coord(cache, obj)

    await asyncio.gather(
        coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART, 300)),
        coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART, 300)),
    )

    # Second entrant sees the memo set by the first and serves cache.
    assert obj.full_reloads == [("m1", "d1")]


# --------------------------------------------------------------------------- #
# smart-fast: incremental apply, delete propagation, baseline advance          #
# --------------------------------------------------------------------------- #


async def test_smart_fast_applies_diff_without_full_reload():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"]}, baseline=_Baseline())
    api = RecordingApi(_changes_response(adds=["a1"], deletes=["d9"]))
    coord = make_coord(cache, obj, api=api, mode=CacheMode.SMART_FAST)

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART_FAST, 300))

    assert obj.full_reloads == []  # no full reload
    assert cache.upserted == ["a1"]
    assert cache.deleted == ["d9"]  # delete propagated
    assert obj.baseline_refreshes == [("m1", "d1")]  # baseline advanced
    assert outcome.fell_back is False
    assert outcome.refreshed_domains == [("m1", "d1")]
    # baseline.published_time was passed as from_date (ISO).
    assert api.calls[0]["from_date"] == datetime(2026, 7, 1).isoformat()


async def test_smart_fast_delete_only_diff_skips_upsert():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"]}, baseline=_Baseline())
    api = RecordingApi(_changes_response(deletes=["d1", "d2"]))
    coord = make_coord(cache, obj, api=api, mode=CacheMode.SMART_FAST)

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART_FAST, 300))

    assert cache.upserted == []  # no adds/updates -> upsert skipped
    assert cache.deleted == ["d1", "d2"]
    assert obj.full_reloads == []
    assert outcome.refreshed_domains == [("m1", "d1")]  # applied == 2 > 0


async def test_smart_fast_set_update_is_upserted():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"]}, baseline=_Baseline())
    api = RecordingApi(_changes_response(extra=[{"uid": "u1", "type": "host", "change-type": "set", "name": "u1"}]))
    coord = make_coord(cache, obj, api=api, mode=CacheMode.SMART_FAST)

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART_FAST, 300))

    assert cache.upserted == ["u1"]
    assert obj.full_reloads == []
    assert outcome.fell_back is False


async def test_smart_fast_no_changes_advances_baseline_without_recording_refresh():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"]}, baseline=_Baseline())
    api = RecordingApi(_changes_response())  # empty changes -> applied == 0
    coord = make_coord(cache, obj, api=api, mode=CacheMode.SMART_FAST)

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART_FAST, 300))

    assert obj.full_reloads == []
    assert obj.baseline_refreshes == [("m1", "d1")]  # baseline still advances
    assert outcome.refreshed_domains == []  # nothing applied -> not recorded
    assert outcome.fell_back is False


async def test_smart_fast_extracts_group_members_on_upsert():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"]}, baseline=_Baseline())
    grp = {
        "uid": "g1",
        "type": "group",
        "change-type": "add",
        "name": "g1",
        "members": {"objects": [{"uid": "m-a"}, {"uid": "m-b"}]},
    }
    api = RecordingApi(_changes_response(extra=[grp]))
    coord = make_coord(cache, obj, api=api, mode=CacheMode.SMART_FAST)

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART_FAST, 300))

    assert cache.upserted == ["g1"]
    assert outcome.fell_back is False


async def test_smart_fast_uses_empty_api_domain_for_special_domains():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "System Data"): ["x"]}, baseline=_Baseline())
    api = RecordingApi(_changes_response(adds=["a1"]))
    coord = make_coord(cache, obj, api=api, mode=CacheMode.SMART_FAST)

    await coord.ensure(
        RefreshScope(["m1"], ["System Data"]),
        CachePolicy(CacheMode.SMART_FAST, 300),
    )

    assert api.calls[0]["domain"] == ""  # special domain mapped to ""


async def test_smart_fast_uses_domain_name_for_regular_domains():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"]}, baseline=_Baseline())
    api = RecordingApi(_changes_response(adds=["a1"]))
    coord = make_coord(cache, obj, api=api, mode=CacheMode.SMART_FAST)

    await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART_FAST, 300))

    assert api.calls[0]["domain"] == "d1"


# --------------------------------------------------------------------------- #
# smart-fast: each fallback-to-full trigger                                    #
# --------------------------------------------------------------------------- #


async def test_smart_fast_fallback_no_baseline():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"]}, baseline=None)
    api = RecordingApi(_changes_response(adds=["a1"]))
    coord = make_coord(cache, obj, api=api, mode=CacheMode.SMART_FAST)

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART_FAST, 300))

    assert obj.full_reloads == [("m1", "d1")]
    assert outcome.fell_back is True
    assert api.calls == []  # bailed before calling show-changes


async def test_smart_fast_fallback_baseline_without_published_time():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"]}, baseline=_Baseline(published_time=None))
    api = RecordingApi(_changes_response(adds=["a1"]))
    coord = make_coord(cache, obj, api=api, mode=CacheMode.SMART_FAST)

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART_FAST, 300))

    assert obj.full_reloads == [("m1", "d1")]
    assert outcome.fell_back is True


async def test_smart_fast_fallback_show_changes_api_error():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"]}, baseline=_Baseline())
    api = RecordingApi(error=True)
    coord = make_coord(cache, obj, api=api, mode=CacheMode.SMART_FAST)

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART_FAST, 300))

    assert obj.full_reloads == [("m1", "d1")]
    assert outcome.fell_back is True


async def test_smart_fast_fallback_unparseable_response():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"]}, baseline=_Baseline())
    api = RecordingApi(response=None)  # parse_changes(None) raises -> unparseable
    coord = make_coord(cache, obj, api=api, mode=CacheMode.SMART_FAST)

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART_FAST, 300))

    assert obj.full_reloads == [("m1", "d1")]
    assert outcome.fell_back is True


async def test_smart_fast_fallback_unhandled_change_type_dropped():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"]}, baseline=_Baseline())
    # "rename" is dropped by the processor; raw_count (2) > parsed (1) -> fallback.
    api = RecordingApi(
        _changes_response(
            adds=["a1"],
            extra=[{"uid": "r1", "type": "host", "change-type": "rename", "name": "r1"}],
        )
    )
    coord = make_coord(cache, obj, api=api, mode=CacheMode.SMART_FAST)

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART_FAST, 300))

    assert obj.full_reloads == [("m1", "d1")]
    assert outcome.fell_back is True
    assert cache.upserted == []  # nothing applied before falling back


async def test_smart_fast_fallback_too_many_changes():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"]}, baseline=_Baseline())
    api = RecordingApi(_changes_response(adds=[f"a{i}" for i in range(600)]))
    coord = make_coord(cache, obj, api=api, mode=CacheMode.SMART_FAST)
    coord.max_incremental_changes = 500

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART_FAST, 300))

    assert obj.full_reloads == [("m1", "d1")]
    assert outcome.fell_back is True


async def test_smart_fast_empty_domain_falls_back_to_full_reload():
    # smart-fast on an empty cache still takes the empty->full-reload path.
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({}, baseline=_Baseline())
    api = RecordingApi(_changes_response(adds=["a1"]))
    coord = make_coord(cache, obj, api=api, mode=CacheMode.SMART_FAST)

    await coord.ensure(RefreshScope(["m1"], ["d1"]), CachePolicy(CacheMode.SMART_FAST, 300))

    assert obj.full_reloads == [("m1", "d1")]
    assert api.calls == []  # empty short-circuit before incremental path


# --------------------------------------------------------------------------- #
# Scope resolution                                                             #
# --------------------------------------------------------------------------- #


async def test_resolve_pairs_uses_product_of_mgmt_and_domain_names():
    obj = FakeObjectService(stale=False)
    coord = make_coord(StatefulCache(), obj)

    pairs = await coord._resolve_pairs(RefreshScope(mgmt_names=["m1", "m2"], domain_names=["d1", "d2"]))

    assert sorted(pairs) == [
        ("m1", "d1"),
        ("m1", "d2"),
        ("m2", "d1"),
        ("m2", "d2"),
    ]


async def test_resolve_pairs_broad_scope_uses_cached_domains():
    obj = FakeObjectService(stale=False)
    cache = StatefulCache(domains=[_Domain("m1", "d1"), _Domain("m1", "d2"), _Domain("m2", "d3")])
    coord = make_coord(cache, obj)

    pairs = await coord._resolve_pairs(RefreshScope(mgmt_names=["m1"]))

    assert sorted(pairs) == [("m1", "d1"), ("m1", "d2")]


async def test_resolve_pairs_filters_domain_names_when_mgmt_names_none():
    obj = FakeObjectService(stale=False)
    cache = StatefulCache(domains=[_Domain("m1", "d1"), _Domain("m1", "d2"), _Domain("m2", "d1")])
    coord = make_coord(cache, obj)

    pairs = await coord._resolve_pairs(RefreshScope(mgmt_names=None, domain_names=["d1"]))

    assert sorted(pairs) == [("m1", "d1"), ("m2", "d1")]


async def test_ensure_iterates_all_resolved_pairs():
    obj = FakeObjectService(stale=True)
    cache = StatefulCache({("m1", "d1"): ["x"], ("m1", "d2"): ["y"]})
    coord = make_coord(cache, obj, mode=CacheMode.SMART)

    outcome = await coord.ensure(RefreshScope(["m1"], ["d1", "d2"]), CachePolicy(CacheMode.SMART, 300))

    assert sorted(obj.full_reloads) == [("m1", "d1"), ("m1", "d2")]
    assert sorted(outcome.refreshed_domains) == [("m1", "d1"), ("m1", "d2")]


# --------------------------------------------------------------------------- #
# Module-level helpers                                                         #
# --------------------------------------------------------------------------- #


def test_raw_change_count_variants():
    assert _raw_change_count("not-a-dict") == 0
    assert _raw_change_count({"data": "not-a-dict"}) == 0
    assert _raw_change_count({"data": {"changes": "not-a-list"}}) == 0
    assert _raw_change_count({"data": {"changes": [1, 2, 3]}}) == 3


def test_extract_members_from_raw_objects_dict_form():
    raw = {"members": {"objects": [{"uid": "a"}, {"uid": "b"}, {"no-uid": 1}]}}

    assert _extract_members_from_raw(raw) == "a,b"


def test_extract_members_from_raw_list_form():
    raw = {"members": [{"uid": "a"}, {"uid": "b"}, "junk"]}

    assert _extract_members_from_raw(raw) == "a,b"


def test_extract_members_from_raw_none_or_scalar():
    assert _extract_members_from_raw({}) == ""
    assert _extract_members_from_raw({"members": "scalar"}) == ""


def test_default_clock_is_system_clock_when_unset():
    # Exercises the `clock or SystemClock()` default branch.
    coord = CacheRefreshCoordinator(cache=StatefulCache(), api=None, object_service=FakeObjectService())

    assert isinstance(coord._clock, SystemClock)
    assert coord.default_policy.mode == CacheMode.SMART
    assert coord.default_policy.ttl == 300


# --------------------------------------------------------------------------- #
# Real task-wrapped show-changes shape (captured live from R81)                #
# --------------------------------------------------------------------------- #


class _ApiResult:
    """Duck-typed ApiCallResult stand-in (the adapter returns one, not a dict)."""

    def __init__(self, data, success=True, message=""):
        self.data = data
        self.success = success
        self.message = message


def _real_diff(operations: dict, to: int = 1, total: int = 1) -> dict:
    return {
        "tasks": [
            {
                "status": "succeeded",
                "task-details": [
                    {
                        "limit": 10,
                        "offset": 0,
                        "from": 1,
                        "to": to,
                        "total": total,
                        "changes": [
                            {
                                "session": {"session-uid": "s-1"},
                                "operations": operations,
                            }
                        ],
                    }
                ],
            }
        ]
    }


async def test_smart_fast_applies_real_task_wrapped_diff():
    """An ApiCallResult carrying the real CP shape applies incrementally."""
    cache = StatefulCache({("m1", "d1"): ["existing"]}, baseline=_Baseline())
    api = RecordingApi(
        response=_ApiResult(
            _real_diff(
                {
                    "added-objects": [
                        {
                            "uid": "u-new",
                            "name": "hostX",
                            "type": "host",
                            "ipv4-address": "10.0.0.9",
                        }
                    ],
                    "deleted-objects": [{"uid": "u-gone", "name": "old", "type": "host"}],
                }
            )
        )
    )
    obj = FakeObjectService(stale=True)
    coord = CacheRefreshCoordinator(cache=cache, api=api, object_service=obj)

    outcome = await coord.ensure(
        RefreshScope(mgmt_names=["m1"], domain_names=["d1"]),
        CachePolicy(mode=CacheMode.SMART_FAST, ttl=0),
    )

    assert not outcome.fell_back
    assert outcome.refreshed_domains == [("m1", "d1")]
    assert cache.upserted == ["u-new"]
    assert cache.deleted == ["u-gone"]
    assert obj.full_reloads == []  # no fallback full reload
    assert obj.baseline_refreshes == [("m1", "d1")]


async def test_smart_fast_falls_back_on_unsuccessful_show_changes():
    """success=False from the API must fall back, never advance the baseline."""
    cache = StatefulCache({("m1", "d1"): ["existing"]}, baseline=_Baseline())
    api = RecordingApi(response=_ApiResult(data=None, success=False, message="boom"))
    obj = FakeObjectService(stale=True)
    coord = CacheRefreshCoordinator(cache=cache, api=api, object_service=obj)

    outcome = await coord.ensure(
        RefreshScope(mgmt_names=["m1"], domain_names=["d1"]),
        CachePolicy(mode=CacheMode.SMART_FAST, ttl=0),
    )

    assert outcome.fell_back
    assert obj.full_reloads == [("m1", "d1")]


async def test_smart_fast_falls_back_on_truncated_diff():
    """A paged diff (to < total) cannot be applied safely -> full reload."""
    cache = StatefulCache({("m1", "d1"): ["existing"]}, baseline=_Baseline())
    api = RecordingApi(
        response=_ApiResult(
            _real_diff(
                {"added-objects": [{"uid": "u1", "name": "a", "type": "host"}]},
                to=1,
                total=5,
            )
        )
    )
    obj = FakeObjectService(stale=True)
    coord = CacheRefreshCoordinator(cache=cache, api=api, object_service=obj)

    outcome = await coord.ensure(
        RefreshScope(mgmt_names=["m1"], domain_names=["d1"]),
        CachePolicy(mode=CacheMode.SMART_FAST, ttl=0),
    )

    assert outcome.fell_back
    assert cache.upserted == []
    assert obj.full_reloads == [("m1", "d1")]


async def test_smart_fast_falls_back_on_uid_less_operation_object():
    """An operations object without a uid is dropped by the parser; the raw
    counter still counts it, so the guard must fall back rather than lose it."""
    cache = StatefulCache({("m1", "d1"): ["existing"]}, baseline=_Baseline())
    api = RecordingApi(
        response=_ApiResult(
            _real_diff(
                {
                    "added-objects": [
                        {"uid": "u-ok", "name": "a", "type": "host"},
                        {"name": "no-uid", "type": "host"},
                    ]
                }
            )
        )
    )
    obj = FakeObjectService(stale=True)
    coord = CacheRefreshCoordinator(cache=cache, api=api, object_service=obj)

    outcome = await coord.ensure(
        RefreshScope(mgmt_names=["m1"], domain_names=["d1"]),
        CachePolicy(mode=CacheMode.SMART_FAST, ttl=0),
    )

    assert outcome.fell_back
    assert cache.upserted == []


async def test_smart_fast_session_only_publish_advances_baseline_quietly():
    """A publish with no object operations (e.g. set-session) applies nothing
    but still advances the baseline."""
    cache = StatefulCache({("m1", "d1"): ["existing"]}, baseline=_Baseline())
    api = RecordingApi(response=_ApiResult(_real_diff({})))
    obj = FakeObjectService(stale=True)
    coord = CacheRefreshCoordinator(cache=cache, api=api, object_service=obj)

    outcome = await coord.ensure(
        RefreshScope(mgmt_names=["m1"], domain_names=["d1"]),
        CachePolicy(mode=CacheMode.SMART_FAST, ttl=0),
    )

    assert not outcome.fell_back
    assert outcome.refreshed_domains == []
    assert obj.baseline_refreshes == [("m1", "d1")]
