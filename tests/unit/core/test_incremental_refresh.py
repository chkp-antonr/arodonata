"""Unit tests for the shared show-changes incremental refresh engine.

Every fallback guard, the in-scope type filter, and the re-fetch-in-full
semantics: changed objects are re-fetched via show-object and converted by
the canonical converter — diff payload bodies are never written to cache.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from arodonata.cache.models import CPObject
from arodonata.core.incremental_refresh import (
    DEFAULT_IN_SCOPE_TYPES,
    FallbackToFull,
    IncrementalRefresher,
)

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _Baseline:
    def __init__(self, published_time=datetime(2026, 7, 1)) -> None:
        self.published_time = published_time


_DEFAULT_BASELINE = _Baseline()


class FakeCache:
    def __init__(self, baseline=_DEFAULT_BASELINE) -> None:
        self._baseline = baseline
        self.upserted: list[CPObject] = []
        self.deleted: list[str] = []

    async def get_last_published_session(self, mgmt, domain):
        return self._baseline

    async def upsert_objects(self, objects):
        self.upserted.extend(objects)
        return len(objects)

    async def delete_object(self, uid, mgmt, domain):
        self.deleted.append(uid)
        return 1


class FakeApi:
    def __init__(self, response=None, error=False) -> None:
        self._response = response
        self._error = error
        self.calls: list[dict] = []

    async def show_changes(
        self, mgmt_name, domain="", from_session=None, from_date=None, to_session=None, to_date=None
    ):
        self.calls.append({"mgmt": mgmt_name, "domain": domain, "from_date": from_date})
        if self._error:
            raise RuntimeError("api down")
        return self._response


class FakeFetcher:
    """fetch_full_object double: scripted full objects, not-founds, and errors."""

    def __init__(self, objects=None, missing=(), error_uids=()) -> None:
        self.objects = objects or {}
        self.missing = set(missing)
        self.error_uids = set(error_uids)
        self.fetched: list[str] = []

    async def __call__(self, mgmt, domain, uid):
        self.fetched.append(uid)
        if uid in self.error_uids:
            raise RuntimeError("fetch failed")
        if uid in self.missing:
            return None
        return self.objects.get(uid, {"uid": uid, "name": uid, "type": "host", "ipv4-address": "10.0.0.1"})


def to_cpobject(api_obj, mgmt, domain):
    """Minimal stand-in converter mirroring the real signature."""
    if api_obj.get("broken"):
        return None
    return CPObject(
        id=f"{mgmt}:{domain}:{api_obj['uid']}",
        uid=api_obj["uid"],
        name=api_obj.get("name", ""),
        type=api_obj.get("type", ""),
        mgmt_name=mgmt,
        domain_name=domain,
        ipv4_address=api_obj.get("ipv4-address", ""),
    )


def flat_response(changes):
    return {"success": True, "data": {"changes": changes}}


def change(uid, ctype="add", otype="host"):
    return {"uid": uid, "type": otype, "change-type": ctype, "name": uid}


def make_engine(api, cache=None, fetcher=None, **kw):
    return IncrementalRefresher(
        api=api,
        cache=cache or FakeCache(),
        fetch_full_object=fetcher or FakeFetcher(),
        to_cpobject=to_cpobject,
        **kw,
    )


# ---------------------------------------------------------------------------
# Happy paths: re-fetch semantics
# ---------------------------------------------------------------------------


async def test_adds_are_refetched_and_upserted_from_full_object():
    fetcher = FakeFetcher(objects={"u1": {"uid": "u1", "name": "h1", "type": "host", "ipv4-address": "10.9.9.9"}})
    cache = FakeCache()
    engine = make_engine(FakeApi(flat_response([change("u1")])), cache, fetcher)

    applied = await engine.apply("m1", "d1")

    assert applied == 1
    assert fetcher.fetched == ["u1"]
    assert cache.upserted[0].ipv4_address == "10.9.9.9"  # from re-fetch, not the diff


async def test_diff_payload_body_is_never_trusted():
    # Diff says 10.0.0.1; the re-fetched object says 10.2.2.2 — cache gets 10.2.2.2.
    diff_entry = change("u1", "set")
    diff_entry["ipv4-address"] = "10.0.0.1"
    fetcher = FakeFetcher(objects={"u1": {"uid": "u1", "name": "h1", "type": "host", "ipv4-address": "10.2.2.2"}})
    cache = FakeCache()
    engine = make_engine(FakeApi(flat_response([diff_entry])), cache, fetcher)

    await engine.apply("m1", "d1")

    assert cache.upserted[0].ipv4_address == "10.2.2.2"


async def test_deletes_are_deleted_without_refetch():
    fetcher = FakeFetcher()
    cache = FakeCache()
    engine = make_engine(FakeApi(flat_response([change("u1", "delete")])), cache, fetcher)

    applied = await engine.apply("m1", "d1")

    assert applied == 1
    assert cache.deleted == ["u1"]
    assert fetcher.fetched == []


async def test_refetch_not_found_becomes_delete():
    fetcher = FakeFetcher(missing={"u1"})
    cache = FakeCache()
    engine = make_engine(FakeApi(flat_response([change("u1", "set")])), cache, fetcher)

    applied = await engine.apply("m1", "d1")

    assert applied == 1
    assert cache.deleted == ["u1"]
    assert cache.upserted == []


async def test_same_uid_changed_twice_fetched_once():
    fetcher = FakeFetcher()
    engine = make_engine(FakeApi(flat_response([change("u1", "add"), change("u1", "set")])), FakeCache(), fetcher)

    applied = await engine.apply("m1", "d1")

    assert fetcher.fetched == ["u1"]
    assert applied == 1


async def test_uid_deleted_then_readded_resolved_by_refetch():
    # delete + add for the same uid: live re-fetch finds it -> upsert only, no delete.
    fetcher = FakeFetcher()
    cache = FakeCache()
    engine = make_engine(FakeApi(flat_response([change("u1", "delete"), change("u1", "add")])), cache, fetcher)

    applied = await engine.apply("m1", "d1")

    assert applied == 1
    assert [o.uid for o in cache.upserted] == ["u1"]
    assert cache.deleted == []


async def test_zero_changes_returns_zero_without_writes():
    cache = FakeCache()
    engine = make_engine(FakeApi(flat_response([])), cache)

    assert await engine.apply("m1", "d1") == 0
    assert cache.upserted == [] and cache.deleted == []


async def test_special_domain_uses_empty_api_domain():
    api = FakeApi(flat_response([]))
    engine = make_engine(api)
    await engine.apply("m1", "SMC User")
    assert api.calls[0]["domain"] == ""


# ---------------------------------------------------------------------------
# Type filter
# ---------------------------------------------------------------------------


async def test_out_of_scope_changes_are_ignored():
    cache = FakeCache()
    fetcher = FakeFetcher()
    engine = make_engine(
        FakeApi(flat_response([change("r1", "set", "access-rule"), change("s1", "delete", "service-tcp")])),
        cache,
        fetcher,
    )

    assert await engine.apply("m1", "d1") == 0
    assert fetcher.fetched == [] and cache.upserted == [] and cache.deleted == []


async def test_mixed_scope_applies_only_in_scope():
    cache = FakeCache()
    engine = make_engine(
        FakeApi(flat_response([change("u1"), change("r1", "set", "access-rule")])), cache, FakeFetcher()
    )

    assert await engine.apply("m1", "d1") == 1
    assert [o.uid for o in cache.upserted] == ["u1"]


async def test_refetched_type_out_of_scope_falls_back():
    fetcher = FakeFetcher(objects={"u1": {"uid": "u1", "name": "x", "type": "simple-gateway"}})
    engine = make_engine(FakeApi(flat_response([change("u1")])), FakeCache(), fetcher)

    with pytest.raises(FallbackToFull, match="out-of-scope"):
        await engine.apply("m1", "d1")


async def test_cap_counts_only_in_scope_changes():
    entries = [change(f"u{i}") for i in range(3)] + [change(f"r{i}", "set", "access-rule") for i in range(10)]
    engine = make_engine(FakeApi(flat_response(entries)), FakeCache(), FakeFetcher(), max_changes=5)
    assert await engine.apply("m1", "d1") == 3  # 3 in-scope <= cap despite 13 total


async def test_over_cap_falls_back():
    entries = [change(f"u{i}") for i in range(6)]
    engine = make_engine(FakeApi(flat_response(entries)), max_changes=5)
    with pytest.raises(FallbackToFull, match="too many changes"):
        await engine.apply("m1", "d1")


# ---------------------------------------------------------------------------
# Fallback guards
# ---------------------------------------------------------------------------


async def test_no_baseline_falls_back():
    engine = make_engine(FakeApi(flat_response([])), FakeCache(baseline=None))
    with pytest.raises(FallbackToFull, match="no baseline"):
        await engine.apply("m1", "d1")


async def test_baseline_without_published_time_falls_back():
    engine = make_engine(FakeApi(flat_response([])), FakeCache(baseline=_Baseline(published_time=None)))
    with pytest.raises(FallbackToFull, match="no baseline"):
        await engine.apply("m1", "d1")


async def test_show_changes_error_falls_back():
    engine = make_engine(FakeApi(error=True))
    with pytest.raises(FallbackToFull, match="show-changes failed"):
        await engine.apply("m1", "d1")


async def test_unsuccessful_show_changes_falls_back():
    class Result:
        success = False
        message = "denied"

    engine = make_engine(FakeApi(Result()))
    with pytest.raises(FallbackToFull, match="unsuccessful"):
        await engine.apply("m1", "d1")


async def test_none_response_falls_back():
    engine = make_engine(FakeApi(None))
    with pytest.raises(FallbackToFull, match="no response"):
        await engine.apply("m1", "d1")


async def test_truncated_diff_falls_back():
    response = {
        "success": True,
        "data": {"tasks": [{"task-details": [{"total": 5, "to": 2, "changes": []}]}]},
    }
    engine = make_engine(FakeApi(response))
    with pytest.raises(FallbackToFull, match="truncated"):
        await engine.apply("m1", "d1")


async def test_dropped_in_scope_entry_falls_back():
    # uid-less host in the real task-wrapped shape: parser drops it, guard trips.
    response = {
        "success": True,
        "data": {
            "tasks": [
                {
                    "task-details": [
                        {
                            "total": 1,
                            "to": 1,
                            "changes": [{"operations": {"added-objects": [{"type": "host", "name": "no-uid"}]}}],
                        }
                    ]
                }
            ]
        },
    }
    engine = make_engine(FakeApi(response))
    with pytest.raises(FallbackToFull, match="unhandled change"):
        await engine.apply("m1", "d1")


async def test_dropped_out_of_scope_entry_does_not_trip_guard():
    # uid-less access-rule: parser drops it, but it's out of scope -> no false fallback.
    response = {
        "success": True,
        "data": {
            "tasks": [
                {
                    "task-details": [
                        {
                            "total": 1,
                            "to": 1,
                            "changes": [
                                {"operations": {"modified-objects": [{"type": "access-rule", "name": "no-uid"}]}}
                            ],
                        }
                    ]
                }
            ]
        },
    }
    engine = make_engine(FakeApi(response))
    assert await engine.apply("m1", "d1") == 0


async def test_unknown_legacy_change_type_in_scope_falls_back():
    entry = {"uid": "u1", "type": "host", "change-type": "mystery", "name": "u1"}
    engine = make_engine(FakeApi(flat_response([entry])))
    with pytest.raises(FallbackToFull, match="unhandled change"):
        await engine.apply("m1", "d1")


async def test_refetch_error_falls_back():
    fetcher = FakeFetcher(error_uids={"u1"})
    engine = make_engine(FakeApi(flat_response([change("u1")])), FakeCache(), fetcher)
    with pytest.raises(FallbackToFull, match="show-object"):
        await engine.apply("m1", "d1")


async def test_conversion_failure_falls_back():
    fetcher = FakeFetcher(objects={"u1": {"uid": "u1", "name": "x", "type": "host", "broken": True}})
    engine = make_engine(FakeApi(flat_response([change("u1")])), FakeCache(), fetcher)
    with pytest.raises(FallbackToFull, match="conversion failed"):
        await engine.apply("m1", "d1")


async def test_real_task_wrapped_diff_applies():
    response = {
        "success": True,
        "data": {
            "tasks": [
                {
                    "task-details": [
                        {
                            "total": 1,
                            "to": 1,
                            "changes": [
                                {
                                    "operations": {
                                        "added-objects": [{"uid": "u1", "type": "host", "name": "h1"}],
                                        "deleted-objects": [{"uid": "u2", "type": "host", "name": "h2"}],
                                    }
                                }
                            ],
                        }
                    ]
                }
            ]
        },
    }
    cache = FakeCache()
    engine = make_engine(FakeApi(response), cache, FakeFetcher())

    assert await engine.apply("m1", "d1") == 2
    assert [o.uid for o in cache.upserted] == ["u1"]
    assert cache.deleted == ["u2"]


def test_default_scope_matches_object_service_types():
    from arodonata.cache.object_service import ObjectService

    assert DEFAULT_IN_SCOPE_TYPES == frozenset(ObjectService.OBJECT_TYPES)
