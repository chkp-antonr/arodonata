"""Tests for arodonata.utils.helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import BaseModel

from arodonata.utils.helpers import (
    _normalize_object_to_dict,
    extract_data_from_response,
    extract_objects_from_response,
    get_caller_name,
    make_composite_key,
    normalize_input_to_list,
    parse_composite_key,
    safe_get,
    to_db_datetime,
    utc_now_naive,
)

# =============================================================================
# Datetime utilities
# =============================================================================


class TestUtcNowNaive:
    def test_returns_naive_datetime(self):
        now = utc_now_naive()
        assert now.tzinfo is None

    def test_close_to_real_utc_now(self):
        now = utc_now_naive()
        real_now = datetime.now(UTC).replace(tzinfo=None)
        assert abs((real_now - now).total_seconds()) < 5


class TestToDbDatetime:
    def test_none_returns_none(self):
        assert to_db_datetime(None) is None

    def test_naive_datetime_returned_as_is(self):
        dt = datetime(2025, 1, 1, 12, 0, 0)
        result = to_db_datetime(dt)
        assert result == dt
        assert result.tzinfo is None

    def test_aware_datetime_converted_and_stripped(self):
        dt = datetime(2025, 1, 1, tzinfo=timezone(timedelta(hours=2)))
        result = to_db_datetime(dt)
        assert result.tzinfo is None
        # 2025-01-01T00:00:00+02:00 == 2024-12-31T22:00:00 UTC
        assert result == datetime(2024, 12, 31, 22, 0, 0)

    def test_string_input_parsed(self):
        result = to_db_datetime("2025-01-01T12:00:00")
        assert result == datetime(2025, 1, 1, 12, 0, 0)

    def test_invalid_string_returns_none(self):
        assert to_db_datetime("not-a-date") is None


# =============================================================================
# get_caller_name
# =============================================================================


class TestGetCallerName:
    def test_caller_name_for_plain_function(self):
        def _inner():
            return get_caller_name(levels=1)

        result = _inner()
        assert result.endswith("_inner")

    def test_caller_name_for_method_includes_class(self):
        class _Foo:
            def bar(self):
                return get_caller_name(levels=1)

        result = _Foo().bar()
        assert "_Foo.bar" in result

    def test_returns_unknown_when_stack_exhausted(self):
        result = get_caller_name(levels=1000)
        assert result == "<unknown>"


# =============================================================================
# normalize_input_to_list
# =============================================================================


class TestNormalizeInputToList:
    def test_none_returns_empty_list(self):
        assert normalize_input_to_list(None) == []

    def test_string_split_by_comma(self):
        assert normalize_input_to_list("a, b,c") == ["a", "b", "c"]

    def test_string_drops_empty_segments(self):
        assert normalize_input_to_list("a,,b, ") == ["a", "b"]

    def test_set_input_converted_to_list(self):
        result = normalize_input_to_list({"x"})
        assert result == ["x"]

    def test_list_input_returned_as_list(self):
        assert normalize_input_to_list(["a", "b"]) == ["a", "b"]


# =============================================================================
# Composite key round trip
# =============================================================================


class TestCompositeKey:
    def test_make_composite_key_joins_with_colon(self):
        assert make_composite_key("mgmt1", "domain1", "uid1") == "mgmt1:domain1:uid1"

    def test_parse_composite_key_splits_on_colon(self):
        assert parse_composite_key("mgmt1:domain1:uid1") == ["mgmt1", "domain1", "uid1"]

    def test_round_trip(self):
        parts = ["mgmt1", "domain-name", "uid-1234"]
        key = make_composite_key(*parts)
        assert parse_composite_key(key) == parts

    def test_make_composite_key_single_part(self):
        assert make_composite_key("only") == "only"


# =============================================================================
# safe_get
# =============================================================================


class TestSafeGet:
    def test_navigates_nested_dict(self):
        data = {"a": {"b": {"c": 42}}}
        assert safe_get(data, "a", "b", "c") == 42

    def test_missing_key_returns_default(self):
        data = {"a": {"b": 1}}
        assert safe_get(data, "a", "x", default="missing") == "missing"

    def test_missing_key_default_is_none(self):
        assert safe_get({}, "a", "b") is None

    def test_non_dict_intermediate_returns_default(self):
        data = {"a": "not-a-dict"}
        assert safe_get(data, "a", "b", default="fallback") == "fallback"

    def test_no_keys_returns_data_itself(self):
        data = {"a": 1}
        assert safe_get(data) == data


# =============================================================================
# _normalize_object_to_dict
# =============================================================================


class _PydanticThing(BaseModel):
    name: str


class _V1Like:
    def dict(self):
        return {"legacy": True}


class TestNormalizeObjectToDict:
    def test_dict_passed_through(self):
        d = {"a": 1}
        assert _normalize_object_to_dict(d) is d

    def test_pydantic_model_uses_model_dump(self):
        obj = _PydanticThing(name="x")
        assert _normalize_object_to_dict(obj) == {"name": "x"}

    def test_v1_like_object_uses_dict_method(self):
        assert _normalize_object_to_dict(_V1Like()) == {"legacy": True}

    def test_plain_object_returned_as_is(self):
        obj = object()
        assert _normalize_object_to_dict(obj) is obj


# =============================================================================
# extract_data_from_response
# =============================================================================


class _ResponseWithData:
    def __init__(self, data):
        self.data = data


class TestExtractDataFromResponse:
    def test_falsy_response_returns_none(self):
        assert extract_data_from_response(None) is None
        assert extract_data_from_response({}) is None

    def test_data_attr_none_returns_none(self):
        response = _ResponseWithData(None)
        assert extract_data_from_response(response) is None

    def test_data_attr_pydantic_model_dumped(self):
        response = _ResponseWithData(_PydanticThing(name="x"))
        assert extract_data_from_response(response) == {"name": "x"}

    def test_data_attr_v1_like_uses_dict(self):
        response = _ResponseWithData(_V1Like())
        assert extract_data_from_response(response) == {"legacy": True}

    def test_data_attr_raw_value_returned(self):
        response = _ResponseWithData({"ip-address": "1.2.3.4"})
        assert extract_data_from_response(response) == {"ip-address": "1.2.3.4"}

    def test_raw_dict_with_data_key(self):
        response = {"data": {"name": "host1"}}
        assert extract_data_from_response(response) == {"name": "host1"}

    def test_raw_dict_without_data_key_returns_dict(self):
        response = {"name": "host1"}
        assert extract_data_from_response(response) == {"name": "host1"}

    def test_unknown_response_type_returns_none(self):
        assert extract_data_from_response(12345) is None

    def test_model_dump_failure_falls_back_to_raw_data(self):
        class _Broken:
            def model_dump(self):
                raise RuntimeError("boom")

        broken = _Broken()
        response = _ResponseWithData(broken)
        assert extract_data_from_response(response) is broken


# =============================================================================
# extract_objects_from_response
# =============================================================================


class _DataWithObjects:
    def __init__(self, objects):
        self.objects = objects


class _DataWithObject:
    def __init__(self, obj):
        self.object = obj


class _ApiResult:
    def __init__(self, data, success=True, message=""):
        self.data = data
        self.success = success
        self.message = message


class TestExtractObjectsFromResponse:
    def test_falsy_response_returns_empty_list(self):
        assert extract_objects_from_response(None) == []
        assert extract_objects_from_response({}) == []

    def test_failed_response_returns_empty_list(self):
        response = _ApiResult(data=None, success=False, message="denied")
        assert extract_objects_from_response(response) == []

    def test_data_objects_list_extracted(self):
        response = _ApiResult(data=_DataWithObjects([{"name": "h1"}, {"name": "h2"}]))
        result = extract_objects_from_response(response)
        assert result == [{"name": "h1"}, {"name": "h2"}]

    def test_data_objects_with_pydantic_models(self):
        response = _ApiResult(data=_DataWithObjects([_PydanticThing(name="h1")]))
        result = extract_objects_from_response(response)
        assert result == [{"name": "h1"}]

    def test_data_object_singular_returned_as_list(self):
        response = _ApiResult(data=_DataWithObject({"name": "single-host"}))
        result = extract_objects_from_response(response)
        assert result == [{"name": "single-host"}]

    def test_data_present_but_no_objects_returns_empty(self):
        response = _ApiResult(data={"unrelated": "value"})
        assert extract_objects_from_response(response) == []

    def test_raw_dict_with_objects_key(self):
        response = {"objects": [{"name": "h1"}]}
        assert extract_objects_from_response(response) == [{"name": "h1"}]

    def test_raw_dict_with_object_key(self):
        response = {"object": {"name": "h1"}}
        assert extract_objects_from_response(response) == [{"name": "h1"}]

    def test_raw_dict_nested_under_data_key(self):
        response = {"data": {"objects": [{"name": "h1"}]}}
        assert extract_objects_from_response(response) == [{"name": "h1"}]

    def test_data_as_plain_list(self):
        response = _ApiResult(data=[{"name": "h1"}, {"name": "h2"}])
        result = extract_objects_from_response(response)
        assert result == [{"name": "h1"}, {"name": "h2"}]

    def test_unrecognized_response_type_returns_empty(self):
        assert extract_objects_from_response(12345) == []


if __name__ == "__main__":
    pytest.main([__file__])
