"""Unit tests for arodonata.api.schemas response models.

Covers ApiCallResult.has_data, ApiQueryResult's before-validator handling of
list/dict/None `data` payloads and has_objects, plus the small SSE event
models built on top of them.
"""

from __future__ import annotations

from datetime import datetime

from arodonata.api.schemas import (
    ApiCallResult,
    ApiQueryResult,
    CompleteEvent,
    ErrorEvent,
    ResultEvent,
    SSEEvent,
    SSEEventType,
)

# --------------------------------------------------------------------------- #
# SSEEventType
# --------------------------------------------------------------------------- #


def test_sse_event_type_values():
    assert SSEEventType.START == "start"
    assert SSEEventType.LOG == "log"
    assert SSEEventType.COMPLETE == "complete"
    assert SSEEventType.RESULT == "result"
    assert SSEEventType.WARNING == "warning"
    assert SSEEventType.ERROR == "error"


# --------------------------------------------------------------------------- #
# ApiCallResult.has_data
# --------------------------------------------------------------------------- #


def test_has_data_false_when_data_is_none():
    result = ApiCallResult(success=True, data=None)
    assert result.has_data is False


def test_has_data_false_when_data_is_empty_dict():
    result = ApiCallResult(success=True, data={})
    assert result.has_data is False


def test_has_data_true_when_data_is_nonempty_dict():
    result = ApiCallResult(success=True, data={"uid": "abc"})
    assert result.has_data is True


def test_api_call_result_defaults():
    result = ApiCallResult(success=False)
    assert result.data is None
    assert result.message == ""
    assert result.code == ""


# --------------------------------------------------------------------------- #
# ApiQueryResult.handle_response_data validator
# --------------------------------------------------------------------------- #


def test_query_result_list_data_populates_objects_and_total():
    result = ApiQueryResult(success=True, data=[{"uid": "1"}, {"uid": "2"}])
    assert result.objects == [{"uid": "1"}, {"uid": "2"}]
    assert result.total == 2
    assert result.res_obj == {"data": [{"uid": "1"}, {"uid": "2"}]}


def test_query_result_list_data_does_not_override_explicit_objects():
    result = ApiQueryResult(
        success=True,
        data=[{"uid": "1"}],
        objects=[{"uid": "explicit"}],
    )
    # Validator only fills `objects` when it wasn't already provided.
    assert result.objects == [{"uid": "explicit"}]
    # total is left at its default since the list branch was skipped.
    assert result.total == 0


def test_query_result_dict_data_extracts_error_code_and_message():
    result = ApiQueryResult(
        success=False,
        data={"code": "generic_err_command_not_found", "message": "boom"},
    )
    assert result.code == "generic_err_command_not_found"
    assert result.message == "boom"
    assert result.res_obj == {"error_data": {"code": "generic_err_command_not_found", "message": "boom"}}


def test_query_result_dict_data_does_not_override_explicit_code_and_message():
    result = ApiQueryResult(
        success=False,
        data={"code": "from_data", "message": "from data"},
        code="explicit_code",
        message="explicit message",
    )
    assert result.code == "explicit_code"
    assert result.message == "explicit message"


def test_query_result_dict_data_does_not_override_explicit_res_obj():
    sentinel = {"already": "set"}
    result = ApiQueryResult(success=False, data={"code": "x"}, res_obj=sentinel)
    assert result.res_obj == sentinel


def test_query_result_none_data_leaves_objects_empty():
    result = ApiQueryResult(success=True, data=None)
    assert result.objects == []
    assert result.total == 0
    assert result.res_obj is None


def test_query_result_missing_data_key_defaults_cleanly():
    result = ApiQueryResult(success=True)
    assert result.data is None
    assert result.objects == []
    assert result.has_objects is False


# --------------------------------------------------------------------------- #
# ApiQueryResult.has_objects
# --------------------------------------------------------------------------- #


def test_has_objects_true_when_objects_present():
    result = ApiQueryResult(success=True, objects=[{"uid": "1"}])
    assert result.has_objects is True


def test_has_objects_false_when_objects_empty():
    result = ApiQueryResult(success=True, objects=[])
    assert result.has_objects is False


# --------------------------------------------------------------------------- #
# SSEEvent and subclasses
# --------------------------------------------------------------------------- #


def test_sse_event_defaults():
    event = SSEEvent(event_type=SSEEventType.LOG)
    assert event.data == {}
    assert event.message is None
    assert event.asset_id is None
    assert event.mgmt_name is None
    assert event.domain is None
    assert isinstance(event.timestamp, datetime)


def test_sse_event_to_sse_format_contains_event_and_data_lines():
    event = SSEEvent(event_type=SSEEventType.LOG, message="hello")
    formatted = event.to_sse_format()
    assert formatted.startswith("event: log\ndata: ")
    assert formatted.endswith("\n\n")
    assert '"message":"hello"' in formatted.replace(" ", "")


def test_result_event_defaults_and_type():
    event = ResultEvent()
    assert event.event_type == SSEEventType.RESULT
    assert event.result_type == ""
    assert event.count == 0


def test_error_event_defaults_and_type():
    event = ErrorEvent(error_code="E1", error_message="failed")
    assert event.event_type == SSEEventType.ERROR
    assert event.error_code == "E1"
    assert event.error_message == "failed"


def test_complete_event_defaults_and_type():
    event = CompleteEvent(total_results=5, duration_seconds=1.5)
    assert event.event_type == SSEEventType.COMPLETE
    assert event.total_results == 5
    assert event.duration_seconds == 1.5
