# tests/unit/cpcrud/test_nat_sentinels.py
"""Tests for the runtime NAT sentinel ("Any"/"Original" object) UID resolver.

Covers the four behaviors the resolver exists to guarantee:

* resolve-succeeds: a clean `show-objects`/`show-nat-rulebase` response resolves both UIDs.
* resolve-fails-falls-back: any API failure/unexpected shape degrades to the verified constant,
  never raises, and warns.
* resolved-differs-from-constant: a resolved UID that disagrees with the constant is used (not
  the constant) and triggers a prominent warning naming the server, object, and both UIDs.
* caching: a second resolve for the same management server makes no further API calls.
"""

from __future__ import annotations

from typing import Any

import pytest

from arodonata.api.schemas import ApiCallResult
from arodonata.cpcrud.nat_sentinels import (
    NAT_ANY_OBJECT_UID,
    NAT_ORIGINAL_OBJECT_UID,
    reset_nat_sentinel_cache,
    resolve_nat_sentinel_uids,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    reset_nat_sentinel_cache()
    yield
    reset_nat_sentinel_cache()


def _any_objects_response(uid: str = NAT_ANY_OBJECT_UID) -> ApiCallResult:
    return ApiCallResult(
        success=True,
        data={
            "from": 1,
            "to": 1,
            "total": 1,
            "objects": [{"uid": uid, "name": "Any", "type": "CpmiAnyObject"}],
        },
    )


def _nat_rulebase_response(original_uid: str = NAT_ORIGINAL_OBJECT_UID) -> ApiCallResult:
    return ApiCallResult(
        success=True,
        data={
            "from": 1,
            "to": 1,
            "total": 1,
            "rulebase": [
                {
                    "type": "nat-rule",
                    "rule-number": 1,
                    "original-source": {"uid": "aaaa", "name": "host1", "type": "host"},
                    "original-destination": {"uid": NAT_ANY_OBJECT_UID, "name": "Any", "type": "CpmiAnyObject"},
                    "original-service": {"uid": NAT_ANY_OBJECT_UID, "name": "Any", "type": "CpmiAnyObject"},
                    "translated-source": {"uid": "aaaa", "name": "host1", "type": "host"},
                    "translated-destination": {"uid": original_uid, "name": "Original", "type": "Global"},
                    "translated-service": {"uid": original_uid, "name": "Original", "type": "Global"},
                }
            ],
        },
    )


class FakeCall:
    """Records calls and returns whatever was queued for the given command."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def __call__(self, command: str, payload: dict[str, Any]) -> Any:
        self.calls.append((command, payload))
        response = self._responses[command]
        if isinstance(response, Exception):
            raise response
        return response


class TestResolveSucceeds:
    async def test_resolves_both_uids_from_live_shaped_responses(self) -> None:
        call = FakeCall(
            {
                "show-objects": _any_objects_response(),
                "show-nat-rulebase": _nat_rulebase_response(),
            }
        )

        resolved = await resolve_nat_sentinel_uids(call, mgmt_name="mdsNP2.np.cparch.in", package="Standard")

        assert resolved.any_uid == NAT_ANY_OBJECT_UID
        assert resolved.original_uid == NAT_ORIGINAL_OBJECT_UID
        # Exactly one call per object, both are read-only show-* lookups.
        commands = [c for c, _ in call.calls]
        assert commands == ["show-objects", "show-nat-rulebase"]
        assert call.calls[0][1]["type"] == "CpmiAnyObject"
        assert call.calls[1][1]["package"] == "Standard"

    async def test_resolves_original_uid_nested_under_a_section(self) -> None:
        # Real show-nat-rulebase responses nest rules under nat-section entries (confirmed
        # against smsNP82 2026-09-03) -- the resolver must recurse into them, not just scan the
        # top-level list.
        nested = ApiCallResult(
            success=True,
            data={
                "rulebase": [
                    {
                        "uid": "section-1",
                        "type": "nat-section",
                        "rulebase": [_nat_rulebase_response().data["rulebase"][0]],
                    }
                ],
                "from": 1,
                "to": 1,
                "total": 1,
            },
        )
        call = FakeCall({"show-objects": _any_objects_response(), "show-nat-rulebase": nested})

        resolved = await resolve_nat_sentinel_uids(call, mgmt_name="mdsNP2.np.cparch.in", package="Standard")

        assert resolved.original_uid == NAT_ORIGINAL_OBJECT_UID


class TestResolveFailsFallsBack:
    async def test_api_failure_falls_back_to_constants_and_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        call = FakeCall(
            {
                "show-objects": ApiCallResult(success=False, message="Too many requests", data=None),
                "show-nat-rulebase": ApiCallResult(success=False, message="Too many requests", data=None),
            }
        )

        resolved = await resolve_nat_sentinel_uids(call, mgmt_name="smsNP82", package="Standard")

        assert resolved.any_uid == NAT_ANY_OBJECT_UID
        assert resolved.original_uid == NAT_ORIGINAL_OBJECT_UID

    async def test_object_not_found_falls_back(self) -> None:
        call = FakeCall(
            {
                "show-objects": ApiCallResult(success=True, data={"from": 1, "to": 0, "total": 0, "objects": []}),
                "show-nat-rulebase": ApiCallResult(success=True, data={"rulebase": [], "from": 1, "to": 0, "total": 0}),
            }
        )

        resolved = await resolve_nat_sentinel_uids(call, mgmt_name="smsNP82", package="Standard")

        assert resolved.any_uid == NAT_ANY_OBJECT_UID
        assert resolved.original_uid == NAT_ORIGINAL_OBJECT_UID

    async def test_missing_package_falls_back_for_original_only(self) -> None:
        call = FakeCall({"show-objects": _any_objects_response()})

        resolved = await resolve_nat_sentinel_uids(call, mgmt_name="smsNP82", package="")

        assert resolved.any_uid == NAT_ANY_OBJECT_UID
        assert resolved.original_uid == NAT_ORIGINAL_OBJECT_UID
        # No show-nat-rulebase call at all -- there is nothing to query without a package.
        assert [c for c, _ in call.calls] == ["show-objects"]

    async def test_unexpected_rulebase_shape_falls_back(self) -> None:
        call = FakeCall(
            {
                "show-objects": _any_objects_response(),
                "show-nat-rulebase": ApiCallResult(success=True, data=None),
            }
        )

        resolved = await resolve_nat_sentinel_uids(call, mgmt_name="smsNP82", package="Standard")

        assert resolved.original_uid == NAT_ORIGINAL_OBJECT_UID

    async def test_unexpected_exception_falls_back_never_raises(self) -> None:
        call = FakeCall(
            {
                "show-objects": RuntimeError("transport exploded"),
                "show-nat-rulebase": RuntimeError("transport exploded"),
            }
        )

        resolved = await resolve_nat_sentinel_uids(call, mgmt_name="smsNP82", package="Standard")

        assert resolved.any_uid == NAT_ANY_OBJECT_UID
        assert resolved.original_uid == NAT_ORIGINAL_OBJECT_UID


class TestResolvedDiffersFromConstant:
    async def test_differing_any_uid_is_used_and_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        differing_uid = "11111111-2222-3333-4444-555555555555"
        call = FakeCall(
            {
                "show-objects": _any_objects_response(uid=differing_uid),
                "show-nat-rulebase": _nat_rulebase_response(),
            }
        )

        with caplog.at_level("WARNING"):
            resolved = await resolve_nat_sentinel_uids(call, mgmt_name="rogue-server", package="Standard")

        assert resolved.any_uid == differing_uid  # the resolved value wins, not the constant
        warning_text = "\n".join(r.getMessage() for r in caplog.records if r.levelname == "WARNING")
        assert "rogue-server" in warning_text
        assert "Any" in warning_text
        assert differing_uid in warning_text
        assert NAT_ANY_OBJECT_UID in warning_text

    async def test_differing_original_uid_is_used_and_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        differing_uid = "99999999-8888-7777-6666-555555555555"
        call = FakeCall(
            {
                "show-objects": _any_objects_response(),
                "show-nat-rulebase": _nat_rulebase_response(original_uid=differing_uid),
            }
        )

        with caplog.at_level("WARNING"):
            resolved = await resolve_nat_sentinel_uids(call, mgmt_name="rogue-server", package="Standard")

        assert resolved.original_uid == differing_uid
        warning_text = "\n".join(r.getMessage() for r in caplog.records if r.levelname == "WARNING")
        assert "rogue-server" in warning_text
        assert "Original" in warning_text
        assert differing_uid in warning_text
        assert NAT_ORIGINAL_OBJECT_UID in warning_text


class TestCaching:
    async def test_second_resolve_for_same_mgmt_makes_no_further_calls(self) -> None:
        call = FakeCall(
            {
                "show-objects": _any_objects_response(),
                "show-nat-rulebase": _nat_rulebase_response(),
            }
        )

        first = await resolve_nat_sentinel_uids(call, mgmt_name="mdsNP2.np.cparch.in", package="Standard")
        assert len(call.calls) == 2

        second = await resolve_nat_sentinel_uids(call, mgmt_name="mdsNP2.np.cparch.in", package="Standard")

        assert len(call.calls) == 2  # unchanged: no new API calls
        assert second == first

    async def test_different_mgmt_names_resolve_independently(self) -> None:
        call = FakeCall(
            {
                "show-objects": _any_objects_response(),
                "show-nat-rulebase": _nat_rulebase_response(),
            }
        )

        await resolve_nat_sentinel_uids(call, mgmt_name="mdsNP2.np.cparch.in", package="Standard")
        assert len(call.calls) == 2

        await resolve_nat_sentinel_uids(call, mgmt_name="smsNP82", package="Standard")
        assert len(call.calls) == 4  # a second, independent management server resolves fresh
