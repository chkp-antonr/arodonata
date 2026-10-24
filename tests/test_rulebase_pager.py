"""Unit tests for `arodonata.rulebase.pager` (`fetch_paged_rulebase`)."""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Any

import pytest

from arodonata.core.context import AuthContext
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.rulebase.pager import fetch_paged_rulebase


class PagerFakeApi:
    """In-memory `ApiPort` double simulating multi-page `show-*-rulebase` responses."""

    def __init__(self, pages_by_offset: dict[int, dict[str, Any]]) -> None:
        self.pages_by_offset = pages_by_offset
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
        offset = int(req.get("offset") or 0)
        page_data = self.pages_by_offset.get(offset, {"rulebase": [], "total": 0})
        return ApiCallResult(success=True, data=page_data)

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
async def test_rulebase_pager_merges_split_sections_and_recovers_empty_trailing_sections() -> None:
    """When Check Point repeats a `rulebase-section` header across two pages, `fetch_paged_rulebase` merges it into one section and preserves empty trailing sections."""
    pages = {
        0: {
            "uid": "layer-net-1",
            "name": "Network",
            "from": 1,
            "to": 2,
            "total": 3,
            "objects-dictionary": [
                {"uid": "obj-h1", "name": "web-srv-01", "type": "host"},
                {"uid": "obj-net1", "name": "internal-net", "type": "network"},
                {"uid": "svc-https", "name": "https", "type": "service-tcp"},
                {"uid": "act-accept", "name": "Accept", "type": "RulebaseAction"},
            ],
            "rulebase": [
                {
                    "uid": "sec-dmz",
                    "name": "DMZ Traffic",
                    "type": "access-section",
                    "from": 1,
                    "to": 2,
                    "rulebase": [
                        {
                            "uid": "r-1",
                            "name": "Allow Web",
                            "type": "access-rule",
                            "rule-number": 1,
                            "enabled": True,
                            "source": ["obj-net1"],
                            "destination": ["obj-h1"],
                            "service": ["svc-https"],
                            "action": "act-accept",
                        },
                        {
                            "uid": "r-2",
                            "name": "Allow Admin",
                            "type": "access-rule",
                            "rule-number": 2,
                            "enabled": True,
                            "source": ["obj-net1"],
                            "destination": ["obj-h1"],
                            "service": ["svc-https"],
                            "action": "act-accept",
                        },
                    ],
                }
            ],
        },
        2: {
            "uid": "layer-net-1",
            "name": "Network",
            "from": 3,
            "to": 3,
            "total": 3,
            "objects-dictionary": [
                {"uid": "act-drop", "name": "Drop", "type": "RulebaseAction"},
            ],
            "rulebase": [
                {
                    # Repeated section header on page 2!
                    "uid": "sec-dmz",
                    "name": "DMZ Traffic",
                    "type": "access-section",
                    "from": 3,
                    "to": 3,
                    "rulebase": [
                        {
                            "uid": "r-3",
                            "name": "Cleanup DMZ",
                            "type": "access-rule",
                            "rule-number": 3,
                            "enabled": False,
                            "action": "act-drop",
                        }
                    ],
                },
                {
                    # Empty trailing section!
                    "uid": "sec-empty-tail",
                    "name": "Future Rules",
                    "type": "access-section",
                    "rulebase": [],
                },
            ],
        },
    }

    api = PagerFakeApi(pages)
    res = await fetch_paged_rulebase(
        api,
        "mds1",
        "Corp",
        rulebase_type="access",
        layer_uid="layer-net-1",
        limit=2,
    )

    assert len(api.calls) == 2
    assert api.calls[0][1]["limit"] == 2
    assert api.calls[0][1]["offset"] == 0
    assert api.calls[1][1]["offset"] == 2

    # Split section was merged into a single section entry containing all 3 rules in order
    assert len(res.sections) == 2
    dmz_sec = res.sections[0]
    assert dmz_sec.uid == "sec-dmz"
    assert dmz_sec.name == "DMZ Traffic"
    assert dmz_sec.rule_uids == ["r-1", "r-2", "r-3"]
    assert dmz_sec.from_rule == 1
    assert dmz_sec.to_rule == 3

    # Empty trailing section recovered
    empty_sec = res.sections[1]
    assert empty_sec.uid == "sec-empty-tail"
    assert empty_sec.name == "Future Rules"
    assert empty_sec.rule_uids == []
    assert empty_sec.from_rule is None
    assert empty_sec.to_rule is None

    # All 3 rules parsed in order with objects-dictionary references resolved
    assert [r.uid for r in res.access_rules] == ["r-1", "r-2", "r-3"]
    assert res.access_rules[0].source == ["internal-net"]
    assert res.access_rules[0].destination == ["web-srv-01"]
    assert res.access_rules[0].service == ["https"]
    assert res.access_rules[0].action == "Accept"
    assert res.access_rules[2].action == "Drop"
    assert res.access_rules[2].enabled is False


@pytest.mark.asyncio
async def test_rulebase_pager_trailing_probe_recovers_empty_section_after_exact_page_boundary() -> None:
    """When `total` rules equals `limit` (e.g. 2 rules with `limit=2`), the pager performs a trailing probe and recovers an empty section at `offset=2`."""
    pages = {
        0: {
            "uid": "layer-1",
            "name": "Layer 1",
            "from": 1,
            "to": 2,
            "total": 2,
            "rulebase": [
                {
                    "uid": "sec-1",
                    "name": "Main Section",
                    "type": "access-section",
                    "from": 1,
                    "to": 2,
                    "rulebase": [
                        {"uid": "r1", "name": "Rule 1", "type": "access-rule"},
                        {"uid": "r2", "name": "Rule 2", "type": "access-rule"},
                    ],
                }
            ],
        },
        2: {
            "uid": "layer-1",
            "name": "Layer 1",
            "from": 0,
            "to": 0,
            "total": 2,
            "rulebase": [
                {
                    "uid": "sec-2-empty",
                    "name": "Empty Trailing Section",
                    "type": "access-section",
                    "rulebase": [],
                }
            ],
        },
    }

    api = PagerFakeApi(pages)
    res = await fetch_paged_rulebase(
        api,
        "mds1",
        "Corp",
        rulebase_type="access",
        layer_uid="layer-1",
        limit=2,
    )
    assert [s.uid for s in res.sections] == ["sec-1", "sec-2-empty"]
    assert res.sections[1].rule_uids == []
    assert [r.uid for r in res.access_rules] == ["r1", "r2"]
