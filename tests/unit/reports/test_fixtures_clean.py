"""Change-report fixtures carry lab names and uids only: no credentials, admin names or real addresses."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("*.json"))
FORBIDDEN_KEY = re.compile(
    r'"(sid|api-key|password|meta-info|email|phone-number|ip-address|connected-server|last-login-time)"\s*:'
)
IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
DOC_RANGES = ("192.0.2.", "198.51.100.", "203.0.113.")


def _values(obj: Any, key: str) -> Iterator[Any]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                yield v
            yield from _values(v, key)
    elif isinstance(obj, list):
        for v in obj:
            yield from _values(v, key)


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_no_forbidden_keys(path: Path) -> None:
    assert not FORBIDDEN_KEY.search(path.read_text()), f"{path.name}: trim it with trim_changes"


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_user_name_is_placeholder(path: Path) -> None:
    assert set(_values(json.loads(path.read_text()), "user-name")) <= {"admin"}


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_ipv4_only_documentation_ranges(path: Path) -> None:
    assert all(ip.startswith(DOC_RANGES) for ip in IPV4.findall(path.read_text()))


def test_report_fixtures_present() -> None:
    assert {p.name for p in FIXTURES} >= {
        "w_A_own_sid_0.json",
        "w_A_after_publish_0.json",
        "to_mid_full.json",
        "noparams.json",
        "w_range_from_base.json",
        "d4_assign_session_changes.json",
        "r1_modified_rules_unpublished.json",
        "r1_modified_rules_published.json",
        "r1c_moves_and_members.json",
        "r3_empty_session.json",
        "rule_field_names.json",
    }
