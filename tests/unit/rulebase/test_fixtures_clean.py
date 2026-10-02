"""Recorded fixtures carry lab test names and uids only: no creator names, no addresses, no session data."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("*.json"))
FORBIDDEN = re.compile(
    r'"(meta-info|creator|last-modifier|ipv4-address|ipv6-address|sid|api-key|password|session-uid|user-name|ip-address|email|phone-number|last-login-time|connected-server)"|'
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
)


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_fixture_holds_no_credentials_or_addresses(path: Path) -> None:
    assert not FORBIDDEN.search(path.read_text()), f"{path.name} must be trimmed with trim_recording"


def test_phase1_fixtures_present() -> None:
    names = {p.name for p in FIXTURES}
    assert {
        "domain_layer_fpcr_uat_active_network.json",
        "inline_layer_fpcr_uat_active_inline.json",
        "global_layer_no_package.json",
        "global_layer_with_package.json",
    } <= names


def test_phase2_fixtures_present() -> None:
    names = {p.name for p in FIXTURES}
    assert {
        "packages_domain4_after_assign.json",
        "packages_global.json",
        "paging_access_limit2_offset0.json",
        "paging_access_limit2_offset2.json",
        "paging_access_limit2_offset4.json",
        "paging_nat_limit1_offset0.json",
        "paging_nat_limit1_offset1.json",
        "paging_nat_limit2_offset0.json",
        "paging_nat_limit3_offset0.json",
        "nat_fpcr_uat_active.json",
        "nat_manual_and_auto.json",
        "threat_ips_empty.json",
        "threat_fpcr_uat_active.json",
        "https_inbound_empty.json",
        "https_outbound.json",
        "global_layer_with_package_standard.json",
        "errors_unsupported.json",
        "show_session_clean.json",
        "show_session_dirty.json",
    } <= names
