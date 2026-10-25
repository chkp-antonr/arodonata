"""Bucket 1 smoke test: verify the integration harness itself works against the live lab.

Checks:
1. ``cp_baseline_snapshot`` captured non-empty session UIDs for ``TEST_DOMAIN_A`` and ``TEST_DOMAIN_B``
   and persisted ``_tmp/cp_baseline.json``.
2. ``all_domains`` discovered the live MDS domains via ``apikey_client.get_domains``.
3. ``apikey_client`` can issue a read-only ``show-session`` in ``TEST_DOMAIN_A`` and reuses the
   cached SID on a second call.
"""

from __future__ import annotations

from arodonata import ArodonataClient
from tests.integration.conftest import BASELINE_FILE
from tests.integration.cp_revision import BaselineSnapshot


async def test_baseline_snapshot_captured(
    cp_baseline_snapshot: BaselineSnapshot,
    test_domain_a: str,
    test_domain_b: str,
) -> None:
    """Verify session-scoped baseline snapshot is captured and written to disk."""
    assert test_domain_a in cp_baseline_snapshot.domains
    assert test_domain_b in cp_baseline_snapshot.domains
    assert len(cp_baseline_snapshot.domains[test_domain_a].session_uid) == 36
    assert len(cp_baseline_snapshot.domains[test_domain_b].session_uid) == 36
    assert BASELINE_FILE.exists()


async def test_all_domains_discovered(
    all_domains: list[str],
    test_domain_a: str,
    test_domain_b: str,
) -> None:
    """Verify domain discovery lists sandbox domains and excludes Global by default."""
    assert test_domain_a in all_domains
    assert test_domain_b in all_domains
    assert "Global" not in all_domains


async def test_apikey_client_reuses_cached_sid(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``apikey_client`` caches and reuses the read-only SID across consecutive calls."""
    r1 = await apikey_client.api_call(mgmt_name, "show-session", {}, domain=test_domain_a)
    r2 = await apikey_client.api_call(mgmt_name, "show-session", {}, domain=test_domain_a)
    assert r1.success and r2.success
    assert r1.data["uid"] == r2.data["uid"]
