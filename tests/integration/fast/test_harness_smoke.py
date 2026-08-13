"""Harness smoke tests: env loads, clients log in, baseline snapshot exists.

These stay in the fast tier permanently as canaries; the fast-tier plan
adds the real suite around them.
"""

from pathlib import Path


async def test_apikey_login_and_call(apikey_client):
    """API-key client logs in and a trivial API call succeeds."""
    client, mgmt_name = apikey_client
    result = await client.api_call(mgmt_name, "show-api-versions")
    assert result.success, result.message


async def test_admin_credential_login(admin_client):
    """Credential client (admin) logs in and calls the API."""
    client, mgmt_name = admin_client
    result = await client.api_call(mgmt_name, "show-session")
    assert result.success, result.message


async def test_baseline_snapshot_written(cp_baseline_snapshot):
    """The safety-net baseline file was written before tests started."""
    assert cp_baseline_snapshot is not None, "snapshot skipped — env not loaded?"
    assert Path(cp_baseline_snapshot).exists()
