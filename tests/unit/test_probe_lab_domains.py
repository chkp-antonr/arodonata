"""Lab-free tests for the per-domain wake-up probe's pure parts."""

from __future__ import annotations

import os

import pytest

from tests.integration.probe_lab_domains import Target, targets_from


def _server(ip, mds, active):
    return {"ipv4-address": ip, "multi-domain-server": mds, "active": active}


def test_targets_pick_each_domains_active_server_and_its_mds_ip():
    domains = {
        "objects": [
            {"name": "General", "servers": [_server("10.0.0.41", "mds-a", True)]},
            {
                "name": "Domain4",
                "servers": [_server("10.0.0.73", "mds-a", False), _server("10.0.0.74", "mds-b", True)],
            },
        ]
    }
    mdss = {"objects": [{"name": "mds-a", "ipv4-address": "10.0.0.40"}, {"name": "mds-b", "ipv4-address": "10.0.0.70"}]}

    assert targets_from(domains, mdss) == [
        Target(domain="General", ip="10.0.0.41", mds="mds-a", mds_ip="10.0.0.40"),
        Target(domain="Domain4", ip="10.0.0.74", mds="mds-b", mds_ip="10.0.0.70"),
    ]


def test_domain_without_an_active_server_is_kept_with_an_empty_ip():
    """A domain with no active server is exactly what the probe must report, not skip."""
    domains = {"objects": [{"name": "Broken", "servers": [_server("10.0.0.9", "mds-a", False)]}]}

    assert targets_from(domains, {"objects": []}) == [Target(domain="Broken", ip="", mds="?", mds_ip="")]


def test_importing_the_script_does_not_load_lab_env_files(monkeypatch):
    """The script reads .env.test with override=True; that must happen in main(), not at import."""
    import importlib

    import tests.integration.probe_lab_domains as mod

    monkeypatch.delenv("API_MGMT", raising=False)
    importlib.reload(mod)
    assert "API_MGMT" not in os.environ


def test_summary_table_has_a_row_per_domain_with_the_step_timings():
    from tests.integration.probe_lab_domains import Result, summary_table

    ok = Result(Target("General", "10.0.0.41", "mds-a", "10.0.0.40"), ok=True, connect_s=0.3, login_s=3.2, call_s=0.4)
    hung = Result(
        Target("Domain4", "10.0.0.74", "mds-b", "10.0.0.70"),
        ok=False,
        connect_s=0.4,
        login_s=120.0,
        detail="TimeoutError: timed out",
    )

    lines = summary_table([ok, hung]).splitlines()

    assert len(lines) == 4  # header, rule, two rows
    assert "General" in lines[2] and "3.2s" in lines[2] and lines[2].endswith("ok")
    assert "Domain4" in lines[3] and "120.0s" in lines[3] and "FAIL: TimeoutError" in lines[3]


@pytest.mark.parametrize("script", ["probe_lab_domains.py", "lab_build.py", "probe_login_throttle.py"])
def test_scripts_start_when_run_directly(script):
    """Run as `uv run tests/integration/<script>`: sys.path[0] is tests/integration, not the repo root.

    Unit tests import these modules as a package, so an import that only works that
    way passes here and breaks for the user. `--help` exits before any lab traffic.
    """
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).parent.parent.parent
    result = subprocess.run(
        [sys.executable, str(root / "tests/integration" / script), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=root,
        env={**os.environ, "ARODONATA_LAB": ""},
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert "usage:" in result.stdout
