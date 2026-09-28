"""Lab-free tests for the lab profile loader (tests/integration/lab_env.py).

`ARODONATA_LAB=<name>` makes every integration entry point (conftest, the
probe scripts, restore_baseline, lab_build) target another lab by layering
`.env.lab.<name>` on top of `.env.test` and `.env.secrets`. The profile holds
no secrets; it points at them with `${VAR}`, which is why it loads last.
"""

from __future__ import annotations

import os

import pytest

from tests.integration.lab_env import LabProfileMissing, load_lab_env

_VARS = ("API_MGMT", "APIKEY", "HOME_LAB_API_KEY", "TEST_DOMAIN_A", "ARODONATA_LAB")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in _VARS:
        monkeypatch.delenv(name, raising=False)


def _write(root, name, text):
    (root / name).write_text(text)


def test_without_a_profile_loads_test_then_secrets(tmp_path):
    _write(tmp_path, ".env.test", "API_MGMT=10.0.0.1\nAPIKEY=from-test\n")
    _write(tmp_path, ".env.secrets", "APIKEY=from-secrets\n")

    assert load_lab_env(tmp_path) is None
    assert os.environ["API_MGMT"] == "10.0.0.1"
    assert os.environ["APIKEY"] == "from-secrets"


def test_profile_overrides_and_resolves_references_to_secrets(tmp_path, monkeypatch):
    _write(tmp_path, ".env.test", "API_MGMT=10.0.0.1\nTEST_DOMAIN_A=OldA\n")
    _write(tmp_path, ".env.secrets", "APIKEY=old-key\nHOME_LAB_API_KEY=home-key\n")
    _write(tmp_path, ".env.lab.home", "API_MGMT=10.0.0.140\nAPIKEY=${HOME_LAB_API_KEY}\nTEST_DOMAIN_A=Domain4\n")
    monkeypatch.setenv("ARODONATA_LAB", "home")

    assert load_lab_env(tmp_path) == "home"
    assert os.environ["API_MGMT"] == "10.0.0.140"
    assert os.environ["APIKEY"] == "home-key"
    assert os.environ["TEST_DOMAIN_A"] == "Domain4"


def test_profile_file_is_ignored_unless_selected(tmp_path):
    _write(tmp_path, ".env.test", "API_MGMT=10.0.0.1\n")
    _write(tmp_path, ".env.lab.home", "API_MGMT=10.0.0.140\n")

    assert load_lab_env(tmp_path) is None
    assert os.environ["API_MGMT"] == "10.0.0.1"


def test_selected_profile_that_does_not_exist_fails_loudly(tmp_path, monkeypatch):
    """Falling back to the old lab silently would run the suite against the wrong server."""
    _write(tmp_path, ".env.test", "API_MGMT=10.0.0.1\n")
    monkeypatch.setenv("ARODONATA_LAB", "hmoe")

    with pytest.raises(LabProfileMissing, match=r"\.env\.lab\.hmoe"):
        load_lab_env(tmp_path)


def test_profile_selected_in_env_test_itself_is_honoured(tmp_path):
    """VS Code loads .env.test before pytest starts; ARODONATA_LAB may come from there."""
    _write(tmp_path, ".env.test", "ARODONATA_LAB=home\nAPI_MGMT=10.0.0.1\n")
    _write(tmp_path, ".env.lab.home", "API_MGMT=10.0.0.140\n")

    assert load_lab_env(tmp_path) == "home"
    assert os.environ["API_MGMT"] == "10.0.0.140"


# ---------------------------------------------------------------------------
# ARODONATA_TEST_DOMAINS: the domains the suite may snapshot, revert and iterate
# ---------------------------------------------------------------------------
#
# A lab MDS can host domains that belong to someone else (the home MDS carries
# another project's domains). The session snapshot/revert and the
# "every domain" fixtures must stay inside the suite's own domains, or a revert
# at teardown silently undoes someone else's publish.


def test_unset_means_every_domain(monkeypatch):
    from tests.integration.lab_env import allowed_test_domains, is_test_domain

    monkeypatch.delenv("ARODONATA_TEST_DOMAINS", raising=False)
    assert allowed_test_domains() is None
    assert is_test_domain("OtherProjectDomain")


def test_list_is_parsed_and_trimmed(monkeypatch):
    from tests.integration.lab_env import allowed_test_domains, is_test_domain

    monkeypatch.setenv("ARODONATA_TEST_DOMAINS", " General, Domain4 ,,Domain5 ")
    assert allowed_test_domains() == frozenset({"General", "Domain4", "Domain5"})
    assert is_test_domain("Domain4")
    assert not is_test_domain("OtherProjectDomain")


def test_blank_value_means_every_domain(monkeypatch):
    from tests.integration.lab_env import allowed_test_domains

    monkeypatch.setenv("ARODONATA_TEST_DOMAINS", "  ")
    assert allowed_test_domains() is None
