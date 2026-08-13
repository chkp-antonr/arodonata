"""Tests for ArodonataSettings (pydantic BaseSettings).

CAUTION: ArodonataSettings is a BaseSettings subclass with case_sensitive=False
and no env_prefix, so it can pick up ambient environment variables that match
a field's declared validation_alias (MGMT_NAMES, MGMT_SERVERS, API_KEYS, etc).
Fields whose alias is ARODONATA_-prefixed (username, password, log_level, ...)
are not reachable via their bare field name as an env var — only via their
alias or an explicit constructor kwarg (see ArodonataSettings.__init__). Every
test below either passes explicit kwargs and/or scrubs the relevant env vars
via the autouse `clean_env` fixture so results never depend on the
developer's real shell environment or a stray .env file.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from arodonata.config.settings import ArodonataSettings
from arodonata.core.exceptions import MissingConfigurationError

_ENV_VARS = [
    "MGMT_NAMES",
    "MGMT_SERVERS",
    "API_KEYS",
    "USERNAME",
    "PASSWORD",
    "MGMT_IP",
    "SESSION_EXPIRE_SECONDS",
    "SESSION_TIMEOUT",
    "CONCURRENT_LIMIT",
    "API_TIMEOUT",
    "LOGIN_RETRY_BACKOFF",
    "LOGIN_MAX_RETRIES",
    "LOG_LEVEL",
    "ARODONATA_LOG_LEVEL",
]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Scrub settings-related env vars so tests are isolated from the shell/.env."""
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    yield


class TestDefaults:
    def test_default_construction(self):
        settings = ArodonataSettings()
        assert settings.mgmt_names == ""
        assert settings.mgmt_servers == ""
        assert settings.api_keys == ""
        assert settings.username is None
        assert settings.password is None
        assert settings.mgmt_ip is None
        assert settings.log_level == "INFO"
        assert settings.auth_mode == "api_key"

    def test_default_numeric_settings(self):
        settings = ArodonataSettings()
        assert settings.session_expire_seconds == 3600
        assert settings.session_timeout == 600
        assert settings.concurrent_limit == 3
        assert settings.api_timeout == 120
        assert settings.login_retry_backoff == 5
        assert settings.login_max_retries == 8


class TestCommaSeparatedParsing:
    def test_mgmt_names_list_parses_and_strips(self):
        settings = ArodonataSettings(mgmt_names=" mgmt1 , mgmt2,mgmt3 ")
        assert settings.mgmt_names_list == ["mgmt1", "mgmt2", "mgmt3"]

    def test_mgmt_names_list_empty_string(self):
        settings = ArodonataSettings(mgmt_names="")
        assert settings.mgmt_names_list == []

    def test_mgmt_names_list_drops_empty_items(self):
        settings = ArodonataSettings(mgmt_names="a,,b, ,c")
        assert settings.mgmt_names_list == ["a", "b", "c"]

    def test_mgmt_servers_list(self):
        settings = ArodonataSettings(mgmt_servers="10.0.0.1, 10.0.0.2 ,, 10.0.0.3")
        assert settings.mgmt_servers_list == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_mgmt_servers_list_whitespace_only(self):
        settings = ArodonataSettings(mgmt_servers="   ")
        assert settings.mgmt_servers_list == []

    def test_api_keys_list(self):
        settings = ArodonataSettings(api_keys="key1,key2 , key3")
        assert settings.api_keys_list == ["key1", "key2", "key3"]

    def test_api_keys_list_empty(self):
        settings = ArodonataSettings(api_keys="")
        assert settings.api_keys_list == []


class TestCredentialModeValidation:
    def test_username_and_password_without_mgmt_ip_raises(self):
        with pytest.raises(MissingConfigurationError):
            ArodonataSettings(username="admin", password="secret")

    def test_username_and_password_with_mgmt_ip_ok(self):
        settings = ArodonataSettings(username="admin", password="secret", mgmt_ip="10.0.0.1")
        assert settings.auth_mode == "credential"
        assert settings.mgmt_ip == "10.0.0.1"

    def test_username_only_without_password_is_api_key_mode(self):
        settings = ArodonataSettings(username="admin")
        assert settings.auth_mode == "api_key"

    def test_password_only_without_username_is_api_key_mode(self):
        settings = ArodonataSettings(password="secret")
        assert settings.auth_mode == "api_key"

    def test_api_keys_only_is_api_key_mode(self):
        settings = ArodonataSettings(api_keys="key1,key2")
        assert settings.auth_mode == "api_key"

    def test_password_is_secret_str(self):
        settings = ArodonataSettings(username="admin", password="secret", mgmt_ip="10.0.0.1")
        assert "secret" not in repr(settings.password)
        assert settings.password.get_secret_value() == "secret"


class TestLogLevelValidation:
    """log_level uses validation_alias="ARODONATA_LOG_LEVEL". ArodonataSettings.__init__
    remaps a plain `log_level=` constructor kwarg to that alias before delegating
    to BaseSettings, so both the plain kwarg/attribute name and the
    "ARODONATA_LOG_LEVEL" alias/env var work as input — but a bare `LOG_LEVEL`
    environment variable does not (see ArodonataSettings.__init__'s docstring).
    """

    def test_default_log_level_is_info(self):
        settings = ArodonataSettings()
        assert settings.log_level == "INFO"

    def test_plain_log_level_kwarg_is_accepted_via_init_remap(self):
        settings = ArodonataSettings(log_level="debug")
        assert settings.log_level == "DEBUG"

    def test_valid_log_level_uppercased_via_alias_kwarg(self):
        settings = ArodonataSettings(ARODONATA_LOG_LEVEL="debug")
        assert settings.log_level == "DEBUG"

    def test_invalid_log_level_falls_back_to_info(self):
        settings = ArodonataSettings(ARODONATA_LOG_LEVEL="NOT_A_LEVEL")
        assert settings.log_level == "INFO"

    def test_all_known_levels_accepted(self):
        for level in ("TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            settings = ArodonataSettings(ARODONATA_LOG_LEVEL=level.lower())
            assert settings.log_level == level

    def test_log_level_from_env_alias(self, monkeypatch):
        monkeypatch.setenv("ARODONATA_LOG_LEVEL", "warning")
        settings = ArodonataSettings()
        assert settings.log_level == "WARNING"

    def test_log_level_from_env_alias_invalid_falls_back(self, monkeypatch):
        monkeypatch.setenv("ARODONATA_LOG_LEVEL", "bogus")
        settings = ArodonataSettings()
        assert settings.log_level == "INFO"


class TestFieldConstraints:
    def test_concurrent_limit_below_minimum_raises(self):
        with pytest.raises(ValidationError):
            ArodonataSettings(concurrent_limit=0)

    def test_concurrent_limit_above_maximum_raises(self):
        with pytest.raises(ValidationError):
            ArodonataSettings(concurrent_limit=21)

    def test_concurrent_limit_within_bounds_ok(self):
        settings = ArodonataSettings(concurrent_limit=20)
        assert settings.concurrent_limit == 20

    def test_negative_session_expire_raises(self):
        with pytest.raises(ValidationError):
            ArodonataSettings(session_expire_seconds=-1)

    def test_zero_api_timeout_raises(self):
        with pytest.raises(ValidationError):
            ArodonataSettings(api_timeout=0)


class TestExtraFieldsIgnored:
    def test_unknown_kwarg_is_ignored_not_error(self):
        settings = ArodonataSettings(totally_unknown_field="value")
        assert not hasattr(settings, "totally_unknown_field")
