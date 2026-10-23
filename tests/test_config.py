"""Unit tests for ArodonataSettings configuration resolution and topology validation."""

from __future__ import annotations

import pytest

from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import (
    REDACTED_PLACEHOLDER,
    ConfigurationError,
    MissingConfigurationError,
)
from arodonata.core.telemetry import set_trace_modules


def test_constructor_kwarg_overrides_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructor keyword argument must override ARODONATA_* environment variable."""
    monkeypatch.setenv("ARODONATA_CONCURRENT_LIMIT", "4")
    settings = ArodonataSettings(concurrent_limit=8)
    assert settings.concurrent_limit == 8
    assert settings.domain_sync_concurrency == 7


def test_env_var_populates_field_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Environment variable populates field when omitted from constructor."""
    monkeypatch.setenv("ARODONATA_SESSION_TIMEOUT", "900")
    settings = ArodonataSettings()
    assert settings.session_timeout == 900


def test_positional_topology_via_api_key_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Positional MGMT_NAMES, MGMT_SERVERS, and API_KEY_VARS resolve and pair by index."""
    monkeypatch.setenv("MGMT_NAMES", "mds1,sms2")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1,10.0.0.2:8443")
    monkeypatch.setenv("API_KEY_VARS", "KEY_MDS1,KEY_MDS2")
    monkeypatch.setenv("KEY_MDS1", "secret1")
    monkeypatch.setenv("KEY_MDS2", "secret2")

    settings = ArodonataSettings()
    assert settings.mgmt_names == ["mds1", "sms2"]
    assert settings.mgmt_servers == ["10.0.0.1", "10.0.0.2:8443"]
    assert settings.api_keys == ["secret1", "secret2"]
    assert settings.auth_mode == "api_key"

    servers = settings.servers
    assert servers["mds1"].host == "10.0.0.1"
    assert servers["mds1"].port == 443
    assert servers["mds1"].api_key == "secret1"
    assert servers["sms2"].host == "10.0.0.2"
    assert servers["sms2"].port == 8443
    assert servers["sms2"].api_key == "secret2"

    # Secret hygiene: repr must never expose api_keys
    assert "secret1" not in repr(settings)
    assert "secret2" not in repr(settings)
    assert "secret1" not in repr(servers["mds1"])
    assert REDACTED_PLACEHOLDER in repr(servers["mds1"])


def test_api_keys_precedence_over_api_key_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit API_KEYS must take precedence over API_KEY_VARS."""
    monkeypatch.setenv("MGMT_NAMES", "mds1,sms2")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1,10.0.0.2")
    monkeypatch.setenv("API_KEYS", "explicit_k1,explicit_k2")
    monkeypatch.setenv("API_KEY_VARS", "KEY_MDS1,KEY_MDS2")
    monkeypatch.setenv("KEY_MDS1", "var_k1")
    monkeypatch.setenv("KEY_MDS2", "var_k2")

    settings = ArodonataSettings()
    assert settings.api_keys == ["explicit_k1", "explicit_k2"]
    assert settings.servers["mds1"].api_key == "explicit_k1"
    assert settings.servers["sms2"].api_key == "explicit_k2"


def test_mismatched_server_and_key_counts_raises() -> None:
    """Mismatched counts across mgmt_names, mgmt_servers, and api_keys raise ConfigurationError."""
    with pytest.raises(ConfigurationError, match="Mismatched"):
        ArodonataSettings(
            mgmt_names=["mds1", "sms2"],
            mgmt_servers=["10.0.0.1", "10.0.0.2"],
            api_keys=["only_one_key"],
        )

    with pytest.raises(ConfigurationError, match="Mismatched"):
        ArodonataSettings(
            mgmt_names=["mds1"],
            mgmt_servers=["10.0.0.1", "10.0.0.2"],
        )


def test_credential_mode_validation() -> None:
    """Credential mode requires target server IP/topology and both username and password."""
    with pytest.raises(MissingConfigurationError, match="management server address"):
        ArodonataSettings(username="admin", password="secret_password")

    with pytest.raises(MissingConfigurationError, match="username and password"):
        ArodonataSettings(mgmt_ip="10.0.0.1", username="admin")

    settings = ArodonataSettings(mgmt_ip="10.0.0.1", username="admin", password="secret_password")
    assert settings.auth_mode == "credential"
    assert settings.mgmt_servers == ["10.0.0.1"]
    assert settings.mgmt_names == ["10.0.0.1"]
    assert "secret_password" not in repr(settings)


def test_dynamic_mode_initializes_without_static_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Servers configured without static API keys or credentials resolve auth_mode == 'dynamic'."""
    monkeypatch.setenv("MGMT_NAMES", "mds1")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1")

    settings = ArodonataSettings()
    assert settings.auth_mode == "dynamic"
    assert settings.mgmt_names == ["mds1"]
    assert settings.mgmt_servers == ["10.0.0.1"]
    assert settings.servers["mds1"].api_key is None


def test_timeout_budgets_and_read_timeout_calculation() -> None:
    """Verify separate timeout budgets and socket read timeout calculation."""
    settings = ArodonataSettings()
    assert settings.connect_timeout == 30.0
    assert settings.api_timeout == 120.0
    assert settings.login_timeout == 120.0
    assert settings.task_timeout == 900.0
    assert settings.rate_limit_slot_timeout == 90.0

    # Explicit per-call budget adds 5s
    assert settings.resolve_read_timeout(45.0) == 50.0
    # Unspecified per-call budget uses max(api_timeout, login_timeout) + 5s
    assert settings.resolve_read_timeout(None) == 125.0


def test_trace_modules_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify ARODONATA_TRACE_MODULES parsing and host tracing rule preservation."""
    import arlogi.otel.decorator as otel_dec

    set_trace_modules({"existing.host": False})
    try:
        default_settings = ArodonataSettings()
        assert default_settings.trace_modules == ""
        assert default_settings.trace_modules_rules == {}
        default_settings.configure_tracing()
        # Host rules must remain untouched when trace_modules is empty
        assert otel_dec._trace_modules == {"existing.host": False}

        monkeypatch.setenv("ARODONATA_TRACE_MODULES", "arodonata:on,arodonata.api.client:off")
        configured = ArodonataSettings()
        assert configured.trace_modules_rules == {
            "arodonata": True,
            "arodonata.api.client": False,
        }
        configured.configure_tracing()
        assert otel_dec._trace_modules == {
            "arodonata": True,
            "arodonata.api.client": False,
        }
    finally:
        set_trace_modules(None)
