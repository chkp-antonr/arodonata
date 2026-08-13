"""Unit tests for ServerRegistry: address parsing, lookup, and metadata updates."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr

from arodonata.asdk.server_registry import ServerConfig, ServerRegistry


def _make_settings(
    *,
    auth_mode="api_key",
    mgmt_ip=None,
    mgmt_names_list=None,
    mgmt_servers_list=None,
    api_keys_list=None,
):
    settings = MagicMock()
    settings.auth_mode = auth_mode
    settings.mgmt_ip = mgmt_ip
    settings.mgmt_names_list = mgmt_names_list or []
    settings.mgmt_servers_list = mgmt_servers_list or []
    settings.api_keys_list = api_keys_list or []
    return settings


# --------------------------------------------------------------------------
# host:port parsing (via _build_server_map / _parse_server_address)
# --------------------------------------------------------------------------


def test_parses_host_without_port():
    settings = _make_settings(mgmt_names_list=["mgmt1"], mgmt_servers_list=["10.0.0.1"], api_keys_list=["key1"])
    registry = ServerRegistry(settings)
    server = registry.get_server("mgmt1")
    assert server.server_ip == "10.0.0.1"
    assert server.port is None
    assert server.host == "10.0.0.1"


def test_parses_host_with_port():
    settings = _make_settings(mgmt_names_list=["mgmt1"], mgmt_servers_list=["10.0.0.1:4434"], api_keys_list=["key1"])
    registry = ServerRegistry(settings)
    server = registry.get_server("mgmt1")
    assert server.server_ip == "10.0.0.1"
    assert server.port == 4434


def test_parses_host_with_non_numeric_port_treats_whole_string_as_host():
    settings = _make_settings(
        mgmt_names_list=["mgmt1"], mgmt_servers_list=["10.0.0.1:notaport"], api_keys_list=["key1"]
    )
    registry = ServerRegistry(settings)
    server = registry.get_server("mgmt1")
    assert server.server_ip == "10.0.0.1:notaport"
    assert server.port is None


def test_credential_mode_parses_mgmt_ip_with_port():
    settings = _make_settings(auth_mode="credential", mgmt_ip="192.168.1.5:8080")
    registry = ServerRegistry(settings)
    server = registry.get_server("192.168.1.5:8080")
    assert server is not None
    assert server.server_ip == "192.168.1.5"
    assert server.port == 8080
    assert server.api_key.get_secret_value() == ""


def test_server_config_host_property_strips_port_when_stored_with_colon():
    """ServerConfig.host handles a server_ip that itself still has a colon."""
    config = ServerConfig(name="x", server_ip="10.0.0.1:443", api_key=SecretStr("k"))
    assert config.host == "10.0.0.1"


def test_server_config_host_property_returns_as_is_without_colon():
    config = ServerConfig(name="x", server_ip="10.0.0.1", api_key=SecretStr("k"))
    assert config.host == "10.0.0.1"


# --------------------------------------------------------------------------
# get_server / get_names / has_server
# --------------------------------------------------------------------------


def test_get_server_by_name_returns_config():
    settings = _make_settings(
        mgmt_names_list=["mgmt1", "mgmt2"],
        mgmt_servers_list=["10.0.0.1", "10.0.0.2"],
        api_keys_list=["key1", "key2"],
    )
    registry = ServerRegistry(settings)
    server = registry.get_server("mgmt2")
    assert server.name == "mgmt2"
    assert server.server_ip == "10.0.0.2"


def test_get_server_unknown_name_returns_none():
    settings = _make_settings(mgmt_names_list=["mgmt1"], mgmt_servers_list=["10.0.0.1"], api_keys_list=["key1"])
    registry = ServerRegistry(settings)
    assert registry.get_server("does-not-exist") is None


def test_get_names_lists_all_servers_in_order():
    settings = _make_settings(
        mgmt_names_list=["mgmt1", "mgmt2", "mgmt3"],
        mgmt_servers_list=["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        api_keys_list=["k1", "k2", "k3"],
    )
    registry = ServerRegistry(settings)
    assert registry.get_names() == ["mgmt1", "mgmt2", "mgmt3"]


def test_get_names_empty_when_no_servers_configured():
    settings = _make_settings()
    registry = ServerRegistry(settings)
    assert registry.get_names() == []


def test_has_server_true_and_false():
    settings = _make_settings(mgmt_names_list=["mgmt1"], mgmt_servers_list=["10.0.0.1"], api_keys_list=["key1"])
    registry = ServerRegistry(settings)
    assert registry.has_server("mgmt1") is True
    assert registry.has_server("mgmt-nope") is False


def test_mismatched_list_lengths_raise_value_error():
    settings = _make_settings(
        mgmt_names_list=["mgmt1", "mgmt2"],
        mgmt_servers_list=["10.0.0.1"],
        api_keys_list=["key1", "key2"],
    )
    with pytest.raises(ValueError, match="Configuration mismatch"):
        ServerRegistry(settings)


# --------------------------------------------------------------------------
# metadata update (MDM status / version)
# --------------------------------------------------------------------------


async def test_update_metadata_sets_is_mdm_and_version():
    settings = _make_settings(mgmt_names_list=["mgmt1"], mgmt_servers_list=["10.0.0.1"], api_keys_list=["key1"])
    registry = ServerRegistry(settings)

    await registry.update_metadata("mgmt1", is_mdm=True, version="1.9")

    server = registry.get_server("mgmt1")
    assert server.is_mdm is True
    assert server.version == "1.9"


async def test_update_metadata_partial_update_leaves_other_field_untouched():
    settings = _make_settings(mgmt_names_list=["mgmt1"], mgmt_servers_list=["10.0.0.1"], api_keys_list=["key1"])
    registry = ServerRegistry(settings)

    await registry.update_metadata("mgmt1", is_mdm=True, version="1.9")
    await registry.update_metadata("mgmt1", version="2.0")

    server = registry.get_server("mgmt1")
    assert server.is_mdm is True  # unchanged since is_mdm=None was passed
    assert server.version == "2.0"


async def test_update_metadata_unknown_server_is_a_noop():
    settings = _make_settings()
    registry = ServerRegistry(settings)

    # Should not raise even though the server doesn't exist.
    await registry.update_metadata("ghost", is_mdm=True, version="1.0")

    assert registry.get_server("ghost") is None


async def test_update_metadata_false_is_mdm_is_applied():
    """is_mdm=False is a meaningful value (not None) and must be written."""
    settings = _make_settings(mgmt_names_list=["mgmt1"], mgmt_servers_list=["10.0.0.1"], api_keys_list=["key1"])
    registry = ServerRegistry(settings)

    await registry.update_metadata("mgmt1", is_mdm=False, version=None)

    server = registry.get_server("mgmt1")
    assert server.is_mdm is False
    assert server.version is None


# --------------------------------------------------------------------------
# immutability of the view (get_all_servers returns a defensive copy)
# --------------------------------------------------------------------------


def test_get_all_servers_returns_copy_not_internal_dict():
    settings = _make_settings(mgmt_names_list=["mgmt1"], mgmt_servers_list=["10.0.0.1"], api_keys_list=["key1"])
    registry = ServerRegistry(settings)

    servers = registry.get_all_servers()
    servers["injected"] = ServerConfig(name="injected", server_ip="9.9.9.9", api_key=SecretStr(""))

    # Mutating the returned dict must not affect the registry's internal state.
    assert registry.has_server("injected") is False
    assert "injected" not in registry.get_all_servers()


def test_get_names_returns_new_list_each_call():
    settings = _make_settings(mgmt_names_list=["mgmt1"], mgmt_servers_list=["10.0.0.1"], api_keys_list=["key1"])
    registry = ServerRegistry(settings)

    names = registry.get_names()
    names.append("mutated")

    assert registry.get_names() == ["mgmt1"]
