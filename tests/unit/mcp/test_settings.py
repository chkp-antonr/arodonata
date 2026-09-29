from __future__ import annotations

import pytest

from arodonata.mcp.settings import ArodonataMCPSettings


def test_defaults():
    s = ArodonataMCPSettings()
    assert (s.host, s.port, s.path) == ("127.0.0.1", 8765, "/mcp")
    assert s.public_url == "http://127.0.0.1:8765/mcp"
    assert s.stateless is True and s.json_response is True
    assert s.live_compat is True and s.cpcrud is False and s.allow_write_api is False
    assert s.auth_mode == "static" and s.token_vars == ""
    assert s.default_limit == 50 and s.max_result_chars == 200_000


def test_env_prefix(monkeypatch):
    monkeypatch.setenv("ARODONATA_MCP_PORT", "9000")
    monkeypatch.setenv("ARODONATA_MCP_CPCRUD", "true")
    monkeypatch.setenv("ARODONATA_MCP_TOKEN_VARS", "ALICE_TOKEN, BOB_TOKEN,")
    s = ArodonataMCPSettings()
    assert s.port == 9000 and s.cpcrud is True
    assert s.token_var_names == ["ALICE_TOKEN", "BOB_TOKEN"]


def test_unprefixed_env_is_ignored(monkeypatch):
    monkeypatch.setenv("PORT", "1")
    assert ArodonataMCPSettings().port == 8765


def test_invalid_auth_mode_rejected():
    with pytest.raises(ValueError):
        ArodonataMCPSettings(auth_mode="oauth")  # type: ignore[arg-type]


def test_path_must_start_with_slash():
    with pytest.raises(ValueError):
        ArodonataMCPSettings(path="mcp")


def test_allowed_hosts_and_origins_derive_from_public_url():
    s = ArodonataMCPSettings(host="0.0.0.0", port=8765, public_url="https://mcp.example.com/mcp")
    assert {"mcp.example.com", "0.0.0.0:8765", "127.0.0.1:8765"} <= set(s.allowed_hosts_list)
    assert "https://mcp.example.com" in s.allowed_origins_list
    explicit = ArodonataMCPSettings(allowed_hosts="a.internal:443, b.internal", allowed_origins="https://a.internal")
    assert explicit.allowed_hosts_list == ["a.internal:443", "b.internal"] and explicit.allowed_origins_list == [
        "https://a.internal"
    ]
