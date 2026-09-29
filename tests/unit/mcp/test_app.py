from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from arodonata.mcp import create_asgi_app, create_mcp_server
from arodonata.mcp.settings import ArodonataMCPConfigError, ArodonataMCPSettings

from .fake_client import FakeArodonataClient

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
}
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
ENV = {"A_TOKEN": "good-token"}


def _settings(
    *, allowed_hosts: str = "testserver", allowed_origins: str = "http://testserver", **kw
) -> ArodonataMCPSettings:
    return ArodonataMCPSettings(
        token_vars="A_TOKEN", allowed_hosts=allowed_hosts, allowed_origins=allowed_origins, **kw
    )


def test_static_mode_refuses_to_start_without_tokens():
    with pytest.raises(ArodonataMCPConfigError):
        create_mcp_server(FakeArodonataClient(), ArodonataMCPSettings(), environ={})  # type: ignore[arg-type]


def test_requests_without_token_are_rejected():
    app = create_asgi_app(
        FakeArodonataClient(), _settings(), server=create_mcp_server(FakeArodonataClient(), _settings(), environ=ENV)
    )  # type: ignore[arg-type]
    with TestClient(app) as c:
        assert c.post("/mcp", json=INIT, headers=HEADERS).status_code == 401
        assert c.post("/mcp", json=INIT, headers=HEADERS | {"Authorization": "Bearer wrong"}).status_code == 401


def test_valid_token_initializes_and_calls_tool():
    fake = FakeArodonataClient()
    server = create_mcp_server(fake, _settings(), environ=ENV)  # type: ignore[arg-type]
    app = create_asgi_app(fake, _settings(), server=server)  # type: ignore[arg-type]
    auth = HEADERS | {"Authorization": "Bearer good-token"}
    with TestClient(app) as c:
        r = c.post("/mcp", json=INIT, headers=auth)
        assert r.status_code == 200 and r.json()["result"]["serverInfo"]["name"] == "arodonata"
        call = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "arodonata_init", "arguments": {}},
        }
        r = c.post("/mcp", json=call, headers=auth)
        assert r.status_code == 200 and r.json()["result"]["isError"] is False
        assert c.get("/.well-known/oauth-protected-resource/mcp").status_code == 200


def test_host_mode_has_no_verifier_and_accepts_anonymous_requests():
    fake = FakeArodonataClient()
    settings = ArodonataMCPSettings(auth_mode="host", allowed_hosts="testserver")
    app = create_asgi_app(fake, settings, server=create_mcp_server(fake, settings, environ={}))  # type: ignore[arg-type]
    with TestClient(app) as c:
        assert c.post("/mcp", json=INIT, headers=HEADERS).status_code == 200


def test_unknown_host_header_is_rejected():
    fake = FakeArodonataClient()
    settings = _settings(allowed_hosts="only.internal")
    app = create_asgi_app(fake, settings, server=create_mcp_server(fake, settings, environ=ENV))  # type: ignore[arg-type]
    with TestClient(app) as c:
        assert c.post("/mcp", json=INIT, headers=HEADERS | {"Authorization": "Bearer good-token"}).status_code == 421


def test_toggles_reach_registry():
    fake = FakeArodonataClient()
    server = create_mcp_server(fake, _settings(cpcrud=True, live_compat=False), environ=ENV)  # type: ignore[arg-type]
    names = {t.name for t in server._tool_manager.list_tools()}  # noqa: SLF001 - no public sync accessor
    assert "cpcrud_plan" in names and "show_services_tcp" not in names


def test_jwt_mode_is_reserved_and_rejected():
    with pytest.raises(ArodonataMCPConfigError, match="jwt"):
        create_mcp_server(FakeArodonataClient(), _settings(auth_mode="jwt"), environ=ENV)  # type: ignore[arg-type]


def test_unauthenticated_get_and_delete_are_rejected_and_trailing_slash_never_authenticates():
    fake = FakeArodonataClient()
    server = create_mcp_server(fake, _settings(), environ=ENV)  # type: ignore[arg-type]
    app = create_asgi_app(fake, _settings(), server=server)  # type: ignore[arg-type]
    with TestClient(app) as c:
        assert c.get("/mcp", headers=HEADERS).status_code == 401
        assert c.delete("/mcp", headers=HEADERS).status_code == 401
        auth = HEADERS | {"Authorization": "Bearer good-token"}
        assert c.post("/mcp/", json=INIT, headers=auth, follow_redirects=False).status_code != 200
