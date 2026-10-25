"""Unit and ASGI tests for MCP security guards (`StaticTokenVerifier`, `auth_mode="host"`, and DNS rebinding `421`/`403`)."""

from __future__ import annotations

from typing import Any

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from arodonata.core.context import get_user_context
from arodonata.core.errors import REDACTED_PLACEHOLDER, ConfigurationError
from arodonata.mcp import (
    ArodonataMCPSettings,
    MCPBearerAuthMiddleware,
    MCPOriginHostGuardMiddleware,
    StaticTokenVerifier,
    create_asgi_app,
    create_mcp_server,
    host_matches_allowed,
    origin_matches_allowed,
)


@pytest.mark.asyncio
async def test_static_token_verifier_maps_env_var_name_to_client_id_without_logging_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario: Static bearer token authentication maps token variable name (`TEAM_A_TOKEN`) to `client_id`
    and never logs the token secret.
    """
    mcp_settings = ArodonataMCPSettings(
        auth_mode="static",
        token_vars="TEAM_A_TOKEN,TEAM_B_TOKEN",
    )
    env = {
        "TEAM_A_TOKEN": "super-secret-team-a-token-value-111",
        "TEAM_B_TOKEN": "super-secret-team-b-token-value-222",
    }
    verifier = StaticTokenVerifier.from_settings(mcp_settings, environ=env)

    logged_events: list[tuple[str, dict[str, Any]]] = []

    def fake_info(msg: str, **kwargs: Any) -> None:
        logged_events.append((msg, kwargs))

    monkeypatch.setattr("arodonata.mcp.security.logger.info", fake_info)

    token_a = await verifier.verify_token("super-secret-team-a-token-value-111")
    assert token_a is not None
    assert token_a.client_id == "TEAM_A_TOKEN"
    assert token_a.token == REDACTED_PLACEHOLDER

    token_b = await verifier.verify_token("super-secret-team-b-token-value-222")
    assert token_b is not None
    assert token_b.client_id == "TEAM_B_TOKEN"

    invalid = await verifier.verify_token("wrong-token")
    assert invalid is None

    # Verify logs contain `client_id` ("TEAM_A_TOKEN", "TEAM_B_TOKEN") and NEVER the secret token string
    assert len(logged_events) == 2
    assert logged_events[0][1]["client_id"] == "TEAM_A_TOKEN"
    assert logged_events[1][1]["client_id"] == "TEAM_B_TOKEN"
    serialized_logs = repr(logged_events) + repr(verifier)
    assert "super-secret-team-a-token-value-111" not in serialized_logs
    assert "super-secret-team-b-token-value-222" not in serialized_logs


def test_host_auth_mode_disables_internal_token_verifier() -> None:
    """Scenario: Host authentication mode in embedded ASGI applications disables internal token verifier."""
    srv = create_mcp_server(auth_mode="host")
    assert srv._arodonata_token_verifier is None
    assert srv.settings.auth is None

    asgi_app = create_asgi_app(mcp_server=srv, auth_mode="host")
    assert asgi_app.token_verifier is None
    assert asgi_app.mcp_settings.auth_mode == "host"


def test_dns_rebinding_host_421_and_origin_403_protection() -> None:
    """Scenario: Unlisted `Host` header is rejected with HTTP `421` and unlisted `Origin` with HTTP `403`."""

    async def echo_endpoint(_request: Any) -> JSONResponse:
        uctx = get_user_context()
        return JSONResponse({"ok": True, "client_id": uctx.client_id if uctx else None})

    base_starlette = Starlette(routes=[Route("/mcp", echo_endpoint, methods=["GET", "POST"])])
    verifier = StaticTokenVerifier([("TEAM_A_TOKEN", "tok-a-val")])
    authed_app = MCPBearerAuthMiddleware(base_starlette, verifier=verifier)
    guarded_app = MCPOriginHostGuardMiddleware(
        authed_app,
        allowed_hosts=["127.0.0.1:*", "localhost:*"],
        allowed_origins=["http://localhost:*"],
        enabled=True,
    )

    with TestClient(guarded_app) as test_client:
        # 1. Unlisted Host -> HTTP 421 Misdirected Request
        res_bad_host = test_client.post(
            "/mcp",
            headers={"Host": "evil.attacker.internal:8000", "Authorization": "Bearer tok-a-val"},
        )
        assert res_bad_host.status_code == 421

        # 2. Listed Host, unlisted Origin -> HTTP 403 Forbidden
        res_bad_origin = test_client.post(
            "/mcp",
            headers={
                "Host": "localhost:8000",
                "Origin": "https://evil.attacker.example",
                "Authorization": "Bearer tok-a-val",
            },
        )
        assert res_bad_origin.status_code == 403

        # 3. Listed Host & Origin, missing Bearer token -> HTTP 401 Unauthorized
        res_no_auth = test_client.post(
            "/mcp",
            headers={"Host": "localhost:8000", "Origin": "http://localhost:3000"},
        )
        assert res_no_auth.status_code == 401

        # 4. Listed Host & Origin + valid Bearer token -> HTTP 200 and UserContext.client_id bound
        res_ok = test_client.post(
            "/mcp",
            headers={
                "Host": "localhost:8000",
                "Origin": "http://localhost:3000",
                "Authorization": "Bearer tok-a-val",
            },
        )
        assert res_ok.status_code == 200
        assert res_ok.json() == {"ok": True, "client_id": "TEAM_A_TOKEN"}


def test_create_asgi_app_enforces_host_421_and_origin_403() -> None:
    """`create_asgi_app` rejects unlisted `Host` with `421` and unlisted `Origin` with `403`."""
    asgi_app = create_asgi_app(
        auth_mode="host",
        allowed_hosts=["127.0.0.1:*", "localhost:*"],
        allowed_origins=["http://localhost:*"],
    )
    with TestClient(asgi_app) as client:
        r_host = client.post("/mcp", headers={"Host": "rebinding.evil.com"})
        assert r_host.status_code == 421

        r_origin = client.post(
            "/mcp",
            headers={"Host": "localhost:8000", "Origin": "http://evil.com"},
        )
        assert r_origin.status_code == 403


@pytest.mark.asyncio
async def test_base64_padded_tokens_jwt_fail_closed_and_wildcard_port_validation() -> None:
    """Adversarial test for C3 and W26:
    - Base64 token with trailing '=' padding in `ARODONATA_MCP_TOKENS` is kept whole under `token_1`
      (never split into `client_id=<secret_prefix>, secret="="`).
    - `create_mcp_server` and `create_asgi_app` raise `ConfigurationError` when `auth_mode='jwt'` and `token_verifier=None`.
    - `host_matches_allowed` and `origin_matches_allowed` reject non-numeric or out-of-range port suffixes on `:*`.
    """
    b64_token = "c2VjcmV0dG9rZW4xMjM0NTY3ODkwMTIzNDU2Nzg5MDEy=="
    mcp_settings = ArodonataMCPSettings(
        auth_mode="static",
        tokens=[b64_token],
    )
    verifier = StaticTokenVerifier.from_settings(mcp_settings)
    assert verifier.client_ids == ["token_1"]
    assert "c2VjcmV0" not in repr(verifier)

    # Full base64 token authenticates; single '=' is rejected!
    assert await verifier.verify_token("=") is None
    matched = await verifier.verify_token(b64_token)
    assert matched is not None
    assert matched.client_id == "token_1"

    # Embedded JWT mode without token_verifier fails closed immediately
    with pytest.raises(ConfigurationError, match="auth_mode='jwt'"):
        create_mcp_server(auth_mode="jwt", token_verifier=None)

    with pytest.raises(ConfigurationError, match="auth_mode='jwt'"):
        create_asgi_app(auth_mode="jwt", token_verifier=None)

    # Wildcard port validation rejects malformed ports
    assert host_matches_allowed("localhost:8000", ["localhost:*"]) is True
    assert host_matches_allowed("localhost:abc", ["localhost:*"]) is False
    assert host_matches_allowed("localhost:0", ["localhost:*"]) is False
    assert host_matches_allowed("localhost:70000", ["localhost:*"]) is False
    assert host_matches_allowed("localhost:8000:evil", ["localhost:*"]) is False

    assert origin_matches_allowed("http://localhost:3000", ["http://localhost:*"]) is True
    assert origin_matches_allowed("http://localhost:notaport", ["http://localhost:*"]) is False
    assert origin_matches_allowed("http://localhost:99999", ["http://localhost:*"]) is False
