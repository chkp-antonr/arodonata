from __future__ import annotations

import pytest
from pydantic import SecretStr

from arodonata.mcp.auth import JwtTokenVerifier, StaticTokenVerifier, build_token_verifier
from arodonata.mcp.settings import ArodonataMCPConfigError, ArodonataMCPSettings


async def test_static_verifier_accepts_known_token_and_reports_var_name():
    v = StaticTokenVerifier({"ALICE_TOKEN": SecretStr("s3cret-a"), "BOB_TOKEN": SecretStr("s3cret-b")})
    tok = await v.verify_token("s3cret-b")
    assert tok is not None and tok.client_id == "BOB_TOKEN" and tok.scopes == []


async def test_static_verifier_rejects_unknown_and_empty():
    v = StaticTokenVerifier({"ALICE_TOKEN": SecretStr("s3cret-a")})
    assert await v.verify_token("nope") is None
    assert await v.verify_token("") is None


def test_build_static_resolves_env_vars():
    s = ArodonataMCPSettings(token_vars="A_TOKEN,B_TOKEN")
    v = build_token_verifier(s, environ={"A_TOKEN": "aaa", "B_TOKEN": "bbb"})
    assert isinstance(v, StaticTokenVerifier)


def test_build_static_fails_closed_without_tokens():
    with pytest.raises(ArodonataMCPConfigError, match="ARODONATA_MCP_TOKEN_VARS"):
        build_token_verifier(ArodonataMCPSettings(token_vars=""), environ={})
    with pytest.raises(ArodonataMCPConfigError):
        build_token_verifier(ArodonataMCPSettings(token_vars="A_TOKEN"), environ={"A_TOKEN": "   "})


def test_build_host_mode_returns_none():
    assert build_token_verifier(ArodonataMCPSettings(auth_mode="host"), environ={}) is None


async def test_jwt_mode_is_reserved():
    s = ArodonataMCPSettings(
        auth_mode="jwt", jwt_issuer="https://idp", jwt_audience="mcp", jwt_jwks_url="https://idp/jwks"
    )
    v = build_token_verifier(s, environ={})
    assert isinstance(v, JwtTokenVerifier)
    with pytest.raises(NotImplementedError):
        await v.verify_token("x")


def test_static_repr_hides_secrets():
    v = StaticTokenVerifier({"A": SecretStr("topsecret")})
    assert "topsecret" not in repr(v)
