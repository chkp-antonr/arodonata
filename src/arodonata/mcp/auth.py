"""Bearer-token verification for the MCP HTTP transport."""

from __future__ import annotations

import hmac
import os
from collections.abc import Mapping

from pydantic import SecretStr

from ._sdk import AccessToken, TokenVerifier
from .settings import ArodonataMCPConfigError, ArodonataMCPSettings


class StaticTokenVerifier:
    """Constant-time comparison against tokens resolved from named environment variables."""

    def __init__(self, tokens: Mapping[str, SecretStr]) -> None:
        self._tokens = dict(tokens)

    def __repr__(self) -> str:
        return f"StaticTokenVerifier(names={sorted(self._tokens)})"

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        for name, secret in self._tokens.items():
            if hmac.compare_digest(secret.get_secret_value().encode(), token.encode()):
                return AccessToken(token=token, client_id=name, scopes=[])
        return None


class JwtTokenVerifier:
    """Reserved: JWT verification against an identity provider (see spec, 'Reserved JWT mode')."""

    def __init__(self, issuer: str, audience: str, jwks_url: str) -> None:
        self.issuer, self.audience, self.jwks_url = issuer, audience, jwks_url

    async def verify_token(self, token: str) -> AccessToken | None:
        raise NotImplementedError(
            "JWT verification is reserved but not implemented; see docs/superpowers/specs/2026-09-27-mcp-server-design.md"
        )


def build_token_verifier(
    settings: ArodonataMCPSettings, environ: Mapping[str, str] | None = None
) -> TokenVerifier | None:
    """Return the verifier for ``settings.auth_mode``; ``None`` only for ``host`` mode."""
    env = os.environ if environ is None else environ
    if settings.auth_mode == "host":
        return None
    if settings.auth_mode == "jwt":
        return JwtTokenVerifier(settings.jwt_issuer, settings.jwt_audience, settings.jwt_jwks_url)
    tokens = {name: SecretStr(env[name].strip()) for name in settings.token_var_names if env.get(name, "").strip()}
    if not tokens:
        raise ArodonataMCPConfigError(
            "auth_mode=static requires at least one non-empty token; set ARODONATA_MCP_TOKEN_VARS to a "
            "comma-separated list of environment variable names holding bearer tokens"
        )
    return StaticTokenVerifier(tokens)
