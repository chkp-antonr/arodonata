"""Security guards for the Arodonata MCP server (`arodonata.mcp.security`).

Provides:
- `StaticTokenVerifier`: constant-time (`hmac.compare_digest`) bearer token verification mapping
  the matching environment variable name (`ARODONATA_MCP_TOKEN_VARS`) to `client_id` in logs and
  `AccessToken` without ever logging the token value.
- `host_matches_allowed` and `origin_matches_allowed` helpers.
- `MCPOriginHostGuardMiddleware`: ASGI middleware enforcing DNS rebinding (`Host` -> HTTP `421`)
  and browser `Origin` (`Origin` -> HTTP `403`) protection across all HTTP methods.
- `MCPClientIdContextMiddleware`: ASGI middleware binding the authenticated `client_id` into
  Arodonata's `UserContext` (`contextvars`) for downstream tool calls.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence

import arlogi
from mcp.server.auth.provider import AccessToken, TokenVerifier
from starlette.datastructures import Headers
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from arodonata.core.context import get_user_context, user_context
from arodonata.core.errors import REDACTED_PLACEHOLDER
from arodonata.mcp.config import ArodonataMCPSettings

logger = arlogi.get_logger(__name__)


def _is_valid_port_suffix(port_str: str) -> bool:
    """Return `True` if `port_str` is strictly digits representing a valid TCP port (1..65535)."""
    if not port_str or not port_str.isascii() or not port_str.isdigit():
        return False
    port_num = int(port_str)
    return 1 <= port_num <= 65535


def host_matches_allowed(host: str | None, allowed_hosts: Sequence[str]) -> bool:
    """Return `True` if `host` matches an entry in `allowed_hosts` (supporting `host:*` port wildcards)."""
    if not host:
        return False
    clean_host = host.strip().lower()
    if not clean_host:
        return False

    for raw_allowed in allowed_hosts:
        allowed = raw_allowed.strip().lower()
        if not allowed:
            continue
        if allowed == "*":
            return True
        if clean_host == allowed:
            return True
        if allowed.endswith(":*"):
            base_host = allowed[:-2]
            if clean_host == base_host:
                return True
            if clean_host.startswith(f"{base_host}:"):
                port_part = clean_host[len(base_host) + 1 :]
                if _is_valid_port_suffix(port_part):
                    return True
    return False


def origin_matches_allowed(origin: str | None, allowed_origins: Sequence[str]) -> bool:
    """Return `True` if `origin` is absent or matches an entry in `allowed_origins` (supporting `scheme://host:*`)."""
    if origin is None or not origin.strip():
        return True
    clean_origin = origin.strip().lower()

    for raw_allowed in allowed_origins:
        allowed = raw_allowed.strip().lower()
        if not allowed:
            continue
        if allowed == "*":
            return True
        if clean_origin == allowed:
            return True
        if allowed.endswith(":*"):
            base_origin = allowed[:-2]
            if clean_origin == base_origin:
                return True
            if clean_origin.startswith(f"{base_origin}:"):
                port_part = clean_origin[len(base_origin) + 1 :]
                if _is_valid_port_suffix(port_part):
                    return True
    return False


class StaticTokenVerifier(TokenVerifier):
    """Verifies incoming `Authorization: Bearer <token>` headers in constant time.

    Maps the matching environment variable name from `ARODONATA_MCP_TOKEN_VARS` (e.g.
    `TEAM_A_TOKEN`) to the caller's `client_id` and records `client_id` in structured
    logs without ever logging the token value. Hashes both sides with SHA-256 before
    `hmac.compare_digest` so token length is never leaked via timing (`W26`).
    """

    def __init__(self, token_pairs: Sequence[tuple[str, str]]) -> None:
        self._pairs: list[tuple[str, bytes]] = [
            (client_id.strip(), hashlib.sha256(secret.encode("utf-8")).digest())
            for client_id, secret in token_pairs
            if client_id.strip() and secret
        ]

    @classmethod
    def from_settings(
        cls,
        mcp_settings: ArodonataMCPSettings,
        *,
        environ: dict[str, str] | None = None,
    ) -> StaticTokenVerifier:
        """Build a `StaticTokenVerifier` from `ArodonataMCPSettings`."""
        pairs = mcp_settings.resolve_static_tokens(environ=environ)
        return cls(pairs)

    @property
    def client_ids(self) -> list[str]:
        """Configured `client_id` names (never exposes token secrets)."""
        return [cid for cid, _ in self._pairs]

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify `token` using SHA-256 digest + `hmac.compare_digest` across all configured pairs without early exit."""
        if not token or not self._pairs:
            logger.warning("MCP static bearer token rejected", reason="empty_or_unconfigured")
            return None

        candidate_digest = hashlib.sha256(token.encode("utf-8")).digest()
        matched_client_id: str | None = None

        for client_id, expected_digest in self._pairs:
            is_match = hmac.compare_digest(candidate_digest, expected_digest)
            if is_match and matched_client_id is None:
                matched_client_id = client_id

        if matched_client_id is None:
            logger.warning("MCP static bearer token rejected", reason="invalid_token")
            return None

        logger.info("MCP static bearer token authenticated", client_id=matched_client_id)
        return AccessToken(
            token=REDACTED_PLACEHOLDER,
            client_id=matched_client_id,
            scopes=["mcp"],
        )

    def __repr__(self) -> str:
        return f"StaticTokenVerifier(client_ids={self.client_ids!r})"


class MCPOriginHostGuardMiddleware:
    """ASGI middleware enforcing DNS rebinding (`Host` -> `421`) and browser `Origin` (`Origin` -> `403`) checks."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_hosts: Sequence[str],
        allowed_origins: Sequence[str],
        enabled: bool = True,
    ) -> None:
        self.app = app
        self.allowed_hosts = list(allowed_hosts)
        self.allowed_origins = list(allowed_origins)
        self.enabled = enabled

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        host = headers.get("host")
        if not host_matches_allowed(host, self.allowed_hosts):
            logger.warning("MCP request rejected due to unlisted Host header", host=host or "<missing>")
            response = PlainTextResponse("Invalid Host header", status_code=421)
            await response(scope, receive, send)
            return

        origin = headers.get("origin")
        if not origin_matches_allowed(origin, self.allowed_origins):
            logger.warning("MCP request rejected due to unlisted Origin header", origin=origin)
            response = PlainTextResponse("Invalid Origin header", status_code=403)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


class MCPBearerAuthMiddleware:
    """ASGI middleware enforcing static bearer token authentication and binding `client_id` to `UserContext`."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        verifier: TokenVerifier,
    ) -> None:
        self.app = app
        self.verifier = verifier

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        auth_header = headers.get("authorization", "")
        parts = auth_header.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
            logger.warning("MCP request missing Bearer Authorization header")
            response = PlainTextResponse(
                "Unauthorized",
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return

        raw_token = parts[1].strip()
        access_token = await self.verifier.verify_token(raw_token)
        if access_token is None:
            response = PlainTextResponse(
                "Unauthorized",
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
            await response(scope, receive, send)
            return

        existing_user = get_user_context()
        eff_user_id = (
            existing_user.user_id if existing_user is not None and existing_user.user_id else access_token.client_id
        )
        with user_context(
            user_id=eff_user_id,
            username=existing_user.username if existing_user else None,
            session_name=existing_user.session_name if existing_user else None,
            session_description=existing_user.session_description if existing_user else None,
            client_id=access_token.client_id,
            extra=existing_user.extra if existing_user else None,
        ):
            await self.app(scope, receive, send)


__all__ = [
    "MCPBearerAuthMiddleware",
    "MCPOriginHostGuardMiddleware",
    "StaticTokenVerifier",
    "host_matches_allowed",
    "origin_matches_allowed",
]
