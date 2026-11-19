"""Credential resolution, SID freshness checks, and Check Point login payload builder."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from arodonata.core.config import ArodonataSettings, ServerEndpointConfig
from arodonata.core.context import SYSTEM_DOMAIN_KEY, AuthContext, get_auth_context, get_user_context
from arodonata.core.errors import InvalidCredentialsError, MissingConfigurationError
from arodonata.core.models.common import ApiCallResult
from arodonata.core.models.domains import SIDCacheEntry
from arodonata.core.ports import AuthProvider, SidCachePort


def build_login_payload(
    *,
    session_timeout: int,
    auth: AuthContext,
    dom_key: str,
    session_name: str | None = None,
    session_description: str | None = None,
    read_only: bool = False,
) -> dict[str, Any]:
    """Construct the JSON payload for a Check Point Web API `login` call."""
    payload: dict[str, Any] = {
        "session-timeout": session_timeout,
    }
    if auth.api_key:
        payload["api-key"] = auth.api_key
    else:
        payload["user"] = auth.username
        payload["password"] = auth.password

    if dom_key != SYSTEM_DOMAIN_KEY:
        payload["domain"] = dom_key
    if session_name:
        payload["session-name"] = session_name
    if session_description:
        payload["session-description"] = session_description
    if read_only:
        payload["read-only"] = True
    return payload


async def resolve_auth_credentials(
    *,
    mgmt_name: str,
    domain: str | None,
    settings: ArodonataSettings,
    endpoint: ServerEndpointConfig,
    auth_provider: AuthProvider | None,
    evicted_identities: set[tuple[str, str]],
    explicit_auth: AuthContext | None = None,
) -> AuthContext:
    """Resolve authentication credentials from explicit override, `contextvars`, `AuthProvider`, or static settings."""
    if explicit_auth is not None:
        if (mgmt_name, explicit_auth.identity_key) in evicted_identities:
            raise InvalidCredentialsError(
                f"Credentials for {explicit_auth.identity_key!r} on {mgmt_name!r} were previously rejected and evicted."
            )
        return explicit_auth

    ctx_auth = get_auth_context()
    if ctx_auth is not None:
        if (mgmt_name, ctx_auth.identity_key) in evicted_identities:
            raise InvalidCredentialsError(
                f"Credentials for {ctx_auth.identity_key!r} on {mgmt_name!r} were previously rejected and evicted."
            )
        return ctx_auth

    if auth_provider is not None:
        user_ctx = get_user_context()
        provided = await auth_provider.get_credentials(mgmt_name, domain, user=user_ctx)
        if (mgmt_name, provided.identity_key) in evicted_identities:
            raise InvalidCredentialsError(
                f"Credentials for {provided.identity_key!r} on {mgmt_name!r} were previously rejected and evicted."
            )
        return provided

    if endpoint.api_key:
        return AuthContext(api_key=endpoint.api_key, user_id=f"static:{mgmt_name}")
    if settings.username and settings.password:
        return AuthContext(
            username=settings.username,
            password=settings.password,
            user_id=f"static:{settings.username}",
        )

    raise MissingConfigurationError(
        f"No credentials available for management server {mgmt_name!r} in auth_mode={settings.auth_mode!r}. "
        "Provide credentials via client.auth_context(...), AuthProvider, or static settings."
    )


def is_sid_entry_fresh(
    entry: SIDCacheEntry,
    *,
    now: datetime,
    session_expire_seconds: float,
) -> bool:
    """Return `True` if `entry` is younger than `session_expire_seconds` and not past `expires_at`."""
    if entry.expires_at is not None and now >= entry.expires_at:
        return False
    age = (now - entry.created_at).total_seconds()
    return age < float(session_expire_seconds)


def is_sid_entry_usable(
    entry: SIDCacheEntry,
    auth: AuthContext,
    *,
    now: datetime,
    session_expire_seconds: float,
) -> bool:
    """Return `True` if `entry` is fresh and belongs to the exact same `auth.identity_key` (`C4`)."""
    if not is_sid_entry_fresh(entry, now=now, session_expire_seconds=session_expire_seconds):
        return False
    if not entry.auth_identity:
        return False
    return entry.auth_identity == auth.identity_key


async def handle_invalid_credentials(
    *,
    mgmt_name: str,
    dom_key: str,
    auth: AuthContext,
    res: ApiCallResult,
    cache: SidCachePort,
    settings: ArodonataSettings,
    auth_provider: AuthProvider | None,
    evicted_identities: set[tuple[str, str]],
) -> None:
    """Evict cached SID and credentials, notify `AuthProvider`, and raise `InvalidCredentialsError`."""
    await cache.evict_sid(mgmt_name, dom_key, auth_identity=auth.identity_key)
    if settings.auth_mode == "dynamic" or get_auth_context() is not None or auth_provider is not None:
        evicted_identities.add((mgmt_name, auth.identity_key))

    exc = InvalidCredentialsError(
        f"Authentication to {mgmt_name!r} ({dom_key!r}) rejected by server: "
        f"{res.error_message or 'Authentication to server failed'}"
    )
    if auth_provider is not None:
        await auth_provider.on_auth_failed(mgmt_name, auth, exc)
    raise exc


__all__ = [
    "build_login_payload",
    "handle_invalid_credentials",
    "is_sid_entry_fresh",
    "is_sid_entry_usable",
    "resolve_auth_credentials",
]
