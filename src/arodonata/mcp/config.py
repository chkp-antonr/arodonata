"""Configuration and startup validation for the Arodonata MCP server (`arodonata.mcp.config`)."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING, Annotated, Any, Literal

import arlogi
from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from arodonata.core.config import ArodonataSettings, _split_csv
from arodonata.core.errors import REDACTED_PLACEHOLDER, ConfigurationError

if TYPE_CHECKING:
    from arodonata.client import TrustPolicy

logger = arlogi.get_logger(__name__)

MCPAuthMode = Literal["static", "host", "jwt", "none"]
MIN_STATIC_TOKEN_LENGTH: int = 32
_CLIENT_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")

CsvStrList = Annotated[list[str], NoDecode]

LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})


def is_loopback_host(host: str) -> bool:
    """Return `True` if `host` is a local loopback address (`127.0.0.1`, `localhost`, or `::1`)."""
    clean = host.strip().lower()
    if clean.startswith("[") and clean.endswith("]"):
        clean = clean[1:-1]
    if not clean:
        return False
    if clean == "localhost":
        return True
    with contextlib.suppress(ValueError):
        clean = ipaddress.ip_address(clean).compressed
    return clean in LOOPBACK_HOSTS


def _extract_host_from_pattern(raw: str) -> str:
    """Extract normalized host token from a `Host` or `Origin` allowlist entry."""
    cleaned = raw.strip().lower()
    if not cleaned:
        return ""
    host_part = cleaned.partition("://")[2] if "://" in cleaned else cleaned
    host_part = host_part.split("/", 1)[0]
    if host_part.startswith("["):
        end_bracket = host_part.find("]")
        return host_part[1:end_bracket] if end_bracket != -1 else host_part.lstrip("[")
    if host_part.count(":") >= 2:
        return host_part
    if ":" in host_part:
        return host_part.rsplit(":", 1)[0]
    return host_part


def _has_wildcard_entry(entries: Sequence[str]) -> bool:
    """Return `True` if any host or origin pattern uses a hostname wildcard (e.g. `*`, `http://*`, `*.domain`).

    Explicit host port-wildcards such as `127.0.0.1:*`, `localhost:*`, `[::1]:*`, and
    `http://localhost:*` are permitted.
    """
    for raw in entries:
        if not raw.strip():
            continue
        host_part = _extract_host_from_pattern(raw)
        if not host_part or "*" in host_part:
            return True
    return False


def _has_non_loopback_entry(entries: Sequence[str]) -> bool:
    """Return `True` if any non-empty allowlist entry targets a non-loopback host."""
    for raw in entries:
        if not raw.strip():
            continue
        host_part = _extract_host_from_pattern(raw)
        if not is_loopback_host(host_part):
            return True
    return False


DEFAULT_ALLOWED_HOSTS: tuple[str, ...] = (
    "127.0.0.1:*",
    "localhost:*",
    "[::1]:*",
    "127.0.0.1",
    "localhost",
    "[::1]",
)

DEFAULT_ALLOWED_ORIGINS: tuple[str, ...] = (
    "http://127.0.0.1:*",
    "http://localhost:*",
    "http://[::1]:*",
    "https://127.0.0.1:*",
    "https://localhost:*",
    "https://[::1]:*",
)


class ArodonataMCPSettings(BaseSettings):
    """Type-safe configuration for the Arodonata MCP server (`ARODONATA_MCP_*`).

    Never loads `.env` files implicitly.
    """

    model_config = SettingsConfigDict(
        env_prefix="ARODONATA_MCP_",
        env_file=None,
        extra="ignore",
        populate_by_name=True,
    )

    host: str = Field(
        default="127.0.0.1",
        validation_alias=AliasChoices("host", "ARODONATA_MCP_HOST"),
    )
    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        validation_alias=AliasChoices("port", "ARODONATA_MCP_PORT"),
    )
    path: str = Field(
        default="/mcp",
        validation_alias=AliasChoices("path", "ARODONATA_MCP_PATH"),
    )

    auth_mode: MCPAuthMode = Field(
        default="static",
        validation_alias=AliasChoices("auth_mode", "ARODONATA_MCP_AUTH_MODE"),
    )
    token_vars: CsvStrList = Field(
        default_factory=list,
        validation_alias=AliasChoices("token_vars", "ARODONATA_MCP_TOKEN_VARS"),
    )
    tokens: CsvStrList = Field(
        default_factory=list,
        repr=False,
        validation_alias=AliasChoices("tokens", "ARODONATA_MCP_TOKENS"),
    )

    enable_dns_rebinding_protection: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "enable_dns_rebinding_protection",
            "ARODONATA_MCP_ENABLE_DNS_REBINDING_PROTECTION",
        ),
    )
    allowed_hosts: CsvStrList = Field(
        default_factory=lambda: list(DEFAULT_ALLOWED_HOSTS),
        validation_alias=AliasChoices("allowed_hosts", "ARODONATA_MCP_ALLOWED_HOSTS"),
    )
    allowed_origins: CsvStrList = Field(
        default_factory=lambda: list(DEFAULT_ALLOWED_ORIGINS),
        validation_alias=AliasChoices("allowed_origins", "ARODONATA_MCP_ALLOWED_ORIGINS"),
    )

    allow_write_api: bool = Field(
        default=False,
        validation_alias=AliasChoices("allow_write_api", "ARODONATA_MCP_ALLOW_WRITE_API"),
    )
    cpcrud: bool = Field(
        default=False,
        validation_alias=AliasChoices("cpcrud", "ARODONATA_MCP_CPCRUD"),
    )
    allow_insecure_unauthenticated: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "allow_insecure_unauthenticated",
            "ARODONATA_MCP_ALLOW_INSECURE_UNAUTHENTICATED",
        ),
    )
    tool_rate_limit_per_minute: int = Field(
        default=120,
        ge=0,
        validation_alias=AliasChoices(
            "tool_rate_limit_per_minute",
            "ARODONATA_MCP_TOOL_RATE_LIMIT_PER_MINUTE",
        ),
    )
    live_tool_rate_limit_per_minute: int = Field(
        default=30,
        ge=0,
        validation_alias=AliasChoices(
            "live_tool_rate_limit_per_minute",
            "ARODONATA_MCP_LIVE_TOOL_RATE_LIMIT_PER_MINUTE",
        ),
    )

    json_response: bool = Field(
        default=False,
        validation_alias=AliasChoices("json_response", "ARODONATA_MCP_JSON_RESPONSE"),
    )
    stateless_http: bool = Field(
        default=False,
        validation_alias=AliasChoices("stateless_http", "ARODONATA_MCP_STATELESS_HTTP"),
    )
    server_name: str = Field(
        default="arodonata-mcp",
        validation_alias=AliasChoices("server_name", "ARODONATA_MCP_SERVER_NAME"),
    )

    @field_validator("token_vars", "tokens", "allowed_hosts", "allowed_origins", mode="before")
    @classmethod
    def _parse_csv_fields(cls, value: Any) -> list[str]:
        return _split_csv(value)

    @field_validator("path", mode="after")
    @classmethod
    def _normalize_path(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            return "/mcp"
        if not cleaned.startswith("/"):
            return f"/{cleaned}"
        return cleaned

    def resolve_static_tokens(
        self,
        environ: dict[str, str] | None = None,
    ) -> list[tuple[str, str]]:
        """Resolve `(client_id, token_secret)` pairs from `token_vars` and `tokens`.

        Each environment variable name in `token_vars` becomes the caller's `client_id`.
        Entries in `tokens` may be `"client_id=secret"` or `"client_id:secret"` ONLY when
        `client_id` matches `^[A-Za-z_][A-Za-z0-9_-]*$` and `secret` has non-padding content;
        otherwise the entry is treated as a bare secret (e.g. a base64 token with trailing `=`
        padding) and assigned a non-secret `client_id` (`f"token_{idx}"`).
        Every resolved token secret MUST be at least 32 characters (`MIN_STATIC_TOKEN_LENGTH`).
        """
        env = environ if environ is not None else dict(os.environ)
        pairs: list[tuple[str, str]] = []

        for var_name in self.token_vars:
            clean_var = var_name.strip()
            if not clean_var:
                continue
            secret = env.get(clean_var, "").strip()
            if not secret:
                raise ConfigurationError(
                    f"Environment variable {clean_var!r} referenced in ARODONATA_MCP_TOKEN_VARS is not set or empty."
                )
            if len(secret) < MIN_STATIC_TOKEN_LENGTH:
                raise ConfigurationError(
                    f"Bearer token in {clean_var!r} is too short ({len(secret)} chars); "
                    f"minimum length is {MIN_STATIC_TOKEN_LENGTH} characters."
                )
            pairs.append((clean_var, secret))

        for idx, raw_entry in enumerate(self.tokens, start=1):
            clean_entry = raw_entry.strip()
            if not clean_entry:
                continue
            resolved_cid: str | None = None
            resolved_sec: str | None = None

            if "=" in clean_entry:
                cid, sec = clean_entry.split("=", 1)
                cid_clean = cid.strip()
                sec_clean = sec.strip()
                # Only treat '=' as a client_id=secret delimiter when left side is a valid identifier
                # and right side is not merely trailing base64 '=' padding.
                if _CLIENT_ID_RE.fullmatch(cid_clean) and sec_clean.lstrip("="):
                    resolved_cid = cid_clean
                    resolved_sec = sec_clean
            if resolved_cid is None and ":" in clean_entry:
                cid, sec = clean_entry.split(":", 1)
                cid_clean = cid.strip()
                sec_clean = sec.strip()
                if _CLIENT_ID_RE.fullmatch(cid_clean) and sec_clean:
                    resolved_cid = cid_clean
                    resolved_sec = sec_clean

            if resolved_cid is None or resolved_sec is None:
                resolved_cid = f"token_{idx}"
                resolved_sec = clean_entry

            if len(resolved_sec) < MIN_STATIC_TOKEN_LENGTH:
                raise ConfigurationError(
                    f"Static bearer token for {resolved_cid!r} is too short ({len(resolved_sec)} chars); "
                    f"minimum length is {MIN_STATIC_TOKEN_LENGTH} characters."
                )
            pairs.append((resolved_cid, resolved_sec))

        return pairs

    def validate_security_policy(
        self,
        *,
        standalone: bool = False,
        has_token_verifier: bool = False,
        environ: dict[str, str] | None = None,
        emit_warning: bool = True,
    ) -> None:
        """Enforce unified fail-closed MCP security invariants across CLI, server, and ASGI factories.

        1. Rejects `auth_mode="host"` or `"jwt"` in standalone CLI mode, and rejects `auth_mode="jwt"`
           without an explicit `token_verifier`.
        2. Requires at least one valid static bearer token in standalone `auth_mode="static"`.
        3. Rejects hostname/origin wildcards (`"*"`) whenever DNS rebinding protection is active.
        4. Rejects `auth_mode="none"` paired with non-loopback `host`, disabled DNS rebinding protection,
           wildcard or non-loopback `allowed_hosts` / `allowed_origins`, or mutating capabilities
           (`allow_write_api=True`, `cpcrud=True`) unless `allow_insecure_unauthenticated=True` is
           explicitly set (in which case a prominent `WARNING` is logged when `emit_warning=True`).
        """
        if standalone and self.auth_mode in ("host", "jwt"):
            raise ConfigurationError(
                f"ARODONATA_MCP_AUTH_MODE={self.auth_mode!r} is not supported in standalone 'arodonata-mcp' CLI mode. "
                "Use ARODONATA_MCP_AUTH_MODE='static' for standalone execution, or embed the server via "
                "create_mcp_server(..., auth_mode='host') / create_asgi_app(..., auth_mode='host') inside an "
                "authenticating ASGI host."
            )

        if self.auth_mode == "jwt" and not has_token_verifier:
            raise ConfigurationError(
                "auth_mode='jwt' requires an explicit token_verifier instance passed to "
                "create_mcp_server / create_asgi_app."
            )

        if standalone and self.auth_mode == "static":
            pairs = self.resolve_static_tokens(environ=environ)
            if not pairs:
                raise ConfigurationError(
                    "ARODONATA_MCP_AUTH_MODE='static' requires at least one bearer token configured via "
                    "ARODONATA_MCP_TOKEN_VARS or ARODONATA_MCP_TOKENS."
                )

        has_wildcard_host = _has_wildcard_entry(self.allowed_hosts)
        has_wildcard_origin = _has_wildcard_entry(self.allowed_origins)

        if self.enable_dns_rebinding_protection and (has_wildcard_host or has_wildcard_origin):
            raise ConfigurationError(
                "Wildcard '*' entries in ARODONATA_MCP_ALLOWED_HOSTS or ARODONATA_MCP_ALLOWED_ORIGINS are forbidden "
                "while DNS rebinding protection is enabled (ARODONATA_MCP_ENABLE_DNS_REBINDING_PROTECTION=true). "
                "Specify explicit hosts/origins or disable DNS rebinding protection explicitly."
            )

        if self.auth_mode == "none":
            unsafe_reasons: list[str] = []
            if not is_loopback_host(self.host):
                unsafe_reasons.append(f"non-loopback host={self.host!r}")
            if not self.enable_dns_rebinding_protection:
                unsafe_reasons.append("enable_dns_rebinding_protection=False")
            if has_wildcard_host:
                unsafe_reasons.append("wildcard entry in allowed_hosts")
            elif _has_non_loopback_entry(self.allowed_hosts):
                unsafe_reasons.append("non-loopback entry in allowed_hosts")
            if has_wildcard_origin:
                unsafe_reasons.append("wildcard entry in allowed_origins")
            elif _has_non_loopback_entry(self.allowed_origins):
                unsafe_reasons.append("non-loopback entry in allowed_origins")
            if self.allow_write_api:
                unsafe_reasons.append("allow_write_api=True")
            if self.cpcrud:
                unsafe_reasons.append("cpcrud=True")

            if unsafe_reasons:
                if not self.allow_insecure_unauthenticated:
                    raise ConfigurationError(
                        "Refusing unsafe unauthenticated MCP configuration (auth_mode='none') with "
                        f"{', '.join(unsafe_reasons)}. Configure authentication (auth_mode='static'/'host'/'jwt') "
                        "or bind strictly to loopback with DNS rebinding protection and no wildcards, non-loopback "
                        "allowlist entries, or write tools, or set allow_insecure_unauthenticated=True "
                        "(ARODONATA_MCP_ALLOW_INSECURE_UNAUTHENTICATED=true) to opt in explicitly."
                    )
                if emit_warning:
                    logger.warning(
                        "SECURITY WARNING: MCP server configured with auth_mode='none' and allow_insecure_unauthenticated=True",
                        host=self.host,
                        allowed_hosts=self.allowed_hosts,
                        allowed_origins=self.allowed_origins,
                        enable_dns_rebinding_protection=self.enable_dns_rebinding_protection,
                        allow_write_api=self.allow_write_api,
                        cpcrud=self.cpcrud,
                        reasons=unsafe_reasons,
                    )

    def validate_standalone_startup(
        self,
        core_settings: ArodonataSettings | None = None,
        *,
        environ: dict[str, str] | None = None,
        emit_warning: bool = True,
    ) -> TrustPolicy:
        """Validate standalone CLI (`arodonata-mcp`) security policy and TLS trust store configuration."""
        self.validate_security_policy(standalone=True, environ=environ, emit_warning=emit_warning)

        resolved_core = core_settings if core_settings is not None else ArodonataSettings()
        from arodonata.client import build_validated_trust_policy

        return build_validated_trust_policy(resolved_core, environ=environ)

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        """Serialize MCP settings with `tokens` masked."""
        dumped = super().model_dump(**kwargs)
        if "tokens" in dumped and dumped["tokens"]:
            dumped["tokens"] = [REDACTED_PLACEHOLDER for _ in dumped["tokens"]]
        return dumped

    def model_dump_json(self, **kwargs: Any) -> str:
        """Serialize MCP settings to JSON with `tokens` masked."""
        dumped = self.model_dump(**{k: v for k, v in kwargs.items() if k != "indent"})
        indent = kwargs.get("indent")
        return json.dumps(dumped, indent=indent, default=str)

    def __repr__(self) -> str:
        fields_repr: list[str] = []
        for name in type(self).model_fields:
            val = getattr(self, name)
            if name == "tokens":
                masked = [REDACTED_PLACEHOLDER for _ in val] if val else []
                fields_repr.append(f"{name}={masked!r}")
            else:
                fields_repr.append(f"{name}={val!r}")
        return f"ArodonataMCPSettings({', '.join(fields_repr)})"

    def __str__(self) -> str:
        return self.__repr__()


__all__ = [
    "ArodonataMCPSettings",
    "DEFAULT_ALLOWED_HOSTS",
    "DEFAULT_ALLOWED_ORIGINS",
    "LOOPBACK_HOSTS",
    "MCPAuthMode",
    "is_loopback_host",
]
