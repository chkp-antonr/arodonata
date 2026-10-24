"""Configuration and startup validation for the Arodonata MCP server (`arodonata.mcp.config`)."""

from __future__ import annotations

import os
from typing import Annotated, Any, Literal

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from arodonata.adapters.checkpoint.tls import TrustPolicy
from arodonata.core.config import ArodonataSettings, _split_csv
from arodonata.core.errors import REDACTED_PLACEHOLDER, ConfigurationError, TrustStoreError

MCPAuthMode = Literal["static", "host", "jwt", "none"]

CsvStrList = Annotated[list[str], NoDecode]

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
    live_compat: bool = Field(
        default=False,
        validation_alias=AliasChoices("live_compat", "ARODONATA_MCP_LIVE_COMPAT"),
    )
    cpcrud: bool = Field(
        default=False,
        validation_alias=AliasChoices("cpcrud", "ARODONATA_MCP_CPCRUD"),
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
        Entries in `tokens` may be `"client_id=secret"`, `"client_id:secret"`, or a bare secret
        (assigned `client_id=f"static_token_{idx}"`).
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
            pairs.append((clean_var, secret))

        for idx, raw_entry in enumerate(self.tokens, start=1):
            clean_entry = raw_entry.strip()
            if not clean_entry:
                continue
            if "=" in clean_entry:
                cid, sec = clean_entry.split("=", 1)
                if cid.strip() and sec.strip():
                    pairs.append((cid.strip(), sec.strip()))
                    continue
            if ":" in clean_entry:
                cid, sec = clean_entry.split(":", 1)
                if cid.strip() and sec.strip():
                    pairs.append((cid.strip(), sec.strip()))
                    continue
            pairs.append((f"static_token_{idx}", clean_entry))

        return pairs

    def validate_standalone_startup(
        self,
        core_settings: ArodonataSettings | None = None,
        *,
        environ: dict[str, str] | None = None,
    ) -> TrustPolicy:
        """Validate standalone CLI (`arodonata-mcp`) auth mode and TLS trust store configuration.

        Refuses `auth_mode="host"` or `"jwt"` in standalone mode by raising `ConfigurationError`.
        Verifies TLS trust policy and loads/validates the trust store.
        """
        if self.auth_mode in ("host", "jwt"):
            raise ConfigurationError(
                f"ARODONATA_MCP_AUTH_MODE={self.auth_mode!r} is not supported in standalone 'arodonata-mcp' CLI mode. "
                "Use ARODONATA_MCP_AUTH_MODE='static' for standalone execution, or embed the server via "
                "create_mcp_server(..., auth_mode='host') / create_asgi_app(..., auth_mode='host') inside an "
                "authenticating ASGI host."
            )

        if self.auth_mode == "static":
            pairs = self.resolve_static_tokens(environ=environ)
            if not pairs:
                raise ConfigurationError(
                    "ARODONATA_MCP_AUTH_MODE='static' requires at least one bearer token configured via "
                    "ARODONATA_MCP_TOKEN_VARS or ARODONATA_MCP_TOKENS."
                )

        resolved_core = core_settings if core_settings is not None else ArodonataSettings()
        env = environ if environ is not None else dict(os.environ)
        lab_env = env.get("ARODONATA_LAB")

        trust_policy = TrustPolicy(
            mode=resolved_core.tls_trust,
            known_hosts_path=resolved_core.tls_known_hosts_path,
            pinned_fingerprints=resolved_core.tls_fingerprints,
            lab_env=lab_env,
        )
        entries = trust_policy.trust_store.load()
        if trust_policy.mode == "pinned" and not trust_policy.pinned_fingerprints and not entries:
            raise TrustStoreError(
                "TLS trust mode 'pinned' requires at least one certificate fingerprint in "
                f"ARODONATA_TLS_FINGERPRINTS or {resolved_core.tls_known_hosts_path!r}."
            )
        return trust_policy

    def __repr__(self) -> str:
        fields_repr: list[str] = []
        for name in type(self).model_fields:
            val = getattr(self, name)
            if name == "tokens":
                masked = [REDACTED_PLACEHOLDER] if val else []
                fields_repr.append(f"{name}={masked!r}")
            else:
                fields_repr.append(f"{name}={val!r}")
        return f"ArodonataMCPSettings({', '.join(fields_repr)})"


__all__ = [
    "ArodonataMCPSettings",
    "DEFAULT_ALLOWED_HOSTS",
    "DEFAULT_ALLOWED_ORIGINS",
    "MCPAuthMode",
]
