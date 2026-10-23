"""Configuration and topology settings for Arodonata v2."""

from __future__ import annotations

import json
import os
from typing import Annotated, Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from arodonata.core.errors import (
    REDACTED_PLACEHOLDER,
    ConfigurationError,
    MissingConfigurationError,
)
from arodonata.core.telemetry import apply_trace_modules, parse_trace_modules

AuthMode = Literal["api_key", "credential", "dynamic"]
TlsTrustMode = Literal["pinned", "tofu", "lab-memory"]


def _split_csv(value: str | list[str] | tuple[str, ...] | None) -> list[str]:
    """Normalize a comma-separated string, JSON array string, or sequence into a list of stripped strings."""
    if value is None:
        return []
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, list):
                    return [str(item).strip() for item in parsed if str(item).strip()]
            except json.JSONDecodeError:
                pass
        return [item.strip() for item in stripped.split(",") if item.strip()]
    return [str(item).strip() for item in value if str(item).strip()]


CsvStrList = Annotated[list[str], NoDecode]


class ServerEndpointConfig(BaseModel):
    """Resolved connection configuration for a single Check Point management server."""

    model_config = ConfigDict(frozen=True)

    name: str
    host: str
    port: int = 443
    api_key: str | None = Field(default=None, repr=False)

    def __repr__(self) -> str:
        key_state = REDACTED_PLACEHOLDER if self.api_key else None
        return (
            f"ServerEndpointConfig(name={self.name!r}, host={self.host!r}, port={self.port!r}, api_key={key_state!r})"
        )


class ArodonataSettings(BaseSettings):
    """Type-safe configuration for Arodonata resolved from kwargs and `os.environ`.

    Never loads `.env` files implicitly.
    """

    model_config = SettingsConfigDict(
        env_prefix="ARODONATA_",
        env_file=None,
        extra="ignore",
        populate_by_name=True,
    )

    # Multi-server positional topology
    mgmt_names: CsvStrList = Field(
        default_factory=list,
        validation_alias=AliasChoices("mgmt_names", "ARODONATA_MGMT_NAMES", "MGMT_NAMES"),
    )
    mgmt_servers: CsvStrList = Field(
        default_factory=list,
        validation_alias=AliasChoices("mgmt_servers", "ARODONATA_MGMT_SERVERS", "MGMT_SERVERS"),
    )
    api_keys: CsvStrList = Field(
        default_factory=list,
        repr=False,
        validation_alias=AliasChoices("api_keys", "ARODONATA_API_KEYS", "API_KEYS"),
    )
    api_key_vars: CsvStrList = Field(
        default_factory=list,
        validation_alias=AliasChoices("api_key_vars", "ARODONATA_API_KEY_VARS", "API_KEY_VARS"),
    )

    # Single-server convenience fields
    mgmt_name: str | None = Field(
        default=None,
        validation_alias=AliasChoices("mgmt_name", "ARODONATA_MGMT_NAME", "MGMT_NAME"),
    )
    mgmt_ip: str | None = Field(
        default=None,
        validation_alias=AliasChoices("mgmt_ip", "ARODONATA_MGMT_IP", "MGMT_IP"),
    )
    mgmt_port: int = Field(
        default=443,
        validation_alias=AliasChoices("mgmt_port", "ARODONATA_MGMT_PORT", "MGMT_PORT"),
    )
    api_key: str | None = Field(
        default=None,
        repr=False,
        validation_alias=AliasChoices("api_key", "ARODONATA_API_KEY", "MGMT_API_KEY", "API_KEY"),
    )
    username: str | None = Field(
        default=None,
        validation_alias=AliasChoices("username", "ARODONATA_USERNAME", "MGMT_USER", "MGMT_USERNAME"),
    )
    password: str | None = Field(
        default=None,
        repr=False,
        validation_alias=AliasChoices("password", "ARODONATA_PASSWORD", "MGMT_PASSWORD"),
    )

    # Resolved authentication mode
    auth_mode: AuthMode = Field(
        default="dynamic",
        validation_alias=AliasChoices("auth_mode", "ARODONATA_AUTH_MODE"),
    )

    # Operational timeout budgets (seconds)
    connect_timeout: float = Field(default=30.0, gt=0)
    api_timeout: float = Field(default=120.0, gt=0)
    login_timeout: float = Field(default=120.0, gt=0)
    task_timeout: float = Field(default=900.0, gt=0)
    rate_limit_slot_timeout: float = Field(default=90.0, gt=0)

    # Session, concurrency, and rate limiting
    session_timeout: int = Field(default=600, gt=0)
    session_expire_seconds: int = Field(default=540, gt=0)
    concurrent_limit: int = Field(default=4, ge=1, le=20)
    login_throttle_window: float = Field(default=70.0, gt=0)
    login_max_wait: float = Field(default=900.0, gt=0)

    # Cache and sync parameters
    cache_ttl: int = Field(default=300, ge=0)
    domain_list_ttl: int = Field(default=3600, ge=0)
    max_incremental_changes: int = Field(default=500, ge=1)

    # TLS identity verification
    tls_trust: TlsTrustMode = Field(default="tofu")
    tls_known_hosts_path: str = Field(default="tls_known_hosts.json")
    tls_fingerprints: str = Field(default="")

    # Storage defaults
    database_url: str = Field(default="sqlite+aiosqlite:///:memory:")
    sqlite_busy_timeout_ms: int = Field(default=30000, ge=0)

    # Optional CPCRUD schema override
    cpcrud_schema_path: str | None = Field(default=None)

    # OpenTelemetry module span gating
    trace_modules: str = Field(default="")

    @field_validator("mgmt_names", "mgmt_servers", "api_keys", "api_key_vars", mode="before")
    @classmethod
    def _parse_csv_list(cls, value: Any) -> list[str]:
        return _split_csv(value)

    @model_validator(mode="before")
    @classmethod
    def _CaptureExplicitAuthMode(cls, values: dict[str, Any]) -> dict[str, Any]:
        if isinstance(values, dict) and ("auth_mode" in values or "ARODONATA_AUTH_MODE" in values):
            values = dict(values)
            explicit_val = values.get("auth_mode") or values.get("ARODONATA_AUTH_MODE")
            if explicit_val is not None:
                values["_explicit_auth_mode"] = explicit_val
        return values

    @model_validator(mode="after")
    def _validate_topology_and_auth_mode(self) -> ArodonataSettings:
        # 1. Normalize single-server fallback into mgmt_servers / mgmt_names if needed
        if not self.mgmt_servers and self.mgmt_ip:
            self.mgmt_servers = [self.mgmt_ip.strip()]
        if not self.mgmt_names and self.mgmt_servers:
            if len(self.mgmt_servers) == 1 and self.mgmt_name:
                self.mgmt_names = [self.mgmt_name.strip()]
            elif len(self.mgmt_servers) == 1 and self.mgmt_ip:
                self.mgmt_names = [self.mgmt_name.strip() if self.mgmt_name else self.mgmt_ip.strip()]

        # 2. Resolve API keys with strict precedence: explicit api_keys > single api_key > api_key_vars
        if not self.api_keys:
            if self.api_key:
                self.api_keys = [self.api_key.strip()]
            elif self.api_key_vars:
                resolved_keys: list[str] = []
                for var_name in self.api_key_vars:
                    env_val = os.environ.get(var_name, "").strip()
                    if not env_val:
                        raise ConfigurationError(
                            f"Environment variable {var_name!r} referenced in API_KEY_VARS is not set or empty."
                        )
                    resolved_keys.append(env_val)
                self.api_keys = resolved_keys

        # 3. Validate positional counts between mgmt_names and mgmt_servers
        if self.mgmt_names and self.mgmt_servers and len(self.mgmt_names) != len(self.mgmt_servers):
            raise ConfigurationError(
                f"Mismatched server topology counts: mgmt_names has {len(self.mgmt_names)} entries "
                f"while mgmt_servers has {len(self.mgmt_servers)} entries."
            )
        if self.mgmt_names and not self.mgmt_servers:
            raise ConfigurationError(
                f"Mismatched server topology counts: mgmt_names has {len(self.mgmt_names)} entries "
                "while mgmt_servers is empty."
            )
        if self.mgmt_servers and not self.mgmt_names:
            raise ConfigurationError(
                f"Mismatched server topology counts: mgmt_servers has {len(self.mgmt_servers)} entries "
                "while mgmt_names is empty."
            )

        # 4. Determine auth_mode and validate mode-specific requirements
        has_api_keys = bool(self.api_keys)
        has_credentials = bool(self.username or self.password)

        if has_api_keys:
            if len(self.api_keys) != len(self.mgmt_servers) or len(self.api_keys) != len(self.mgmt_names):
                raise ConfigurationError(
                    f"Mismatched server and API key counts: mgmt_names={len(self.mgmt_names)}, "
                    f"mgmt_servers={len(self.mgmt_servers)}, api_keys={len(self.api_keys)}."
                )
            self.auth_mode = "api_key"
        elif has_credentials:
            if not (self.username and self.password):
                raise MissingConfigurationError(
                    "Both username and password are required for credential authentication."
                )
            if not self.mgmt_servers:
                raise MissingConfigurationError(
                    "A target management server address (mgmt_ip or mgmt_servers) is required for credential mode."
                )
            self.auth_mode = "credential"
        else:
            self.auth_mode = "dynamic"

        # 5. Validate trace_modules syntax eagerly (without overwriting global host rules if empty)
        if self.trace_modules:
            _ = parse_trace_modules(self.trace_modules)

        return self

    @property
    def servers(self) -> dict[str, ServerEndpointConfig]:
        """Return positional mapping of `mgmt_name -> ServerEndpointConfig`."""
        registry: dict[str, ServerEndpointConfig] = {}
        for idx, (name, raw_server) in enumerate(zip(self.mgmt_names, self.mgmt_servers)):
            host, port = _parse_host_port(raw_server, default_port=self.mgmt_port)
            key = self.api_keys[idx] if idx < len(self.api_keys) else None
            registry[name] = ServerEndpointConfig(name=name, host=host, port=port, api_key=key)
        return registry

    @property
    def domain_sync_concurrency(self) -> int:
        """Maximum concurrent domain refreshes per MDS member (`max(1, concurrent_limit - 1)`)."""
        return max(1, self.concurrent_limit - 1)

    @property
    def trace_modules_rules(self) -> dict[str, bool]:
        """Parsed OpenTelemetry module span gating rules."""
        return parse_trace_modules(self.trace_modules)

    def configure_tracing(self) -> dict[str, bool]:
        """Apply `trace_modules` rules if non-empty; preserve host rules when empty."""
        return apply_trace_modules(self.trace_modules)

    def resolve_read_timeout(self, budget: float | None = None) -> float:
        """Compute socket read timeout for an API call (`budget + 5` or `max(api, login) + 5`)."""
        if budget is not None:
            return float(budget) + 5.0
        return float(max(self.api_timeout, self.login_timeout)) + 5.0

    def __repr__(self) -> str:
        fields_repr: list[str] = []
        for name in type(self).model_fields:
            val = getattr(self, name)
            if name in ("api_keys", "api_key", "password"):
                masked = REDACTED_PLACEHOLDER if val else val
                fields_repr.append(f"{name}={masked!r}")
            else:
                fields_repr.append(f"{name}={val!r}")
        return f"ArodonataSettings({', '.join(fields_repr)})"


def _parse_host_port(raw_server: str, *, default_port: int = 443) -> tuple[str, int]:
    """Split `host` or `host:port` into `(host, port)`."""
    cleaned = raw_server.strip()
    if ":" in cleaned and not cleaned.startswith("["):
        host_part, port_part = cleaned.rsplit(":", 1)
        if port_part.isdigit():
            return host_part.strip(), int(port_part)
    return cleaned, default_port
