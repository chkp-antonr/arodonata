"""Configuration settings for Arodonata library.

Uses Pydantic v2 BaseSettings for type-safe configuration.
Settings can be provided via:
1. Environment variables (e.g., ARODONATA_LOG_LEVEL, MGMT_NAMES, etc.)
2. Explicit constructor parameters (overrides env vars)

Priority: Constructor parameters > Environment variables > Defaults
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .constants import (
    DEFAULT_API_TIMEOUT,
    DEFAULT_CONCURRENT_LIMIT,
    DEFAULT_LOGIN_BACKOFF,
    DEFAULT_LOGIN_RETRIES,
    DEFAULT_RATE_LIMIT_SLOT_TIMEOUT,
    DEFAULT_SESSION_EXPIRE,
    DEFAULT_SESSION_TIMEOUT,
    LOG_LEVELS,
)


class ArodonataSettings(BaseSettings):
    """Configuration for Arodonata library.

    Settings can be provided via environment variables or explicit parameters.
    Explicit parameters override environment variables.

    Examples:
        # Approach 1: Environment variables (automatic)
        # Set MGMT_NAMES, MGMT_SERVERS, API_KEYS in .env file
        from arodonata import ArodonataSettings
        settings = ArodonataSettings()  # Auto-reads from environment

        # Approach 2: Explicit parameters (override env vars)
        settings = ArodonataSettings(
            mgmt_names="mgmt1,mgmt2",
            mgmt_servers="10.0.0.1,10.0.0.2",
            api_keys="key1,key2",  # Actual keys, not variable names
        )

        # Approach 3: Mix of both (specific overrides)
        # MGMT_NAMES from env, but explicit server/keys
        settings = ArodonataSettings(
            mgmt_servers="custom.server.com",
            api_keys="my_key",
        )
    """

    model_config = SettingsConfigDict(
        case_sensitive=False,
        extra="ignore",
    )

    # Management servers (comma-separated, can be set via env vars or explicit params)
    mgmt_names: str = Field(
        default="", description="Comma-separated management server names", validation_alias="MGMT_NAMES"
    )
    mgmt_servers: str = Field(
        default="", description="Comma-separated management server IPs/hosts", validation_alias="MGMT_SERVERS"
    )

    # API keys with automatic indirection support
    # Supports both: API_KEY_VARS=var_name and direct API_KEYS=value
    api_keys_raw: str = Field(default="", validation_alias="API_KEYS", exclude=True)
    api_key_vars: str = Field(default="", validation_alias="API_KEY_VARS", exclude=True)
    api_keys: str = Field(default="", description="Comma-separated API keys (actual values)")

    # Credential-based authentication (alternative to api_keys)
    username: str | None = Field(
        default=None, description="Username for credential-based auth", validation_alias="ARODONATA_USERNAME"
    )
    password: SecretStr | None = Field(
        default=None, description="Password for credential-based auth", validation_alias="ARODONATA_PASSWORD"
    )
    mgmt_ip: str | None = Field(
        default=None, description="Management server IP for credential mode", validation_alias="ARODONATA_MGMT_IP"
    )

    # Session/Cache settings
    session_expire_seconds: int = Field(
        default=DEFAULT_SESSION_EXPIRE,
        ge=0,
        description="Session expiration in seconds",
        validation_alias="ARODONATA_SESSION_EXPIRE",
    )
    session_timeout: int = Field(
        default=DEFAULT_SESSION_TIMEOUT,
        ge=0,
        description="Session timeout in seconds (passed to login API)",
        validation_alias="ARODONATA_SESSION_TIMEOUT",
    )

    # Rate limiting
    concurrent_limit: int = Field(
        default=DEFAULT_CONCURRENT_LIMIT,
        ge=1,
        le=20,
        description="Max concurrent API requests per server",
        validation_alias="ARODONATA_CONCURRENT_LIMIT",
    )
    rate_limit_slot_timeout: int = Field(
        default=DEFAULT_RATE_LIMIT_SLOT_TIMEOUT,
        ge=1,
        description=(
            "Seconds a caller waits for a free concurrency slot (RateLimiter.acquire) "
            "before giving up. Must comfortably exceed how long another caller can "
            "legitimately hold a slot during its own login retry-with-backoff sequence, "
            "or concurrent callers fail fast under real server-side throttling even "
            "though the server would have accepted a login moments later."
        ),
        validation_alias="ARODONATA_RATE_LIMIT_SLOT_TIMEOUT",
    )

    # Timeouts
    api_timeout: int = Field(
        default=DEFAULT_API_TIMEOUT,
        ge=1,
        description="API timeout in seconds",
        validation_alias="ARODONATA_API_TIMEOUT",
    )
    login_retry_backoff: int = Field(
        default=DEFAULT_LOGIN_BACKOFF,
        ge=1,
        description="Login retry backoff in seconds",
        validation_alias="ARODONATA_LOGIN_BACKOFF",
    )
    login_max_retries: int = Field(
        default=DEFAULT_LOGIN_RETRIES,
        ge=1,
        description="Maximum login retry attempts",
        validation_alias="ARODONATA_LOGIN_RETRIES",
    )

    # Logging - supports ARODONATA_LOG_LEVEL env var
    log_level: str = Field(
        default="INFO",
        description="Logging level",
        validation_alias="ARODONATA_LOG_LEVEL",
    )

    # OpenTelemetry per-module span gating (arlogi @traced v2 semantics:
    # longest dotted-prefix match, unmatched modules default to on)
    trace_modules: str = Field(
        default="",
        description="Comma-separated 'module:on|off' span gating rules",
        validation_alias="ARODONATA_TRACE_MODULES",
    )

    # ---- CPCRUD (idempotent object CRUD) ----
    cpcrud_on_name_conflict: str = Field(
        default="update",
        description="Name conflict policy: 'update' | 'error'",
        validation_alias="ARODONATA_CPCRUD_ON_NAME_CONFLICT",
    )
    cpcrud_on_ip_conflict: str = Field(
        default="reuse",
        description="IP conflict policy: 'reuse' | 'error' | 'create_new'",
        validation_alias="ARODONATA_CPCRUD_ON_IP_CONFLICT",
    )
    cpcrud_auto_name_prefix_host: str = Field(
        default="Host_", validation_alias="ARODONATA_CPCRUD_AUTO_NAME_PREFIX_HOST"
    )
    cpcrud_auto_name_prefix_network: str = Field(
        default="Net_", validation_alias="ARODONATA_CPCRUD_AUTO_NAME_PREFIX_NETWORK"
    )
    cpcrud_auto_name_prefix_range: str = Field(
        default="IPR_", validation_alias="ARODONATA_CPCRUD_AUTO_NAME_PREFIX_RANGE"
    )
    cpcrud_auto_name_prefix_svc_tcp: str = Field(
        default="TCP_", validation_alias="ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_TCP"
    )
    cpcrud_auto_name_prefix_svc_udp: str = Field(
        default="UDP_", validation_alias="ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_UDP"
    )
    cpcrud_auto_name_prefix_svc_icmp: str = Field(
        default="ICMP_", validation_alias="ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_ICMP"
    )
    cpcrud_refresh_mode: str = Field(
        default="invalidate",
        description="Post-publish cache refresh: 'invalidate' | 'force'",
        validation_alias="ARODONATA_CPCRUD_REFRESH_MODE",
    )
    cpcrud_schema_path: str = Field(
        default="",
        description="Override path to checkpoint_ops_schema.json",
        validation_alias="ARODONATA_CPCRUD_SCHEMA_PATH",
    )

    def __init__(self, **data: Any) -> None:
        """Construct settings, allowing plain Python field names as kwargs.

        Every field above declares a ``validation_alias`` — its intended
        environment-variable name (e.g. ``ARODONATA_USERNAME``, ``MGMT_NAMES``).
        Pydantic only accepts that alias as input by default, so a plain kwarg
        like ``ArodonataSettings(username=...)`` would silently be dropped.

        To support that ergonomic kwarg form *without* also turning every bare
        field name into a valid environment variable (which a blanket
        ``populate_by_name=True`` on ``model_config`` would do — see
        ``pydantic_settings.sources.base.EnvSettingsSource._extract_field_info``,
        which registers an env-var candidate for every name the field accepts
        as input), remap explicit constructor kwargs from their plain field
        name to their alias *before* handing off to ``BaseSettings.__init__``.

        This only touches keys the caller passed in directly here; it never
        changes what ``model_config`` or any field's ``validation_alias``
        declares, so environment variable sourcing is completely unaffected —
        an ambient env var like ``USERNAME`` or ``LOG_LEVEL`` is never
        absorbed.
        """
        model_fields = type(self).model_fields
        remapped: dict[str, Any] = {}
        for key, value in data.items():
            field = model_fields.get(key)
            if field is not None and isinstance(field.validation_alias, str) and field.validation_alias != key:
                remapped[field.validation_alias] = value
            else:
                remapped[key] = value
        super().__init__(**remapped)

    @property
    def auth_mode(self) -> str:
        """Return authentication mode based on provided credentials.

        Returns:
            'credential' if username and password provided, else 'api_key'.
        """
        if self.username and self.password:
            return "credential"
        return "api_key"

    @property
    def mgmt_names_list(self) -> list[str]:
        """Parse comma-separated management names to list."""
        return self._parse_comma_separated(self.mgmt_names)

    @property
    def mgmt_servers_list(self) -> list[str]:
        """Parse comma-separated management servers to list."""
        return self._parse_comma_separated(self.mgmt_servers)

    @property
    def trace_modules_rules(self) -> dict[str, bool]:
        """Parsed gating rules for arlogi's set_trace_modules()."""
        rules: dict[str, bool] = {}
        for entry in self._parse_comma_separated(self.trace_modules):
            module, _, state = entry.partition(":")
            rules[module.strip()] = state.strip().lower() == "on"
        return rules

    @property
    def api_keys_list(self) -> list[str]:
        """Parse comma-separated API keys to list.

        Returns:
            List of API key values.
        """
        return self._parse_comma_separated(self.api_keys)

    @staticmethod
    def _parse_comma_separated(value: str) -> list[str]:
        """Parse comma-separated string into list of non-empty values."""
        if not value:
            return []
        return [item.strip() for item in value.split(",") if item.strip()]

    @field_validator("api_keys", mode="before")
    @classmethod
    def resolve_api_keys(cls, v: Any, info: ValidationInfo) -> str:
        """Resolve API keys with priority: explicit parameter > API_KEY_VARS > API_KEYS > default.

        This allows both automatic environment reading AND explicit override support,
        plus support for the API_KEY_VARS indirection pattern.
        """
        # If explicit value provided (non-empty string), use it
        if isinstance(v, str) and v.strip():
            return v.strip()

        # Try API_KEY_VARS indirection pattern first
        if hasattr(info, "data") and "api_key_vars" in info.data:
            api_key_vars_str = info.data.get("api_key_vars", "").strip()
            if api_key_vars_str:
                var_names = [var.strip() for var in api_key_vars_str.split(",") if var.strip()]
                resolved_keys = ",".join(os.getenv(var, "") for var in var_names)
                if resolved_keys:
                    return resolved_keys

        # Fall back to direct API_KEYS environment variable
        if hasattr(info, "data") and "api_keys_raw" in info.data:
            env_value = info.data.get("api_keys_raw", "")
            if isinstance(env_value, str) and env_value.strip():
                return env_value.strip()

        # Default to empty string
        return ""

    @field_validator("log_level", mode="before")
    @classmethod
    def validate_log_level(cls, v: Any) -> str:
        """Validate log level is one of the allowed values."""
        if isinstance(v, str):
            v_str = v
        else:
            v_str = str(v) if v is not None else "INFO"

        v_str = v_str.upper()
        if v_str not in LOG_LEVELS:
            return "INFO"
        return v_str

    @field_validator("trace_modules")
    @classmethod
    def validate_trace_modules(cls, v: str) -> str:
        """Each entry must be 'dotted.module:on' or 'dotted.module:off'."""
        for entry in cls._parse_comma_separated(v):
            module, sep, state = entry.partition(":")
            if not sep or not module.strip() or state.strip().lower() not in ("on", "off"):
                raise ValueError(f"trace_modules entry '{entry}' is invalid; expected 'module:on' or 'module:off'")
        return v

    @model_validator(mode="after")
    def validate_credential_mode(self) -> ArodonataSettings:
        """Validate that mgmt_ip is provided when using credential-based auth."""
        if self.username and self.password and not self.mgmt_ip:
            from ..core.exceptions import MissingConfigurationError

            raise MissingConfigurationError(
                "mgmt_ip is required when using credential-based authentication "
                "(username/password). Provide mgmt_ip to specify the management server."
            )
        return self


__all__ = ["ArodonataSettings"]
