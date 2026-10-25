"""Configuration and topology settings for Arodonata v2."""

from __future__ import annotations

import ipaddress
import json
import os
import urllib.parse
from pathlib import Path
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

DEFAULT_TLS_KNOWN_HOSTS_PATH: str = str(Path.home() / ".config" / "arodonata" / "tls_known_hosts.json")


def mask_database_url(url: str) -> str:
    """Mask password embedded in a database connection URL (`postgresql+asyncpg://user:***@host/db`)."""
    if not url or "://" not in url:
        return url
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.password is None:
            return url
        user = urllib.parse.quote(parsed.username or "", safe="")
        host_part = parsed.hostname or ""
        if ":" in host_part and not host_part.startswith("["):
            host_part = f"[{host_part}]"
        port_suffix = f":{parsed.port}" if parsed.port is not None else ""
        netloc = f"{user}:{REDACTED_PLACEHOLDER}@{host_part}{port_suffix}"
        return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
    except Exception:
        return REDACTED_PLACEHOLDER


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
        env_file=None,
        extra="ignore",
        populate_by_name=False,
    )

    # Multi-server positional topology
    mgmt_names: CsvStrList = Field(
        default_factory=list,
        validation_alias=AliasChoices("ARODONATA_MGMT_NAMES", "MGMT_NAMES"),
    )
    mgmt_servers: CsvStrList = Field(
        default_factory=list,
        validation_alias=AliasChoices("ARODONATA_MGMT_SERVERS", "MGMT_SERVERS"),
    )
    api_keys: CsvStrList = Field(
        default_factory=list,
        repr=False,
        validation_alias=AliasChoices("ARODONATA_API_KEYS", "API_KEYS"),
    )
    api_key_vars: CsvStrList = Field(
        default_factory=list,
        validation_alias=AliasChoices("ARODONATA_API_KEY_VARS", "API_KEY_VARS"),
    )

    # Single-server convenience fields
    mgmt_name: str | None = Field(
        default=None,
        validation_alias=AliasChoices("ARODONATA_MGMT_NAME", "MGMT_NAME"),
    )
    mgmt_ip: str | None = Field(
        default=None,
        validation_alias=AliasChoices("ARODONATA_MGMT_IP", "MGMT_IP"),
    )
    mgmt_port: int = Field(
        default=443,
        validation_alias=AliasChoices("ARODONATA_MGMT_PORT", "MGMT_PORT"),
    )
    api_key: str | None = Field(
        default=None,
        repr=False,
        validation_alias=AliasChoices("ARODONATA_API_KEY", "MGMT_API_KEY"),
    )
    username: str | None = Field(
        default=None,
        validation_alias=AliasChoices("ARODONATA_USERNAME", "MGMT_USER", "MGMT_USERNAME"),
    )
    password: str | None = Field(
        default=None,
        repr=False,
        validation_alias=AliasChoices("ARODONATA_PASSWORD", "MGMT_PASSWORD"),
    )

    # Resolved authentication mode
    auth_mode: AuthMode = Field(
        default="dynamic",
        validation_alias=AliasChoices("ARODONATA_AUTH_MODE"),
    )

    # Operational timeout budgets (seconds)
    connect_timeout: float = Field(
        default=30.0,
        gt=0,
        validation_alias=AliasChoices("ARODONATA_CONNECT_TIMEOUT"),
    )
    api_timeout: float = Field(
        default=120.0,
        gt=0,
        validation_alias=AliasChoices("ARODONATA_API_TIMEOUT"),
    )
    login_timeout: float = Field(
        default=120.0,
        gt=0,
        validation_alias=AliasChoices("ARODONATA_LOGIN_TIMEOUT"),
    )
    task_timeout: float = Field(
        default=900.0,
        gt=0,
        validation_alias=AliasChoices("ARODONATA_TASK_TIMEOUT"),
    )
    rate_limit_slot_timeout: float = Field(
        default=90.0,
        gt=0,
        validation_alias=AliasChoices("ARODONATA_RATE_LIMIT_SLOT_TIMEOUT"),
    )

    # Session, concurrency, and rate limiting
    session_timeout: int = Field(
        default=600,
        gt=0,
        validation_alias=AliasChoices("ARODONATA_SESSION_TIMEOUT"),
    )
    session_expire_seconds: int = Field(
        default=540,
        gt=0,
        validation_alias=AliasChoices("ARODONATA_SESSION_EXPIRE_SECONDS", "ARODONATA_SESSION_EXPIRE"),
    )
    concurrent_limit: int = Field(
        default=4,
        ge=1,
        le=20,
        validation_alias=AliasChoices("ARODONATA_CONCURRENT_LIMIT"),
    )
    login_throttle_window: float = Field(
        default=70.0,
        gt=0,
        validation_alias=AliasChoices("ARODONATA_LOGIN_THROTTLE_WINDOW"),
    )
    login_max_wait: float = Field(
        default=900.0,
        gt=0,
        validation_alias=AliasChoices("ARODONATA_LOGIN_MAX_WAIT"),
    )

    # Cache and sync parameters
    cache_ttl: int = Field(
        default=300,
        ge=0,
        validation_alias=AliasChoices("ARODONATA_CACHE_TTL"),
    )
    domain_list_ttl: int = Field(
        default=3600,
        ge=0,
        validation_alias=AliasChoices("ARODONATA_DOMAIN_LIST_TTL"),
    )
    max_incremental_changes: int = Field(
        default=500,
        ge=1,
        validation_alias=AliasChoices("ARODONATA_MAX_INCREMENTAL_CHANGES"),
    )

    # TLS identity verification
    tls_trust: TlsTrustMode = Field(
        default="tofu",
        validation_alias=AliasChoices("ARODONATA_TLS_TRUST"),
    )
    tls_known_hosts_path: str = Field(
        default_factory=lambda: str(Path.home() / ".config" / "arodonata" / "tls_known_hosts.json"),
        validation_alias=AliasChoices("ARODONATA_TLS_KNOWN_HOSTS_PATH"),
    )
    tls_fingerprints: str = Field(
        default="",
        validation_alias=AliasChoices("ARODONATA_TLS_FINGERPRINTS"),
    )

    # Storage defaults
    database_url: str = Field(
        default="sqlite+aiosqlite:///:memory:",
        validation_alias=AliasChoices("ARODONATA_DATABASE_URL"),
    )
    sqlite_busy_timeout_ms: int = Field(
        default=30000,
        ge=0,
        validation_alias=AliasChoices("ARODONATA_SQLITE_BUSY_TIMEOUT_MS"),
    )

    # Optional CPCRUD schema override
    cpcrud_schema_path: str | None = Field(
        default=None,
        validation_alias=AliasChoices("ARODONATA_CPCRUD_SCHEMA_PATH"),
    )

    # OpenTelemetry module span gating
    trace_modules: str = Field(
        default="",
        validation_alias=AliasChoices("ARODONATA_TRACE_MODULES"),
    )

    def __init__(self, **data: Any) -> None:
        model_fields = type(self).model_fields
        remapped: dict[str, Any] = {}
        for key, value in data.items():
            field = model_fields.get(key)
            if (
                field is not None
                and isinstance(field.validation_alias, AliasChoices)
                and field.validation_alias.choices
            ):
                first_alias = field.validation_alias.choices[0]
                if isinstance(first_alias, str):
                    remapped[first_alias] = value
                    continue
            remapped[key] = value
        super().__init__(**remapped)

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
        #    When username/password credentials are provided (and no explicit api_keys), do not absorb ambient api_key.
        has_credentials = bool(self.username or self.password)
        if not self.api_keys and not has_credentials:
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

        if has_credentials and not has_api_keys:
            if not (self.username and self.password):
                raise MissingConfigurationError(
                    "Both username and password are required for credential authentication."
                )
            if not self.mgmt_servers:
                raise MissingConfigurationError(
                    "A target management server address (mgmt_ip or mgmt_servers) is required for credential mode."
                )
            self.auth_mode = "credential"
        elif has_api_keys:
            if len(self.api_keys) != len(self.mgmt_servers) or len(self.api_keys) != len(self.mgmt_names):
                raise ConfigurationError(
                    f"Mismatched server and API key counts: mgmt_names={len(self.mgmt_names)}, "
                    f"mgmt_servers={len(self.mgmt_servers)}, api_keys={len(self.api_keys)}."
                )
            self.auth_mode = "api_key"
        else:
            self.auth_mode = "dynamic"

        # 5. Normalize tls_known_hosts_path (~ expansion)
        if self.tls_known_hosts_path:
            self.tls_known_hosts_path = str(Path(self.tls_known_hosts_path).expanduser())

        # 6. Validate trace_modules syntax eagerly (without overwriting global host rules if empty)
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

    def _mask_serialized_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Mask secret fields and database URL passwords in serialized dictionaries."""
        if "password" in data and data["password"]:
            data["password"] = REDACTED_PLACEHOLDER
        if "api_key" in data and data["api_key"]:
            data["api_key"] = REDACTED_PLACEHOLDER
        if "api_keys" in data and data["api_keys"]:
            data["api_keys"] = [REDACTED_PLACEHOLDER for _ in data["api_keys"]]
        if "database_url" in data and isinstance(data["database_url"], str):
            data["database_url"] = mask_database_url(data["database_url"])
        return data

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        """Serialize settings with secrets and database URL passwords masked."""
        dumped = super().model_dump(**kwargs)
        return self._mask_serialized_dict(dumped)

    def model_dump_json(self, **kwargs: Any) -> str:
        """Serialize settings to JSON with secrets and database URL passwords masked."""
        dumped = self.model_dump(**{k: v for k, v in kwargs.items() if k != "indent"})
        indent = kwargs.get("indent")
        return json.dumps(dumped, indent=indent, default=str)

    def __repr__(self) -> str:
        fields_repr: list[str] = []
        for name in type(self).model_fields:
            val = getattr(self, name)
            if name in ("api_keys", "api_key", "password"):
                masked: Any = (
                    [REDACTED_PLACEHOLDER for _ in val]
                    if isinstance(val, list) and val
                    else (REDACTED_PLACEHOLDER if val else val)
                )
                fields_repr.append(f"{name}={masked!r}")
            elif name == "database_url" and isinstance(val, str):
                fields_repr.append(f"{name}={mask_database_url(val)!r}")
            else:
                fields_repr.append(f"{name}={val!r}")
        return f"ArodonataSettings({', '.join(fields_repr)})"

    def __str__(self) -> str:
        return self.__repr__()


def parse_host_port(raw_server: str, *, default_port: int = 443) -> tuple[str, int]:
    """Split `host`, `host:port`, `[ipv6]:port`, or bare IPv6 `2001:db8::1` into `(host, port)`."""
    cleaned = raw_server.strip()
    if not cleaned:
        return "", default_port

    if cleaned.startswith("["):
        end_bracket = cleaned.find("]")
        if end_bracket == -1:
            raise ConfigurationError(f"Malformed bracketed IPv6 address {raw_server!r}: missing closing ']'.")
        host_inner = cleaned[1:end_bracket].strip()
        remainder = cleaned[end_bracket + 1 :].strip()
        try:
            addr = ipaddress.ip_address(host_inner)
            normalized_host = addr.compressed
        except ValueError:
            normalized_host = host_inner
        if not remainder:
            return normalized_host, default_port
        if remainder.startswith(":") and remainder[1:].isdigit():
            port_val = int(remainder[1:])
            if not (1 <= port_val <= 65535):
                raise ConfigurationError(f"Port out of range in {raw_server!r}: {port_val}")
            return normalized_host, port_val
        raise ConfigurationError(f"Malformed port suffix in bracketed address {raw_server!r}.")

    # Check if cleaned is a bare IPv6 literal (contains >= 2 colons or valid ip_address v6)
    try:
        addr = ipaddress.ip_address(cleaned)
        if addr.version == 6:
            return addr.compressed, default_port
    except ValueError:
        pass

    if cleaned.count(":") == 1:
        host_part, port_part = cleaned.rsplit(":", 1)
        if port_part.isdigit():
            port_val = int(port_part)
            if not (1 <= port_val <= 65535):
                raise ConfigurationError(f"Port out of range in {raw_server!r}: {port_val}")
            return host_part.strip(), port_val
    elif cleaned.count(":") > 1:
        # Unbracketed multi-colon string that wasn't a bare IPv6 address: check if it's ipv6:port or invalid
        raise ConfigurationError(
            f"Ambiguous IPv6 address/port {raw_server!r}: wrap IPv6 addresses with ports in brackets '[ipv6]:port'."
        )

    return cleaned, default_port


_parse_host_port = parse_host_port
