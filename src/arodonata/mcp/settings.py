"""Settings for the Arodonata MCP server (env prefix ``ARODONATA_MCP_``)."""

from __future__ import annotations

from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ArodonataMCPConfigError(ValueError):
    """Raised when MCP settings are inconsistent (e.g. static auth with no tokens)."""


class ArodonataMCPSettings(BaseSettings):
    """Server-side configuration. Library settings (``ArodonataSettings``) are separate and unchanged."""

    model_config = SettingsConfigDict(env_prefix="ARODONATA_MCP_", case_sensitive=False, extra="ignore")

    host: str = Field(default="127.0.0.1", description="Bind address")
    port: int = Field(default=8765, ge=1, le=65535)
    path: str = Field(default="/mcp", description="Streamable HTTP path")
    public_url: str = Field(default="http://127.0.0.1:8765/mcp", description="URL clients use; resource_server_url")
    stateless: bool = Field(default=True)
    json_response: bool = Field(default=True)
    live_compat: bool = Field(default=True, description="Register live show_* tools from the manifest")
    cpcrud: bool = Field(default=False, description="Register cpcrud validate/plan/apply/inverse tools")
    allow_write_api: bool = Field(default=False, description="Allow non show-* commands through api_call")
    auth_mode: Literal["static", "jwt", "host"] = Field(default="static")
    token_vars: str = Field(default="", description="Comma-separated env var names holding bearer tokens")
    jwt_issuer: str = Field(default="")
    jwt_audience: str = Field(default="")
    jwt_jwks_url: str = Field(default="")
    default_limit: int = Field(default=50, ge=0)
    max_result_chars: int = Field(default=200_000, ge=1000)
    shutdown_timeout: int = Field(
        default=5,
        ge=0,
        description="Seconds Ctrl+C waits for open client connections and for SDK calls stuck in network I/O",
    )
    allowed_hosts: str = Field(
        default="",
        description="Comma-separated Host header values accepted (DNS-rebinding protection); default derives from host, port and public_url",
    )
    allowed_origins: str = Field(
        default="", description="Comma-separated Origin values accepted; default derives from public_url"
    )

    @field_validator("path")
    @classmethod
    def _path_starts_with_slash(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("path must start with '/'")
        return v

    @property
    def token_var_names(self) -> list[str]:
        return _split(self.token_vars)

    @property
    def allowed_hosts_list(self) -> list[str]:
        if self.allowed_hosts:
            return _split(self.allowed_hosts)
        public = urlparse(self.public_url)
        hosts = {
            f"{self.host}:{self.port}",
            self.host,
            "localhost",
            f"localhost:{self.port}",
            "127.0.0.1",
            f"127.0.0.1:{self.port}",
        }
        if public.netloc:
            hosts |= {public.netloc, public.hostname or public.netloc}
        return sorted(hosts)

    @property
    def allowed_origins_list(self) -> list[str]:
        if self.allowed_origins:
            return _split(self.allowed_origins)
        public = urlparse(self.public_url)
        origins = {f"http://{self.host}:{self.port}", f"http://localhost:{self.port}", f"http://127.0.0.1:{self.port}"}
        if public.scheme and public.netloc:
            origins.add(f"{public.scheme}://{public.netloc}")
        return sorted(origins)


def _split(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]
