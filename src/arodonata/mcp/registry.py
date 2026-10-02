"""Register Arodonata tools and prompts on a caller-owned ``MCPServer``."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ._sdk import MCPServer

if TYPE_CHECKING:
    from ..api.client import ArodonataClient


@dataclass(frozen=True)
class ToolOptions:
    tool_prefix: str = ""
    default_limit: int = 50
    max_result_chars: int = 200_000
    allow_write_api: bool = False

    def name(self, base: str) -> str:
        return f"{self.tool_prefix}{base}"


@dataclass(frozen=True)
class RegisteredTools:
    cached: tuple[str, ...] = field(default_factory=tuple)
    live: tuple[str, ...] = field(default_factory=tuple)
    native: tuple[str, ...] = field(default_factory=tuple)
    cpcrud: tuple[str, ...] = field(default_factory=tuple)

    @property
    def all(self) -> tuple[str, ...]:
        return self.cached + self.live + self.native + self.cpcrud


def register_arodonata_tools(
    server: MCPServer,
    client: ArodonataClient,
    *,
    live_compat: bool = True,
    cpcrud: bool = False,
    allow_write_api: bool = False,
    tool_prefix: str = "",
    default_limit: int = 50,
    max_result_chars: int = 200_000,
) -> RegisteredTools:
    """Add the Arodonata tool set to ``server``. The caller owns ``client`` and its lifecycle."""
    from .cached_tools import register_cached_tools
    from .change_report_tools import register_change_report_tools
    from .compat import register_live_tools
    from .cpcrud_tools import register_cpcrud_tools
    from .native import register_native_tools
    from .prompts import register_prompts
    from .rulebase_tools import register_rulebase_tools

    opts = ToolOptions(
        tool_prefix=tool_prefix,
        default_limit=default_limit,
        max_result_chars=max_result_chars,
        allow_write_api=allow_write_api,
    )
    cached: list[str] = register_cached_tools(server, client, opts)
    cached += register_rulebase_tools(server, client, opts)
    cached += register_change_report_tools(server, client, opts)
    live: list[str] = register_live_tools(server, client, opts) if live_compat else []
    native = register_native_tools(server, client, opts)
    cpcrud_names: list[str] = register_cpcrud_tools(server, client, opts) if cpcrud else []
    register_prompts(server, opts)
    return RegisteredTools(cached=tuple(cached), live=tuple(live), native=tuple(native), cpcrud=tuple(cpcrud_names))
