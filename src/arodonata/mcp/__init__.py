"""MCP server support for Arodonata (optional extra ``arodonata[mcp]``).

Importing this package must never require the ``mcp`` SDK to be installed: only
``_sdk.py`` imports it directly, and every public name below is resolved lazily via
``__getattr__`` on first access, so ``import arodonata.mcp`` (or any of its submodules
that do not themselves need the SDK, e.g. ``arodonata.mcp.settings``) always succeeds.
"""

from __future__ import annotations

import importlib
from typing import Any

__all__ = [
    "MISSING_EXTRA_MESSAGE",
    "ArodonataMCPConfigError",
    "ArodonataMCPSettings",
    "RegisteredTools",
    "create_asgi_app",
    "create_mcp_server",
    "register_arodonata_tools",
]

# Public name -> relative submodule that defines it. Resolved lazily (PEP 562) so that
# merely importing ``arodonata.mcp`` never imports the ``mcp`` SDK or any submodule that
# does.
_LAZY_ATTRS: dict[str, str] = {
    "MISSING_EXTRA_MESSAGE": "_messages",
    "create_mcp_server": "app",
    "create_asgi_app": "app",
    "register_arodonata_tools": "registry",
    "RegisteredTools": "registry",
    "ArodonataMCPSettings": "settings",
    "ArodonataMCPConfigError": "settings",
}


def __getattr__(name: str) -> Any:
    module_name = _LAZY_ATTRS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = importlib.import_module(f".{module_name}", __name__)
    return getattr(module, name)


def __dir__() -> list[str]:
    return sorted(__all__)
