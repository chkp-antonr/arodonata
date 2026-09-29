"""Zero-dependency constants shared by ``_sdk`` and the package ``__init__``.

This module must never import the ``mcp`` SDK (or anything else optional) so that
``arodonata.mcp.__init__`` can surface ``MISSING_EXTRA_MESSAGE`` without pulling in the
optional dependency it is warning about.
"""

from __future__ import annotations

MISSING_EXTRA_MESSAGE = "arodonata MCP support requires the 'mcp' extra: uv pip install 'arodonata[mcp]'"
