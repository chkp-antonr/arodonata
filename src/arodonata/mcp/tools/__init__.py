"""MCP tool surface registration (`arodonata.mcp.tools`).

Exposes a consolidated, cache-aligned tool surface across focused domain submodules:
- Collection listing & structured queries (`objects.py`): `list_objects`, `list_services`,
  `list_assets`, `search_objects`, `query_objects`.
- Single-entity & group lookup (`lookup.py`): `list_domains`, `show_object`, `get_group_members`.
- Rulebase inspection & numbering (`rulebase.py`): `show_rulebase`, `locate_rules`.
- Gateway topology matching (`topology.py`): `locate_gateways`.
- Administration, reports & API tools (`admin.py`): `cache_control`, `change_report`,
  `api_call`, `api_reference`.
- Opt-in declarative CPCRUD (`cpcrud.py`): `cpcrud_validate`, `cpcrud_plan`, `cpcrud_apply`,
  `cpcrud_inverse`, `cpcrud_staged_session`.
"""

from __future__ import annotations

from collections.abc import Callable

from mcp.server.mcpserver import MCPServer

from arodonata.client import ArodonataClient
from arodonata.mcp.config import ArodonataMCPSettings
from arodonata.mcp.quota import MCPToolQuotaManager
from arodonata.mcp.tools._common import (
    CANONICAL_LAYER_AND_PACKAGE_TYPES as CANONICAL_LAYER_AND_PACKAGE_TYPES,
)
from arodonata.mcp.tools._common import (
    CANONICAL_SHOW_OBJECT_TYPES as CANONICAL_SHOW_OBJECT_TYPES,
)
from arodonata.mcp.tools._common import (
    MAX_MCP_API_TIMEOUT_SECONDS as MAX_MCP_API_TIMEOUT_SECONDS,
)
from arodonata.mcp.tools._common import (
    MAX_STORED_PLANS as MAX_STORED_PLANS,
)
from arodonata.mcp.tools._common import (
    RULEBASE_TYPE_TO_LIVE_COMMAND as RULEBASE_TYPE_TO_LIVE_COMMAND,
)
from arodonata.mcp.tools._common import (
    MCPCacheModeInput as MCPCacheModeInput,
)
from arodonata.mcp.tools._common import (
    _build_page_envelope as _build_page_envelope,
)
from arodonata.mcp.tools._common import (
    _canonical_plan_payload as _canonical_plan_payload,
)
from arodonata.mcp.tools._common import (
    _compute_cache_age as _compute_cache_age,
)
from arodonata.mcp.tools._common import (
    _entity_scope_and_type as _entity_scope_and_type,
)
from arodonata.mcp.tools._common import (
    _filter_assets as _filter_assets,
)
from arodonata.mcp.tools._common import (
    _filter_cp_objects as _filter_cp_objects,
)
from arodonata.mcp.tools._common import (
    _filter_cp_services as _filter_cp_services,
)
from arodonata.mcp.tools._common import (
    _get_v2_cache as _get_v2_cache,
)
from arodonata.mcp.tools._common import (
    _normalize_cache_mode as _normalize_cache_mode,
)
from arodonata.mcp.tools._common import (
    _raise_if_sync_failed as _raise_if_sync_failed,
)
from arodonata.mcp.tools._common import (
    _serialize_any_entity as _serialize_any_entity,
)
from arodonata.mcp.tools._common import (
    _serialize_asset as _serialize_asset,
)
from arodonata.mcp.tools._common import (
    _serialize_domain as _serialize_domain,
)
from arodonata.mcp.tools._common import (
    _serialize_layer as _serialize_layer,
)
from arodonata.mcp.tools._common import (
    _serialize_object as _serialize_object,
)
from arodonata.mcp.tools._common import (
    _serialize_package as _serialize_package,
)
from arodonata.mcp.tools._common import (
    _serialize_service as _serialize_service,
)
from arodonata.mcp.tools._common import (
    _sign_plan as _sign_plan,
)
from arodonata.mcp.tools._common import (
    _upgrade_uninitialized_cache_mode as _upgrade_uninitialized_cache_mode,
)
from arodonata.mcp.tools.admin import register_admin_tools
from arodonata.mcp.tools.cpcrud import register_cpcrud_tools
from arodonata.mcp.tools.lookup import register_lookup_tools
from arodonata.mcp.tools.objects import register_object_tools
from arodonata.mcp.tools.rulebase import register_rulebase_tools
from arodonata.mcp.tools.topology import register_topology_tools


def register_mcp_tools(
    server: MCPServer,
    client_getter: Callable[[], ArodonataClient],
    mcp_settings: ArodonataMCPSettings,
    *,
    quota_manager: MCPToolQuotaManager | None = None,
) -> None:
    """Register all configured MCP tools on `server`, enforcing per-client quota if enabled."""
    eff_quota = quota_manager if quota_manager is not None else MCPToolQuotaManager.from_settings(mcp_settings)
    register_lookup_tools(server, client_getter, mcp_settings, quota_manager=eff_quota)
    register_object_tools(server, client_getter, mcp_settings, quota_manager=eff_quota)
    register_rulebase_tools(server, client_getter, mcp_settings, quota_manager=eff_quota)
    register_topology_tools(server, client_getter, mcp_settings, quota_manager=eff_quota)
    register_admin_tools(server, client_getter, mcp_settings, quota_manager=eff_quota)
    register_cpcrud_tools(server, client_getter, mcp_settings, quota_manager=eff_quota)


__all__ = [
    "CANONICAL_LAYER_AND_PACKAGE_TYPES",
    "CANONICAL_SHOW_OBJECT_TYPES",
    "MAX_MCP_API_TIMEOUT_SECONDS",
    "MAX_STORED_PLANS",
    "MCPCacheModeInput",
    "RULEBASE_TYPE_TO_LIVE_COMMAND",
    "register_admin_tools",
    "register_cpcrud_tools",
    "register_lookup_tools",
    "register_mcp_tools",
    "register_object_tools",
    "register_rulebase_tools",
    "register_topology_tools",
]
