"""arodonata.helpers - Domain-organized helper functions for plugins.

This module provides cache-first, user-aware helper functions organized
by Check Point domains: assets, objects, and policy.

Example usage:
    from arodonata import ArodonataClient
    from arodonata.helpers import find_object, get_gateways
    from arodonata.helpers._context import UserContext

    context = UserContext.from_cli()
    client = await ArodonataClient.create(settings)

    host = await find_object(client, "web-server", user_context=context)
    gateways = await get_gateways(client, user_context=context)
"""

from ._context import UserContext
from .assets import get_gateways, refresh_assets
from .objects import find_object, get_group_members, get_objects
from .policy import (
    add_object,
    create_session,
    delete_object,
    discard_session,
    get_access_rules,
    get_https_rules,
    get_nat_rules,
    get_threat_rules,
    publish_session,
    set_object,
    write_session,
)

__all__ = [
    "UserContext",
    "find_object",
    "get_objects",
    "get_group_members",
    "get_gateways",
    "refresh_assets",
    "create_session",
    "publish_session",
    "discard_session",
    "write_session",
    "add_object",
    "set_object",
    "delete_object",
    "get_access_rules",
    "get_nat_rules",
    "get_https_rules",
    "get_threat_rules",
]
