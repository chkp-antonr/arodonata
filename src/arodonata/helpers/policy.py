"""Helper functions for policy and session management operations.

Provides session management, write operations, and rule queries.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ..logger import lazy_logger

if TYPE_CHECKING:
    from ..api.client import ArodonataClient
    from ..cache.models import CPObject
    from ..models.rulebases import AccessRule, HTTPSRule, NATRule, ThreatRule
    from ._context import UserContext

log = lazy_logger("arodonata.helpers.policy")


def _generate_session_id(username: str, description: str) -> str:
    """Generate a session ID in the format {username}-{timestamp}-{description}.

    Args:
        username: Username creating the session.
        description: Session description.

    Returns:
        Session ID string.
    """
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    # Sanitize description: replace spaces with underscores, remove special chars
    clean_desc = description.replace(" ", "_").replace("-", "_")[:50]
    return f"{username}-{timestamp}-{clean_desc}"


def _get_sid_from_session_tracker(
    client: ArodonataClient,
    mgmt_name: str,
    domain_name: str,
    session_id: str,
) -> str:
    """Extract SID from session tracker for a given session.

    Args:
        client: ArodonataClient instance.
        mgmt_name: Management server name.
        domain_name: Domain name.
        session_id: Session ID to lookup.

    Returns:
        SID string.

    Raises:
        ConfigurationError: If session tracker not available or session not found.
    """
    from ..core.exceptions import ConfigurationError

    if client._orchestration._session_tracker:
        session_changes = client._orchestration._session_tracker.get_session_changes(
            mgmt_name=mgmt_name, domain=domain_name
        )
        # Find the session change to get the actual SID
        sid = None
        for change in session_changes:
            if change.object_type == "session" and change.name == session_id:
                change_data = change.data if change.data else {}
                sid = change_data.get("sid")
                break
        if not sid:
            raise ConfigurationError(f"Session {session_id} not found in tracker")
        return sid
    else:
        raise ConfigurationError("Session tracker not available")


def _get_session_info_from_tracker(
    client: ArodonataClient,
    mgmt_name: str,
    domain_name: str,
    session_id: str,
) -> tuple[str, str]:
    """Resolve (sid, server_ip) for a tracked write session.

    The server IP recorded by create_session() is the domain server's —
    required on MDM, where the registry only knows the MDS IP. Sessions
    tracked before server_ip was recorded fall back to the registry.
    """
    if not client._orchestration._session_tracker:
        from ..core.exceptions import ConfigurationError

        raise ConfigurationError("Session tracker not available")

    for change in client._orchestration._session_tracker.get_session_changes(mgmt_name=mgmt_name, domain=domain_name):
        if change.object_type == "session" and change.name == session_id:
            data = change.data or {}
            sid = data.get("sid")
            if not sid:
                break
            server_ip = data.get("server_ip") or _get_server_ip_from_registry(client, mgmt_name)
            return sid, server_ip

    from ..core.exceptions import ConfigurationError

    raise ConfigurationError(f"Session {session_id} not found in tracker")


def _get_server_ip_from_registry(
    client: ArodonataClient,
    mgmt_name: str,
) -> str:
    """Extract server IP from registry for a given management server.

    Args:
        client: ArodonataClient instance.
        mgmt_name: Management server name.

    Returns:
        Server IP string.

    Raises:
        ConfigurationError: If management server not found in registry.
    """
    from ..core.exceptions import ConfigurationError

    server_config = client._mgmt._registry.get_server(mgmt_name)
    if not server_config:
        raise ConfigurationError(f"Management server {mgmt_name} not found in registry")
    return server_config.server_ip


async def create_session(
    client: ArodonataClient,
    mgmt_name: str,
    domain_name: str,
    user_context: UserContext,
    description: str | None = None,
) -> str:
    """Create a write session for policy changes.

    Args:
        client: ArodonataClient instance.
        mgmt_name: Management server name.
        domain_name: Domain name (empty string for system domain).
        user_context: User context for session tracking.
        description: Optional session description.

    Returns:
        Session ID string.
    """
    log().debug(f"User {user_context.username} ({user_context.source}) creating session on {mgmt_name}")

    # Generate session ID
    session_id = _generate_session_id(user_context.username, description or "session")

    # Create dedicated session. The returned server IP is the DOMAIN server's
    # (which differs from the MDS registry IP on MDM) — every follow-up call
    # for this session must go there, so it is tracked alongside the SID.
    sid, server_ip = await client._mgmt.create_dedicated_session(
        mgmt_name=mgmt_name,
        domain=domain_name,
        session_name=session_id,
        session_description=description or "",
    )

    # Store session info in tracker (using 'add' operation for session creation)
    if client._orchestration._session_tracker:
        from ..core.session_tracker import SessionChange

        client._orchestration._session_tracker.add_change(
            mgmt_name=mgmt_name,
            domain=domain_name,
            change=SessionChange(
                operation="add",
                object_type="session",
                uid=sid,
                name=session_id,
                data={"sid": sid, "server_ip": server_ip},
            ),
        )

    return session_id


async def publish_session(
    client: ArodonataClient,
    mgmt_name: str,
    domain_name: str,
    session_id: str,
    user_context: UserContext,
) -> dict[str, Any]:
    """Publish session changes.

    Args:
        client: ArodonataClient instance.
        mgmt_name: Management server name.
        domain_name: Domain name (empty string for system domain).
        session_id: Session ID from create_session().
        user_context: User context for session tracking.

    Returns:
        API call result as dictionary.
    """
    log().debug(f"User {user_context.username} ({user_context.source}) publishing session {session_id[:8]}...")

    # Resolve the tracked session's SID and its (domain) server IP
    sid, server_ip = _get_session_info_from_tracker(client, mgmt_name, domain_name, session_id)

    # Use api_call_with_sid to ensure correct SID is used
    result = await client.api_call_with_sid(
        mgmt_name=mgmt_name,
        sid=sid,
        server_ip=server_ip,
        command="publish",
        payload={},
    )

    # Clear session changes from tracker
    if client._orchestration._session_tracker:
        client._orchestration._session_tracker.clear_session(mgmt_name=mgmt_name, domain=domain_name)

    # Return result as dictionary
    if hasattr(result, "model_dump"):
        return result.model_dump()
    elif hasattr(result, "data"):
        result_data = result.data if result.data else {}
        return result_data if isinstance(result_data, dict) else {}
    # Fallback: convert to dict
    return {"success": result.success, "message": getattr(result, "message", "")}


async def discard_session(
    client: ArodonataClient,
    mgmt_name: str,
    domain_name: str,
    session_id: str,
    user_context: UserContext,
) -> None:
    """Discard session changes.

    Args:
        client: ArodonataClient instance.
        mgmt_name: Management server name.
        domain_name: Domain name (empty string for system domain).
        session_id: Session ID from create_session().
        user_context: User context for session tracking.
    """
    log().debug(f"User {user_context.username} ({user_context.source}) discarding session {session_id[:8]}...")

    # Resolve the tracked session's SID and its (domain) server IP
    sid, server_ip = _get_session_info_from_tracker(client, mgmt_name, domain_name, session_id)

    # Use api_call_with_sid to ensure correct SID is used
    await client.api_call_with_sid(
        mgmt_name=mgmt_name,
        sid=sid,
        server_ip=server_ip,
        command="discard",
        payload={},
    )

    # Clear session changes from tracker
    if client._orchestration._session_tracker:
        client._orchestration._session_tracker.clear_session(mgmt_name=mgmt_name, domain=domain_name)


@asynccontextmanager
async def write_session(
    client: ArodonataClient,
    mgmt_name: str,
    domain_name: str,
    user_context: UserContext,
    description: str | None = None,
    auto_publish: bool = True,
) -> AsyncIterator[str]:
    """Context manager for write sessions.

    Automatically handles publish/discard based on success/exception.

    Args:
        client: ArodonataClient instance.
        mgmt_name: Management server name.
        domain_name: Domain name (empty string for system domain).
        user_context: User context for session tracking.
        description: Optional session description.
        auto_publish: If True (default), publish on successful completion.
                      If False, discard on exit (useful for testing).

    Yields:
        Session ID string.

    Example:
        async with write_session(client, "mgmt1", "domain1", context, "Add host") as session_id:
            await add_object(client, mgmt_name="mgmt1", domain_name="domain1", session_id=session_id, ...)
    """
    session_id = None

    try:
        session_id = await create_session(
            client=client,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            user_context=user_context,
            description=description,
        )
        yield session_id
        # Publish on successful completion
        if auto_publish:
            await publish_session(
                client=client,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                session_id=session_id,
                user_context=user_context,
            )
        else:
            # Discard if auto_publish is False
            await discard_session(
                client=client,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                session_id=session_id,
                user_context=user_context,
            )
    except Exception:
        # Discard on exception
        if session_id:
            await discard_session(
                client=client,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                session_id=session_id,
                user_context=user_context,
            )
        raise


async def add_object(
    client: ArodonataClient,
    mgmt_name: str,
    domain_name: str,
    object_type: str,
    data: dict[str, Any],
    session_id: str,
    user_context: UserContext,
) -> CPObject:
    """Add object to session.

    Args:
        client: ArodonataClient instance.
        mgmt_name: Management server name.
        domain_name: Domain name (empty string for system domain).
        object_type: Object type (host, network, group, etc.).
        data: Object properties (must include 'name' field).
        session_id: Session ID from create_session().
        user_context: User context for session tracking.

    Returns:
        CPObject instance for the created object.
    """
    log().debug(f"User {user_context.username} ({user_context.source}) adding {object_type} {data.get('name')}")

    # Resolve the tracked session's SID and its (domain) server IP
    sid, server_ip = _get_session_info_from_tracker(client, mgmt_name, domain_name, session_id)

    command = f"add-{object_type}"
    payload = data

    result = await client.api_call_with_sid(
        mgmt_name=mgmt_name,
        sid=sid,
        server_ip=server_ip,
        command=command,
        payload=payload,
    )

    if not result.success:
        from ..core.exceptions import ApiError

        raise ApiError(f"Failed to add {object_type}: {result.message}")

    # Track change if successful
    if client._orchestration._session_tracker:
        from ..core.session_tracker import SessionChange

        result_data = result.data if result.data else {}
        uid = result_data.get("uid", "")
        name = data.get("name", "")
        if isinstance(uid, str):
            client._orchestration._session_tracker.add_change(
                mgmt_name=mgmt_name,
                domain=domain_name,
                change=SessionChange(
                    operation="add",
                    object_type=object_type,
                    uid=uid,
                    name=name,
                    data=data,
                ),
            )

    # Return CPObject
    from ..cache.models import CPObject

    return CPObject(
        uid=uid,
        name=name,
        object_type=object_type,
        domain=domain_name,
        mgmt_name=mgmt_name,
        data=data,
    )


async def _resolve_object_type(
    obj_service: Any,
    uid: str,
    data: dict[str, Any],
) -> str:
    """Determine object type from data or fetch from cache.

    Args:
        obj_service: Object service used to look up the cached object.
        uid: Object UID to resolve the type for.
        data: Object properties to update; checked first for a "type" key.

    Returns:
        Resolved object type string.

    Raises:
        ConfigurationError: If the object type cannot be determined from
            data or from the cache.
    """
    object_type = data.get("type")
    if not object_type:
        # Try to get object type from cache
        cached_obj = await obj_service._cache.get_object_by_uid(uid)
        if cached_obj:
            # Use getattr to safely access object_type attribute
            object_type = getattr(cached_obj, "object_type", None)
            if not object_type:
                from ..core.exceptions import ConfigurationError

                raise ConfigurationError(f"Cannot determine object type for UID {uid}")
        else:
            from ..core.exceptions import ConfigurationError

            raise ConfigurationError(f"Cannot determine object type for UID {uid}")

    return object_type


def _record_change_if_tracked(
    client: ArodonataClient,
    mgmt_name: str,
    domain_name: str,
    object_type: str,
    uid: str,
    data: dict[str, Any],
) -> None:
    """Record a "modify" change in the session tracker, if one is active.

    Args:
        client: ArodonataClient instance.
        mgmt_name: Management server name.
        domain_name: Domain name (empty string for system domain).
        object_type: Resolved object type being modified.
        uid: Object UID that was modified.
        data: Object properties that were set.
    """
    if client._orchestration._session_tracker:
        from ..core.session_tracker import SessionChange

        client._orchestration._session_tracker.add_change(
            mgmt_name=mgmt_name,
            domain=domain_name,
            change=SessionChange(
                operation="modify",
                object_type=object_type,
                uid=uid,
                name=uid,
                data=data,
            ),
        )


async def set_object(
    client: ArodonataClient,
    mgmt_name: str,
    domain_name: str,
    uid: str,
    data: dict[str, Any],
    session_id: str,
    user_context: UserContext,
) -> CPObject:
    """Update object in session.

    Args:
        client: ArodonataClient instance.
        mgmt_name: Management server name.
        domain_name: Domain name (empty string for system domain).
        uid: Object UID to update.
        data: Object properties to update.
        session_id: Session ID from create_session().
        user_context: User context for session tracking.

    Returns:
        CPObject instance for the updated object.
    """
    log().debug(f"User {user_context.username} ({user_context.source}) updating object {uid}")

    # Resolve the tracked session's SID and its (domain) server IP
    sid, server_ip = _get_session_info_from_tracker(client, mgmt_name, domain_name, session_id)

    # Determine object type from data or fetch from cache
    object_type = await _resolve_object_type(client._object_service, uid, data)

    command = f"set-{object_type}"
    payload = {"uid": uid, **data}

    result = await client.api_call_with_sid(
        mgmt_name=mgmt_name,
        sid=sid,
        server_ip=server_ip,
        command=command,
        payload=payload,
    )

    if not result.success:
        from ..core.exceptions import ApiError

        raise ApiError(f"Failed to set object {uid}: {result.message}")

    # Track change if successful
    _record_change_if_tracked(client, mgmt_name, domain_name, object_type, uid, data)

    # Return CPObject
    from ..cache.models import CPObject

    return CPObject(
        uid=uid,
        name=data.get("name", uid),
        object_type=object_type,
        domain=domain_name,
        mgmt_name=mgmt_name,
        data=data,
    )


async def delete_object(
    client: ArodonataClient,
    mgmt_name: str,
    domain_name: str,
    uid: str,
    session_id: str,
    user_context: UserContext,
) -> None:
    """Delete object in session.

    Args:
        client: ArodonataClient instance.
        mgmt_name: Management server name.
        domain_name: Domain name (empty string for system domain).
        uid: Object UID to delete.
        session_id: Session ID from create_session().
        user_context: User context for session tracking.
    """
    log().debug(f"User {user_context.username} ({user_context.source}) deleting object {uid}")

    # Resolve the tracked session's SID and its (domain) server IP
    sid, server_ip = _get_session_info_from_tracker(client, mgmt_name, domain_name, session_id)

    # Determine object type from cache
    obj_service = client._object_service
    cached_obj = await obj_service._cache.get_object_by_uid(uid)
    if not cached_obj:
        from ..core.exceptions import ConfigurationError

        raise ConfigurationError(f"Cannot find object with UID {uid}")

    # Use getattr to safely access object_type attribute
    object_type = getattr(cached_obj, "object_type", None)
    if not object_type:
        from ..core.exceptions import ConfigurationError

        raise ConfigurationError("Cached object has no object_type attribute")

    command = f"delete-{object_type}"
    payload = {"uid": uid}

    result = await client.api_call_with_sid(
        mgmt_name=mgmt_name,
        sid=sid,
        server_ip=server_ip,
        command=command,
        payload=payload,
    )

    if not result.success:
        from ..core.exceptions import ApiError

        raise ApiError(f"Failed to delete object {uid}: {result.message}")

    # Track change if successful
    if client._orchestration._session_tracker:
        from ..core.session_tracker import SessionChange

        client._orchestration._session_tracker.add_change(
            mgmt_name=mgmt_name,
            domain=domain_name,
            change=SessionChange(
                operation="delete",
                object_type=object_type,
                uid=uid,
                name=cached_obj.name,
                data=None,
            ),
        )


async def get_access_rules(
    client: ArodonataClient,
    layer_name: str | None = None,
    mgmt_name: str | None = None,
    domain_name: str | None = None,
    user_context: UserContext | None = None,
) -> list[AccessRule]:
    """Get access rules.

    Args:
        client: ArodonataClient instance.
        layer_name: Optional layer name filter.
        mgmt_name: Optional management server filter.
        domain_name: Optional domain filter.
        user_context: Optional user context for logging.

    Returns:
        List of access rules.
    """
    if user_context:
        log().debug(f"User {user_context.username} ({user_context.source}) getting access rules")

    orchestration = client._orchestration

    # Convert single values to lists for orchestration call
    mgmt_names = [mgmt_name] if mgmt_name else None
    domain_names = [domain_name] if domain_name else None

    return await orchestration.get_access_rules(
        layer_name=layer_name,
        mgmt_names=mgmt_names,
        domain_names=domain_names,
    )


async def get_nat_rules(
    client: ArodonataClient,
    layer_name: str | None = None,
    mgmt_name: str | None = None,
    domain_name: str | None = None,
    user_context: UserContext | None = None,
) -> list[NATRule]:
    """Get NAT rules.

    Args:
        client: ArodonataClient instance.
        layer_name: Optional layer name filter.
        mgmt_name: Optional management server filter.
        domain_name: Optional domain filter.
        user_context: Optional user context for logging.

    Returns:
        List of NAT rules.
    """
    if user_context:
        log().debug(f"User {user_context.username} ({user_context.source}) getting NAT rules")

    orchestration = client._orchestration

    # Convert single values to lists for orchestration call
    mgmt_names = [mgmt_name] if mgmt_name else None
    domain_names = [domain_name] if domain_name else None

    return await orchestration.get_nat_rules(
        layer_name=layer_name,
        mgmt_names=mgmt_names,
        domain_names=domain_names,
    )


async def get_https_rules(
    client: ArodonataClient,
    layer_name: str | None = None,
    mgmt_name: str | None = None,
    domain_name: str | None = None,
    user_context: UserContext | None = None,
) -> list[HTTPSRule]:
    """Get HTTPS rules.

    Args:
        client: ArodonataClient instance.
        layer_name: Optional layer name filter.
        mgmt_name: Optional management server filter.
        domain_name: Optional domain filter.
        user_context: Optional user context for logging.

    Returns:
        List of HTTPS rules.
    """
    if user_context:
        log().debug(f"User {user_context.username} ({user_context.source}) getting HTTPS rules")

    orchestration = client._orchestration

    # Convert single values to lists for orchestration call
    mgmt_names = [mgmt_name] if mgmt_name else None
    domain_names = [domain_name] if domain_name else None

    return await orchestration.get_https_rules(
        layer_name=layer_name,
        mgmt_names=mgmt_names,
        domain_names=domain_names,
    )


async def get_threat_rules(
    client: ArodonataClient,
    layer_name: str | None = None,
    mgmt_name: str | None = None,
    domain_name: str | None = None,
    user_context: UserContext | None = None,
) -> list[ThreatRule]:
    """Get threat rules.

    Args:
        client: ArodonataClient instance.
        layer_name: Optional layer name filter.
        mgmt_name: Optional management server filter.
        domain_name: Optional domain filter.
        user_context: Optional user context for logging.

    Returns:
        List of threat rules.
    """
    if user_context:
        log().debug(f"User {user_context.username} ({user_context.source}) getting threat rules")

    orchestration = client._orchestration

    # Convert single values to lists for orchestration call
    mgmt_names = [mgmt_name] if mgmt_name else None
    domain_names = [domain_name] if domain_name else None

    return await orchestration.get_threat_rules(
        layer_name=layer_name,
        mgmt_names=mgmt_names,
        domain_names=domain_names,
    )
