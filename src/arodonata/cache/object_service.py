"""High-level object cache operations."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select

from ..config import GLOBAL_DOMAIN_NAME
from ..core import RefreshMode
from ..core.domain_list_refresh import DOMAIN_LIST_REFRESH_TTL_SECONDS, DomainListRefreshTracker
from ..core.incremental_refresh import FallbackToFull, IncrementalRefresher
from ..logger import lazy_logger
from ..utils.helpers import utc_now_naive
from .database import DatabaseManager
from .models import CPObject, Domain, LastPublishedSession
from .repository import CacheRepository

if TYPE_CHECKING:
    from ..api.client import ArodonataClient
    from ..core.cache_policy import Clock

log = lazy_logger("arodonata.cache.object_service")


# ---------------------------------------------------------------------------
# SearchType enum and input classification
# ---------------------------------------------------------------------------


class SearchType(StrEnum):
    """Classification of search input."""

    HOST = "host"
    NETWORK = "network"
    RANGE = "address-range"
    NAME = "name"


# Regex patterns for input classification
_IP_RANGE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$")
_NETWORK_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,3}(?:\.\d{1,3}){0,3}|\d{1,2})$")
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def classify_input(raw: str) -> tuple[SearchType, str]:
    """Classify search input and return (SearchType, cleaned_input).

    Args:
        raw: User input string (IP, network, range, or name).

    Returns:
        Tuple of (SearchType, cleaned_input).

    Examples:
        >>> classify_input("127.0.0.1")
        (SearchType.HOST, '127.0.0.1')
        >>> classify_input("192.168.1.0/24")
        (SearchType.NETWORK, '192.168.1.0/24')
        >>> classify_input("10.0.0.1-10.0.0.10")
        (SearchType.RANGE, '10.0.0.1-10.0.0.10')
        >>> classify_input("web-server-01")
        (SearchType.NAME, 'web-server-01')
    """
    text = raw.strip()

    if _IP_RANGE_RE.match(text):
        return SearchType.RANGE, text

    if _NETWORK_RE.match(text):
        return SearchType.NETWORK, text

    if _IPV4_RE.match(text):
        return SearchType.HOST, text

    return SearchType.NAME, text


# ---------------------------------------------------------------------------
# Module-level object converter functions
# ---------------------------------------------------------------------------


def _extract_ip_fields(obj_type: str, api_obj: dict[str, Any]) -> tuple[str, str, str, str, str]:
    ipv4_address = ""
    subnet4 = ""
    subnet_mask = ""
    ipv4_address_first = ""
    ipv4_address_last = ""

    if obj_type == "host":
        ipv4_address = api_obj.get("ipv4-address", "")
    elif obj_type == "network":
        subnet4 = api_obj.get("subnet4", "")
        subnet_mask = api_obj.get("subnet-mask", "")
    elif obj_type == "address-range":
        ipv4_address_first = api_obj.get("ipv4-address-first", "")
        ipv4_address_last = api_obj.get("ipv4-address-last", "")

    return ipv4_address, subnet4, subnet_mask, ipv4_address_first, ipv4_address_last


def _extract_group_members(obj_type: str, api_obj: dict[str, Any]) -> str:
    if obj_type != "group":
        return ""

    members_list = api_obj.get("members", [])
    if not isinstance(members_list, list):
        return ""

    member_uids = []
    for m in members_list:
        if isinstance(m, str):
            member_uids.append(m)
        elif isinstance(m, dict):
            member_uids.append(m.get("uid", ""))

    return ",".join(f'"{uid}"' for uid in member_uids if uid)


def _extract_tags(api_obj: dict[str, Any]) -> str:
    tags_list = api_obj.get("tags", [])
    if not isinstance(tags_list, list):
        return ""

    tag_names = []
    for t in tags_list:
        if isinstance(t, str):
            tag_names.append(t)
        elif isinstance(t, dict):
            tag_names.append(t.get("name", ""))
    return ",".join(tag_names)


def _parse_api_timestamp(time_data: dict[str, Any] | None) -> datetime | None:
    """Parse timestamp from API meta-info.

    Args:
        time_data: Time data from API meta-info (contains 'iso-8601' or 'posix').

    Returns:
        Naive datetime for database compatibility, or None.
        Returns None if input is None, empty, or unparseable (never raises).
    """
    if not time_data:
        return None

    # Try ISO-8601
    iso_time = time_data.get("iso-8601")
    if iso_time:
        try:
            if iso_time.endswith("+0000"):
                iso_time = iso_time.replace("+0000", "+00:00")
            return datetime.fromisoformat(iso_time.replace("Z", "+00:00")).astimezone(UTC).replace(tzinfo=None)
        except (ValueError, TypeError):
            pass

    # Try POSIX
    posix_time = time_data.get("posix")
    if posix_time:
        try:
            return datetime.fromtimestamp(int(posix_time) / 1000, tz=UTC).replace(tzinfo=None)
        except (ValueError, TypeError, OverflowError):
            pass

    return None


def api_object_to_cpobject(
    api_obj: dict[str, Any],
    mgmt_name: str,
    domain_name: str,
) -> CPObject | None:
    """Convert a full-detail API object dict to a CPObject row.

    The single canonical converter: both the full-reload path and the
    incremental re-fetch path produce rows through this function.
    """
    try:
        # Extract common fields
        uid = api_obj.get("uid", "")
        name = api_obj.get("name", "")
        obj_type = api_obj.get("type", "")

        if not uid or not name:
            log().warning(f"API object missing uid or name: {api_obj}")
            return None

        # Build compound key
        obj_id = f"{mgmt_name}:{domain_name}:{uid}"

        # Extract IP fields
        ipv4_address, subnet4, subnet_mask, ipv4_address_first, ipv4_address_last = _extract_ip_fields(
            obj_type, api_obj
        )

        # Extract group members
        members = _extract_group_members(obj_type, api_obj)

        # Extract other common fields
        comments = api_obj.get("comments", "")
        tags = _extract_tags(api_obj)

        color = api_obj.get("color", "")

        # Extract new fields (interfaces, nat_settings, version, cluster_uid, original_domain_uid)
        interfaces = api_obj.get("interfaces")  # Returns list or None
        nat_settings = api_obj.get("nat-settings")  # Returns dict or None
        version = api_obj.get("version", "")
        cluster_uid = api_obj.get("cluster-uid", "")
        domain_data = api_obj.get("domain", {})
        if isinstance(domain_data, dict):
            original_domain_uid = domain_data.get("uid", "")
        else:
            original_domain_uid = ""

        # Extract timestamps
        # Check for malformed timestamp dicts (not iso-8601 or posix keys)
        # to match the old to_db_datetime behavior for backwards compatibility
        creation_time_data = api_obj.get("creation-time")
        if isinstance(creation_time_data, dict) and creation_time_data:
            if "iso-8601" not in creation_time_data and "posix" not in creation_time_data:
                raise ValueError(f"Malformed timestamp dict: {creation_time_data}")
        creation_time = _parse_api_timestamp(creation_time_data)

        last_modify_time_data = api_obj.get("last-modify-time")
        if isinstance(last_modify_time_data, dict) and last_modify_time_data:
            if "iso-8601" not in last_modify_time_data and "posix" not in last_modify_time_data:
                raise ValueError(f"Malformed timestamp dict: {last_modify_time_data}")
        last_modify_time = _parse_api_timestamp(last_modify_time_data)

        # Get original domain (for global objects)
        original_domain = api_obj.get("domain", {}).get("name", "")

        # Create CPObject
        cp_obj = CPObject(
            id=obj_id,
            uid=uid,
            name=name,
            type=obj_type,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            original_domain=original_domain,
            ipv4_address=ipv4_address,
            subnet4=subnet4,
            subnet_mask=subnet_mask,
            ipv4_address_first=ipv4_address_first,
            ipv4_address_last=ipv4_address_last,
            members=members,
            comments=comments,
            tags=tags,
            color=color,
            interfaces=interfaces,
            nat_settings=nat_settings,
            version=version,
            cluster_uid=cluster_uid,
            original_domain_uid=original_domain_uid,
            creation_time=creation_time,
            last_modify_time=last_modify_time,
            update_time=utc_now_naive(),
            raw_data=api_obj,
        )

        return cp_obj

    except Exception as e:
        log().exception(f"Error converting API object to CPObject: {e}")
        return None


# ---------------------------------------------------------------------------
# Result data classes
# ---------------------------------------------------------------------------


@dataclass
class GroupNode:
    """A node in the group membership tree."""

    uid: str
    name: str
    domain: str
    depth: int
    children: list[GroupNode] | None = None

    def __post_init__(self) -> None:
        if self.children is None:
            self.children = []


@dataclass
class SearchResult:
    """Search result for a single term."""

    search_term: str
    search_type: SearchType
    objects: list[CPObject]
    memberships: dict[str, list[GroupNode]] | None = None


# ---------------------------------------------------------------------------
# ObjectService
# ---------------------------------------------------------------------------


class ObjectService:
    """High-level object cache operations.

    Provides search and refresh functionality with cache-first queries,
    API fallback, and SSE streaming for progress tracking.
    """

    # Object types to fetch from API
    OBJECT_TYPES = ["host", "network", "address-range", "group"]

    # Above this many collected objects held in memory before the atomic
    # swap, warn so operators can spot unexpectedly large domain refreshes.
    LARGE_DOMAIN_WARN_THRESHOLD = 50_000

    def __init__(
        self,
        db_manager: DatabaseManager,
        client: ArodonataClient,
        max_incremental_changes: int = 500,
        domain_list_refresh_ttl: int = DOMAIN_LIST_REFRESH_TTL_SECONDS,
        clock: Clock | None = None,
    ) -> None:
        """Initialize ObjectService.

        Args:
            db_manager: DatabaseManager instance.
            client: ArodonataClient instance for API fallback.
            max_incremental_changes: Max in-scope changes an incremental
                apply will accept before falling back to a full reload.
            domain_list_refresh_ttl: Seconds between opportunistic (CHECK/
                INCREMENTAL-mode) re-fetches of a management server's domain
                list. FORCE mode ignores this and always re-fetches. See
                `DOMAIN_LIST_REFRESH_TTL_SECONDS`.
            clock: Injectable time source for the TTL memo (tests only;
                defaults to the real wall clock).
        """
        self._db = db_manager
        self._cache = CacheRepository(db_manager)
        self._client = client
        self.max_incremental_changes = max_incremental_changes
        self._domain_list_refresh = DomainListRefreshTracker(ttl_seconds=domain_list_refresh_ttl, clock=clock)

    async def _fetch_objects_from_db(
        self,
        search_type: SearchType,
        cleaned: str,
        mgmt_names: list[str] | None,
        domain_names: list[str] | None,
    ) -> list[CPObject]:
        """Fetch objects from cache based on search type."""
        objects: list[CPObject] = []

        if search_type == SearchType.HOST:
            objects = await self._cache.get_objects_by_ip(
                ip_address=cleaned,
                mgmt_names=mgmt_names,
                domain_names=domain_names,
            )
        elif search_type == SearchType.NETWORK:
            objects = await self._cache.get_objects_by_subnet(
                subnet=cleaned,
                mgmt_names=mgmt_names,
                domain_names=domain_names,
            )
        elif search_type == SearchType.RANGE:
            if "-" in cleaned:
                start_ip, end_ip = cleaned.split("-", 1)
                start_ip = start_ip.strip()
                end_ip = end_ip.strip()

                objects = await self._cache.get_objects_in_ip_range(
                    start_ip=start_ip,
                    end_ip=end_ip,
                    mgmt_names=mgmt_names,
                    domain_names=domain_names,
                )
        elif search_type == SearchType.NAME:
            objects = await self._cache.get_objects_by_name(
                name=cleaned,
                mgmt_names=mgmt_names,
                domain_names=domain_names,
            )
        return objects

    async def search_objects(
        self,
        search_input: str,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        max_depth: int = 2,
    ) -> AsyncIterator[SearchResult]:
        """Search for objects by IP, name, UID, or type.

        Args:
            search_input: Comma-separated search terms.
            mgmt_names: Optional management server filter.
            domain_names: Optional domain filter.
            max_depth: Maximum depth for group membership traversal.

        Yields:
            SearchResult for each search term.
        """
        # Parse comma-separated input
        terms = [t.strip() for t in search_input.split(",") if t.strip()]

        if not terms:
            yield SearchResult(
                search_term=search_input,
                search_type=SearchType.NAME,
                objects=[],
            )
            return

        # Get target management servers
        target_mgmt_names = mgmt_names or self._client.get_mgmt_names()

        if not target_mgmt_names:
            log().warning("No management servers configured for search")
            yield SearchResult(
                search_term=search_input,
                search_type=SearchType.NAME,
                objects=[],
            )
            return

        # Search for each term
        for term in terms:
            # Classify the search input
            search_type, cleaned = classify_input(term)

            # Query cache based on search type
            objects = await self._fetch_objects_from_db(search_type, cleaned, target_mgmt_names, domain_names)

            # Resolve group memberships if objects found
            memberships: dict[str, list[GroupNode]] | None = None
            if objects and max_depth > 0:
                memberships = {}
                for obj in objects:
                    obj_groups = await self._resolve_group_memberships(
                        obj_uid=obj.uid,
                        mgmt_name=obj.mgmt_name,
                        domain_name=obj.domain_name,
                        max_depth=max_depth,
                    )
                    if obj_groups:
                        memberships[obj.uid] = obj_groups

            yield SearchResult(
                search_term=term,
                search_type=search_type,
                objects=objects,
                memberships=memberships if memberships else None,
            )

    async def refresh_objects(
        self,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        mode: str = "force",  # RefreshMode value
        include_global: bool = False,
    ) -> AsyncIterator[dict[str, Any]]:
        """Refresh object cache from API.

        Args:
            mgmt_names: Optional management server filter.
            domain_names: Optional domain filter.
            mode: Refresh mode (skip/check/force/incremental).
            include_global: When False (default), the synthetic "Global" domain
                is excluded from the all-domains refresh path so existing
                callers see today's behavior. An explicit ``domain_names``
                request for "Global" is honored regardless of this flag.

        Yields:
            Progress dictionaries with keys:
                - message: str - Progress message
                - mgmt_name: str - Management server name
                - domain_name: str - Domain name
                - object_type: str - Type being fetched
                - count: int - Number of objects processed
                - total: int - Total objects to process
        """
        # Parse refresh mode
        try:
            refresh_mode = RefreshMode(mode)
        except ValueError:
            log().warning(f"Invalid refresh mode '{mode}', defaulting to 'skip'")
            refresh_mode = RefreshMode.SKIP

        # Handle SKIP mode
        if refresh_mode == RefreshMode.SKIP:
            yield {
                "message": "Refresh skipped (mode=skip)",
                "status": "skipped",
            }
            return

        # Get target management servers
        target_mgmt_names = mgmt_names or self._client.get_mgmt_names()

        if not target_mgmt_names:
            yield {
                "message": "No management servers available",
                "status": "error",
            }
            return

        log().info(f"Refreshing object cache for {len(target_mgmt_names)} server(s), mode={refresh_mode.value}")

        # Process each management server
        for mgmt_name in target_mgmt_names:
            async for progress in self._refresh_mgmt_server(
                mgmt_name=mgmt_name,
                domain_names=domain_names,
                mode=refresh_mode,
                include_global=include_global,
            ):
                yield progress

    async def _refresh_mgmt_server(
        self,
        mgmt_name: str,
        domain_names: list[str] | None,
        mode: RefreshMode,
        include_global: bool = False,
    ) -> AsyncIterator[dict[str, Any]]:
        """Refresh objects for a single management server.

        Args:
            mgmt_name: Management server name.
            domain_names: Optional domain filter.
            mode: Refresh mode.
            include_global: When False (default), the synthetic "Global" domain
                is excluded from the all-domains refresh path.

        Yields:
            Progress dictionaries.
        """
        yield {
            "message": f"Processing {mgmt_name}",
            "mgmt_name": mgmt_name,
            "status": "processing_mgmt",
        }

        # Get domains to refresh
        domains_to_refresh = await self._get_domains_to_refresh(
            mgmt_name=mgmt_name,
            domain_names=domain_names,
            mode=mode,
            include_global=include_global,
        )

        if not domains_to_refresh:
            yield {
                "message": f"No domains to refresh for {mgmt_name}",
                "mgmt_name": mgmt_name,
                "status": "no_domains",
            }
            return

        log().debug(f"Refreshing {len(domains_to_refresh)} domain(s) for {mgmt_name}")

        # Process each domain
        refresh = self._refresh_domain_incremental if mode == RefreshMode.INCREMENTAL else self._refresh_domain
        for domain_name in domains_to_refresh:
            async for progress in refresh(mgmt_name=mgmt_name, domain_name=domain_name):
                yield progress

    async def _get_domains_to_refresh(
        self,
        mgmt_name: str,
        domain_names: list[str] | None,
        mode: RefreshMode,
        include_global: bool = False,
    ) -> list[str]:
        """Get list of domains that need refreshing.

        A domain created in SmartConsole after this mgmt's domains table was
        first seeded used to be invisible to every refresh forever: the old
        code only ever called `populate_domain_cache` when the table came
        back completely empty. That floor behavior is preserved below, but
        it is no longer the *only* trigger for a domain-list re-fetch:

        * FORCE mode always re-fetches unconditionally (no TTL, no
          conditions) - see `_refetch_domain_list`.
        * CHECK/INCREMENTAL ("smart") modes re-fetch opportunistically, at
          most once every `DOMAIN_LIST_REFRESH_TTL_SECONDS` (default) - see
          `self._domain_list_refresh` (a `DomainListRefreshTracker`) - so a
          new domain surfaces within that window without hammering
          `show-domains` on every smart-refresh tick.

        This single mechanism also covers what a separate "backfill a
        missing Global row" special case used to handle on its own: any
        re-fetch (forced or TTL-triggered) re-populates the whole domain
        list, Global row included, so that special case no longer needs to
        exist as its own bypass-the-TTL code path.

        Args:
            mgmt_name: Management server name.
            domain_names: Optional domain filter.
            mode: Refresh mode.
            include_global: When False (default), the synthetic "Global" domain
                is excluded from the table read. An explicit request for
                "Global" via ``domain_names`` is honored regardless, since
                this method treats ``domain_names`` as an intersection filter
                against the table rather than a pass-through - if the table
                read excluded Global, an explicit request for it would be
                filtered out before the intersection ever runs.

        Returns:
            List of domain names to refresh.
        """
        # An explicit request for "Global" must reach the table even if the
        # caller didn't set include_global - otherwise it gets filtered out
        # before the intersection below can match it.
        fetch_include_global = include_global or (GLOBAL_DOMAIN_NAME in (domain_names or []))

        # Get all domains for this mgmt server
        all_domains = await self._cache.get_domains(mgmt_name=mgmt_name, include_global=fetch_include_global)

        # Floor: an empty table must always be populated, regardless of mode/TTL.
        table_was_empty = not all_domains
        should_refetch = (
            table_was_empty or mode == RefreshMode.FORCE or self._domain_list_refresh.is_stale(mgmt_name)
        )

        if should_refetch:
            all_domains = await self._refetch_domain_list(
                mgmt_name=mgmt_name,
                fetch_include_global=fetch_include_global,
                fallback=all_domains,
                required=table_was_empty,
            )

        if not all_domains:
            log().warning(f"No domains found for {mgmt_name}")
            return []

        # Filter by domain_names if specified
        if domain_names:
            filtered_domains = [d for d in all_domains if d.domain_name in domain_names]
        else:
            filtered_domains = all_domains

        # For FORCE mode, refresh all filtered domains
        if mode == RefreshMode.FORCE:
            return [d.domain_name for d in filtered_domains]

        # For CHECK and INCREMENTAL modes, filter by staleness
        stale_domains = []
        for domain in filtered_domains:
            if await self._is_domain_stale(mgmt_name, domain.domain_name):
                stale_domains.append(domain.domain_name)

        return stale_domains

    async def _refetch_domain_list(
        self,
        mgmt_name: str,
        fetch_include_global: bool,
        fallback: list[Domain],
        required: bool,
    ) -> list[Domain]:
        """Re-fetch one mgmt server's domain list from the API and re-read the cache.

        Args:
            mgmt_name: Management server name.
            fetch_include_global: Whether the re-read should include the Global row.
            fallback: The already-cached domains to fall back to if the
                re-fetch can't be attempted or fails. An opportunistic
                re-fetch (TTL/force on an already-populated table) failing
                is not fatal - the existing, possibly slightly stale, cached
                list is safer to serve than nothing.
            required: True when the table was empty before this call - unlike
                the opportunistic case, a failed or unavailable re-fetch here
                must not be silently papered over with a fallback that is
                itself empty, so the caller gets ``[]`` instead.

        Returns:
            The freshly re-read domains, or ``fallback`` if the re-fetch
            could not run or failed.
        """
        if not hasattr(self._client, "_domain_service"):
            log().warning(f"Domain service not available for {mgmt_name}")
            return [] if required else fallback

        try:
            await self._client._domain_service.populate_domain_cache(mgmt_name)
        except Exception as e:
            log().exception(f"Failed to {'populate' if required else 'refresh'} domains for {mgmt_name}: {e}")
            return [] if required else fallback

        self._domain_list_refresh.mark_checked(mgmt_name)
        refreshed = await self._cache.get_domains(mgmt_name=mgmt_name, include_global=fetch_include_global)
        if refreshed:
            log().debug(f"Fetched {len(refreshed)} domain(s) for {mgmt_name}")
            return refreshed

        if required:
            log().warning(f"API returned no domains for {mgmt_name}")
            return []
        return fallback

    async def _resolve_group_memberships(
        self,
        obj_uid: str,
        mgmt_name: str,
        domain_name: str,
        max_depth: int = 2,
        current_depth: int = 0,
        visited: set[str] | None = None,
    ) -> list[GroupNode]:
        """Resolve group memberships for an object.

        Args:
            obj_uid: Object UID to find memberships for.
            mgmt_name: Management server name.
            domain_name: Domain name.
            max_depth: Maximum depth to traverse.
            current_depth: Current depth in recursion.
            visited: Set of visited UIDs to avoid cycles.

        Returns:
            List of GroupNode objects representing group memberships.
        """
        if visited is None:
            visited = set()

        # Prevent infinite recursion
        if current_depth >= max_depth:
            return []

        # Add current UID to visited set
        visited.add(obj_uid)

        # Find groups containing this object
        groups = await self._cache.get_objects_by_members(
            member_uid=obj_uid,
            mgmt_names=[mgmt_name],
            domain_names=[domain_name],
        )

        if not groups:
            return []

        # Build group nodes
        result = []
        for group in groups:
            # Skip if we've already visited this group (avoid cycles)
            if group.uid in visited:
                continue

            node = GroupNode(
                uid=group.uid,
                name=group.name,
                domain=group.domain_name,
                depth=current_depth,
                children=[],
            )

            # Recursively find parent groups
            parent_groups = await self._resolve_group_memberships(
                obj_uid=group.uid,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                max_depth=max_depth,
                current_depth=current_depth + 1,
                visited=visited.copy(),
            )

            if parent_groups:
                node.children = parent_groups

            result.append(node)

        return result

    async def _is_domain_stale(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> bool:
        """Check if a domain has stale object cache based on Last Published Session.

        Compares the last publish time from the API with the cached value.
        If no cached value or API value is newer, domain is considered stale.

        Args:
            mgmt_name: Management server name.
            domain_name: Domain name.

        Returns:
            True if domain is stale (needs refresh), False otherwise.
        """
        # 1. Check if there are any cached objects for this domain
        # This is a safety check: if objects are missing entirely, it's definitely stale
        if await self._count_cached_objects(mgmt_name, domain_name) == 0:
            log().debug(f"Domain {mgmt_name}/{domain_name} is stale (no cached objects)")
            return True

        # 2. Check LastPublishedSession comparison
        return await self._compare_published_times(mgmt_name, domain_name)

    async def _count_cached_objects(self, mgmt_name: str, domain_name: str) -> int:
        """Cheapest available check for whether a domain's object cache is empty."""
        count_stmt = select(func.count()).where(
            CPObject.mgmt_name == mgmt_name,  # type: ignore[arg-type]
            CPObject.domain_name == domain_name,  # type: ignore[arg-type]
        )
        async with self._cache._db.session() as session:
            res = await session.execute(count_stmt)
            return res.scalar() or 0

    async def _compare_published_times(self, mgmt_name: str, domain_name: str) -> bool:
        """Compare the API's last-published-session time to the cached value.

        Args:
            mgmt_name: Management server name.
            domain_name: Domain name.

        Returns:
            True if the API's published time is newer than the cached value,
            or if no cached session exists yet, False otherwise (including
            when the check cannot be completed).
        """
        try:
            # Fetch last published session from API
            api_domain = "" if domain_name in ("SMC User", "System Data") else domain_name

            response = await self._client.api_call(
                mgmt_name=mgmt_name,
                domain=api_domain,
                command="show-last-published-session",
                payload={},
            )

            if response.success and response.data:
                # Extract published_time from meta-info
                meta_info = response.data.get("meta-info", {})
                last_modify_time = meta_info.get("last-modify-time", {})

                # Parse timestamp (returns naive UTC)
                api_published_time = self._parse_api_timestamp(last_modify_time)

                if api_published_time:
                    # Get cached record
                    cached = await self._cache.get_last_published_session(mgmt_name, domain_name)

                    if not cached:
                        log().debug(f"Domain {mgmt_name}/{domain_name} is stale (no cached session info)")
                        return True

                    # Session uid comparison is authoritative: CP publish-times
                    # have MINUTE resolution, so a publish in the same minute
                    # as the cached baseline is invisible to the timestamp
                    # check below. Different uid == something was published.
                    api_uid = response.data.get("uid", "")
                    if api_uid and cached.uid:
                        if api_uid != cached.uid:
                            log().debug(
                                f"Domain {mgmt_name}/{domain_name} is stale "
                                f"(session uid {cached.uid[:8]} -> {api_uid[:8]})"
                            )
                            return True
                        log().debug(f"Domain {mgmt_name}/{domain_name} is up to date (uid match)")
                        return False

                    if api_published_time > cached.published_time:
                        log().debug(
                            f"Domain {mgmt_name}/{domain_name} is stale "
                            f"(API: {api_published_time}, Cache: {cached.published_time})"
                        )
                        return True

                    log().debug(f"Domain {mgmt_name}/{domain_name} is up to date")
                    return False

        except Exception as e:
            log().warning(f"Error checking staleness for {mgmt_name}/{domain_name}: {e}")
            # Fallback: if check fails, assume it's NOT stale to avoid excessive refreshes
            # unless it was already empty (handled by the cached-objects check)
            return False

        log().debug(f"Could not determine staleness for {mgmt_name}/{domain_name}, assuming fresh")
        return False

    def _parse_api_timestamp(self, time_data: dict[str, Any] | None) -> datetime | None:
        """Delegate to module-level timestamp parser."""
        return _parse_api_timestamp(time_data)

    async def refresh_last_published_session(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> LastPublishedSession | None:
        """Refresh and upsert the last-published-session record for one domain.

        Makes a single, lightweight `show-last-published-session` API call —
        does not touch CPObject or Asset caches. Safe to call independently
        of a full object/asset refresh.

        Args:
            mgmt_name: Management server name.
            domain_name: Domain name.

        Returns:
            The upserted LastPublishedSession record, or None if the API
            call failed or returned no usable timestamp.
        """
        try:
            api_domain = "" if domain_name in ("SMC User", "System Data") else domain_name

            response = await self._client.api_call(
                mgmt_name=mgmt_name,
                domain=api_domain,
                command="show-last-published-session",
                payload={},
            )

            if response.success and response.data:
                data = response.data
                meta_info = data.get("meta-info", {})
                last_modify_time = meta_info.get("last-modify-time", {})
                published_time = self._parse_api_timestamp(last_modify_time)

                if published_time:
                    record = LastPublishedSession(
                        id=f"{mgmt_name}:{domain_name}",
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        published_time=published_time,
                        uid=data.get("uid", ""),
                        name=data.get("name", ""),
                        ip_address=data.get("ip-address", ""),
                        creator=data.get("creator", ""),
                        description=data.get("description", ""),
                    )
                    await self._cache.upsert_last_published_session(record)
                    return record
        except Exception as e:
            log().warning(f"Failed to update LastPublishedSession for {mgmt_name}/{domain_name}: {e}")

        return None

    async def fetch_full_object(
        self,
        mgmt_name: str,
        domain_name: str,
        uid: str,
    ) -> dict[str, Any] | None:
        """Fetch one object in full detail via show-object.

        Returns the raw object dict, or None ONLY when the management server
        cleanly reports the object does not exist (deleted since the diff was
        taken). Any other failure raises RuntimeError — callers treat that as
        "incremental apply unsafe".
        """
        api_domain = "" if domain_name in ("SMC User", "System Data") else domain_name
        response = await self._client.api_call(
            mgmt_name=mgmt_name,
            command="show-object",
            domain=api_domain,
            details_level="full",
            payload={"uid": uid},
        )
        if response.success and response.data:
            obj = response.data.get("object")
            if isinstance(obj, dict):
                return obj
            raise RuntimeError(f"show-object {uid} returned no object payload")
        if "object_not_found" in (response.code or "") or "not found" in (response.message or "").lower():
            return None
        raise RuntimeError(f"show-object {uid} failed: {response.message or response.code or 'unknown error'}")

    def _make_refresher(self) -> IncrementalRefresher:
        # Built per-apply so runtime mutation of max_incremental_changes
        # always takes effect. The client's API adapter provides show_changes.
        return IncrementalRefresher(
            api=self._client._api_adapter,
            cache=self._cache,
            fetch_full_object=self.fetch_full_object,
            to_cpobject=api_object_to_cpobject,
            max_changes=self.max_incremental_changes,
        )

    async def _refresh_domain_incremental(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> AsyncIterator[dict[str, Any]]:
        """Incrementally refresh one stale domain from its show-changes diff.

        Changed objects are re-fetched in full (show-object) — the diff is
        only a change list. Any unsafe condition falls back to the atomic
        full-domain reload. The baseline stamp advances only on success
        (of either path).
        """
        if await self._count_cached_objects(mgmt_name, domain_name) == 0:
            # A domain with a baseline stamp but zero (or partial) cached rows
            # must not have a diff applied on top of it: the diff only covers
            # changes since the baseline, so an incremental apply here would
            # stamp the domain fresh while leaving it permanently incomplete.
            # Mirrors the coordinator's empty-cache guard
            # (cache_refresh_coordinator.py _ensure_one's `_is_empty` check).
            yield {
                "message": (
                    f"Incremental refresh of {mgmt_name}/{domain_name} not safe "
                    f"(empty domain cache); falling back to full reload"
                ),
                "mgmt_name": mgmt_name,
                "domain_name": domain_name,
                "status": "domain_fallback",
                "reason": "empty domain cache",
            }
            async for progress in self._refresh_domain(mgmt_name, domain_name):
                yield progress
            return

        try:
            applied = await self._make_refresher().apply(mgmt_name, domain_name)
        except FallbackToFull as exc:
            yield {
                "message": (
                    f"Incremental refresh of {mgmt_name}/{domain_name} not safe ({exc}); falling back to full reload"
                ),
                "mgmt_name": mgmt_name,
                "domain_name": domain_name,
                "status": "domain_fallback",
                "reason": str(exc),
            }
            async for progress in self._refresh_domain(mgmt_name, domain_name):
                yield progress
            return

        yield {
            "message": f"Incremental: {mgmt_name}/{domain_name} - {applied} change(s) applied",
            "mgmt_name": mgmt_name,
            "domain_name": domain_name,
            "status": "domain_incremental",
            "count": applied,
        }
        # Success (including a rules-only publish with 0 in-scope changes):
        # advance the freshness stamp so the next probe sees this domain fresh.
        await self.refresh_last_published_session(mgmt_name, domain_name)

    async def _refresh_domain(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> AsyncIterator[dict[str, Any]]:
        """Refresh all objects for a single domain (collect-then-swap).

        All object types are fetched into memory first; the cache is only
        touched after every type succeeded, via one atomic
        replace_domain_objects transaction. Any API failure aborts the
        domain refresh, leaving the previous cache contents and freshness
        stamp intact.
        """
        log().info(f"Refreshing objects for {mgmt_name}/{domain_name}")

        yield {
            "message": f"Refreshing {mgmt_name}/{domain_name}",
            "mgmt_name": mgmt_name,
            "domain_name": domain_name,
            "status": "refreshing_domain",
        }

        collected: list[CPObject] = []
        for object_type in self.OBJECT_TYPES:
            objects, error = await self._collect_objects_by_type(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                object_type=object_type,
            )
            if error is not None:
                yield {
                    "message": (
                        f"Aborting refresh of {mgmt_name}/{domain_name}: "
                        f"fetching {object_type}s failed: {error}. "
                        f"Previous cache contents kept."
                    ),
                    "mgmt_name": mgmt_name,
                    "domain_name": domain_name,
                    "object_type": object_type,
                    "status": "domain_failed",
                    "error": error,
                }
                return
            collected.extend(objects)
            yield {
                "message": f"Fetched {len(objects)} {object_type}(s)",
                "mgmt_name": mgmt_name,
                "domain_name": domain_name,
                "object_type": object_type,
                "status": "type_fetched",
                "count": len(objects),
            }

        if len(collected) > self.LARGE_DOMAIN_WARN_THRESHOLD:
            log().warning(
                f"Large domain refresh for {mgmt_name}/{domain_name}: {len(collected)} objects held in memory before swap"
            )

        deleted, inserted = await self._cache.replace_domain_objects(mgmt_name, domain_name, collected)
        log().debug(f"Swapped cache for {mgmt_name}/{domain_name}: -{deleted} +{inserted}")

        yield {
            "message": f"Complete: {mgmt_name}/{domain_name} - {inserted} object(s)",
            "mgmt_name": mgmt_name,
            "domain_name": domain_name,
            "status": "domain_complete",
            "total": inserted,
        }

        # Only a fully successful refresh may advance the freshness stamp.
        await self.refresh_last_published_session(mgmt_name, domain_name)

    async def _collect_objects_by_type(
        self,
        mgmt_name: str,
        domain_name: str,
        object_type: str,
    ) -> tuple[list[CPObject], str | None]:
        """Fetch one object type from the API without touching the cache.

        Args:
            mgmt_name: Management server name.
            domain_name: Domain name.
            object_type: Object type (host, network, etc.).

        Returns:
            (objects, None) on success; ([], error_message) on failure.
        """
        log().debug(f"Fetching {object_type} objects for {mgmt_name}/{domain_name}")
        command = f"show-{object_type}s"

        try:
            result = await self._client.api_query(
                mgmt_name=mgmt_name,
                command=command,
                domain=domain_name,
                details_level="full",
            )
        except Exception as e:  # noqa: BLE001 - any transport error aborts the domain
            log().exception(f"Error fetching {object_type}s for {mgmt_name}/{domain_name}")
            return [], str(e)

        if not result.success:
            return [], result.message or f"{command} returned success=False"

        cp_objects: list[CPObject] = []
        for api_obj in result.objects:
            cp_obj = self._api_object_to_cpobject(
                api_obj=api_obj,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
            )
            if cp_obj:
                cp_objects.append(cp_obj)
        return cp_objects, None

    def _extract_ip_fields(self, obj_type: str, api_obj: dict[str, Any]) -> tuple[str, str, str, str, str]:
        """Delegate to module-level function."""
        return _extract_ip_fields(obj_type, api_obj)

    def _extract_group_members(self, obj_type: str, api_obj: dict[str, Any]) -> str:
        """Delegate to module-level function."""
        return _extract_group_members(obj_type, api_obj)

    def _extract_tags(self, api_obj: dict[str, Any]) -> str:
        """Delegate to module-level function."""
        return _extract_tags(api_obj)

    def _api_object_to_cpobject(
        self,
        api_obj: dict[str, Any],
        mgmt_name: str,
        domain_name: str,
    ) -> CPObject | None:
        """Delegate to the module-level canonical converter."""
        return api_object_to_cpobject(api_obj, mgmt_name, domain_name)


__all__ = [
    "ObjectService",
    "SearchType",
    "classify_input",
    "SearchResult",
    "GroupNode",
    "RefreshMode",
    "api_object_to_cpobject",
]
