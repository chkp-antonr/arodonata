"""Search service for Check Point objects across management servers and domains.

Orchestrates input parsing, cache queries, group membership resolution with
cycle protection, and SSE event streaming.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable
from typing import TYPE_CHECKING, Any, Literal

from arlogi.otel.decorator import traced

from ..api.schemas import SSEEvent, SSEEventType
from ..cache.object_service import SearchType, classify_input
from ..logger import lazy_logger

if TYPE_CHECKING:
    from ..cache.object_service import ObjectService

log = lazy_logger("arodonata.services.search")


class SearchService:
    """Service providing search across Check Point objects with SSE streaming."""

    def __init__(
        self,
        object_service: ObjectService,
        refresh_objects_fn: Callable[..., AsyncGenerator[SSEEvent]],
    ) -> None:
        """Initialize SearchService.

        Args:
            object_service: ObjectService for database cache lookups and group resolution.
            refresh_objects_fn: Callable delegating to object cache refresh generator.
        """
        self._object_service = object_service
        self._refresh_objects_fn = refresh_objects_fn

    def _convert_group_nodes(
        self,
        nodes: list[Any],
        visited: set[str] | None = None,
        depth: int = 0,
        max_depth: int = 20,
    ) -> list[dict[str, Any]]:
        """Recursively convert GroupNode objects to dicts with cycle detection and depth limit.

        Args:
            nodes: List of GroupNode objects.
            visited: Set of visited node UIDs along the current ancestor path.
            depth: Current recursion depth.
            max_depth: Maximum recursion depth to prevent stack overflow.

        Returns:
            List of converted node dictionaries.
        """
        if visited is None:
            visited = set()
        if depth >= max_depth:
            return []

        result = []
        for node in nodes:
            uid = getattr(node, "uid", None) or (node.get("uid") if isinstance(node, dict) else None)
            if uid and uid in visited:
                log().trace(f"Cycle detected in group hierarchy for node '{uid}' - skipping recursive expansion")
                continue

            new_visited = set(visited)
            if uid:
                new_visited.add(uid)

            children = []
            node_children = getattr(node, "children", None) or (
                node.get("children") if isinstance(node, dict) else None
            )
            if node_children:
                children = self._convert_group_nodes(
                    node_children,
                    visited=new_visited,
                    depth=depth + 1,
                    max_depth=max_depth,
                )

            name = getattr(node, "name", None) or (node.get("name") if isinstance(node, dict) else "")
            domain = getattr(node, "domain", None) or (node.get("domain") if isinstance(node, dict) else "")
            node_depth = getattr(node, "depth", depth) or depth

            result.append(
                {
                    "uid": uid,
                    "name": name,
                    "domain": domain,
                    "depth": node_depth,
                    "children": children,
                }
            )
        return result

    async def _fetch_objects_for_search(
        self,
        search_type: Any,
        cleaned: str,
        mgmt_names: list[str] | None,
        domain_names: list[str] | None,
    ) -> list[Any]:
        """Fetch objects from cache based on search type."""
        objects = []
        cache = self._object_service._cache
        if search_type == SearchType.HOST:
            objects = await cache.get_objects_by_ip(
                ip_address=cleaned,
                mgmt_names=mgmt_names,
                domain_names=domain_names,
            )
        elif search_type == SearchType.NETWORK:
            objects = await cache.get_objects_by_subnet(
                subnet=cleaned,
                mgmt_names=mgmt_names,
                domain_names=domain_names,
            )
        elif search_type == SearchType.RANGE:
            if "-" in cleaned:
                start_ip, end_ip = cleaned.split("-", 1)
                objects = await cache.get_objects_in_ip_range(
                    start_ip=start_ip.strip(),
                    end_ip=end_ip.strip(),
                    mgmt_names=mgmt_names,
                    domain_names=domain_names,
                )
        elif search_type == SearchType.NAME:
            objects = await cache.get_objects_by_name(
                name=cleaned,
                mgmt_names=mgmt_names,
                domain_names=domain_names,
            )
        return objects

    async def _resolve_search_memberships(
        self,
        m_name: str,
        d_name: str,
        domain_objects: list[Any],
        cleaned: str,
        search_type: Any,
        max_depth: int,
    ) -> SSEEvent:
        """Resolve group memberships and return an SSEEvent for a domain."""
        memberships_dict = None
        if domain_objects and max_depth > 0:
            memberships = {}
            for obj in domain_objects:
                obj_groups = await self._object_service._resolve_group_memberships(
                    obj_uid=obj.uid,
                    mgmt_name=obj.mgmt_name,
                    domain_name=obj.domain_name,
                    max_depth=max_depth,
                )
                if obj_groups:
                    memberships[obj.uid] = obj_groups

            if memberships:
                memberships_dict = {uid: self._convert_group_nodes(nodes) for uid, nodes in memberships.items()}

        return SSEEvent(
            event_type=SSEEventType.LOG,
            message=f"{m_name}/{d_name} ({len(domain_objects)} object(s))",
            mgmt_name=m_name,
            data={
                "domain": d_name,
                "mgmt_name": m_name,
                "search_term": cleaned,
                "search_type": search_type.value,
                "objects": [obj.model_dump() for obj in domain_objects],
                "memberships": memberships_dict,
            },
        )

    def _parse_search_input(self, search_input: str) -> tuple[list[tuple[Any, str]], str]:
        """Parse comma-separated search terms and classify each."""
        terms = [t.strip() for t in search_input.split(",") if t.strip()]
        classified = [classify_input(t) for t in terms]
        labels = ", ".join(f"'{c}' ({st.value})" for st, c in classified)
        return classified, labels

    def _group_search_objects(self, objects: list[Any]) -> dict[str, dict[str, list[Any]]]:
        """Group objects by mgmt_name and domain_name."""
        grouped: dict[str, dict[str, list[Any]]] = {}
        for obj in objects:
            m_name = obj.mgmt_name
            d_name = obj.domain_name
            if m_name not in grouped:
                grouped[m_name] = {}
            if d_name not in grouped[m_name]:
                grouped[m_name][d_name] = []
            grouped[m_name][d_name].append(obj)
        return grouped

    async def _process_search_term(
        self,
        search_type: Any,
        cleaned: str,
        mgmt_names: list[str] | None,
        domain_names: list[str] | None,
        max_depth: int,
    ) -> AsyncGenerator[SSEEvent]:
        """Execute lookup and group membership resolution for a single term."""
        yield SSEEvent(
            event_type=SSEEventType.LOG,
            message=f" > '{cleaned}' ({search_type.value})",
        )

        objects = await self._fetch_objects_for_search(search_type, cleaned, mgmt_names, domain_names)
        grouped = self._group_search_objects(objects)

        for m_name, domains in grouped.items():
            yield SSEEvent(
                event_type=SSEEventType.LOG,
                message=f"  Searching across {len(domains)} domain(s) on {m_name}",
                mgmt_name=m_name,
            )
            for d_name, domain_objects in domains.items():
                yield await self._resolve_search_memberships(
                    m_name, d_name, domain_objects, cleaned, search_type, max_depth
                )

    async def _handle_search_refresh(
        self,
        mgmt_names: list[str] | None,
        domain_names: list[str] | None,
        refresh: Literal["skip", "check", "force", "incremental"],
    ) -> AsyncGenerator[SSEEvent]:
        """Handle optional pre-search cache refresh, normalizing events for SSE."""
        if refresh != "skip":
            async for event in self._refresh_objects_fn(
                mgmt_names=mgmt_names,
                domain_names=domain_names,
                mode=refresh,
            ):
                # Filter out START and COMPLETE from refresh sub-task to avoid confusing frontend
                if event.event_type == SSEEventType.COMPLETE or event.event_type == SSEEventType.RESULT:
                    continue

                if event.event_type == SSEEventType.START:
                    # Convert sub-task START to LOG so it doesn't reset the frontend
                    event.event_type = SSEEventType.LOG

                yield event

    @traced
    async def search_objects(
        self,
        search_input: str,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        refresh: Literal["skip", "check", "force", "incremental"] = "skip",
        max_depth: int = 2,
    ) -> AsyncGenerator[SSEEvent]:
        """Search for Check Point objects with cache-first queries and SSE streaming.

        Args:
            search_input: Comma-separated search terms.
            mgmt_names: Optional management server filter.
            domain_names: Optional domain filter.
            refresh: Refresh mode - "skip", "check", "force", or "incremental".
            max_depth: Maximum depth for group membership traversal.

        Yields:
            SSEEvent with refresh progress and domain-grouped search results.
        """
        # Refresh cache first if requested
        async for event in self._handle_search_refresh(mgmt_names, domain_names, refresh):
            yield event

        # Parse and classify search terms for the header
        classified, labels = self._parse_search_input(search_input)

        yield SSEEvent(
            event_type=SSEEventType.START,
            message=f"Searching for {labels}",
        )

        # Process each search term
        for _term_idx, (search_type, cleaned) in enumerate(classified, 1):
            async for event in self._process_search_term(search_type, cleaned, mgmt_names, domain_names, max_depth):
                yield event

        yield SSEEvent(
            event_type=SSEEventType.COMPLETE,
            message="Search complete",
        )
