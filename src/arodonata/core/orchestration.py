"""Cache orchestration service for smart caching."""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from arodonata.cache.models import CPObject
    from arodonata.models import Domain, Gateway, Group, Host, Network

if TYPE_CHECKING:
    from arodonata.core.cache_mode import CacheMode
    from arodonata.core.cache_refresh_coordinator import CacheRefreshCoordinator
    from arodonata.core.session_tracker import SessionChangeTracker
    from arodonata.ports.api_port import ApiPort
    from arodonata.ports.cache_port import CachePort

if TYPE_CHECKING:
    from arodonata.models.rulebases import AccessRule, HTTPSRule, NATRule, ThreatRule


class CacheOrchestrationService:
    """Orchestrates cache and API interactions.

    Responsibilities:
    - Provide typed cache-read helper methods (get_domains, get_gateways, etc.)
    - Check cache freshness for smart-refresh callers
    - Handle session-aware change tracking
    - Coordinate smart refresh
    """

    # Default cache freshness times per table (in seconds)
    DEFAULT_FRESHNESS_SECONDS: dict[str, int] = {
        "objects": 900,  # 15 minutes
        "assets": 3600,  # 1 hour
        "domains": 86400,  # 1 day
    }

    def __init__(
        self,
        cache: "CachePort",
        api: "ApiPort",
        session_tracker: "SessionChangeTracker | None",
        coordinator: "CacheRefreshCoordinator | None" = None,
    ) -> None:
        """Initialize orchestration service.

        Args:
            cache: Cache implementation.
            api: API implementation.
            session_tracker: Session change tracker (optional for now).
            coordinator: Cache refresh coordinator (optional; when absent,
                read helpers skip cache-mode-driven refresh entirely).
        """
        self._cache = cache
        self._api = api
        self._session_tracker = session_tracker
        self._coordinator = coordinator

    async def _ensure(
        self,
        mgmt_names: list[str] | None,
        domain_names: list[str] | None,
        cache_mode: "CacheMode | str | None",
        cache_ttl: int | None,
    ) -> None:
        """Resolve the effective cache policy and ensure freshness before a read.

        No-op when no coordinator was injected (keeps existing callers/tests
        that construct CacheOrchestrationService without one working unchanged).
        """
        from arodonata.core.cache_policy import CachePolicy, RefreshScope

        if self._coordinator is None:
            return

        policy = CachePolicy.resolve(cache_mode, cache_ttl, self._coordinator.default_policy)
        scope = RefreshScope(mgmt_names=mgmt_names, domain_names=domain_names)
        await self._coordinator.ensure(scope, policy)

    async def _is_cache_fresh(
        self,
        table: str,
        mgmt_name: str,
        domain: str,
    ) -> bool:
        """Check if cache is fresh for the given table.

        Uses last_published_session to determine if cache needs refresh.
        If there's a session tracker with changes, cache is not fresh.

        Args:
            table: Table name (objects, assets, domains).
            mgmt_name: Management server name.
            domain: Domain name.

        Returns:
            True if cache is fresh, False if refresh needed.
        """
        from datetime import UTC, datetime

        # Check if there are unpublished local changes
        if self._session_tracker and self._session_tracker.has_changes(mgmt_name, domain):
            return False

        # Get last published session time
        last_session = await self._cache.get_last_published_session(mgmt_name, domain)

        if last_session is None:
            return False  # No publish history, need refresh

        # Get the published_time - handle mock/test scenarios
        published_time = last_session.published_time
        if not isinstance(published_time, datetime):
            # Handle mock or missing data
            return False

        # Get freshness timeout for this table
        freshness_seconds = self.DEFAULT_FRESHNESS_SECONDS.get(table, 900)

        # Check if cache is still fresh
        now = datetime.now(UTC).replace(tzinfo=None)
        age = (now - published_time.replace(tzinfo=None)).total_seconds()

        return age < freshness_seconds

    # ==================== Typed Helper Methods ====================

    async def get_domains(
        self,
        mgmt_names: list[str] | None = None,
        cache_mode: "CacheMode | str | None" = None,
        cache_ttl: int | None = None,
        include_global: bool = False,
    ) -> list["Domain"]:
        """Get domains from cache.

        Args:
            mgmt_names: Optional list of management server names to filter.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.
            include_global: When False (default), the synthetic "Global" domain
                is excluded so existing callers see today's behavior.

        Returns:
            List of Domain Pydantic models.
        """
        await self._ensure(mgmt_names, None, cache_mode, cache_ttl)

        from arodonata.models import Domain

        cache_domains = await self._cache.get_domains(mgmt_names=mgmt_names, include_global=include_global)

        return [
            Domain(
                uid=d.domain_uid,
                name=d.domain_name,
                active_mds=d.active_mds,
                active_ip=d.active_ip,
                active_server=d.active_server,
                standby_ips=d.standby_ips.split(",") if d.standby_ips else [],
                standby_servers=d.standby_servers.split(",") if d.standby_servers else [],
                mgmt_name=d.mgmt_name,
                is_mdm=d.is_mdm,
            )
            for d in cache_domains
        ]

    async def get_gateways(
        self,
        mgmt_names: list[str] | None = None,
        cache_mode: "CacheMode | str | None" = None,
        cache_ttl: int | None = None,
    ) -> list["Gateway"]:
        """Get gateways and servers from cache.

        Args:
            mgmt_names: Optional list of management server names to filter.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.

        Returns:
            List of Gateway Pydantic models.
        """
        await self._ensure(mgmt_names, None, cache_mode, cache_ttl)

        from arodonata.models import Gateway

        assets = await self._cache.get_gateways(mgmt_names=mgmt_names)

        return [
            Gateway(
                uid=a.asset_uid,
                name=a.name,
                type=a.asset_type,
                ip_address=a.ip_address,
                ssh_ip=a.ssh_ip,
                domain_name=a.domain_name,
                mgmt_name=a.mgmt_name,
                parent_uid=a.parent_asset_id,
                raw_data=a.raw_data or {},
            )
            for a in assets
        ]

    async def get_hosts(
        self,
        name_filter: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        cache_mode: "CacheMode | str | None" = None,
        cache_ttl: int | None = None,
    ) -> list["Host"]:
        """Get host objects from cache.

        Args:
            name_filter: Optional name filter (supports wildcards).
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.

        Returns:
            List of Host Pydantic models.
        """
        await self._ensure(mgmt_names, domain_names, cache_mode, cache_ttl)

        from arodonata.models import Host

        filters: dict[str, Any] = {}
        if name_filter:
            filters["name"] = name_filter

        objects = await self._cache.get_objects(
            object_type="host",
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            filters=filters if filters else None,
        )

        return [
            Host(
                uid=obj.uid,
                name=obj.name,
                ip_address=obj.ipv4_address,
                mgmt_name=obj.mgmt_name,
                domain_name=obj.domain_name,
                raw_data=obj.raw_data or {},
            )
            for obj in objects
        ]

    async def get_networks(
        self,
        subnet: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        cache_mode: "CacheMode | str | None" = None,
        cache_ttl: int | None = None,
    ) -> list["Network"]:
        """Get network objects from cache.

        Args:
            subnet: Optional subnet filter (CIDR notation).
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.

        Returns:
            List of Network Pydantic models.
        """
        await self._ensure(mgmt_names, domain_names, cache_mode, cache_ttl)

        from arodonata.models import Network

        objects = await self._cache.get_objects(
            object_type="network",
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            filters=None,
        )

        networks = [
            Network(
                uid=obj.uid,
                name=obj.name,
                subnet4=obj.subnet4,
                subnet_mask=obj.subnet_mask,
                mgmt_name=obj.mgmt_name,
                domain_name=obj.domain_name,
                raw_data=obj.raw_data or {},
            )
            for obj in objects
        ]

        # Apply subnet filter if provided
        if subnet:
            networks = [n for n in networks if n.subnet4 == subnet]

        return networks

    async def get_groups(
        self,
        name_filter: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        cache_mode: "CacheMode | str | None" = None,
        cache_ttl: int | None = None,
    ) -> list["Group"]:
        """Get group objects from cache.

        Args:
            name_filter: Optional name filter (supports wildcards).
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.

        Returns:
            List of Group Pydantic models.
        """
        await self._ensure(mgmt_names, domain_names, cache_mode, cache_ttl)

        from arodonata.models import Group

        filters: dict[str, Any] = {}
        if name_filter:
            filters["name"] = name_filter

        objects = await self._cache.get_objects(
            object_type="group",
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            filters=filters if filters else None,
        )

        return [
            Group(
                uid=obj.uid,
                name=obj.name,
                member_uids=obj.members.split(",") if obj.members else [],
                mgmt_name=obj.mgmt_name,
                domain_name=obj.domain_name,
                raw_data=obj.raw_data or {},
            )
            for obj in objects
        ]

    async def get_object_by_uid(
        self,
        uid: str,
        mgmt_name: str,
        domain_name: str = "",
    ) -> "CPObject | None":
        """Get any object by UID.

        Args:
            uid: Object UID.
            mgmt_name: Management server name.
            domain_name: Domain name (default: system domain).

        Returns:
            CPObject or None if not found.
        """
        return await self._cache.get_object_by_uid(
            uid=uid,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
        )

    # ==================== Rulebase Helper Methods ====================

    async def get_access_rules(
        self,
        layer_name: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        enabled_only: bool | None = None,
        cache_mode: "CacheMode | str | None" = None,
        cache_ttl: int | None = None,
    ) -> list["AccessRule"]:
        """Get access control rules from cache.

        Args:
            layer_name: Optional layer name filter (e.g., "Network").
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            enabled_only: If True, only return enabled rules.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.

        Returns:
            List of AccessRule Pydantic models.
        """
        await self._ensure(mgmt_names, domain_names, cache_mode, cache_ttl)

        from arodonata.models import AccessRule

        # Get rulebase cache models
        cache_rules = await self._cache.get_rulebase(
            rulebase_type="access",
            layer_name=layer_name,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            enabled_only=enabled_only,
        )

        # Convert cache models to Pydantic models
        return [
            AccessRule(  # type: ignore[misc]  # type: ignore[misc]
                uid=r.uid,
                rule_number=r.rule_number,
                name=r.name,
                enabled=r.enabled,
                sources=r.sources.split(",") if r.sources else [],
                destinations=r.destinations.split(",") if r.destinations else [],
                services=r.services.split(",") if r.services else [],
                action=r.action,
                track=r.track,
                layer_name=r.layer_name,
                mgmt_name=r.mgmt_name,
                domain_name=r.domain_name,
                raw_data=r.raw_data,
            )
            for r in cache_rules
        ]

    async def get_nat_rules(
        self,
        layer_name: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        enabled_only: bool | None = None,
        cache_mode: "CacheMode | str | None" = None,
        cache_ttl: int | None = None,
    ) -> list["NATRule"]:
        """Get NAT rules from cache.

        Args:
            layer_name: Optional layer name filter (e.g., "NAT").
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            enabled_only: If True, only return enabled rules.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.

        Returns:
            List of NATRule Pydantic models.
        """
        await self._ensure(mgmt_names, domain_names, cache_mode, cache_ttl)

        from arodonata.models import NATRule

        cache_rules = await self._cache.get_rulebase(
            rulebase_type="nat",
            layer_name=layer_name,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            enabled_only=enabled_only,
        )

        return [
            NATRule(  # type: ignore[misc]
                uid=r.uid,
                rule_number=r.rule_number,
                name=r.name,
                enabled=r.enabled,
                original_source=r.original_source,
                original_destination=r.original_destination,
                original_service=r.original_service,
                translated_source=r.translated_source,
                translated_destination=r.translated_destination,
                translated_service=r.translated_service,
                layer_name=r.layer_name,
                mgmt_name=r.mgmt_name,
                domain_name=r.domain_name,
                raw_data=r.raw_data,
            )
            for r in cache_rules
        ]

    async def get_https_rules(
        self,
        layer_name: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        enabled_only: bool | None = None,
        cache_mode: "CacheMode | str | None" = None,
        cache_ttl: int | None = None,
    ) -> list["HTTPSRule"]:
        """Get HTTPS inspection rules from cache.

        Args:
            layer_name: Optional layer name filter (e.g., "CVD").
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            enabled_only: If True, only return enabled rules.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.

        Returns:
            List of HTTPSRule Pydantic models.
        """
        await self._ensure(mgmt_names, domain_names, cache_mode, cache_ttl)

        from arodonata.models import HTTPSRule

        cache_rules = await self._cache.get_rulebase(
            rulebase_type="https",
            layer_name=layer_name,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            enabled_only=enabled_only,
        )

        return [
            HTTPSRule(  # type: ignore[misc]
                uid=r.uid,
                rule_number=r.rule_number,
                name=r.name,
                enabled=r.enabled,
                sources=r.sources.split(",") if r.sources else [],
                destinations=r.destinations.split(",") if r.destinations else [],
                track=r.track,
                layer_name=r.layer_name,
                mgmt_name=r.mgmt_name,
                domain_name=r.domain_name,
                raw_data=r.raw_data,
            )
            for r in cache_rules
        ]

    async def get_threat_rules(
        self,
        layer_name: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        enabled_only: bool | None = None,
        cache_mode: "CacheMode | str | None" = None,
        cache_ttl: int | None = None,
    ) -> list["ThreatRule"]:
        """Get threat prevention rules from cache.

        Args:
            layer_name: Optional layer name filter (e.g., "Threat").
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            enabled_only: If True, only return enabled rules.
            cache_mode: Optional per-call cache refresh mode override.
            cache_ttl: Optional per-call cache freshness TTL override.

        Returns:
            List of ThreatRule Pydantic models.
        """
        await self._ensure(mgmt_names, domain_names, cache_mode, cache_ttl)

        from arodonata.models import ThreatRule

        cache_rules = await self._cache.get_rulebase(
            rulebase_type="threat",
            layer_name=layer_name,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            enabled_only=enabled_only,
        )

        return [
            ThreatRule(  # type: ignore[misc]
                uid=r.uid,
                rule_number=r.rule_number,
                name=r.name,
                enabled=r.enabled,
                track=r.track,
                protections=r.protections.split(",") if r.protections else [],
                layer_name=r.layer_name,
                mgmt_name=r.mgmt_name,
                domain_name=r.domain_name,
                raw_data=r.raw_data,
            )
            for r in cache_rules
        ]

    # ==================== Session Management ====================

    async def publish(
        self,
        mgmt_name: str,
        domain: str,
    ) -> None:
        """Publish the session, then reconcile cache from server truth.

        The API mints authoritative UIDs on publish, so we do not upsert local
        SessionChange rows. Instead we publish, then run a smart-fast refresh
        (which diffs last-cached -> new last-published) to pull the just-published
        objects with their real UIDs, then clear the in-memory tracker.
        """
        from arodonata.core.cache_mode import CacheMode
        from arodonata.core.cache_policy import CachePolicy, RefreshScope

        response = await self._api.publish(mgmt_name=mgmt_name, domain=domain)

        success = getattr(response, "success", None)
        if success is None and isinstance(response, dict):
            success = response.get("success", True)
        if success is None:
            success = True  # no signal -> assume ok (e.g. test doubles returning None)

        if not success:
            raise RuntimeError(f"Publish failed for {mgmt_name}/{domain}: {response}")

        if self._coordinator is not None:
            self._coordinator.invalidate(mgmt_name, domain)
            await self._coordinator.ensure(
                RefreshScope(mgmt_names=[mgmt_name], domain_names=[domain]),
                CachePolicy(mode=CacheMode.SMART_FAST, ttl=None),
            )

        if self._session_tracker is not None:
            self._session_tracker.clear_session(mgmt_name, domain)

    async def discard(
        self,
        mgmt_name: str,
        domain: str,
    ) -> None:
        """Discard session changes without persisting.

        Clears in-memory session changes without writing to cache.

        Args:
            mgmt_name: Management server name.
            domain: Domain name.
        """
        if self._session_tracker is None:
            return

        # Check if there are changes to discard
        if not self._session_tracker.has_changes(mgmt_name, domain):
            return

        # Simply clear the session without persisting
        self._session_tracker.clear_session(mgmt_name, domain)
