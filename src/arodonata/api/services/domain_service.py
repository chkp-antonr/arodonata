"""Domain discovery and caching service.

Handles domain enumeration, caching, and IP resolution for Check Point management servers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ...config import GLOBAL_DOMAIN_NAME
from ...logger import lazy_logger

if TYPE_CHECKING:
    from ...asdk import AMgmtClient
    from ...asdk.server_registry import ServerConfig
    from ...cache import CacheRepository

log = lazy_logger("arodonata.api.services.domain_service")


class DomainService:
    """Domain discovery and caching service.

    Handles domain enumeration and caching for both Smart Center and MDM servers.
    """

    def __init__(
        self,
        mgmt_client: AMgmtClient,
        cache: CacheRepository,
        api_client: Any,  # ArodonataClient - avoiding circular import
    ) -> None:
        """Initialize domain service.

        Args:
            mgmt_client: ASDK management client.
            cache: Cache repository instance.
            api_client: ArodonataClient instance for API calls.
        """
        self._mgmt = mgmt_client
        self._cache = cache
        self._api_client = api_client
        log().trace("DomainService initialized")

    async def populate_domain_cache(
        self, mgmt_name: str, cache_mode: str = "auto", include_global: bool = False
    ) -> list[str]:
        """Query domains from management server and populate cache.

        Args:
            mgmt_name: Management server name.
            cache_mode: Cache mode for the underlying API query.
            include_global: When False (default), the synthetic "Global" domain
                is written to the cache table (for MDMs) but excluded from the
                *returned* list, so unflagged callers (e.g. asset collection)
                are unaffected by its existence.

        Returns:
            List of domain names (including system domain as empty string).
        """
        server = await self._mgmt.get_server(mgmt_name)
        is_mdm = server.is_mdm if server else None

        if is_mdm is False:
            return await self._populate_smart_center_domain(mgmt_name, server, is_mdm=False, cache_mode=cache_mode)
        else:
            # `is_mdm` may be None (not yet detected). Pass the raw value
            # through rather than assuming MDM - `_populate_mdm_domains`
            # only writes the Global row when it is positively known to be
            # an MDM, so an undetected SmartCenter never gets one.
            return await self._populate_mdm_domains(
                mgmt_name, server, is_mdm=is_mdm, cache_mode=cache_mode, include_global=include_global
            )

    async def _populate_smart_center_domain(
        self, mgmt_name: str, server: ServerConfig | None, is_mdm: bool = False, cache_mode: str = "auto"
    ) -> list[str]:
        """Populate domain cache for Smart Center server.

        Args:
            mgmt_name: Management server name.
            server: Server configuration object.

        Returns:
            List of domain names.
        """
        domain_names = [""]  # Always include system domain
        log().debug(f"Processing Smart Center server {mgmt_name}")

        try:
            server_ip = server.server_ip if server else ""

            host_response = await self._api_client.api_call(
                mgmt_name=mgmt_name,
                command="show-checkpoint-host",
                payload={"name": mgmt_name},
                details_level="full",
                cache_mode=cache_mode,
            )

            if not host_response.success or not host_response.data:
                log().warning(f"Failed to get checkpoint-host info for {mgmt_name}: {host_response.message}")
                return domain_names

            host_data = host_response.data
            if not isinstance(host_data, dict):
                log().warning(f"Unexpected response format for show-checkpoint-host on {mgmt_name}")
                return domain_names

            domain_name = host_data.get("domain", {}).get("name", "SMC User")
            domain_uid = host_data.get("domain", {}).get("uid", "")
            server_uid = host_data.get("uid", "")

            if not (domain_name and domain_uid):
                log().warning(f"Could not extract domain UID for Smart Center {mgmt_name}")
                return domain_names

            from ...cache.models import Domain

            domain = Domain.build(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                domain_uid=domain_uid,
                active_ip=server_ip,
                is_mdm=is_mdm,
            )
            await self._cache.upsert_domain(domain)
            domain_names.append(domain_name)

            log().debug(
                f"Populated Smart Center domain: {mgmt_name}:{domain_name} "
                f"(uid={domain_uid[:8]}..., server_uid={server_uid[:8]}...)"
            )

        except Exception as e:
            log().error(f"Error processing Smart Center domain for {mgmt_name}: {e}")

        log().debug(f"Populated {len(domain_names)} domains for Smart Center {mgmt_name}")
        return domain_names

    async def _populate_mdm_domains(
        self,
        mgmt_name: str,
        server: ServerConfig | None = None,
        is_mdm: bool | None = True,
        cache_mode: str = "auto",
        include_global: bool = False,
    ) -> list[str]:
        """Populate domain cache for MDM server.

        Args:
            mgmt_name: Management server name.
            server: Server configuration, used to seed the Global domain's active_ip.
            is_mdm: Multi-Domain Management status. ``None`` means "not yet
                positively detected" - the Global row is only ever written
                when this is ``True``, never on an unknown or non-MDM status.
            cache_mode: Cache mode for the underlying API query.
            include_global: When False (default), the Global row is still
                written to the cache (if applicable) but excluded from the
                returned list.

        Returns:
            List of domain names.
        """
        domain_names = [""]  # Always include system domain

        response = await self._api_client.api_query(
            mgmt_name=mgmt_name,
            command="show-domains",
            details_level="full",
            cache_mode=cache_mode,
        )

        from ...cache.models import Domain

        global_seen = False
        if response.success and response.objects:
            for obj in response.objects:
                if not isinstance(obj, dict):
                    continue

                domain_name = obj.get("name", "")
                if not domain_name:
                    continue

                if domain_name == GLOBAL_DOMAIN_NAME:
                    global_seen = True

                domain_uid = obj.get("uid", "")
                active_ip = self._extract_active_server_ip(obj)

                domain = Domain.build(
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    domain_uid=domain_uid,
                    active_ip=active_ip,
                    is_mdm=bool(is_mdm),
                )
                await self._cache.upsert_domain(domain)
                domain_names.append(domain_name)

                log().debug(
                    f"Populated domain cache: {mgmt_name}:{domain_name} "
                    f"(uid={domain_uid[:8]}..., active_ip={active_ip})"
                )
        else:
            log().warning(
                f"show-domains failed or returned no domains for {mgmt_name}: {response.message}; "
                "will still attempt to add the Global domain"
            )

        # `show-domains` never lists the implicit Global domain - add it
        # explicitly, regardless of whether the call above succeeded, so the
        # cache (and everything that reads it) knows Global exists. This is
        # gated on `is_mdm is True` (positively known), never on a merely
        # unknown or non-MDM status, so a SmartCenter can never get one.
        if not global_seen and is_mdm is True:
            global_ip = server.server_ip if server else ""
            if global_ip:
                global_domain = Domain.build(
                    mgmt_name=mgmt_name,
                    domain_name=GLOBAL_DOMAIN_NAME,
                    domain_uid="",
                    active_ip=global_ip,
                    is_mdm=True,
                )
                await self._cache.upsert_domain(global_domain)
                domain_names.append(GLOBAL_DOMAIN_NAME)
                log().debug(f"Populated domain cache: {mgmt_name}:{GLOBAL_DOMAIN_NAME} (active_ip={global_ip})")
            else:
                log().warning(f"Cannot determine active_ip for Global domain on MDM {mgmt_name}; skipping cache row")

        log().debug(f"Populated {len(domain_names)} domains for MDM {mgmt_name}")
        if include_global:
            return domain_names
        return [d for d in domain_names if d != GLOBAL_DOMAIN_NAME]

    def _extract_active_server_ip(self, domain_obj: dict[str, Any]) -> str:
        """Extract active server IP from domain object.

        Args:
            domain_obj: Domain object from API response.

        Returns:
            Active server IP address or empty string.
        """
        servers = domain_obj.get("servers", [])
        if not isinstance(servers, list):
            return ""

        for server in servers:
            if isinstance(server, dict) and server.get("active") is True:
                ipv4_address = server.get("ipv4-address", "")
                if isinstance(ipv4_address, str) and ipv4_address:
                    return ipv4_address

        return ""

    async def get_domain_uid(self, mgmt_name: str, domain_name: str) -> str:
        """Get domain UID from cache.

        Args:
            mgmt_name: Management server name.
            domain_name: Domain name (empty string for system domain).

        Returns:
            Domain UID or empty string if not found.
        """
        # For system domain, return empty UID
        if not domain_name:
            return ""

        # Try to get from cache
        domain = await self._cache.get_domain(mdm_dmn=f"{mgmt_name}:{domain_name}")
        return domain.domain_uid if domain else ""


__all__ = ["DomainService"]
