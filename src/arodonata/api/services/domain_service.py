"""Domain discovery and caching service.

Handles domain enumeration, caching, and IP resolution for Check Point management servers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ...asdk.domain_servers import (
    GlobalDomainMdss,
    extract_domain_servers,
    extract_global_domain_mdss,
    mds_ip_map,
)
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
        mds_ips: dict[str, str] = {}
        if response.success and response.objects:
            # Which member hosts each server matters to the login gate
            # (asdk/login_gate.py). Enrichment only: a failed show-mdss leaves
            # active_mds_ip empty and the gate keys on the configured host.
            mds_ips = await self._fetch_mds_ips(mgmt_name, cache_mode)

            for obj in response.objects:
                if not isinstance(obj, dict):
                    continue

                domain_name = obj.get("name", "")
                if not domain_name:
                    continue

                if domain_name == GLOBAL_DOMAIN_NAME:
                    global_seen = True

                domain_uid = obj.get("uid", "")
                layout = extract_domain_servers(obj)
                active_ip = layout.active_ip

                domain = Domain.build(
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    domain_uid=domain_uid,
                    active_ip=active_ip,
                    active_server=layout.active_server,
                    active_mds=layout.active_mds,
                    active_mds_ip=mds_ips.get(layout.active_mds, ""),
                    standby_mdss=",".join(layout.standby_mdss),
                    standby_ips=",".join(layout.standby_ips),
                    standby_servers=",".join(layout.standby_servers),
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
            global_layout = (
                await self._fetch_global_domain_mdss(mgmt_name) if response.success else GlobalDomainMdss()
            )
            active_mds_ip = mds_ips.get(global_layout.active_mds, "")
            default_ip = server.server_ip if server else ""
            active_ip = active_mds_ip or default_ip
            if active_ip:
                global_domain = Domain.build(
                    mgmt_name=mgmt_name,
                    domain_name=GLOBAL_DOMAIN_NAME,
                    domain_uid="",
                    active_ip=active_ip,
                    active_mds=global_layout.active_mds,
                    active_mds_ip=active_mds_ip,
                    standby_mdss=",".join(global_layout.standby_mdss),
                    is_mdm=True,
                )
                await self._cache.upsert_domain(global_domain)
                domain_names.append(GLOBAL_DOMAIN_NAME)
                if active_mds_ip:
                    log().debug(
                        f"Populated domain cache: {mgmt_name}:{GLOBAL_DOMAIN_NAME} "
                        f"with active_ip={active_ip} on active MDS {global_layout.active_mds}"
                    )
                else:
                    log().debug(f"Populated domain cache: {mgmt_name}:{GLOBAL_DOMAIN_NAME} (active_ip={active_ip})")
            else:
                log().warning(f"Cannot determine active_ip for Global domain on MDM {mgmt_name}; skipping cache row")

        log().debug(f"Populated {len(domain_names)} domains for MDM {mgmt_name}")
        if include_global:
            return domain_names
        return [d for d in domain_names if d != GLOBAL_DOMAIN_NAME]

    async def _fetch_global_domain_mdss(self, mgmt_name: str) -> GlobalDomainMdss:
        """Which MDS member holds the writable Global domain; empty layout on any failure.

        `show-domains` never lists Global, so its active member has to come from
        its own object via `show-global-domain`. Enrichment only: a failed call
        falls back to an empty layout so domain population proceeds and uses
        the configured MDS IP as default.
        """
        try:
            response = await self._api_client.api_call(
                mgmt_name=mgmt_name,
                command="show-global-domain",
                payload={"name": GLOBAL_DOMAIN_NAME, "details-level": "full"},
            )
        except Exception as exc:  # noqa: BLE001 - enrichment only
            log().debug(f"show-global-domain failed for {mgmt_name}: {exc}; using configured MDS for Global")
            return GlobalDomainMdss()
        if not response.success:
            log().debug(
                f"show-global-domain refused for {mgmt_name}: {response.message}; using configured MDS for Global"
            )
            return GlobalDomainMdss()
        data = response.data
        return extract_global_domain_mdss(data if isinstance(data, dict) else {})

    async def _fetch_mds_ips(self, mgmt_name: str, cache_mode: str) -> dict[str, str]:
        """{MDS member name: IPv4} via `show-mdss`; {} on any failure.

        The login gate keys on the member that hosts a domain's active server
        (asdk/login_gate.py). Enrichment only: a failed or unsuccessful call
        must never abort domain population, so any exception (transport
        timeout, connection error, ...) and any unsuccessful/empty response
        both degrade to an empty map, logged at debug.
        """
        try:
            mds_response = await self._api_client.api_query(
                mgmt_name=mgmt_name, command="show-mdss", details_level="full", cache_mode=cache_mode
            )
        except Exception as exc:  # noqa: BLE001 - enrichment only; domain population must proceed
            log().debug(f"show-mdss failed for {mgmt_name}: {exc}; domain rows will not carry member IPs")
            return {}
        if mds_response.success and mds_response.objects:
            return mds_ip_map(list(mds_response.objects))
        log().debug(f"show-mdss unavailable for {mgmt_name}; domain rows will not carry member IPs")
        return {}

    def _extract_active_server_ip(self, domain_obj: dict[str, Any]) -> str:
        """Active server IP from a `show-domains` object; '' if none. See asdk/domain_servers.py."""
        return extract_domain_servers(domain_obj).active_ip

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
