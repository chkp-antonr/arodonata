"""Service lookup mixin for `HybridStateReader` (`arodonata.cpcrud._state_reader_services`)."""

from __future__ import annotations

from arodonata.core.models.services import CPService
from arodonata.cpcrud._state_reader_common import SERVICE_ITEM_TYPES, _HybridStateReaderBase


class _ServiceLookupMixin(_HybridStateReaderBase):
    """Cache-first + live API fallback lookups and virtual overlay resolution for `CPService`."""

    async def get_service_by_name(
        self,
        mgmt_name: str,
        domain_name: str,
        svc_type: str,
        name: str,
    ) -> CPService | None:
        """Look up a service object by `(mgmt_name, domain_name, svc_type, name)`."""
        return await self._get_entity_by_name(
            mgmt_name,
            domain_name,
            svc_type,
            name,
            valid_types=SERVICE_ITEM_TYPES,
            invalid_type_label="service",
            scope="services",
            deleted_store=self._deleted_services,
            virtual_store=self._virtual_services,
            cache_fetch_by_names=lambda lookup_names: self._cache.get_services(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                types=[svc_type],
                names=lookup_names,
            ),
            parser=lambda raw: CPService.from_cp_dict(mgmt_name, domain_name, raw),
        )

    async def get_service_by_uid(
        self,
        mgmt_name: str,
        domain_name: str,
        svc_type: str,
        uid: str,
    ) -> CPService | None:
        """Look up a service object by `(mgmt_name, domain_name, svc_type, uid)`."""
        return await self._get_entity_by_uid(
            mgmt_name,
            domain_name,
            svc_type,
            uid,
            valid_types=SERVICE_ITEM_TYPES,
            invalid_type_label="service",
            scope="services",
            deleted_store=self._deleted_services,
            virtual_store=self._virtual_services,
            cache_fetch_by_uid=lambda: self._cache.get_service_by_uid(mgmt_name, domain_name, uid),
            parser=lambda raw: CPService.from_cp_dict(mgmt_name, domain_name, raw),
        )

    async def _candidates_for_service_value_lookup(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        svc_type: str,
        filter_text: str,
    ) -> list[CPService]:
        """Return candidate `CPService` entries from fresh cache, live memo, or targeted `show-objects`."""
        return await self._candidates_for_entity_value_lookup(
            mgmt_name,
            domain_name,
            entity_type=svc_type,
            filter_text=filter_text,
            ip_only=False,
            valid_types=SERVICE_ITEM_TYPES,
            invalid_type_label="service",
            scope="services",
            live_memo=self._live_services_memo,
            deleted_store=self._deleted_services,
            virtual_store=self._virtual_services,
            list_all=lambda: self.list_services_of_type(mgmt_name, domain_name, svc_type),
            parser=lambda raw: CPService.from_cp_dict(mgmt_name, domain_name, raw),
        )

    async def list_services_of_type(
        self,
        mgmt_name: str,
        domain_name: str,
        svc_type: str,
    ) -> list[CPService]:
        """Return all services of `svc_type` in `(mgmt_name, domain_name)` from fresh cache or live `api_query`."""
        return await self._list_entities_of_type(
            mgmt_name,
            domain_name,
            svc_type,
            valid_types=SERVICE_ITEM_TYPES,
            invalid_type_label="service",
            scope="services",
            live_memo=self._live_services_memo,
            deleted_store=self._deleted_services,
            virtual_store=self._virtual_services,
            cache_list=lambda: self._cache.get_services(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                types=[svc_type],
            ),
            parser=lambda raw: CPService.from_cp_dict(mgmt_name, domain_name, raw),
        )

    async def find_service_by_port(
        self,
        mgmt_name: str,
        domain_name: str,
        svc_type: str,
        port: str,
        protocol: str | None = None,
    ) -> list[CPService]:
        """Find existing TCP/UDP services matching `(svc_type, port, protocol)`."""
        target_port = str(port).strip()
        target_proto = str(protocol).strip().upper() if protocol else None
        services = await self._candidates_for_service_value_lookup(
            mgmt_name,
            domain_name,
            svc_type=svc_type,
            filter_text=target_port,
        )
        matches: list[CPService] = []
        for s in services:
            if s.port != target_port:
                continue
            if target_proto is not None and (s.protocol or "").upper() != target_proto:
                continue
            matches.append(s)
        return matches

    async def find_icmp_service(
        self,
        mgmt_name: str,
        domain_name: str,
        svc_type: str,
        icmp_type: int,
        icmp_code: int | None = None,
    ) -> list[CPService]:
        """Find existing ICMP services matching `(icmp_type, icmp_code)`.

        Note: Check Point `show-objects` `filter` does not match numeric `icmp-type` fields (e.g. built-in
        `echo-request` has `icmp-type=8` without `'8'` in its name), whereas `show-services-icmp` /
        `show-services-icmp6` fits in a single page (~50-60 objects) and is memoized per domain.
        """
        services = await self.list_services_of_type(mgmt_name, domain_name, svc_type)
        matches: list[CPService] = []
        for s in services:
            if s.icmp_type != icmp_type:
                continue
            if icmp_code is not None and s.icmp_code != icmp_code:
                continue
            matches.append(s)
        return matches
