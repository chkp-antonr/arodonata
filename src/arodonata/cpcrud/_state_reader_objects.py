"""Network object lookup mixin for `HybridStateReader` (`arodonata.cpcrud._state_reader_objects`)."""

from __future__ import annotations

from typing import Any

from arodonata.core.models.objects import CPObject
from arodonata.cpcrud._state_reader_common import (
    OBJECT_ITEM_TYPES,
    _HybridStateReaderBase,
    normalize_app_site_url_key,
    normalize_mask_length,
)


class _ObjectLookupMixin(_HybridStateReaderBase):
    """Cache-first + live API fallback lookups and virtual overlay resolution for `CPObject`."""

    async def get_object_by_name(
        self,
        mgmt_name: str,
        domain_name: str,
        obj_type: str,
        name: str,
    ) -> CPObject | None:
        """Look up a network object by `(mgmt_name, domain_name, obj_type, name)`."""
        return await self._get_entity_by_name(
            mgmt_name,
            domain_name,
            obj_type,
            name,
            valid_types=OBJECT_ITEM_TYPES,
            invalid_type_label="object",
            scope="objects",
            deleted_store=self._deleted_objects,
            virtual_store=self._virtual_objects,
            cache_fetch_by_names=lambda lookup_names: self._cache.get_objects(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                types=[obj_type],
                names=lookup_names,
            ),
            parser=lambda raw: CPObject.from_cp_dict(mgmt_name, domain_name, raw),
            allow_dot_domain_fallback=True,
        )

    async def get_object_by_uid(
        self,
        mgmt_name: str,
        domain_name: str,
        obj_type: str,
        uid: str,
    ) -> CPObject | None:
        """Look up a network object by `(mgmt_name, domain_name, obj_type, uid)`."""
        return await self._get_entity_by_uid(
            mgmt_name,
            domain_name,
            obj_type,
            uid,
            valid_types=OBJECT_ITEM_TYPES,
            invalid_type_label="object",
            scope="objects",
            deleted_store=self._deleted_objects,
            virtual_store=self._virtual_objects,
            cache_fetch_by_uid=lambda: self._cache.get_object_by_uid(mgmt_name, domain_name, uid),
            parser=lambda raw: CPObject.from_cp_dict(mgmt_name, domain_name, raw),
        )

    async def _candidates_for_object_value_lookup(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        obj_type: str,
        filter_text: str,
        ip_only: bool = False,
    ) -> list[CPObject]:
        """Return candidate `CPObject` entries from fresh cache, live memo, or targeted `show-objects`."""
        return await self._candidates_for_entity_value_lookup(
            mgmt_name,
            domain_name,
            entity_type=obj_type,
            filter_text=filter_text,
            ip_only=ip_only,
            valid_types=OBJECT_ITEM_TYPES,
            invalid_type_label="object",
            scope="objects",
            live_memo=self._live_objects_memo,
            deleted_store=self._deleted_objects,
            virtual_store=self._virtual_objects,
            list_all=lambda: self.list_objects_of_type(mgmt_name, domain_name, obj_type),
            parser=lambda raw: CPObject.from_cp_dict(mgmt_name, domain_name, raw),
        )

    async def list_objects_of_type(
        self,
        mgmt_name: str,
        domain_name: str,
        obj_type: str,
    ) -> list[CPObject]:
        """Return all objects of `obj_type` in `(mgmt_name, domain_name)` from fresh cache or live `api_query`."""
        return await self._list_entities_of_type(
            mgmt_name,
            domain_name,
            obj_type,
            valid_types=OBJECT_ITEM_TYPES,
            invalid_type_label="object",
            scope="objects",
            live_memo=self._live_objects_memo,
            deleted_store=self._deleted_objects,
            virtual_store=self._virtual_objects,
            cache_list=lambda: self._cache.get_objects(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                types=[obj_type],
            ),
            parser=lambda raw: CPObject.from_cp_dict(mgmt_name, domain_name, raw),
        )

    async def find_host_by_ip(
        self,
        mgmt_name: str,
        domain_name: str,
        ip_address: str,
    ) -> list[CPObject]:
        """Find all existing `host` objects matching `ip_address` (IPv4 or IPv6)."""
        target = ip_address.strip()
        hosts = await self._candidates_for_object_value_lookup(
            mgmt_name,
            domain_name,
            obj_type="host",
            filter_text=target,
            ip_only=True,
        )
        matches: list[CPObject] = []
        for h in hosts:
            if h.ipv4_address == target or h.ipv6_address == target:
                matches.append(h)
        return matches

    async def find_network_by_subnet(
        self,
        mgmt_name: str,
        domain_name: str,
        subnet4: str,
        mask_length4: int,
    ) -> list[CPObject]:
        """Find all existing `network` objects matching `(subnet4, mask_length4)`."""
        target_sub = subnet4.strip()
        networks = await self._candidates_for_object_value_lookup(
            mgmt_name,
            domain_name,
            obj_type="network",
            filter_text=target_sub,
            ip_only=True,
        )
        matches: list[CPObject] = []
        for net in networks:
            net_mask = normalize_mask_length(net.mask_length4, net.subnet_mask)
            if net.subnet4 == target_sub and net_mask == mask_length4:
                matches.append(net)
        return matches

    async def find_address_range_by_bounds(
        self,
        mgmt_name: str,
        domain_name: str,
        first_ip: str,
        last_ip: str,
    ) -> list[CPObject]:
        """Find all existing `address-range` objects matching `(first_ip, last_ip)`."""
        f_clean = first_ip.strip()
        l_clean = last_ip.strip()
        ranges = await self._candidates_for_object_value_lookup(
            mgmt_name,
            domain_name,
            obj_type="address-range",
            filter_text=f_clean,
            ip_only=True,
        )
        matches: list[CPObject] = []
        for r in ranges:
            if r.ipv4_address_first == f_clean and r.ipv4_address_last == l_clean:
                matches.append(r)
        return matches

    async def find_application_site_by_url_list(
        self,
        mgmt_name: str,
        domain_name: str,
        url_list: list[str],
        urls_defined_as_regular_expression: bool = False,
    ) -> list[CPObject]:
        """Find all existing `application-site` objects matching normalized `url_list` and regex flag."""
        target_regex = bool(urls_defined_as_regular_expression)
        target_urls = frozenset(
            normalize_app_site_url_key(str(u), is_regex=target_regex) for u in url_list if str(u).strip()
        )
        if not target_urls:
            return []
        sites = await self.list_objects_of_type(mgmt_name, domain_name, "application-site")
        matches: list[CPObject] = []
        for site in sites:
            raw_urls: Any = site.url_list
            if not raw_urls and isinstance(site.raw_data, dict):
                raw_urls = site.raw_data.get("url-list") or site.raw_data.get("url_list") or []
            site_urls = frozenset(
                normalize_app_site_url_key(str(u), is_regex=target_regex)
                for u in (raw_urls if isinstance(raw_urls, list) else [])
                if str(u).strip()
            )
            site_regex = bool(site.urls_defined_as_regular_expression)
            if site_urls == target_urls and site_regex == target_regex:
                matches.append(site)
        return matches

    async def find_objects_by_value(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        obj_type: str,
        ip_address: str | None = None,
        subnet4: str | None = None,
        mask_length4: int | None = None,
        first_ip: str | None = None,
        last_ip: str | None = None,
        url_list: list[str] | None = None,
        urls_defined_as_regular_expression: bool = False,
    ) -> list[CPObject]:
        """Find existing objects matching type-specific values (`host`, `network`, `address-range`, `application-site`)."""
        if obj_type == "host" and ip_address:
            return await self.find_host_by_ip(mgmt_name, domain_name, ip_address)
        if obj_type == "network" and subnet4 and mask_length4 is not None:
            return await self.find_network_by_subnet(mgmt_name, domain_name, subnet4, mask_length4)
        if obj_type == "address-range" and first_ip and last_ip:
            return await self.find_address_range_by_bounds(mgmt_name, domain_name, first_ip, last_ip)
        if obj_type == "application-site" and url_list:
            return await self.find_application_site_by_url_list(
                mgmt_name,
                domain_name,
                url_list,
                urls_defined_as_regular_expression=urls_defined_as_regular_expression,
            )
        return []
