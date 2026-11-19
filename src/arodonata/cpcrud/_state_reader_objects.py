"""Network object lookup mixin for `HybridStateReader` (`arodonata.cpcrud._state_reader_objects`)."""

from __future__ import annotations

from typing import Any

from arodonata.core.errors import ServerIdentityError, ValidationError
from arodonata.core.models.objects import CPObject
from arodonata.cpcrud._state_reader_common import (
    OBJECT_ITEM_TYPES,
    TYPE_TO_SHOW_PLURAL_CMD,
    TYPE_TO_SHOW_SINGLE_CMD,
    StateLookupError,
    _apply_fetched_entity_overlay,
    _HybridStateReaderBase,
    is_not_found_error,
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
        if obj_type not in OBJECT_ITEM_TYPES:
            raise ValidationError(f"Unsupported CPCRUD object type: {obj_type!r}")
        dom_key = (mgmt_name, domain_name)
        del_set = self._deleted_objects.get(dom_key, set())
        virt_map = self._virtual_objects.get(dom_key, {})
        if f"name:{obj_type}:{name}" in del_set:
            return None
        virt = virt_map.get(f"name:{obj_type}:{name}")
        if virt is not None:
            return virt

        if await self.is_slice_cache_fresh(mgmt_name, domain_name, "objects", obj_type):
            lookup_names = [name, f".{name}"] if (obj_type == "dns-domain" and not name.startswith(".")) else [name]
            try:
                objs = await self._cache.get_objects(
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    types=[obj_type],
                    names=lookup_names,
                )
            except Exception as exc:
                raise StateLookupError(
                    f"Cache lookup failed for {obj_type} {name!r} in {mgmt_name}:{domain_name}: {exc}"
                ) from exc
            for item in objs:
                if item.name != name:
                    continue
                resolved = _apply_fetched_entity_overlay(obj_type, item, del_set, virt_map)
                if resolved is not None:
                    return resolved
            if obj_type == "dns-domain" and not name.startswith("."):
                dot_name = f".{name}"
                if f"name:dns-domain:{dot_name}" in del_set:
                    return None
                dot_virt = virt_map.get(f"name:dns-domain:{dot_name}")
                if dot_virt is not None:
                    return dot_virt
                for item in objs:
                    if item.name != dot_name:
                        continue
                    resolved = _apply_fetched_entity_overlay(obj_type, item, del_set, virt_map)
                    if resolved is not None:
                        return resolved
            return None

        # Fallback to live API call
        cmd = TYPE_TO_SHOW_SINGLE_CMD[obj_type]
        payload: dict[str, Any] = {"name": name}
        try:
            res = await self._api.api_call(
                mgmt_name,
                cmd,
                payload,
                domain=domain_name or None,
            )
        except ServerIdentityError:
            raise
        except Exception as exc:
            raise StateLookupError(
                f"Live API lookup ({cmd}) failed for {name!r} in {mgmt_name}:{domain_name}: {exc}"
            ) from exc

        if not res.success:
            if is_not_found_error(res.status_code, res.error_code, res.error_message):
                # For dns-domain, Check Point often stores names with a leading dot (e.g. ".example.com")
                if obj_type == "dns-domain" and not name.startswith("."):
                    if f"name:dns-domain:.{name}" in del_set:
                        return None
                    dot_virt = virt_map.get(f"name:dns-domain:.{name}")
                    if dot_virt is not None:
                        return dot_virt
                    try:
                        dot_res = await self._api.api_call(
                            mgmt_name,
                            cmd,
                            {"name": f".{name}"},
                            domain=domain_name or None,
                        )
                    except ServerIdentityError:
                        raise
                    except Exception as exc:
                        raise StateLookupError(
                            f"Live API lookup ({cmd}) failed for .{name!r} in {mgmt_name}:{domain_name}: {exc}"
                        ) from exc
                    if dot_res.success and isinstance(dot_res.data, dict):
                        fetched_dot = CPObject.from_cp_dict(mgmt_name, domain_name, dot_res.data)
                        return _apply_fetched_entity_overlay(obj_type, fetched_dot, del_set, virt_map)
                    if not dot_res.success and not is_not_found_error(
                        dot_res.status_code, dot_res.error_code, dot_res.error_message
                    ):
                        raise StateLookupError(
                            f"Live API lookup ({cmd}) failed for .{name!r}: "
                            f"{dot_res.error_message or dot_res.error_code or 'API error'}"
                        )
                return None
            raise StateLookupError(
                f"Live API lookup ({cmd}) failed for {name!r} in {mgmt_name}:{domain_name}: "
                f"{res.error_message or res.error_code or f'HTTP {res.status_code}'}"
            )

        if not isinstance(res.data, dict) or not res.data:
            return None
        fetched = CPObject.from_cp_dict(mgmt_name, domain_name, res.data)
        return _apply_fetched_entity_overlay(obj_type, fetched, del_set, virt_map)

    async def get_object_by_uid(
        self,
        mgmt_name: str,
        domain_name: str,
        obj_type: str,
        uid: str,
    ) -> CPObject | None:
        """Look up a network object by `(mgmt_name, domain_name, obj_type, uid)`."""
        if obj_type not in OBJECT_ITEM_TYPES:
            raise ValidationError(f"Unsupported CPCRUD object type: {obj_type!r}")
        dom_key = (mgmt_name, domain_name)
        del_set = self._deleted_objects.get(dom_key, set())
        virt_map = self._virtual_objects.get(dom_key, {})
        if f"uid:{uid}" in del_set:
            return None
        virt = virt_map.get(f"uid:{uid}")
        if virt is not None:
            return virt

        if await self.is_slice_cache_fresh(mgmt_name, domain_name, "objects", obj_type):
            try:
                obj = await self._cache.get_object_by_uid(mgmt_name, domain_name, uid)
            except Exception as exc:
                raise StateLookupError(
                    f"Cache UID lookup failed for {obj_type} {uid!r} in {mgmt_name}:{domain_name}: {exc}"
                ) from exc
            if obj is not None and obj.type == obj_type:
                return _apply_fetched_entity_overlay(obj_type, obj, del_set, virt_map)
            return None

        cmd = TYPE_TO_SHOW_SINGLE_CMD[obj_type]
        try:
            res = await self._api.api_call(
                mgmt_name,
                cmd,
                {"uid": uid},
                domain=domain_name or None,
            )
        except ServerIdentityError:
            raise
        except Exception as exc:
            raise StateLookupError(
                f"Live API UID lookup ({cmd}) failed for {uid!r} in {mgmt_name}:{domain_name}: {exc}"
            ) from exc

        if not res.success:
            if is_not_found_error(res.status_code, res.error_code, res.error_message):
                return None
            raise StateLookupError(
                f"Live API UID lookup ({cmd}) failed for {uid!r} in {mgmt_name}:{domain_name}: "
                f"{res.error_message or res.error_code or f'HTTP {res.status_code}'}"
            )

        if not isinstance(res.data, dict) or not res.data:
            return None
        fetched = CPObject.from_cp_dict(mgmt_name, domain_name, res.data)
        return _apply_fetched_entity_overlay(obj_type, fetched, del_set, virt_map)

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
        if obj_type not in OBJECT_ITEM_TYPES:
            raise ValidationError(f"Unsupported CPCRUD object type: {obj_type!r}")
        if (
            await self.is_slice_cache_fresh(mgmt_name, domain_name, "objects", obj_type)
            or (mgmt_name, domain_name, obj_type) in self._live_objects_memo
        ):
            return await self.list_objects_of_type(mgmt_name, domain_name, obj_type)

        raw_items = await self._query_filtered_objects(
            mgmt_name,
            domain_name,
            obj_type=obj_type,
            filter_text=filter_text,
            ip_only=ip_only,
        )
        if raw_items is None:
            return await self.list_objects_of_type(mgmt_name, domain_name, obj_type)

        base_list = [CPObject.from_cp_dict(mgmt_name, domain_name, raw) for raw in raw_items]
        return self._merge_object_overlay(mgmt_name, domain_name, obj_type, base_list)

    async def list_objects_of_type(
        self,
        mgmt_name: str,
        domain_name: str,
        obj_type: str,
    ) -> list[CPObject]:
        """Return all objects of `obj_type` in `(mgmt_name, domain_name)` from fresh cache or live `api_query`."""
        if obj_type not in OBJECT_ITEM_TYPES:
            raise ValidationError(f"Unsupported CPCRUD object type: {obj_type!r}")

        base_list: list[CPObject]
        if await self.is_slice_cache_fresh(mgmt_name, domain_name, "objects", obj_type):
            try:
                base_list = await self._cache.get_objects(
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    types=[obj_type],
                )
            except Exception as exc:
                raise StateLookupError(
                    f"Cache listing failed for {obj_type} in {mgmt_name}:{domain_name}: {exc}"
                ) from exc
        else:
            memo_key = (mgmt_name, domain_name, obj_type)
            if memo_key in self._live_objects_memo:
                base_list = list(self._live_objects_memo[memo_key])
            else:
                plural_cmd = TYPE_TO_SHOW_PLURAL_CMD[obj_type]
                try:
                    q_res = await self._api.api_query(
                        mgmt_name,
                        plural_cmd,
                        domain=domain_name or None,
                        details_level="standard",
                    )
                except ServerIdentityError:
                    raise
                except Exception as exc:
                    raise StateLookupError(
                        f"Live API query ({plural_cmd}) failed in {mgmt_name}:{domain_name}: {exc}"
                    ) from exc

                if not q_res.success or q_res.code == "paging_inconsistent":
                    reason = q_res.error_message or q_res.code or f"{plural_cmd} query failed"
                    raise StateLookupError(
                        f"Live API query ({plural_cmd}) failed in {mgmt_name}:{domain_name}: {reason}"
                    )

                base_list = [
                    CPObject.from_cp_dict(mgmt_name, domain_name, raw) for raw in q_res.objects if isinstance(raw, dict)
                ]
                self._live_objects_memo[memo_key] = list(base_list)

        return self._merge_object_overlay(mgmt_name, domain_name, obj_type, base_list)

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
