"""Service lookup mixin for `HybridStateReader` (`arodonata.cpcrud._state_reader_services`)."""

from __future__ import annotations

from arodonata.core.errors import ServerIdentityError, ValidationError
from arodonata.core.models.services import CPService
from arodonata.cpcrud._state_reader_common import (
    SERVICE_ITEM_TYPES,
    TYPE_TO_SHOW_PLURAL_CMD,
    TYPE_TO_SHOW_SINGLE_CMD,
    StateLookupError,
    _apply_fetched_entity_overlay,
    _HybridStateReaderBase,
    is_not_found_error,
)


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
        if svc_type not in SERVICE_ITEM_TYPES:
            raise ValidationError(f"Unsupported CPCRUD service type: {svc_type!r}")
        dom_key = (mgmt_name, domain_name)
        del_set = self._deleted_services.get(dom_key, set())
        virt_map = self._virtual_services.get(dom_key, {})
        if f"name:{svc_type}:{name}" in del_set:
            return None
        virt = virt_map.get(f"name:{svc_type}:{name}")
        if virt is not None:
            return virt

        if await self.is_slice_cache_fresh(mgmt_name, domain_name, "services", svc_type):
            try:
                svcs = await self._cache.get_services(
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    types=[svc_type],
                    names=[name],
                )
            except Exception as exc:
                raise StateLookupError(
                    f"Cache lookup failed for {svc_type} {name!r} in {mgmt_name}:{domain_name}: {exc}"
                ) from exc
            for item in svcs:
                resolved = _apply_fetched_entity_overlay(svc_type, item, del_set, virt_map)
                if resolved is not None:
                    return resolved
            return None

        cmd = TYPE_TO_SHOW_SINGLE_CMD[svc_type]
        try:
            res = await self._api.api_call(
                mgmt_name,
                cmd,
                {"name": name},
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
                return None
            raise StateLookupError(
                f"Live API lookup ({cmd}) failed for {name!r} in {mgmt_name}:{domain_name}: "
                f"{res.error_message or res.error_code or f'HTTP {res.status_code}'}"
            )

        if not isinstance(res.data, dict) or not res.data:
            return None
        fetched = CPService.from_cp_dict(mgmt_name, domain_name, res.data)
        return _apply_fetched_entity_overlay(svc_type, fetched, del_set, virt_map)

    async def get_service_by_uid(
        self,
        mgmt_name: str,
        domain_name: str,
        svc_type: str,
        uid: str,
    ) -> CPService | None:
        """Look up a service object by `(mgmt_name, domain_name, svc_type, uid)`."""
        if svc_type not in SERVICE_ITEM_TYPES:
            raise ValidationError(f"Unsupported CPCRUD service type: {svc_type!r}")
        dom_key = (mgmt_name, domain_name)
        del_set = self._deleted_services.get(dom_key, set())
        virt_map = self._virtual_services.get(dom_key, {})
        if f"uid:{uid}" in del_set:
            return None
        virt = virt_map.get(f"uid:{uid}")
        if virt is not None:
            return virt

        if await self.is_slice_cache_fresh(mgmt_name, domain_name, "services", svc_type):
            try:
                svc = await self._cache.get_service_by_uid(mgmt_name, domain_name, uid)
            except Exception as exc:
                raise StateLookupError(
                    f"Cache UID lookup failed for {svc_type} {uid!r} in {mgmt_name}:{domain_name}: {exc}"
                ) from exc
            if svc is not None and svc.type == svc_type:
                return _apply_fetched_entity_overlay(svc_type, svc, del_set, virt_map)
            return None

        cmd = TYPE_TO_SHOW_SINGLE_CMD[svc_type]
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
        fetched = CPService.from_cp_dict(mgmt_name, domain_name, res.data)
        return _apply_fetched_entity_overlay(svc_type, fetched, del_set, virt_map)

    async def _candidates_for_service_value_lookup(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        svc_type: str,
        filter_text: str,
    ) -> list[CPService]:
        """Return candidate `CPService` entries from fresh cache, live memo, or targeted `show-objects`."""
        if svc_type not in SERVICE_ITEM_TYPES:
            raise ValidationError(f"Unsupported CPCRUD service type: {svc_type!r}")
        if (
            await self.is_slice_cache_fresh(mgmt_name, domain_name, "services", svc_type)
            or (mgmt_name, domain_name, svc_type) in self._live_services_memo
        ):
            return await self.list_services_of_type(mgmt_name, domain_name, svc_type)

        raw_items = await self._query_filtered_objects(
            mgmt_name,
            domain_name,
            obj_type=svc_type,
            filter_text=filter_text,
            ip_only=False,
        )
        if raw_items is None:
            return await self.list_services_of_type(mgmt_name, domain_name, svc_type)

        base_list = [CPService.from_cp_dict(mgmt_name, domain_name, raw) for raw in raw_items]
        return self._merge_service_overlay(mgmt_name, domain_name, svc_type, base_list)

    async def list_services_of_type(
        self,
        mgmt_name: str,
        domain_name: str,
        svc_type: str,
    ) -> list[CPService]:
        """Return all services of `svc_type` in `(mgmt_name, domain_name)` from fresh cache or live `api_query`."""
        if svc_type not in SERVICE_ITEM_TYPES:
            raise ValidationError(f"Unsupported CPCRUD service type: {svc_type!r}")

        base_list: list[CPService]
        if await self.is_slice_cache_fresh(mgmt_name, domain_name, "services", svc_type):
            try:
                base_list = await self._cache.get_services(
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    types=[svc_type],
                )
            except Exception as exc:
                raise StateLookupError(
                    f"Cache listing failed for {svc_type} in {mgmt_name}:{domain_name}: {exc}"
                ) from exc
        else:
            memo_key = (mgmt_name, domain_name, svc_type)
            if memo_key in self._live_services_memo:
                base_list = list(self._live_services_memo[memo_key])
            else:
                plural_cmd = TYPE_TO_SHOW_PLURAL_CMD[svc_type]
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
                    CPService.from_cp_dict(mgmt_name, domain_name, raw)
                    for raw in q_res.objects
                    if isinstance(raw, dict)
                ]
                self._live_services_memo[memo_key] = list(base_list)

        return self._merge_service_overlay(mgmt_name, domain_name, svc_type, base_list)

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
