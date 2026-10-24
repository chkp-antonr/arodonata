"""Hybrid cache-first + live API fallback state reader (`src/arodonata/cpcrud/state_reader.py`).

Implements `HybridStateReader`:
- Isolated per-run state reader created for each `plan()` invocation.
- Reads network objects (`host`, `network`, `address-range`, `dns-domain`, `group`) from
  `arodonata_objects` and services (`service-tcp`, `service-udp`, `service-icmp`, `service-group`,
  `service-other`) from `arodonata_services` ONLY when the domain's stored `domain_sync_state`
  row for that specific `(scope, item_type)` has `status == "ok"` and matches the planner's
  `DomainStamp` (`last_published_at` and `last_session_uid`).
- Falls back to live Management API calls (`show-*` / `api_query`) otherwise.
- Raises `StateLookupError` when any lookup fails or `api_query` returns `paging_inconsistent`
  so the planner emits `Outcome.ERROR` rather than mistaking a failed read for "not found".
- Maintains an in-run virtual state overlay so objects/services planned for creation, update,
  or deletion earlier in the same `plan()` run are visible to subsequent steps.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from arodonata.core.errors import ArodonataError, ServerIdentityError
from arodonata.core.models.common import SyncScope
from arodonata.core.models.domains import DomainSyncState
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import RulebaseType
from arodonata.core.models.services import CPService
from arodonata.core.ports import ApiPort, CachePort
from arodonata.cpcrud.models import DomainStamp
from arodonata.rulebase.pager import PagedRulebaseResult, fetch_paged_rulebase

OBJECT_ITEM_TYPES: frozenset[str] = frozenset(
    {
        "host",
        "network",
        "address-range",
        "dns-domain",
        "group",
    }
)

SERVICE_ITEM_TYPES: frozenset[str] = frozenset(
    {
        "service-tcp",
        "service-udp",
        "service-icmp",
        "service-icmp6",
        "service-other",
        "service-group",
    }
)

TYPE_TO_SHOW_SINGLE_CMD: dict[str, str] = {
    "host": "show-host",
    "network": "show-network",
    "address-range": "show-address-range",
    "dns-domain": "show-dns-domain",
    "group": "show-group",
    "service-tcp": "show-service-tcp",
    "service-udp": "show-service-udp",
    "service-icmp": "show-service-icmp",
    "service-icmp6": "show-service-icmp6",
    "service-other": "show-service-other",
    "service-group": "show-service-group",
}

TYPE_TO_SHOW_PLURAL_CMD: dict[str, str] = {
    "host": "show-hosts",
    "network": "show-networks",
    "address-range": "show-address-ranges",
    "dns-domain": "show-dns-domains",
    "group": "show-groups",
    "service-tcp": "show-services-tcp",
    "service-udp": "show-services-udp",
    "service-icmp": "show-services-icmp",
    "service-icmp6": "show-services-icmp6",
    "service-other": "show-services-other",
    "service-group": "show-service-groups",
}


class StateLookupError(ArodonataError):
    """Raised when a cache or live API state lookup fails during planning."""


def is_not_found_error(
    status_code: int,
    error_code: str | None,
    error_message: str | None,
) -> bool:
    """Return `True` if a Check Point API response specifically indicates 'object not found'."""
    if status_code == 404:
        return True
    code_low = (error_code or "").strip().lower()
    msg_low = (error_message or "").strip().lower()
    if "not_found" in code_low or "not found" in msg_low:
        return True
    return "requested object" in msg_low and "not found" in msg_low


def normalize_mask_length(
    mask_length: int | str | None,
    subnet_mask: str | None = None,
) -> int | None:
    """Normalize a mask length or dotted-quad subnet mask into an integer prefix length (0..32)."""
    if mask_length is not None:
        try:
            return int(mask_length)
        except (TypeError, ValueError):
            pass
    if subnet_mask and isinstance(subnet_mask, str):
        clean = subnet_mask.strip()
        if clean.isdigit():
            return int(clean)
        try:
            net = ipaddress.IPv4Network(f"0.0.0.0/{clean}", strict=False)
            return net.prefixlen
        except ValueError:
            return None
    return None


def _sync_state_matches_stamp(
    sync_state: DomainSyncState | None,
    stamp: DomainStamp | None,
) -> bool:
    """Return `True` iff `sync_state` is `"ok"` and matches `stamp`'s session UID and publish timestamp."""
    if sync_state is None or sync_state.status != "ok":
        return False
    if stamp is None or not stamp.readable:
        return False

    # Both last_published_at and last_session_uid must match when present on the stamp
    if stamp.last_session_uid is not None:
        if sync_state.last_session_uid != stamp.last_session_uid:
            return False
    elif sync_state.last_session_uid is not None:
        return False

    if stamp.last_published_at is not None:
        if sync_state.last_published_at != stamp.last_published_at:
            return False
    elif sync_state.last_published_at is not None:
        return False

    # Require at least one non-None identifier on the stamp to trust the cache
    return stamp.last_session_uid is not None or stamp.last_published_at is not None


class HybridStateReader:
    """Isolated per-plan state reader combining `DomainStamp`-gated cache lookups with live API fallback."""

    def __init__(
        self,
        *,
        api: ApiPort,
        cache: CachePort,
        domain_stamps: dict[str, DomainStamp] | None = None,
    ) -> None:
        self._api = api
        self._cache = cache
        self._stamps: dict[str, DomainStamp] = dict(domain_stamps or {})

        # Memoized cache-eligibility decisions per (mgmt_name, domain_name, scope, item_type)
        self._slice_fresh_memo: dict[tuple[str, str, str, str], bool] = {}

        # Memoized live listings per (mgmt_name, domain_name, item_type) to avoid redundant full queries in one plan
        self._live_objects_memo: dict[tuple[str, str, str], list[CPObject]] = {}
        self._live_services_memo: dict[tuple[str, str, str], list[CPService]] = {}

        # Memoized rulebases per (mgmt_name, domain_name, rulebase_type, layer_or_pkg)
        self._rulebase_memo: dict[tuple[str, str, str, str], PagedRulebaseResult] = {}

        # Intra-plan virtual state overlay keyed by (mgmt_name, domain_name)
        self._virtual_objects: dict[tuple[str, str], dict[str, CPObject]] = {}
        self._deleted_objects: dict[tuple[str, str], set[str]] = {}
        self._virtual_services: dict[tuple[str, str], dict[str, CPService]] = {}
        self._deleted_services: dict[tuple[str, str], set[str]] = {}

    def set_domain_stamp(self, stamp: DomainStamp) -> None:
        """Record or update a `DomainStamp` for `(stamp.mgmt_name, stamp.domain_name)`."""
        self._stamps[stamp.key] = stamp

    def get_domain_stamp(self, mgmt_name: str, domain_name: str = "") -> DomainStamp | None:
        """Return the recorded `DomainStamp` for `(mgmt_name, domain_name)`."""
        return self._stamps.get(f"{mgmt_name}:{domain_name}")

    async def is_slice_cache_fresh(
        self,
        mgmt_name: str,
        domain_name: str,
        scope: SyncScope,
        item_type: str,
    ) -> bool:
        """Check whether `(mgmt_name, domain_name, scope, item_type)` in `domain_sync_state` matches `DomainStamp`."""
        memo_key = (mgmt_name, domain_name, scope, item_type)
        if memo_key in self._slice_fresh_memo:
            return self._slice_fresh_memo[memo_key]

        stamp = self.get_domain_stamp(mgmt_name, domain_name)
        if stamp is None or not stamp.readable:
            self._slice_fresh_memo[memo_key] = False
            return False

        try:
            sync_state = await self._cache.get_sync_state(mgmt_name, domain_name, scope, item_type)
        except Exception as exc:
            raise StateLookupError(
                f"Failed to read domain_sync_state for {mgmt_name}:{domain_name} ({scope}/{item_type}): {exc}"
            ) from exc

        fresh = _sync_state_matches_stamp(sync_state, stamp)
        self._slice_fresh_memo[memo_key] = fresh
        return fresh

    # ------------------------------------------------------------------
    # Intra-plan Virtual Overlay Recording
    # ------------------------------------------------------------------

    def record_virtual_object(self, obj: CPObject, *, previous_name: str | None = None) -> None:
        """Record an object planned for creation or update within the current `plan()` run."""
        dom_key = (obj.mgmt_name, obj.domain_name)
        bucket = self._virtual_objects.setdefault(dom_key, {})
        deleted = self._deleted_objects.setdefault(dom_key, set())
        if previous_name and previous_name != obj.name:
            deleted.add(f"name:{obj.type}:{previous_name}")
            bucket.pop(f"name:{obj.type}:{previous_name}", None)
        bucket[f"name:{obj.type}:{obj.name}"] = obj
        if obj.uid:
            bucket[f"uid:{obj.uid}"] = obj
            deleted.discard(f"uid:{obj.uid}")
        deleted.discard(f"name:{obj.type}:{obj.name}")

    def record_virtual_object_delete(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        obj_type: str,
        name: str | None = None,
        uid: str | None = None,
    ) -> None:
        """Record an object planned for deletion within the current `plan()` run."""
        dom_key = (mgmt_name, domain_name)
        bucket = self._virtual_objects.setdefault(dom_key, {})
        deleted = self._deleted_objects.setdefault(dom_key, set())
        if name:
            deleted.add(f"name:{obj_type}:{name}")
            bucket.pop(f"name:{obj_type}:{name}", None)
        if uid:
            deleted.add(f"uid:{uid}")
            bucket.pop(f"uid:{uid}", None)

    def record_virtual_service(self, svc: CPService, *, previous_name: str | None = None) -> None:
        """Record a service planned for creation or update within the current `plan()` run."""
        dom_key = (svc.mgmt_name, svc.domain_name)
        bucket = self._virtual_services.setdefault(dom_key, {})
        deleted = self._deleted_services.setdefault(dom_key, set())
        if previous_name and previous_name != svc.name:
            deleted.add(f"name:{svc.type}:{previous_name}")
            bucket.pop(f"name:{svc.type}:{previous_name}", None)
        bucket[f"name:{svc.type}:{svc.name}"] = svc
        if svc.uid:
            bucket[f"uid:{svc.uid}"] = svc
            deleted.discard(f"uid:{svc.uid}")
        deleted.discard(f"name:{svc.type}:{svc.name}")

    def record_virtual_service_delete(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        svc_type: str,
        name: str | None = None,
        uid: str | None = None,
    ) -> None:
        """Record a service planned for deletion within the current `plan()` run."""
        dom_key = (mgmt_name, domain_name)
        bucket = self._virtual_services.setdefault(dom_key, {})
        deleted = self._deleted_services.setdefault(dom_key, set())
        if name:
            deleted.add(f"name:{svc_type}:{name}")
            bucket.pop(f"name:{svc_type}:{name}", None)
        if uid:
            deleted.add(f"uid:{uid}")
            bucket.pop(f"uid:{uid}", None)

    # ------------------------------------------------------------------
    # Network Object Lookups (host, network, address-range, dns-domain, group)
    # ------------------------------------------------------------------

    async def get_object_by_name(
        self,
        mgmt_name: str,
        domain_name: str,
        obj_type: str,
        name: str,
    ) -> CPObject | None:
        """Look up a network object by `(mgmt_name, domain_name, obj_type, name)`."""
        dom_key = (mgmt_name, domain_name)
        del_set = self._deleted_objects.get(dom_key, set())
        if f"name:{obj_type}:{name}" in del_set:
            return None
        virt = self._virtual_objects.get(dom_key, {}).get(f"name:{obj_type}:{name}")
        if virt is not None:
            return virt

        if await self.is_slice_cache_fresh(mgmt_name, domain_name, "objects", obj_type):
            try:
                objs = await self._cache.get_objects(
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    types=[obj_type],
                    names=[name],
                )
            except Exception as exc:
                raise StateLookupError(
                    f"Cache lookup failed for {obj_type} {name!r} in {mgmt_name}:{domain_name}: {exc}"
                ) from exc
            for item in objs:
                if f"uid:{item.uid}" not in del_set and f"name:{obj_type}:{item.name}" not in del_set:
                    return item
            return None

        # Fallback to live API call
        cmd = TYPE_TO_SHOW_SINGLE_CMD.get(obj_type, f"show-{obj_type}")
        payload: dict[str, Any] = {"name": name}
        if obj_type == "dns-domain" and not name.startswith("."):
            payload["name"] = name
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
                    dot_res = await self._api.api_call(
                        mgmt_name,
                        cmd,
                        {"name": f".{name}"},
                        domain=domain_name or None,
                    )
                    if dot_res.success and isinstance(dot_res.data, dict):
                        return CPObject.from_cp_dict(mgmt_name, domain_name, dot_res.data)
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
        return CPObject.from_cp_dict(mgmt_name, domain_name, res.data)

    async def get_object_by_uid(
        self,
        mgmt_name: str,
        domain_name: str,
        obj_type: str,
        uid: str,
    ) -> CPObject | None:
        """Look up a network object by `(mgmt_name, domain_name, obj_type, uid)`."""
        dom_key = (mgmt_name, domain_name)
        del_set = self._deleted_objects.get(dom_key, set())
        if f"uid:{uid}" in del_set:
            return None
        virt = self._virtual_objects.get(dom_key, {}).get(f"uid:{uid}")
        if virt is not None:
            return virt

        if await self.is_slice_cache_fresh(mgmt_name, domain_name, "objects", obj_type):
            try:
                obj = await self._cache.get_object_by_uid(mgmt_name, domain_name, uid)
            except Exception as exc:
                raise StateLookupError(
                    f"Cache UID lookup failed for {obj_type} {uid!r} in {mgmt_name}:{domain_name}: {exc}"
                ) from exc
            if obj is not None and obj.type == obj_type and f"name:{obj.type}:{obj.name}" not in del_set:
                return obj
            return None

        cmd = TYPE_TO_SHOW_SINGLE_CMD.get(obj_type, f"show-{obj_type}")
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
        return CPObject.from_cp_dict(mgmt_name, domain_name, res.data)

    async def list_objects_of_type(
        self,
        mgmt_name: str,
        domain_name: str,
        obj_type: str,
    ) -> list[CPObject]:
        """Return all objects of `obj_type` in `(mgmt_name, domain_name)` from fresh cache or live `api_query`."""
        dom_key = (mgmt_name, domain_name)
        del_set = self._deleted_objects.get(dom_key, set())
        virt_map = self._virtual_objects.get(dom_key, {})

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
                plural_cmd = TYPE_TO_SHOW_PLURAL_CMD.get(obj_type, f"show-{obj_type}s")
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

        # Merge intra-plan virtual overlay
        result: list[CPObject] = []
        seen_names: set[str] = set()
        for item in base_list:
            if f"uid:{item.uid}" in del_set or f"name:{obj_type}:{item.name}" in del_set:
                continue
            override = virt_map.get(f"uid:{item.uid}") or virt_map.get(f"name:{obj_type}:{item.name}")
            if override is not None:
                if override.name not in seen_names:
                    result.append(override)
                    seen_names.add(override.name)
            else:
                if item.name not in seen_names:
                    result.append(item)
                    seen_names.add(item.name)

        for key, virt_obj in virt_map.items():
            if key.startswith(f"name:{obj_type}:") and virt_obj.name not in seen_names:
                result.append(virt_obj)
                seen_names.add(virt_obj.name)

        return result

    async def find_host_by_ip(
        self,
        mgmt_name: str,
        domain_name: str,
        ip_address: str,
    ) -> list[CPObject]:
        """Find all existing `host` objects matching `ip_address` (IPv4 or IPv6)."""
        target = ip_address.strip()
        hosts = await self.list_objects_of_type(mgmt_name, domain_name, "host")
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
        networks = await self.list_objects_of_type(mgmt_name, domain_name, "network")
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
        ranges = await self.list_objects_of_type(mgmt_name, domain_name, "address-range")
        matches: list[CPObject] = []
        for r in ranges:
            if r.ipv4_address_first == f_clean and r.ipv4_address_last == l_clean:
                matches.append(r)
        return matches

    # ------------------------------------------------------------------
    # Service Lookups (service-tcp, service-udp, service-icmp, service-group, service-other)
    # ------------------------------------------------------------------

    async def get_service_by_name(
        self,
        mgmt_name: str,
        domain_name: str,
        svc_type: str,
        name: str,
    ) -> CPService | None:
        """Look up a service object by `(mgmt_name, domain_name, svc_type, name)`."""
        dom_key = (mgmt_name, domain_name)
        del_set = self._deleted_services.get(dom_key, set())
        if f"name:{svc_type}:{name}" in del_set:
            return None
        virt = self._virtual_services.get(dom_key, {}).get(f"name:{svc_type}:{name}")
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
                if f"uid:{item.uid}" not in del_set and f"name:{svc_type}:{item.name}" not in del_set:
                    return item
            return None

        cmd = TYPE_TO_SHOW_SINGLE_CMD.get(svc_type, f"show-{svc_type}")
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
        return CPService.from_cp_dict(mgmt_name, domain_name, res.data)

    async def get_service_by_uid(
        self,
        mgmt_name: str,
        domain_name: str,
        svc_type: str,
        uid: str,
    ) -> CPService | None:
        """Look up a service object by `(mgmt_name, domain_name, svc_type, uid)`."""
        dom_key = (mgmt_name, domain_name)
        del_set = self._deleted_services.get(dom_key, set())
        if f"uid:{uid}" in del_set:
            return None
        virt = self._virtual_services.get(dom_key, {}).get(f"uid:{uid}")
        if virt is not None:
            return virt

        if await self.is_slice_cache_fresh(mgmt_name, domain_name, "services", svc_type):
            try:
                svc = await self._cache.get_service_by_uid(mgmt_name, domain_name, uid)
            except Exception as exc:
                raise StateLookupError(
                    f"Cache UID lookup failed for {svc_type} {uid!r} in {mgmt_name}:{domain_name}: {exc}"
                ) from exc
            if svc is not None and svc.type == svc_type and f"name:{svc.type}:{svc.name}" not in del_set:
                return svc
            return None

        cmd = TYPE_TO_SHOW_SINGLE_CMD.get(svc_type, f"show-{svc_type}")
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
        return CPService.from_cp_dict(mgmt_name, domain_name, res.data)

    async def list_services_of_type(
        self,
        mgmt_name: str,
        domain_name: str,
        svc_type: str,
    ) -> list[CPService]:
        """Return all services of `svc_type` in `(mgmt_name, domain_name)` from fresh cache or live `api_query`."""
        dom_key = (mgmt_name, domain_name)
        del_set = self._deleted_services.get(dom_key, set())
        virt_map = self._virtual_services.get(dom_key, {})

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
                plural_cmd = TYPE_TO_SHOW_PLURAL_CMD.get(svc_type, f"show-{svc_type}s")
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

        result: list[CPService] = []
        seen_names: set[str] = set()
        for item in base_list:
            if f"uid:{item.uid}" in del_set or f"name:{svc_type}:{item.name}" in del_set:
                continue
            override = virt_map.get(f"uid:{item.uid}") or virt_map.get(f"name:{svc_type}:{item.name}")
            if override is not None:
                if override.name not in seen_names:
                    result.append(override)
                    seen_names.add(override.name)
            else:
                if item.name not in seen_names:
                    result.append(item)
                    seen_names.add(item.name)

        for key, virt_svc in virt_map.items():
            if key.startswith(f"name:{svc_type}:") and virt_svc.name not in seen_names:
                result.append(virt_svc)
                seen_names.add(virt_svc.name)

        return result

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
        services = await self.list_services_of_type(mgmt_name, domain_name, svc_type)
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
        """Find existing ICMP services matching `(icmp_type, icmp_code)`."""
        services = await self.list_services_of_type(mgmt_name, domain_name, svc_type)
        matches: list[CPService] = []
        for s in services:
            if s.icmp_type != icmp_type:
                continue
            if icmp_code is not None and s.icmp_code != icmp_code:
                continue
            matches.append(s)
        return matches

    # ------------------------------------------------------------------
    # Rulebase & Where-Used Lookups
    # ------------------------------------------------------------------

    async def get_rulebase(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        rulebase_type: RulebaseType,
        layer: str | None = None,
        package: str | None = None,
    ) -> PagedRulebaseResult:
        """Read a rulebase layer or NAT package via `fetch_paged_rulebase`, raising `StateLookupError` on failure."""
        target_key = layer or package or ""
        memo_key = (mgmt_name, domain_name, rulebase_type, target_key)
        if memo_key in self._rulebase_memo:
            return self._rulebase_memo[memo_key]

        try:
            paged = await fetch_paged_rulebase(
                self._api,
                mgmt_name,
                domain_name or None,
                rulebase_type=rulebase_type,
                layer_name=layer or "",
                package_name=package,
            )
        except ServerIdentityError:
            raise
        except Exception as exc:
            raise StateLookupError(
                f"Failed to read {rulebase_type} rulebase {target_key!r} in {mgmt_name}:{domain_name}: {exc}"
            ) from exc

        self._rulebase_memo[memo_key] = paged
        return paged

    async def check_where_used(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        name: str | None = None,
        uid: str | None = None,
    ) -> dict[str, Any]:
        """Run `where-used` on `(name or uid)`, raising `StateLookupError` if the API call fails."""
        payload: dict[str, Any] = {}
        if uid:
            payload["uid"] = uid
        elif name:
            payload["name"] = name
        else:
            raise StateLookupError("where-used requires either uid or name.")

        try:
            res = await self._api.api_call(
                mgmt_name,
                "where-used",
                payload,
                domain=domain_name or None,
            )
        except ServerIdentityError:
            raise
        except Exception as exc:
            raise StateLookupError(
                f"where-used lookup failed for {uid or name!r} in {mgmt_name}:{domain_name}: {exc}"
            ) from exc

        if not res.success:
            raise StateLookupError(
                f"where-used lookup failed for {uid or name!r} in {mgmt_name}:{domain_name}: "
                f"{res.error_message or res.error_code or f'HTTP {res.status_code}'}"
            )
        return res.data if isinstance(res.data, dict) else {}


__all__ = [
    "HybridStateReader",
    "OBJECT_ITEM_TYPES",
    "SERVICE_ITEM_TYPES",
    "StateLookupError",
    "is_not_found_error",
    "normalize_mask_length",
]
