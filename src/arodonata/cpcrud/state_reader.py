"""Hybrid cache-first + live API fallback state reader (`src/arodonata.cpcrud.state_reader`).

Implements `HybridStateReader`:
- Isolated per-run state reader created for each `plan()` invocation.
- Reads network objects (`host`, `network`, `address-range`, `dns-domain`, `group`,
  `application-site`) from `arodonata_objects` and services (`service-tcp`, `service-udp`,
  `service-icmp`, `service-icmp6`, `service-group`, `service-other`) from
  `arodonata_services` ONLY when the domain's stored `domain_sync_state` row for that
  specific `(scope, item_type)` has `status == "ok"` and matches the planner's `DomainStamp`
  (`last_published_at` and `last_session_uid`).
- Falls back to live Management API calls (`show-*` / `api_query`) otherwise.
- Raises `StateLookupError` when any lookup fails or `api_query` returns `paging_inconsistent`
  so the planner emits `Outcome.ERROR` rather than mistaking a failed read for "not found".
- Maintains an in-run virtual state overlay so objects/services planned for creation, update,
  or deletion earlier in the same `plan()` run are visible to subsequent steps.
"""

from __future__ import annotations

from typing import Any

from arodonata.core.errors import ServerIdentityError
from arodonata.core.models.rulebase import RulebaseType
from arodonata.cpcrud._state_reader_common import (
    OBJECT_ITEM_TYPES,
    SERVICE_ITEM_TYPES,
    TYPE_TO_SHOW_PLURAL_CMD,
    TYPE_TO_SHOW_SINGLE_CMD,
    StateLookupError,
    _is_command_not_recognized,
    _StateReaderCachePort,
    _sync_state_matches_stamp,
    is_not_found_error,
    normalize_app_site_url_key,
    normalize_mask_length,
)
from arodonata.cpcrud._state_reader_objects import _ObjectLookupMixin
from arodonata.cpcrud._state_reader_services import _ServiceLookupMixin
from arodonata.rulebase.pager import PagedRulebaseResult, fetch_paged_rulebase


class HybridStateReader(_ObjectLookupMixin, _ServiceLookupMixin):
    """Isolated per-plan state reader combining `DomainStamp`-gated cache lookups with live API fallback."""

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
    "TYPE_TO_SHOW_PLURAL_CMD",
    "TYPE_TO_SHOW_SINGLE_CMD",
    "_StateReaderCachePort",
    "_is_command_not_recognized",
    "_sync_state_matches_stamp",
    "is_not_found_error",
    "normalize_app_site_url_key",
    "normalize_mask_length",
]
