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
from arodonata.cpcrud.position_helper import is_cleanup_rule
from arodonata.rulebase.pager import PagedRulebaseResult, fetch_paged_rulebase


class HybridStateReader(_ObjectLookupMixin, _ServiceLookupMixin):
    """Isolated per-plan state reader combining `DomainStamp`-gated cache lookups with live API fallback."""

    # ------------------------------------------------------------------
    # Rulebase & Where-Used Lookups
    # ------------------------------------------------------------------

    def _apply_virtual_rules(
        self,
        paged: PagedRulebaseResult,
        *,
        mgmt_name: str,
        domain_name: str,
        rulebase_type: RulebaseType,
        target_key: str,
    ) -> PagedRulebaseResult:
        """Merge intra-plan virtual rule creations, updates, and deletions onto `paged` without mutating cache."""
        rb_key = (mgmt_name, domain_name, rulebase_type, target_key)
        del_set = self._deleted_rules.get(rb_key, set())
        virt_map = self._virtual_rules.get(rb_key, {})
        anchor_map = self._virtual_rule_anchors.get(rb_key, {})
        if not del_set and not virt_map:
            return paged

        attr_map: dict[RulebaseType, str] = {
            "access": "access_rules",
            "nat": "nat_rules",
            "https": "https_rules",
            "threat": "threat_rules",
        }
        attr = attr_map[rulebase_type]
        base_rules = list(getattr(paged, attr))
        merged_rules: list[Any] = []
        seen_uids: set[str] = set()
        seen_names: set[str] = set()

        for rule in base_rules:
            if rule.uid and f"uid:{rule.uid}" in del_set:
                continue
            override = virt_map.get(f"uid:{rule.uid}") if rule.uid else None
            if override is None:
                if rule.name and f"name:{rule.name}" in del_set:
                    continue
                if rule.name:
                    override = virt_map.get(f"name:{rule.name}")
            eff = override if override is not None else rule
            merged_rules.append(eff)
            if eff.uid:
                seen_uids.add(eff.uid)
            if eff.name:
                seen_names.add(eff.name)

        seen_vrule_ids: set[int] = set()
        for v_rule in virt_map.values():
            if id(v_rule) in seen_vrule_ids:
                continue
            seen_vrule_ids.add(id(v_rule))
            if v_rule.uid and v_rule.uid in seen_uids:
                continue
            if v_rule.name and v_rule.name in seen_names:
                continue
            if (v_rule.uid and f"uid:{v_rule.uid}" in del_set) or (v_rule.name and f"name:{v_rule.name}" in del_set):
                continue

            anchor = (anchor_map.get(f"uid:{v_rule.uid}") if v_rule.uid else None) or (
                anchor_map.get(f"name:{v_rule.name}") if v_rule.name else None
            )
            insert_idx: int | None = None
            if isinstance(anchor, dict):
                if "above" in anchor:
                    target = str(anchor["above"])
                    insert_idx = next(
                        (i for i, r in enumerate(merged_rules) if r.uid == target or (r.name and r.name == target)),
                        None,
                    )
                elif "below" in anchor:
                    target = str(anchor["below"])
                    found_i = next(
                        (i for i, r in enumerate(merged_rules) if r.uid == target or (r.name and r.name == target)),
                        None,
                    )
                    if found_i is not None:
                        insert_idx = found_i + 1
                elif "bottom" in anchor:
                    sec_target = str(anchor["bottom"])
                    sec_indices = [
                        i
                        for i, r in enumerate(merged_rules)
                        if r.section_name == sec_target or r.section_uid == sec_target
                    ]
                    if sec_indices:
                        last_i = sec_indices[-1]
                        if is_cleanup_rule(merged_rules[last_i], obj_dict=paged.objects_dictionary):
                            insert_idx = last_i
                        else:
                            insert_idx = last_i + 1
            elif isinstance(anchor, str) and anchor.strip().lower() == "top":
                insert_idx = 0

            if insert_idx is None:
                insert_idx = len(merged_rules)
                while insert_idx > 0 and is_cleanup_rule(
                    merged_rules[insert_idx - 1],
                    obj_dict=paged.objects_dictionary,
                ):
                    insert_idx -= 1

            merged_rules.insert(insert_idx, v_rule)
            if v_rule.uid:
                seen_uids.add(v_rule.uid)
            if v_rule.name:
                seen_names.add(v_rule.name)

        return paged.model_copy(update={attr: merged_rules})

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
            return self._apply_virtual_rules(
                self._rulebase_memo[memo_key],
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                rulebase_type=rulebase_type,
                target_key=target_key,
            )

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
        return self._apply_virtual_rules(
            paged,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            rulebase_type=rulebase_type,
            target_key=target_key,
        )

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
