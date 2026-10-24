"""Declarative CPCRUD planner (`src/arodonata/cpcrud/planner.py`).

Implements `Planner` (`Planner.decide`):
- Reads `DomainStamp` (`show-last-published-session`) for every target `(mgmt_name, domain_name)`
  BEFORE performing any object, service, or rulebase lookups.
- Creates an isolated `HybridStateReader` per `plan()` run.
- Evaluates two-axis conflict policies (`NameConflictPolicy` x `IpConflictPolicy`) with
  convention-compliant auto-naming via `NamingPrefixes`.
- Emits `Outcome.ERROR` (`"lookup failed, nothing planned (re-plan to retry): ..."`) on any
  failed lookup or unreadable domain head instead of a false `CREATE`, and marks dependent
  actions as `Outcome.SKIPPED_DEPENDENCY` (`status="skipped_dependency"`).
- Resolves rules by key (`uid`, `name`, `rule_number`) or traffic tuple, normalizes Check Point
  NAT `"Original"` / `"Any"` sentinels, and anchors `"bottom"` placements above trailing cleanup rules.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from arodonata.core.errors import ServerIdentityError
from arodonata.core.models.common import utc_now
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import NatRuleEntry, RulebaseType
from arodonata.core.models.services import CPService
from arodonata.core.ports import ApiPort, CachePort
from arodonata.core.services.sync_coordinator import parse_cp_publish_timestamp
from arodonata.core.telemetry import span_attrs, traced
from arodonata.cpcrud.differ import (
    compute_object_diff,
    compute_rule_diff,
    compute_service_diff,
    resolve_member_reference,
)
from arodonata.cpcrud.models import (
    ConflictPolicy,
    DomainStamp,
    IpConflictPolicy,
    NameConflictPolicy,
    NamingPrefixes,
    Outcome,
    Plan,
    PlannedAction,
)
from arodonata.cpcrud.position_helper import resolve_rule_position
from arodonata.cpcrud.rule_identity import (
    RuleEntryUnion,
    match_rule,
    normalize_nat_traffic_ref,
    normalize_traffic_list,
)
from arodonata.cpcrud.state_reader import (
    OBJECT_ITEM_TYPES,
    SERVICE_ITEM_TYPES,
    HybridStateReader,
    StateLookupError,
    normalize_mask_length,
)

LOOKUP_ERROR_PREFIX = "lookup failed, nothing planned (re-plan to retry): "


def _normalize_verb(spec: Mapping[str, Any], *, is_rule: bool = False) -> str:
    """Resolve the desired operation verb (`present` / `add`, `set` / `update`, `absent` / `delete`)."""
    raw_op = spec.get("operation") or spec.get("state")
    if raw_op is None and not is_rule:
        raw_op = spec.get("action")
    elif raw_op is None and is_rule:
        cand = spec.get("action")
        if isinstance(cand, str) and cand.strip().lower() in (
            "present",
            "absent",
            "add",
            "set",
            "update",
            "delete",
        ):
            raw_op = cand
    verb = str(raw_op or "present").strip().lower()
    if verb in ("absent", "delete"):
        return "delete"
    if verb in ("set", "update"):
        return "set"
    return "present"


def _resolve_rulebase_type(spec: Mapping[str, Any]) -> tuple[RulebaseType, str]:
    """Return `(rulebase_type, canonical_rule_type)` for a rule operation dict."""
    raw_rb = str(spec.get("rulebase_type") or spec.get("type") or "").strip().lower()
    if raw_rb in ("nat", "nat-rule") or any(
        k in spec
        for k in (
            "original_source",
            "original-source",
            "translated_source",
            "translated-source",
            "method",
        )
    ):
        return "nat", "nat-rule"
    if raw_rb in ("https", "https-rule"):
        return "https", "https-rule"
    if raw_rb in ("threat", "threat-rule"):
        return "threat", "threat-rule"
    return "access", "access-rule"


def _extract_rule_references(spec: Mapping[str, Any]) -> set[str]:
    """Collect object/service names referenced by a rule specification for dependency checking."""
    refs: set[str] = set()
    for list_key in (
        "source",
        "destination",
        "service",
        "install_on",
        "install-on",
        "protected_scope",
        "protected-scope",
    ):
        val = spec.get(list_key)
        if isinstance(val, str) and val.strip():
            refs.add(val.strip())
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.strip():
                    refs.add(item.strip())
    for str_key in (
        "original_source",
        "original-source",
        "original_destination",
        "original-destination",
        "original_service",
        "original-service",
        "translated_source",
        "translated-source",
        "translated_destination",
        "translated-destination",
        "translated_service",
        "translated-service",
    ):
        val = spec.get(str_key)
        if isinstance(val, str) and val.strip():
            refs.add(val.strip())
    refs.discard("Any")
    refs.discard("any")
    refs.discard("Original")
    refs.discard("original")
    return refs


def _extract_group_references(spec: Mapping[str, Any]) -> set[str]:
    """Collect member names referenced by a group or service-group specification."""
    refs: set[str] = set()
    members = spec.get("members")
    if isinstance(members, list):
        for m in members:
            if isinstance(m, str) and m.strip():
                refs.add(m.strip())
    elif isinstance(members, dict):
        for k in ("add", "remove"):
            sub = members.get(k)
            if isinstance(sub, list):
                for m in sub:
                    if isinstance(m, str) and m.strip():
                        refs.add(m.strip())
    return refs


def _build_prior_object_state(obj: CPObject) -> dict[str, Any]:
    """Capture reversible state from an existing `CPObject` for `build_inverse_template`."""
    state: dict[str, Any] = {
        "uid": obj.uid,
        "name": obj.name,
        "type": obj.type,
        "comments": obj.comments,
    }
    if obj.color:
        state["color"] = obj.color
    if obj.tags:
        state["tags"] = list(obj.tags)
    if obj.type == "host":
        if obj.ipv4_address:
            state["ipv4-address"] = obj.ipv4_address
        if obj.ipv6_address:
            state["ipv6-address"] = obj.ipv6_address
    elif obj.type == "network":
        if obj.subnet4:
            state["subnet4"] = obj.subnet4
        mask = normalize_mask_length(obj.mask_length4, obj.subnet_mask)
        if mask is not None:
            state["mask-length4"] = mask
    elif obj.type == "address-range":
        if obj.ipv4_address_first:
            state["ipv4-address-first"] = obj.ipv4_address_first
        if obj.ipv4_address_last:
            state["ipv4-address-last"] = obj.ipv4_address_last
    elif obj.type == "dns-domain":
        if obj.is_sub_domain is not None:
            state["is-sub-domain"] = obj.is_sub_domain
    elif obj.type == "group":
        raw_members = obj.raw_data.get("members") if isinstance(obj.raw_data, dict) else None
        if isinstance(raw_members, list) and raw_members:
            names = [
                str(m.get("name") or m.get("uid"))
                for m in raw_members
                if isinstance(m, dict) and (m.get("name") or m.get("uid"))
            ]
            state["members"] = names if names else list(obj.members)
        else:
            state["members"] = list(obj.members)
    if obj.nat_settings:
        state["nat-settings"] = dict(obj.nat_settings)
    return state


def _build_prior_service_state(svc: CPService) -> dict[str, Any]:
    """Capture reversible state from an existing `CPService` for `build_inverse_template`."""
    state: dict[str, Any] = {
        "uid": svc.uid,
        "name": svc.name,
        "type": svc.type,
        "comments": svc.comments,
    }
    if svc.color:
        state["color"] = svc.color
    if svc.tags:
        state["tags"] = list(svc.tags)
    if svc.port is not None:
        state["port"] = svc.port
    if svc.protocol is not None:
        state["protocol"] = svc.protocol
    if svc.icmp_type is not None:
        state["icmp-type"] = svc.icmp_type
    if svc.icmp_code is not None:
        state["icmp-code"] = svc.icmp_code
    if svc.session_timeout is not None:
        state["session-timeout"] = svc.session_timeout
    if svc.match_for_any is not None:
        state["match-for-any"] = svc.match_for_any
    if svc.type == "service-group":
        raw_members = svc.raw_data.get("members") if isinstance(svc.raw_data, dict) else None
        if isinstance(raw_members, list) and raw_members:
            names = [
                str(m.get("name") or m.get("uid"))
                for m in raw_members
                if isinstance(m, dict) and (m.get("name") or m.get("uid"))
            ]
            state["members"] = names if names else list(svc.members)
        else:
            state["members"] = list(svc.members)
    return state


def _build_prior_rule_state(
    rule: RuleEntryUnion,
    *,
    rulebase_type: RulebaseType,
    layer: str | None,
    package: str | None,
) -> dict[str, Any]:
    """Capture reversible state from an existing rule for `build_inverse_template`."""
    state: dict[str, Any] = {
        "uid": rule.uid,
        "name": rule.name,
        "type": f"{rulebase_type}-rule",
        "rulebase_type": rulebase_type,
        "enabled": rule.enabled,
        "comments": rule.comments,
        "position": rule.position if rule.position > 0 else "bottom",
    }
    if layer:
        state["layer"] = layer
    if package:
        state["package"] = package
    if isinstance(rule, NatRuleEntry):
        state["method"] = rule.method or "static"
        state["original-source"] = rule.original_source or "Any"
        state["original-destination"] = rule.original_destination or "Any"
        state["original-service"] = rule.original_service or "Any"
        state["translated-source"] = rule.translated_source or "Original"
        state["translated-destination"] = rule.translated_destination or "Original"
        state["translated-service"] = rule.translated_service or "Original"
        if rule.install_on:
            state["install-on"] = list(rule.install_on)
    else:
        state["source"] = list(rule.source) if rule.source else ["Any"]
        state["destination"] = list(rule.destination) if rule.destination else ["Any"]
        state["service"] = list(rule.service) if rule.service else ["Any"]
        if rule.action:
            state["rule_action"] = rule.action
        if rule.track:
            state["track"] = rule.track
        if rule.install_on:
            state["install-on"] = list(rule.install_on)
    return state


class Planner:
    """Declarative CPCRUD planner producing deterministic, idempotent `Plan` objects."""

    def __init__(
        self,
        *,
        api: ApiPort,
        cache: CachePort,
        default_mgmt_name: str | None = None,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._api = api
        self._cache = cache
        self._default_mgmt_name = default_mgmt_name or ""
        self._now = now_fn

    async def _capture_domain_stamp(self, mgmt_name: str, domain_name: str) -> DomainStamp:
        """Read `show-last-published-session` for `(mgmt_name, domain_name)` BEFORE any domain lookups."""
        try:
            res = await self._api.api_call(
                mgmt_name,
                "show-last-published-session",
                {},
                domain=domain_name or None,
            )
        except ServerIdentityError:
            raise
        except Exception as exc:
            return DomainStamp(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                readable=False,
                error=str(exc),
                captured_at=self._now(),
            )

        if not res.success:
            err_msg = res.error_message or res.error_code or f"HTTP {res.status_code}"
            return DomainStamp(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                readable=False,
                error=err_msg,
                captured_at=self._now(),
            )

        data = res.data if isinstance(res.data, dict) else {}
        pub_at = parse_cp_publish_timestamp(data.get("publish-time") or data.get("last-modify-time"))
        uid_raw = data.get("uid")
        session_uid = str(uid_raw).strip() if isinstance(uid_raw, str) and uid_raw.strip() else None

        return DomainStamp(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            last_session_uid=session_uid,
            last_published_at=pub_at,
            readable=True,
            captured_at=self._now(),
        )

    def _expand_targets(self, template: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Normalize a flat or multi-target template into a list of target specifications."""
        raw_targets = template.get("targets") or template.get("domains")
        root_mgmt = str(template.get("mgmt_name") or self._default_mgmt_name).strip()
        root_domain = str(template.get("domain") or template.get("domain_name") or "").strip()
        raw_root_conflict = template.get("conflict_policy")
        root_conflict: dict[str, Any] = dict(raw_root_conflict) if isinstance(raw_root_conflict, dict) else {}
        root_name_pol = template.get("on_name_conflict") or root_conflict.get("on_name_conflict") or "update"
        root_ip_pol = template.get("on_ip_conflict") or root_conflict.get("on_ip_conflict") or "reuse"
        raw_root_prefixes = template.get("naming_prefixes")
        root_prefixes: dict[str, Any] = dict(raw_root_prefixes) if isinstance(raw_root_prefixes, dict) else {}

        targets: list[dict[str, Any]] = []
        if isinstance(raw_targets, list) and raw_targets:
            for item in raw_targets:
                if not isinstance(item, dict):
                    continue
                raw_t_conflict = item.get("conflict_policy")
                t_conflict: dict[str, Any] = dict(raw_t_conflict) if isinstance(raw_t_conflict, dict) else {}
                t_prefixes = dict(root_prefixes)
                raw_t_prefixes = item.get("naming_prefixes")
                if isinstance(raw_t_prefixes, dict):
                    t_prefixes.update(raw_t_prefixes)
                targets.append(
                    {
                        "mgmt_name": str(item.get("mgmt_name") or root_mgmt).strip(),
                        "domain_name": str(
                            item.get("domain") if "domain" in item else item.get("domain_name", root_domain) or ""
                        ).strip(),
                        "on_name_conflict": item.get("on_name_conflict")
                        or t_conflict.get("on_name_conflict")
                        or root_name_pol,
                        "on_ip_conflict": item.get("on_ip_conflict") or t_conflict.get("on_ip_conflict") or root_ip_pol,
                        "naming_prefixes": t_prefixes,
                        "objects": list(item.get("objects") or []),
                        "services": list(item.get("services") or []),
                        "groups": list(item.get("groups") or []),
                        "rules": list(item.get("rules") or []),
                        "operations": list(item.get("operations") or []),
                    }
                )
        else:
            targets.append(
                {
                    "mgmt_name": root_mgmt,
                    "domain_name": root_domain,
                    "on_name_conflict": root_name_pol,
                    "on_ip_conflict": root_ip_pol,
                    "naming_prefixes": dict(root_prefixes),
                    "objects": list(template.get("objects") or []),
                    "services": list(template.get("services") or []),
                    "groups": list(template.get("groups") or []),
                    "rules": list(template.get("rules") or []),
                    "operations": list(template.get("operations") or []),
                }
            )
        return targets

    def _collect_ordered_steps(self, target: Mapping[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        """Collect operations for a target in deterministic order (`object`, `service`, `group`, `rule`)."""
        steps: list[tuple[str, dict[str, Any]]] = []
        for obj in target.get("objects") or []:
            if isinstance(obj, dict):
                o_type = str(obj.get("type") or "host").strip().lower()
                if o_type == "group":
                    steps.append(("group", dict(obj)))
                else:
                    steps.append(("object", dict(obj)))
        for svc in target.get("services") or []:
            if isinstance(svc, dict):
                s_type = str(svc.get("type") or "service-tcp").strip().lower()
                if s_type == "service-group":
                    steps.append(("group", dict(svc)))
                else:
                    steps.append(("service", dict(svc)))
        for grp in target.get("groups") or []:
            if isinstance(grp, dict):
                steps.append(("group", dict(grp)))
        for rule in target.get("rules") or []:
            if isinstance(rule, dict):
                steps.append(("rule", dict(rule)))
        for op in target.get("operations") or []:
            if not isinstance(op, dict):
                continue
            op_type = str(op.get("type") or "").strip().lower()
            if (
                op_type in ("access-rule", "nat-rule", "https-rule", "threat-rule", "access", "nat", "https", "threat")
                or "layer" in op
                or "package" in op
            ):
                steps.append(("rule", dict(op)))
            elif op_type in ("group", "service-group"):
                steps.append(("group", dict(op)))
            elif op_type in SERVICE_ITEM_TYPES:
                steps.append(("service", dict(op)))
            else:
                steps.append(("object", dict(op)))
        return steps

    @traced
    async def decide(
        self,
        template: Mapping[str, Any],
        *,
        on_name_conflict: NameConflictPolicy | None = None,
        on_ip_conflict: IpConflictPolicy | None = None,
        naming_prefixes: NamingPrefixes | Mapping[str, Any] | None = None,
    ) -> Plan:
        """Produce a deterministic `Plan` for `template` using an isolated `HybridStateReader`."""
        targets = self._expand_targets(template)
        span_attrs(target_count=len(targets))

        # 1. Discover all unique (mgmt_name, domain_name) pairs across targets and step-level overrides
        domain_pairs: list[tuple[str, str]] = []
        seen_pairs: set[tuple[str, str]] = set()
        for t in targets:
            t_mgmt = str(t.get("mgmt_name") or self._default_mgmt_name).strip()
            t_dom = str(t.get("domain_name") or "").strip()
            steps = self._collect_ordered_steps(t)
            if not steps and (t_mgmt, t_dom) not in seen_pairs:
                seen_pairs.add((t_mgmt, t_dom))
                domain_pairs.append((t_mgmt, t_dom))
            for _kind, step_spec in steps:
                s_mgmt = str(step_spec.get("mgmt_name") or t_mgmt).strip()
                s_dom = str(
                    step_spec.get("domain") if "domain" in step_spec else step_spec.get("domain_name", t_dom) or ""
                ).strip()
                if (s_mgmt, s_dom) not in seen_pairs:
                    seen_pairs.add((s_mgmt, s_dom))
                    domain_pairs.append((s_mgmt, s_dom))

        # 2. Read DomainStamp (`show-last-published-session`) BEFORE any domain lookups
        domain_stamps: dict[str, DomainStamp] = {}
        for m_name, d_name in domain_pairs:
            stamp = await self._capture_domain_stamp(m_name, d_name)
            domain_stamps[stamp.key] = stamp

        # 3. Create isolated HybridStateReader for this planning run
        reader = HybridStateReader(
            api=self._api,
            cache=self._cache,
            domain_stamps=domain_stamps,
        )

        actions: list[PlannedAction] = []
        global_name_resolutions: dict[str, str] = {}
        action_seq = 0

        for t in targets:
            t_mgmt = str(t.get("mgmt_name") or self._default_mgmt_name).strip()
            t_dom = str(t.get("domain_name") or "").strip()
            eff_name_pol: NameConflictPolicy = (
                on_name_conflict if on_name_conflict is not None else (t.get("on_name_conflict") or "update")
            )
            eff_ip_pol: IpConflictPolicy = (
                on_ip_conflict if on_ip_conflict is not None else (t.get("on_ip_conflict") or "reuse")
            )
            if isinstance(naming_prefixes, NamingPrefixes):
                eff_prefixes = naming_prefixes
            elif isinstance(naming_prefixes, Mapping):
                eff_prefixes = NamingPrefixes.from_mapping(dict(naming_prefixes))
            else:
                eff_prefixes = NamingPrefixes.from_mapping(t.get("naming_prefixes") or {})

            # Track per-domain failed object/service names and action IDs for dependency skipping
            failed_refs_by_domain: dict[tuple[str, str], set[str]] = {}
            failed_action_ids_by_domain: dict[tuple[str, str], set[str]] = {}
            domain_resolutions: dict[tuple[str, str], dict[str, str]] = {}

            steps = self._collect_ordered_steps(t)
            for kind, step_spec in steps:
                action_seq += 1
                action_id = str(step_spec.get("id") or f"act-{action_seq}")
                s_mgmt = str(step_spec.get("mgmt_name") or t_mgmt).strip()
                s_dom = str(
                    step_spec.get("domain") if "domain" in step_spec else step_spec.get("domain_name", t_dom) or ""
                ).strip()
                dom_key = (s_mgmt, s_dom)
                step_stamp = domain_stamps.get(f"{s_mgmt}:{s_dom}")

                step_name_pol: NameConflictPolicy = step_spec.get("on_name_conflict") or eff_name_pol
                step_ip_pol: IpConflictPolicy = step_spec.get("on_ip_conflict") or eff_ip_pol
                policy = ConflictPolicy(
                    on_name_conflict=step_name_pol,
                    on_ip_conflict=step_ip_pol,
                )

                failed_refs = failed_refs_by_domain.setdefault(dom_key, set())
                failed_ids = failed_action_ids_by_domain.setdefault(dom_key, set())
                res_map = domain_resolutions.setdefault(dom_key, {})

                # Check if stamp was unreadable at the start of plan()
                if step_stamp is None or not step_stamp.readable:
                    err_reason = (step_stamp.error if step_stamp else None) or "show-last-published-session failed"
                    err_msg = f"{LOOKUP_ERROR_PREFIX}failed to read domain head for {s_mgmt}:{s_dom}: {err_reason}"
                    raw_name = str(step_spec.get("name") or step_spec.get("uid") or "")
                    obj_type = (
                        _resolve_rulebase_type(step_spec)[1]
                        if kind == "rule"
                        else str(step_spec.get("type") or "group")
                    )
                    act = PlannedAction(
                        action_id=action_id,
                        mgmt_name=s_mgmt,
                        domain_name=s_dom,
                        operation=_normalize_verb(step_spec, is_rule=(kind == "rule")),
                        object_type=obj_type,
                        name=raw_name,
                        outcome=Outcome.ERROR,
                        status="error",
                        desired_spec=dict(step_spec),
                        message=err_msg,
                        error=err_msg,
                    )
                    actions.append(act)
                    if raw_name:
                        failed_refs.add(raw_name)
                    failed_ids.add(action_id)
                    continue

                # Check explicit `depends_on` or implicit references to failed actions
                explicit_deps = [str(d) for d in (step_spec.get("depends_on") or []) if str(d)]
                broken_deps = [d for d in explicit_deps if d in failed_ids or d in failed_refs]
                if kind == "group":
                    grp_refs = _extract_group_references(step_spec)
                    broken_deps.extend(sorted(r for r in grp_refs if r in failed_refs))
                elif kind == "rule":
                    rule_refs = _extract_rule_references(step_spec)
                    broken_deps.extend(sorted(r for r in rule_refs if r in failed_refs))

                if broken_deps:
                    raw_name = str(step_spec.get("name") or step_spec.get("uid") or "")
                    obj_type = (
                        _resolve_rulebase_type(step_spec)[1]
                        if kind == "rule"
                        else str(step_spec.get("type") or "group")
                    )
                    skip_msg = f"Skipped due to failed dependency: {', '.join(dict.fromkeys(broken_deps))}"
                    act = PlannedAction(
                        action_id=action_id,
                        mgmt_name=s_mgmt,
                        domain_name=s_dom,
                        operation=_normalize_verb(step_spec, is_rule=(kind == "rule")),
                        object_type=obj_type,
                        name=raw_name,
                        outcome=Outcome.SKIPPED_DEPENDENCY,
                        status="skipped_dependency",
                        desired_spec=dict(step_spec),
                        depends_on=list(dict.fromkeys(explicit_deps + broken_deps)),
                        message=skip_msg,
                        error=skip_msg,
                    )
                    actions.append(act)
                    if raw_name:
                        failed_refs.add(raw_name)
                    failed_ids.add(action_id)
                    continue

                if kind == "object":
                    act = await self._plan_object_step(
                        action_id=action_id,
                        mgmt_name=s_mgmt,
                        domain_name=s_dom,
                        spec=step_spec,
                        policy=policy,
                        prefixes=eff_prefixes,
                        reader=reader,
                        res_map=res_map,
                    )
                elif kind == "service":
                    act = await self._plan_service_step(
                        action_id=action_id,
                        mgmt_name=s_mgmt,
                        domain_name=s_dom,
                        spec=step_spec,
                        policy=policy,
                        prefixes=eff_prefixes,
                        reader=reader,
                        res_map=res_map,
                    )
                elif kind == "group":
                    act = await self._plan_group_step(
                        action_id=action_id,
                        mgmt_name=s_mgmt,
                        domain_name=s_dom,
                        spec=step_spec,
                        policy=policy,
                        reader=reader,
                        res_map=res_map,
                    )
                else:
                    act = await self._plan_rule_step(
                        action_id=action_id,
                        mgmt_name=s_mgmt,
                        domain_name=s_dom,
                        spec=step_spec,
                        policy=policy,
                        reader=reader,
                        res_map=res_map,
                    )

                actions.append(act)
                if act.outcome in (Outcome.ERROR, Outcome.SKIPPED_DEPENDENCY):
                    if act.requested_name:
                        failed_refs.add(act.requested_name)
                    if act.name:
                        failed_refs.add(act.name)
                    failed_ids.add(act.action_id)
                elif act.requested_name and act.resolved_name and act.requested_name != act.resolved_name:
                    res_map[act.requested_name] = act.resolved_name
                    global_name_resolutions[act.requested_name] = act.resolved_name

        return Plan(
            created_at=self._now(),
            domain_stamps=domain_stamps,
            actions=actions,
            name_resolutions=global_name_resolutions,
            template=dict(template),
        )

    # ------------------------------------------------------------------
    # Object Planning (host, network, address-range, dns-domain)
    # ------------------------------------------------------------------

    async def _plan_object_step(
        self,
        *,
        action_id: str,
        mgmt_name: str,
        domain_name: str,
        spec: Mapping[str, Any],
        policy: ConflictPolicy,
        prefixes: NamingPrefixes,
        reader: HybridStateReader,
        res_map: dict[str, str],
    ) -> PlannedAction:
        obj_type = str(spec.get("type") or "host").strip().lower()
        verb = _normalize_verb(spec)
        req_name = str(spec.get("name") or "").strip()
        req_uid = str(spec.get("uid") or "").strip()
        display_name = req_name or req_uid

        try:
            existing: CPObject | None = None
            if req_uid:
                existing = await reader.get_object_by_uid(mgmt_name, domain_name, obj_type, req_uid)
            if existing is None and req_name:
                existing = await reader.get_object_by_name(mgmt_name, domain_name, obj_type, req_name)

            if verb == "delete":
                if existing is None:
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation="delete",
                        object_type=obj_type,
                        name=display_name,
                        outcome=Outcome.UNCHANGED,
                        desired_spec=dict(spec),
                        message=f"{obj_type} {display_name!r} is already absent.",
                    )
                if spec.get("check_where_used"):
                    _ = await reader.check_where_used(mgmt_name, domain_name, uid=existing.uid, name=existing.name)

                del_payload: dict[str, Any] = {"uid": existing.uid} if existing.uid else {"name": existing.name}
                reader.record_virtual_object_delete(
                    mgmt_name, domain_name, obj_type=obj_type, name=existing.name, uid=existing.uid
                )
                return PlannedAction(
                    action_id=action_id,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    operation="delete",
                    object_type=obj_type,
                    name=existing.name,
                    requested_name=display_name,
                    resolved_name=existing.name,
                    target_uid=existing.uid,
                    outcome=Outcome.DELETE,
                    command=f"delete-{obj_type}",
                    payload=del_payload,
                    prior_state=_build_prior_object_state(existing),
                    desired_spec=dict(spec),
                    message=f"Delete {obj_type} {existing.name!r}.",
                )

            # Case A: Object with requested name/UID already exists
            if existing is not None:
                diffs, update_payload = compute_object_diff(spec, existing, name_resolutions=res_map)
                if not diffs:
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation=verb,
                        object_type=obj_type,
                        name=existing.name,
                        requested_name=display_name,
                        resolved_name=existing.name,
                        target_uid=existing.uid,
                        outcome=Outcome.UNCHANGED,
                        prior_state=_build_prior_object_state(existing),
                        desired_spec=dict(spec),
                        message=f"{obj_type} {existing.name!r} is unchanged.",
                    )
                if policy.on_name_conflict == "error":
                    diff_keys = ", ".join(sorted(diffs.keys()))
                    err_msg = (
                        f"Name conflict on {obj_type} {existing.name!r}: "
                        f"differs on [{diff_keys}] and on_name_conflict='error'."
                    )
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation=verb,
                        object_type=obj_type,
                        name=existing.name,
                        requested_name=display_name,
                        resolved_name=existing.name,
                        target_uid=existing.uid,
                        outcome=Outcome.ERROR,
                        diffs=diffs,
                        prior_state=_build_prior_object_state(existing),
                        desired_spec=dict(spec),
                        message=err_msg,
                        error=err_msg,
                    )

                if existing.uid:
                    update_payload["uid"] = existing.uid
                else:
                    update_payload["name"] = existing.name

                new_target_name = str(update_payload.get("new-name") or existing.name)
                updated_model = existing.model_copy(
                    update={
                        "name": new_target_name,
                        "ipv4_address": update_payload.get("ipv4-address", existing.ipv4_address),
                        "ipv6_address": update_payload.get("ipv6-address", existing.ipv6_address),
                        "subnet4": update_payload.get("subnet4", existing.subnet4),
                        "mask_length4": update_payload.get("mask-length4", existing.mask_length4),
                        "ipv4_address_first": update_payload.get("ipv4-address-first", existing.ipv4_address_first),
                        "ipv4_address_last": update_payload.get("ipv4-address-last", existing.ipv4_address_last),
                        "comments": update_payload.get("comments", existing.comments),
                        "color": update_payload.get("color", existing.color),
                        "tags": update_payload.get("tags", existing.tags),
                    }
                )
                reader.record_virtual_object(updated_model, previous_name=existing.name)

                return PlannedAction(
                    action_id=action_id,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    operation="set",
                    object_type=obj_type,
                    name=existing.name,
                    requested_name=display_name,
                    resolved_name=new_target_name,
                    target_uid=existing.uid,
                    outcome=Outcome.UPDATE,
                    command=f"set-{obj_type}",
                    payload=update_payload,
                    diffs=diffs,
                    prior_state=_build_prior_object_state(existing),
                    desired_spec=dict(spec),
                    message=f"Update {obj_type} {existing.name!r} ({', '.join(sorted(diffs.keys()))}).",
                )

            # Case B: Name does not exist -> check IP/subnet/range conflict
            ip_matches: list[CPObject] = []
            auto_name: str | None = None

            if obj_type == "host":
                ip_val = (
                    spec.get("ipv4_address")
                    or spec.get("ipv4-address")
                    or spec.get("ip_address")
                    or spec.get("ip-address")
                    or spec.get("ipv6_address")
                    or spec.get("ipv6-address")
                )
                if isinstance(ip_val, str) and ip_val.strip():
                    ip_matches = await reader.find_host_by_ip(mgmt_name, domain_name, ip_val.strip())
                    auto_name = prefixes.format_host(ip_val.strip())
            elif obj_type == "network":
                sub_val = spec.get("subnet4") or spec.get("subnet")
                mask_raw = spec.get("mask_length4") if "mask_length4" in spec else spec.get("mask-length4")
                submask_raw = spec.get("subnet_mask") or spec.get("subnet-mask")
                norm_mask = normalize_mask_length(mask_raw, submask_raw)
                if isinstance(sub_val, str) and sub_val.strip() and norm_mask is not None:
                    ip_matches = await reader.find_network_by_subnet(mgmt_name, domain_name, sub_val.strip(), norm_mask)
                    auto_name = prefixes.format_network(sub_val.strip(), norm_mask)
            elif obj_type == "address-range":
                f_val = spec.get("ipv4_address_first") or spec.get("ipv4-address-first")
                l_val = spec.get("ipv4_address_last") or spec.get("ipv4-address-last")
                if isinstance(f_val, str) and f_val.strip() and isinstance(l_val, str) and l_val.strip():
                    ip_matches = await reader.find_address_range_by_bounds(
                        mgmt_name, domain_name, f_val.strip(), l_val.strip()
                    )
                    auto_name = prefixes.format_address_range(f_val.strip(), l_val.strip())

            target_create_name = req_name
            extra_create_flags: dict[str, Any] = {}

            if ip_matches:
                matched_obj = ip_matches[0]
                if policy.on_ip_conflict == "error":
                    err_msg = (
                        f"IP/subnet conflict for {obj_type} {req_name!r}: "
                        f"already exists as {matched_obj.name!r} ({matched_obj.uid}) and on_ip_conflict='error'."
                    )
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation=verb,
                        object_type=obj_type,
                        name=req_name,
                        requested_name=req_name,
                        resolved_name=req_name,
                        target_uid=matched_obj.uid,
                        outcome=Outcome.ERROR,
                        desired_spec=dict(spec),
                        message=err_msg,
                        error=err_msg,
                    )
                if policy.on_ip_conflict == "reuse":
                    res_map[req_name] = matched_obj.name
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation=verb,
                        object_type=obj_type,
                        name=matched_obj.name,
                        requested_name=req_name,
                        resolved_name=matched_obj.name,
                        target_uid=matched_obj.uid,
                        outcome=Outcome.REUSE,
                        prior_state=_build_prior_object_state(matched_obj),
                        desired_spec=dict(spec),
                        message=f"Reuse existing {obj_type} {matched_obj.name!r} for requested {req_name!r}.",
                    )
                if policy.on_ip_conflict == "create_new" and auto_name:
                    target_create_name = auto_name
                    extra_create_flags["ignore-warnings"] = True
                    # Check if the convention-named object itself already exists
                    existing_auto = await reader.get_object_by_name(mgmt_name, domain_name, obj_type, auto_name)
                    if existing_auto is not None:
                        res_map[req_name] = existing_auto.name
                        return PlannedAction(
                            action_id=action_id,
                            mgmt_name=mgmt_name,
                            domain_name=domain_name,
                            operation=verb,
                            object_type=obj_type,
                            name=existing_auto.name,
                            requested_name=req_name,
                            resolved_name=existing_auto.name,
                            target_uid=existing_auto.uid,
                            outcome=Outcome.UNCHANGED,
                            prior_state=_build_prior_object_state(existing_auto),
                            desired_spec=dict(spec),
                            message=f"Auto-named {obj_type} {existing_auto.name!r} already exists.",
                        )

            # Case C: Plan CREATE
            add_payload = _build_add_object_payload(obj_type, target_create_name, spec)
            add_payload.update(extra_create_flags)
            virt_cp = CPObject.from_cp_dict(
                mgmt_name,
                domain_name,
                {
                    **add_payload,
                    "uid": f"planned:{obj_type}:{target_create_name}",
                    "type": obj_type,
                    "name": target_create_name,
                },
            )
            reader.record_virtual_object(virt_cp)
            if req_name and target_create_name != req_name:
                res_map[req_name] = target_create_name

            return PlannedAction(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                operation="add",
                object_type=obj_type,
                name=target_create_name,
                requested_name=req_name or target_create_name,
                resolved_name=target_create_name,
                outcome=Outcome.CREATE,
                command=f"add-{obj_type}",
                payload=add_payload,
                desired_spec=dict(spec),
                message=f"Create {obj_type} {target_create_name!r}.",
            )

        except StateLookupError as exc:
            err_msg = f"{LOOKUP_ERROR_PREFIX}{exc}"
            return PlannedAction(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                operation=verb,
                object_type=obj_type,
                name=display_name,
                requested_name=display_name,
                resolved_name=display_name,
                outcome=Outcome.ERROR,
                status="error",
                desired_spec=dict(spec),
                message=err_msg,
                error=err_msg,
            )

    # ------------------------------------------------------------------
    # Service Planning (service-tcp, service-udp, service-icmp, service-other)
    # ------------------------------------------------------------------

    async def _plan_service_step(
        self,
        *,
        action_id: str,
        mgmt_name: str,
        domain_name: str,
        spec: Mapping[str, Any],
        policy: ConflictPolicy,
        prefixes: NamingPrefixes,
        reader: HybridStateReader,
        res_map: dict[str, str],
    ) -> PlannedAction:
        svc_type = str(spec.get("type") or "service-tcp").strip().lower()
        verb = _normalize_verb(spec)
        req_name = str(spec.get("name") or "").strip()
        req_uid = str(spec.get("uid") or "").strip()
        display_name = req_name or req_uid

        try:
            existing: CPService | None = None
            if req_uid:
                existing = await reader.get_service_by_uid(mgmt_name, domain_name, svc_type, req_uid)
            if existing is None and req_name:
                existing = await reader.get_service_by_name(mgmt_name, domain_name, svc_type, req_name)

            if verb == "delete":
                if existing is None:
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation="delete",
                        object_type=svc_type,
                        name=display_name,
                        outcome=Outcome.UNCHANGED,
                        desired_spec=dict(spec),
                        message=f"{svc_type} {display_name!r} is already absent.",
                    )
                del_payload: dict[str, Any] = {"uid": existing.uid} if existing.uid else {"name": existing.name}
                reader.record_virtual_service_delete(
                    mgmt_name, domain_name, svc_type=svc_type, name=existing.name, uid=existing.uid
                )
                return PlannedAction(
                    action_id=action_id,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    operation="delete",
                    object_type=svc_type,
                    name=existing.name,
                    requested_name=display_name,
                    resolved_name=existing.name,
                    target_uid=existing.uid,
                    outcome=Outcome.DELETE,
                    command=f"delete-{svc_type}",
                    payload=del_payload,
                    prior_state=_build_prior_service_state(existing),
                    desired_spec=dict(spec),
                    message=f"Delete {svc_type} {existing.name!r}.",
                )

            if existing is not None:
                diffs, update_payload = compute_service_diff(spec, existing, name_resolutions=res_map)
                if not diffs:
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation=verb,
                        object_type=svc_type,
                        name=existing.name,
                        requested_name=display_name,
                        resolved_name=existing.name,
                        target_uid=existing.uid,
                        outcome=Outcome.UNCHANGED,
                        prior_state=_build_prior_service_state(existing),
                        desired_spec=dict(spec),
                        message=f"{svc_type} {existing.name!r} is unchanged.",
                    )
                if policy.on_name_conflict == "error":
                    diff_keys = ", ".join(sorted(diffs.keys()))
                    err_msg = (
                        f"Name conflict on {svc_type} {existing.name!r}: "
                        f"differs on [{diff_keys}] and on_name_conflict='error'."
                    )
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation=verb,
                        object_type=svc_type,
                        name=existing.name,
                        requested_name=display_name,
                        resolved_name=existing.name,
                        target_uid=existing.uid,
                        outcome=Outcome.ERROR,
                        diffs=diffs,
                        prior_state=_build_prior_service_state(existing),
                        desired_spec=dict(spec),
                        message=err_msg,
                        error=err_msg,
                    )

                if existing.uid:
                    update_payload["uid"] = existing.uid
                else:
                    update_payload["name"] = existing.name

                new_target_name = str(update_payload.get("new-name") or existing.name)
                updated_svc = existing.model_copy(
                    update={
                        "name": new_target_name,
                        "port": str(update_payload["port"]) if "port" in update_payload else existing.port,
                        "comments": update_payload.get("comments", existing.comments),
                        "color": update_payload.get("color", existing.color),
                        "tags": update_payload.get("tags", existing.tags),
                    }
                )
                reader.record_virtual_service(updated_svc, previous_name=existing.name)

                return PlannedAction(
                    action_id=action_id,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    operation="set",
                    object_type=svc_type,
                    name=existing.name,
                    requested_name=display_name,
                    resolved_name=new_target_name,
                    target_uid=existing.uid,
                    outcome=Outcome.UPDATE,
                    command=f"set-{svc_type}",
                    payload=update_payload,
                    diffs=diffs,
                    prior_state=_build_prior_service_state(existing),
                    desired_spec=dict(spec),
                    message=f"Update {svc_type} {existing.name!r} ({', '.join(sorted(diffs.keys()))}).",
                )

            # Check port/protocol or ICMP conflict under another name
            port_matches: list[CPService] = []
            auto_name: str | None = None
            if svc_type in ("service-tcp", "service-udp") and spec.get("port") is not None:
                port_str = str(spec["port"]).strip()
                proto_str = str(spec["protocol"]).strip() if spec.get("protocol") is not None else None
                port_matches = await reader.find_service_by_port(mgmt_name, domain_name, svc_type, port_str, proto_str)
                auto_name = (
                    prefixes.format_tcp(port_str) if svc_type == "service-tcp" else prefixes.format_udp(port_str)
                )
            elif svc_type in ("service-icmp", "service-icmp6"):
                icmp_t = spec.get("icmp_type") if "icmp_type" in spec else spec.get("icmp-type")
                icmp_c = spec.get("icmp_code") if "icmp_code" in spec else spec.get("icmp-code")
                if isinstance(icmp_t, int):
                    port_matches = await reader.find_icmp_service(
                        mgmt_name,
                        domain_name,
                        svc_type,
                        icmp_t,
                        icmp_c if isinstance(icmp_c, int) else None,
                    )
                    auto_name = prefixes.format_icmp(icmp_t, icmp_c if isinstance(icmp_c, int) else None)

            target_create_name = req_name
            extra_flags: dict[str, Any] = {}
            if port_matches:
                matched_svc = port_matches[0]
                if policy.on_ip_conflict == "error":
                    err_msg = (
                        f"Port/protocol conflict for {svc_type} {req_name!r}: "
                        f"already exists as {matched_svc.name!r} ({matched_svc.uid}) and on_ip_conflict='error'."
                    )
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation=verb,
                        object_type=svc_type,
                        name=req_name,
                        requested_name=req_name,
                        resolved_name=req_name,
                        target_uid=matched_svc.uid,
                        outcome=Outcome.ERROR,
                        desired_spec=dict(spec),
                        message=err_msg,
                        error=err_msg,
                    )
                if policy.on_ip_conflict == "reuse":
                    res_map[req_name] = matched_svc.name
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation=verb,
                        object_type=svc_type,
                        name=matched_svc.name,
                        requested_name=req_name,
                        resolved_name=matched_svc.name,
                        target_uid=matched_svc.uid,
                        outcome=Outcome.REUSE,
                        prior_state=_build_prior_service_state(matched_svc),
                        desired_spec=dict(spec),
                        message=f"Reuse existing {svc_type} {matched_svc.name!r} for requested {req_name!r}.",
                    )
                if policy.on_ip_conflict == "create_new" and auto_name:
                    target_create_name = auto_name
                    extra_flags["ignore-warnings"] = True
                    existing_auto = await reader.get_service_by_name(mgmt_name, domain_name, svc_type, auto_name)
                    if existing_auto is not None:
                        res_map[req_name] = existing_auto.name
                        return PlannedAction(
                            action_id=action_id,
                            mgmt_name=mgmt_name,
                            domain_name=domain_name,
                            operation=verb,
                            object_type=svc_type,
                            name=existing_auto.name,
                            requested_name=req_name,
                            resolved_name=existing_auto.name,
                            target_uid=existing_auto.uid,
                            outcome=Outcome.UNCHANGED,
                            prior_state=_build_prior_service_state(existing_auto),
                            desired_spec=dict(spec),
                            message=f"Auto-named {svc_type} {existing_auto.name!r} already exists.",
                        )

            add_payload = _build_add_service_payload(svc_type, target_create_name, spec)
            add_payload.update(extra_flags)
            virt_svc = CPService.from_cp_dict(
                mgmt_name,
                domain_name,
                {
                    **add_payload,
                    "uid": f"planned:{svc_type}:{target_create_name}",
                    "type": svc_type,
                    "name": target_create_name,
                },
            )
            reader.record_virtual_service(virt_svc)
            if req_name and target_create_name != req_name:
                res_map[req_name] = target_create_name

            return PlannedAction(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                operation="add",
                object_type=svc_type,
                name=target_create_name,
                requested_name=req_name or target_create_name,
                resolved_name=target_create_name,
                outcome=Outcome.CREATE,
                command=f"add-{svc_type}",
                payload=add_payload,
                desired_spec=dict(spec),
                message=f"Create {svc_type} {target_create_name!r}.",
            )

        except StateLookupError as exc:
            err_msg = f"{LOOKUP_ERROR_PREFIX}{exc}"
            return PlannedAction(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                operation=verb,
                object_type=svc_type,
                name=display_name,
                requested_name=display_name,
                resolved_name=display_name,
                outcome=Outcome.ERROR,
                status="error",
                desired_spec=dict(spec),
                message=err_msg,
                error=err_msg,
            )

    # ------------------------------------------------------------------
    # Group & Service-Group Planning
    # ------------------------------------------------------------------

    async def _plan_group_step(
        self,
        *,
        action_id: str,
        mgmt_name: str,
        domain_name: str,
        spec: Mapping[str, Any],
        policy: ConflictPolicy,
        reader: HybridStateReader,
        res_map: dict[str, str],
    ) -> PlannedAction:
        grp_type = str(spec.get("type") or "group").strip().lower()
        verb = _normalize_verb(spec)
        req_name = str(spec.get("name") or "").strip()
        req_uid = str(spec.get("uid") or "").strip()
        display_name = req_name or req_uid

        try:
            if grp_type == "service-group":
                existing_svc = (
                    await reader.get_service_by_uid(mgmt_name, domain_name, "service-group", req_uid)
                    if req_uid
                    else None
                )
                if existing_svc is None and req_name:
                    existing_svc = await reader.get_service_by_name(mgmt_name, domain_name, "service-group", req_name)

                if verb == "delete":
                    if existing_svc is None:
                        return PlannedAction(
                            action_id=action_id,
                            mgmt_name=mgmt_name,
                            domain_name=domain_name,
                            operation="delete",
                            object_type="service-group",
                            name=display_name,
                            outcome=Outcome.UNCHANGED,
                            desired_spec=dict(spec),
                            message=f"service-group {display_name!r} is already absent.",
                        )
                    del_payload = {"uid": existing_svc.uid} if existing_svc.uid else {"name": existing_svc.name}
                    reader.record_virtual_service_delete(
                        mgmt_name, domain_name, svc_type="service-group", name=existing_svc.name, uid=existing_svc.uid
                    )
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation="delete",
                        object_type="service-group",
                        name=existing_svc.name,
                        target_uid=existing_svc.uid,
                        outcome=Outcome.DELETE,
                        command="delete-service-group",
                        payload=del_payload,
                        prior_state=_build_prior_service_state(existing_svc),
                        desired_spec=dict(spec),
                        message=f"Delete service-group {existing_svc.name!r}.",
                    )

                if existing_svc is not None:
                    diffs, update_payload = compute_service_diff(spec, existing_svc, name_resolutions=res_map)
                    if not diffs:
                        return PlannedAction(
                            action_id=action_id,
                            mgmt_name=mgmt_name,
                            domain_name=domain_name,
                            operation=verb,
                            object_type="service-group",
                            name=existing_svc.name,
                            target_uid=existing_svc.uid,
                            outcome=Outcome.UNCHANGED,
                            prior_state=_build_prior_service_state(existing_svc),
                            desired_spec=dict(spec),
                            message=f"service-group {existing_svc.name!r} is unchanged.",
                        )
                    if policy.on_name_conflict == "error":
                        err_msg = (
                            f"Name conflict on service-group {existing_svc.name!r}: "
                            f"differs on [{', '.join(sorted(diffs.keys()))}] and on_name_conflict='error'."
                        )
                        return PlannedAction(
                            action_id=action_id,
                            mgmt_name=mgmt_name,
                            domain_name=domain_name,
                            operation=verb,
                            object_type="service-group",
                            name=existing_svc.name,
                            target_uid=existing_svc.uid,
                            outcome=Outcome.ERROR,
                            diffs=diffs,
                            prior_state=_build_prior_service_state(existing_svc),
                            desired_spec=dict(spec),
                            message=err_msg,
                            error=err_msg,
                        )
                    if existing_svc.uid:
                        update_payload["uid"] = existing_svc.uid
                    else:
                        update_payload["name"] = existing_svc.name
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation="set",
                        object_type="service-group",
                        name=existing_svc.name,
                        target_uid=existing_svc.uid,
                        outcome=Outcome.UPDATE,
                        command="set-service-group",
                        payload=update_payload,
                        diffs=diffs,
                        prior_state=_build_prior_service_state(existing_svc),
                        desired_spec=dict(spec),
                        message=f"Update service-group {existing_svc.name!r}.",
                    )

                add_payload = _build_add_group_payload(req_name, spec, name_resolutions=res_map)
                virt_sg = CPService.from_cp_dict(
                    mgmt_name,
                    domain_name,
                    {
                        **add_payload,
                        "uid": f"planned:service-group:{req_name}",
                        "type": "service-group",
                        "name": req_name,
                    },
                )
                reader.record_virtual_service(virt_sg)
                return PlannedAction(
                    action_id=action_id,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    operation="add",
                    object_type="service-group",
                    name=req_name,
                    outcome=Outcome.CREATE,
                    command="add-service-group",
                    payload=add_payload,
                    desired_spec=dict(spec),
                    message=f"Create service-group {req_name!r}.",
                )

            # Standard network object group (`group`)
            existing_grp = await reader.get_object_by_uid(mgmt_name, domain_name, "group", req_uid) if req_uid else None
            if existing_grp is None and req_name:
                existing_grp = await reader.get_object_by_name(mgmt_name, domain_name, "group", req_name)

            if verb == "delete":
                if existing_grp is None:
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation="delete",
                        object_type="group",
                        name=display_name,
                        outcome=Outcome.UNCHANGED,
                        desired_spec=dict(spec),
                        message=f"group {display_name!r} is already absent.",
                    )
                del_payload = {"uid": existing_grp.uid} if existing_grp.uid else {"name": existing_grp.name}
                reader.record_virtual_object_delete(
                    mgmt_name, domain_name, obj_type="group", name=existing_grp.name, uid=existing_grp.uid
                )
                return PlannedAction(
                    action_id=action_id,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    operation="delete",
                    object_type="group",
                    name=existing_grp.name,
                    target_uid=existing_grp.uid,
                    outcome=Outcome.DELETE,
                    command="delete-group",
                    payload=del_payload,
                    prior_state=_build_prior_object_state(existing_grp),
                    desired_spec=dict(spec),
                    message=f"Delete group {existing_grp.name!r}.",
                )

            if existing_grp is not None:
                diffs, update_payload = compute_object_diff(spec, existing_grp, name_resolutions=res_map)
                if not diffs:
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation=verb,
                        object_type="group",
                        name=existing_grp.name,
                        target_uid=existing_grp.uid,
                        outcome=Outcome.UNCHANGED,
                        prior_state=_build_prior_object_state(existing_grp),
                        desired_spec=dict(spec),
                        message=f"group {existing_grp.name!r} is unchanged.",
                    )
                if policy.on_name_conflict == "error":
                    err_msg = (
                        f"Name conflict on group {existing_grp.name!r}: "
                        f"differs on [{', '.join(sorted(diffs.keys()))}] and on_name_conflict='error'."
                    )
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation=verb,
                        object_type="group",
                        name=existing_grp.name,
                        target_uid=existing_grp.uid,
                        outcome=Outcome.ERROR,
                        diffs=diffs,
                        prior_state=_build_prior_object_state(existing_grp),
                        desired_spec=dict(spec),
                        message=err_msg,
                        error=err_msg,
                    )
                if existing_grp.uid:
                    update_payload["uid"] = existing_grp.uid
                else:
                    update_payload["name"] = existing_grp.name
                return PlannedAction(
                    action_id=action_id,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    operation="set",
                    object_type="group",
                    name=existing_grp.name,
                    target_uid=existing_grp.uid,
                    outcome=Outcome.UPDATE,
                    command="set-group",
                    payload=update_payload,
                    diffs=diffs,
                    prior_state=_build_prior_object_state(existing_grp),
                    desired_spec=dict(spec),
                    message=f"Update group {existing_grp.name!r}.",
                )

            add_payload = _build_add_group_payload(req_name, spec, name_resolutions=res_map)
            virt_grp = CPObject.from_cp_dict(
                mgmt_name,
                domain_name,
                {
                    **add_payload,
                    "uid": f"planned:group:{req_name}",
                    "type": "group",
                    "name": req_name,
                },
            )
            reader.record_virtual_object(virt_grp)
            return PlannedAction(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                operation="add",
                object_type="group",
                name=req_name,
                outcome=Outcome.CREATE,
                command="add-group",
                payload=add_payload,
                desired_spec=dict(spec),
                message=f"Create group {req_name!r}.",
            )

        except StateLookupError as exc:
            err_msg = f"{LOOKUP_ERROR_PREFIX}{exc}"
            return PlannedAction(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                operation=verb,
                object_type=grp_type,
                name=display_name,
                requested_name=display_name,
                resolved_name=display_name,
                outcome=Outcome.ERROR,
                status="error",
                desired_spec=dict(spec),
                message=err_msg,
                error=err_msg,
            )

    # ------------------------------------------------------------------
    # Rule Planning (access-rule, nat-rule, https-rule, threat-rule)
    # ------------------------------------------------------------------

    async def _plan_rule_step(
        self,
        *,
        action_id: str,
        mgmt_name: str,
        domain_name: str,
        spec: Mapping[str, Any],
        policy: ConflictPolicy,
        reader: HybridStateReader,
        res_map: dict[str, str],
    ) -> PlannedAction:
        rb_type, rule_type = _resolve_rulebase_type(spec)
        verb = _normalize_verb(spec, is_rule=True)
        layer = str(spec.get("layer") or "").strip() or None
        package = str(spec.get("package") or "").strip() or None
        req_name = str(spec.get("name") or "").strip()
        req_uid = str(spec.get("uid") or "").strip()
        display_name = req_name or req_uid or f"{rule_type}@{layer or package}"

        try:
            paged = await reader.get_rulebase(
                mgmt_name,
                domain_name,
                rulebase_type=rb_type,
                layer=layer,
                package=package,
            )

            rules_list: list[RuleEntryUnion]
            if rb_type == "nat":
                rules_list = list(paged.nat_rules)
            elif rb_type == "https":
                rules_list = list(paged.https_rules)
            elif rb_type == "threat":
                rules_list = list(paged.threat_rules)
            else:
                rules_list = list(paged.access_rules)

            existing = match_rule(
                spec,
                rules_list,
                rulebase_type=rb_type,
                obj_dict=paged.objects_dictionary,
                name_resolutions=res_map,
            )

            if verb == "delete":
                if existing is None:
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation="delete",
                        object_type=rule_type,
                        name=display_name,
                        layer=layer,
                        package=package,
                        outcome=Outcome.UNCHANGED,
                        desired_spec=dict(spec),
                        message=f"{rule_type} {display_name!r} is already absent.",
                    )
                del_payload: dict[str, Any] = {"uid": existing.uid}
                if rb_type == "nat":
                    del_payload["package"] = package or paged.package_name or paged.layer_name
                else:
                    del_payload["layer"] = layer or paged.layer_name
                return PlannedAction(
                    action_id=action_id,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    operation="delete",
                    object_type=rule_type,
                    name=existing.name or display_name,
                    target_uid=existing.uid,
                    layer=layer,
                    package=package,
                    outcome=Outcome.DELETE,
                    command=f"delete-{rule_type}",
                    payload=del_payload,
                    prior_state=_build_prior_rule_state(existing, rulebase_type=rb_type, layer=layer, package=package),
                    desired_spec=dict(spec),
                    message=f"Delete {rule_type} {existing.name or existing.uid!r}.",
                )

            if existing is not None:
                diffs, update_payload = compute_rule_diff(
                    spec,
                    existing,
                    rulebase_type=rb_type,
                    obj_dict=paged.objects_dictionary,
                    name_resolutions=res_map,
                )
                if not diffs:
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation=verb,
                        object_type=rule_type,
                        name=existing.name or display_name,
                        target_uid=existing.uid,
                        layer=layer,
                        package=package,
                        outcome=Outcome.UNCHANGED,
                        prior_state=_build_prior_rule_state(
                            existing, rulebase_type=rb_type, layer=layer, package=package
                        ),
                        desired_spec=dict(spec),
                        message=f"{rule_type} {existing.name or existing.uid!r} is unchanged.",
                    )
                if policy.on_name_conflict == "error":
                    err_msg = (
                        f"Rule conflict on {rule_type} {existing.name or existing.uid!r}: "
                        f"differs on [{', '.join(sorted(diffs.keys()))}] and on_name_conflict='error'."
                    )
                    return PlannedAction(
                        action_id=action_id,
                        mgmt_name=mgmt_name,
                        domain_name=domain_name,
                        operation=verb,
                        object_type=rule_type,
                        name=existing.name or display_name,
                        target_uid=existing.uid,
                        layer=layer,
                        package=package,
                        outcome=Outcome.ERROR,
                        diffs=diffs,
                        prior_state=_build_prior_rule_state(
                            existing, rulebase_type=rb_type, layer=layer, package=package
                        ),
                        desired_spec=dict(spec),
                        message=err_msg,
                        error=err_msg,
                    )

                update_payload["uid"] = existing.uid
                if rb_type == "nat":
                    update_payload["package"] = package or paged.package_name or paged.layer_name
                else:
                    update_payload["layer"] = layer or paged.layer_name

                return PlannedAction(
                    action_id=action_id,
                    mgmt_name=mgmt_name,
                    domain_name=domain_name,
                    operation="set",
                    object_type=rule_type,
                    name=existing.name or display_name,
                    target_uid=existing.uid,
                    layer=layer,
                    package=package,
                    outcome=Outcome.UPDATE,
                    command=f"set-{rule_type}",
                    payload=update_payload,
                    diffs=diffs,
                    prior_state=_build_prior_rule_state(existing, rulebase_type=rb_type, layer=layer, package=package),
                    desired_spec=dict(spec),
                    message=f"Update {rule_type} {existing.name or existing.uid!r} ({', '.join(sorted(diffs.keys()))}).",
                )

            # Create new rule with cleanup-rule-aware position resolution
            resolved_pos = resolve_rule_position(
                spec.get("position", "bottom"),
                rules_list,
                sections=paged.sections,
                obj_dict=paged.objects_dictionary,
            )
            add_payload = _build_add_rule_payload(
                rb_type=rb_type,
                spec=spec,
                layer=layer or paged.layer_name,
                package=package or paged.package_name or paged.layer_name,
                position=resolved_pos,
                name_resolutions=res_map,
            )
            return PlannedAction(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                operation="add",
                object_type=rule_type,
                name=req_name or display_name,
                layer=layer,
                package=package,
                outcome=Outcome.CREATE,
                command=f"add-{rule_type}",
                payload=add_payload,
                desired_spec=dict(spec),
                message=f"Create {rule_type} {req_name or display_name!r}.",
            )

        except StateLookupError as exc:
            err_msg = f"{LOOKUP_ERROR_PREFIX}{exc}"
            return PlannedAction(
                action_id=action_id,
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                operation=verb,
                object_type=rule_type,
                name=display_name,
                layer=layer,
                package=package,
                outcome=Outcome.ERROR,
                status="error",
                desired_spec=dict(spec),
                message=err_msg,
                error=err_msg,
            )


def _build_add_object_payload(
    obj_type: str,
    name: str,
    spec: Mapping[str, Any],
) -> dict[str, Any]:
    payload: dict[str, Any] = {"name": name}
    if obj_type == "host":
        ipv4 = spec.get("ipv4_address") or spec.get("ipv4-address") or spec.get("ip_address") or spec.get("ip-address")
        ipv6 = spec.get("ipv6_address") or spec.get("ipv6-address")
        if isinstance(ipv4, str) and ipv4.strip():
            payload["ipv4-address"] = ipv4.strip()
        if isinstance(ipv6, str) and ipv6.strip():
            payload["ipv6-address"] = ipv6.strip()
    elif obj_type == "network":
        sub = spec.get("subnet4") or spec.get("subnet")
        if isinstance(sub, str) and sub.strip():
            payload["subnet4"] = sub.strip()
        mask = normalize_mask_length(
            spec.get("mask_length4") if "mask_length4" in spec else spec.get("mask-length4"),
            spec.get("subnet_mask") or spec.get("subnet-mask"),
        )
        if mask is not None:
            payload["mask-length4"] = mask
    elif obj_type == "address-range":
        first_ip = spec.get("ipv4_address_first") or spec.get("ipv4-address-first")
        last_ip = spec.get("ipv4_address_last") or spec.get("ipv4-address-last")
        if isinstance(first_ip, str) and first_ip.strip():
            payload["ipv4-address-first"] = first_ip.strip()
        if isinstance(last_ip, str) and last_ip.strip():
            payload["ipv4-address-last"] = last_ip.strip()
    elif obj_type == "dns-domain":
        is_sub = spec.get("is_sub_domain") if "is_sub_domain" in spec else spec.get("is-sub-domain")
        payload["is-sub-domain"] = bool(is_sub) if is_sub is not None else False

    if "comments" in spec and spec["comments"] is not None:
        payload["comments"] = str(spec["comments"])
    if "color" in spec and spec["color"] is not None:
        payload["color"] = str(spec["color"])
    if "tags" in spec and isinstance(spec["tags"], list):
        payload["tags"] = [str(t) for t in spec["tags"]]
    nat_s = spec.get("nat_settings") if "nat_settings" in spec else spec.get("nat-settings")
    if isinstance(nat_s, dict):
        payload["nat-settings"] = dict(nat_s)
    return payload


def _build_add_service_payload(
    svc_type: str,
    name: str,
    spec: Mapping[str, Any],
) -> dict[str, Any]:
    payload: dict[str, Any] = {"name": name}
    if spec.get("port") is not None:
        payload["port"] = str(spec["port"]).strip()
    proto = spec.get("protocol") or spec.get("ip_protocol") or spec.get("ip-protocol")
    if proto is not None:
        if svc_type == "service-other":
            payload["ip-protocol"] = proto
        else:
            payload["protocol"] = proto
    icmp_t = spec.get("icmp_type") if "icmp_type" in spec else spec.get("icmp-type")
    if isinstance(icmp_t, int):
        payload["icmp-type"] = icmp_t
    icmp_c = spec.get("icmp_code") if "icmp_code" in spec else spec.get("icmp-code")
    if isinstance(icmp_c, int):
        payload["icmp-code"] = icmp_c
    s_to = spec.get("session_timeout") if "session_timeout" in spec else spec.get("session-timeout")
    if isinstance(s_to, int):
        payload["session-timeout"] = s_to
    mfa = spec.get("match_for_any") if "match_for_any" in spec else spec.get("match-for-any")
    if isinstance(mfa, bool):
        payload["match-for-any"] = mfa
    if "comments" in spec and spec["comments"] is not None:
        payload["comments"] = str(spec["comments"])
    if "color" in spec and spec["color"] is not None:
        payload["color"] = str(spec["color"])
    if "tags" in spec and isinstance(spec["tags"], list):
        payload["tags"] = [str(t) for t in spec["tags"]]
    return payload


def _build_add_group_payload(
    name: str,
    spec: Mapping[str, Any],
    *,
    name_resolutions: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"name": name}
    raw_members = spec.get("members")
    if isinstance(raw_members, list):
        payload["members"] = [resolve_member_reference(str(m), name_resolutions) for m in raw_members]
    elif isinstance(raw_members, dict):
        adds = raw_members.get("add") or []
        payload["members"] = [resolve_member_reference(str(m), name_resolutions) for m in adds]
    if "comments" in spec and spec["comments"] is not None:
        payload["comments"] = str(spec["comments"])
    if "color" in spec and spec["color"] is not None:
        payload["color"] = str(spec["color"])
    if "tags" in spec and isinstance(spec["tags"], list):
        payload["tags"] = [str(t) for t in spec["tags"]]
    return payload


def _build_add_rule_payload(
    *,
    rb_type: RulebaseType,
    spec: Mapping[str, Any],
    layer: str,
    package: str,
    position: str | int | dict[str, str],
    name_resolutions: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"position": position}
    if spec.get("name"):
        payload["name"] = str(spec["name"]).strip()
    if "enabled" in spec and spec["enabled"] is not None:
        payload["enabled"] = bool(spec["enabled"])
    if "comments" in spec and spec["comments"] is not None:
        payload["comments"] = str(spec["comments"])

    if rb_type == "nat":
        payload["package"] = package
        payload["method"] = str(spec.get("method") or "static").strip().lower()
        payload["original-source"] = normalize_nat_traffic_ref(
            spec.get("original_source", spec.get("original-source")),
            is_translated=False,
            name_resolutions=name_resolutions,
        )
        payload["original-destination"] = normalize_nat_traffic_ref(
            spec.get("original_destination", spec.get("original-destination")),
            is_translated=False,
            name_resolutions=name_resolutions,
        )
        payload["original-service"] = normalize_nat_traffic_ref(
            spec.get("original_service", spec.get("original-service")),
            is_translated=False,
            name_resolutions=name_resolutions,
        )
        payload["translated-source"] = normalize_nat_traffic_ref(
            spec.get("translated_source", spec.get("translated-source")),
            is_translated=True,
            name_resolutions=name_resolutions,
        )
        payload["translated-destination"] = normalize_nat_traffic_ref(
            spec.get("translated_destination", spec.get("translated-destination")),
            is_translated=True,
            name_resolutions=name_resolutions,
        )
        payload["translated-service"] = normalize_nat_traffic_ref(
            spec.get("translated_service", spec.get("translated-service")),
            is_translated=True,
            name_resolutions=name_resolutions,
        )
    else:
        payload["layer"] = layer
        payload["source"] = list(normalize_traffic_list(spec.get("source"), name_resolutions=name_resolutions))
        payload["destination"] = list(
            normalize_traffic_list(spec.get("destination"), name_resolutions=name_resolutions)
        )
        payload["service"] = list(normalize_traffic_list(spec.get("service"), name_resolutions=name_resolutions))
        raw_act = spec.get("rule_action")
        if raw_act is None and "action" in spec:
            cand = spec["action"]
            if isinstance(cand, str) and cand.lower() not in ("present", "absent", "add", "set", "update", "delete"):
                raw_act = cand
        payload["action"] = str(raw_act or "Accept").strip()
        if "track" in spec and spec["track"] is not None:
            t_val = spec["track"]
            payload["track"] = {"type": t_val} if isinstance(t_val, str) else t_val

    inst_val = spec.get("install_on") if "install_on" in spec else spec.get("install-on")
    if inst_val is not None:
        payload["install-on"] = list(normalize_traffic_list(inst_val, name_resolutions=name_resolutions))

    return payload


__all__ = [
    "LOOKUP_ERROR_PREFIX",
    "OBJECT_ITEM_TYPES",
    "Planner",
]
