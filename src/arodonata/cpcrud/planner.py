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
from contextlib import suppress
from datetime import datetime
from typing import Any, Protocol

from arodonata.core.errors import ServerIdentityError, ValidationError, redact_sid
from arodonata.core.models.common import parse_cp_publish_timestamp, utc_now
from arodonata.core.ports import ApiPort, ObjectCachePort, ServiceCachePort, SidCachePort, SyncStatePort
from arodonata.core.telemetry import span_attrs, traced
from arodonata.cpcrud._planner_diff import _plan_existing_object_diff, _plan_existing_service_diff
from arodonata.cpcrud._planner_entity_steps import (
    _DomainPlanState,
    _record_action_outcome,
    plan_group_step,
    plan_object_step,
    plan_service_step,
)
from arodonata.cpcrud._planner_helpers import (
    CANONICAL_CPCRUD_TYPES,
    LOOKUP_ERROR_PREFIX,
    RULE_OPERATION_TYPES,
    _build_add_group_payload,
    _build_add_object_payload,
    _build_add_rule_payload,
    _build_add_service_payload,
    _build_prior_object_state,
    _build_prior_rule_state,
    _build_prior_service_state,
    _extract_add_url_list,
    _extract_group_references,
    _extract_rule_references,
    _make_error_action,
    _normalize_verb,
    _resolve_rulebase_type,
)
from arodonata.cpcrud._planner_rule_steps import plan_rule_step
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
from arodonata.cpcrud.state_reader import OBJECT_ITEM_TYPES, SERVICE_ITEM_TYPES, HybridStateReader


class _PlannerCachePort(ObjectCachePort, ServiceCachePort, SidCachePort, SyncStatePort, Protocol):
    """Cache capabilities required by `Planner` and its internal `HybridStateReader`."""


def _resolve_domain_name(mapping: Mapping[str, Any], default: str = "") -> str:
    """Resolve `domain` / `domain_name` safely, falling back to `default` when `None` or blank."""
    raw = mapping.get("domain") or mapping.get("domain_name") or default
    return str(raw).strip() if raw is not None else ""


class Planner:
    """Declarative CPCRUD planner producing deterministic, idempotent `Plan` objects."""

    def __init__(
        self,
        *,
        api: ApiPort,
        cache: _PlannerCachePort,
        default_mgmt_name: str | None = None,
        default_naming_prefixes: NamingPrefixes | None = None,
        now_fn: Callable[[], datetime] = utc_now,
    ) -> None:
        self._api = api
        self._cache = cache
        self._default_mgmt_name = default_mgmt_name or ""
        self._default_naming_prefixes = default_naming_prefixes or NamingPrefixes()
        self._now = now_fn

    async def _collect_known_sids(self, mgmt_name: str) -> list[str]:
        """Collect cached and active SIDs for `mgmt_name` so `redact_sid` can scrub non-header tokens."""
        sids: list[str] = []
        with suppress(Exception):
            rows = await self._cache.list_sids(mgmt_name=mgmt_name)
            for row in rows:
                if row.sid:
                    sids.append(row.sid)
        with suppress(Exception):
            active = getattr(self._api, "active_sids", None)
            if callable(active):
                sids.extend(s for s in active(mgmt_name) if s)
            elif isinstance(active, (list, tuple, set)):
                sids.extend(str(s) for s in active if s)
        return sids

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
            known_sids = await self._collect_known_sids(mgmt_name)
            return DomainStamp(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                readable=False,
                error=redact_sid(str(exc), known_sids=known_sids),
                captured_at=self._now(),
            )

        if not res.success:
            err_msg = res.error_message or res.error_code or f"HTTP {res.status_code}"
            known_sids = await self._collect_known_sids(mgmt_name)
            return DomainStamp(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                readable=False,
                error=redact_sid(err_msg, known_sids=known_sids),
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
        root_domain = _resolve_domain_name(template)
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
                        "domain_name": _resolve_domain_name(item, root_domain),
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
        raw_operations = target.get("operations")
        if isinstance(raw_operations, list) and raw_operations:
            for op in raw_operations:
                if not isinstance(op, dict):
                    continue
                op_type = str(op.get("type") or "").strip().lower()
                if op_type and op_type not in CANONICAL_CPCRUD_TYPES:
                    raise ValidationError(f"Unsupported CPCRUD operation type: {op_type!r}")
                if op_type in RULE_OPERATION_TYPES or "layer" in op or "package" in op:
                    steps.append(("rule", dict(op)))
                elif op_type in ("group", "service-group"):
                    steps.append(("group", dict(op)))
                elif op_type in SERVICE_ITEM_TYPES:
                    steps.append(("service", dict(op)))
                else:
                    if not op_type:
                        raise ValidationError("CPCRUD operation is missing a required 'type' field.")
                    steps.append(("object", dict(op)))
            return steps

        for obj in target.get("objects") or []:
            if isinstance(obj, dict):
                o_type = str(obj.get("type") or "host").strip().lower()
                if o_type not in OBJECT_ITEM_TYPES:
                    raise ValidationError(f"Unsupported CPCRUD object type: {o_type!r}")
                steps.append(("group" if o_type == "group" else "object", dict(obj)))
        for svc in target.get("services") or []:
            if isinstance(svc, dict):
                s_type = str(svc.get("type") or "service-tcp").strip().lower()
                if s_type == "application-site":
                    steps.append(("object", dict(svc)))
                    continue
                if s_type not in SERVICE_ITEM_TYPES:
                    raise ValidationError(f"Unsupported CPCRUD service type: {s_type!r}")
                steps.append(("group" if s_type == "service-group" else "service", dict(svc)))
        for grp in target.get("groups") or []:
            if isinstance(grp, dict):
                g_type = str(grp.get("type") or "group").strip().lower()
                if g_type not in ("group", "service-group"):
                    raise ValidationError(f"Unsupported CPCRUD group type: {g_type!r}")
                steps.append(("group", dict(grp)))
        for rule in target.get("rules") or []:
            if isinstance(rule, dict):
                _resolve_rulebase_type(rule)
                steps.append(("rule", dict(rule)))
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

        # 1. Discover all unique (mgmt_name, domain_name) pairs across targets and cache ordered steps
        domain_pairs: list[tuple[str, str]] = []
        seen_pairs: set[tuple[str, str]] = set()
        seen_explicit_ids: set[str] = set()
        steps_by_target: list[list[tuple[str, dict[str, Any]]]] = []
        for t in targets:
            t_mgmt = str(t.get("mgmt_name") or self._default_mgmt_name).strip()
            t_dom = str(t.get("domain_name") or "").strip()
            steps = self._collect_ordered_steps(t)
            steps_by_target.append(steps)
            if not steps and (t_mgmt, t_dom) not in seen_pairs:
                seen_pairs.add((t_mgmt, t_dom))
                domain_pairs.append((t_mgmt, t_dom))
            for _kind, step_spec in steps:
                if "id" in step_spec and step_spec["id"] is not None:
                    explicit_id = step_spec["id"]
                    if not isinstance(explicit_id, str) or not explicit_id.strip():
                        raise ValidationError("CPCRUD operation 'id' must be a non-empty string.")
                    id_str = explicit_id.strip()
                    if id_str in seen_explicit_ids:
                        raise ValidationError(f"Duplicate CPCRUD operation id: {id_str!r}")
                    seen_explicit_ids.add(id_str)
                s_mgmt = str(step_spec.get("mgmt_name") or t_mgmt).strip()
                s_dom = _resolve_domain_name(step_spec, t_dom)
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
        domain_states: dict[tuple[str, str], _DomainPlanState] = {}
        action_seq = 0

        for target_idx, t in enumerate(targets):
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
                eff_prefixes = NamingPrefixes.from_mapping(dict(naming_prefixes), base=self._default_naming_prefixes)
            elif t.get("naming_prefixes"):
                eff_prefixes = NamingPrefixes.from_mapping(t.get("naming_prefixes"), base=self._default_naming_prefixes)
            else:
                eff_prefixes = self._default_naming_prefixes

            steps = steps_by_target[target_idx]
            for kind, step_spec in steps:
                raw_explicit_id = step_spec.get("id")
                if raw_explicit_id is not None:
                    action_id = str(raw_explicit_id).strip()
                else:
                    while True:
                        action_seq += 1
                        cand_id = f"act-{action_seq}"
                        if cand_id not in seen_explicit_ids:
                            action_id = cand_id
                            seen_explicit_ids.add(cand_id)
                            break
                s_mgmt = str(step_spec.get("mgmt_name") or t_mgmt).strip()
                s_dom = _resolve_domain_name(step_spec, t_dom)
                dom_key = (s_mgmt, s_dom)
                step_stamp = domain_stamps.get(f"{s_mgmt}:{s_dom}")

                policy = ConflictPolicy(
                    on_name_conflict=step_spec.get("on_name_conflict") or eff_name_pol,
                    on_ip_conflict=step_spec.get("on_ip_conflict") or eff_ip_pol,
                )

                dom_state = domain_states.setdefault(dom_key, _DomainPlanState())
                failed_refs = dom_state.failed_refs
                failed_ids = dom_state.failed_ids
                res_map = dom_state.res_map

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
                    _record_action_outcome(act, dom_state)
                    continue

                explicit_deps = [str(d) for d in (step_spec.get("depends_on") or []) if str(d)]
                broken_deps = [d for d in explicit_deps if d in failed_ids or d in failed_refs]
                step_refs: set[str] = set()
                if kind == "group":
                    step_refs = _extract_group_references(step_spec)
                    broken_deps.extend(sorted(r for r in step_refs if r in failed_refs))
                elif kind == "rule":
                    step_refs = _extract_rule_references(step_spec)
                    broken_deps.extend(sorted(r for r in step_refs if r in failed_refs))

                ref_action_ids = dom_state.ref_action_ids
                entity_action_ids = dom_state.entity_action_ids
                inferred_deps: list[str] = []
                for ref in sorted(step_refs):
                    resolved_ref = res_map.get(ref, ref)
                    for cand in (ref, resolved_ref):
                        aid = ref_action_ids.get(cand)
                        if aid and aid not in inferred_deps:
                            inferred_deps.append(aid)

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
                    _record_action_outcome(act, dom_state)
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

                if kind in ("object", "service", "group", "rule"):
                    scope_prefix = (
                        f"{act.layer or act.package}:" if kind == "rule" and (act.layer or act.package) else ""
                    )
                    if act.outcome in (Outcome.UPDATE, Outcome.DELETE):
                        dep_cands = [
                            entity_action_ids.get(("uid", act.target_uid)) if act.target_uid else None,
                            entity_action_ids.get((act.object_type, f"{scope_prefix}{act.name}")) if act.name else None,
                            entity_action_ids.get((act.object_type, act.name))
                            if act.name and not scope_prefix
                            else None,
                            entity_action_ids.get((act.object_type, f"{scope_prefix}{act.requested_name}"))
                            if act.requested_name
                            else None,
                            entity_action_ids.get((act.object_type, act.requested_name))
                            if act.requested_name and not scope_prefix
                            else None,
                        ]
                        for aid in dep_cands:
                            if aid and aid != act.action_id and aid not in inferred_deps:
                                inferred_deps.append(aid)
                    elif act.outcome == Outcome.CREATE and act.name:
                        prev_aid = entity_action_ids.get((act.object_type, f"{scope_prefix}{act.name}")) or (
                            entity_action_ids.get((act.object_type, act.name)) if not scope_prefix else None
                        )
                        if prev_aid and prev_aid != act.action_id and prev_aid not in inferred_deps:
                            inferred_deps.append(prev_aid)

                merged_deps = list(dict.fromkeys([*explicit_deps, *inferred_deps, *act.depends_on]))
                if merged_deps and merged_deps != act.depends_on:
                    act = act.model_copy(update={"depends_on": merged_deps})

                actions.append(act)
                _record_action_outcome(act, dom_state)

        final_action_ids = [a.action_id for a in actions]
        if len(set(final_action_ids)) != len(final_action_ids):
            raise ValidationError("Duplicate action_id detected while building CPCRUD Plan.")

        global_name_resolutions = {
            k: v for dom_state in domain_states.values() for k, v in dom_state.global_res.items()
        }
        return Plan(
            created_at=self._now(),
            domain_stamps=domain_stamps,
            actions=actions,
            name_resolutions=global_name_resolutions,
            template=dict(template),
        )

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
        return await plan_object_step(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            spec=spec,
            policy=policy,
            prefixes=prefixes,
            reader=reader,
            res_map=res_map,
            collect_known_sids=self._collect_known_sids,
        )

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
        return await plan_service_step(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            spec=spec,
            policy=policy,
            prefixes=prefixes,
            reader=reader,
            res_map=res_map,
            collect_known_sids=self._collect_known_sids,
        )

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
        return await plan_group_step(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            spec=spec,
            policy=policy,
            reader=reader,
            res_map=res_map,
            collect_known_sids=self._collect_known_sids,
        )

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
        return await plan_rule_step(
            action_id=action_id,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            spec=spec,
            policy=policy,
            reader=reader,
            res_map=res_map,
            collect_known_sids=self._collect_known_sids,
        )


__all__ = [
    "CANONICAL_CPCRUD_TYPES",
    "LOOKUP_ERROR_PREFIX",
    "OBJECT_ITEM_TYPES",
    "Planner",
    "RULE_OPERATION_TYPES",
    "_PlannerCachePort",
    "_build_add_group_payload",
    "_build_add_object_payload",
    "_build_add_rule_payload",
    "_build_add_service_payload",
    "_build_prior_object_state",
    "_build_prior_rule_state",
    "_build_prior_service_state",
    "_extract_add_url_list",
    "_extract_group_references",
    "_extract_rule_references",
    "_make_error_action",
    "_normalize_verb",
    "_plan_existing_object_diff",
    "_plan_existing_service_diff",
    "_resolve_rulebase_type",
]
