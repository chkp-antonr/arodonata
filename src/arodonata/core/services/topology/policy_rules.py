"""Policy package snapshot loading, gateway policy metadata resolution, rule expansion, and one-arm checks."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from typing import Protocol

from arodonata.core.context import get_write_session
from arodonata.core.errors import ServerIdentityError, redact_sid
from arodonata.core.models.assets import Asset
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import DomainRulebaseSnapshot, extract_policy_packages
from arodonata.core.models.sentinels import ANY_RULE_TOKENS, ORIGINAL_NAT_TOKENS, POLICY_TARGETS_TOKENS
from arodonata.core.models.topology import LIVE_ROUTE_SOURCES, GatewayTopologyEntry
from arodonata.core.ports import RulebaseCachePort, RulebaseRefreshPort, SyncStatePort
from arodonata.core.primitives import MAX_IPV4_INT
from arodonata.core.services.topology._shared import (
    _ExpandedPolicyRule,
    _NormalizedInterface,
    _ResolvedEndpointInterval,
    logger,
)
from arodonata.core.services.topology.normalizer import (
    _extract_policy_candidates_from_raw,
    _extract_timestamp_posix,
    _normalize_gateway_interfaces,
)
from arodonata.core.services.topology.scoring import _resolve_endpoint_intervals


class _PackageSnapshotCachePort(RulebaseCachePort, SyncStatePort, Protocol):
    """Cache capabilities required to read rulebase package snapshots and sync states."""


async def _load_domain_package_snapshot(
    cache: _PackageSnapshotCachePort,
    rulebase_refresh: RulebaseRefreshPort | None,
    mgmt_name: str,
    domain_name: str,
    *,
    allow_refresh: bool = False,
    cache_ttl: float | None = None,
) -> DomainRulebaseSnapshot:
    """Load lightweight rulebase package metadata without reading rule tables, refreshing `show-packages` if cold."""
    snap = await cache.get_domain_rulebase_packages(mgmt_name, domain_name)
    if snap.package_layers or not allow_refresh:
        return snap
    full_st = await cache.get_sync_state(mgmt_name, domain_name, "rulebase", "*")
    pkg_st = await cache.get_sync_state(mgmt_name, domain_name, "rulebase", "packages")
    if (full_st is not None and full_st.status == "ok") or (pkg_st is not None and pkg_st.status == "ok"):
        return snap
    if rulebase_refresh is None:
        logger.warning(
            f"Skipping lazy show-packages refresh during topology extraction on {mgmt_name}:{domain_name}: "
            "TopologyService was initialized without rulebase_refresh (RulebaseRefreshPort).",
            mgmt_name=mgmt_name,
            domain_name=domain_name,
        )
        return snap
    try:
        await rulebase_refresh.refresh_policy_packages(
            mgmt_name=mgmt_name,
            domains=[domain_name],
            include_global=(domain_name == "Global"),
            mode="smart",
            cache_ttl=cache_ttl,
        )
        snap = await cache.get_domain_rulebase_packages(mgmt_name, domain_name)
    except ServerIdentityError:
        raise
    except Exception as exc:
        active_ws = get_write_session(mgmt_name=mgmt_name, domain_name=domain_name)
        known_sids = [active_ws.sid] if active_ws is not None and active_ws.sid else None
        logger.debug(
            f"Lightweight package refresh skipped during topology extraction on {mgmt_name}:{domain_name}: "
            f"{redact_sid(str(exc), known_sids=known_sids)}",
            mgmt_name=mgmt_name,
            domain_name=domain_name,
        )
    return snap


async def _resolve_gateway_policy_metadata(
    cache: _PackageSnapshotCachePort,
    rulebase_refresh: RulebaseRefreshPort | None,
    mgmt_name: str,
    domain_name: str,
    asset: Asset | None,
    gateway_uid: str,
    gateway_name: str,
    all_assets: Sequence[Asset] | None = None,
    *,
    snapshot: DomainRulebaseSnapshot | None = None,
) -> tuple[str | None, list[str], list[str]]:
    """Resolve `(installed_access_policy, policy_packages, access_layers)` for a single gateway/cluster."""
    candidates: list[tuple[int, int, str]] = []
    if asset is not None:
        candidates.extend(_extract_policy_candidates_from_raw(asset.raw_data, priority=2))
        if all_assets:
            member_uid_set = set(asset.member_uids)
            member_asset_id_set = set(asset.member_asset_ids)
            for other in all_assets:
                if other.uid == asset.uid:
                    continue
                if (
                    other.uid in member_uid_set
                    or other.asset_id in member_asset_id_set
                    or other.parent_uid == asset.uid
                    or other.parent_id == asset.id
                    or other.parent_asset_id == asset.asset_id
                ):
                    candidates.extend(_extract_policy_candidates_from_raw(other.raw_data, priority=1))

    installed_policy: str | None = None
    if candidates:
        best = max(candidates, key=lambda item: (item[0], item[1]))
        installed_policy = best[2]

    eff_snapshot = (
        snapshot
        if snapshot is not None
        else await _load_domain_package_snapshot(cache, rulebase_refresh, mgmt_name, domain_name)
    )
    packages = extract_policy_packages(eff_snapshot) if (eff_snapshot.package_layers or eff_snapshot.nat_rules) else []

    # Fallback when gateway/cluster asset does not report an installed policy:
    # match ONLY explicit non-"all" gateway installation-targets (or a single-package domain).
    if not installed_policy and packages:
        gw_tokens = {gateway_uid.lower(), gateway_name.lower()}
        if asset is not None:
            gw_tokens.add(asset.id.lower())
            gw_tokens.add(asset.asset_id.lower())

        explicit_matches = []
        for pkg in packages:
            targets = pkg.raw_data.get("installation-targets") or pkg.raw_data.get("installation_targets")
            if isinstance(targets, list):
                for t in targets:
                    if isinstance(t, str) and t.strip().lower() in gw_tokens:
                        explicit_matches.append(pkg)
                        break
                    if isinstance(t, dict):
                        t_uid = str(t.get("uid") or "").lower()
                        t_name = str(t.get("name") or "").lower()
                        if (t_uid and t_uid in gw_tokens) or (t_name and t_name in gw_tokens):
                            explicit_matches.append(pkg)
                            break

        if explicit_matches:
            best_pkg = max(
                explicit_matches,
                key=lambda p: (
                    _extract_timestamp_posix(
                        p.raw_data.get("meta-info", {}).get("last-modify-time")
                        if isinstance(p.raw_data.get("meta-info"), dict)
                        else None
                    ),
                    p.updated_at,
                ),
            )
            installed_policy = best_pkg.name
        elif len(packages) == 1:
            installed_policy = packages[0].name

    policy_packages: list[str] = [installed_policy] if installed_policy else []
    access_layers: list[str] = []

    if installed_policy and packages:
        for pkg in packages:
            if pkg.name.lower() == installed_policy.lower():
                installed_policy = pkg.name
                policy_packages = [pkg.name]
                for layer_entry in pkg.access_layers:
                    if layer_entry.layer_name not in access_layers:
                        access_layers.append(layer_entry.layer_name)
                break

    return installed_policy, policy_packages, access_layers


def _is_explicit_rule_terms(terms: Sequence[str]) -> list[str]:
    """Return non-empty explicit (non-`Any`) rule endpoint references, or `[]` if any term is `Any`."""
    cleaned: list[str] = []
    for t in terms:
        val = str(t).strip()
        if not val:
            continue
        if val.lower() in ANY_RULE_TOKENS:
            return []
        cleaned.append(val)
    return cleaned


def _normalize_install_on_tokens(
    install_on: Sequence[str],
    *,
    assets_by_uid: dict[str, Asset],
    obj_by_uid: dict[str, CPObject],
) -> tuple[frozenset[str], bool]:
    """Normalize `install_on` strings into `(lowercase_tokens, is_gateway_specific_target)`."""
    if not install_on:
        return frozenset(), False
    tokens: set[str] = set()
    has_generic = False
    for item in install_on:
        clean = str(item).strip()
        if not clean:
            continue
        lower_val = clean.lower()
        if lower_val in POLICY_TARGETS_TOKENS:
            has_generic = True
            continue
        tokens.add(lower_val)
        matched_asset = assets_by_uid.get(clean)
        if matched_asset is not None:
            tokens.add(matched_asset.uid.lower())
            tokens.add(matched_asset.name.lower())
            tokens.add(matched_asset.id.lower())
            tokens.add(matched_asset.asset_id.lower())
        matched_obj = obj_by_uid.get(clean)
        if matched_obj is not None:
            tokens.add(matched_obj.uid.lower())
            tokens.add(matched_obj.name.lower())
    is_specific = bool(tokens) and not has_generic
    return frozenset(tokens), is_specific


def _build_layer_package_map(snapshot: DomainRulebaseSnapshot) -> dict[str, set[str]]:
    """Map each access layer (including inline/placeholder sub-layers) to its owning policy package(s)."""
    layer_to_packages: dict[str, set[str]] = defaultdict(set)
    for pl in snapshot.package_layers:
        if pl.rulebase_type == "access" and pl.package_name:
            layer_to_packages[pl.layer_uid].add(pl.package_name.lower())
            layer_to_packages[pl.layer_name.lower()].add(pl.package_name.lower())

    changed = True
    while changed:
        changed = False
        for ar in snapshot.access_rules:
            parent_pkgs = set(layer_to_packages.get(ar.layer_uid, set())) | set(
                layer_to_packages.get(ar.layer_name.lower(), set())
            )
            if not parent_pkgs:
                continue
            for child_layer in (
                ar.inline_layer_uid,
                ar.inline_layer_name.lower() if ar.inline_layer_name else None,
                ar.placeholder_domain_layer_uid,
            ):
                if child_layer and not parent_pkgs.issubset(layer_to_packages[child_layer]):
                    layer_to_packages[child_layer].update(parent_pkgs)
                    changed = True
    return layer_to_packages


def _resolve_non_any_intervals(
    terms: Sequence[str],
    *,
    obj_by_uid: dict[str, CPObject],
    obj_by_name: dict[str, CPObject],
) -> list[_ResolvedEndpointInterval]:
    return [
        ep
        for ep in _resolve_endpoint_intervals(terms, obj_by_uid=obj_by_uid, obj_by_name=obj_by_name)
        if not (ep.ip_first_int == 0 and ep.ip_last_int == MAX_IPV4_INT)
    ]


def _expand_access_rules(
    snapshot: DomainRulebaseSnapshot,
    *,
    layer_to_packages: dict[str, set[str]],
    assets_by_uid: dict[str, Asset],
    obj_by_uid: dict[str, CPObject],
    obj_by_name: dict[str, CPObject],
    for_reconciliation: bool,
) -> list[_ExpandedPolicyRule]:
    expanded_rules: list[_ExpandedPolicyRule] = []
    for ar in snapshot.access_rules:
        if not ar.enabled or ar.source_negate or ar.destination_negate:
            continue
        if ar.rule_type == "place-holder":
            continue
        if not for_reconciliation:
            action_lower = (ar.action or "").strip().lower()
            if action_lower in ("drop", "reject", "block", "inactive"):
                continue

        src_terms = _is_explicit_rule_terms(ar.source)
        dst_terms = _is_explicit_rule_terms(ar.destination)
        if for_reconciliation:
            if not src_terms and not dst_terms:
                continue
        elif not src_terms or not dst_terms:
            continue

        src_eps = (
            _resolve_non_any_intervals(src_terms, obj_by_uid=obj_by_uid, obj_by_name=obj_by_name) if src_terms else []
        )
        dst_eps = (
            _resolve_non_any_intervals(dst_terms, obj_by_uid=obj_by_uid, obj_by_name=obj_by_name) if dst_terms else []
        )
        if for_reconciliation:
            if not src_eps and not dst_eps:
                continue
        elif not src_eps or not dst_eps:
            continue

        pkgs = sorted(
            set(layer_to_packages.get(ar.layer_uid, set())) | set(layer_to_packages.get(ar.layer_name.lower(), set()))
        )
        install_tokens, is_specific = _normalize_install_on_tokens(
            ar.install_on,
            assets_by_uid=assets_by_uid,
            obj_by_uid=obj_by_uid,
        )
        label = ar.name or (f"rule#{ar.rule_number}" if ar.rule_number else ar.uid)
        expanded_rules.append(
            _ExpandedPolicyRule(
                rule_kind="access_rule",
                rule_uid=ar.uid,
                rule_label=label,
                package_names=tuple(pkgs),
                install_on_tokens=install_tokens,
                is_gateway_specific_target=is_specific,
                source_intervals=tuple(src_eps),
                destination_intervals=tuple(dst_eps),
            )
        )
    return expanded_rules


def _expand_nat_rules(
    snapshot: DomainRulebaseSnapshot,
    *,
    assets_by_uid: dict[str, Asset],
    obj_by_uid: dict[str, CPObject],
    obj_by_name: dict[str, CPObject],
    for_reconciliation: bool,
) -> list[_ExpandedPolicyRule]:
    expanded_rules: list[_ExpandedPolicyRule] = []
    for nr in snapshot.nat_rules:
        if not nr.enabled:
            continue
        install_tokens, is_specific = _normalize_install_on_tokens(
            nr.install_on,
            assets_by_uid=assets_by_uid,
            obj_by_uid=obj_by_uid,
        )
        pkg_tuple = (nr.package_name.lower(),) if nr.package_name else ()
        label = nr.name or (f"nat#{nr.rule_number}" if nr.rule_number else nr.uid)

        orig_src_raw = (nr.original_source or "").strip()
        orig_dst_raw = (nr.original_destination or "").strip()
        xlate_src_raw = (nr.translated_source or "").strip()
        xlate_dst_raw = (nr.translated_destination or "").strip()

        eff_xlate_src = (
            orig_src_raw if (not xlate_src_raw or xlate_src_raw.lower() in ORIGINAL_NAT_TOKENS) else xlate_src_raw
        )
        eff_xlate_dst = (
            orig_dst_raw if (not xlate_dst_raw or xlate_dst_raw.lower() in ORIGINAL_NAT_TOKENS) else xlate_dst_raw
        )

        if for_reconciliation:
            reconcile_src_eps: list[_ResolvedEndpointInterval] = []
            reconcile_dst_eps: list[_ResolvedEndpointInterval] = []
            for cand_src in dict.fromkeys([orig_src_raw, eff_xlate_src]):
                s_terms = _is_explicit_rule_terms([cand_src])
                if s_terms:
                    for ep in _resolve_non_any_intervals(s_terms, obj_by_uid=obj_by_uid, obj_by_name=obj_by_name):
                        if ep not in reconcile_src_eps:
                            reconcile_src_eps.append(ep)
            for cand_dst in dict.fromkeys([orig_dst_raw, eff_xlate_dst]):
                d_terms = _is_explicit_rule_terms([cand_dst])
                if d_terms:
                    for ep in _resolve_non_any_intervals(d_terms, obj_by_uid=obj_by_uid, obj_by_name=obj_by_name):
                        if ep not in reconcile_dst_eps:
                            reconcile_dst_eps.append(ep)
            if not reconcile_src_eps and not reconcile_dst_eps:
                continue
            expanded_rules.append(
                _ExpandedPolicyRule(
                    rule_kind="nat_rule",
                    rule_uid=nr.uid,
                    rule_label=label,
                    package_names=pkg_tuple,
                    install_on_tokens=install_tokens,
                    is_gateway_specific_target=is_specific,
                    source_intervals=tuple(reconcile_src_eps),
                    destination_intervals=tuple(reconcile_dst_eps),
                )
            )
            continue

        candidate_pairs: list[tuple[str, str]] = []
        if orig_src_raw and orig_dst_raw:
            candidate_pairs.append((orig_src_raw, orig_dst_raw))
        if eff_xlate_src and eff_xlate_dst and (eff_xlate_src, eff_xlate_dst) not in candidate_pairs:
            candidate_pairs.append((eff_xlate_src, eff_xlate_dst))

        for pair_src, pair_dst in candidate_pairs:
            src_terms = _is_explicit_rule_terms([pair_src])
            dst_terms = _is_explicit_rule_terms([pair_dst])
            if not src_terms or not dst_terms:
                continue
            src_eps = _resolve_non_any_intervals(src_terms, obj_by_uid=obj_by_uid, obj_by_name=obj_by_name)
            dst_eps = _resolve_non_any_intervals(dst_terms, obj_by_uid=obj_by_uid, obj_by_name=obj_by_name)
            if not src_eps or not dst_eps:
                continue
            expanded_rules.append(
                _ExpandedPolicyRule(
                    rule_kind="nat_rule",
                    rule_uid=nr.uid,
                    rule_label=label,
                    package_names=pkg_tuple,
                    install_on_tokens=install_tokens,
                    is_gateway_specific_target=is_specific,
                    source_intervals=tuple(src_eps),
                    destination_intervals=tuple(dst_eps),
                )
            )
    return expanded_rules


def _expand_domain_policy_rules(
    snapshot: DomainRulebaseSnapshot,
    *,
    domain_assets: Sequence[Asset],
    obj_by_uid: dict[str, CPObject],
    obj_by_name: dict[str, CPObject],
    for_reconciliation: bool = False,
) -> list[_ExpandedPolicyRule]:
    """Expand active explicit Access and NAT rules from `snapshot` into `_ExpandedPolicyRule` items.

    When `for_reconciliation=True`:
    - Includes rules that have at least one explicit (non-`Any`) side (`source` OR `destination`).
    - Includes enabled Access rules regardless of action (`Accept`, `Drop`, `Reject`, etc.).
    - Aggregates all explicit intervals (`original` and `translated`) of a NAT rule into a single `_ExpandedPolicyRule`
      so inbound/outbound NAT rules that overlap internal topology on either side are not falsely flagged.
    """
    if not snapshot.access_rules and not snapshot.nat_rules:
        return []

    assets_by_uid = {a.uid: a for a in domain_assets}
    layer_to_packages = _build_layer_package_map(snapshot)
    expanded_access = _expand_access_rules(
        snapshot,
        layer_to_packages=layer_to_packages,
        assets_by_uid=assets_by_uid,
        obj_by_uid=obj_by_uid,
        obj_by_name=obj_by_name,
        for_reconciliation=for_reconciliation,
    )
    expanded_nat = _expand_nat_rules(
        snapshot,
        assets_by_uid=assets_by_uid,
        obj_by_uid=obj_by_uid,
        obj_by_name=obj_by_name,
        for_reconciliation=for_reconciliation,
    )
    return [*expanded_access, *expanded_nat]


def _filter_rules_for_gateway(
    domain_rules: Sequence[_ExpandedPolicyRule],
    *,
    gateway_uid: str,
    gateway_name: str,
    gateway_id: str,
    gateway_asset_id: str,
    installed_policy: str | None,
    policy_packages: Sequence[str],
    require_gateway_specific_install_on: bool = False,
) -> list[_ExpandedPolicyRule]:
    """Return the subset of `domain_rules` applicable to the target gateway."""
    gw_tokens = {
        gateway_uid.lower(),
        gateway_name.lower(),
        gateway_id.lower(),
        gateway_asset_id.lower(),
    }
    gw_pkgs = {p.lower() for p in policy_packages if p}
    if installed_policy:
        gw_pkgs.add(installed_policy.lower())

    matched: list[_ExpandedPolicyRule] = []
    for rule in domain_rules:
        if require_gateway_specific_install_on:
            if not rule.is_gateway_specific_target:
                continue
            if not (rule.install_on_tokens & gw_tokens):
                continue
            if rule.package_names and gw_pkgs and not (set(rule.package_names) & gw_pkgs):
                continue
            matched.append(rule)
            continue

        if rule.is_gateway_specific_target:
            if not (rule.install_on_tokens & gw_tokens):
                continue
            if rule.package_names and gw_pkgs and not (set(rule.package_names) & gw_pkgs):
                continue
            matched.append(rule)
        else:
            # Rule has generic/empty install_on -> applies only if its package is installed on this gateway
            if gw_pkgs and rule.package_names and (set(rule.package_names) & gw_pkgs):
                matched.append(rule)

    return matched


def _match_endpoints_against_policy_rules(
    src_ep: _ResolvedEndpointInterval,
    dst_ep: _ResolvedEndpointInterval,
    gw_rules: Sequence[_ExpandedPolicyRule],
) -> tuple[_ExpandedPolicyRule, _ResolvedEndpointInterval, _ResolvedEndpointInterval] | None:
    """Return `(rule, matched_rule_src_ep, matched_rule_dst_ep)` if any rule covers `(src_ep, dst_ep)`."""
    s_lo, s_hi = src_ep.ip_first_int, src_ep.ip_last_int
    d_lo, d_hi = dst_ep.ip_first_int, dst_ep.ip_last_int
    for rule in gw_rules:
        matched_s: _ResolvedEndpointInterval | None = None
        for r_src in rule.source_intervals:
            if not (r_src.ip_last_int < s_lo or r_src.ip_first_int > s_hi):
                matched_s = r_src
                break
        if matched_s is None:
            continue
        matched_d: _ResolvedEndpointInterval | None = None
        for r_dst in rule.destination_intervals:
            if not (r_dst.ip_last_int < d_lo or r_dst.ip_first_int > d_hi):
                matched_d = r_dst
                break
        if matched_d is not None:
            return rule, matched_s, matched_d
    return None


def _is_one_arm_or_incomplete_topology_gateway(
    gw_asset: Asset | None,
    gw_entries: Sequence[GatewayTopologyEntry],
    *,
    norm_ifs: Sequence[_NormalizedInterface] | None = None,
) -> bool:
    """Return `True` if `gw_asset` is a one-arm / external-only gateway or has incomplete interface topology."""
    internal_entries = [e for e in gw_entries if e.topology_zone == "internal"]
    if not internal_entries:
        return True
    distinct_ifs = {e.interface_name for e in gw_entries}
    if len(distinct_ifs) <= 1:
        return True
    if gw_asset is None:
        return False

    eff_norm_ifs = list(norm_ifs) if norm_ifs is not None else _normalize_gateway_interfaces(gw_asset)
    if len(eff_norm_ifs) <= 1 or not any(not n.is_external for n in eff_norm_ifs):
        return True

    entries_by_if: dict[str, list[GatewayTopologyEntry]] = defaultdict(list)
    for e in gw_entries:
        entries_by_if[e.interface_name].append(e)

    for nif in eff_norm_ifs:
        if nif.is_external:
            continue
        mode_lower = nif.behind_mode.lower()
        if_entries = entries_by_if.get(nif.interface_name, [])
        has_routes = any(
            (e.source_type in LIVE_ROUTE_SOURCES and e.source_type != "connected_route")
            or e.source_type == "vs_static_route"
            for e in if_entries
        )
        if ("routing" in mode_lower or not mode_lower or "not defined" in mode_lower) and not has_routes:
            return True
    return False
