"""Rulebase placement numbering (`arodonata.reports.placement`) for session change reports.

Numbers added, modified, moved, and deleted rules according to SmartConsole hierarchy:
1. When a matching unpublished `OwnedSession` (`sid`, `server_ip`) is supplied:
   - Verifies session ownership and unpublished state via read-only `show-session`.
   - Reads `show-packages` and `show-*-rulebase` using that SID strictly read-only
     (never calling `publish`, `discard`, or `logout`).
   - Labels the session `"Numbering read live in the owned session at <time> UTC"`.
   - Scrubs any occurrence of the SID from warnings, errors, and raw responses.
2. When no `OwnedSession` is supplied, or the `OwnedSession` is already published / fails:
   - Records an `owned_session_not_used` or `owned_session_error` `ReportWarning`.
   - Falls back to numbering from the domain's cached rulebase snapshot (`CachePort.get_domain_rulebase`).
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from datetime import UTC, datetime

from arodonata.core.errors import ServerIdentityError, redact_sid
from arodonata.core.models.common import utc_now
from arodonata.core.models.rulebase import DomainRulebaseSnapshot
from arodonata.core.ports import ApiPort, CachePort
from arodonata.core.telemetry import span_attrs, traced
from arodonata.reports.models import (
    OwnedSession,
    ReportWarning,
    RuleChangeEntry,
    SessionChangeReport,
)
from arodonata.rulebase.models import RuleLocation
from arodonata.rulebase.numbering import locate_rules_in_snapshot
from arodonata.rulebase.refresh import collect_domain_rulebase_snapshot


def _format_utc_timestamp(dt: datetime) -> str:
    utc_dt = dt.astimezone(UTC) if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
    return utc_dt.strftime("%Y-%m-%d %H:%M:%S")


def _snapshot_has_rules_or_layers(snapshot: DomainRulebaseSnapshot) -> bool:
    return bool(
        snapshot.access_rules or snapshot.nat_rules or snapshot.https_rules or snapshot.threat_rules or snapshot.layers
    )


def _apply_snapshot_locations_to_rules(
    rule_changes: list[RuleChangeEntry],
    snapshot: DomainRulebaseSnapshot,
) -> None:
    """Assign SmartConsole hierarchical numbers and section info from `snapshot` onto `rule_changes`."""
    if not rule_changes:
        return

    all_rule_uids = [rc.uid for rc in rule_changes if rc.uid]
    all_layer_uids = [rc.layer_uid for rc in rule_changes if rc.layer_uid]
    locations = locate_rules_in_snapshot(
        snapshot,
        rule_uids=all_rule_uids,
        layer_uids=all_layer_uids,
    )

    for rc in rule_changes:
        matched_locs: list[RuleLocation] = locations.rule_locations.get(rc.uid, [])
        if matched_locs:
            # Prefer package context location if available
            pkg_locs = [loc for loc in matched_locs if loc.context == "package"]
            best = pkg_locs[0] if pkg_locs else matched_locs[0]
            if rc.old_rule_number and rc.old_rule_number != best.rule_number:
                rc.moved = True
            rc.rule_number = best.rule_number
            if not rc.package_uid and best.package_uid:
                rc.package_uid = best.package_uid
            if not rc.package_name and best.package_name:
                rc.package_name = best.package_name
            if not rc.layer_uid and best.layer_uid:
                rc.layer_uid = best.layer_uid
            if not rc.layer_name and best.layer_name:
                rc.layer_name = best.layer_name
            if not rc.section_uid and best.section_uid:
                rc.section_uid = best.section_uid
            if not rc.section_name and best.section_name:
                rc.section_name = best.section_name
            if not rc.section_range and best.section_range:
                rc.section_range = best.section_range
            continue

        # If a deleted or modified rule is not directly in the current snapshot by UID,
        # check if its layer has a known prefix so a relative rule number can still be prefixed.
        if rc.layer_uid and rc.layer_uid in locations.layer_prefixes:
            prefixes = locations.layer_prefixes[rc.layer_uid]
            if prefixes:
                p_loc = prefixes[0]
                if not rc.package_uid and p_loc.package_uid:
                    rc.package_uid = p_loc.package_uid
                if not rc.package_name and p_loc.package_name:
                    rc.package_name = p_loc.package_name
                if rc.rule_number and p_loc.prefix and not rc.rule_number.startswith(p_loc.prefix):
                    rc.rule_number = f"{p_loc.prefix}{rc.rule_number}"

        if rc.operation == "deleted" and not rc.rule_number:
            rc.rule_number = rc.old_rule_number or "DELETED"


@traced
async def apply_session_rule_placement(
    session_report: SessionChangeReport,
    *,
    api: ApiPort,
    cache: CachePort,
    owned_session: OwnedSession | None = None,
    warnings: list[ReportWarning],
    now_fn: Callable[[], datetime] = utc_now,
) -> None:
    """Populate SmartConsole rule numbers on `session_report.rule_changes` via `OwnedSession` or cached snapshot."""
    mgmt_name = session_report.mgmt_name
    domain_name = session_report.domain_name
    session_uid = session_report.session_uid
    span_attrs(
        mgmt_name=mgmt_name,
        domain=domain_name,
        session_uid=session_uid,
        has_owned_session=(owned_session is not None),
    )

    if not session_report.rule_changes:
        session_report.numbering_basis = ""
        session_report.numbering_source = "not_applicable"
        return

    if owned_session is not None:
        raw_sid = owned_session.sid
        srv_ip = owned_session.server_ip or None
        try:
            # Verify ownership and unpublished state strictly read-only via show-session
            verify_res = await api.api_call(
                mgmt_name,
                "show-session",
                {},
                domain=domain_name or None,
                sid=raw_sid,
                server_ip=srv_ip,
            )
            if not verify_res.success:
                err_msg = redact_sid(
                    verify_res.error_message or verify_res.error_code or "show-session failed",
                    known_sids=[raw_sid],
                )
                warnings.append(
                    ReportWarning(
                        code="owned_session_error",
                        mgmt_name=mgmt_name,
                        domain=domain_name,
                        session_uid=session_uid,
                        message=(
                            f"OwnedSession verification failed for session {session_uid}: {err_msg}; "
                            "falling back to cached rulebase snapshot."
                        ),
                    )
                )
            else:
                s_data = verify_res.data if isinstance(verify_res.data, dict) else {}
                live_uid = str(s_data.get("uid") or "")
                live_state = str(s_data.get("state") or "").strip().lower()
                has_pub_time = bool(s_data.get("publish-time"))
                live_changes = int(s_data.get("changes") or 0)
                target_is_published = (
                    session_report.state.strip().lower() == "published" or session_report.published_at is not None
                )

                if (
                    (not live_uid or live_uid == session_uid)
                    and live_state not in ("published", "discarded")
                    and not has_pub_time
                    and not target_is_published
                ):
                    # Case 1: Live read-only rulebase collection in the unpublished owned session
                    live_snapshot = await collect_domain_rulebase_snapshot(
                        api,
                        mgmt_name,
                        domain_name,
                        sid=raw_sid,
                        server_ip=srv_ip,
                    )
                    _apply_snapshot_locations_to_rules(session_report.rule_changes, live_snapshot)
                    ts_str = _format_utc_timestamp(now_fn())
                    session_report.numbering_basis = f"Numbering read live in the owned session at {ts_str} UTC"
                    session_report.numbering_source = "owned_session"
                    return
                if (
                    target_is_published
                    and live_state != "discarded"
                    and (not live_uid or live_uid == session_uid or live_changes == 0)
                ):
                    # Case 2: Target session is published and OwnedSession is clean (post-publish before logout)
                    live_snapshot = await collect_domain_rulebase_snapshot(
                        api,
                        mgmt_name,
                        domain_name,
                        sid=raw_sid,
                        server_ip=srv_ip,
                    )
                    _apply_snapshot_locations_to_rules(session_report.rule_changes, live_snapshot)
                    if _snapshot_has_rules_or_layers(live_snapshot):
                        with contextlib.suppress(Exception):
                            await cache.replace_domain_rulebase(live_snapshot)
                    ts_str = _format_utc_timestamp(now_fn())
                    session_report.numbering_basis = f"Numbering read live after publish at {ts_str} UTC"
                    session_report.numbering_source = "live_published"
                    return
                if live_uid and live_uid != session_uid:
                    warnings.append(
                        ReportWarning(
                            code="owned_session_not_used",
                            mgmt_name=mgmt_name,
                            domain=domain_name,
                            session_uid=session_uid,
                            message=(
                                f"OwnedSession UID ({live_uid}) does not match target session ({session_uid}); "
                                "falling back to cached rulebase snapshot."
                            ),
                        )
                    )
                else:
                    warnings.append(
                        ReportWarning(
                            code="owned_session_not_used",
                            mgmt_name=mgmt_name,
                            domain=domain_name,
                            session_uid=session_uid,
                            message=(
                                f"OwnedSession for {session_uid} is already {live_state or 'published'}; "
                                "falling back to cached rulebase snapshot."
                            ),
                        )
                    )
        except ServerIdentityError:
            raise
        except Exception as exc:
            safe_err = redact_sid(str(exc), known_sids=[raw_sid])
            warnings.append(
                ReportWarning(
                    code="owned_session_error",
                    mgmt_name=mgmt_name,
                    domain=domain_name,
                    session_uid=session_uid,
                    message=(
                        f"OwnedSession live rulebase read failed for session {session_uid}: {safe_err}; "
                        "falling back to cached rulebase snapshot."
                    ),
                )
            )

    # Fallback: number rules from the domain's cached rulebase snapshot
    cached_snapshot = await cache.get_domain_rulebase(mgmt_name, domain_name)
    sync_state = await cache.get_sync_state(mgmt_name, domain_name, "rulebase", "*")

    has_cached_rules = _snapshot_has_rules_or_layers(cached_snapshot)
    if has_cached_rules:
        _apply_snapshot_locations_to_rules(session_report.rule_changes, cached_snapshot)
        if sync_state is not None and sync_state.last_session_uid:
            pub_str = (
                f" ({_format_utc_timestamp(sync_state.last_published_at)} UTC)"
                if sync_state.last_published_at is not None
                else ""
            )
            session_report.numbering_basis = (
                f"Numbering from cached rulebase snapshot (session {sync_state.last_session_uid}{pub_str})"
            )
        else:
            session_report.numbering_basis = "Numbering from cached rulebase snapshot"
        session_report.numbering_source = "cache"
    else:
        # Cold-cache fallback: attempt read-only live published rulebase fetch
        fallback_snapshot: DomainRulebaseSnapshot | None = None
        try:
            fallback_snapshot = await collect_domain_rulebase_snapshot(api, mgmt_name, domain_name)
        except ServerIdentityError:
            raise
        except Exception:
            fallback_snapshot = None

        if fallback_snapshot is not None and _snapshot_has_rules_or_layers(fallback_snapshot):
            _apply_snapshot_locations_to_rules(session_report.rule_changes, fallback_snapshot)
            with contextlib.suppress(Exception):
                await cache.replace_domain_rulebase(fallback_snapshot)
            ts_str = _format_utc_timestamp(now_fn())
            session_report.numbering_basis = f"Numbering read live from published rulebase at {ts_str} UTC"
            session_report.numbering_source = "live_published"
            return

        for rc in session_report.rule_changes:
            if rc.operation == "deleted" and not rc.rule_number:
                rc.rule_number = rc.old_rule_number or "DELETED"
        session_report.numbering_basis = "Numbering from cached rulebase snapshot (unavailable)"
        session_report.numbering_source = "unnumbered"


__all__ = [
    "apply_session_rule_placement",
]
