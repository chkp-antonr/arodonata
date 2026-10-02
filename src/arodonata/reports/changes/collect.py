"""Collect a change report: show-changes per session or range through the shared session, then build, member
names and numbering (spec 2.2, 2.3, 4, 5)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Collection, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from typing import TYPE_CHECKING, Any, Literal, Protocol

from arlogi.otel.decorator import traced

from ... import __version__
from ...api.schemas import ApiCallResult
from ...api.services.live_rulebase_source import LiveRulebaseSource, SidCaller
from ...config import GLOBAL_DOMAIN_NAME
from ...logger import lazy_logger
from ...rulebase.model import RulebaseType
from ...rulebase.source import RuleLocations
from ...telemetry import span_attrs
from .build import build_session, published_at, session_uid
from .model import (
    ChangeReport,
    DomainChanges,
    DomainError,
    MgmtChanges,
    NumberBasis,
    NumberingInfo,
    RawResponse,
    ReportWarning,
    RequestedScope,
    SessionChanges,
)
from .names import NameBudget, resolve_names
from .placement import place_session
from .scopes import ChangeReportInputError, OwnedSession, RangeScope, Scope, SessionScope

if TYPE_CHECKING:
    from ...api.client import ArodonataClient

log = lazy_logger("arodonata.reports.changes.collect")

COMMAND = "show-changes"
CACHE_DOMAIN_SMS = "SMC User"
# Lab checks R2/R3 (plan decision 11): only offset-less dates in server local time are accepted; from-session and
# from-date cannot be combined; an empty date window fails with err_validation_failed; an unknown uid answers
# generic_server_error.
UNKNOWN_SESSION_CODES: frozenset[str] = frozenset({"generic_server_error"})
EMPTY_RANGE_CODES: frozenset[str] = frozenset({"err_validation_failed"})  # "Only one publish made": empty window
_DATE_STYLE: Literal["z", "colon", "nocolon", "offsetless"] = "offsetless"


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class _Request:
    payload: dict[str, Any]  # ranges: filled at fetch time
    session_uid: str | None = None
    scope: RangeScope | None = None


@dataclass
class _DomainWork:
    mgmt: str
    domain: str
    requests: list[_Request] = field(default_factory=list)
    owned: dict[str, OwnedSession] = field(default_factory=dict)  # session uid -> winning owned session
    explicit: list[str] = field(default_factory=list)  # SessionScope uids in request order


@dataclass
class _DomainResult:
    domain: DomainChanges
    warnings: list[ReportWarning]
    raw: list[RawResponse]


@dataclass
class _Context:
    client: ArodonataClient
    include_raw: bool
    max_sessions: int | None
    now: Callable[[], datetime] = _utcnow
    offsets: dict[str, tzinfo] = field(default_factory=dict)
    offset_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    concurrency: int = 4
    names: NameBudget = field(default_factory=NameBudget)


def cache_domain(domain: str) -> str:
    return domain or CACHE_DOMAIN_SMS


def _floor_minute(dt: datetime) -> datetime:
    return dt.replace(second=0, microsecond=0)


def _ceil_minute(dt: datetime) -> datetime:
    floored = _floor_minute(dt)
    return floored if floored == dt else floored + timedelta(minutes=1)


def _format_date(dt: datetime, server_tz: tzinfo | None) -> str:
    if _DATE_STYLE == "offsetless":
        return dt.astimezone(server_tz or UTC).strftime("%Y-%m-%dT%H:%M:%S")
    utc = dt.astimezone(UTC)
    if _DATE_STYLE == "z":
        return utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    text = utc.isoformat(timespec="seconds")  # ...+00:00
    return text[:-3] + text[-2:] if _DATE_STYLE == "nocolon" else text


def _sends_from_date(scope: RangeScope) -> bool:
    """from-date reaches the server unless from-session is set (R2: it refuses that pair); to-session combines."""
    return scope.from_date is not None and scope.from_session is None


def _sends_to_date(scope: RangeScope) -> bool:
    """to-date is sent only when no session bound is set; combined with to-session it was never verified."""
    return scope.to_date is not None and scope.from_session is None and scope.to_session is None


def _sends_dates(scope: RangeScope) -> bool:
    return _sends_from_date(scope) or _sends_to_date(scope)


def _range_payload(
    scope: RangeScope, server_tz: tzinfo | None = None, now: datetime | None = None, *, offset_known: bool = True
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if scope.from_session:
        payload["from-session"] = scope.from_session
    if scope.to_session:
        payload["to-session"] = scope.to_session
    if _sends_dates(scope):
        if _DATE_STYLE != "offsetless":
            widen = timedelta(minutes=1)
        elif offset_known:
            widen = timedelta(minutes=61)
        else:
            widen = timedelta(hours=15)  # covers every UTC offset; the exact posix filter still applies
        if _sends_from_date(scope) and scope.from_date:
            payload["from-date"] = _format_date(_floor_minute(scope.from_date) - widen, server_tz)
        if _sends_to_date(scope) and scope.to_date:
            upper = _ceil_minute(scope.to_date) + widen
            if now is None or upper <= now:  # a future to-date was never verified against the server
                payload["to-date"] = _format_date(upper, server_tz)
    return payload


_SCOPES_MESSAGE = "scopes must be a non-empty list of SessionScope/RangeScope"


def _as_scope_list(scopes: Iterable[Scope], max_sessions: int | None) -> list[Scope]:
    """Validate the call arguments; a single scope (a pydantic model is iterable) or a str is not a scope list."""
    if max_sessions is not None and max_sessions < 1:
        raise ChangeReportInputError("max_sessions must be None or at least 1")
    if isinstance(scopes, SessionScope | RangeScope | str | bytes):
        raise ChangeReportInputError(_SCOPES_MESSAGE)
    return list(scopes)


def _plan(  # noqa: C901
    client: ArodonataClient, scopes: Sequence[Scope]
) -> tuple[list[_DomainWork], list[RequestedScope], list[ReportWarning]]:
    if not scopes:
        raise ChangeReportInputError(_SCOPES_MESSAGE)
    names = client.get_mgmt_names()
    if not names:
        raise ChangeReportInputError("no management server is configured")
    work: dict[tuple[str, str], _DomainWork] = {}
    requested: list[RequestedScope] = []
    warnings: list[ReportWarning] = []
    for scope in scopes:
        if not isinstance(scope, SessionScope | RangeScope):
            raise ChangeReportInputError(f"expected SessionScope or RangeScope, got {type(scope).__name__}")
        mgmt = scope.mgmt_name or names[0]
        if mgmt not in names:
            raise ChangeReportInputError(f"unknown mgmt_name {mgmt!r}; configured servers: {', '.join(names)}")
        w = work.setdefault((mgmt, scope.domain), _DomainWork(mgmt, scope.domain))
        if isinstance(scope, SessionScope):
            requested.append(
                RequestedScope(
                    kind="session",
                    mgmt_name=mgmt,
                    domain=scope.domain,
                    session_uids=list(scope.session_uids),
                    owned_session_supplied=scope.owned_session is not None,
                )
            )
            for uid in scope.session_uids:
                if uid in w.explicit:
                    if w.owned.get(uid) != scope.owned_session:
                        warnings.append(
                            ReportWarning(
                                mgmt=mgmt,
                                domain=scope.domain,
                                code="owned_session_conflict",
                                session_uid=uid,
                                message=f"session {uid} was requested with different owned sessions; the first is used",
                            )
                        )
                    continue
                w.explicit.append(uid)
                w.requests.append(_Request({"to-session": uid}, session_uid=uid))
                if scope.owned_session is not None:
                    w.owned[uid] = scope.owned_session
        else:
            requested.append(
                RequestedScope(
                    kind="range",
                    mgmt_name=mgmt,
                    domain=scope.domain,
                    from_session=scope.from_session,
                    to_session=scope.to_session,
                    from_date=scope.from_date,
                    to_date=scope.to_date,
                )
            )
            w.requests.append(_Request({}, scope=scope))
    return list(work.values()), requested, warnings


async def _server_offset(ctx: _Context, w: _DomainWork) -> tzinfo | None:
    """The server's UTC offset, read once per mgmt from the last published session's publish-time.iso-8601.

    None when it cannot be read (failed call, empty domain, exception); that is not cached, so the next domain of
    the mgmt tries again."""
    async with ctx.offset_lock:
        if w.mgmt in ctx.offsets:
            return ctx.offsets[w.mgmt]
        try:
            res = await ctx.client.api_query(w.mgmt, COMMAND, domain=w.domain, details_level="standard", payload={})
            if res.success and res.objects:
                iso = str((res.objects[0].get("session") or {}).get("publish-time", {}).get("iso-8601", ""))
                tz = datetime.strptime(iso[-5:], "%z").tzinfo if len(iso) >= 5 else None
                if tz is not None:
                    ctx.offsets[w.mgmt] = tz
                    return tz
        except Exception as exc:  # the exact posix filter still applies; only the server-side window shifts
            log().warning(f"Server offset of {w.mgmt} unreadable ({type(exc).__name__}); widening the date window")
            return None
        log().warning(f"Server offset of {w.mgmt} unreadable (no publish time); widening the date window")
        return None


def _in_range(changes: list[dict[str, Any]], scope: RangeScope) -> list[dict[str, Any]]:
    kept = []
    for change in changes:
        meta = change.get("session") or {}
        when = published_at(meta)
        if not meta.get("published") or when is None:
            continue
        if (scope.from_date and when < scope.from_date) or (scope.to_date and when > scope.to_date):
            continue
        kept.append(change)
    return kept


def _warning(w: _DomainWork, code: str, message: str, **kw: Any) -> ReportWarning:
    return ReportWarning(mgmt=w.mgmt, domain=w.domain, code=code, message=message, **kw)


def _order_and_cap(
    w: _DomainWork, fetched: list[tuple[dict[str, Any], bool]], max_sessions: int | None
) -> tuple[list[dict[str, Any]], list[ReportWarning]]:
    """Dedupe by uid (first wins), cap range-only sessions to the earliest max_sessions, then order published by
    publish time and unpublished in request order."""
    seen: dict[str, tuple[dict[str, Any], bool]] = {}
    for change, explicit in fetched:
        uid = session_uid(change)
        if uid in seen:
            seen[uid] = (seen[uid][0], seen[uid][1] or explicit)
        else:
            seen[uid] = (change, explicit)
    warnings: list[ReportWarning] = []
    range_only = sorted(
        (c for c, explicit in seen.values() if not explicit), key=lambda c: int(c["session"]["publish-time"]["posix"])
    )
    if max_sessions is not None and len(range_only) > max_sessions:
        dropped = {session_uid(c) for c in range_only[max_sessions:]}
        last = session_uid(range_only[max_sessions - 1]) if max_sessions else ""
        warnings.append(
            _warning(
                w,
                "range_truncated",
                f"{len(dropped)} more range sessions omitted (cap {max_sessions}); continue with from_session={last}",
            )
        )
        seen = {uid: v for uid, v in seen.items() if uid not in dropped}
    changes = [c for c, _ in seen.values()]
    published = sorted(
        (c for c in changes if c["session"].get("published")),
        key=lambda c: int((c["session"].get("publish-time") or {}).get("posix") or 0),
    )
    return published + [c for c in changes if not c["session"].get("published")], warnings


class RuleLocator(Protocol):
    """Structural subset of RulebaseSource that numbering needs (spec 5.1)."""

    async def locate_rules(
        self,
        mgmt_name: str,
        domain_name: str,
        rule_uids: Collection[str] = (),
        rulebase_type: RulebaseType | None = None,
        *,
        layer_uids: Collection[str] = (),
    ) -> RuleLocations: ...


@dataclass(frozen=True)
class CacheLocator:
    """RuleLocator over the client facade with a fixed cache_mode ("smart", or "force" for the D19 re-locate)."""

    client: Any
    mode: str

    async def locate_rules(
        self,
        mgmt_name: str,
        domain_name: str,
        rule_uids: Collection[str] = (),
        rulebase_type: RulebaseType | None = None,
        *,
        layer_uids: Collection[str] = (),
    ) -> RuleLocations:
        return await self.client.locate_rules(
            mgmt_name, domain_name, rule_uids, rulebase_type, layer_uids=layer_uids, cache_mode=self.mode
        )


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def _touched(sessions: Sequence[SessionChanges]) -> tuple[set[str], set[str]]:
    """Rule uids (deleted included, plan decision 14) and every layer a rule is or was in."""
    rules = {r.uid for s in sessions for r in s.rules}
    layers = {u for s in sessions for r in s.rules for u in (r.layer_uid, r.old_layer_uid) if u}
    return rules, layers


def _freshness(session: SessionChanges, locations: RuleLocations) -> Literal["fresh", "older", "ambiguous"]:
    """D19 per published session: same uid -> fresh; snapshot published after the session's minute -> fresh;
    snapshot older -> older; the same minute with another uid -> ambiguous."""
    if locations.snapshot_session_uid == session.uid:
        return "fresh"
    snapshot = _aware(locations.snapshot_published_at)
    if snapshot is None or session.published_at is None:
        return "older"
    minute = _floor_minute(session.published_at)
    if minute > snapshot:
        return "older"
    return "ambiguous" if minute == snapshot else "fresh"


def _error_text(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    return f"{type(exc).__name__} ({code})" if code else type(exc).__name__


async def _locate(
    locator: RuleLocator, w: _DomainWork, rules: set[str], layers: set[str]
) -> tuple[RuleLocations | None, str | None]:
    try:
        return await locator.locate_rules(w.mgmt, cache_domain(w.domain), rules, layer_uids=layers), None
    except Exception as exc:
        log().warning(f"Change report numbering for {w.mgmt}:{cache_domain(w.domain)} failed: {_error_text(exc)}")
        return None, _error_text(exc)


@traced
def _number_session(
    session: SessionChanges,
    locations: RuleLocations | None,
    error: str | None,
    *,
    global_packages: bool,
    forced: bool,
    verified: bool = False,
) -> SessionChanges:
    if locations is None:
        info = NumberingInfo(
            source="cache",
            status="failed",
            last_error=error,
            provisional=not session.published,
            global_packages=global_packages,
        )
        placed = place_session(session, None, basis="none")
    else:
        basis: NumberBasis = "snapshot" if session.published else "provisional"
        info = NumberingInfo(
            source="cache",
            snapshot_session_uid=locations.snapshot_session_uid,
            snapshot_published_at=_aware(locations.snapshot_published_at),
            snapshot_refreshed_at=_aware(locations.snapshot_refreshed_at),
            status=locations.status,
            last_error=locations.last_error,
            provisional=not session.published,
            global_packages=global_packages,
        )
        placed = place_session(session, locations, basis=basis, prior=None if session.published else locations)
    span_attrs(
        **{
            "session_uid": session.uid,
            "report.numbering_source": info.source,
            "report.snapshot_session_uid": info.snapshot_session_uid,
            "report.numbering_status": info.status,
            "report.forced_relocate": forced,
            "report.owned_session_verified": verified,
        }
    )
    return placed.model_copy(update={"numbering": info})


def _snapshot_label(locations: RuleLocations) -> str:
    return locations.snapshot_session_uid or "unknown"


async def _relocate(
    ctx: _Context,
    w: _DomainWork,
    locations: RuleLocations,
    stale: list[SessionChanges],
    warnings: list[ReportWarning],
    touched: tuple[set[str], set[str]],
) -> RuleLocations:
    """D19: one forced re-locate for the stale published sessions; a failure keeps the smart locations."""
    relocated, error = await _locate(CacheLocator(ctx.client, "force"), w, *touched)
    if relocated is None:
        warnings.append(
            _warning(
                w,
                "numbering_failed",
                f"forced re-locate failed ({error}); numbers describe snapshot {_snapshot_label(locations)}",
                severity="info",
            )
        )
        return locations
    for s in stale:
        if _freshness(s, relocated) == "older":
            warnings.append(
                _warning(
                    w,
                    "numbering_failed",
                    f"the rulebase snapshot {_snapshot_label(relocated)} predates session {s.uid}; "
                    "numbers describe that snapshot",
                    severity="info",
                    session_uid=s.uid,
                )
            )
    return relocated


async def _smart_locate(
    ctx: _Context, w: _DomainWork, touched: tuple[set[str], set[str]]
) -> tuple[RuleLocations | None, str | None]:
    try:
        ctx.client.invalidate_domain(w.mgmt, cache_domain(w.domain))
    except Exception as exc:
        log().warning(f"Change report cache invalidation for {w.mgmt} failed: {_error_text(exc)}")
        return None, _error_text(exc)
    return await _locate(CacheLocator(ctx.client, "smart"), w, *touched)


def _group_owners(w: _DomainWork, fetched: dict[str, SessionChanges]) -> list[tuple[OwnedSession, list[str]]]:
    """The distinct owned sessions that won a collected uid, each with those uids."""
    owners: list[tuple[OwnedSession, list[str]]] = []
    for uid, owned_session in w.owned.items():
        if uid not in fetched:
            continue
        for owner, uids in owners:
            if owner == owned_session:
                uids.append(uid)
                break
        else:
            owners.append((owned_session, [uid]))
    return owners


async def _verify_owned(
    ctx: _Context, w: _DomainWork, sessions: list[SessionChanges], warnings: list[ReportWarning]
) -> dict[str, OwnedSession]:
    """session uid -> the owned session verified for it: one show-session per distinct owned session that won a
    collected uid; verified when its session uid is one of them and that session is unpublished (spec 2.3)."""
    fetched = {s.uid: s for s in sessions}
    verified: dict[str, OwnedSession] = {}
    for owner, uids in _group_owners(w, fetched):
        caller = SidCaller(ctx.client, w.mgmt, owner.sid, owner.server_ip)
        res: ApiCallResult | None = None
        try:
            res = await caller.api_call(mgmt_name=w.mgmt, domain=w.domain, command="show-session", payload={})
            code = "" if res.success and isinstance(res.data, dict) else (res.code or "invalid_response")
        except Exception as exc:
            code = type(exc).__name__
        if code:
            for uid in uids:
                warnings.append(_warning(w, "owned_session_error", code, session_uid=uid))
            continue
        assert res is not None and isinstance(res.data, dict)
        current = str(res.data.get("uid") or "")
        for uid in uids:
            if uid == current and not fetched[uid].published:
                verified[uid] = owner
                log().debug(f"Owned session for {uid} verified on {w.mgmt}:{w.domain}")
            else:
                warnings.append(
                    _warning(
                        w,
                        "owned_session_not_used",
                        f"the owned session for {uid} is no longer that unpublished "
                        "session (published or discarded); numbering from the cache",
                        severity="info",
                        session_uid=uid,
                    )
                )
    return verified


def _live_packages(session: SessionChanges, locations: RuleLocations | None) -> set[str] | None:
    """Packages holding the session's touched layers (a layer new in the session: its parent rule's layer)."""
    if locations is None:
        return None
    by_inline = {r.inline_layer_uid: r for r in session.rules if r.inline_layer_uid}
    names: set[str] = set()

    def add(layer: str, path: frozenset[str]) -> None:
        positions = locations.layers.get(layer, [])
        if positions:
            names.update(p.package_name for p in positions)
            return
        parent = by_inline.get(layer)
        if parent is not None and parent.uid not in path and parent.layer_uid:
            add(parent.layer_uid, path | {parent.uid})

    for rule in session.rules:
        for layer in (rule.layer_uid, rule.old_layer_uid):
            if layer:
                add(layer, frozenset())
    return names or None


@traced
async def _number_live(
    ctx: _Context,
    w: _DomainWork,
    session: SessionChanges,
    owner: OwnedSession,
    packages: set[str] | None,
    prior: RuleLocations | None,
    warnings: list[ReportWarning],
) -> SessionChanges | str:
    """Number an unpublished session through its owned session's SID; on any read warning or failure return the
    error code (the caller then numbers it provisionally from the cache)."""
    cdomain = cache_domain(w.domain)
    source = LiveRulebaseSource(
        ctx.client, w.mgmt, cdomain, owner.sid, owner.server_ip, session_uid=session.uid, packages=packages
    )
    rules, layers = _touched([session])
    try:
        locations = await source.locate_rules(w.mgmt, cdomain, rules, layer_uids=layers)
    except Exception as exc:
        code = type(exc).__name__
    else:
        if not source.warnings:
            info = NumberingInfo(
                source="live",
                snapshot_session_uid=locations.snapshot_session_uid,
                snapshot_refreshed_at=_aware(locations.snapshot_refreshed_at),
                status="live",
                global_packages=w.domain == GLOBAL_DOMAIN_NAME,
            )
            span_attrs(
                **{
                    "session_uid": session.uid,
                    "report.numbering_source": "live",
                    "report.snapshot_session_uid": session.uid,
                    "report.numbering_status": "live",
                    "report.owned_session_verified": True,
                }
            )
            placed = place_session(session, locations, basis="live", prior=prior)  # prior: deleted rules (D27)
            return placed.model_copy(update={"numbering": info})
        code = "live_read_warning"
    warnings.append(
        _warning(
            w,
            "live_numbering_degraded",
            f"live numbering of {session.uid} degraded ({code}); provisional numbers from the cache",
            session_uid=session.uid,
        )
    )
    return code


async def _number_domain(
    ctx: _Context,
    w: _DomainWork,
    sessions: list[SessionChanges],
    warnings: list[ReportWarning],
    verified: dict[str, OwnedSession] | None = None,
) -> list[SessionChanges]:
    """One cache locate per (mgmt, cache domain), after invalidating the smart memo; one forced re-locate when a
    published session is newer than the snapshot (D19); a failure numbers nothing and warns once."""
    if not any(s.rules for s in sessions):
        return sessions
    live = verified or {}
    touched = _touched(sessions)
    locations, error = await _smart_locate(ctx, w, touched)
    forced = False
    if locations is not None:
        stale = [s for s in sessions if s.published and s.rules and _freshness(s, locations) != "fresh"]
        if stale:
            forced = True
            locations = await _relocate(ctx, w, locations, stale, warnings, touched)
    else:
        warnings.append(
            _warning(w, "numbering_failed", f"rule numbering unavailable for {cache_domain(w.domain)}: {error}")
        )
    global_packages = w.domain == GLOBAL_DOMAIN_NAME
    out: list[SessionChanges] = []
    for s in sessions:
        if not s.rules:
            out.append(s)
            continue
        if s.uid in live:
            result = await _number_live(ctx, w, s, live[s.uid], _live_packages(s, locations), locations, warnings)
            if isinstance(result, SessionChanges):
                out.append(result)
                continue
            fallback = _number_session(
                s, locations, error, global_packages=global_packages, forced=forced, verified=True
            )
            numbering = fallback.numbering.model_copy(update={"last_error": result})
            out.append(fallback.model_copy(update={"numbering": numbering}))
            continue
        out.append(_number_session(s, locations, error, global_packages=global_packages, forced=forced))
    return out


@traced
async def _collect_domain(ctx: _Context, w: _DomainWork) -> _DomainResult:  # noqa: C901
    span_attrs(
        **{
            "mgmt_name": w.mgmt,
            "domain": w.domain,
            "report.session_uids": ",".join(w.explicit) or None,
            "report.scope_kind": "range" if any(r.scope for r in w.requests) else "session",
            "report.from_session": next((r.scope.from_session for r in w.requests if r.scope), None),
            "report.to_session": next((r.scope.to_session for r in w.requests if r.scope), None),
            "report.from_date": next(
                (r.scope.from_date.isoformat() for r in w.requests if r.scope and r.scope.from_date), None
            ),
            "report.to_date": next(
                (r.scope.to_date.isoformat() for r in w.requests if r.scope and r.scope.to_date), None
            ),
        }
    )
    warnings: list[ReportWarning] = []
    raw: list[RawResponse] = []
    fetched: list[tuple[dict[str, Any], bool]] = []
    unavailable: DomainError | None = None
    for req in w.requests:
        if req.scope is not None and req.scope.from_date is not None and req.scope.from_date > ctx.now():
            continue  # the server refuses a from-date later than now: the range is empty
        payload = req.payload
        if req.scope is not None:
            tz = await _server_offset(ctx, w) if _DATE_STYLE == "offsetless" and _sends_dates(req.scope) else None
            payload = _range_payload(req.scope, tz, ctx.now(), offset_known=tz is not None)
        record = {"command": COMMAND, "details-level": "full", **payload}
        try:
            res = await ctx.client.api_query(w.mgmt, COMMAND, domain=w.domain, details_level="full", payload=payload)
        except Exception as exc:
            code = type(exc).__name__
            message = f"{COMMAND} raised {code}"
            log().warning(f"Change report: {message} for {w.mgmt}:{w.domain}")
            if ctx.include_raw:
                raw.append(
                    RawResponse(mgmt=w.mgmt, domain=w.domain, request=record, success=False, code=code, message=message)
                )
            unavailable = DomainError(code=code, message=message)
            break
        if ctx.include_raw:
            raw.append(
                RawResponse(
                    mgmt=w.mgmt,
                    domain=w.domain,
                    request=record,
                    success=res.success,
                    code=res.code,
                    message=res.message,
                    response=res.data if res.success and isinstance(res.data, dict) else None,
                )
            )
        if not res.success:
            if req.scope is not None and res.code in EMPTY_RANGE_CODES:
                continue  # no publish inside the window
            if req.session_uid is not None and res.code in UNKNOWN_SESSION_CODES:
                warnings.append(
                    _warning(
                        w,
                        "session_not_found",
                        f"session {req.session_uid} is unknown ({res.code})",
                        session_uid=req.session_uid,
                    )
                )
                continue
            unavailable = DomainError(code=res.code or "failed", message=res.message)
            break
        changes = [c for c in res.objects if isinstance(c, dict)]
        if req.session_uid is not None:
            match = [c for c in changes if session_uid(c) == req.session_uid]
            if not match:
                returned = ", ".join(session_uid(c) for c in changes) or "none"
                warnings.append(
                    _warning(
                        w,
                        "session_not_found",
                        f"session {req.session_uid} not returned (returned: {returned}); it may be empty, of another "
                        "domain or not visible to this administrator",
                        session_uid=req.session_uid,
                    )
                )
                continue
            fetched.append((match[0], True))
        else:
            assert req.scope is not None
            fetched += [(c, False) for c in _in_range(changes, req.scope)]
    if unavailable is not None:
        warnings.append(_warning(w, "domain_unavailable", f"{unavailable.code}: {unavailable.message}"))
    entries, cap_warnings = _order_and_cap(w, fetched, ctx.max_sessions)
    warnings += cap_warnings
    sessions, name_warning = await resolve_names(
        ctx.client, w.mgmt, w.domain, [(build_session(e), e) for e in entries], ctx.names, ctx.concurrency
    )
    if name_warning is not None:
        warnings.append(name_warning)
    verified = await _verify_owned(ctx, w, sessions, warnings)
    sessions = await _number_domain(ctx, w, sessions, warnings, verified)
    display = next((str((e["session"].get("domain-info") or {}).get("name") or "") for e in entries), "")
    return _DomainResult(
        domain=DomainChanges(
            domain=w.domain, display_name=display or cache_domain(w.domain), unavailable=unavailable, sessions=sessions
        ),
        warnings=warnings,
        raw=raw,
    )


def _failed_domain(w: _DomainWork, exc: Exception) -> _DomainResult:
    code = type(exc).__name__
    message = f"change report raised {code}"
    log().warning(f"Change report: {message} for {w.mgmt}:{w.domain}")
    error = DomainError(code=code, message=message)
    return _DomainResult(
        domain=DomainChanges(domain=w.domain, display_name=cache_domain(w.domain), unavailable=error, sessions=[]),
        warnings=[_warning(w, "domain_unavailable", f"{code}: {message}")],
        raw=[],
    )


@traced
async def collect_change_report(
    client: ArodonataClient,
    scopes: Iterable[Scope],
    *,
    include_raw: bool = False,
    concurrency: int = 4,
    max_sessions: int | None = None,
    now: Callable[[], datetime] = _utcnow,
) -> ChangeReport:
    """Collect the changes of the given scopes into one ChangeReport (spec 2.2). Errors become warnings; only
    invalid input raises (ChangeReportInputError, or pydantic's ValidationError when the scope was built)."""
    scopes = _as_scope_list(scopes, max_sessions)
    work, requested, warnings = _plan(client, scopes)
    span_attrs(
        **{
            "report.scopes": len(scopes),
            "report.mgmt_names": ",".join(dict.fromkeys(w.mgmt for w in work)),
            "report.domains": ",".join(dict.fromkeys(w.domain for w in work)),
            "report.session_uids": ",".join(uid for w in work for uid in w.explicit) or None,
            "report.include_raw": include_raw,
        }
    )
    ctx = _Context(
        client=client, include_raw=include_raw, max_sessions=max_sessions, now=now, concurrency=max(1, concurrency)
    )
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def run(w: _DomainWork) -> _DomainResult:
        async with semaphore:
            try:
                return await _collect_domain(ctx, w)
            except Exception as exc:  # D13: one domain's failure never loses the report (CancelledError propagates)
                return _failed_domain(w, exc)

    results = await asyncio.gather(*(run(w) for w in work))
    servers: dict[str, list[DomainChanges]] = {}
    raw: list[RawResponse] = []
    for w, result in zip(work, results, strict=True):
        servers.setdefault(w.mgmt, []).append(result.domain)
        warnings += result.warnings
        raw += result.raw
    report = ChangeReport(
        generated_at=now(),
        arodonata_version=__version__,
        requested=requested,
        servers=[MgmtChanges(mgmt_name=m, domains=d) for m, d in servers.items()],
        warnings=warnings,
        raw=raw if include_raw else None,
    )
    sessions = [s for m in report.servers for d in m.domains for s in d.sessions]
    span_attrs(
        **{
            "report.sessions": len(sessions),
            "report.rules": sum(len(s.rules) for s in sessions),
            "report.objects": sum(len(s.objects) + len(s.other) for s in sessions),
            "report.warnings": len(report.warnings),
        }
    )
    return report


__all__ = ["CACHE_DOMAIN_SMS", "EMPTY_RANGE_CODES", "UNKNOWN_SESSION_CODES", "cache_domain", "collect_change_report"]
