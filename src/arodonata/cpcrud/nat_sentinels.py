"""Runtime resolver for Check Point's two platform-fixed NAT "empty cell" objects.

``NAT_ANY_OBJECT_UID``/``NAT_ORIGINAL_OBJECT_UID`` (see ``resolver.py``) were live-verified
identical on two independent Check Point installations (``mdsNP2.np.cparch.in`` and ``smsNP82``,
2026-09-03) and are safe to use as a hardcoded default. But they are still, in principle, values a
management server generates once at install time -- a customer's server could theoretically have
different UIDs for these objects. Writing a foreign UID into a live NAT rule's cell would either
fail loudly or, worse, silently write the wrong object into a customer's production rule.

This module resolves both UIDs at runtime, by name/type, once per management server, and caches
the result for the process. Resolution never blocks a NAT removal: any failure (API error, object
not found, unexpected response shape, missing package) degrades to the verified constant and logs
a warning. If a resolved UID ever *differs* from the constant, that is logged prominently at
warning level -- naming the management server, the object, and both UIDs -- since that is the
exact early-warning signal for the scenario this module exists to guard against.

The two objects need different resolution strategies, both empirically verified against
``mdsNP2.np.cparch.in`` (MDS, domain ``General``) and ``smsNP82`` (plain SmartCenter) on
2026-09-03:

* The "Any" object (type ``CpmiAnyObject``) IS a normal, catalog-listed object: a read-only
  ``show-objects`` call filtered by ``filter="Any", type="CpmiAnyObject"`` returns exactly one
  match on both servers, with a UID matching ``NAT_ANY_OBJECT_UID``.
* The "Original" object (type ``Global``) is NOT catalog-listed: ``show-objects`` rejects
  ``type="Global"`` outright ("Requested API type: [Global] not found"), and a name filter for
  "Original" with no type filter returns 15 unrelated objects, none of them the sentinel. It is
  only reachable indirectly, e.g. by reading it off a real NAT rule -- exactly how the constant
  itself was originally discovered (see ``resolver.py``'s module docstring above
  ``NAT_ORIGINAL_OBJECT_UID``). This module resolves it by reading a page of an existing NAT
  rulebase (the same package the caller is already operating against) and taking the first
  ``translated-*`` cell whose embedded object has type ``Global``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from ..logger import lazy_logger
from ..utils.helpers import extract_data_from_response, extract_objects_from_response
from .resolver import NAT_ANY_OBJECT_UID, NAT_ORIGINAL_OBJECT_UID

log = lazy_logger("arodonata.cpcrud.nat_sentinels")

# Matches `ApiSession.call`'s signature in MMP's decom removal engine (and `ArodonataClient.
# api_call`'s own shape minus the mgmt/domain args, which the caller's session already knows) --
# this module is deliberately decoupled from any concrete session/client type, so any caller that
# can produce an `(command, payload) -> ApiCallResult`-shaped awaitable can use it.
ApiCall = Callable[[str, dict[str, Any]], Awaitable[Any]]

_ANY_OBJECT_NAME = "Any"
_ANY_OBJECT_TYPE = "CpmiAnyObject"
_ORIGINAL_OBJECT_NAME = "Original"
_ORIGINAL_OBJECT_TYPE = "Global"
_TRANSLATED_FIELDS = ("translated-source", "translated-destination", "translated-service")
_RULEBASE_SCAN_LIMIT = 50


@dataclass(frozen=True)
class NatSentinelUids:
    """The two resolved (or fallback) NAT sentinel UIDs for one management server."""

    any_uid: str
    original_uid: str


# Per-management-server cache, process-lifetime. These two objects are shared across every domain
# on a given management server (both live-verified responses reported them under the "Check Point
# Data" system domain regardless of which customer domain was queried), so the cache is keyed by
# `mgmt_name` alone, not by domain.
_cache: dict[str, NatSentinelUids] = {}


def reset_nat_sentinel_cache() -> None:
    """Clear the per-process cache. Test-only; production code never needs to call this."""
    _cache.clear()


async def resolve_nat_sentinel_uids(call: ApiCall, mgmt_name: str, package: str = "") -> NatSentinelUids:
    """Resolve (or fall back to) the "Any"/"Original" NAT sentinel UIDs for `mgmt_name`.

    Resolved once per management server and cached for the process -- a second call for the same
    `mgmt_name` returns the cached result without making any API call, regardless of `package`.

    Args:
        call: Async `(command, payload) -> ApiCallResult`-shaped callable, e.g. MMP's
            `ApiSession.call` bound to the right management server/domain/session.
        mgmt_name: Management server name -- used only for cache keying and log messages, never
            sent on the wire (the caller's `call` already knows which server it targets).
        package: NAT policy package name/uid the caller is already operating against, used to
            resolve the "Original" object (see module docstring). If empty, "Original" resolution
            is skipped and the verified constant is used, with a warning.

    Returns:
        NatSentinelUids with both UIDs -- resolved where possible, the verified constant
        otherwise. Never raises: any failure degrades to the constant.
    """
    cached = _cache.get(mgmt_name)
    if cached is not None:
        return cached

    any_uid = await _resolve_any_uid(call, mgmt_name)
    original_uid = await _resolve_original_uid(call, mgmt_name, package)

    resolved = NatSentinelUids(any_uid=any_uid, original_uid=original_uid)
    _cache[mgmt_name] = resolved
    return resolved


async def _resolve_any_uid(call: ApiCall, mgmt_name: str) -> str:
    try:
        result = await call(
            "show-objects",
            {"filter": _ANY_OBJECT_NAME, "type": _ANY_OBJECT_TYPE, "details-level": "full", "limit": 10},
        )
        if not getattr(result, "success", False):
            log().warning(
                f"Failed to resolve NAT 'Any' object UID on management server {mgmt_name!r} "
                f"({getattr(result, 'message', 'no message')}) - falling back to the verified "
                f"constant {NAT_ANY_OBJECT_UID!r}"
            )
            return NAT_ANY_OBJECT_UID

        match = _find_matching_object(
            extract_objects_from_response(result), name=_ANY_OBJECT_NAME, type_=_ANY_OBJECT_TYPE
        )
        if match is None:
            log().warning(
                f"show-objects returned no '{_ANY_OBJECT_NAME}'/{_ANY_OBJECT_TYPE} object on "
                f"management server {mgmt_name!r} - falling back to the verified constant "
                f"{NAT_ANY_OBJECT_UID!r}"
            )
            return NAT_ANY_OBJECT_UID

        return _accept_resolved_uid(match, constant=NAT_ANY_OBJECT_UID, mgmt_name=mgmt_name, object_name="Any")
    except Exception as e:  # noqa: BLE001 - a resolution failure must never block a NAT removal
        log().warning(
            f"Error resolving NAT 'Any' object UID on management server {mgmt_name!r}: {e} - "
            f"falling back to the verified constant {NAT_ANY_OBJECT_UID!r}"
        )
        return NAT_ANY_OBJECT_UID


async def _resolve_original_uid(call: ApiCall, mgmt_name: str, package: str) -> str:
    if not package:
        log().warning(
            f"No NAT package identifier available to resolve the 'Original' object UID on "
            f"management server {mgmt_name!r} - falling back to the verified constant "
            f"{NAT_ORIGINAL_OBJECT_UID!r}"
        )
        return NAT_ORIGINAL_OBJECT_UID

    try:
        result = await call(
            "show-nat-rulebase",
            {
                "package": package,
                "details-level": "full",
                "use-object-dictionary": False,
                "limit": _RULEBASE_SCAN_LIMIT,
            },
        )
        if not getattr(result, "success", False):
            log().warning(
                f"Failed to resolve NAT 'Original' object UID on management server {mgmt_name!r} "
                f"({getattr(result, 'message', 'no message')}) - falling back to the verified "
                f"constant {NAT_ORIGINAL_OBJECT_UID!r}"
            )
            return NAT_ORIGINAL_OBJECT_UID

        data = extract_data_from_response(result)
        match = _find_original_in_rulebase(data)
        if match is None:
            log().warning(
                f"Could not find the 'Original' sentinel object in any NAT rule of package "
                f"{package!r} on management server {mgmt_name!r} - falling back to the verified "
                f"constant {NAT_ORIGINAL_OBJECT_UID!r}"
            )
            return NAT_ORIGINAL_OBJECT_UID

        return _accept_resolved_uid(
            match, constant=NAT_ORIGINAL_OBJECT_UID, mgmt_name=mgmt_name, object_name="Original"
        )
    except Exception as e:  # noqa: BLE001 - a resolution failure must never block a NAT removal
        log().warning(
            f"Error resolving NAT 'Original' object UID on management server {mgmt_name!r}: {e} - "
            f"falling back to the verified constant {NAT_ORIGINAL_OBJECT_UID!r}"
        )
        return NAT_ORIGINAL_OBJECT_UID


def _accept_resolved_uid(match: dict[str, Any], *, constant: str, mgmt_name: str, object_name: str) -> str:
    """Return `match`'s uid, warning loudly first if it differs from the known-good constant."""
    uid = str(match.get("uid", ""))
    if not uid:
        return constant
    if uid != constant:
        log().warning(
            f"NAT '{object_name}' object UID on management server {mgmt_name!r} differs from the "
            f"verified constant - resolved={uid!r} constant={constant!r}. Using the resolved "
            f"value. This is the exact scenario the runtime resolver exists to catch: if this is "
            f"unexpected, verify the resolved object on that server before trusting further NAT "
            f"removals against it."
        )
    return uid


def _find_matching_object(objects: list[dict[str, Any]], *, name: str, type_: str) -> dict[str, Any] | None:
    for obj in objects:
        if isinstance(obj, dict) and obj.get("name") == name and obj.get("type") == type_:
            return obj
    return None


def _flatten_rulebase(items: list[Any]) -> list[dict[str, Any]]:
    """Flatten a show-*-rulebase response's rule/section tree into a flat list of rule dicts."""
    flat: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if "rulebase" in item:
            flat.extend(_flatten_rulebase(item.get("rulebase") or []))
        else:
            flat.append(item)
    return flat


def _find_original_in_rulebase(data: Any) -> dict[str, Any] | None:
    """Find the "Original" sentinel embedded in a show-nat-rulebase response's translated-* cells.

    An empty translated-* cell dereferences to the full ``{"uid", "name", "type"}`` object
    directly, even with ``use-object-dictionary: false`` (empirically confirmed against
    ``mdsNP2.np.cparch.in`` 2026-09-03) -- no separate objects-dictionary lookup is needed.
    """
    if not isinstance(data, dict):
        return None
    for rule in _flatten_rulebase(data.get("rulebase") or []):
        for field in _TRANSLATED_FIELDS:
            value = rule.get(field)
            if isinstance(value, dict) and value.get("type") == _ORIGINAL_OBJECT_TYPE and value.get("uid"):
                return value
    return None


__all__ = [
    "ApiCall",
    "NatSentinelUids",
    "resolve_nat_sentinel_uids",
    "reset_nat_sentinel_cache",
]
