"""Builders for show-changes session entries in the recorded shape (plan decision 5).

Bodies follow the recordings in fixtures/ (``w_A_own_sid_0.json``, R1): references are dereferenced
``{uid, name, type}`` objects, group members are bare uid strings, a modified entry is ``{old-object, new-object}``
(``new-object`` only when the object was created in the session), a deleted entry is the pre-session body.
``test_builder_shapes_match_r1_recordings`` (Task 3) pins these shapes to R1. ``position`` is optional (pass it for
added and deleted rules and for a moved rule's old/new pair, never for an unmoved modified rule — F1); positions
count within the rule's section (F2).
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from tests.unit.rulebase.fakes import domain4_snapshot

ANY = {"uid": "97aeb369-9aea-11d5-bd16-0090272ccb30", "name": "Any", "type": "CpmiAnyObject"}
ORIGINAL = {"uid": "85c0f50f-6d8a-4528-88ab-5fb11d8fe16c", "name": "Original", "type": "Global"}
POLICY_TARGETS = {"uid": "6c488338-8eec-4103-ad21-cd461ac2c476", "name": "Policy Targets", "type": "Global"}
ACCEPT = {"uid": "6c488338-8eec-4103-ad21-cd461ac2c472", "name": "Accept", "type": "RulebaseAction"}
DROP = {"uid": "6c488338-8eec-4103-ad21-cd461ac2c473", "name": "Drop", "type": "RulebaseAction"}
TRACK_NONE = {"uid": "29e53e3d-23bf-48fe-b6b1-d59bd88036f9", "name": "None", "type": "Track"}
TRACK_LOG = {"uid": "598ead32-aa42-4615-90ed-f51a5928d41d", "name": "Log", "type": "Track"}
OPTIMIZED = {"uid": "fa1aa324-a8cc-4dbd-bc04-f31fdb8abf61", "name": "Optimized", "type": "ThreatProfile"}
PUBLISHED_MS = 1790835558610  # 2026-10-01T06:19:18.610Z (w_A_after_publish_0.json)


def ref(uid: str, name: str | None = None, obj_type: str = "host") -> dict[str, Any]:
    return {"uid": uid, "name": name or uid, "type": obj_type}


def host(uid: str, name: str | None = None, ip: str = "192.0.2.10", **extra: Any) -> dict[str, Any]:
    return {
        "uid": uid,
        "name": name or uid,
        "type": "host",
        "ipv4-address": ip,
        "interfaces": [],
        "nat-settings": {"auto-rule": False},
        "comments": "",
        "color": "black",
        "tags": [],
        **extra,
    }


def group(uid: str, name: str | None = None, members: Iterable[str] = (), **extra: Any) -> dict[str, Any]:
    return {
        "uid": uid,
        "name": name or uid,
        "type": "group",
        "members": list(members),
        "comments": "",
        "color": "black",
        "tags": [],
        **extra,
    }


def section(uid: str, name: str, obj_type: str = "access-section") -> dict[str, Any]:
    return {"uid": uid, "name": name, "type": obj_type, "color": "none"}


def _at(position: int | None, body: dict[str, Any]) -> dict[str, Any]:
    """Add ``position`` like CP does: always for added/deleted rules, for a modified rule only when it moved (F1)."""
    return body if position is None else {**body, "position": position}


def _track(track: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": track,
        "per-session": False,
        "per-connection": False,
        "accounting": False,
        "enable-firewall-session": False,
        "alert": "none",
    }


def access_rule(
    uid: str,
    name: str,
    *,
    layer: str,
    position: int | None = None,
    source: Iterable[dict[str, Any]] = (ANY,),
    destination: Iterable[dict[str, Any]] = (ANY,),
    service: Iterable[dict[str, Any]] = (ANY,),
    action: dict[str, Any] = ACCEPT,
    track: dict[str, Any] = TRACK_NONE,
    enabled: bool = True,
    comments: str = "",
    **extra: Any,
) -> dict[str, Any]:
    return _at(
        position,
        {
            "uid": uid,
            "name": name,
            "type": "access-rule",
            "track": _track(track),
            "layer": layer,
            "source": list(source),
            "source-negate": False,
            "destination": list(destination),
            "destination-negate": False,
            "service": list(service),
            "service-negate": False,
            "service-resource": "",
            "vpn": [ANY],
            "action": action,
            "action-settings": {"enable-identity-captive-portal": False},
            "content": [ANY],
            "content-negate": False,
            "content-direction": "any",
            "time": [ANY],
            "custom-fields": {"field-1": "", "field-2": "", "field-3": ""},
            "comments": comments,
            "enabled": enabled,
            "install-on": [POLICY_TARGETS],
            "tags": [],
            **extra,
        },
    )


def threat_rule(
    uid: str, *, layer: str, position: int | None = None, name: str | None = None, **extra: Any
) -> dict[str, Any]:
    body = _at(
        position,
        {
            "uid": uid,
            "type": "threat-rule",
            "layer": layer,
            "action": OPTIMIZED,
            "protected-scope": [ANY],
            "protected-scope-negate": False,
            "source": [ANY],
            "source-negate": False,
            "destination": [ANY],
            "destination-negate": False,
            "service": [ANY],
            "service-negate": False,
            "track": TRACK_LOG,
            "track-settings": {"packet-capture": True, "forensics": True},
            "exceptions-layer": "exceptions-layer-uid",
            "install-on": [POLICY_TARGETS],
            "comments": "",
            "enabled": True,
            "tags": [],
            **extra,
        },
    )
    if name is not None:
        body["name"] = name
    return body


def nat_rule(uid: str, name: str, *, layer: str, position: int | None = None, **extra: Any) -> dict[str, Any]:
    """``layer`` goes into ``package``: NAT bodies name the show-nat-rulebase uid there (R1)."""
    return _at(
        position,
        {
            "uid": uid,
            "name": name,
            "type": "nat-rule",
            "package": layer,
            "method": "static",
            "auto-generated": False,
            "original-source": ANY,
            "original-destination": ANY,
            "original-service": ANY,
            "translated-source": ORIGINAL,
            "translated-destination": ORIGINAL,
            "translated-service": ORIGINAL,
            "install-on": [POLICY_TARGETS],
            "comments": "",
            "enabled": True,
            "tags": [],
            **extra,
        },
    )


def https_rule(uid: str, name: str, *, layer: str, position: int | None = None, **extra: Any) -> dict[str, Any]:
    return _at(
        position,
        {
            "uid": uid,
            "name": name,
            "type": "https-rule",
            "layer": layer,
            "source": [ANY],
            "source-negate": False,
            "destination": [ANY],
            "destination-negate": False,
            "service": [ANY],
            "service-negate": False,
            "site-category": [ANY],
            "site-category-negate": False,
            "action": ref("bypass", "Bypass", "RulebaseAction"),
            "track": TRACK_NONE,
            "blade": [ANY],
            "certificate": ref("cert", "Outbound Certificate", "CpmiOutboundCertificate"),
            "owner": layer,
            "install-on": [POLICY_TARGETS],
            "comments": "",
            "enabled": True,
            "tags": [],
            **extra,
        },
    )


def modified(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    return {"old-object": old, "new-object": new}


def created(new: dict[str, Any]) -> dict[str, Any]:
    """A modified-objects entry for an object created in the same session (no old-object)."""
    return {"new-object": new}


def session_meta(
    uid: str,
    *,
    name: str | None = None,
    published: bool = True,
    posix_ms: int = PUBLISHED_MS,
    domain: str = "Domain4",
    user: str = "admin",
    description: str = "",
) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "session-uid": uid,
        "session-name": name or uid,
        "session-description": description,
        "user-name": user,
        "published": published,
        "domain-info": {"uid": f"{domain}-uid", "name": domain, "domain-type": "domain"},
    }
    if published:
        iso = datetime.fromtimestamp(posix_ms / 1000, UTC).strftime("%Y-%m-%dT%H:%M+0000")
        meta["publish-time"] = {"posix": posix_ms, "iso-8601": iso}
    return meta


def entry(
    meta: dict[str, Any],
    *,
    added: Iterable[dict[str, Any]] = (),
    modified: Iterable[dict[str, Any]] = (),
    deleted: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    return {
        "session": meta,
        "operations": {
            "added-objects": list(added),
            "modified-objects": list(modified),
            "deleted-objects": list(deleted),
        },
    }


def d4_rule(name: str) -> dict[str, Any]:
    """uid, layer uid and in-layer position of a Domain4 snapshot rule (tests/unit/rulebase/fakes.domain4_snapshot)."""
    for layer in domain4_snapshot().layers:
        for item in layer.items:
            if item.name == name:
                return {
                    "uid": item.uid,
                    "layer": layer.layer_uid,
                    "position": item.rule_number,
                    "inline_layer": item.inline_layer_uid,
                }
    raise KeyError(name)


def d4_layer(name: str) -> str:
    return next(layer.layer_uid for layer in domain4_snapshot().layers if layer.layer_name == name)
