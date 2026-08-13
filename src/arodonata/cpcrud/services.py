"""Service string spec parsing and deterministic naming (FPCR ServiceMatcher grammar)."""

from __future__ import annotations

import re
from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field

from .naming import DEFAULT_PREFIXES, NamingPrefixes

_TCP_UDP_SLASH_OR_UNDERSCORE = re.compile(r"^(TCP|UDP)[/_](\d+(?:-\d+)?)$", re.IGNORECASE)
_TCP_UDP_GLUED = re.compile(r"^(TCP|UDP)(\d+(?:-\d+)?)$", re.IGNORECASE)
_BARE_PORT = re.compile(r"^\d+(?:-\d+)?$")
_ICMP = re.compile(r"^icmp(?:/(\d+)(?::(\d+))?)?$", re.IGNORECASE)


class ServiceSpec(BaseModel):
    kind: Literal["any", "named", "tcp", "udp", "icmp"]
    name: str | None = None  # for "named"
    port: str | None = None  # for tcp/udp: "22" or "2000-2026"
    icmp_type: int | None = None
    icmp_code: int | None = None


def _validate_range(port: str) -> None:
    if "-" not in port:
        return
    start_s, end_s = port.split("-", 1)
    start, end = int(start_s), int(end_s)
    if start >= end:
        raise ValueError(f"invalid port range {port!r}: start must be less than end")


def parse_service_spec(text: str) -> ServiceSpec:
    """Parse a rule-service string per FPCR ServiceMatcher grammar.

    Order matters: any -> tcp/udp explicit protocol -> bare port (defaults tcp)
    -> icmp -> named (fallback, resolved by exact-name lookup only, never auto-created).
    """
    stripped = text.strip()
    if stripped.lower() == "any":
        return ServiceSpec(kind="any")

    for pattern in (_TCP_UDP_SLASH_OR_UNDERSCORE, _TCP_UDP_GLUED):
        m = pattern.match(stripped)
        if m:
            proto, port = m.group(1).lower(), m.group(2)
            _validate_range(port)
            return ServiceSpec(kind=proto, port=port)  # type: ignore[arg-type]

    if _BARE_PORT.match(stripped):
        _validate_range(stripped)
        return ServiceSpec(kind="tcp", port=stripped)

    m = _ICMP.match(stripped)
    if m:
        icmp_type = int(m.group(1)) if m.group(1) is not None else None
        icmp_code = int(m.group(2)) if m.group(2) is not None else None
        return ServiceSpec(kind="icmp", icmp_type=icmp_type, icmp_code=icmp_code)

    return ServiceSpec(kind="named", name=stripped)


def auto_service_name(spec: ServiceSpec, prefixes: NamingPrefixes | None = None) -> str:
    """Deterministic name for an auto-created service (never used for kind='named')."""
    p = prefixes or DEFAULT_PREFIXES
    if spec.kind == "tcp":
        return f"{p.svc_tcp}{spec.port}"
    if spec.kind == "udp":
        return f"{p.svc_udp}{spec.port}"
    if spec.kind == "icmp":
        if spec.icmp_code is not None:
            return f"{p.svc_icmp}{spec.icmp_type}_{spec.icmp_code}"
        return f"{p.svc_icmp}{spec.icmp_type}"
    raise ValueError(f"cannot auto-name a service spec of kind {spec.kind!r}")


class _ServiceStateReader(Protocol):
    async def get_service(self, spec: ServiceSpec, original_text: str, *, mgmt: str, domain: str) -> Any: ...


class ServiceResolution(BaseModel):
    outcome: Literal["any", "match", "create", "error"]
    uid: str | None = None
    name: str = ""
    type: str = ""
    command: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    message: str = ""


_CREATE_COMMAND = {"tcp": "add-service-tcp", "udp": "add-service-udp", "icmp": "add-service-icmp"}


def _create_payload(spec: ServiceSpec, name: str) -> dict[str, Any]:
    if spec.kind in ("tcp", "udp"):
        return {"name": name, "port": spec.port}
    if spec.kind == "icmp":
        payload: dict[str, Any] = {"name": name, "icmp-type": spec.icmp_type}
        if spec.icmp_code is not None:
            payload["icmp-code"] = spec.icmp_code
        return payload
    raise ValueError(f"cannot build a create payload for kind {spec.kind!r}")


async def resolve_service(
    reader: _ServiceStateReader, text: str, *, mgmt: str, domain: str, prefixes: NamingPrefixes | None = None
) -> ServiceResolution:
    """Find-or-create decision for one rule-service entry (FPCR ServiceMatcher + ServiceValidator).

    Format check (pure, from parse_service_spec) happens before any API call. Named services
    (kind='named') are never auto-created -- an unresolved name is a plan-time error directing
    the user to SmartConsole.
    """
    try:
        spec = parse_service_spec(text)
    except ValueError as exc:
        return ServiceResolution(outcome="error", message=str(exc))

    if spec.kind == "any":
        return ServiceResolution(outcome="any", name="Any")

    existing = await reader.get_service(spec, text, mgmt=mgmt, domain=domain)
    if existing is not None:
        return ServiceResolution(outcome="match", uid=existing.uid, name=existing.name, type=existing.type)

    if spec.kind == "named":
        return ServiceResolution(
            outcome="error",
            message=f"service '{text}' not found and named services are never auto-created; "
            "fix the name or create it in SmartConsole",
        )

    name = auto_service_name(spec, prefixes)
    return ServiceResolution(
        outcome="create",
        name=name,
        type=f"{spec.kind}-service",
        command=_CREATE_COMMAND[spec.kind],
        payload=_create_payload(spec, name),
    )
