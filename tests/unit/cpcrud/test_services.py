"""Service string spec parsing (FPCR ServiceMatcher grammar)."""

from unittest.mock import AsyncMock

import pytest

from arodonata.cpcrud.models import ObjectState
from arodonata.cpcrud.naming import NamingPrefixes
from arodonata.cpcrud.services import (
    ServiceSpec,
    auto_service_name,
    parse_service_spec,
    resolve_service,
)


def test_any_is_literal():
    spec = parse_service_spec("any")
    assert spec.kind == "any"


@pytest.mark.parametrize("text", ["TCP/22", "TCP_22", "TCP22", "tcp/22"])
def test_tcp_port_formats(text):
    spec = parse_service_spec(text)
    assert spec.kind == "tcp"
    assert spec.port == "22"


@pytest.mark.parametrize("text", ["UDP/53", "UDP_53", "udp53"])
def test_udp_port_formats(text):
    spec = parse_service_spec(text)
    assert spec.kind == "udp"
    assert spec.port == "53"


def test_bare_port_defaults_to_tcp():
    spec = parse_service_spec("22")
    assert spec.kind == "tcp"
    assert spec.port == "22"


def test_tcp_port_range():
    spec = parse_service_spec("2000-2026")
    assert spec.kind == "tcp"
    assert spec.port == "2000-2026"


def test_explicit_protocol_port_range():
    spec = parse_service_spec("UDP/2000-2026")
    assert spec.kind == "udp"
    assert spec.port == "2000-2026"


def test_invalid_range_start_not_less_than_end_raises():
    with pytest.raises(ValueError, match="range"):
        parse_service_spec("2026-2000")


def test_invalid_range_equal_bounds_raises():
    with pytest.raises(ValueError, match="range"):
        parse_service_spec("2000-2000")


def test_icmp_bare():
    spec = parse_service_spec("icmp")
    assert spec.kind == "icmp"
    assert spec.icmp_type is None
    assert spec.icmp_code is None


def test_icmp_with_type():
    spec = parse_service_spec("icmp/8")
    assert spec.kind == "icmp"
    assert spec.icmp_type == 8
    assert spec.icmp_code is None


def test_icmp_with_type_and_code():
    spec = parse_service_spec("icmp/8:0")
    assert spec.kind == "icmp"
    assert spec.icmp_type == 8
    assert spec.icmp_code == 0


def test_named_service_falls_through():
    spec = parse_service_spec("https")
    assert spec.kind == "named"
    assert spec.name == "https"


def test_named_service_original_text_preserved_case():
    spec = parse_service_spec("tcp_22_custom")  # doesn't match TCP_<digits> exactly -> named
    assert spec.kind == "named"
    assert spec.name == "tcp_22_custom"


def test_auto_name_tcp():
    assert auto_service_name(ServiceSpec(kind="tcp", port="22")) == "TCP_22"


def test_auto_name_tcp_range():
    assert auto_service_name(ServiceSpec(kind="udp", port="2000-2026")) == "UDP_2000-2026"


def test_auto_name_icmp_type_only():
    assert auto_service_name(ServiceSpec(kind="icmp", icmp_type=8)) == "ICMP_8"


def test_auto_name_icmp_type_and_code():
    assert auto_service_name(ServiceSpec(kind="icmp", icmp_type=8, icmp_code=0)) == "ICMP_8_0"


@pytest.mark.asyncio
async def test_resolve_service_any_is_literal_no_lookup():
    reader = AsyncMock()
    result = await resolve_service(reader, "any", mgmt="m", domain="d")
    assert result.outcome == "any"
    reader.get_service.assert_not_awaited()


@pytest.mark.asyncio
async def test_resolve_service_match_existing_by_name():
    reader = AsyncMock()
    reader.get_service.return_value = ObjectState(uid="u1", name="https", type="tcp-service", raw={})
    result = await resolve_service(reader, "https", mgmt="m", domain="d")
    assert result.outcome == "match"
    assert result.uid == "u1"
    assert result.name == "https"


@pytest.mark.asyncio
async def test_resolve_service_named_not_found_is_error_never_auto_created():
    reader = AsyncMock()
    reader.get_service.return_value = None
    result = await resolve_service(reader, "totally_unknown_name", mgmt="m", domain="d")
    assert result.outcome == "error"
    assert "totally_unknown_name" in result.message
    assert "SmartConsole" in result.message


@pytest.mark.asyncio
async def test_resolve_service_tcp_port_not_found_is_create():
    reader = AsyncMock()
    reader.get_service.return_value = None
    result = await resolve_service(reader, "TCP/2200", mgmt="m", domain="d")
    assert result.outcome == "create"
    assert result.name == "TCP_2200"
    assert result.command == "add-service-tcp"
    assert result.payload == {"name": "TCP_2200", "port": "2200"}


@pytest.mark.asyncio
async def test_resolve_service_icmp_with_code_not_found_is_create():
    reader = AsyncMock()
    reader.get_service.return_value = None
    result = await resolve_service(reader, "icmp/8:0", mgmt="m", domain="d")
    assert result.outcome == "create"
    assert result.name == "ICMP_8_0"
    assert result.command == "add-service-icmp"
    assert result.payload == {"name": "ICMP_8_0", "icmp-type": 8, "icmp-code": 0}


@pytest.mark.asyncio
async def test_resolve_service_invalid_range_is_error_before_any_lookup():
    reader = AsyncMock()
    result = await resolve_service(reader, "2026-2000", mgmt="m", domain="d")
    assert result.outcome == "error"
    assert "range" in result.message
    reader.get_service.assert_not_awaited()  # format check happens before any lookup


def test_auto_service_name_default_prefixes_unchanged():
    assert auto_service_name(parse_service_spec("tcp/443")) == "TCP_443"
    assert auto_service_name(parse_service_spec("udp_53")) == "UDP_53"
    assert auto_service_name(parse_service_spec("icmp/8:0")) == "ICMP_8_0"


def test_auto_service_name_custom_prefixes():
    p = NamingPrefixes(svc_tcp="Tcp-", svc_udp="Udp-", svc_icmp="Icmp-")
    assert auto_service_name(parse_service_spec("tcp/443"), p) == "Tcp-443"
    assert auto_service_name(parse_service_spec("udp_53"), p) == "Udp-53"
    assert auto_service_name(parse_service_spec("icmp/8:0"), p) == "Icmp-8_0"
