"""Pure shorthand expression parser for declarative CPCRUD templates (`src/arodonata/cpcrud/expressions.py`).

Parses shorthand object, range, DNS domain, wildcard application-site, service, and inline
group expressions into schema-valid CPCRUD operation dictionaries formatted with `NamingPrefixes`.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from typing import Any

from arodonata.core.errors import ValidationError
from arodonata.cpcrud.models import NamingPrefixes

_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_PARENS_EXPR_RE = re.compile(r"^([^(]+)\((.*)\)$")


def _validate_domain_name(domain: str, *, raw_expr: str) -> str:
    clean = domain.strip()
    if not clean or "*" in clean or any(ch.isspace() for ch in clean) or "/" in clean or "\\" in clean:
        raise ValidationError(f"Invalid domain expression {raw_expr!r}.")
    if clean.startswith(".") or clean.endswith(".") or ".." in clean:
        raise ValidationError(f"Invalid domain expression {raw_expr!r}.")
    labels = clean.split(".")
    if len(labels) < 2 or not all(_DOMAIN_LABEL_RE.fullmatch(lbl) for lbl in labels):
        raise ValidationError(f"Invalid domain name {raw_expr!r}.")
    return clean


def normalize_wildcard_domain(token: str) -> str:
    """Normalize `*domain` or `*.domain` into a validated bare DNS domain string."""
    if not isinstance(token, str):
        raise ValidationError(f"Wildcard domain must be a string, got {type(token).__name__}.")
    clean = token.strip()
    if not clean:
        raise ValidationError("Wildcard domain expression cannot be empty.")
    if clean.startswith("*."):
        candidate = clean[2:]
    elif clean.startswith("*") or clean.startswith("."):
        candidate = clean[1:]
    else:
        candidate = clean
    return _validate_domain_name(candidate, raw_expr=token)


def wildcard_domain_to_cp_regex_urls(token: str) -> list[str]:
    """Convert `*domain` or `*.domain` into Check Point `url-list` regex patterns `[r'\\/domain', r'\\.domain']`."""
    domain = normalize_wildcard_domain(token)
    escaped = domain.replace(".", r"\.")
    return [f"\\/{escaped}", f"\\.{escaped}"]


def parse_range_token(token: str, *, prefixes: NamingPrefixes | None = None) -> tuple[str, str]:
    """Parse full or compressed IPv4 range expressions (`10.1.1.1-9`, `Range_10.1.1.1_9`, `10.1.1.1-10.1.1.9`)."""
    if not isinstance(token, str):
        raise ValidationError(f"Address range expression must be a string, got {type(token).__name__}.")
    eff = prefixes or NamingPrefixes()
    clean = token.strip()
    if not clean or "/" in clean or "(" in clean or ")" in clean or "*" in clean:
        raise ValidationError(f"Invalid address range expression {token!r}.")

    non_range_prefixes = {p for p in ("Net_", "Host_", eff.network, eff.host) if p and p != eff.address_range}
    for bad_prefix in non_range_prefixes:
        if clean.startswith(bad_prefix):
            raise ValidationError(f"Expression {token!r} is not an address range.")

    body = clean
    range_prefixes = sorted({p for p in (eff.address_range, "Range_", "IPR_") if p}, key=len, reverse=True)
    for r_prefix in range_prefixes:
        if body.startswith(r_prefix):
            body = body[len(r_prefix) :]
            break

    seps = sorted({s for s in ("-", "_", eff.range_separator) if s}, key=len, reverse=True)
    sep_pattern = "|".join(re.escape(s) for s in seps)
    match = re.fullmatch(
        rf"(\d{{1,3}}(?:\.\d{{1,3}}){{3}})(?:{sep_pattern})(\d{{1,3}}(?:\.\d{{1,3}}){{3}}|\d{{1,3}})",
        body,
    )
    if match is None:
        raise ValidationError(f"Invalid address range expression {token!r}.")

    first_raw, last_raw = match.group(1), match.group(2)
    try:
        first_addr = ipaddress.IPv4Address(first_raw)
    except ValueError as exc:
        raise ValidationError(f"Invalid start IPv4 address in range {token!r}: {exc}") from exc

    if "." not in last_raw:
        octet_val = int(last_raw)
        if not (0 <= octet_val <= 255):
            raise ValidationError(f"Invalid compressed end octet {last_raw!r} in range {token!r}.")
        prefix3 = str(first_addr).rsplit(".", 1)[0]
        last_candidate = f"{prefix3}.{octet_val}"
    else:
        last_candidate = last_raw

    try:
        last_addr = ipaddress.IPv4Address(last_candidate)
    except ValueError as exc:
        raise ValidationError(f"Invalid end IPv4 address in range {token!r}: {exc}") from exc

    if int(first_addr) > int(last_addr):
        raise ValidationError(f"Address range start {first_addr} exceeds end {last_addr} in {token!r}.")

    return str(first_addr), str(last_addr)


def parse_app_site_expression(expr: str, *, prefixes: NamingPrefixes | None = None) -> dict[str, Any]:
    """Parse `*domain`, `*.domain`, or `SiteName(*d1, *.d2)` into a CPCRUD `application-site` spec."""
    if not isinstance(expr, str):
        raise ValidationError(f"Application-site expression must be a string, got {type(expr).__name__}.")
    eff = prefixes or NamingPrefixes()
    clean = expr.strip()
    if not clean:
        raise ValidationError("Application-site expression cannot be empty.")

    if clean.startswith("*"):
        domain = normalize_wildcard_domain(clean)
        return {
            "type": "application-site",
            "name": eff.format_app_site(domain, is_wildcard=True),
            "primary-category": "Custom_Application_Site",
            "urls-defined-as-regular-expression": True,
            "url-list": wildcard_domain_to_cp_regex_urls(domain),
        }

    match = _PARENS_EXPR_RE.fullmatch(clean)
    if match is None:
        raise ValidationError(f"Invalid application-site expression {expr!r}.")

    site_name = match.group(1).strip()
    raw_args = match.group(2).strip()
    if not site_name or "*" in site_name or any(ch.isspace() for ch in site_name):
        raise ValidationError(f"Invalid application-site name {site_name!r} in {expr!r}.")
    if not raw_args:
        raise ValidationError(f"Application-site expression {expr!r} requires at least one URL/domain entry.")

    items = [part.strip() for part in raw_args.split(",")]
    if any(not item for item in items):
        raise ValidationError(f"Empty URL entry in application-site expression {expr!r}.")

    has_wildcard = [item.startswith("*") for item in items]
    if any(has_wildcard) and not all(has_wildcard):
        raise ValidationError(
            f"Cannot mix wildcard ('*domain') and plain URL entries in application-site expression {expr!r}."
        )

    if all(has_wildcard):
        urls: list[str] = []
        for item in items:
            urls.extend(wildcard_domain_to_cp_regex_urls(item))
        dedup_urls = list(dict.fromkeys(urls))
        is_regex = True
    else:
        for item in items:
            if "*" in item or any(ch.isspace() for ch in item):
                raise ValidationError(f"Invalid URL entry {item!r} in application-site expression {expr!r}.")
        dedup_urls = list(dict.fromkeys(items))
        is_regex = False

    return {
        "type": "application-site",
        "name": site_name,
        "primary-category": "Custom_Application_Site",
        "urls-defined-as-regular-expression": is_regex,
        "url-list": dedup_urls,
    }


def _validate_port_spec(raw_port: str, *, raw_expr: str) -> str:
    clean = raw_port.strip()
    if re.fullmatch(r"\d+", clean):
        port_num = int(clean)
        if not (1 <= port_num <= 65535):
            raise ValidationError(f"Port {port_num} out of range 1..65535 in {raw_expr!r}.")
        return str(port_num)
    range_match = re.fullmatch(r"(\d+)-(\d+)", clean)
    if range_match is not None:
        low, high = int(range_match.group(1)), int(range_match.group(2))
        if not (1 <= low <= high <= 65535):
            raise ValidationError(f"Port range {clean!r} out of range 1..65535 in {raw_expr!r}.")
        return f"{low}-{high}"
    raise ValidationError(f"Invalid port specification {raw_port!r} in {raw_expr!r}.")


def parse_service_expression(expr: str, *, prefixes: NamingPrefixes | None = None) -> dict[str, Any]:
    """Parse TCP, UDP, or ICMP shorthand service expressions into CPCRUD `ServiceOperation` dicts."""
    if not isinstance(expr, str):
        raise ValidationError(f"Service expression must be a string, got {type(expr).__name__}.")
    eff = prefixes or NamingPrefixes()
    clean = expr.strip()
    if not clean:
        raise ValidationError("Service expression cannot be empty.")

    # tcp/443, tcp:443, udp/53, udp:53, tcp/8080-8090
    proto_port = re.fullmatch(r"(tcp|udp)[/:](\d+(?:-\d+)?)", clean, flags=re.IGNORECASE)
    if proto_port is not None:
        proto = proto_port.group(1).lower()
        port_str = _validate_port_spec(proto_port.group(2), raw_expr=expr)
        if proto == "tcp":
            return {"type": "service-tcp", "name": eff.format_tcp(port_str), "port": port_str}
        return {"type": "service-udp", "name": eff.format_udp(port_str), "port": port_str}

    # 443/tcp, 53/udp, 8080-8090/tcp
    port_proto = re.fullmatch(r"(\d+(?:-\d+)?)/(tcp|udp)", clean, flags=re.IGNORECASE)
    if port_proto is not None:
        port_str = _validate_port_spec(port_proto.group(1), raw_expr=expr)
        proto = port_proto.group(2).lower()
        if proto == "tcp":
            return {"type": "service-tcp", "name": eff.format_tcp(port_str), "port": port_str}
        return {"type": "service-udp", "name": eff.format_udp(port_str), "port": port_str}

    # Named TCP_<port> / UDP_<port> or custom prefix
    for prefix in sorted({p for p in (eff.tcp, "TCP_") if p}, key=len, reverse=True):
        if clean.startswith(prefix):
            port_str = _validate_port_spec(clean[len(prefix) :], raw_expr=expr)
            return {"type": "service-tcp", "name": eff.format_tcp(port_str), "port": port_str}

    for prefix in sorted({p for p in (eff.udp, "UDP_") if p}, key=len, reverse=True):
        if clean.startswith(prefix):
            port_str = _validate_port_spec(clean[len(prefix) :], raw_expr=expr)
            return {"type": "service-udp", "name": eff.format_udp(port_str), "port": port_str}

    # ICMP: icmp/8, icmp/8/0, icmp:8, icmp:8:0, ICMP_8, ICMP_8_0
    icmp_match = re.fullmatch(r"icmp[/:](\d+)(?:[/:](\d+))?", clean, flags=re.IGNORECASE)
    if icmp_match is None:
        for prefix in sorted({p for p in (eff.icmp, "ICMP_") if p}, key=len, reverse=True):
            if clean.startswith(prefix):
                icmp_match = re.fullmatch(r"(\d+)(?:_(\d+))?", clean[len(prefix) :])
                if icmp_match is not None:
                    break
                raise ValidationError(f"Invalid ICMP service expression {expr!r}.")

    if icmp_match is not None:
        icmp_type = int(icmp_match.group(1))
        icmp_code = int(icmp_match.group(2)) if icmp_match.group(2) is not None else None
        if not (0 <= icmp_type <= 255):
            raise ValidationError(f"ICMP type {icmp_type} out of range 0..255 in {expr!r}.")
        if icmp_code is not None and not (0 <= icmp_code <= 255):
            raise ValidationError(f"ICMP code {icmp_code} out of range 0..255 in {expr!r}.")
        spec: dict[str, Any] = {
            "type": "service-icmp",
            "name": eff.format_icmp(icmp_type, icmp_code),
            "icmp-type": icmp_type,
        }
        if icmp_code is not None:
            spec["icmp-code"] = icmp_code
        return spec

    raise ValidationError(f"Unrecognized CPCRUD service expression: {expr!r}.")


def _split_top_level_csv(raw_args: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    buf: list[str] = []
    for ch in raw_args:
        if ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth -= 1
            if depth < 0:
                raise ValidationError(f"Unbalanced parentheses in group members {raw_args!r}.")
            buf.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if depth != 0:
        raise ValidationError(f"Unbalanced parentheses in group members {raw_args!r}.")
    parts.append("".join(buf).strip())
    return parts


def _looks_like_app_site_url_or_domain(token: str, eff: NamingPrefixes) -> bool:
    clean = token.strip()
    if not clean or clean.startswith("."):
        return False
    reserved_prefixes = {p for p in (eff.host, eff.network, eff.address_range, "Host_", "Net_", "IPR_") if p}
    if any(clean.startswith(pref) for pref in reserved_prefixes):
        return False
    if "://" in clean:
        return True
    return "." in clean and any(ch.isalpha() for ch in clean)


def _is_parenthesized_app_site(
    raw_name: str,
    arg_tokens: Sequence[str],
    eff: NamingPrefixes,
) -> bool:
    if not arg_tokens or any("(" in tok or ")" in tok for tok in arg_tokens):
        return False
    if any(tok.startswith("*") for tok in arg_tokens):
        return True
    if all("://" in tok for tok in arg_tokens):
        return True
    if bool(eff.app_site) and raw_name.startswith(eff.app_site):
        return all(_looks_like_app_site_url_or_domain(tok, eff) for tok in arg_tokens)
    return False


def expand_group_expression(
    expr: str,
    *,
    prefixes: NamingPrefixes | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse `GroupName(m1, m2)` into `(member_object_specs, group_spec)` formatted with `NamingPrefixes`."""
    if not isinstance(expr, str):
        raise ValidationError(f"Group expression must be a string, got {type(expr).__name__}.")
    eff = prefixes or NamingPrefixes()
    clean = expr.strip()
    match = _PARENS_EXPR_RE.fullmatch(clean)
    if match is None:
        raise ValidationError(f"Invalid inline group expression {expr!r}.")

    raw_name = match.group(1).strip()
    raw_members = match.group(2).strip()
    if not raw_name or "*" in raw_name or any(ch.isspace() for ch in raw_name):
        raise ValidationError(f"Invalid group name {raw_name!r} in {expr!r}.")
    if not raw_members:
        raise ValidationError(f"Inline group expression {expr!r} requires at least one member.")

    member_tokens = _split_top_level_csv(raw_members)
    if any(not tok for tok in member_tokens):
        raise ValidationError(f"Empty member entry in group expression {expr!r}.")

    member_names: list[str] = []
    member_objects: list[dict[str, Any]] = []
    seen_members: set[str] = set()
    seen_obj_keys: set[tuple[str, str]] = set()

    def _append_member_object(obj_spec: dict[str, Any]) -> None:
        obj_key = (str(obj_spec["type"]), str(obj_spec["name"]))
        if obj_key not in seen_obj_keys:
            seen_obj_keys.add(obj_key)
            member_objects.append(obj_spec)

    for tok in member_tokens:
        if "(" in tok or ")" in tok:
            inner_match = _PARENS_EXPR_RE.fullmatch(tok)
            if inner_match is None:
                raise ValidationError(f"Malformed parenthesized expression {tok!r} in {expr!r}.")
            inner_name = inner_match.group(1).strip()
            inner_raw_args = inner_match.group(2).strip()
            inner_args = _split_top_level_csv(inner_raw_args) if inner_raw_args else []
            if _is_parenthesized_app_site(inner_name, inner_args, eff):
                parsed_app = parse_app_site_expression(tok, prefixes=eff)
                _append_member_object(parsed_app)
                resolved_name = str(parsed_app["name"])
            else:
                nested_objs, nested_grp = expand_group_expression(tok, prefixes=eff)
                for nested_obj in nested_objs:
                    _append_member_object(nested_obj)
                _append_member_object(nested_grp)
                resolved_name = str(nested_grp["name"])
        else:
            try:
                parsed_obj = parse_object_expression(tok, prefixes=eff)
            except ValidationError:
                resolved_name = tok
            else:
                resolved_name = str(parsed_obj["name"])
                _append_member_object(parsed_obj)

        if resolved_name not in seen_members:
            seen_members.add(resolved_name)
            member_names.append(resolved_name)

    group_spec: dict[str, Any] = {
        "type": "group",
        "name": eff.format_group(raw_name),
        "members": member_names,
    }
    return member_objects, group_spec


def parse_group_expression(expr: str, *, prefixes: NamingPrefixes | None = None) -> dict[str, Any]:
    """Parse `GroupName(m1, m2)` into a schema-valid CPCRUD `group` dictionary."""
    _, group_spec = expand_group_expression(expr, prefixes=prefixes)
    return group_spec


def parse_object_expression(expr: str, *, prefixes: NamingPrefixes | None = None) -> dict[str, Any]:
    """Parse a shorthand host, CIDR, range, `.domain`, wildcard app-site, or inline group expression."""
    if not isinstance(expr, str):
        raise ValidationError(f"Object expression must be a string, got {type(expr).__name__}.")
    eff = prefixes or NamingPrefixes()
    clean = expr.strip()
    if not clean:
        raise ValidationError("Object expression cannot be empty.")

    # 1. Wildcard application-site (`*domain` / `*.domain`)
    if clean.startswith("*"):
        return parse_app_site_expression(clean, prefixes=eff)

    # 2. Parenthesized expression (`SiteName(*d1, *.d2)` vs `GroupName(m1, m2)`)
    if "(" in clean or ")" in clean:
        match = _PARENS_EXPR_RE.fullmatch(clean)
        if match is None:
            raise ValidationError(f"Malformed parenthesized expression {expr!r}.")
        raw_name = match.group(1).strip()
        raw_args = match.group(2).strip()
        arg_tokens = _split_top_level_csv(raw_args) if raw_args else []
        if _is_parenthesized_app_site(raw_name, arg_tokens, eff):
            return parse_app_site_expression(clean, prefixes=eff)
        return parse_group_expression(clean, prefixes=eff)

    # 3. Leading-dot DNS domain (`.abc.com`)
    if clean.startswith("."):
        _validate_domain_name(clean[1:], raw_expr=expr)
        return {
            "type": "dns-domain",
            "name": clean,
            "is_sub_domain": True,
        }

    # 4. Network CIDR (`10.1.1.0/24`) or prefixed network (`Net_10.1.1.0_24`)
    if "/" in clean:
        try:
            net = ipaddress.IPv4Network(clean, strict=True)
        except ValueError as exc:
            raise ValidationError(f"Invalid IPv4 network CIDR expression {expr!r}: {exc}") from exc
        subnet_str = str(net.network_address)
        return {
            "type": "network",
            "name": eff.format_network(subnet_str, net.prefixlen),
            "subnet4": subnet_str,
            "mask-length4": net.prefixlen,
        }

    net_prefixes = sorted({p for p in (eff.network, "Net_") if p and p != eff.address_range}, key=len, reverse=True)
    for n_prefix in net_prefixes:
        if clean.startswith(n_prefix):
            net_body = clean[len(n_prefix) :]
            net_match = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})_(\d{1,2})", net_body)
            if net_match is None:
                raise ValidationError(f"Invalid prefixed network expression {expr!r}.")
            try:
                net = ipaddress.IPv4Network(f"{net_match.group(1)}/{net_match.group(2)}", strict=True)
            except ValueError as exc:
                raise ValidationError(f"Invalid IPv4 network expression {expr!r}: {exc}") from exc
            subnet_str = str(net.network_address)
            return {
                "type": "network",
                "name": eff.format_network(subnet_str, net.prefixlen),
                "subnet4": subnet_str,
                "mask-length4": net.prefixlen,
            }

    # 5. Address range (`10.1.1.1-9`, `10.1.1.1-10.1.1.9`, `Range_10.1.1.1_9`, `IPR_10.1.1.1-10.1.1.9`)
    range_prefixes = tuple(p for p in (eff.address_range, "Range_", "IPR_") if p)
    seps = sorted({s for s in ("-", "_", eff.range_separator) if s}, key=len, reverse=True)
    sep_pattern = "|".join(re.escape(s) for s in seps)
    if clean.startswith(range_prefixes) or re.fullmatch(rf"\d+(?:\.\d+){{3}}(?:{sep_pattern})\d+(?:\.\d+)*", clean):
        first_ip, last_ip = parse_range_token(clean, prefixes=eff)
        return {
            "type": "address-range",
            "name": eff.format_address_range(first_ip, last_ip),
            "ipv4-address-first": first_ip,
            "ipv4-address-last": last_ip,
        }

    # 6. Host (`10.1.1.1`, `Host_10.1.1.1`, IPv6)
    host_body = clean
    host_prefixes = sorted({p for p in (eff.host, "Host_") if p}, key=len, reverse=True)
    for h_prefix in host_prefixes:
        if host_body.startswith(h_prefix):
            host_body = host_body[len(h_prefix) :]
            break

    ip_candidate = host_body.replace("_", ":") if ":" not in host_body and host_body.count("_") >= 2 else host_body
    try:
        addr = ipaddress.ip_address(ip_candidate)
    except ValueError as exc:
        raise ValidationError(f"Unrecognized CPCRUD object expression {expr!r}.") from exc

    ip_str = str(addr)
    if addr.version == 4:
        return {
            "type": "host",
            "name": eff.format_host(ip_str),
            "ipv4-address": ip_str,
        }
    return {
        "type": "host",
        "name": eff.format_host(ip_str),
        "ipv6-address": ip_str,
    }


__all__ = [
    "expand_group_expression",
    "normalize_wildcard_domain",
    "parse_app_site_expression",
    "parse_group_expression",
    "parse_object_expression",
    "parse_range_token",
    "parse_service_expression",
    "wildcard_domain_to_cp_regex_urls",
]
