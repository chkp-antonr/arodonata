"""Canonical Check Point object summary field registry, parser, and unified formatter (`arodonata.reports._object_summary`)."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from arodonata.reports.models import FieldDiff, ObjectChangeEntry

OBJECT_SUMMARY_TRAILER_SCALAR_KEYS: tuple[str, ...] = (
    "port",
    "protocol",
    "ip-protocol",
    "icmp-type",
    "icmp-code",
    "fqdn",
    "primary-category",
    "urls-defined-as-regular-expression",
)

OBJECT_SUMMARY_SCALAR_KEYS: tuple[str, ...] = (
    "ipv4-address",
    "ipv6-address",
    "subnet4",
    "mask-length4",
    "subnet-mask",
    "subnet6",
    "mask-length6",
    "ipv4-address-first",
    "ipv4-address-last",
    "ipv6-address-first",
    "ipv6-address-last",
    *OBJECT_SUMMARY_TRAILER_SCALAR_KEYS,
)

SUMMARY_SPLIT_RE = re.compile(
    r", (?=(?:ipv4-address|ipv6-address|subnet4|subnet6|range|range6|"
    r"port|protocol|ip-protocol|icmp-type|icmp-code|fqdn|primary-category|"
    r"urls-defined-as-regular-expression|url-list|members|description|comments)=)"
)


def _as_clean_str_list(val: Any) -> list[str]:
    if isinstance(val, list):
        return [str(x).strip() for x in val if x is not None and str(x).strip()]
    if val is not None and str(val).strip():
        return [str(val).strip()]
    return []


def build_object_summary_fields(
    source: Mapping[str, Any],
    *,
    members: Sequence[str] | None = None,
    diff_by_name: Mapping[str, FieldDiff] | None = None,
    allow_underscore_keys: bool = False,
) -> dict[str, Any]:
    """Extract canonical structured summary attributes for a non-rule Check Point object."""
    fields: dict[str, Any] = {}
    for key in OBJECT_SUMMARY_SCALAR_KEYS:
        val = source.get(key)
        if val is None and allow_underscore_keys:
            val = source.get(key.replace("-", "_"))
        if val is not None:
            fields[key] = val

    # url-list
    if diff_by_name and "url-list" in diff_by_name and isinstance(diff_by_name["url-list"].new_value, list):
        clean_urls = _as_clean_str_list(diff_by_name["url-list"].new_value)
    else:
        raw_urls = source.get("url-list")
        if raw_urls is None and allow_underscore_keys:
            raw_urls = source.get("url_list")
        clean_urls = _as_clean_str_list(raw_urls) if isinstance(raw_urls, list) else []
    if clean_urls:
        fields["url-list"] = clean_urls

    # members
    if members is not None:
        clean_members = [str(m) for m in members]
    elif diff_by_name and "members" in diff_by_name and isinstance(diff_by_name["members"].new_value, list):
        clean_members = [str(x) for x in diff_by_name["members"].new_value]
    else:
        raw_members = source.get("members")
        clean_members = _as_clean_str_list(raw_members)
    if clean_members:
        fields["members"] = clean_members

    for text_key in ("description", "comments"):
        text_val = str(source.get(text_key) or "").strip()
        if text_val:
            fields[text_key] = text_val
    return fields


def format_plain_object_summary(fields: Mapping[str, Any]) -> str:
    """Format canonical `summary_fields` into plain text."""
    parts: list[str] = []
    for addr_k in ("ipv4-address", "ipv6-address"):
        if fields.get(addr_k) is not None:
            parts.append(f"{addr_k}={fields[addr_k]}")
    if fields.get("subnet4") is not None:
        if fields.get("mask-length4") is not None:
            parts.append(f"subnet4={fields['subnet4']}/{fields['mask-length4']}")
        elif fields.get("subnet-mask") is not None:
            parts.append(f"subnet4={fields['subnet4']}/{fields['subnet-mask']}")
        else:
            parts.append(f"subnet4={fields['subnet4']}")
    if fields.get("subnet6") is not None:
        if fields.get("mask-length6") is not None:
            parts.append(f"subnet6={fields['subnet6']}/{fields['mask-length6']}")
        else:
            parts.append(f"subnet6={fields['subnet6']}")
    if fields.get("ipv4-address-first") is not None or fields.get("ipv4-address-last") is not None:
        parts.append(f"range={fields.get('ipv4-address-first') or ''}-{fields.get('ipv4-address-last') or ''}")
    if fields.get("ipv6-address-first") is not None or fields.get("ipv6-address-last") is not None:
        parts.append(f"range6={fields.get('ipv6-address-first') or ''}-{fields.get('ipv6-address-last') or ''}")
    for key in OBJECT_SUMMARY_TRAILER_SCALAR_KEYS:
        if fields.get(key) is not None:
            parts.append(f"{key}={fields[key]}")
    for list_key in ("url-list", "members"):
        vals = fields.get(list_key)
        if isinstance(vals, list) and vals:
            parts.append(f"{list_key}=[{', '.join(str(v) for v in vals)}]")
    for text_key in ("description", "comments"):
        text_val = str(fields.get(text_key) or "").strip()
        if text_val:
            parts.append(f"{text_key}={text_val}")
    return ", ".join(parts)


def parse_object_summary_clauses(oc: ObjectChangeEntry) -> dict[str, Any]:
    """Extract `summary_fields` from `oc.summary_fields` or by splitting `oc.summary`."""
    if oc.summary_fields:
        return dict(oc.summary_fields)
    fields: dict[str, Any] = {}
    if not oc.summary:
        return fields
    for raw_clause in SUMMARY_SPLIT_RE.split(oc.summary):
        if "=" not in raw_clause:
            fields.setdefault("_raw", raw_clause)
            continue
        k, v = raw_clause.split("=", 1)
        key = k.strip()
        if key == "subnet4" and "/" in v:
            net4, mask4 = v.split("/", 1)
            fields["subnet4"] = net4
            fields["mask-length4" if mask4.isdigit() else "subnet-mask"] = mask4
        elif key == "subnet6" and "/" in v:
            net6, mask6 = v.split("/", 1)
            fields["subnet6"] = net6
            fields["mask-length6"] = mask6
        elif key == "range" and "-" in v:
            f4, l4 = v.split("-", 1)
            fields["ipv4-address-first"] = f4
            fields["ipv4-address-last"] = l4
        elif key == "range6" and "-" in v:
            f6, l6 = v.split("-", 1)
            fields["ipv6-address-first"] = f6
            fields["ipv6-address-last"] = l6
        elif key in ("url-list", "members") and v.startswith("[") and v.endswith("]"):
            fields[key] = [x.strip() for x in v[1:-1].split(",") if x.strip()]
        else:
            fields[key] = v
    return fields


def render_object_details_with_diffs(
    oc: ObjectChangeEntry,
    *,
    render_scalar: Callable[[Any, FieldDiff | None], str],
    render_list: Callable[[list[str], FieldDiff | None], str],
    esc: Callable[[Any], str],
) -> str:
    """Render an object's canonical summary fields + extra field diffs for HTML/Markdown cells."""
    diffs_by_name: dict[str, FieldDiff] = (
        {d.field_name.strip().lower(): d for d in oc.field_diffs} if oc.operation == "modified" else {}
    )
    sfields = parse_object_summary_clauses(oc)
    if not sfields and not diffs_by_name:
        return esc(oc.summary)

    rendered_fields: set[str] = set()
    parts: list[str] = []

    def _scalar_val(field_key: str) -> str:
        val = sfields.get(field_key)
        d = diffs_by_name.get(field_key)
        rendered_fields.add(field_key)
        return render_scalar(val, d)

    for addr_k in ("ipv4-address", "ipv6-address"):
        if addr_k in sfields or addr_k in diffs_by_name:
            parts.append(f"{esc(addr_k)}={_scalar_val(addr_k)}")

    if any(k in sfields or k in diffs_by_name for k in ("subnet4", "mask-length4", "subnet-mask")):
        net4_s = _scalar_val("subnet4") if ("subnet4" in sfields or "subnet4" in diffs_by_name) else ""
        if "mask-length4" in sfields or "mask-length4" in diffs_by_name:
            mask4_s = _scalar_val("mask-length4")
            parts.append(f"subnet4={net4_s}/{mask4_s}" if net4_s else f"mask-length4={mask4_s}")
        elif "subnet-mask" in sfields or "subnet-mask" in diffs_by_name:
            smask_s = _scalar_val("subnet-mask")
            parts.append(f"subnet4={net4_s}/{smask_s}" if net4_s else f"subnet-mask={smask_s}")
        else:
            parts.append(f"subnet4={net4_s}")

    if any(k in sfields or k in diffs_by_name for k in ("subnet6", "mask-length6")):
        net6_s = _scalar_val("subnet6") if ("subnet6" in sfields or "subnet6" in diffs_by_name) else ""
        if "mask-length6" in sfields or "mask-length6" in diffs_by_name:
            mask6_s = _scalar_val("mask-length6")
            parts.append(f"subnet6={net6_s}/{mask6_s}" if net6_s else f"mask-length6={mask6_s}")
        else:
            parts.append(f"subnet6={net6_s}")

    if any(k in sfields or k in diffs_by_name for k in ("ipv4-address-first", "ipv4-address-last")):
        parts.append(f"range={_scalar_val('ipv4-address-first')}-{_scalar_val('ipv4-address-last')}")

    if any(k in sfields or k in diffs_by_name for k in ("ipv6-address-first", "ipv6-address-last")):
        parts.append(f"range6={_scalar_val('ipv6-address-first')}-{_scalar_val('ipv6-address-last')}")

    for k in OBJECT_SUMMARY_TRAILER_SCALAR_KEYS:
        if k in sfields or k in diffs_by_name:
            parts.append(f"{esc(k)}={_scalar_val(k)}")

    for list_k in ("url-list", "members"):
        if list_k in sfields or list_k in diffs_by_name:
            ldiff = diffs_by_name.get(list_k)
            raw_l = sfields.get(list_k)
            curr_l = (
                [str(x) for x in ldiff.new_value]
                if (ldiff is not None and isinstance(ldiff.new_value, list))
                else ([str(x) for x in raw_l] if isinstance(raw_l, list) else [])
            )
            parts.append(f"{list_k}=[{render_list(curr_l, ldiff)}]")
            rendered_fields.add(list_k)

    for text_k in ("description", "comments"):
        if text_k in sfields or text_k in diffs_by_name:
            parts.append(f"{text_k}={_scalar_val(text_k)}")

    if "_raw" in sfields:
        parts.append(esc(sfields["_raw"]))

    for d in oc.field_diffs:
        low_f = d.field_name.strip().lower()
        if low_f in rendered_fields or low_f == "name":
            continue
        rendered_fields.add(low_f)
        if low_f in ("members", "groups", "tags", "url-list") or d.added_items or d.removed_items:
            curr_l = [str(x) for x in d.new_value] if isinstance(d.new_value, list) else []
            parts.append(f"{esc(d.field_name)}=[{render_list(curr_l, d)}]")
        else:
            parts.append(f"{esc(d.field_name)}={render_scalar(d.new_value, d)}")

    return ", ".join(parts)
