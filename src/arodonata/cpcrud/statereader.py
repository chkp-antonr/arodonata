"""StateReader port and the live (API-backed) implementation."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from ..utils.helpers import extract_data_from_response, extract_objects_from_response
from .differ import _mask_to_dotted
from .models import LayerInfo, ObjectState, RuleMatch, SectionInfo
from .resolver import _TYPE_CMD
from .resolver import StateReader as StateReader  # re-export the Protocol from the resolver module
from .rule_identity import nat_tuple, traffic_tuple
from .services import auto_service_name

if TYPE_CHECKING:
    from ..api.client import ArodonataClient

_RULEBASE_PAGE_SIZE = 50

_UID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _looks_like_uid(text: str) -> bool:
    """True if `text` is shaped like a Check Point object uid (standard UUID format).

    Uses `fullmatch`, not `match` with `^`/`$` anchors -- in non-MULTILINE mode `$` matches just
    before a trailing newline, not strictly end-of-string, so a `match`-based check could
    misroute a ref with a stray trailing newline (e.g. a YAML block-scalar artifact).
    """
    return bool(_UID_RE.fullmatch(text))


async def _paginate_rulebase(
    client: Any, mgmt: str, command: str, domain: str, payload: dict[str, Any]
) -> dict[str, Any] | None:
    """Accumulate a full show-*-rulebase read across all pages.

    Confirmed against Check Point's own API reference (show-access-rulebase.j.md): "The 'limit'
    and 'offset' parameters control the number of returned results... the default limit is 50."
    A single `api_call` only ever sees the first page -- for any layer/package with more than 50
    top-level rulebase entries (rules + sections), rules beyond that silently never appear,
    breaking traffic-tuple matching (duplicate creation on re-apply), key-based lookup (a real
    rule wrongly reported "not found"), and last-rule/cleanup-rule detection.

    This deliberately does NOT reuse the codebase's `client.api_query()` wrapper: its transport
    layer hardcodes `include_container_key=False`, which discards every OTHER top-level response
    key (`objects-dictionary`, used by `_dereference_rule`/`_dereference_nat_rule`) and keeps only
    the container_key's own list -- exactly the data this dereferencing logic also needs. Looping
    `api_call` directly with explicit `offset`/`limit` (mirroring the official Check Point SDK's
    own `gen_api_query` algorithm) preserves the full per-page response so both `rulebase` and
    `objects-dictionary` can be merged across pages.
    """
    offset = 0
    merged_rulebase: list[Any] = []
    merged_dictionary: dict[str, dict[str, Any]] = {}
    combined: dict[str, Any] | None = None
    while True:
        page_payload = {**payload, "limit": _RULEBASE_PAGE_SIZE, "offset": offset}
        result = await client.api_call(mgmt, command, domain, payload=page_payload)
        if not result.success:
            return combined
        data = extract_data_from_response(result)
        if not isinstance(data, dict):
            return combined
        if combined is None:
            combined = dict(data)  # seed with the first page's non-paginated fields (uid, name, ...)
        merged_rulebase.extend(data.get("rulebase", []) or [])
        for obj in data.get("objects-dictionary", []) or []:
            if isinstance(obj, dict) and "uid" in obj:
                merged_dictionary[obj["uid"]] = obj
        total = data.get("total", 0)
        received = data.get("to", len(merged_rulebase))
        if not data.get("rulebase") or received >= total:
            break
        offset += _RULEBASE_PAGE_SIZE
    combined["rulebase"] = merged_rulebase
    combined["objects-dictionary"] = list(merged_dictionary.values())
    return combined


_SERVICE_PROBE_COMMANDS = ("show-service-tcp", "show-service-udp", "show-service-other", "show-service-icmp")
_SERVICE_PROBE_TYPE = {
    "show-service-tcp": "tcp-service",
    "show-service-udp": "udp-service",
    "show-service-other": "other-service",
    "show-service-icmp": "icmp-service",
}
_SERVICE_PORT_LIST_COMMAND = {"tcp": "show-services-tcp", "udp": "show-services-udp"}
_SERVICE_KIND_SHOW_COMMAND = {"tcp": "show-service-tcp", "udp": "show-service-udp", "icmp": "show-service-icmp"}
_LAYER_SHOW_COMMAND = {
    "access": "show-access-layer",
    "https": "show-https-layer",
    "threat-prevention": "show-threat-layer",
}
_RULEBASE_SHOW_COMMAND = {
    "access": "show-access-rulebase",
    "https": "show-https-rulebase",
    "threat-prevention": "show-threat-rulebase",
}
_SECTION_TYPE = {"access": "access-section", "https": "https-section", "threat-prevention": "threat-section"}


class LiveStateReader:
    """Reads actual object state from the live Check Point API (auto-session reads)."""

    def __init__(self, client: ArodonataClient) -> None:
        self._client = client

    async def get_by_name(self, type: str, name: str, *, mgmt: str, domain: str) -> ObjectState | None:
        # map template type -> singular show command
        suffix = _TYPE_CMD.get(type, type)
        # resolve_update/resolve_delete/resolve_show (resolver.py) collapse a template's
        # key: {name|uid} into this single string before calling here -- the ops schema
        # explicitly permits {"uid": ...} alone with no "name" (e.g. host_key/network_key,
        # minProperties: 1), so a uid-shaped value must route through "uid", not "name", or a
        # legitimate uid-only key would always report "not found" -- same bug class, same fix
        # (_looks_like_uid), as get_layer's MDS name-collision fix.
        key = "uid" if _looks_like_uid(name) else "name"
        result = await self._client.api_call(
            mgmt, f"show-{suffix}", domain, payload={key: name, "details-level": "full"}
        )
        if not result.success:
            return None
        data = extract_data_from_response(result)
        if not isinstance(data, dict) or "uid" not in data:
            return None
        return ObjectState(uid=data["uid"], name=data.get("name", name), type=type, raw=data)

    async def find_by_ip(self, *, type: str, ip_value: dict[str, Any], mgmt: str, domain: str) -> list[ObjectState]:
        # show-objects is a listing endpoint (default page limit 50, per Check Point's own API
        # reference) -- api_query auto-paginates via offset/limit until all matches are returned,
        # unlike a single api_call which would silently miss anything past the first page.
        result = await self._client.api_query(
            mgmt,
            "show-objects",
            domain,
            details_level="full",
            payload={"filter": _filter_value(ip_value), "ip-only": True},
            container_key="objects",
        )
        if not result.success:
            return []
        objects = extract_objects_from_response(result)
        matches = [o for o in objects if _ip_matches(type, ip_value, o)]
        return [
            ObjectState(uid=o.get("uid", ""), name=o.get("name", ""), type=type, raw=o) for o in matches if o.get("uid")
        ]

    async def where_used(self, uid: str, *, mgmt: str, domain: str) -> int:
        result = await self._client.api_call(mgmt, "where-used", domain, payload={"uid": uid})
        if not result.success:
            return 0
        data = extract_data_from_response(result)
        if isinstance(data, dict):
            direct = data.get("used-directly")
            if isinstance(direct, dict) and "total" in direct:
                return int(direct.get("total", 0) or 0)
            return int(data.get("total", 0) or 0)
        return 0

    async def get_last_publish_session(self, *, mgmt: str, domain: str) -> str:
        record = await self._client.refresh_last_published_session(mgmt, domain)
        return record.uid if record is not None else ""

    async def _probe_named_service(self, original_text: str, *, mgmt: str, domain: str) -> ObjectState | None:
        """Probe each `show-service-*` command by name; return the first hit, if any."""
        for command in _SERVICE_PROBE_COMMANDS:
            result = await self._client.api_call(
                mgmt, command, domain, payload={"name": original_text, "details-level": "full"}
            )
            if result.success:
                data = extract_data_from_response(result)
                if isinstance(data, dict) and "uid" in data:
                    return ObjectState(
                        uid=data["uid"],
                        name=data.get("name", original_text),
                        type=_SERVICE_PROBE_TYPE[command],
                        raw=data,
                    )
        return None

    async def _probe_canonical_service(self, spec: Any, *, mgmt: str, domain: str) -> ObjectState | None:
        """For a bare port/ICMP spec (kind != "named"), the original template text (e.g.
        "TCP/58011") is never a real object's name -- only `auto_service_name`'s canonical form
        ("TCP_58011") ever is, since that's the exact name this module uses when auto-creating
        this kind of service (services.py's resolve_service, Task 10's caller). Probe for it
        directly so a re-applied template that already auto-created this service finds it
        immediately -- cheaper than the paginated show-services-tcp/-udp fallback
        (`_probe_service_by_port`), which now correctly accumulates every page via api_query (a
        single api_call originally missed anything past the first page: confirmed live in Task 14
        that Domain4's 219 existing TCP services meant a freshly created one wasn't on page 1,
        breaking idempotency on re-apply).
        """
        kind_command = _SERVICE_KIND_SHOW_COMMAND.get(spec.kind)
        if kind_command is None:
            return None
        canonical_name = auto_service_name(spec)
        result = await self._client.api_call(
            mgmt, kind_command, domain, payload={"name": canonical_name, "details-level": "full"}
        )
        if not result.success:
            return None
        data = extract_data_from_response(result)
        if isinstance(data, dict) and "uid" in data:
            return ObjectState(
                uid=data["uid"], name=data.get("name", canonical_name), type=_SERVICE_PROBE_TYPE[kind_command], raw=data
            )
        return None

    async def _probe_service_by_port(self, spec: Any, *, mgmt: str, domain: str) -> ObjectState | None:
        list_command = _SERVICE_PORT_LIST_COMMAND.get(spec.kind)
        if list_command is None or not spec.port:
            return None
        # show-services-tcp/-udp are listing endpoints (default page limit 50) -- api_query
        # auto-paginates; a single api_call silently missed anything past the first page
        # (confirmed live in Task 14: 219 existing TCP services on the lab, a freshly created
        # one wasn't on page 1, breaking idempotency on re-apply).
        result = await self._client.api_query(
            mgmt, list_command, domain, details_level="full", payload={}, container_key="objects"
        )
        if not result.success:
            return None
        for obj in extract_objects_from_response(result):
            if obj.get("port") == spec.port and obj.get("uid"):
                return ObjectState(uid=obj["uid"], name=obj.get("name", ""), type=f"{spec.kind}-service", raw=obj)
        return None

    async def get_service(self, spec: Any, original_text: str, *, mgmt: str, domain: str) -> ObjectState | None:
        named = await self._probe_named_service(original_text, mgmt=mgmt, domain=domain)
        if named is not None:
            return named
        canonical = await self._probe_canonical_service(spec, mgmt=mgmt, domain=domain)
        if canonical is not None:
            return canonical
        return await self._probe_service_by_port(spec, mgmt=mgmt, domain=domain)

    async def get_layer(self, layer_ref: str, layer_type: str, *, mgmt: str, domain: str) -> LayerInfo | None:
        command = _LAYER_SHOW_COMMAND[layer_type]
        # A layer name can collide across domains in an MDS environment (a domain-local layer
        # and a Global-assigned layer sharing the same name -- a real, Check-Point-recognized
        # issue: SK180759/SK183697 document "More than one object named X exists" during Global
        # assignment). Looking up strictly by name has no way to disambiguate that. Check Point's
        # own API docs (add-access-rule.j.md) confirm a rule's `layer` field is "identified by
        # the name or UID" -- so a template author who already knows the exact layer's uid (e.g.
        # from SmartConsole or a prior show-access-layers listing) can put it directly in the
        # `layer` field instead of the ambiguous name, and this lookup must route it through
        # `uid`, not `name`, to actually resolve the intended layer rather than erroring or
        # (worse) silently matching an unrelated same-named one.
        key = "uid" if _looks_like_uid(layer_ref) else "name"
        result = await self._client.api_call(mgmt, command, domain, payload={key: layer_ref, "details-level": "full"})
        if not result.success:
            return None
        data = extract_data_from_response(result)
        if not isinstance(data, dict) or "uid" not in data:
            return None
        # Task 4's caveat: the field NAME "parent-layer" was a correct plan-time guess (confirmed
        # against the live lab and Check Point's own show-access-layer docs), but the VALUE shape
        # guess was wrong -- it's a bare UID STRING (e.g. "b9c8206c-..."), not a nested {"uid":
        # ...} object like the plan sketch assumed. Fixed here in Task 14 after the live run
        # showed a real inline sub-layer's parent_layer_uid silently coming back None.
        parent = data.get("parent-layer")
        parent_uid: str | None
        if isinstance(parent, str):
            parent_uid = parent
        elif isinstance(parent, dict):
            parent_uid = parent.get("uid")
        else:
            parent_uid = None
        return LayerInfo(
            uid=data["uid"], name=data.get("name", layer_ref), type=layer_type, parent_layer_uid=parent_uid
        )

    async def get_section(
        self, section_ref: str, layer_uid: str, layer_type: str, *, mgmt: str, domain: str
    ) -> SectionInfo | None:
        command = _RULEBASE_SHOW_COMMAND[layer_type]
        data = await _paginate_rulebase(
            self._client, mgmt, command, domain, {"uid": layer_uid, "details-level": "full"}
        )
        if data is None:
            return None
        items = data.get("rulebase", [])
        section_type = _SECTION_TYPE[layer_type]
        for item in items:
            if not isinstance(item, dict) or item.get("type") != section_type:
                continue
            if item.get("name") == section_ref or item.get("uid") == section_ref:
                return SectionInfo(uid=item.get("uid", ""), name=item.get("name", ""), layer_uid=layer_uid)
        return None

    async def get_last_rule(self, scope_uid: str, layer_type: str, *, mgmt: str, domain: str) -> RuleMatch | None:
        command = _RULEBASE_SHOW_COMMAND[layer_type]
        data = await _paginate_rulebase(
            self._client,
            mgmt,
            command,
            domain,
            {"uid": scope_uid, "details-level": "full", "use-object-dictionary": True},
        )
        if data is None:
            return None
        flat = _flatten_rulebase(data.get("rulebase", []))
        if not flat:
            return None
        uid_to_name = _uid_to_name_map(data)
        last = _dereference_rule(flat[-1], uid_to_name)
        return RuleMatch(
            uid=last.get("uid", ""), name=last.get("name", ""), rule_number=last.get("rule-number", 0), raw=last
        )

    async def find_rules_by_traffic(
        self,
        scope_uid: str,
        layer_type: str,
        source_uids: list[str],
        dest_uids: list[str],
        service_uids: list[str],
        *,
        mgmt: str,
        domain: str,
    ) -> list[RuleMatch]:
        command = _RULEBASE_SHOW_COMMAND[layer_type]
        data = await _paginate_rulebase(
            self._client,
            mgmt,
            command,
            domain,
            {"uid": scope_uid, "details-level": "full", "use-object-dictionary": True},
        )
        if data is None:
            return []
        uid_to_name = _uid_to_name_map(data)
        target = traffic_tuple(source_uids, dest_uids, service_uids)
        matches = []
        for raw_rule in _flatten_rulebase(data.get("rulebase", [])):
            rule = _dereference_rule(raw_rule, uid_to_name)
            candidate = traffic_tuple(
                rule.get("source", []) or [],
                rule.get("destination", []) or [],
                rule.get("service", []) or [],
            )
            if candidate == target:
                matches.append(
                    RuleMatch(
                        uid=rule.get("uid", ""),
                        name=rule.get("name", ""),
                        rule_number=rule.get("rule-number", 0),
                        raw=rule,
                    )
                )
        return matches

    async def find_nat_rules_by_tuple(
        self, package: str, tup: tuple[str, str, str, str, str, str], *, mgmt: str, domain: str
    ) -> list[RuleMatch]:
        data = await _paginate_rulebase(
            self._client,
            mgmt,
            "show-nat-rulebase",
            domain,
            {"package": package, "details-level": "full", "use-object-dictionary": True},
        )
        if data is None:
            return []
        uid_to_name = _uid_to_name_map(data)
        matches = []
        # NAT rules nest inside nat-section items exactly like access rules nest inside
        # access-sections (confirmed against the live lab -- every NAT package on the lab put
        # all its rules under nat-sections, none at the rulebase's top level) -- _flatten_rulebase
        # already recurses generically ("nat-rule".endswith("-rule") too), so reuse it here
        # instead of the flat top-level scan Task 12's original sketch used, which silently never
        # matched anything on a real server.
        for raw_rule in _flatten_rulebase(data.get("rulebase", [])):
            if raw_rule.get("type") != "nat-rule":
                continue
            rule = _dereference_nat_rule(raw_rule, uid_to_name)
            candidate = nat_tuple(
                rule.get("original-source", ""),
                rule.get("original-destination", ""),
                rule.get("original-service", ""),
                rule.get("translated-source", ""),
                rule.get("translated-destination", ""),
                rule.get("translated-service", ""),
            )
            if candidate == tup:
                matches.append(
                    RuleMatch(
                        uid=rule.get("uid", ""),
                        name=rule.get("name", ""),
                        rule_number=rule.get("rule-number", 0),
                        raw=rule,
                    )
                )
        return matches

    async def get_last_nat_rule(self, package: str, *, mgmt: str, domain: str) -> RuleMatch | None:
        data = await _paginate_rulebase(
            self._client,
            mgmt,
            "show-nat-rulebase",
            domain,
            {"package": package, "details-level": "full", "use-object-dictionary": True},
        )
        if data is None:
            return None
        nat_rules = [r for r in _flatten_rulebase(data.get("rulebase", [])) if r.get("type") == "nat-rule"]
        if not nat_rules:
            return None
        uid_to_name = _uid_to_name_map(data)
        last = _dereference_nat_rule(nat_rules[-1], uid_to_name)
        return RuleMatch(
            uid=last.get("uid", ""), name=last.get("name", ""), rule_number=last.get("rule-number", 0), raw=last
        )

    async def get_rule_by_key(
        self, scope_uid: str, layer_type: str, key: dict[str, Any], *, mgmt: str, domain: str
    ) -> RuleMatch | None:
        command = _RULEBASE_SHOW_COMMAND[layer_type]
        data = await _paginate_rulebase(
            self._client,
            mgmt,
            command,
            domain,
            {"uid": scope_uid, "details-level": "full", "use-object-dictionary": True},
        )
        if data is None:
            return None
        uid_to_name = _uid_to_name_map(data)
        for raw_rule in _flatten_rulebase(data.get("rulebase", [])):
            if _rule_matches_key(raw_rule, key):
                rule = _dereference_rule(raw_rule, uid_to_name)
                return RuleMatch(
                    uid=rule.get("uid", ""), name=rule.get("name", ""), rule_number=rule.get("rule-number", 0), raw=rule
                )
        return None

    async def get_nat_rule_by_key(
        self, package: str, key: dict[str, Any], *, mgmt: str, domain: str
    ) -> RuleMatch | None:
        data = await _paginate_rulebase(
            self._client,
            mgmt,
            "show-nat-rulebase",
            domain,
            {"package": package, "details-level": "full", "use-object-dictionary": True},
        )
        if data is None:
            return None
        uid_to_name = _uid_to_name_map(data)
        for raw_rule in _flatten_rulebase(data.get("rulebase", [])):
            if raw_rule.get("type") != "nat-rule":
                continue
            if _rule_matches_key(raw_rule, key):
                rule = _dereference_nat_rule(raw_rule, uid_to_name)
                return RuleMatch(
                    uid=rule.get("uid", ""), name=rule.get("name", ""), rule_number=rule.get("rule-number", 0), raw=rule
                )
        return None


def _rule_matches_key(rule: dict[str, Any], key: dict[str, Any]) -> bool:
    """Match one flattened rulebase entry against a template `key: {name|uid|rule-number}`.

    uid takes precedence when present (most specific identifier), falling back to name,
    then rule-number -- the ops schema's `access_rule_key`/`nat_rule_key` allow any one or
    more of the three (`minProperties: 1`), so this order is a deliberate choice, not
    something the schema itself mandates."""
    if "uid" in key:
        return rule.get("uid") == key["uid"]
    if "name" in key:
        return rule.get("name") == key["name"]
    if "rule-number" in key:
        return rule.get("rule-number") == key["rule-number"]
    return False


_REFERENCE_LIST_FIELDS = (
    "source",
    "destination",
    "service",
    "install-on",
    "time",
    "vpn",
    "protected-scope",  # threat-prevention-rule
    "site-category",
    "blade",  # https-rule
)
_REFERENCE_STRING_FIELDS = ("action", "certificate")  # certificate: https-rule
_NAT_REFERENCE_STRING_FIELDS = (
    "original-source",
    "original-destination",
    "original-service",
    "translated-source",
    "translated-destination",
    "translated-service",
)
_NAT_REFERENCE_LIST_FIELDS = ("install-on",)


def _uid_to_name_map(data: dict[str, Any]) -> dict[str, str]:
    """Build a uid -> name lookup from the `objects-dictionary` a rulebase read returns
    alongside the rulebase itself when queried with `use-object-dictionary: true`.

    Confirmed against the live lab (and cross-checked against Check Point's own Management
    API docs, show-access-rulebase.j.md): a plain rulebase read -- the shape Task 7 built
    against -- returns source/destination/service/action/track.type/install-on/time/vpn as
    BARE UID STRINGS, never the nested name/uid objects Task 7's caveat speculated as the
    alternative. Comparing those UIDs directly against a template's declared names (or the
    literal "Any") never matches, which silently breaks both traffic-tuple identity and the
    UNCHANGED/UPDATE field comparison -- confirmed empirically in Task 14's live run (every
    re-apply duplicated the rule instead of finding it). `use-object-dictionary: true` is the
    documented way to get a name back for each such UID without a details-level change.
    """
    mapping: dict[str, str] = {}
    for obj in data.get("objects-dictionary", []):
        if isinstance(obj, dict) and "uid" in obj:
            uid = str(obj["uid"])
            mapping[uid] = str(obj.get("name", uid))
    return mapping


def _dereference_rule(rule: dict[str, Any], uid_to_name: dict[str, str]) -> dict[str, Any]:
    """Translate an access/threat-prevention/https rule's bare-UID reference fields into their
    canonical names via `uid_to_name` (see `_uid_to_name_map`). A no-op when the dictionary is
    empty (e.g. existing unit tests that don't model `objects-dictionary` at all)."""
    if not uid_to_name:
        return rule
    out = dict(rule)
    for field in _REFERENCE_LIST_FIELDS:
        value = out.get(field)
        if isinstance(value, list):
            out[field] = [uid_to_name.get(v, v) if isinstance(v, str) else v for v in value]
    for field in _REFERENCE_STRING_FIELDS:
        value = out.get(field)
        if isinstance(value, str):
            out[field] = uid_to_name.get(value, value)
    track = out.get("track")
    if isinstance(track, dict) and isinstance(track.get("type"), str):
        out["track"] = {**track, "type": uid_to_name.get(track["type"], track["type"])}
    return out


def _dereference_nat_rule(rule: dict[str, Any], uid_to_name: dict[str, str]) -> dict[str, Any]:
    """NAT counterpart to `_dereference_rule`: the 6-tuple fields are singular strings, not
    lists (positional identity, per rule_identity.nat_tuple), so translated independently.
    `install-on` is NAT's own array-valued reference field (nat_rule_add/update's schema),
    dereferenced the same way as access-rule's `install-on`."""
    if not uid_to_name:
        return rule
    out = dict(rule)
    for field in _NAT_REFERENCE_STRING_FIELDS:
        value = out.get(field)
        if isinstance(value, str):
            out[field] = uid_to_name.get(value, value)
    for field in _NAT_REFERENCE_LIST_FIELDS:
        value = out.get(field)
        if isinstance(value, list):
            out[field] = [uid_to_name.get(v, v) if isinstance(v, str) else v for v in value]
    return out


def _flatten_rulebase(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten a rulebase response into a plain, ordered list of leaf rule dicts (sections recursed into, not returned themselves)."""
    flat: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if "rulebase" in item:  # section -- recurse
            flat.extend(_flatten_rulebase(item["rulebase"]))
        elif item.get("type", "").endswith("-rule"):
            flat.append(item)
    return flat


def _filter_value(ip_value: dict[str, Any]) -> str:
    # use the first address-like value as the substring filter; post-filtering enforces exactness
    for key in ("ip-address", "subnet", "ip-address-first"):
        if ip_value.get(key):
            return str(ip_value[key])
    return ""


def _ip_matches(type: str, ip_value: dict[str, Any], obj: dict[str, Any]) -> bool:
    if type == "host":
        return obj.get("ipv4-address") == ip_value.get("ip-address") or obj.get("ip-address") == ip_value.get(
            "ip-address"
        )
    if type == "network":
        return obj.get("subnet4") == ip_value.get("subnet") and str(
            obj.get("mask-length4", obj.get("mask-length"))
        ) == str(ip_value.get("mask-length", ""))
    if type == "address-range":
        return obj.get("ipv4-address-first") == ip_value.get("ip-address-first") and obj.get(
            "ipv4-address-last"
        ) == ip_value.get("ip-address-last")
    return False


_CACHE_TYPE = {"network-group": "group"}  # template type -> cache CPObject.type
_CACHED_TYPES = {"host", "network", "address-range", "network-group"}  # types the object cache actually indexes


def _state_from_cpobject(template_type: str, row: Any) -> ObjectState:
    raw = row.raw_data if isinstance(getattr(row, "raw_data", None), dict) else {"uid": row.uid, "name": row.name}
    return ObjectState(uid=row.uid, name=row.name, type=template_type, raw=raw)


class HybridStateReader:
    """Cache-first StateReader: object cache lookups with immediate live-API fallback.

    where-used has no cache backing yet -> always live (spec decision)."""

    def __init__(self, client: ArodonataClient) -> None:
        self._client = client
        self._live = LiveStateReader(client)

    async def get_by_name(self, type: str, name: str, *, mgmt: str, domain: str) -> ObjectState | None:
        if type not in _CACHED_TYPES:
            return await self._live.get_by_name(type, name, mgmt=mgmt, domain=domain)
        cache_type = _CACHE_TYPE.get(type, type)
        rows = await self._client.cache.get_objects_by_name(name, mgmt_names=[mgmt], domain_names=[domain])
        exact = [r for r in rows if r.name == name and r.type == cache_type]
        if exact:
            return _state_from_cpobject(type, exact[0])
        return await self._live.get_by_name(type, name, mgmt=mgmt, domain=domain)

    async def find_by_ip(self, *, type: str, ip_value: dict[str, Any], mgmt: str, domain: str) -> list[ObjectState]:
        cache_type = _CACHE_TYPE.get(type, type)
        rows: list[Any] = []
        if type == "host" and ip_value.get("ip-address"):
            rows = await self._client.cache.get_objects_by_ip(
                ip_value["ip-address"], mgmt_names=[mgmt], domain_names=[domain]
            )
        elif type == "network" and ip_value.get("subnet"):
            rows = await self._client.cache.get_objects_by_subnet(
                ip_value["subnet"], mgmt_names=[mgmt], domain_names=[domain]
            )
        elif type == "address-range" and ip_value.get("ip-address-first"):
            rows = await self._client.cache.get_objects_in_ip_range(
                ip_value["ip-address-first"],
                ip_value.get("ip-address-last", ip_value["ip-address-first"]),
                mgmt_names=[mgmt],
                domain_names=[domain],
            )
        typed = [r for r in rows if r.type == cache_type]
        if type == "network":
            # get_objects_by_subnet only matches the bare network address, not the mask, so two
            # objects rooted at the same address (e.g. 10.0.0.0/24 vs 10.0.0.0/16) are otherwise
            # indistinguishable here. Require an exact mask match too; if no mask-length was
            # supplied we can't verify it, so don't guess -- fall through to the live API instead.
            mask_length = ip_value.get("mask-length")
            if mask_length is None:
                typed = []
            else:
                expected_mask = _mask_to_dotted(int(mask_length))
                typed = [r for r in typed if r.subnet_mask == expected_mask]
        if typed:
            return [_state_from_cpobject(type, r) for r in typed]
        return await self._live.find_by_ip(type=type, ip_value=ip_value, mgmt=mgmt, domain=domain)

    async def where_used(self, uid: str, *, mgmt: str, domain: str) -> int:
        return await self._live.where_used(uid, mgmt=mgmt, domain=domain)

    async def get_last_publish_session(self, *, mgmt: str, domain: str) -> str:
        return await self._live.get_last_publish_session(mgmt=mgmt, domain=domain)

    async def get_service(self, spec: Any, original_text: str, *, mgmt: str, domain: str) -> ObjectState | None:
        return await self._live.get_service(spec, original_text, mgmt=mgmt, domain=domain)

    async def get_layer(self, layer_ref: str, layer_type: str, *, mgmt: str, domain: str) -> LayerInfo | None:
        return await self._live.get_layer(layer_ref, layer_type, mgmt=mgmt, domain=domain)

    async def get_section(
        self, section_ref: str, layer_uid: str, layer_type: str, *, mgmt: str, domain: str
    ) -> SectionInfo | None:
        return await self._live.get_section(section_ref, layer_uid, layer_type, mgmt=mgmt, domain=domain)

    async def get_last_rule(self, scope_uid: str, layer_type: str, *, mgmt: str, domain: str) -> RuleMatch | None:
        return await self._live.get_last_rule(scope_uid, layer_type, mgmt=mgmt, domain=domain)

    async def find_rules_by_traffic(
        self,
        scope_uid: str,
        layer_type: str,
        source_uids: list[str],
        dest_uids: list[str],
        service_uids: list[str],
        *,
        mgmt: str,
        domain: str,
    ) -> list[RuleMatch]:
        return await self._live.find_rules_by_traffic(
            scope_uid, layer_type, source_uids, dest_uids, service_uids, mgmt=mgmt, domain=domain
        )

    async def find_nat_rules_by_tuple(
        self, package: str, tup: tuple[str, str, str, str, str, str], *, mgmt: str, domain: str
    ) -> list[RuleMatch]:
        return await self._live.find_nat_rules_by_tuple(package, tup, mgmt=mgmt, domain=domain)

    async def get_last_nat_rule(self, package: str, *, mgmt: str, domain: str) -> RuleMatch | None:
        return await self._live.get_last_nat_rule(package, mgmt=mgmt, domain=domain)

    async def get_rule_by_key(
        self, scope_uid: str, layer_type: str, key: dict[str, Any], *, mgmt: str, domain: str
    ) -> RuleMatch | None:
        return await self._live.get_rule_by_key(scope_uid, layer_type, key, mgmt=mgmt, domain=domain)

    async def get_nat_rule_by_key(
        self, package: str, key: dict[str, Any], *, mgmt: str, domain: str
    ) -> RuleMatch | None:
        return await self._live.get_nat_rule_by_key(package, key, mgmt=mgmt, domain=domain)
