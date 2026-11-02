"""Offline Two-Step Check Point API Reference & Payload Validation Engine (`arodonata.api_reference.engine`)."""

from __future__ import annotations

import asyncio
import copy
import gzip
import importlib.resources
import json
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from arodonata.api_reference.models import ApiPayloadValidationResult, ApiValidationIssue

DEFAULT_API_VERSION = "v2.2"

_ENGINE_LOCK = threading.Lock()
_DEFAULT_ENGINE: ApiReferenceEngine | None = None


def normalize_api_version(version: str | None, *, default: str = DEFAULT_API_VERSION) -> str:
    """Normalize a Check Point API version string into canonical index form (`v1.9`, `v2`, `v2.1`, `v2.2`)."""
    if not version or not str(version).strip():
        return default
    raw = str(version).strip().lower()
    if raw.startswith("v"):
        raw = raw[1:]
    if raw in ("1.9", "1.9.0", "1.9.1"):
        return "v1.9"
    if raw in ("2", "2.0", "2.0.0", "2.0.1"):
        return "v2"
    if raw in ("2.1", "2.1.0", "2.1.1"):
        return "v2.1"
    if raw in ("2.2", "2.2.0", "2.2.1"):
        return "v2.2"
    return f"v{raw}"


class ApiReferenceEngine:
    """In-memory multi-version Check Point API reference and payload validation engine."""

    def __init__(self, index_data: dict[str, Any]) -> None:
        self.meta: dict[str, Any] = index_data.get("meta") or {}
        self.enums: dict[str, dict[str, Any]] = index_data.get("enums") or {}
        self.shared_objects: dict[str, dict[str, Any]] = index_data.get("shared_objects") or {}
        self.commands: dict[str, dict[str, Any]] = index_data.get("commands") or {}

    @classmethod
    def default(cls) -> ApiReferenceEngine:
        """Return the lazily loaded singleton `ApiReferenceEngine` backed by bundled `cp_api_index.json.gz`."""
        global _DEFAULT_ENGINE
        if _DEFAULT_ENGINE is not None:
            return _DEFAULT_ENGINE
        with _ENGINE_LOCK:
            if _DEFAULT_ENGINE is None:
                pkg_files = importlib.resources.files("arodonata.api_reference.data")
                resource = pkg_files.joinpath("cp_api_index.json.gz")
                raw_bytes = resource.read_bytes()
                decompressed = gzip.decompress(raw_bytes).decode("utf-8")
                _DEFAULT_ENGINE = cls(json.loads(decompressed))
            return _DEFAULT_ENGINE

    @classmethod
    async def async_default(cls) -> ApiReferenceEngine:
        """Return the lazily loaded singleton `ApiReferenceEngine`, decompressing off the event loop via `asyncio.to_thread` (`R9`)."""
        if _DEFAULT_ENGINE is not None:
            return _DEFAULT_ENGINE
        return await asyncio.to_thread(cls.default)

    @classmethod
    def from_path(cls, path: Path | str) -> ApiReferenceEngine:
        """Load an `ApiReferenceEngine` from a custom `.json` or `.json.gz` file path."""
        resolved = Path(path).expanduser()
        if resolved.suffix == ".gz":
            with gzip.open(resolved, "rt", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = json.loads(resolved.read_text(encoding="utf-8"))
        return cls(data)

    def _version_matches(self, supported: list[str], target_version: str | None) -> bool:
        """Check whether an element is supported in `target_version`."""
        if not target_version:
            return True
        norm = normalize_api_version(target_version)
        if norm in supported:
            return True
        raw = target_version.strip()
        raw_v = raw if raw.startswith("v") else f"v{raw}"
        return raw_v in supported

    def search_commands(
        self,
        query: str = "",
        *,
        category: str | None = None,
        crud_type: str | None = None,
        api_family: str | None = None,
        version: str | None = DEFAULT_API_VERSION,
        limit: int = 15,
    ) -> list[dict[str, Any]]:
        """Step 1: Search commands filtered by version, category, CRUD type, and API family, ranked by relevance."""
        eff_version = normalize_api_version(version) if version else None
        q_norm = (query or "").strip().lower().replace("_", "-")
        q_tokens = [t for t in q_norm.split() if t]
        cat_norm = category.strip().lower() if category and category.strip() else None
        crud_norm = crud_type.strip().lower() if crud_type and crud_type.strip() else None
        fam_norm = api_family.strip().lower() if api_family and api_family.strip() else None
        eff_limit = max(1, min(int(limit), 200))

        scored: list[tuple[int, str, dict[str, Any]]] = []
        for cmd_name, cmd in self.commands.items():
            supported = cmd.get("supported_versions") or []
            if (
                eff_version
                and cmd.get("api_family") == "management"
                and not self._version_matches(supported, eff_version)
            ):
                continue
            if fam_norm and str(cmd.get("api_family", "")).lower() != fam_norm:
                continue
            if crud_norm and str(cmd.get("crud_type", "")).lower() != crud_norm:
                continue

            cat_path = cmd.get("category_path") or []
            cat_str = " > ".join(cat_path)
            if cat_norm and cat_norm not in cat_str.lower():
                continue

            desc = str(cmd.get("description") or "")
            short_desc = desc.splitlines()[0] if desc else ""
            cpm_obj = str(cmd.get("cpm_object") or "")

            score = 0
            if not q_tokens:
                score = 1
            else:
                name_lower = cmd_name.lower()
                cli_lower = str(cmd.get("cli_name") or "").lower()
                haystack = f"{name_lower} {cli_lower} {cat_str.lower()} {short_desc.lower()} {cpm_obj.lower()}"
                if q_norm in (name_lower, cli_lower):
                    score += 100
                elif name_lower.startswith(q_norm):
                    score += 60
                elif q_norm in name_lower:
                    score += 40
                if all(tok in haystack for tok in q_tokens):
                    score += 20
                    score += sum(10 for tok in q_tokens if tok in name_lower)
                    score += sum(5 for tok in q_tokens if tok in cat_str.lower())

            if score > 0:
                summary = {
                    "name": cmd_name,
                    "cli_name": cmd.get("cli_name", ""),
                    "api_family": cmd.get("api_family", "management"),
                    "category": cat_str,
                    "crud_type": cmd.get("crud_type", "action"),
                    "cpm_object": cpm_obj,
                    "added_in": cmd.get("added_in", ""),
                    "supported_versions": supported,
                    "short_description": short_desc,
                }
                scored.append((score, cmd_name, summary))

        scored.sort(key=lambda item: (-item[0], item[1]))
        return [item[2] for item in scored[:eff_limit]]

    def describe_command(
        self,
        command: str | Sequence[str],
        *,
        version: str | None = DEFAULT_API_VERSION,
        resolve_nested: bool = True,
        include_examples: bool = True,
    ) -> dict[str, Any] | None:
        """Step 2: Return the resolved command schema(s) dynamically filtered to the target API version.

        When `command` is a single command name (`str`), returns the resolved command dict or `None` if not found
        or unsupported in `version`.
        When `command` is a sequence of command names (`list[str]` / `tuple[str, ...]`), returns a batch dictionary:
        `{"target_version": ..., "commands": {...}, "not_found": [...]}`.
        """
        eff_version = normalize_api_version(version, default=self.meta.get("latest", DEFAULT_API_VERSION))
        if isinstance(command, str):
            return self._describe_single(
                command,
                version=eff_version,
                resolve_nested=resolve_nested,
                include_examples=include_examples,
            )

        commands_out: dict[str, dict[str, Any]] = {}
        not_found: list[str] = []
        for item in command:
            if not isinstance(item, str) or not item.strip():
                continue
            clean_name = item.strip().lower().replace(" ", "-")
            desc = self._describe_single(
                item,
                version=eff_version,
                resolve_nested=resolve_nested,
                include_examples=include_examples,
            )
            if desc is not None:
                commands_out[desc["name"]] = desc
            else:
                not_found.append(clean_name)

        return {
            "target_version": eff_version,
            "commands": commands_out,
            "not_found": not_found,
        }

    def _describe_single(
        self,
        name: str,
        *,
        version: str,
        resolve_nested: bool = True,
        include_examples: bool = True,
    ) -> dict[str, Any] | None:
        norm_name = name.strip().lower().replace("_", "-").replace(" ", "-")
        cmd = self.commands.get(norm_name) or self.commands.get(name.strip())
        if not cmd:
            return None

        supported = cmd.get("supported_versions") or []
        if version and cmd.get("api_family") == "management" and not self._version_matches(supported, version):
            return None

        filtered_fields = self._filter_fields(cmd.get("fields") or [], version)
        valid_field_names = {f["name"] for f in filtered_fields}

        # Filter field_alternatives on individual fields and top-level groups to only valid fields in `version`
        for f_item in filtered_fields:
            if "field_alternatives" in f_item:
                f_alts = [alt for alt in f_item["field_alternatives"] if alt in valid_field_names]
                if f_alts:
                    f_item["field_alternatives"] = f_alts
                else:
                    f_item.pop("field_alternatives", None)

        filtered_alts: list[list[str]] = []
        for grp in cmd.get("field_alternatives") or []:
            valid_grp = [fname for fname in grp if fname in valid_field_names]
            if len(valid_grp) >= 2 and valid_grp not in filtered_alts:
                filtered_alts.append(valid_grp)

        result: dict[str, Any] = {
            "name": cmd["name"],
            "cli_name": cmd.get("cli_name", ""),
            "http_method": cmd.get("http_method", "POST"),
            "api_family": cmd.get("api_family", "management"),
            "category_path": cmd.get("category_path", []),
            "crud_type": cmd.get("crud_type", "action"),
            "cpm_object": cmd.get("cpm_object", ""),
            "allowed_domains": cmd.get("allowed_domains", []),
            "description": cmd.get("description", ""),
            "target_version": version,
            "supported_versions": supported,
            "added_in": cmd.get("added_in", ""),
            "field_alternatives": filtered_alts,
            "fields": filtered_fields,
        }

        if resolve_nested:
            nested_schemas: dict[str, dict[str, Any]] = {}
            self._collect_resolved_objects(filtered_fields, version, nested_schemas, depth=1, max_depth=2)
            result["nested_objects"] = nested_schemas
            result["enums"] = self._collect_referenced_enums(filtered_fields, nested_schemas)

        if include_examples and "example" in cmd:
            result["example"] = copy.deepcopy(cmd["example"])

        return result

    def _filter_fields(self, raw_fields: list[dict[str, Any]], version: str | None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for f in raw_fields:
            f_vers = f.get("supported_versions") or []
            if version and f_vers and not self._version_matches(f_vers, version):
                continue
            out.append(copy.deepcopy(f))
        return out

    def _collect_resolved_objects(
        self,
        fields: list[dict[str, Any]],
        version: str | None,
        acc: dict[str, dict[str, Any]],
        *,
        depth: int,
        max_depth: int,
    ) -> None:
        if depth > max_depth:
            return
        next_fields: list[dict[str, Any]] = []
        for f in fields:
            for t in f.get("types") or []:
                refs: list[str] = []
                if t.get("kind") == "object" and t.get("object_ref"):
                    refs.append(str(t["object_ref"]))
                elif t.get("kind") == "list" and isinstance(t.get("element_type"), dict):
                    et = t["element_type"]
                    if et.get("kind") == "object" and et.get("object_ref"):
                        refs.append(str(et["object_ref"]))
                for ref in refs:
                    if ref not in acc and ref in self.shared_objects:
                        obj_raw = self.shared_objects[ref]
                        obj_fields = self._filter_fields(obj_raw.get("fields") or [], version)
                        acc[ref] = {
                            "id": ref,
                            "description": obj_raw.get("description", ""),
                            "fields": obj_fields,
                        }
                        if obj_raw.get("field_alternatives"):
                            valid_names = {of["name"] for of in obj_fields}
                            obj_alts = [
                                [fn for fn in grp if fn in valid_names] for grp in obj_raw["field_alternatives"]
                            ]
                            obj_alts = [g for g in obj_alts if len(g) >= 2]
                            if obj_alts:
                                acc[ref]["field_alternatives"] = obj_alts
                        next_fields.extend(obj_fields)
        if next_fields:
            self._collect_resolved_objects(next_fields, version, acc, depth=depth + 1, max_depth=max_depth)

    def _collect_referenced_enums(
        self,
        top_fields: list[dict[str, Any]],
        nested_objects: dict[str, dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        enums_out: dict[str, dict[str, Any]] = {}
        all_fields = list(top_fields)
        for n_obj in nested_objects.values():
            all_fields.extend(n_obj.get("fields") or [])

        for f in all_fields:
            for t in f.get("types") or []:
                enum_refs: list[str] = []
                if t.get("enum_ref"):
                    enum_refs.append(str(t["enum_ref"]))
                if isinstance(t.get("element_type"), dict) and t["element_type"].get("enum_ref"):
                    enum_refs.append(str(t["element_type"]["enum_ref"]))
                for er in enum_refs:
                    if er not in enums_out and er in self.enums:
                        enums_out[er] = copy.deepcopy(self.enums[er])
        return enums_out

    def validate_payload(
        self,
        command: str,
        payload: dict[str, Any] | None,
        *,
        version: str | None = DEFAULT_API_VERSION,
    ) -> dict[str, Any]:
        """Step 3: Offline validation of a candidate request payload against the command's versioned schema."""
        eff_version = normalize_api_version(version, default=self.meta.get("latest", DEFAULT_API_VERSION))
        norm_name = command.strip().lower().replace("_", "-").replace(" ", "-")
        raw_cmd = self.commands.get(norm_name) or self.commands.get(command.strip())

        if raw_cmd is None:
            suggestions = self.search_commands(norm_name, version=eff_version, limit=5)
            res = ApiPayloadValidationResult(
                valid=False,
                command=norm_name,
                target_version=eff_version,
                error_count=1,
                errors=[
                    ApiValidationIssue(
                        code="unknown_command",
                        message=f"Unknown Check Point API command {command!r}.",
                    )
                ],
                suggestions=suggestions,
            )
            return res.model_dump(mode="json")

        supported_cmd_versions = raw_cmd.get("supported_versions") or []
        if (
            eff_version
            and raw_cmd.get("api_family") == "management"
            and not self._version_matches(supported_cmd_versions, eff_version)
        ):
            res = ApiPayloadValidationResult(
                valid=False,
                command=raw_cmd["name"],
                target_version=eff_version,
                error_count=1,
                errors=[
                    ApiValidationIssue(
                        code="unsupported_command_version",
                        message=(
                            f"Command {raw_cmd['name']!r} is not supported in API version {eff_version!r} "
                            f"(added_in={raw_cmd.get('added_in')!r}, supported_versions={supported_cmd_versions})."
                        ),
                        supported_versions=supported_cmd_versions,
                    )
                ],
            )
            return res.model_dump(mode="json")

        eff_payload = payload if isinstance(payload, dict) else {}
        described = self._describe_single(
            raw_cmd["name"], version=eff_version, resolve_nested=True, include_examples=False
        )
        assert described is not None

        all_cmd_fields_by_name: dict[str, dict[str, Any]] = {f["name"]: f for f in (raw_cmd.get("fields") or [])}
        version_fields_by_name: dict[str, dict[str, Any]] = {f["name"]: f for f in (described.get("fields") or [])}
        # Map field aliases if any
        alias_to_canonical: dict[str, str] = {}
        for fname, fdef in version_fields_by_name.items():
            for alias in fdef.get("aliases") or []:
                alias_to_canonical[alias] = fname

        issues: list[ApiValidationIssue] = []

        # 1. Check unknown or version-unsupported fields in payload
        present_canonical_fields: set[str] = set()
        for key, val in eff_payload.items():
            canonical_key = alias_to_canonical.get(key, key)
            if canonical_key in version_fields_by_name:
                present_canonical_fields.add(canonical_key)
                self._validate_field_value(canonical_key, val, version_fields_by_name[canonical_key], issues)
            elif canonical_key in all_cmd_fields_by_name:
                other_f = all_cmd_fields_by_name[canonical_key]
                f_sup = other_f.get("supported_versions") or []
                issues.append(
                    ApiValidationIssue(
                        code="unsupported_field_version",
                        field=key,
                        message=(
                            f"Field {key!r} on {raw_cmd['name']!r} is not supported in target version {eff_version!r} "
                            f"(supported in {f_sup}, added_in={other_f.get('added_in')!r}, "
                            f"removed_in={other_f.get('removed_in')!r})."
                        ),
                        supported_versions=f_sup,
                    )
                )
            else:
                issues.append(
                    ApiValidationIssue(
                        code="unknown_field",
                        field=key,
                        message=f"Unknown request parameter {key!r} for command {raw_cmd['name']!r} ({eff_version}).",
                    )
                )

        # 2. Check field_alternatives and required fields
        alt_groups: list[list[str]] = described.get("field_alternatives") or []
        fields_in_alt_groups: set[str] = {fname for grp in alt_groups for fname in grp}

        for grp in alt_groups:
            present_in_grp = [fname for fname in grp if fname in present_canonical_fields]
            any_required_in_grp = any(version_fields_by_name.get(fname, {}).get("required", False) for fname in grp)
            if any_required_in_grp and not present_in_grp:
                issues.append(
                    ApiValidationIssue(
                        code="missing_alternative_group",
                        field=" | ".join(grp),
                        message=(f"Missing required parameter for {raw_cmd['name']!r}: provide one of {grp}."),
                        allowed_values=grp,
                    )
                )
            elif len(present_in_grp) > 1:
                # Special case: ipv4-address + ipv6-address can both be provided when ip-address is omitted
                if set(present_in_grp) == {"ipv4-address", "ipv6-address"} and "ip-address" in grp:
                    continue
                issues.append(
                    ApiValidationIssue(
                        code="conflicting_alternatives",
                        field=" | ".join(present_in_grp),
                        message=(
                            f"Mutually exclusive parameters {present_in_grp} provided together; "
                            f"choose from alternative group {grp}."
                        ),
                        allowed_values=grp,
                    )
                )

        for fname, fdef in version_fields_by_name.items():
            if fdef.get("required") and fname not in fields_in_alt_groups and fname not in present_canonical_fields:
                # Also check if field has field-level alternatives satisfied
                f_alts = [alt for alt in (fdef.get("field_alternatives") or []) if alt in version_fields_by_name]
                if f_alts:
                    if not any(alt in present_canonical_fields for alt in f_alts):
                        all_opts = [fname, *f_alts]
                        issues.append(
                            ApiValidationIssue(
                                code="missing_alternative_group",
                                field=" | ".join(all_opts),
                                message=(
                                    f"Missing required parameter for {raw_cmd['name']!r}: provide one of {all_opts}."
                                ),
                                allowed_values=all_opts,
                            )
                        )
                else:
                    issues.append(
                        ApiValidationIssue(
                            code="missing_required_field",
                            field=fname,
                            message=f"Missing required parameter {fname!r} for command {raw_cmd['name']!r}.",
                        )
                    )

        res = ApiPayloadValidationResult(
            valid=len(issues) == 0,
            command=raw_cmd["name"],
            target_version=eff_version,
            error_count=len(issues),
            errors=issues,
        )
        return res.model_dump(mode="json")

    def _validate_field_value(
        self,
        field_name: str,
        value: Any,
        field_def: dict[str, Any],
        issues: list[ApiValidationIssue],
    ) -> None:
        types: list[dict[str, Any]] = field_def.get("types") or []
        if not types:
            return

        # Check if value matches any declared type descriptor
        for t in types:
            if self._matches_type_descriptor(value, t):
                # If matched an enum or primitive string when an enum type exists, check enum values if applicable
                if isinstance(value, str):
                    enum_types = [
                        et
                        for et in types
                        if et.get("kind") == "enum" and (et.get("valid_values") or et.get("enum_ref"))
                    ]
                    non_enum_str_types = [
                        et for et in types if et.get("kind") == "primitive" and et.get("primitive") in ("string", None)
                    ]
                    if enum_types and not non_enum_str_types:
                        allowed: list[str] = []
                        for et in enum_types:
                            vals = et.get("valid_values") or []
                            if not vals and et.get("enum_ref") and str(et["enum_ref"]) in self.enums:
                                vals = self.enums[str(et["enum_ref"])].get("values") or []
                            for v in vals:
                                if v not in allowed:
                                    allowed.append(v)
                        if allowed and value not in allowed and value.lower() not in {a.lower() for a in allowed}:
                            issues.append(
                                ApiValidationIssue(
                                    code="invalid_enum_value",
                                    field=field_name,
                                    message=(
                                        f"Invalid value {value!r} for enum parameter {field_name!r}. "
                                        f"Allowed values: {allowed}."
                                    ),
                                    allowed_values=allowed,
                                )
                            )
                return

        expected_labels = [self._format_type_label(t) for t in types]
        issues.append(
            ApiValidationIssue(
                code="invalid_type",
                field=field_name,
                message=(
                    f"Invalid type {type(value).__name__!r} for parameter {field_name!r}; "
                    f"expected {' | '.join(expected_labels)}."
                ),
            )
        )

    def _matches_type_descriptor(self, value: Any, t: dict[str, Any]) -> bool:
        kind = t.get("kind", "primitive")
        if kind == "object":
            return isinstance(value, dict)
        if kind == "list":
            if not isinstance(value, list):
                return False
            el_type = t.get("element_type")
            if isinstance(el_type, dict) and value:
                return all(self._matches_type_descriptor(item, el_type) for item in value)
            return True
        if kind == "enum":
            return isinstance(value, str)
        prim = t.get("primitive") or "string"
        if prim == "boolean":
            return isinstance(value, bool)
        if prim == "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        if prim in ("number", "float", "double"):
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        return isinstance(value, str)

    def _format_type_label(self, t: dict[str, Any]) -> str:
        kind = t.get("kind", "primitive")
        if kind == "list":
            el = t.get("element_type")
            inner = self._format_type_label(el) if isinstance(el, dict) else "any"
            return f"list[{inner}]"
        if kind == "object":
            ref = t.get("object_ref")
            return f"object({ref})" if ref else "object"
        if kind == "enum":
            ref = t.get("enum_ref")
            return f"enum({ref})" if ref else "string(enum)"
        return str(t.get("primitive") or "string")


def get_api_reference() -> ApiReferenceEngine:
    """Return the singleton `ApiReferenceEngine` loaded lazily from bundled `cp_api_index.json.gz`."""
    return ApiReferenceEngine.default()


def search_api_commands(
    query: str = "",
    *,
    category: str | None = None,
    crud_type: str | None = None,
    api_family: str | None = None,
    version: str | None = DEFAULT_API_VERSION,
    limit: int = 15,
) -> list[dict[str, Any]]:
    """Step 1: Search Check Point API commands by keyword, category, `crud_type`, `api_family`, and `version`."""
    return get_api_reference().search_commands(
        query,
        category=category,
        crud_type=crud_type,
        api_family=api_family,
        version=version,
        limit=limit,
    )


def describe_api_command(
    command: str | Sequence[str],
    *,
    version: str | None = DEFAULT_API_VERSION,
    resolve_nested: bool = True,
    include_examples: bool = True,
) -> dict[str, Any] | None:
    """Step 2: Return the version-filtered command schema (or batch of schemas when passed a list of names)."""
    return get_api_reference().describe_command(
        command,
        version=version,
        resolve_nested=resolve_nested,
        include_examples=include_examples,
    )


def validate_api_payload(
    command: str,
    payload: dict[str, Any] | None,
    *,
    version: str | None = DEFAULT_API_VERSION,
) -> dict[str, Any]:
    """Step 3: Validate a candidate request `payload` dictionary offline against a command's versioned schema."""
    return get_api_reference().validate_payload(
        command,
        payload,
        version=version,
    )


__all__ = [
    "DEFAULT_API_VERSION",
    "ApiReferenceEngine",
    "describe_api_command",
    "get_api_reference",
    "normalize_api_version",
    "search_api_commands",
    "validate_api_payload",
]
