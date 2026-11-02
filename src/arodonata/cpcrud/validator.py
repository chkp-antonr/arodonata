"""Offline JSON Schema validator and template normalizer (`src/arodonata/cpcrud/validator.py`).

Validates YAML or JSON declarative templates against `checkpoint_ops_schema.json`
(or an explicit `schema_path` override) using `jsonschema.Draft7Validator` without
making any network or database calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from arodonata.core.errors import ConfigurationError

_DEFAULT_SCHEMA_PATH = Path(__file__).with_name("checkpoint_ops_schema.json")
_SCHEMA_CACHE: dict[str, dict[str, Any]] = {}


def load_cpcrud_schema(schema_path: str | Path | None = None) -> dict[str, Any]:
    """Load and cache the CPCRUD Draft-07 JSON Schema from disk."""
    target = Path(schema_path) if schema_path is not None else _DEFAULT_SCHEMA_PATH
    cache_key = str(target.resolve())
    if cache_key in _SCHEMA_CACHE:
        return _SCHEMA_CACHE[cache_key]

    if not target.is_file():
        raise ConfigurationError(f"CPCRUD JSON Schema file not found at {str(target)!r}.")

    try:
        raw_text = target.read_text(encoding="utf-8")
        parsed = json.loads(raw_text)
    except Exception as exc:
        raise ConfigurationError(f"Failed to parse CPCRUD JSON Schema at {str(target)!r}: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ConfigurationError(f"CPCRUD JSON Schema at {str(target)!r} must be a JSON object.")

    _SCHEMA_CACHE[cache_key] = parsed
    return parsed


def parse_template_input(template: dict[str, Any] | str) -> tuple[dict[str, Any] | None, list[str]]:
    """Parse a dictionary or YAML/JSON string into a template dict, returning `(parsed, errors)`."""
    if isinstance(template, dict):
        return dict(template), []
    if isinstance(template, str):
        stripped = template.strip()
        if not stripped:
            return None, ["Template string is empty."]
        try:
            loaded = yaml.safe_load(stripped)
        except Exception as exc:
            return None, [f"Failed to parse YAML/JSON template: {exc}"]
        if not isinstance(loaded, dict):
            return None, [f"Template root must be a mapping/object, got {type(loaded).__name__}."]
        return dict(loaded), []
    return None, [f"Template must be a dict or YAML/JSON string, got {type(template).__name__}."]


def _format_error_path(error: jsonschema.ValidationError) -> str:
    if not error.absolute_path:
        return "<root>"
    parts: list[str] = []
    for elem in error.absolute_path:
        if isinstance(elem, int):
            parts.append(f"[{elem}]")
        else:
            if parts:
                parts.append(f".{elem}")
            else:
                parts.append(str(elem))
    return "".join(parts)


def validate_template(
    template: dict[str, Any] | str,
    *,
    schema_path: str | Path | None = None,
) -> list[str]:
    """Validate `template` against `checkpoint_ops_schema.json` using `jsonschema.Draft7Validator`.

    Returns:
        Empty list `[]` when valid, or a non-empty list of human-readable validation error strings.
        Performs zero network or database calls.
    """
    parsed, parse_errors = parse_template_input(template)
    if parse_errors or parsed is None:
        return parse_errors

    schema = load_cpcrud_schema(schema_path)
    validator = jsonschema.Draft7Validator(schema)

    errors = sorted(
        validator.iter_errors(parsed),
        key=lambda e: ([str(p) for p in e.absolute_path], e.message),
    )

    formatted: list[str] = []
    for err in errors:
        path_str = _format_error_path(err)
        formatted.append(f"{path_str}: {err.message}")

    formatted.extend(_validate_semantic_rules(parsed))
    return formatted


def _validate_semantic_rules(parsed: dict[str, Any]) -> list[str]:
    """Perform semantic validation on normalized operations (e.g. `application-site` required fields)."""
    errors: list[str] = []

    def _check_bucket(items: Any, path_prefix: str) -> None:
        if not isinstance(items, list):
            return
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            item_type = str(item.get("type") or "").strip().lower()
            if item_type != "application-site":
                continue
            action = str(item.get("action") or item.get("operation") or item.get("state") or "present").strip().lower()
            if action == "add":
                raw_urls = item.get("url-list") if "url-list" in item else item.get("url_list")
                has_urls = isinstance(raw_urls, list) and any(str(u).strip() for u in raw_urls)
                raw_sig = item.get("application-signature") or item.get("application_signature")
                has_sig = bool(str(raw_sig or "").strip())
                if not has_urls and not has_sig:
                    errors.append(
                        f"{path_prefix}[{idx}]: 'application-site' with action {action!r} requires "
                        "'url-list' (or 'url_list') or 'application-signature' (or 'application_signature')."
                    )

    for bucket in ("objects", "services", "operations"):
        _check_bucket(parsed.get(bucket), bucket)

    for target_key in ("targets", "domains"):
        targets = parsed.get(target_key)
        if isinstance(targets, list):
            for t_idx, target in enumerate(targets):
                if isinstance(target, dict):
                    for bucket in ("objects", "services", "operations"):
                        _check_bucket(target.get(bucket), f"{target_key}[{t_idx}].{bucket}")

    return errors


__all__ = [
    "load_cpcrud_schema",
    "parse_template_input",
    "validate_template",
]
