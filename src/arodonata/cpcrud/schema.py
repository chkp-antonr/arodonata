"""Template loading and JSON-schema validation for CPCRUD."""

from __future__ import annotations

import copy
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft7Validator

from ..config.settings import ArodonataSettings

_SCHEMA_FILENAME = "checkpoint_ops_schema.json"


def _default_schema_path() -> Path:
    # ops/checkpoint_ops_schema.json relative to the package root (src/arodonata)
    return Path(__file__).resolve().parents[3] / "ops" / _SCHEMA_FILENAME


@lru_cache(maxsize=1)
def _load_schema() -> dict[str, Any]:
    settings = ArodonataSettings()
    path = Path(settings.cpcrud_schema_path) if settings.cpcrud_schema_path else _default_schema_path()
    if not path.exists():
        from ..core.exceptions import ConfigurationError

        raise ConfigurationError(f"CPCRUD schema not found: {path}")
    with path.open() as f:
        return json.load(f)


def load_template(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Load a template from a dict, a file path, or a YAML/JSON string."""
    if isinstance(source, dict):
        return source
    p = Path(source)
    if p.exists():
        text = p.read_text()
    else:
        text = str(source)
    return yaml.safe_load(text)


def normalize_operations(doc: dict[str, Any]) -> dict[str, Any]:
    """Set operation='add' where missing. Returns a normalized copy."""
    out = copy.deepcopy(doc)
    for ms in out.get("management_servers", []):
        for domain in ms.get("domains", []):
            for op in domain.get("operations", []):
                op.setdefault("operation", "add")
    return out


def validate_template(doc: dict[str, Any]) -> list[str]:
    """Validate a template against the schema. Returns a list of error strings (empty = valid)."""
    normalized = normalize_operations(doc)
    validator = Draft7Validator(_load_schema())
    return [
        f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in validator.iter_errors(normalized)
    ]
