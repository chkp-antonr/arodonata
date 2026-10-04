"""TLS identity settings helpers: trust modes, SHA-256 fingerprint parsing, trust-store path.

Pure functions only (no cpapi, no sockets, no file writes), so `config.settings` can import them. The
verification itself lives in `arodonata.asdk.tls` (spec D1).
"""

from __future__ import annotations

import os
import re
from enum import StrEnum
from pathlib import Path


class TrustMode(StrEnum):
    """How unknown Check Point server certificates are treated (spec D6)."""

    TOFU = "tofu"  # learn the first certificate per host:port and persist it
    PINNED = "pinned"  # accept only certificates in the store or in ARODONATA_TLS_FINGERPRINTS
    LAB_MEMORY = "lab-memory"  # learn in memory only; honoured only when ARODONATA_LAB is set


_PREFIXES = ("sha256 fingerprint=", "sha256:")
_SEPARATORS = re.compile(r"[\s:]")
_HEX = re.compile(r"[0-9a-f]+")
_WORDS = re.compile(r"[A-Za-z]{2,4}(?:[\s-]+[A-Za-z]{2,4}){5,}")
_HOW_TO_GET = "run 'api fingerprint -f json' on the management server and use its fingerprint-sha256"


def normalize_sha256(value: str) -> str:
    """Return the 64 lowercase hex digits of a SHA-256 fingerprint, or raise ValueError with a hint."""
    text = value.strip()
    lowered = text.lower()
    for prefix in _PREFIXES:
        if lowered.startswith(prefix):
            text = text[len(prefix) :].strip()
            break
    compact = _SEPARATORS.sub("", text).lower()
    if _HEX.fullmatch(compact):
        if len(compact) == 64:
            return compact
        if len(compact) == 40:
            raise ValueError(f"'{value}' is a SHA-1 fingerprint; a SHA-256 one is needed: {_HOW_TO_GET}")
        if len(compact) == 32:
            raise ValueError(
                f"'{value}' looks like an MD5 from 'fwm fingerprint', not the API certificate: {_HOW_TO_GET}"
            )
        raise ValueError(f"'{value}' has {len(compact)} hex digits; a SHA-256 fingerprint has 64 hex digits")
    if _WORDS.fullmatch(text):
        raise ValueError(
            f"'{value}' looks like the ICA fingerprint (cp_conf finger / SmartConsole), "
            f"not the API certificate: {_HOW_TO_GET}"
        )
    raise ValueError(f"'{value}' is not a fingerprint; expected 64 hex digits (SHA-256): {_HOW_TO_GET}")


def parse_fingerprints(value: str) -> list[str]:
    """Parse ARODONATA_TLS_FINGERPRINTS: comma-separated SHA-256 values, blanks ignored."""
    return [normalize_sha256(item) for item in value.split(",") if item.strip()]


def colon_hex(hex_digits: str) -> str:
    """`ab01…` -> `AB:01:…`, the form `api fingerprint` and openssl print."""
    return ":".join(hex_digits[i : i + 2] for i in range(0, len(hex_digits), 2)).upper()


def default_store_path() -> Path:
    """`${XDG_STATE_HOME:-~/.local/state}/arodonata/tls_known_hosts.json` (spec D11)."""
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "arodonata" / "tls_known_hosts.json"


def resolve_store_path(configured: str) -> Path:
    """The store file for ARODONATA_TLS_KNOWN_HOSTS_PATH; empty means the default, relative means cwd-relative."""
    if not configured.strip():
        return default_store_path()
    path = Path(configured.strip()).expanduser()
    return path if path.is_absolute() else Path.cwd() / path


__all__ = [
    "TrustMode",
    "colon_hex",
    "default_store_path",
    "normalize_sha256",
    "parse_fingerprints",
    "resolve_store_path",
]
