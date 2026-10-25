"""TLS certificate SHA-256 fingerprint verification (`TrustStore` and `TrustPolicy`).

Verifies server identity immediately after the TLS handshake and before any HTTP
request line, headers (`X-chkp-sid`), credentials, or JSON payloads are sent.
"""

from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from arodonata.core.config import DEFAULT_TLS_KNOWN_HOSTS_PATH, TlsTrustMode, parse_host_port
from arodonata.core.errors import (
    CertificateMismatchError,
    ConfigurationError,
    ServerIdentityError,
    TrustStoreError,
    UnknownServerCertificateError,
)
from arodonata.core.models.common import utc_now
from arodonata.core.telemetry import span_attrs, traced

_HEX_CLEAN_RE = re.compile(r"[^0-9a-fA-F]")


def normalize_fingerprint(raw: str) -> str:
    """Normalize a SHA-256 certificate fingerprint to colon-separated uppercase hex (`AA:BB:...`).

    Accepts raw 64-character hex strings, colon-separated hex strings, or strings prefixed
    with `SHA256:` / `sha256:`.
    """
    cleaned = raw.strip()
    if cleaned.lower().startswith("sha256:"):
        cleaned = cleaned[7:].strip()
    hex_chars = _HEX_CLEAN_RE.sub("", cleaned).upper()
    if len(hex_chars) != 64:
        raise ConfigurationError(
            f"Invalid SHA-256 fingerprint {raw!r}: expected 64 hexadecimal characters (got {len(hex_chars)})."
        )
    return ":".join(hex_chars[i : i + 2] for i in range(0, 64, 2))


def compute_der_fingerprint(der_bytes: bytes) -> str:
    """Compute the canonical colon-separated uppercase SHA-256 fingerprint of DER certificate bytes."""
    if not der_bytes:
        raise TrustStoreError("Peer did not present a TLS certificate. No request was sent.")
    digest = hashlib.sha256(der_bytes).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, 64, 2))


def format_host_attr_for_url(host: str) -> str:
    """Wrap raw IPv6 literal in brackets `[...]` for URL/key construction."""
    cleaned = host.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        return cleaned
    try:
        addr = ipaddress.ip_address(cleaned)
        if addr.version == 6:
            return f"[{addr.compressed}]"
    except ValueError:
        if ":" in cleaned:
            return f"[{cleaned}]"
    return cleaned


def format_host_port(host: str, port: int = 443) -> str:
    """Format `(host, port)` into canonical `host:port` or `[ipv6]:port` key."""
    parsed_host, parsed_port = parse_host_port(host, default_port=port)
    return f"{format_host_attr_for_url(parsed_host)}:{int(parsed_port)}"


def parse_tls_fingerprints(raw: str | dict[str, str] | None, *, default_port: int = 443) -> dict[str, str]:
    """Parse `ARODONATA_TLS_FINGERPRINTS` into a mapping of `host:port -> normalized_fingerprint` and
    collect standalone fingerprints under `*{index}` if no host is specified.

    Supports:
    - JSON object: `'{"10.0.0.1:443": "AA:BB...", "10.0.0.2": "CC:DD..."}'`
    - Key-value CSV: `'10.0.0.1:443=AA:BB...,10.0.0.2=CC:DD...'`
    - Bare fingerprint CSV: `'AA:BB...,CC:DD...'` (stored under `*:<idx>` as global trusted fingerprints)
    """
    if not raw:
        return {}
    if isinstance(raw, dict):
        result: dict[str, str] = {}
        for k, v in raw.items():
            key = k if k.startswith("*:") else format_host_port(k, default_port)
            result[key] = normalize_fingerprint(v)
        return result

    text = raw.strip()
    if not text:
        return {}

    if text.startswith("{") and text.endswith("}"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parse_tls_fingerprints(
                    {str(k): str(v) for k, v in parsed.items()},
                    default_port=default_port,
                )
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"Invalid JSON in ARODONATA_TLS_FINGERPRINTS: {exc}") from exc

    entries: dict[str, str] = {}
    for idx, token in enumerate(text.split(",")):
        item = token.strip()
        if not item:
            continue
        if "=" in item:
            addr_part, fp_part = item.split("=", 1)
            key = format_host_port(addr_part.strip(), default_port)
            entries[key] = normalize_fingerprint(fp_part.strip())
        else:
            entries[f"*:{idx}"] = normalize_fingerprint(item)
    return entries


class KnownHostEntry(BaseModel):
    """Persisted record for a trusted `host:port` certificate fingerprint."""

    model_config = ConfigDict(extra="ignore")

    fingerprint: str
    source: str = "tofu"
    first_seen_at: str = Field(default_factory=lambda: utc_now().isoformat())
    last_seen_at: str = Field(default_factory=lambda: utc_now().isoformat())


class TrustStore:
    """Manages persistent `tls_known_hosts.json` storage with atomic `0600` file writes and flock locking."""

    def __init__(
        self,
        path: str | Path = DEFAULT_TLS_KNOWN_HOSTS_PATH,
        *,
        in_memory: bool = False,
    ) -> None:
        self._path = Path(path).expanduser()
        self._in_memory = in_memory
        self._entries: dict[str, KnownHostEntry] = {}
        self._loaded = False

    @property
    def path(self) -> Path:
        """File path for `tls_known_hosts.json`."""
        return self._path

    @property
    def in_memory(self) -> bool:
        """Return `True` if this store operates solely in memory without disk I/O."""
        return self._in_memory

    @property
    def entries(self) -> dict[str, KnownHostEntry]:
        """Return a copy of loaded known-host entries."""
        self.load()
        return dict(self._entries)

    def _validate_file_security(self) -> None:
        """Verify ownership and absence of group/world write permissions on `self._path`."""
        try:
            st = os.stat(self._path, follow_symlinks=False)
        except OSError as exc:
            raise TrustStoreError(
                f"Failed to stat TLS trust store at {str(self._path)!r}: {exc}. No request was sent."
            ) from exc
        if hasattr(os, "geteuid"):
            euid = os.geteuid()
            if st.st_uid not in (euid, 0):
                raise TrustStoreError(
                    f"Unsafe ownership on TLS trust store {str(self._path)!r}: owned by uid {st.st_uid}, "
                    f"expected {euid}. No request was sent."
                )
        mode = stat.S_IMODE(st.st_mode)
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise TrustStoreError(
                f"Unsafe permissions {oct(mode)} on TLS trust store {str(self._path)!r}: "
                "group or world write permissions are forbidden (expected 0600). No request was sent."
            )

    def _read_entries_from_disk(self) -> dict[str, KnownHostEntry]:
        """Read and validate entries from `self._path` if present on disk."""
        if not self._path.exists():
            return {}
        self._validate_file_security()
        try:
            raw_text = self._path.read_text(encoding="utf-8")
            if not raw_text.strip():
                return {}
            data = json.loads(raw_text)
        except (OSError, json.JSONDecodeError) as exc:
            raise TrustStoreError(
                f"Failed to read TLS trust store at {str(self._path)!r}: {exc}. No request was sent."
            ) from exc

        if not isinstance(data, dict):
            raise TrustStoreError(
                f"Invalid TLS trust store format at {str(self._path)!r}: expected JSON object. No request was sent."
            )

        hosts_map = data.get("hosts", data) if isinstance(data.get("hosts"), dict) else data
        parsed_entries: dict[str, KnownHostEntry] = {}
        for raw_key, raw_val in hosts_map.items():
            if not isinstance(raw_key, str):
                continue
            key = format_host_port(raw_key)
            try:
                if isinstance(raw_val, str):
                    fp = normalize_fingerprint(raw_val)
                    parsed_entries[key] = KnownHostEntry(fingerprint=fp, source="stored")
                elif isinstance(raw_val, dict):
                    fp = normalize_fingerprint(str(raw_val.get("fingerprint", "")))
                    parsed_entries[key] = KnownHostEntry(
                        fingerprint=fp,
                        source=str(raw_val.get("source") or "stored"),
                        first_seen_at=str(raw_val.get("first_seen_at") or utc_now().isoformat()),
                        last_seen_at=str(raw_val.get("last_seen_at") or utc_now().isoformat()),
                    )
            except ConfigurationError as exc:
                raise TrustStoreError(
                    f"Corrupted fingerprint for {key!r} in {str(self._path)!r}: {exc}. No request was sent."
                ) from exc
        return parsed_entries

    def load(self) -> dict[str, KnownHostEntry]:
        """Load entries from disk if not already loaded (or no-op in memory mode)."""
        if self._loaded or self._in_memory:
            self._loaded = True
            return self._entries

        self._entries = self._read_entries_from_disk()
        self._loaded = True
        return self._entries

    def get(self, host: str, port: int = 443) -> KnownHostEntry | None:
        """Return the `KnownHostEntry` for `(host, port)`, if present."""
        self.load()
        key = format_host_port(host, port)
        entry = self._entries.get(key)
        if entry is None and not self._in_memory and self._path.exists():
            # Re-read disk in case a sibling process learned the entry after initial load
            disk_entries = self._read_entries_from_disk()
            self._entries.update(disk_entries)
            entry = self._entries.get(key)
        return entry

    def has_fingerprint_anywhere(self, fingerprint: str) -> bool:
        """Return `True` if `fingerprint` is already trusted for any address in the store."""
        self.load()
        normalized = normalize_fingerprint(fingerprint)
        if any(entry.fingerprint == normalized for entry in self._entries.values()):
            return True
        if not self._in_memory and self._path.exists():
            disk_entries = self._read_entries_from_disk()
            self._entries.update(disk_entries)
            return any(entry.fingerprint == normalized for entry in self._entries.values())
        return False

    def record(
        self,
        host: str,
        port: int,
        fingerprint: str,
        *,
        source: str = "tofu",
        persist: bool = True,
    ) -> KnownHostEntry:
        """Record a trusted fingerprint for `(host, port)` and atomically persist with mode `0600`."""
        self.load()
        key = format_host_port(host, port)
        normalized = normalize_fingerprint(fingerprint)
        now_iso = utc_now().isoformat()
        existing = self._entries.get(key)
        entry = KnownHostEntry(
            fingerprint=normalized,
            source=source,
            first_seen_at=existing.first_seen_at if existing else now_iso,
            last_seen_at=now_iso,
        )
        self._entries[key] = entry
        if persist and not self._in_memory:
            self._save_atomic(key, entry)
        return entry

    def _save_atomic(self, updated_key: str | None = None, updated_entry: KnownHostEntry | None = None) -> None:
        """Atomically merge and write `self._entries` to `self._path` with `fcntl.flock` and mode `0600`."""
        parent = self._path.parent
        lock_path = parent / f".{self._path.name}.lock"
        try:
            parent.mkdir(parents=True, exist_ok=True)
            lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                disk_entries = self._read_entries_from_disk()
                merged = dict(disk_entries)
                for k, v in self._entries.items():
                    if k not in merged:
                        merged[k] = v
                if updated_key is not None and updated_entry is not None:
                    existing_on_disk = disk_entries.get(updated_key)
                    if existing_on_disk is not None and existing_on_disk.fingerprint != updated_entry.fingerprint:
                        raise CertificateMismatchError(
                            f"TLS certificate fingerprint mismatch for {updated_key} during concurrent TOFU merge: "
                            f"expected {existing_on_disk.fingerprint}, got {updated_entry.fingerprint}. "
                            "No request was sent."
                        )
                    merged[updated_key] = updated_entry
                self._entries = merged

                payload = {
                    "version": 1,
                    "hosts": {k: v.model_dump() for k, v in sorted(self._entries.items())},
                }
                serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"

                fd, tmp_path_str = tempfile.mkstemp(
                    prefix=f".{self._path.name}.",
                    suffix=".tmp",
                    dir=str(parent),
                )
                tmp_path = Path(tmp_path_str)
                try:
                    os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
                    with os.fdopen(fd, "w", encoding="utf-8") as handle:
                        handle.write(serialized)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.chmod(tmp_path, 0o600)
                    os.replace(tmp_path, self._path)
                    os.chmod(self._path, 0o600)
                except Exception:
                    if tmp_path.exists():
                        tmp_path.unlink(missing_ok=True)
                    raise
            finally:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
        except ServerIdentityError:
            raise
        except OSError as exc:
            raise TrustStoreError(
                f"Failed to persist TLS trust store at {str(self._path)!r}: {exc}. No request was sent."
            ) from exc


class TrustPolicy:
    """Enforces Check Point server TLS certificate fingerprint verification (`pinned`, `tofu`, `lab-memory`)."""

    def __init__(
        self,
        mode: TlsTrustMode = "tofu",
        *,
        trust_store: TrustStore | None = None,
        known_hosts_path: str | Path = DEFAULT_TLS_KNOWN_HOSTS_PATH,
        pinned_fingerprints: str | dict[str, str] | None = None,
        lab_env: str | None = None,
    ) -> None:
        if mode not in ("pinned", "tofu", "lab-memory"):
            raise ConfigurationError(f"Unsupported tls_trust mode: {mode!r}.")

        resolved_lab = lab_env if lab_env is not None else os.environ.get("ARODONATA_LAB", "").strip()
        if mode == "lab-memory" and (not resolved_lab or resolved_lab.lower() in ("0", "false", "no", "off")):
            raise ConfigurationError(
                "tls_trust='lab-memory' requires ARODONATA_LAB=1 to be explicitly set in the environment."
            )

        self._mode: TlsTrustMode = mode
        self._store = (
            trust_store
            if trust_store is not None
            else TrustStore(path=known_hosts_path, in_memory=(mode == "lab-memory"))
        )
        raw_pins = (
            pinned_fingerprints if pinned_fingerprints is not None else os.environ.get("ARODONATA_TLS_FINGERPRINTS", "")
        )
        self._pinned = parse_tls_fingerprints(raw_pins)

    @property
    def mode(self) -> TlsTrustMode:
        """Active TLS trust policy mode (`'pinned'`, `'tofu'`, or `'lab-memory'`)."""
        return self._mode

    @property
    def trust_store(self) -> TrustStore:
        """Underlying `TrustStore` instance."""
        return self._store

    @property
    def pinned_fingerprints(self) -> dict[str, str]:
        """Explicitly configured fingerprint pins (`ARODONATA_TLS_FINGERPRINTS`)."""
        return dict(self._pinned)

    def _is_fingerprint_trusted_elsewhere(self, fingerprint: str) -> bool:
        """Check if `fingerprint` is already trusted for another MDS/domain address in pins or store."""
        if fingerprint in self._pinned.values():
            return True
        return self._store.has_fingerprint_anywhere(fingerprint)

    @traced
    def verify_der(self, host: str, port: int, der_cert: bytes | None) -> str:
        """Verify raw DER certificate bytes presented by `(host, port)` before sending any HTTP request."""
        if not der_cert:
            raise TrustStoreError(f"Server at {host}:{port} did not present a peer certificate. No request was sent.")
        fp = compute_der_fingerprint(der_cert)
        return self.verify_fingerprint(host, port, fp)

    @traced
    def verify_fingerprint(self, host: str, port: int, presented_fingerprint: str) -> str:
        """Verify a normalized or hex SHA-256 fingerprint for `(host, port)` according to `self.mode`."""
        key = format_host_port(host, port)
        presented = normalize_fingerprint(presented_fingerprint)
        span_attrs(tls_host=host, tls_port=port, tls_mode=self._mode, tls_fingerprint=presented[:17])

        # 1. Check explicit per-address pin in ARODONATA_TLS_FINGERPRINTS first
        pinned_for_addr = self._pinned.get(key)
        if pinned_for_addr is not None:
            if presented != pinned_for_addr:
                raise CertificateMismatchError(
                    f"TLS certificate fingerprint mismatch for {key}: expected pinned {pinned_for_addr}, "
                    f"got {presented}. No request was sent."
                )
            return presented

        # 2. Check existing entry for this address in TrustStore
        stored_entry = self._store.get(host, port)
        if stored_entry is not None:
            if presented != stored_entry.fingerprint:
                raise CertificateMismatchError(
                    f"TLS certificate fingerprint mismatch for {key}: expected {stored_entry.fingerprint} "
                    f"({stored_entry.source}), got {presented}. No request was sent."
                )
            return presented

        # 3. Check if this certificate belongs to a known MDS member already trusted on another IP
        if self._is_fingerprint_trusted_elsewhere(presented):
            if self._mode in ("tofu", "lab-memory"):
                self._store.record(
                    host,
                    port,
                    presented,
                    source="known-identity",
                    persist=(self._mode == "tofu"),
                )
            return presented

        # 4. Handle unknown certificate for new address based on mode
        if self._mode == "pinned":
            raise UnknownServerCertificateError(
                f"Untrusted TLS server certificate for {key} (fingerprint {presented}) in 'pinned' mode. "
                "No request was sent."
            )

        if self._mode == "tofu":
            self._store.record(host, port, presented, source="tofu", persist=True)
            return presented

        # mode == "lab-memory"
        self._store.record(host, port, presented, source="lab-memory", persist=False)
        return presented


__all__ = [
    "KnownHostEntry",
    "TrustPolicy",
    "TrustStore",
    "compute_der_fingerprint",
    "format_host_attr_for_url",
    "format_host_port",
    "normalize_fingerprint",
    "parse_tls_fingerprints",
]
