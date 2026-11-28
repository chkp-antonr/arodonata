"""TLS certificate SHA-256 fingerprint verification (`TrustStore` and `TrustPolicy`).

Verifies server identity immediately after the TLS handshake and before any HTTP
request line, headers (`X-chkp-sid`), credentials, or JSON payloads are sent.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import stat
import sys
import tempfile
import weakref
from collections.abc import Mapping, Sequence
from pathlib import Path

if sys.platform == "win32":  # pragma: no cover
    import msvcrt
else:
    import fcntl

import arlogi
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
from arodonata.core.primitives import format_host_attr_for_url
from arodonata.core.telemetry import span_attrs, traced

logger = arlogi.get_logger("arodonata.adapters.checkpoint.tls")

_HEX_CLEAN_RE = re.compile(r"[^0-9a-fA-F]")


class PolicyBoundSSLContext(ssl.SSLContext):
    """TLS 1.2+ `ssl.SSLContext` bound explicitly to an immutable `TrustPolicy` reference and mode."""

    _trust_policy_mode: TlsTrustMode
    _trust_policy_ref: weakref.ReferenceType[TrustPolicy]

    def __new__(
        cls,
        protocol: int = ssl.PROTOCOL_TLS_CLIENT,
        *,
        trust_policy: TrustPolicy,
    ) -> PolicyBoundSSLContext:
        if not isinstance(trust_policy, TrustPolicy):
            raise ConfigurationError("PolicyBoundSSLContext requires a valid TrustPolicy instance.")
        obj = super().__new__(cls, protocol)
        obj._trust_policy_mode = trust_policy.mode
        obj._trust_policy_ref = weakref.ref(trust_policy)
        return obj

    @property
    def trust_policy_mode(self) -> TlsTrustMode:
        """TLS trust mode (`'pinned'`, `'tofu'`, or `'lab-memory'`) bound to this SSL context."""
        return self._trust_policy_mode

    @property
    def trust_policy(self) -> TrustPolicy | None:
        """Referenced `TrustPolicy` instance if still alive."""
        return self._trust_policy_ref()


def _build_pinned_ssl_context(trust_policy: TrustPolicy) -> PolicyBoundSSLContext:
    """Create a TLS 1.2+ `PolicyBoundSSLContext` designed for post-handshake SHA-256 pinning.

    Note:
        `check_hostname = False` and `verify_mode = ssl.CERT_NONE` are configured intentionally
        because Check Point Internal CA (ICA) server certificates routinely omit IP Subject
        Alternative Names (SANs) and blocking disk CA bundle loads inside async loops would stall
        concurrent MDS connections. Security is enforced immediately after the TLS handshake by
        `FingerprintTCPConnector` calling `TrustPolicy.verify_der()`, which validates the peer
        certificate SHA-256 fingerprint before any HTTP request line, `X-chkp-sid` header,
        credentials, or JSON payload bytes are transmitted.
    """
    ctx = PolicyBoundSSLContext(ssl.PROTOCOL_TLS_CLIENT, trust_policy=trust_policy)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION
    if hasattr(ssl, "OP_NO_RENEGOTIATION"):
        ctx.options |= ssl.OP_NO_RENEGOTIATION
    ctx.set_alpn_protocols(("http/1.1",))
    return ctx


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
        trust_mode: TlsTrustMode | None = None,
    ) -> None:
        self._path = Path(path).expanduser()
        self._in_memory = in_memory
        self._trust_mode: TlsTrustMode | None = trust_mode
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

    def _validate_parent_dir_security(self, parent: Path) -> None:
        """Verify parent directory is not a symlink, owned safely, and not non-sticky group/world writable."""
        if not os.path.lexists(parent):
            return
        try:
            st = os.lstat(parent)
        except OSError as exc:
            raise TrustStoreError(
                f"Failed to stat TLS trust store directory {str(parent)!r}: {exc}. No request was sent."
            ) from exc
        if stat.S_ISLNK(st.st_mode):
            raise TrustStoreError(
                f"Unsafe symlink TLS trust store directory {str(parent)!r}: symlinks are forbidden. No request was sent."
            )
        if not stat.S_ISDIR(st.st_mode):
            raise TrustStoreError(
                f"Unsafe TLS trust store directory {str(parent)!r}: expected directory. No request was sent."
            )
        if hasattr(os, "geteuid"):
            euid = os.geteuid()
            if st.st_uid not in (euid, 0):
                raise TrustStoreError(
                    f"Unsafe ownership on TLS trust store directory {str(parent)!r}: owned by uid {st.st_uid}, "
                    f"expected {euid}. No request was sent."
                )
        if os.name != "nt":
            mode = stat.S_IMODE(st.st_mode)
            is_sticky = bool(mode & stat.S_ISVTX)
            if (mode & (stat.S_IWGRP | stat.S_IWOTH)) and not is_sticky:
                raise TrustStoreError(
                    f"Unsafe permissions {oct(mode)} on TLS trust store directory {str(parent)!r}: "
                    "non-sticky group or world write permissions are forbidden (expected 0700). No request was sent."
                )

    def _validate_file_security(self) -> None:
        """Verify symlink refusal, ownership, and safe permissions on `self._path` and its parent directory."""
        self._validate_parent_dir_security(self._path.parent)
        try:
            st = os.lstat(self._path)
        except OSError as exc:
            raise TrustStoreError(
                f"Failed to stat TLS trust store at {str(self._path)!r}: {exc}. No request was sent."
            ) from exc
        if stat.S_ISLNK(st.st_mode):
            raise TrustStoreError(
                f"Unsafe symlink TLS trust store at {str(self._path)!r}: symlinks are forbidden. No request was sent."
            )
        if not stat.S_ISREG(st.st_mode):
            raise TrustStoreError(
                f"Unsafe TLS trust store at {str(self._path)!r}: expected regular file. No request was sent."
            )
        euid = os.geteuid() if hasattr(os, "geteuid") else None
        if euid is not None and st.st_uid not in (euid, 0):
            raise TrustStoreError(
                f"Unsafe ownership on TLS trust store {str(self._path)!r}: owned by uid {st.st_uid}, "
                f"expected {euid}. No request was sent."
            )
        if os.name != "nt":
            mode = stat.S_IMODE(st.st_mode)
            if mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise TrustStoreError(
                    f"Unsafe permissions {oct(mode)} on TLS trust store {str(self._path)!r}: "
                    "group or world write permissions are forbidden (expected 0600). No request was sent."
                )
            # Preserve uid=0 read-only ConfigMap mounts (0444/0644), while warning on euid-owned TOFU stores
            # whose group/world read bits expose local trust-store metadata.
            is_owner_managed_tofu = (self._trust_mode or "tofu") == "tofu" and (
                euid is None or (euid != 0 and st.st_uid == euid)
            )
            if is_owner_managed_tofu and (mode & (stat.S_IRGRP | stat.S_IROTH)):
                logger.warning(
                    "tls_trust_store_over_readable",
                    event="tls_trust_store_over_readable",
                    path=str(self._path),
                    mode=oct(mode),
                    expected_mode="0o600",
                )

    def _read_entries_from_disk(self) -> dict[str, KnownHostEntry]:
        """Read and validate entries from `self._path` if present on disk."""
        self._validate_parent_dir_security(self._path.parent)
        if not os.path.lexists(self._path):
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
        key = format_host_port(host, port)
        return self.record_many([(host, port)], fingerprint, source=source, persist=persist)[key]

    def record_many(
        self,
        targets: Sequence[tuple[str, int]],
        fingerprint: str,
        *,
        source: str = "tofu",
        persist: bool = True,
    ) -> dict[str, KnownHostEntry]:
        """Record a trusted fingerprint for multiple `(host, port)` targets atomically.

        Checks all target keys against on-disk entries inside a single `flock` critical section
        before writing or replacing `tls_known_hosts.json` so a conflict on any target never
        persists a partial write for sibling targets.
        """
        self.load()
        normalized = normalize_fingerprint(fingerprint)
        now_iso = utc_now().isoformat()
        updates: dict[str, KnownHostEntry] = {}
        for host, port in targets:
            key = format_host_port(host, port)
            if key in updates:
                continue
            existing = self._entries.get(key)
            updates[key] = KnownHostEntry(
                fingerprint=normalized,
                source=source,
                first_seen_at=existing.first_seen_at if existing else now_iso,
                last_seen_at=now_iso,
            )
        if not updates:
            return {}
        if persist and not self._in_memory:
            self._save_atomic(updates=updates)
        else:
            for key, entry in updates.items():
                existing = self._entries.get(key)
                if existing is not None and existing.fingerprint != entry.fingerprint:
                    raise CertificateMismatchError(
                        f"TLS certificate fingerprint mismatch for {key}: "
                        f"expected {existing.fingerprint}, got {entry.fingerprint}. No request was sent."
                    )
            self._entries.update(updates)
        return updates

    def _save_atomic(
        self,
        updated_key: str | None = None,
        updated_entry: KnownHostEntry | None = None,
        *,
        updates: Mapping[str, KnownHostEntry] | None = None,
    ) -> None:
        """Atomically merge and write `self._entries` to `self._path` with `fcntl.flock` and mode `0600`."""
        parent = self._path.parent
        lock_path = parent / f".{self._path.name}.lock"
        pending: dict[str, KnownHostEntry] = dict(updates) if updates else {}
        if updated_key is not None and updated_entry is not None:
            pending[updated_key] = updated_entry
        try:
            self._validate_parent_dir_security(parent)
            if not parent.exists():
                missing_parents: list[Path] = []
                cur = parent
                while not cur.exists() and cur != cur.parent:
                    missing_parents.append(cur)
                    cur = cur.parent
                parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if os.name != "nt" and hasattr(os, "chmod"):
                    for created_dir in missing_parents:
                        os.chmod(created_dir, 0o700)
            self._validate_parent_dir_security(parent)
            if os.path.lexists(lock_path):
                lock_st = os.lstat(lock_path)
                if stat.S_ISLNK(lock_st.st_mode):
                    raise TrustStoreError(
                        f"Unsafe symlink TLS trust store lock at {str(lock_path)!r}: symlinks are forbidden. "
                        "No request was sent."
                    )
            if os.path.lexists(self._path):
                self._validate_file_security()
            open_flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            lock_fd = os.open(str(lock_path), open_flags, 0o600)
            try:
                if sys.platform == "win32":  # pragma: no cover
                    os.lseek(lock_fd, 0, os.SEEK_SET)
                    msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)
                else:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX)
                disk_entries = self._read_entries_from_disk()
                merged = dict(disk_entries)
                for k, v in self._entries.items():
                    if k not in merged:
                        merged[k] = v
                for k, v in pending.items():
                    existing_on_disk = disk_entries.get(k)
                    if existing_on_disk is not None and existing_on_disk.fingerprint != v.fingerprint:
                        raise CertificateMismatchError(
                            f"TLS certificate fingerprint mismatch for {k} during concurrent TOFU merge: "
                            f"expected {existing_on_disk.fingerprint}, got {v.fingerprint}. "
                            "No request was sent."
                        )
                merged.update(pending)

                payload = {
                    "version": 1,
                    "hosts": {k: v.model_dump() for k, v in sorted(merged.items())},
                }
                serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"

                fd, tmp_path_str = tempfile.mkstemp(
                    prefix=f".{self._path.name}.",
                    suffix=".tmp",
                    dir=str(parent),
                )
                tmp_path = Path(tmp_path_str)
                try:
                    if hasattr(os, "fchmod"):
                        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
                    with os.fdopen(fd, "w", encoding="utf-8") as handle:
                        handle.write(serialized)
                        handle.flush()
                        os.fsync(handle.fileno())
                    if hasattr(os, "chmod"):
                        os.chmod(tmp_path, 0o600)
                    os.replace(tmp_path, self._path)
                    if hasattr(os, "chmod"):
                        os.chmod(self._path, 0o600)
                except Exception:
                    if tmp_path.exists():
                        tmp_path.unlink(missing_ok=True)
                    raise
                self._entries = merged
            finally:
                try:
                    if sys.platform == "win32":  # pragma: no cover
                        try:
                            os.lseek(lock_fd, 0, os.SEEK_SET)
                            msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
                        except OSError:
                            pass
                    else:
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
            else TrustStore(path=known_hosts_path, in_memory=(mode == "lab-memory"), trust_mode=mode)
        )
        raw_pins = (
            pinned_fingerprints if pinned_fingerprints is not None else os.environ.get("ARODONATA_TLS_FINGERPRINTS", "")
        )
        self._pinned = parse_tls_fingerprints(raw_pins)
        self._ssl_context: PolicyBoundSSLContext | None = None

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

    def create_ssl_context(self) -> PolicyBoundSSLContext:
        """Create a TLS 1.2+ client `PolicyBoundSSLContext` bound to this validated `TrustPolicy`.

        Security Invariant:
            Hostname checking and CA store verification are intentionally delegated to
            post-handshake, pre-request SHA-256 DER fingerprint verification (`verify_der`)
            because Check Point Internal CA (ICA) certificates frequently lack IP SANs and
            loading system CA stores synchronously would block the event loop. Calling
            `FingerprintTCPConnector` ensures `verify_der()` completes before any HTTP request
            line, credentials, or `X-chkp-sid` headers are sent on the wire.
        """
        if self._ssl_context is None:
            self._ssl_context = _build_pinned_ssl_context(self)
        return self._ssl_context

    def _is_fingerprint_trusted_elsewhere(self, fingerprint: str) -> bool:
        """Check if `fingerprint` is already trusted for another MDS/domain address in pins or store."""
        if fingerprint in self._pinned.values():
            return True
        return self._store.has_fingerprint_anywhere(fingerprint)

    @traced
    def verify_der(
        self,
        host: str,
        port: int,
        der_cert: bytes | None,
        *,
        identity_host: str | None = None,
    ) -> str:
        """Verify raw DER certificate bytes presented by `(host, port)` before sending any HTTP request."""
        if not der_cert:
            span_attrs(tls_host=host, tls_port=port, tls_mode=self._mode, tls_decision="missing_cert")
            logger.error(
                "tls_missing_peer_certificate",
                event="tls_missing_peer_certificate",
                host=host,
                port=port,
                mode=self._mode,
            )
            raise TrustStoreError(f"Server at {host}:{port} did not present a peer certificate. No request was sent.")
        fp = compute_der_fingerprint(der_cert)
        return self.verify_fingerprint(host, port, fp, identity_host=identity_host)

    @traced
    def verify_fingerprint(
        self,
        host: str,
        port: int,
        presented_fingerprint: str,
        *,
        identity_host: str | None = None,
    ) -> str:
        """Verify a normalized or hex SHA-256 fingerprint for `(host, port)` according to `self.mode`."""
        key = format_host_port(host, port)
        clean_identity = identity_host.strip() if isinstance(identity_host, str) and identity_host.strip() else None
        id_host = clean_identity if (clean_identity is not None and clean_identity != host) else None
        id_key = format_host_port(id_host, port) if id_host is not None else None
        presented = normalize_fingerprint(presented_fingerprint)
        span_attrs(tls_host=host, tls_port=port, tls_mode=self._mode, tls_fingerprint=presented[:17])

        # 1. Check explicit per-address pins in ARODONATA_TLS_FINGERPRINTS (both resolved IP and identity_host)
        pinned_for_addr = self._pinned.get(key)
        pinned_for_id = self._pinned.get(id_key) if id_key is not None else None
        if pinned_for_addr is not None and presented != pinned_for_addr:
            span_attrs(tls_decision="mismatch")
            logger.error(
                "tls_certificate_mismatch",
                event="tls_certificate_mismatch",
                host=host,
                port=port,
                expected_fingerprint=pinned_for_addr,
                presented_fingerprint=presented,
                mode=self._mode,
                source="pinned",
            )
            raise CertificateMismatchError(
                f"TLS certificate fingerprint mismatch for {key}: expected pinned {pinned_for_addr}, "
                f"got {presented}. No request was sent."
            )
        if pinned_for_id is not None and presented != pinned_for_id:
            span_attrs(tls_decision="mismatch")
            logger.error(
                "tls_certificate_mismatch",
                event="tls_certificate_mismatch",
                host=id_host,
                port=port,
                expected_fingerprint=pinned_for_id,
                presented_fingerprint=presented,
                mode=self._mode,
                source="pinned",
            )
            raise CertificateMismatchError(
                f"TLS certificate fingerprint mismatch for {id_key} (resolved to {key}): "
                f"expected pinned {pinned_for_id}, got {presented}. No request was sent."
            )
        if pinned_for_addr is not None or pinned_for_id is not None:
            span_attrs(tls_decision="pinned_match")
            return presented

        # 2. Check existing entries for this address and identity_host in TrustStore
        stored_entry = self._store.get(host, port)
        stored_id_entry = self._store.get(id_host, port) if id_host is not None else None
        if stored_entry is not None and presented != stored_entry.fingerprint:
            span_attrs(tls_decision="mismatch")
            logger.error(
                "tls_certificate_mismatch",
                event="tls_certificate_mismatch",
                host=host,
                port=port,
                expected_fingerprint=stored_entry.fingerprint,
                presented_fingerprint=presented,
                mode=self._mode,
                source=stored_entry.source,
            )
            raise CertificateMismatchError(
                f"TLS certificate fingerprint mismatch for {key}: expected {stored_entry.fingerprint} "
                f"({stored_entry.source}), got {presented}. No request was sent."
            )
        if stored_id_entry is not None and presented != stored_id_entry.fingerprint:
            span_attrs(tls_decision="mismatch")
            logger.error(
                "tls_certificate_mismatch",
                event="tls_certificate_mismatch",
                host=id_host,
                port=port,
                expected_fingerprint=stored_id_entry.fingerprint,
                presented_fingerprint=presented,
                mode=self._mode,
                source=stored_id_entry.source,
            )
            raise CertificateMismatchError(
                f"TLS certificate fingerprint mismatch for {id_key} (resolved to {key}): "
                f"expected {stored_id_entry.fingerprint} ({stored_id_entry.source}), got {presented}. "
                "No request was sent."
            )
        matched_entry = stored_entry if stored_entry is not None else stored_id_entry
        if matched_entry is not None:
            if self._mode in ("tofu", "lab-memory"):
                persist_known = self._mode == "tofu"
                missing_targets: list[tuple[str, int]] = []
                if stored_entry is None and stored_id_entry is not None:
                    missing_targets.append((host, port))
                if stored_id_entry is None and id_host is not None and id_key != key:
                    missing_targets.append((id_host, port))
                if missing_targets:
                    try:
                        self._store.record_many(
                            missing_targets,
                            presented,
                            source="known-identity",
                            persist=persist_known,
                        )
                    except CertificateMismatchError:
                        span_attrs(tls_decision="mismatch")
                        logger.error(
                            "tls_certificate_mismatch",
                            event="tls_certificate_mismatch",
                            host=host,
                            port=port,
                            presented_fingerprint=presented,
                            mode=self._mode,
                            source="tofu_concurrent_merge",
                        )
                        raise
            decision_by_source = {
                "tofu": "tofu_match",
                "stored": "stored_match",
                "lab-memory": "lab_memory_match",
                "known-identity": "known_identity_match",
                "pinned": "pinned_match",
            }
            span_attrs(tls_decision=decision_by_source.get(matched_entry.source, "stored_match"))
            return presented

        # 3. Check if this certificate belongs to a known MDS member already trusted on another IP
        if self._is_fingerprint_trusted_elsewhere(presented):
            if self._mode in ("tofu", "lab-memory"):
                persist_known = self._mode == "tofu"
                targets: list[tuple[str, int]] = [(host, port)]
                if id_host is not None and id_key != key:
                    targets.append((id_host, port))
                try:
                    self._store.record_many(
                        targets,
                        presented,
                        source="known-identity",
                        persist=persist_known,
                    )
                except CertificateMismatchError:
                    span_attrs(tls_decision="mismatch")
                    logger.error(
                        "tls_certificate_mismatch",
                        event="tls_certificate_mismatch",
                        host=host,
                        port=port,
                        presented_fingerprint=presented,
                        mode=self._mode,
                        source="tofu_concurrent_merge",
                    )
                    raise
            span_attrs(tls_decision="known_identity_match")
            return presented

        # 4. Handle unknown certificate for new address based on mode
        if self._mode == "pinned":
            span_attrs(tls_decision="unpinned_rejected")
            logger.warning(
                "tls_unpinned_certificate_rejected",
                event="tls_unpinned_certificate_rejected",
                host=host,
                port=port,
                fingerprint=presented,
                mode=self._mode,
            )
            raise UnknownServerCertificateError(
                f"Untrusted TLS server certificate for {key} (fingerprint {presented}) in 'pinned' mode. "
                "No request was sent."
            )

        if self._mode == "tofu":
            targets = [(host, port)]
            if id_host is not None and id_key != key:
                targets.append((id_host, port))
            try:
                self._store.record_many(targets, presented, source="tofu", persist=True)
            except CertificateMismatchError:
                span_attrs(tls_decision="mismatch")
                logger.error(
                    "tls_certificate_mismatch",
                    event="tls_certificate_mismatch",
                    host=host,
                    port=port,
                    presented_fingerprint=presented,
                    mode="tofu",
                    source="tofu_concurrent_merge",
                )
                raise
            span_attrs(tls_decision="tofu_first_contact")
            logger.warning(
                "tls_tofu_first_contact",
                event="tls_tofu_first_contact",
                host=host,
                port=port,
                fingerprint=presented,
                mode="tofu",
            )
            return presented

        # mode == "lab-memory"
        targets = [(host, port)]
        if id_host is not None and id_key != key:
            targets.append((id_host, port))
        self._store.record_many(targets, presented, source="lab-memory", persist=False)
        span_attrs(tls_decision="lab_memory_first_contact")
        logger.warning(
            "tls_tofu_first_contact",
            event="tls_tofu_first_contact",
            host=host,
            port=port,
            fingerprint=presented,
            mode="lab-memory",
        )
        return presented


def create_verified_ssl_context(trust_policy: TrustPolicy) -> PolicyBoundSSLContext:
    """Create a TLS 1.2+ `PolicyBoundSSLContext` explicitly bound to a validated `TrustPolicy`.

    Raises:
        ConfigurationError: If `trust_policy` is not a valid `TrustPolicy` instance.
    """
    if not isinstance(trust_policy, TrustPolicy):
        raise ConfigurationError("create_verified_ssl_context requires a valid TrustPolicy instance.")
    return trust_policy.create_ssl_context()


__all__ = [
    "KnownHostEntry",
    "PolicyBoundSSLContext",
    "TrustPolicy",
    "TrustStore",
    "compute_der_fingerprint",
    "create_verified_ssl_context",
    "format_host_attr_for_url",
    "format_host_port",
    "normalize_fingerprint",
    "parse_tls_fingerprints",
]
