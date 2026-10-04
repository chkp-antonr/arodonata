"""Verified, time-bounded connections to Check Point servers (Backlog #1 and #12).

Identity is a pinned SHA-256 certificate fingerprint per ``host:port`` (trust on first use by default), checked in
``connect()`` after the TLS handshake and before any application byte. cpapi's own ``check_fingerprint`` (cwd
``fingerprints.txt``, ``input()`` prompt, unchecked re-send) is bypassed. The only module allowed to build an
``ssl.SSLContext`` or to construct cpapi clients (``tests/unit/test_tls_hygiene.py``). Design:
``docs/superpowers/specs/2026-10-04-tls-fingerprint-verification-design.md``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import ssl
import stat
import tempfile
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows is not supported (spec D13)
    fcntl = None  # type: ignore[assignment]

from ..config.tls import TrustMode, colon_hex, normalize_sha256, resolve_store_path
from ..core.exceptions import (
    CertificateMismatchError,
    ConfigurationError,
    TrustStoreError,
    UnknownServerCertificateError,
)
from ..logger import lazy_logger

if TYPE_CHECKING:
    from ..config.settings import ArodonataSettings

log = lazy_logger("arodonata.asdk.tls")

_NOT_WRITABLE_HINT = (
    "set ARODONATA_TLS_KNOWN_HOSTS_PATH to a writable file, or ARODONATA_TLS_TRUST=pinned with "
    "ARODONATA_TLS_FINGERPRINTS"
)


def host_key(host: str, port: int) -> str:
    """Trust-store key: ``host:port`` as dialled, IPs normalised, IPv6 bracketed, hostnames lowercased."""
    name = host.strip()
    try:
        ip = ipaddress.ip_address(name.strip("[]"))
    except ValueError:
        return f"{name.lower()}:{port}"
    return f"[{ip.compressed}]:{port}" if ip.version == 6 else f"{ip.compressed}:{port}"


@dataclass(frozen=True)
class TrustEntry:
    """One trusted certificate: SHA-256 (64 lowercase hex), its PEM when known, how it was learned, when."""

    sha256: str
    pem: str | None
    source: str  # tofu | known-identity | manual | env | memory
    first_seen: str


def _entry(key: str, value: Any, path: Path) -> TrustEntry:
    if not isinstance(value, dict) or not isinstance(value.get("sha256"), str):
        raise TrustStoreError(f"TLS trust store {path}: entry '{key}' has no sha256; fix or remove that entry")
    try:
        sha = normalize_sha256(value["sha256"])
    except ValueError as exc:
        raise TrustStoreError(f"TLS trust store {path}: entry '{key}': {exc}") from exc
    pem = value.get("pem") if isinstance(value.get("pem"), str) else None
    return TrustEntry(sha, pem, str(value.get("source") or "manual"), str(value.get("first_seen") or ""))


class TrustStore:
    """The persisted ``host:port`` -> certificate map (spec D11-D13). Reads are lock-free; writes are atomic."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock_path = path.with_name(path.name + ".lock")
        self._thread_lock = threading.Lock()

    def load(self) -> dict[str, TrustEntry]:
        raw = self._read_raw()
        return {key: _entry(key, value, self.path) for key, value in raw["hosts"].items()}

    def record(self, key: str, entry: TrustEntry) -> TrustEntry:
        """Persist ``entry`` unless ``key`` is already recorded; return what the store holds for ``key``."""
        with self._thread_lock, self._file_lock():
            raw = self._read_raw()
            existing = raw["hosts"].get(key)
            if existing is not None:
                return _entry(key, existing, self.path)
            raw["hosts"][key] = {
                "sha256": entry.sha256,
                "pem": entry.pem,
                "first_seen": entry.first_seen,
                "source": entry.source,
            }
            raw.setdefault("version", 1)
            self._atomic_write(raw)
            return entry

    def ensure_writable(self) -> None:
        """Preflight for ``tofu``: the directory and lock file can be created and the store is sane."""
        with self._thread_lock, self._file_lock():
            self._read_raw()
            if not os.access(self.path.parent, os.W_OK):
                raise TrustStoreError(
                    f"TLS trust store directory {self.path.parent} is not writable; {_NOT_WRITABLE_HINT}"
                )

    def _read_raw(self) -> dict[str, Any]:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return {"version": 1, "hosts": {}}
        except OSError as exc:
            raise TrustStoreError(f"TLS trust store {self.path} cannot be read ({exc.strerror})") from exc
        if st.st_uid != os.getuid():
            raise TrustStoreError(f"TLS trust store {self.path} is owned by uid {st.st_uid}, not by this user")
        if st.st_mode & stat.S_IWOTH:
            raise TrustStoreError(f"TLS trust store {self.path} is world-writable; chmod 600 it")
        if st.st_mode & stat.S_IWGRP:
            log().warning(f"TLS trust store {self.path} is group-writable; chmod 600 it")
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise TrustStoreError(
                f"TLS trust store {self.path} is unreadable or not valid JSON ({type(exc).__name__}); "
                "fix or move it -- it is never rewritten while broken"
            ) from exc
        if not isinstance(data, dict) or not isinstance(data.get("hosts", {}), dict):
            raise TrustStoreError(f"TLS trust store {self.path} has no 'hosts' object; fix or move it")
        data.setdefault("hosts", {})
        for key, value in data["hosts"].items():
            _entry(key, value, self.path)  # validate every entry, so a bad one is never silently rewritten
        return data

    @contextmanager
    def _file_lock(self) -> Iterator[None]:
        if fcntl is None:  # pragma: no cover
            raise TrustStoreError(f"file locking is not available on this platform; {_NOT_WRITABLE_HINT}")
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            raise TrustStoreError(
                f"TLS trust store directory {self.path.parent} is not writable ({exc.strerror}); {_NOT_WRITABLE_HINT}"
            ) from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _atomic_write(self, raw: dict[str, Any]) -> None:
        try:
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".tls_known_hosts.", suffix=".tmp")  # mode 0600
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(raw, handle, indent=2, sort_keys=True)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, self.path)
            except BaseException:
                with suppress(FileNotFoundError):
                    os.unlink(tmp)
                raise
            dir_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError as exc:
            raise TrustStoreError(
                f"TLS trust store {self.path} cannot be written ({exc.strerror}); {_NOT_WRITABLE_HINT}"
            ) from exc


_LAB_MEMORY: dict[Path, dict[str, TrustEntry]] = {}  # lab-memory: one map per process and store path (spec D9)
_LAB_MEMORY_LOCK = threading.Lock()
_REPORTED: set[tuple[str, str]] = set()  # (key, presented sha) already logged at ERROR / WARNING this process


def reset_lab_memory() -> None:
    """Forget everything lab-memory learned in this process (tests only)."""
    with _LAB_MEMORY_LOCK:
        _LAB_MEMORY.clear()
    _REPORTED.clear()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _once(key: str, sha: str) -> bool:
    marker = (key, sha)
    if marker in _REPORTED:
        return False
    _REPORTED.add(marker)
    return True


class TrustPolicy:
    """Decides whether a presented certificate is the trusted one for ``host:port`` (spec D6)."""

    def __init__(self, mode: TrustMode, store: TrustStore, pins: Iterable[str]) -> None:
        self.mode = TrustMode(mode)
        self.store = store
        self._pins = frozenset(pins)
        self._session: dict[str, TrustEntry] = {}
        self._lock = threading.Lock()
        if self.mode is TrustMode.LAB_MEMORY:
            log().warning(
                f"TLS trust mode lab-memory: certificates are learned in memory only, nothing is written ({store.path})"
            )

    @classmethod
    def from_settings(cls, settings: ArodonataSettings) -> TrustPolicy:
        mode = TrustMode(settings.tls_trust)
        if mode is TrustMode.LAB_MEMORY and not os.environ.get("ARODONATA_LAB"):
            raise ConfigurationError(
                "ARODONATA_TLS_TRUST=lab-memory is honoured only in a lab run (ARODONATA_LAB set); "
                "use tofu, or pinned with ARODONATA_TLS_FINGERPRINTS"
            )
        return cls(mode, TrustStore(resolve_store_path(settings.tls_known_hosts_path)), settings.tls_fingerprints_list)

    def preflight(self) -> None:
        """Fail at startup instead of at the first new host (spec D14)."""
        if self.mode is TrustMode.TOFU:
            self.store.ensure_writable()
        else:
            self.store.load()

    def _memory(self) -> dict[str, TrustEntry]:
        with _LAB_MEMORY_LOCK:
            return _LAB_MEMORY.setdefault(self.store.path, {})

    def _known(self) -> dict[str, TrustEntry]:
        known = dict(self.store.load())
        if self.mode is TrustMode.LAB_MEMORY:
            for key, value in self._memory().items():
                known.setdefault(key, value)
        return known

    def anchor_pems(self, host: str, port: int) -> list[str] | None:
        key = host_key(host, port)
        with self._lock:
            hit = self._session.get(key)
        if hit is not None and hit.pem:
            return [hit.pem]
        if self._pins:
            return None
        entry = self._known().get(key)
        return [entry.pem] if entry is not None and entry.pem else None

    def check(self, host: str, port: int, der: bytes) -> TrustEntry:
        key = host_key(host, port)
        sha = hashlib.sha256(der).hexdigest()
        pem = ssl.DER_cert_to_PEM_cert(der)
        with self._lock:
            entry = self._decide(host, port, key, sha, pem, der)
            self._session[key] = entry if entry.pem else replace(entry, pem=pem)
            return self._session[key]

    def _decide(self, host: str, port: int, key: str, sha: str, pem: str, der: bytes) -> TrustEntry:
        known = self._known()
        recorded = known.get(key)
        if sha in self._pins:
            if recorded is not None and recorded.sha256 != sha and _once(key, sha):
                log().warning(
                    f"TLS {key}: stale store entry in {self.store.path}; the env pin ARODONATA_TLS_FINGERPRINTS wins"
                )
            return TrustEntry(sha, pem, "env", _now())
        if recorded is not None:
            if recorded.sha256 == sha:
                return recorded
            raise self._mismatch(host, port, key, sha, der, recorded)
        trusted = set(self._pins) | {value.sha256 for value in known.values()}
        if sha in trusted:
            entry = TrustEntry(sha, pem, "known-identity", _now())
            log().info(f"TLS {key}: certificate {colon_hex(sha)} is already trusted for another address")
            return self.store.record(key, entry) if self.mode is TrustMode.TOFU else entry
        if self.mode is TrustMode.PINNED:
            raise UnknownServerCertificateError(
                f"TLS certificate of {key} is not trusted (ARODONATA_TLS_TRUST=pinned). No request was sent.\n"
                f"  presented SHA-256: {colon_hex(sha)}\n"
                "Check it on the management server ('api fingerprint -f json') and add it to ARODONATA_TLS_FINGERPRINTS.",
                host=host,
                port=port,
                presented_sha256=sha,
                presented_sha1=hashlib.sha1(der, usedforsecurity=False).hexdigest(),
                source="pinned",
            )
        entry = TrustEntry(sha, pem, "tofu", _now())
        if self.mode is TrustMode.LAB_MEMORY:
            with _LAB_MEMORY_LOCK:
                stored = _LAB_MEMORY.setdefault(self.store.path, {}).setdefault(key, replace(entry, source="memory"))
            if stored.sha256 != sha:
                raise self._mismatch(host, port, key, sha, der, stored)
            log().warning(
                f"TLS {key}: first contact, certificate {colon_hex(sha)} trusted for this process only (lab-memory)"
            )
            return stored
        stored = self.store.record(key, entry)
        if stored.sha256 != sha:
            raise self._mismatch(host, port, key, sha, der, stored)
        log().warning(
            f"TLS {key}: first contact, certificate {colon_hex(sha)} trusted and recorded in {self.store.path}"
        )
        return stored

    def _mismatch(
        self, host: str, port: int, key: str, sha: str, der: bytes, expected: TrustEntry
    ) -> CertificateMismatchError:
        origin = "this process (lab-memory)" if expected.source == "memory" else str(self.store.path)
        message = (
            f"TLS certificate of {key} does not match the trusted one. No request was sent.\n"
            f"  expected SHA-256:  {colon_hex(expected.sha256)} (from {origin})\n"
            f"  presented SHA-256: {colon_hex(sha)}\n"
            f"  presented SHA-1:   {colon_hex(hashlib.sha1(der, usedforsecurity=False).hexdigest())}\n"
            "Check on the management server: 'api fingerprint -f json', or "
            "'cpopenssl x509 -in /web/conf/server.crt -noout -fingerprint -sha256'.\n"
            f"If the change is legitimate, replace the sha256 value of {key} in {self.store.path} "
            "(do not delete the entry), or add the new value to ARODONATA_TLS_FINGERPRINTS."
        )
        if _once(key, sha):
            log().error(message)
        return CertificateMismatchError(
            message,
            host=host,
            port=port,
            presented_sha256=sha,
            presented_sha1=hashlib.sha1(der, usedforsecurity=False).hexdigest(),
            expected_sha256=expected.sha256,
            source=origin,
        )
