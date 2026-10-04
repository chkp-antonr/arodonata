"""Verified, time-bounded connections to Check Point servers (Backlog #1 and #12).

Identity is a pinned SHA-256 certificate fingerprint per ``host:port`` (trust on first use by default), checked in
``connect()`` after the TLS handshake and before any application byte. cpapi's own ``check_fingerprint`` (cwd
``fingerprints.txt``, ``input()`` prompt, unchecked re-send) is bypassed. The only module allowed to build an
``ssl.SSLContext`` or to construct cpapi clients (``tests/unit/test_tls_hygiene.py``). Design:
``docs/superpowers/specs/2026-10-04-tls-fingerprint-verification-design.md``.
"""

from __future__ import annotations

import ipaddress
import json
import os
import stat
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows is not supported (spec D13)
    fcntl = None  # type: ignore[assignment]

from ..config.tls import normalize_sha256
from ..core.exceptions import TrustStoreError
from ..logger import lazy_logger

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
