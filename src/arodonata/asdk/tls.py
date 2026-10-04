"""Verified, time-bounded connections to Check Point servers (Backlog #1 and #12).

Identity is a pinned SHA-256 certificate fingerprint per ``host:port`` (trust on first use by default), checked in
``connect()`` after the TLS handshake and before any application byte. cpapi's own ``check_fingerprint`` (cwd
``fingerprints.txt``, ``input()`` prompt, unchecked re-send) is bypassed. The only module allowed to build an
``ssl.SSLContext`` or to construct cpapi clients (``tests/unit/test_tls_hygiene.py``). Design:
``docs/superpowers/specs/2026-10-04-tls-fingerprint-verification-design.md``.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import socket
import ssl
import stat
import sys
import tempfile
import threading
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows is not supported (spec D13)
    fcntl = None  # type: ignore[assignment]

from cpapi import APIClient, APIClientArgs
from cpapi.mgmt_api import HTTPSConnection as _CpapiHTTPSConnection

from ..config.constants import DEFAULT_CONNECT_TIMEOUT
from ..config.tls import TrustMode, colon_hex, normalize_sha256, resolve_store_path
from ..core.exceptions import (
    ApiTimeoutError,
    ArodonataError,
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


def _emit(level: str, message: str) -> None:
    """Log ``message`` literally: arlogi's console handler renders Rich markup and emoji, which would eat
    a bracketed IPv6 key and turn a fingerprint pair like ``:AB:`` into an emoji. ``markup=False`` makes
    RichHandler build a plain ``Text`` (no markup, no emoji codes). ``stacklevel=3`` skips this helper and
    arlogi's wrapper (whose own default is 2), so the record names the real call site."""
    getattr(log(), level)(message, extra={"markup": False}, stacklevel=3)


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
            _emit("warning", f"TLS trust store {self.path} is group-writable; chmod 600 it")
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
_MISMATCH_REPORTED: set[tuple[str, str]] = set()  # (key, presented sha) already logged at ERROR this process
_STALE_REPORTED: set[str] = set()  # keys already warned about a stale store entry this process


def reset_lab_memory() -> None:
    """Forget everything lab-memory learned in this process (tests only)."""
    with _LAB_MEMORY_LOCK:
        _LAB_MEMORY.clear()
    _MISMATCH_REPORTED.clear()
    _STALE_REPORTED.clear()


def _pem_matches(pem: str, sha: str) -> bool:
    try:
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest() == sha
    except ValueError:
        return False


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _once(key: str, sha: str) -> bool:
    marker = (key, sha)
    if marker in _MISMATCH_REPORTED:
        return False
    _MISMATCH_REPORTED.add(marker)
    return True


def _stale_once(key: str) -> bool:
    if key in _STALE_REPORTED:
        return False
    _STALE_REPORTED.add(key)
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
            _emit(
                "warning",
                f"TLS trust mode lab-memory: certificates are learned in memory only, nothing is written ({store.path})",
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
            return dict(_LAB_MEMORY.get(self.store.path, {}))

    def _remember(self, key: str, entry: TrustEntry) -> TrustEntry:
        """lab-memory counterpart of ``TrustStore.record``: an existing value wins."""
        with _LAB_MEMORY_LOCK:
            return _LAB_MEMORY.setdefault(self.store.path, {}).setdefault(key, replace(entry, source="memory"))

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
        if entry is not None and entry.pem and _pem_matches(entry.pem, entry.sha256):
            return [entry.pem]
        return None  # no PEM, or one that is not the trusted certificate (stale after a manual re-trust): probe

    def check(self, host: str, port: int, der: bytes) -> TrustEntry:
        key = host_key(host, port)
        sha = hashlib.sha256(der).hexdigest()
        pem = ssl.DER_cert_to_PEM_cert(der)
        with self._lock:
            entry = self._decide(host, port, key, sha, pem, der)
            # the presented DER is by construction the accepted certificate, whatever PEM the entry carries
            self._session[key] = replace(entry, pem=pem)
            return self._session[key]

    def _learn(self, host: str, port: int, key: str, sha: str, der: bytes, entry: TrustEntry) -> TrustEntry:
        """Remember ``entry`` (store in tofu, process map in lab-memory); an existing value wins and must match."""
        if self.mode is TrustMode.TOFU:
            stored = self.store.record(key, entry)
        elif self.mode is TrustMode.LAB_MEMORY:
            stored = self._remember(key, entry)
        else:
            return entry
        if stored.sha256 != sha:  # another process (or this one) recorded a different value first
            raise self._mismatch(host, port, key, sha, der, stored)
        return stored

    def _decide(self, host: str, port: int, key: str, sha: str, pem: str, der: bytes) -> TrustEntry:
        known = self._known()
        recorded = known.get(key)
        if sha in self._pins:
            if recorded is not None and recorded.sha256 != sha and _stale_once(key):
                _emit(
                    "warning",
                    f"TLS {key}: stale store entry in {self.store.path}; the env pin ARODONATA_TLS_FINGERPRINTS wins",
                )
            return TrustEntry(sha, pem, "env", _now())
        if recorded is not None:
            if recorded.sha256 == sha:
                return recorded
            raise self._mismatch(host, port, key, sha, der, recorded)
        trusted = set(self._pins) | {value.sha256 for value in known.values()}
        if sha in trusted:
            entry = TrustEntry(sha, pem, "known-identity", _now())
            _emit("info", f"TLS {key}: certificate {colon_hex(sha)} is already trusted for another address")
            return self._learn(host, port, key, sha, der, entry)
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
        stored = self._learn(host, port, key, sha, der, TrustEntry(sha, pem, "tofu", _now()))
        where = (
            "trusted for this process only (lab-memory)"
            if self.mode is TrustMode.LAB_MEMORY
            else f"trusted and recorded in {self.store.path}"
        )
        _emit("warning", f"TLS {key}: first contact, certificate {colon_hex(sha)} {where}")
        return stored

    def _mismatch(
        self, host: str, port: int, key: str, sha: str, der: bytes, expected: TrustEntry
    ) -> CertificateMismatchError:
        in_memory = expected.source == "memory"
        origin = "this process (lab-memory)" if in_memory else str(self.store.path)
        remedy = (
            "restart the process, or add the new value to ARODONATA_TLS_FINGERPRINTS."
            if in_memory
            else f"replace the sha256 value of {key} in {self.store.path} (do not delete the entry), "
            "or add the new value to ARODONATA_TLS_FINGERPRINTS."
        )
        message = (
            f"TLS certificate of {key} does not match the trusted one. No request was sent.\n"
            f"  expected SHA-256:  {colon_hex(expected.sha256)} (from {origin})\n"
            f"  presented SHA-256: {colon_hex(sha)}\n"
            f"  presented SHA-1:   {colon_hex(hashlib.sha1(der, usedforsecurity=False).hexdigest())}\n"
            "Check on the management server: 'api fingerprint -f json', or "
            "'cpopenssl x509 -in /web/conf/server.crt -noout -fingerprint -sha256'.\n"
            f"If the change is legitimate, {remedy}"
        )
        if _once(key, sha):
            _emit("error", message)
        return CertificateMismatchError(
            message,
            host=host,
            port=port,
            presented_sha256=sha,
            presented_sha1=hashlib.sha1(der, usedforsecurity=False).hexdigest(),
            expected_sha256=expected.sha256,
            source=origin,
        )


_X509_V_FLAG_NO_CHECK_TIME = 0x200000  # OpenSSL X509_V_FLAG_NO_CHECK_TIME; Python has no constant (spec D2)


def anchored_context(pems: Sequence[str]) -> ssl.SSLContext:
    """CERT_REQUIRED with the pinned certificate(s) as the only trust anchors; no hostname, no expiry check."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # loads no default CAs: the pins are the only anchors
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_RENEGOTIATION
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN | _X509_V_FLAG_NO_CHECK_TIME
    context.load_verify_locations(cadata="".join(pems))
    return context


def probe_certificate(host: str, port: int, timeout: float) -> bytes:
    """Handshake only, to read the presented certificate; never carries application data (spec D3).

    The single CERT_NONE site in the repo: the certificate is judged by ``TrustPolicy.check`` afterwards, and only
    an accepted one becomes the trust anchor of the connection that carries data.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            context.wrap_socket(raw, server_hostname=None) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
    except TimeoutError as exc:
        raise ApiTimeoutError(
            f"TLS handshake with {host_key(host, port)} did not complete within {timeout}s",
            phase="connect",
            host=host,
            port=port,
            timeout=timeout,
        ) from exc
    if not der:
        raise ssl.SSLError(f"{host_key(host, port)} presented no certificate")
    return der


class PinnedHTTPSConnection(_CpapiHTTPSConnection):  # type: ignore[misc]
    """cpapi's connection with the identity check in ``connect()`` (spec D4)."""

    sock: socket.socket | None  # set by http.client; the base class is untyped

    def __init__(self, client: VerifiedAPIClient, pems: Sequence[str]) -> None:
        super().__init__(
            client.server, client.get_port(), timeout=client.connect_timeout, context=anchored_context(pems)
        )
        self._client = client

    def connect(self) -> None:
        client = self._client
        host, port = client.server, client.get_port()
        try:
            raw = self._tcp_connect()
            try:
                tls = self._context.wrap_socket(raw, server_hostname=None)
            except ssl.SSLCertVerificationError as exc:
                raw.close()
                raise self._refused(host, port, exc) from exc
            except TimeoutError as exc:
                raw.close()
                raise self._connect_timeout("TLS handshake with") from exc
            except BaseException:
                raw.close()
                raise
            try:
                der = tls.getpeercert(binary_form=True)
                if not der:
                    raise ssl.SSLError(f"{host_key(host, port)} presented no certificate")
                client.policy.check(host, port, der)  # authoritative SHA-256 comparison (spec D2)
                tls.settimeout(client.read_timeout)  # only now: the handshake ran under the connect timeout
            except BaseException:
                tls.close()
                raise
            self.sock = tls
        except ArodonataError as exc:
            client.record_failure(exc)
            raise

    def _tcp_connect(self) -> socket.socket:
        """TCP connect under the connect timeout (spec D15); returns the plain socket with ``self.sock`` None."""
        try:
            http.client.HTTPConnection.connect(self)
        except BaseException as exc:
            # it sets self.sock before TCP_NODELAY, which can still raise: never leave a plaintext socket behind
            half_open, self.sock = self.sock, None
            if half_open is not None:
                half_open.close()
            if isinstance(exc, TimeoutError):
                raise self._connect_timeout("TCP connect to") from exc
            raise
        raw, self.sock = self.sock, None  # a plaintext socket is never reachable through the connection
        if raw is None:  # pragma: no cover - HTTPConnection.connect() sets a socket or raises
            raise OSError(f"no socket to {host_key(self.host, self.port)}")
        return raw

    def _connect_timeout(self, what: str) -> ApiTimeoutError:
        client = self._client
        host, port = client.server, client.get_port()
        return ApiTimeoutError(
            f"{what} {host_key(host, port)} did not complete within {client.connect_timeout}s",
            phase="connect",
            host=host,
            port=port,
            timeout=client.connect_timeout,
            command=client.command,
        )

    def _refused(self, host: str, port: int, cause: ssl.SSLCertVerificationError) -> ArodonataError:
        """The anchored handshake refused the certificate: name the precise identity error, sending nothing."""
        client = self._client
        key = host_key(host, port)
        try:
            der = probe_certificate(host, port, client.connect_timeout)
        except OSError as exc:  # ApiTimeoutError included: the refusal itself is the identity fact
            message = (
                f"TLS certificate of {key} failed verification against the trusted certificate "
                f"({cause.verify_message}) and could not be read again ({type(exc).__name__}). No request was sent."
            )
            if _once(key, ""):
                _emit("error", message)
            return CertificateMismatchError(message, host=host, port=port, source="anchor")
        client.policy.check(host, port, der)  # raises the precise identity error
        # accepted: the trusted value changed since this connection's anchor was chosen (an operator re-trust in a
        # running process); refuse this attempt, the next one anchors on the accepted certificate
        return CertificateMismatchError(
            f"TLS certificate of {key} changed during the connection (anchored verification: "
            f"{cause.verify_message}). No request was sent.",
            host=host,
            port=port,
            presented_sha256=hashlib.sha256(der).hexdigest(),
            presented_sha1=hashlib.sha1(der, usedforsecurity=False).hexdigest(),
            source="anchor",
        )


class VerifiedAPIClient(APIClient):  # type: ignore[misc]
    """cpapi client whose every connection is verified and time-bounded (spec D5)."""

    def __init__(
        self, args: APIClientArgs, *, policy: TrustPolicy, connect_timeout: float, read_timeout: float
    ) -> None:
        super().__init__(args)
        self.policy = policy
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.command = ""
        self._failure: ArodonataError | None = None

    def record_failure(self, exc: ArodonataError) -> None:
        self._failure = exc

    def check_fingerprint(self) -> bool:
        return True  # identity is enforced in PinnedHTTPSConnection.connect(); cpapi's file and input() are bypassed

    def create_https_connection(self) -> PinnedHTTPSConnection:
        if self._failure is not None:
            raise self._failure  # cpapi's re-send branch after connect() failed on http.client's auto-reopen
        current = sys.exception()
        if self.conn is not None and isinstance(current, TimeoutError):
            # Only cpapi's re-send branch (mgmt_api.py, except IOError -> create_https_connection) calls us while
            # handling an exception. A timed-out request may already have run on the server: never send it again.
            host, port = self.server, self.get_port()
            with suppress(Exception):
                self.conn.close()  # a late reply must never be read as the answer to a later request
            raise ApiTimeoutError(
                f"{self.command or 'request'} to {host_key(host, port)}: no response within "
                f"{self.read_timeout}s; the command may still have run on the server",
                phase="read",
                host=host,
                port=port,
                timeout=self.read_timeout,
                command=self.command,
            ) from current
        host, port = self.server, self.get_port()
        pems = self.policy.anchor_pems(host, port)
        if not pems:
            entry = self.policy.check(host, port, probe_certificate(host, port, self.connect_timeout))
            pems = [entry.pem] if entry.pem else []
        conn = PinnedHTTPSConnection(self, pems)
        conn.set_debuglevel(0)
        conn.connect()
        return conn

    def api_call(self, command, payload=None, sid=None, wait_for_task=True, timeout=-1, method="POST"):  # type: ignore[no-untyped-def]
        self.command = command
        self._failure = None
        sock = getattr(self.conn, "sock", None)
        if sock is not None:
            sock.settimeout(self.read_timeout)  # read_timeout is set per call (spec D16); the connection is cached
        response = super().api_call(command, payload, sid, wait_for_task, timeout, method)
        if self._failure is not None:
            raise self._failure  # folded into a generic APIResponse by cpapi's `except Exception` (auto-reopen path)
        folded = getattr(response, "error_message", None)
        if isinstance(folded, ArodonataError):
            raise folded
        return response


def verified_api_client(
    server: str,
    port: int | None = None,
    *,
    sid: str | None = None,
    policy: TrustPolicy | None = None,
    settings: ArodonataSettings | None = None,
    connect_timeout: float | None = None,
    read_timeout: float | None = None,
) -> VerifiedAPIClient:
    """The only way arodonata (and its lab scripts) builds a cpapi client (spec D23)."""
    if policy is None or connect_timeout is None or read_timeout is None:
        if settings is None:
            from ..config.settings import ArodonataSettings

            settings = ArodonataSettings()
        policy = policy or TrustPolicy.from_settings(settings)
        connect_timeout = connect_timeout or settings.connect_timeout
        read_timeout = read_timeout or settings.default_read_timeout
    return VerifiedAPIClient(
        APIClientArgs(server=server, port=port, sid=sid),
        policy=policy,
        connect_timeout=float(connect_timeout or DEFAULT_CONNECT_TIMEOUT),
        read_timeout=float(read_timeout),
    )
