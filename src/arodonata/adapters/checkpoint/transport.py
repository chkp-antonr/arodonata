"""Native `aiohttp` Check Point Web API transport and `VerifiedConnectionPool`.

Enforces pre-request SHA-256 certificate fingerprint verification immediately after
the TLS handshake, separate socket connect/read timeouts, strict prohibition of
silent request re-transmission after socket write, and 10-second idle keep-alive
pooling restricted to read-only `show-*` commands.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import ssl
import time
import weakref
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Protocol

import aiohttp
from aiohttp.client_proto import ResponseHandler
from aiohttp.client_reqrep import ClientRequest, ConnectionKey
from aiohttp.connector import Connection
from aiohttp.tracing import Trace

from arodonata.adapters.checkpoint.tls import TrustPolicy, format_host_attr_for_url
from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import (
    ApiTimeoutError,
    ConfigurationError,
    ServerIdentityError,
    TransportError,
    TrustStoreError,
    ValidationError,
    redact_sid,
)
from arodonata.core.models.common import ApiCallResult
from arodonata.core.telemetry import span_attrs, traced

KEEPALIVE_IDLE_LIMIT_SECONDS: float = 10.0
MAX_KEEPALIVE_REQUESTS_PER_SOCKET: int = 95
NON_POOLABLE_SESSION_COMMANDS: frozenset[str] = frozenset(
    {
        "login",
        "logout",
        "keepalive",
        "publish",
        "discard",
        "continue-session",
        "switch-session",
        "take-over-session",
        "disconnect",
    }
)
_COMMAND_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def validate_command_name(command: str) -> str:
    """Validate and normalize a Check Point Web API command name against `^[a-z0-9]+(-[a-z0-9]+)*$`."""
    if not isinstance(command, str):
        raise ValidationError(f"Invalid Check Point API command type: {type(command).__name__}")
    if command != command.strip():
        raise ValidationError(
            f"Invalid Check Point Web API command {command!r}: leading or trailing whitespace is forbidden."
        )
    raw = command
    if raw.startswith("/web_api/"):
        raw = raw.removeprefix("/web_api/")
    elif raw.startswith("web_api/"):
        raw = raw.removeprefix("web_api/")
    if not raw or not _COMMAND_NAME_RE.fullmatch(raw):
        raise ValidationError(
            f"Invalid Check Point Web API command {command!r}: must match '^[a-z0-9]+(-[a-z0-9]+)*$'."
        )
    return raw


def is_readonly_poolable_command(command: str) -> bool:
    """Return `True` if `command` is a read-only `show-*` command eligible for connection reuse."""
    normalized = command.strip().lower()
    return normalized.startswith("show-")


def derive_session_pool_scope(sid: str) -> str:
    """Derive a non-reversible pool scope tag from `sid` so raw SIDs never appear in memory keys or repr()."""
    if not sid:
        return ""
    digest = hashlib.sha256(sid.encode("utf-8")).hexdigest()[:16]
    return f"s:{digest}"


def is_poolable_command(command: str, *, session_scope: str | None = None) -> bool:
    """Return `True` if `command` is eligible for keep-alive connection reuse in `VerifiedConnectionPool`."""
    normalized = command.strip().lower()
    if not normalized or normalized in NON_POOLABLE_SESSION_COMMANDS:
        return False
    if normalized.startswith("show-"):
        return True
    return bool(session_scope)


def _create_checkpoint_ssl_context() -> ssl.SSLContext:
    """Create a lightweight TLS 1.2+ client context without blocking disk CA loads (pinned via TrustPolicy)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION
    if hasattr(ssl, "OP_NO_RENEGOTIATION"):
        ctx.options |= ssl.OP_NO_RENEGOTIATION
    ctx.set_alpn_protocols(("http/1.1",))
    return ctx


_DEFAULT_CHECKPOINT_SSL_CONTEXT: ssl.SSLContext = _create_checkpoint_ssl_context()


def extract_peer_der_cert(transport: asyncio.BaseTransport | None) -> bytes | None:
    """Extract binary DER peer certificate from an `asyncio` SSL transport."""
    if transport is None:
        return None
    ssl_obj = transport.get_extra_info("ssl_object")
    if ssl_obj is not None and hasattr(ssl_obj, "getpeercert"):
        der = ssl_obj.getpeercert(binary_form=True)
        if isinstance(der, bytes):
            return der
    peercert = transport.get_extra_info("peercert")
    if isinstance(peercert, bytes):
        return peercert
    return None


def verify_transport_peer_certificate(
    transport: asyncio.BaseTransport | None,
    *,
    host: str,
    port: int,
    trust_policy: TrustPolicy,
) -> str:
    """Verify the peer certificate on `transport` immediately after TLS handshake.

    If verification fails, closes `transport` immediately before any HTTP bytes are written
    and propagates `ServerIdentityError`.
    """
    der_cert = extract_peer_der_cert(transport)
    try:
        return trust_policy.verify_der(host, port, der_cert)
    except ServerIdentityError:
        if transport is not None:
            transport.close()
        raise
    except Exception as exc:
        if transport is not None:
            transport.close()
        raise TrustStoreError(
            f"Unexpected error verifying TLS certificate for {host}:{port}: {exc}. No request was sent."
        ) from exc


@dataclass
class PooledSocketEntry:
    """Represents a fingerprint-verified keep-alive connection in `VerifiedConnectionPool`."""

    host: str
    port: int
    fingerprint: str
    protocol: Any
    last_used_at: float
    request_count: int = 1
    pool_scope: str = ""

    def is_usable(self, now: float, max_idle_seconds: float = KEEPALIVE_IDLE_LIMIT_SECONDS) -> bool:
        """Return `True` if the connection is still open and within the idle and request limits."""
        if now - self.last_used_at > max_idle_seconds:
            return False
        if self.request_count >= MAX_KEEPALIVE_REQUESTS_PER_SOCKET:
            return False
        if bool(getattr(self.protocol, "should_close", False)):
            return False
        is_conn = getattr(self.protocol, "is_connected", None)
        if callable(is_conn):
            return bool(is_conn())
        transport = getattr(self.protocol, "transport", None)
        if transport is not None and hasattr(transport, "is_closing"):
            return not bool(transport.is_closing())
        return True

    def close(self) -> None:
        """Close the underlying protocol/transport."""
        close_fn = getattr(self.protocol, "close", None)
        if callable(close_fn):
            close_fn()
        else:
            transport = getattr(self.protocol, "transport", None)
            if transport is not None and hasattr(transport, "close"):
                transport.close()


class VerifiedConnectionPool:
    """Pools fingerprint-verified keep-alive connections per `(server_ip, port, scope)` for up to 10s idle.

    Reuses connections for read-only `show-*` commands under shared scope (`""`) and for
    non-boundary commands under dedicated `session_scope` tags; session-boundary commands
    and un-scoped mutations bypass pooling and close idle sockets before connecting.
    """

    def __init__(
        self,
        *,
        max_idle_seconds: float = KEEPALIVE_IDLE_LIMIT_SECONDS,
        monotonic_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_idle_seconds = float(max_idle_seconds)
        self._monotonic = monotonic_fn
        self._pool: dict[tuple[str, int, str], deque[PooledSocketEntry]] = defaultdict(deque)
        self._reuse_count: int = 0
        self._fresh_count: int = 0

    @property
    def max_idle_seconds(self) -> float:
        """Maximum idle duration in seconds (default 10.0s)."""
        return self._max_idle_seconds

    @property
    def reuse_count(self) -> int:
        """Total number of requests that reused a pooled verified connection."""
        return self._reuse_count

    @property
    def fresh_count(self) -> int:
        """Total number of requests that opened a fresh connection."""
        return self._fresh_count

    def evict_expired(self, host: str | None = None, port: int | None = None) -> int:
        """Close and remove any pooled connections idle for more than `max_idle_seconds`."""
        now = self._monotonic()
        closed_count = 0
        if host is not None and port is not None:
            target_port = int(port)
            keys = [k for k in self._pool if k[0] == host and k[1] == target_port]
        else:
            keys = list(self._pool.keys())
        for key in keys:
            queue = self._pool.get(key)
            if not queue:
                continue
            kept: deque[PooledSocketEntry] = deque()
            while queue:
                entry = queue.popleft()
                if entry.is_usable(now, self._max_idle_seconds):
                    kept.append(entry)
                else:
                    entry.close()
                    closed_count += 1
            if kept:
                self._pool[key] = kept
            else:
                self._pool.pop(key, None)
        return closed_count

    def acquire_for_command(
        self,
        host: str,
        port: int,
        command: str,
        *,
        session_scope: str | None = None,
    ) -> PooledSocketEntry | None:
        """Acquire a pooled verified connection for `(host, port, scope)` if eligible.

        Always evicts expired connections first. For non-pooled commands, closes idle sockets
        before returning `None` so a fresh TLS-verified connection is established cleanly.
        """
        target_port = int(port)
        self.evict_expired(host, target_port)
        scope = session_scope or ""
        if not is_poolable_command(command, session_scope=scope or None):
            if scope:
                self.close_scope(host, target_port, scope)
            self.close_scope(host, target_port, "")
            self._fresh_count += 1
            return None

        key = (host, target_port, scope)
        queue = self._pool.get(key)
        now = self._monotonic()
        while queue:
            entry = queue.popleft()
            if entry.is_usable(now, self._max_idle_seconds):
                if not queue:
                    self._pool.pop(key, None)
                entry.last_used_at = now
                entry.request_count += 1
                self._reuse_count += 1
                return entry
            entry.close()

        self._pool.pop(key, None)
        if scope:
            # Close idle shared read-only sockets on this host before opening a dedicated connection.
            self.close_scope(host, target_port, "")
        self._fresh_count += 1
        return None

    def release_after_command(
        self,
        entry: PooledSocketEntry,
        command: str,
        *,
        should_close: bool = False,
        session_scope: str | None = None,
    ) -> bool:
        """Return a healthy verified connection to the pool if eligible, else close it."""
        eff_scope = entry.pool_scope if session_scope is None else session_scope
        entry.pool_scope = eff_scope
        now = self._monotonic()
        if (
            should_close
            or not is_poolable_command(command, session_scope=eff_scope or None)
            or not entry.is_usable(now, self._max_idle_seconds)
        ):
            entry.close()
            return False
        entry.last_used_at = now
        self._pool[(entry.host, int(entry.port), eff_scope)].append(entry)
        return True

    def close_scope(self, host: str, port: int, session_scope: str = "") -> int:
        """Close all pooled connections for `(host, port, session_scope)`."""
        key = (host, int(port), session_scope)
        queue = self._pool.pop(key, None)
        if not queue:
            return 0
        count = 0
        while queue:
            entry = queue.popleft()
            entry.close()
            count += 1
        return count

    def close_session_scope(self, session_scope: str) -> int:
        """Close all pooled connections associated with `session_scope` across all hosts."""
        if not session_scope:
            return 0
        total = 0
        for host, port, scope in list(self._pool.keys()):
            if scope == session_scope:
                total += self.close_scope(host, port, scope)
        return total

    def close_host(self, host: str, port: int) -> int:
        """Close all pooled connections across all scopes for `(host, port)`."""
        target_port = int(port)
        total = 0
        for h, p, scope in list(self._pool.keys()):
            if h == host and p == target_port:
                total += self.close_scope(h, p, scope)
        return total

    def close_all(self) -> int:
        """Close all pooled connections across all hosts and scopes."""
        total = 0
        for h, p, scope in list(self._pool.keys()):
            total += self.close_scope(h, p, scope)
        return total

    def pooled_count(
        self,
        host: str | None = None,
        port: int | None = None,
        *,
        session_scope: str | None = None,
    ) -> int:
        """Return the number of currently pooled idle connections."""
        target_port = int(port) if port is not None else None
        total = 0
        for (h, p, s), queue in self._pool.items():
            if host is not None and h != host:
                continue
            if target_port is not None and p != target_port:
                continue
            if session_scope is not None and s != session_scope:
                continue
            total += len(queue)
        return total


@dataclass(frozen=True)
class _TransportPoolContext:
    """Per-request command and derived session scope propagated via `ContextVar` to the connector."""

    command: str
    session_scope: str = ""


_transport_pool_ctx: ContextVar[_TransportPoolContext | None] = ContextVar(
    "arodonata_transport_pool_ctx",
    default=None,
)


@dataclass
class _ProtoTrackEntry:
    """Tracks per-protocol TLS fingerprint, last command, session scope, and request count."""

    fingerprint: str
    command: str = ""
    pool_scope: str = ""
    request_count: int = 1


class FingerprintTCPConnector(aiohttp.TCPConnector):
    """Custom `aiohttp.TCPConnector` that verifies peer SHA-256 certificate fingerprints
    immediately after the TLS handshake and delegates keep-alive reuse to `VerifiedConnectionPool`.
    """

    def __init__(
        self,
        *,
        trust_policy: TrustPolicy,
        connection_pool: VerifiedConnectionPool,
        ssl_context: ssl.SSLContext | None = None,
        **kwargs: Any,
    ) -> None:
        if ssl_context is None:
            ssl_context = _DEFAULT_CHECKPOINT_SSL_CONTEXT
        super().__init__(ssl=ssl_context, keepalive_timeout=connection_pool.max_idle_seconds, **kwargs)
        self._trust_policy = trust_policy
        self._connection_pool = connection_pool
        self._proto_fingerprints: weakref.WeakKeyDictionary[ResponseHandler, str] = weakref.WeakKeyDictionary()
        self._proto_state: weakref.WeakKeyDictionary[ResponseHandler, _ProtoTrackEntry] = weakref.WeakKeyDictionary()

    async def _create_proxy_connection(
        self,
        _req: ClientRequest,
        _traces: list[Trace],
        _timeout: aiohttp.ClientTimeout,
    ) -> tuple[asyncio.Transport, ResponseHandler]:
        """Reject HTTP proxy connections explicitly so TLS fingerprint pinning can never be bypassed."""
        raise TransportError(
            "HTTP proxy connections are forbidden with pre-request TLS fingerprint verification. No request was sent.",
            phase="connect",
            request_sent=False,
        )

    async def _create_direct_connection(
        self,
        req: ClientRequest,
        traces: list[Trace],
        timeout: aiohttp.ClientTimeout,
        *,
        client_error: type[Exception] = aiohttp.ClientConnectorError,
    ) -> tuple[asyncio.Transport, ResponseHandler]:
        transp, proto = await super()._create_direct_connection(
            req,
            traces,
            timeout,
            client_error=client_error,
        )
        host = req.url.raw_host or req.host
        port = req.port or 443
        fp = verify_transport_peer_certificate(
            transp,
            host=host,
            port=port,
            trust_policy=self._trust_policy,
        )
        self._proto_fingerprints[proto] = fp
        self._proto_state[proto] = _ProtoTrackEntry(fingerprint=fp, request_count=1)
        return transp, proto

    async def connect(
        self,
        req: ClientRequest,
        traces: list[Trace],
        timeout: aiohttp.ClientTimeout,
    ) -> Connection:
        call_ctx = _transport_pool_ctx.get()
        command = (
            call_ctx.command if call_ctx is not None else (req.url.path.rsplit("/", 1)[-1] if req.url.path else "")
        )
        session_scope = call_ctx.session_scope if call_ctx is not None else ""
        host = req.url.raw_host or req.host
        port = req.port or 443
        key: ConnectionKey = req.connection_key

        self._connection_pool.evict_expired()
        pooled = self._connection_pool.acquire_for_command(
            host,
            port,
            command,
            session_scope=session_scope or None,
        )
        if pooled is not None and isinstance(pooled.protocol, ResponseHandler):
            proto = pooled.protocol
            self._proto_state[proto] = _ProtoTrackEntry(
                fingerprint=pooled.fingerprint,
                command=command,
                pool_scope=pooled.pool_scope,
                request_count=pooled.request_count,
            )
            self._acquired.add(proto)
            if self._limit_per_host:
                self._acquired_per_host[key].add(proto)
            return Connection(self, key, proto, self._loop)

        # Ensure aiohttp's internal `_conns` does not hand back a connection when `VerifiedConnectionPool`
        # declined reuse (e.g. non-pooled command, different scope, or expired idle time)
        if key in self._conns:
            while self._conns[key]:
                old_proto, _ = self._conns[key].popleft()
                old_proto.close()
            del self._conns[key]

        conn = await super().connect(req, traces, timeout)
        if conn.protocol is not None:
            existing = self._proto_state.get(conn.protocol)
            req_count = existing.request_count if existing is not None else 1
            fp = existing.fingerprint if existing is not None else self._proto_fingerprints.get(conn.protocol, "")
            self._proto_state[conn.protocol] = _ProtoTrackEntry(
                fingerprint=fp,
                command=command,
                pool_scope=session_scope,
                request_count=req_count,
            )
        return conn

    def _release(
        self,
        key: ConnectionKey,
        protocol: ResponseHandler,
        *,
        should_close: bool = False,
    ) -> None:
        if self._closed:
            return
        self._release_acquired(key, protocol)
        state = self._proto_state.pop(protocol, None)
        fp = state.fingerprint if state is not None else self._proto_fingerprints.get(protocol, "")
        command = state.command if state is not None else ""
        pool_scope = state.pool_scope if state is not None else ""
        req_count = state.request_count if state is not None else 1
        entry = PooledSocketEntry(
            host=key.host,
            port=key.port or 443,
            fingerprint=fp,
            protocol=protocol,
            last_used_at=self._connection_pool._monotonic(),
            request_count=req_count,
            pool_scope=pool_scope,
        )
        if (
            should_close
            or self._force_close
            or protocol.should_close
            or not is_poolable_command(command, session_scope=pool_scope or None)
        ):
            entry.close()
            self._proto_fingerprints.pop(protocol, None)
            return
        kept = self._connection_pool.release_after_command(
            entry,
            command,
            should_close=False,
            session_scope=pool_scope,
        )
        if not kept:
            self._proto_fingerprints.pop(protocol, None)


@dataclass
class RawHttpResponse:
    """Low-level HTTP response returned by a request executor."""

    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)
    reused_connection: bool = False


class RequestSenderProtocol(Protocol):
    """Injectable low-level connection/request hook for deterministic unit testing."""

    async def __call__(
        self,
        *,
        host: str,
        port: int,
        command: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
        connect_timeout: float,
        read_timeout: float,
        reused_entry: PooledSocketEntry | None,
    ) -> tuple[RawHttpResponse, PooledSocketEntry | None]: ...


def _parse_cp_json_response(status_code: int, raw_body: bytes) -> ApiCallResult:
    """Parse a Check Point Web API HTTP status and JSON body into `ApiCallResult`."""
    text = raw_body.decode("utf-8", errors="replace").strip()
    data: dict[str, Any] = {}
    if text:
        try:
            parsed = json.loads(text)
            data = parsed if isinstance(parsed, dict) else {"result": parsed}
        except json.JSONDecodeError:
            data = {"raw_text": text}

    success = 200 <= status_code < 300
    error_message: str | None = None
    error_code: str | None = None
    task_id: str | None = None

    if "task-id" in data and isinstance(data["task-id"], str):
        task_id = data["task-id"]
    elif "tasks" in data and isinstance(data["tasks"], list) and data["tasks"]:
        first_task = data["tasks"][0]
        if isinstance(first_task, dict) and isinstance(first_task.get("task-id"), str):
            task_id = first_task["task-id"]

    if not success:
        error_code = str(data.get("code") or f"http_{status_code}")
        msg = data.get("message") or data.get("error") or data.get("raw_text") or f"HTTP {status_code}"
        errors_list = data.get("errors") or data.get("blocking-errors")
        if isinstance(errors_list, list) and errors_list:
            details = "; ".join(
                str(item.get("message") or item) if isinstance(item, dict) else str(item) for item in errors_list
            )
            error_message = f"{msg} ({details})"
        else:
            error_message = str(msg)

    return ApiCallResult(
        success=success,
        status_code=status_code,
        data=data,
        error_message=error_message,
        error_code=error_code,
        task_id=task_id,
    )


class ApiTransport:
    """Native `aiohttp` transport for Check Point Management Web API (`/web_api/<command>`).

    Invariants:
    - Verifies peer SHA-256 certificate fingerprint via `TrustPolicy` immediately after
      the TLS handshake and BEFORE sending any HTTP headers (`X-chkp-sid`), credentials,
      or command payload bytes.
    - Enforces separate `connect_timeout` (`phase="connect"`) and socket `read_timeout`
      (`phase="read"`).
    - NEVER automatically re-sends a request after request bytes have been written to
      the socket (on read timeout, `ConnectionResetError`, or `BrokenPipeError`).
    - Reuses verified keep-alive connections via `VerifiedConnectionPool` (up to 10s idle
      and `< 95` requests) for read-only `show-*` commands and scoped dedicated-session
      commands while closing idle sockets before non-pooled boundary/mutating commands.
    """

    def __init__(
        self,
        settings: ArodonataSettings | None = None,
        *,
        trust_policy: TrustPolicy | None = None,
        connection_pool: VerifiedConnectionPool | None = None,
        peer_cert_getter: Callable[[str, int], bytes | Awaitable[bytes | None] | None] | None = None,
        request_sender: RequestSenderProtocol | None = None,
    ) -> None:
        self._settings = settings or ArodonataSettings()
        self._trust_policy = trust_policy or TrustPolicy(
            mode=self._settings.tls_trust,
            known_hosts_path=self._settings.tls_known_hosts_path,
            pinned_fingerprints=self._settings.tls_fingerprints,
        )
        self._pool = connection_pool or VerifiedConnectionPool(
            max_idle_seconds=KEEPALIVE_IDLE_LIMIT_SECONDS,
        )
        self._peer_cert_getter = peer_cert_getter
        self._request_sender = request_sender
        if self._request_sender is not None and self._peer_cert_getter is None:
            raise ConfigurationError(
                "ApiTransport requires 'peer_cert_getter' whenever a custom 'request_sender' is provided "
                "so pre-request TLS certificate verification is never bypassed."
            )
        self._connector: FingerprintTCPConnector | None = None
        self._session: aiohttp.ClientSession | None = None

    @property
    def settings(self) -> ArodonataSettings:
        """Active `ArodonataSettings`."""
        return self._settings

    @property
    def trust_policy(self) -> TrustPolicy:
        """Active `TrustPolicy`."""
        return self._trust_policy

    @property
    def connection_pool(self) -> VerifiedConnectionPool:
        """Active `VerifiedConnectionPool`."""
        return self._pool

    async def _ensure_aiohttp_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._connector = FingerprintTCPConnector(
                trust_policy=self._trust_policy,
                connection_pool=self._pool,
            )
            self._session = aiohttp.ClientSession(connector=self._connector, trust_env=False)
        return self._session

    @traced
    async def execute(
        self,
        host: str,
        command: str,
        payload: dict[str, Any] | None = None,
        *,
        port: int = 443,
        sid: str | None = None,
        timeout: float | None = None,
        session_scope: str | None = None,
    ) -> ApiCallResult:
        """Execute `POST https://<host>:<port>/web_api/<command>` with pre-request TLS verification."""
        clean_cmd = validate_command_name(command)
        eff_scope = session_scope or ""

        connect_timeout = float(self._settings.connect_timeout)
        read_timeout = self._settings.resolve_read_timeout(timeout)
        span_attrs(
            cp_host=host,
            cp_port=port,
            cp_command=clean_cmd,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )

        url_host = format_host_attr_for_url(host)
        url = f"https://{url_host}:{port}/web_api/{clean_cmd}"
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "arodonata/2.0",
        }
        if sid:
            headers["X-chkp-sid"] = sid
        if not is_poolable_command(clean_cmd, session_scope=eff_scope or None):
            headers["Connection"] = "close"

        body_bytes = json.dumps(payload or {}, separators=(",", ":")).encode("utf-8")
        known_sids = (sid,) if sid else None

        if self._request_sender is not None:
            return await self._execute_with_custom_sender(
                host=host,
                port=port,
                command=clean_cmd,
                url=url,
                headers=headers,
                body_bytes=body_bytes,
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
                known_sids=known_sids,
                session_scope=eff_scope,
            )

        return await self._execute_with_aiohttp(
            host=host,
            port=port,
            command=clean_cmd,
            url=url,
            headers=headers,
            body_bytes=body_bytes,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            known_sids=known_sids,
            session_scope=eff_scope,
        )

    async def _execute_with_custom_sender(
        self,
        *,
        host: str,
        port: int,
        command: str,
        url: str,
        headers: dict[str, str],
        body_bytes: bytes,
        connect_timeout: float,
        read_timeout: float,
        known_sids: tuple[str, ...] | None,
        session_scope: str = "",
    ) -> ApiCallResult:
        """Execute request through the injected `request_sender` while enforcing all pool/TLS/timeout rules."""
        assert self._request_sender is not None
        pooled_entry = self._pool.acquire_for_command(
            host,
            port,
            command,
            session_scope=session_scope or None,
        )

        # Step 1: If no pooled connection was reused, perform pre-request TLS verification
        # BEFORE any request headers or bytes can be sent.
        verified_fp = pooled_entry.fingerprint if pooled_entry is not None else ""
        if pooled_entry is None:
            if self._peer_cert_getter is None:
                raise ConfigurationError("ApiTransport requires 'peer_cert_getter' whenever 'request_sender' is used.")
            try:
                maybe_coro = self._peer_cert_getter(host, port)
                der_cert = await asyncio.wait_for(
                    maybe_coro if asyncio.iscoroutine(maybe_coro) else asyncio.sleep(0, result=maybe_coro),
                    timeout=connect_timeout,
                )
            except TimeoutError as exc:
                raise ApiTimeoutError(
                    f"TCP/TLS connection to {host}:{port} timed out after {connect_timeout}s during 'connect' phase.",
                    phase="connect",
                    request_sent=False,
                    host=host,
                    port=port,
                    command=command,
                    known_sids=known_sids,
                ) from exc
            except OSError as exc:
                raise TransportError(
                    f"Failed to connect to {host}:{port} for {command!r}: {redact_sid(str(exc), known_sids)}",
                    phase="connect",
                    request_sent=False,
                    known_sids=known_sids,
                ) from exc
            verified_fp = self._trust_policy.verify_der(host, port, der_cert)

        # Step 2: Send request and await response WITHOUT any retry after write
        try:
            raw_resp, new_entry = await self._request_sender(
                host=host,
                port=port,
                command=command,
                url=url,
                headers=headers,
                body=body_bytes,
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
                reused_entry=pooled_entry,
            )
        except ServerIdentityError:
            if pooled_entry is not None:
                pooled_entry.close()
            raise
        except ApiTimeoutError:
            if pooled_entry is not None:
                pooled_entry.close()
            raise
        except TransportError:
            if pooled_entry is not None:
                pooled_entry.close()
            raise
        except (ConnectionResetError, BrokenPipeError) as exc:
            if pooled_entry is not None:
                pooled_entry.close()
            raise TransportError(
                f"Connection to {host}:{port} failed during {command!r} ({type(exc).__name__}: {exc}). "
                "Request was NOT re-sent.",
                phase="post-send",
                request_sent=True,
                known_sids=known_sids,
            ) from exc
        except TimeoutError as exc:
            if pooled_entry is not None:
                pooled_entry.close()
            raise ApiTimeoutError(
                f"Socket read timed out after {read_timeout}s waiting for {command!r} from {host}:{port}. "
                "Warning: the command may still have run on the server; request was NOT re-sent.",
                phase="read",
                request_sent=True,
                host=host,
                port=port,
                command=command,
                known_sids=known_sids,
            ) from exc
        except OSError as exc:
            if pooled_entry is not None:
                pooled_entry.close()
            raise TransportError(
                f"Transport error communicating with {host}:{port} on {command!r}: {exc}",
                phase="post-send",
                request_sent=True,
                known_sids=known_sids,
            ) from exc

        if 300 <= raw_resp.status < 400:
            if pooled_entry is not None:
                pooled_entry.close()
            if new_entry is not None:
                new_entry.close()
            raise TransportError(
                f"Unexpected HTTP redirect (status {raw_resp.status}) from {host}:{port} on {command!r}. "
                "Redirects are forbidden.",
                phase="post-send",
                request_sent=True,
                known_sids=known_sids,
            )

        active_entry = new_entry or pooled_entry
        if active_entry is None:
            active_entry = PooledSocketEntry(
                host=host,
                port=port,
                fingerprint=verified_fp,
                protocol=object(),
                last_used_at=self._pool._monotonic(),
                pool_scope=session_scope,
            )
        should_close = raw_resp.headers.get("Connection", "").lower() == "close"
        self._pool.release_after_command(
            active_entry,
            command,
            should_close=should_close,
            session_scope=session_scope,
        )
        return _parse_cp_json_response(raw_resp.status, raw_resp.body)

    async def _execute_with_aiohttp(
        self,
        *,
        host: str,
        port: int,
        command: str,
        url: str,
        headers: dict[str, str],
        body_bytes: bytes,
        connect_timeout: float,
        read_timeout: float,
        known_sids: tuple[str, ...] | None,
        session_scope: str = "",
    ) -> ApiCallResult:
        session = await self._ensure_aiohttp_session()
        client_timeout = aiohttp.ClientTimeout(
            total=None,
            connect=connect_timeout,
            sock_connect=connect_timeout,
            sock_read=read_timeout,
        )

        pool_ctx_token = _transport_pool_ctx.set(_TransportPoolContext(command=command, session_scope=session_scope))
        try:
            async with session.post(
                url,
                data=body_bytes,
                headers=headers,
                timeout=client_timeout,
                allow_redirects=False,
            ) as response:
                raw_body = await response.read()
                status_code = response.status
                conn_header = response.headers.get("Connection", "")
        except ServerIdentityError:
            raise
        except aiohttp.ConnectionTimeoutError as exc:
            raise ApiTimeoutError(
                f"TCP/TLS connection to {host}:{port} timed out after {connect_timeout}s during 'connect' phase.",
                phase="connect",
                request_sent=False,
                host=host,
                port=port,
                command=command,
                known_sids=known_sids,
            ) from exc
        except (aiohttp.SocketTimeoutError, aiohttp.ServerTimeoutError, TimeoutError) as exc:
            self._pool.close_host(host, port)
            raise ApiTimeoutError(
                f"Socket read timed out after {read_timeout}s waiting for {command!r} from {host}:{port}. "
                "Warning: the command may still have run on the server; request was NOT re-sent.",
                phase="read",
                request_sent=True,
                host=host,
                port=port,
                command=command,
                known_sids=known_sids,
            ) from exc
        except aiohttp.ClientConnectorError as exc:
            os_err = getattr(exc, "os_error", None)
            if isinstance(os_err, ServerIdentityError):
                raise os_err from exc
            if isinstance(os_err, TimeoutError):
                raise ApiTimeoutError(
                    f"TCP/TLS connection to {host}:{port} timed out after {connect_timeout}s during 'connect' phase.",
                    phase="connect",
                    request_sent=False,
                    host=host,
                    port=port,
                    command=command,
                    known_sids=known_sids,
                ) from exc
            raise TransportError(
                f"Failed to connect to {host}:{port} for {command!r}: {redact_sid(str(exc), known_sids)}",
                phase="connect",
                request_sent=False,
                known_sids=known_sids,
            ) from exc
        except (ConnectionResetError, BrokenPipeError, aiohttp.ClientOSError, aiohttp.ServerDisconnectedError) as exc:
            self._pool.close_host(host, port)
            raise TransportError(
                f"Connection reset or closed by peer {host}:{port} during {command!r}: "
                f"{redact_sid(str(exc), known_sids)}. Request was NOT re-sent.",
                phase="post-send",
                request_sent=True,
                known_sids=known_sids,
            ) from exc
        except aiohttp.ClientError as exc:
            self._pool.close_host(host, port)
            raise TransportError(
                f"HTTP transport error on {host}:{port} during {command!r}: {redact_sid(str(exc), known_sids)}",
                phase="post-send",
                request_sent=True,
                known_sids=known_sids,
            ) from exc
        finally:
            _transport_pool_ctx.reset(pool_ctx_token)

        if 300 <= status_code < 400:
            self._pool.close_host(host, port)
            raise TransportError(
                f"Unexpected HTTP redirect (status {status_code}) from {host}:{port} on {command!r}. "
                "Redirects are forbidden.",
                phase="post-send",
                request_sent=True,
                known_sids=known_sids,
            )

        if not is_poolable_command(command, session_scope=session_scope or None):
            if session_scope:
                self._pool.close_scope(host, port, session_scope)
            self._pool.close_scope(host, port, "")
        elif conn_header.lower() == "close":
            self._pool.close_scope(host, port, session_scope)

        return _parse_cp_json_response(status_code, raw_body)

    @traced
    async def close(self) -> None:
        """Close all pooled connections and the underlying `aiohttp.ClientSession`."""
        self._pool.close_all()
        if self._session is not None and not self._session.closed:
            await self._session.close()
        self._session = None
        self._connector = None


__all__ = [
    "KEEPALIVE_IDLE_LIMIT_SECONDS",
    "MAX_KEEPALIVE_REQUESTS_PER_SOCKET",
    "NON_POOLABLE_SESSION_COMMANDS",
    "ApiTransport",
    "FingerprintTCPConnector",
    "PooledSocketEntry",
    "RawHttpResponse",
    "VerifiedConnectionPool",
    "derive_session_pool_scope",
    "extract_peer_der_cert",
    "is_poolable_command",
    "is_readonly_poolable_command",
    "validate_command_name",
    "verify_transport_peer_certificate",
]
