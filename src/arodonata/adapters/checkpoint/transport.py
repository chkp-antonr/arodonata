"""Native `aiohttp` Check Point Web API transport and `VerifiedConnectionPool`.

Enforces pre-request SHA-256 certificate fingerprint verification immediately after
the TLS handshake, separate socket connect/read timeouts, strict prohibition of
silent request re-transmission after socket write, and 10-second idle keep-alive
pooling restricted to read-only `show-*` commands.
"""

from __future__ import annotations

import asyncio
import json
import ssl
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

import aiohttp
from aiohttp.client_proto import ResponseHandler
from aiohttp.client_reqrep import ClientRequest, ConnectionKey
from aiohttp.connector import Connection
from aiohttp.tracing import Trace

from arodonata.adapters.checkpoint.tls import TrustPolicy
from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import (
    ApiTimeoutError,
    ServerIdentityError,
    TransportError,
    TrustStoreError,
    redact_sid,
)
from arodonata.core.models.common import ApiCallResult
from arodonata.core.telemetry import span_attrs, traced

KEEPALIVE_IDLE_LIMIT_SECONDS: float = 10.0


def is_readonly_poolable_command(command: str) -> bool:
    """Return `True` if `command` is a read-only `show-*` command eligible for connection reuse."""
    normalized = command.strip().lower()
    return normalized.startswith("show-")


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

    def is_usable(self, now: float, max_idle_seconds: float = KEEPALIVE_IDLE_LIMIT_SECONDS) -> bool:
        """Return `True` if the connection is still open and within the idle window."""
        if now - self.last_used_at > max_idle_seconds:
            return False
        if self.request_count >= 95:
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
    """Pools fingerprint-verified keep-alive connections per `(server_ip, port)` for up to 10s idle.

    Exclusively reuses connections for read-only `show-*` commands; mutating commands,
    logins, logouts, keepalives, publish, and discard bypass pooling and close any
    expired idle sockets.
    """

    def __init__(
        self,
        *,
        max_idle_seconds: float = KEEPALIVE_IDLE_LIMIT_SECONDS,
        monotonic_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_idle_seconds = float(max_idle_seconds)
        self._monotonic = monotonic_fn
        self._pool: dict[tuple[str, int], deque[PooledSocketEntry]] = defaultdict(deque)
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
        keys = [(host, port)] if (host is not None and port is not None) else list(self._pool.keys())
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

    def acquire_for_command(self, host: str, port: int, command: str) -> PooledSocketEntry | None:
        """Acquire a pooled verified connection for `(host, port)` if `command` is `show-*`.

        Always evicts expired connections first. For non-`show-*` commands, returns `None`
        so a fresh TLS-verified connection is established.
        """
        self.evict_expired(host, port)
        if not is_readonly_poolable_command(command):
            self._fresh_count += 1
            return None

        key = (host, int(port))
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
        self._fresh_count += 1
        return None

    def release_after_command(
        self,
        entry: PooledSocketEntry,
        command: str,
        *,
        should_close: bool = False,
    ) -> bool:
        """Return a healthy verified connection to the pool if `command` is `show-*`, else close it."""
        now = self._monotonic()
        if (
            should_close
            or not is_readonly_poolable_command(command)
            or not entry.is_usable(now, self._max_idle_seconds)
        ):
            entry.close()
            return False
        entry.last_used_at = now
        self._pool[(entry.host, int(entry.port))].append(entry)
        return True

    def close_host(self, host: str, port: int) -> int:
        """Close all pooled connections for `(host, port)`."""
        key = (host, int(port))
        queue = self._pool.pop(key, None)
        if not queue:
            return 0
        count = 0
        while queue:
            entry = queue.popleft()
            entry.close()
            count += 1
        return count

    def close_all(self) -> int:
        """Close all pooled connections across all hosts."""
        total = 0
        for key in list(self._pool.keys()):
            total += self.close_host(key[0], key[1])
        return total

    def pooled_count(self, host: str | None = None, port: int | None = None) -> int:
        """Return the number of currently pooled idle connections."""
        if host is not None and port is not None:
            return len(self._pool.get((host, int(port)), ()))
        return sum(len(q) for q in self._pool.values())


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
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        super().__init__(ssl=ssl_context, keepalive_timeout=connection_pool.max_idle_seconds, **kwargs)
        self._trust_policy = trust_policy
        self._connection_pool = connection_pool
        self._proto_fingerprints: dict[int, str] = {}

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
        self._proto_fingerprints[id(proto)] = fp
        return transp, proto

    async def connect(
        self,
        req: ClientRequest,
        traces: list[Trace],
        timeout: aiohttp.ClientTimeout,
    ) -> Connection:
        command = req.url.path.rsplit("/", 1)[-1] if req.url.path else ""
        host = req.url.raw_host or req.host
        port = req.port or 443
        key: ConnectionKey = req.connection_key

        pooled = self._connection_pool.acquire_for_command(host, port, command)
        if pooled is not None and isinstance(pooled.protocol, ResponseHandler):
            proto = pooled.protocol
            self._acquired.add(proto)
            if self._limit_per_host:
                self._acquired_per_host[key].add(proto)
            return Connection(self, key, proto, self._loop)

        # Ensure aiohttp's internal `_conns` does not hand back a connection when `VerifiedConnectionPool`
        # declined reuse (e.g. non-show command or expired idle time)
        if key in self._conns:
            while self._conns[key]:
                old_proto, _ = self._conns[key].popleft()
                old_proto.close()
            del self._conns[key]

        return await super().connect(req, traces, timeout)

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
        fp = self._proto_fingerprints.get(id(protocol), "")
        entry = PooledSocketEntry(
            host=key.host,
            port=key.port or 443,
            fingerprint=fp,
            protocol=protocol,
            last_used_at=self._connection_pool._monotonic(),
        )
        if should_close or self._force_close or protocol.should_close:
            entry.close()
            self._proto_fingerprints.pop(id(protocol), None)
            return
        # Connection eligibility is finalized by `release_after_command` in `ApiTransport`
        self._connection_pool._pool[(key.host, int(key.port or 443))].append(entry)


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
    - Reuses verified keep-alive connections via `VerifiedConnectionPool` (up to 10s idle)
      strictly for read-only `show-*` commands.
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
            self._session = aiohttp.ClientSession(connector=self._connector)
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
    ) -> ApiCallResult:
        """Execute `POST https://<host>:<port>/web_api/<command>` with pre-request TLS verification."""
        clean_cmd = command.strip().lstrip("/")
        if clean_cmd.startswith("web_api/"):
            clean_cmd = clean_cmd.removeprefix("web_api/")

        connect_timeout = float(self._settings.connect_timeout)
        read_timeout = self._settings.resolve_read_timeout(timeout)
        span_attrs(
            cp_host=host,
            cp_port=port,
            cp_command=clean_cmd,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )

        url = f"https://{host}:{port}/web_api/{clean_cmd}"
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "arodonata/2.0",
        }
        if sid:
            headers["X-chkp-sid"] = sid
        if not is_readonly_poolable_command(clean_cmd):
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
    ) -> ApiCallResult:
        """Execute request through the injected `request_sender` while enforcing all pool/TLS/timeout rules."""
        assert self._request_sender is not None
        pooled_entry = self._pool.acquire_for_command(host, port, command)

        # Step 1: If no pooled connection was reused, perform pre-request TLS verification
        # BEFORE any request headers or bytes can be sent.
        verified_fp = pooled_entry.fingerprint if pooled_entry is not None else ""
        if pooled_entry is None and self._peer_cert_getter is not None:
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
                    host=host,
                    port=port,
                    command=command,
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
        except (ConnectionResetError, BrokenPipeError) as exc:
            if pooled_entry is not None:
                pooled_entry.close()
            raise TransportError(
                f"Connection to {host}:{port} failed during {command!r} ({type(exc).__name__}: {exc}). "
                "Request was NOT re-sent.",
                known_sids=known_sids,
            ) from exc
        except TimeoutError as exc:
            if pooled_entry is not None:
                pooled_entry.close()
            raise ApiTimeoutError(
                f"Socket read timed out after {read_timeout}s waiting for {command!r} from {host}:{port}. "
                "Warning: the command may still have run on the server; request was NOT re-sent.",
                phase="read",
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
                known_sids=known_sids,
            ) from exc

        active_entry = new_entry or pooled_entry
        if active_entry is None:
            active_entry = PooledSocketEntry(
                host=host,
                port=port,
                fingerprint=verified_fp,
                protocol=object(),
                last_used_at=self._pool._monotonic(),
            )
        should_close = raw_resp.headers.get("Connection", "").lower() == "close"
        self._pool.release_after_command(active_entry, command, should_close=should_close)
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
    ) -> ApiCallResult:
        session = await self._ensure_aiohttp_session()
        client_timeout = aiohttp.ClientTimeout(
            total=None,
            connect=connect_timeout,
            sock_connect=connect_timeout,
            sock_read=read_timeout,
        )

        try:
            async with session.post(
                url,
                data=body_bytes,
                headers=headers,
                timeout=client_timeout,
            ) as response:
                raw_body = await response.read()
                status_code = response.status
                conn_header = response.headers.get("Connection", "")
        except ServerIdentityError:
            raise
        except (aiohttp.ServerTimeoutError, TimeoutError) as exc:
            # Distinguish connect timeout vs socket read timeout
            if isinstance(exc, aiohttp.ConnectionTimeoutError) or "connect" in str(exc).lower():
                raise ApiTimeoutError(
                    f"TCP/TLS connection to {host}:{port} timed out after {connect_timeout}s during 'connect' phase.",
                    phase="connect",
                    host=host,
                    port=port,
                    command=command,
                    known_sids=known_sids,
                ) from exc
            self._pool.close_host(host, port)
            raise ApiTimeoutError(
                f"Socket read timed out after {read_timeout}s waiting for {command!r} from {host}:{port}. "
                "Warning: the command may still have run on the server; request was NOT re-sent.",
                phase="read",
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
                    host=host,
                    port=port,
                    command=command,
                    known_sids=known_sids,
                ) from exc
            raise TransportError(
                f"Failed to connect to {host}:{port} for {command!r}: {redact_sid(str(exc), known_sids)}",
                known_sids=known_sids,
            ) from exc
        except (ConnectionResetError, BrokenPipeError, aiohttp.ClientOSError, aiohttp.ServerDisconnectedError) as exc:
            self._pool.close_host(host, port)
            raise TransportError(
                f"Connection reset or closed by peer {host}:{port} during {command!r}: "
                f"{redact_sid(str(exc), known_sids)}. Request was NOT re-sent.",
                known_sids=known_sids,
            ) from exc
        except aiohttp.ClientError as exc:
            self._pool.close_host(host, port)
            raise TransportError(
                f"HTTP transport error on {host}:{port} during {command!r}: {redact_sid(str(exc), known_sids)}",
                known_sids=known_sids,
            ) from exc

        if not is_readonly_poolable_command(command) or conn_header.lower() == "close":
            self._pool.close_host(host, port)

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
    "ApiTransport",
    "FingerprintTCPConnector",
    "PooledSocketEntry",
    "RawHttpResponse",
    "VerifiedConnectionPool",
    "extract_peer_der_cert",
    "is_readonly_poolable_command",
    "verify_transport_peer_certificate",
]
