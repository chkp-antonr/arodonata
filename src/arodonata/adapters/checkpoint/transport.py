"""Native `aiohttp` Check Point Web API transport and backward-compatible transport exports.

Enforces pre-request SHA-256 certificate fingerprint verification immediately after
the TLS handshake, separate socket connect/read timeouts, strict prohibition of
silent request re-transmission after socket write, and 10-second idle keep-alive
pooling restricted to read-only `show-*` and session-scoped commands.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

import aiohttp

from arodonata.adapters.checkpoint.connection_pool import (
    KEEPALIVE_IDLE_LIMIT_SECONDS,
    MAX_KEEPALIVE_REQUESTS_PER_SOCKET,
    NON_POOLABLE_SESSION_COMMANDS,
    PooledSocketEntry,
    VerifiedConnectionPool,
    _transport_pool_ctx,
    _TransportPoolContext,
    derive_session_pool_scope,
    is_poolable_command,
    is_readonly_poolable_command,
)
from arodonata.adapters.checkpoint.connector import (
    FingerprintTCPConnector,
    extract_peer_der_cert,
    verify_transport_peer_certificate,
)
from arodonata.adapters.checkpoint.tls import TrustPolicy, format_host_attr_for_url
from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import (
    ApiTimeoutError,
    ConfigurationError,
    ServerIdentityError,
    TransportError,
    redact_sid,
)
from arodonata.core.models.common import ApiCallResult
from arodonata.core.primitives import validate_command_name
from arodonata.core.telemetry import span_attrs, traced


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
        except (ServerIdentityError, ApiTimeoutError, TransportError):
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
    "RequestSenderProtocol",
    "VerifiedConnectionPool",
    "derive_session_pool_scope",
    "extract_peer_der_cert",
    "is_poolable_command",
    "is_readonly_poolable_command",
    "validate_command_name",
    "verify_transport_peer_certificate",
]
