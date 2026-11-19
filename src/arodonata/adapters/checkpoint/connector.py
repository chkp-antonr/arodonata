"""Custom `aiohttp.TCPConnector` enforcing pre-request TLS fingerprint pinning and pool scoping."""

from __future__ import annotations

import asyncio
import ssl
import weakref
from dataclasses import dataclass
from typing import Any

import aiohttp
from aiohttp.client_proto import ResponseHandler
from aiohttp.client_reqrep import ClientRequest, ConnectionKey
from aiohttp.connector import Connection
from aiohttp.tracing import Trace

from arodonata.adapters.checkpoint.connection_pool import (
    PooledSocketEntry,
    VerifiedConnectionPool,
    _transport_pool_ctx,
    is_poolable_command,
)
from arodonata.adapters.checkpoint.tls import (
    TrustPolicy,
    create_verified_ssl_context,
)
from arodonata.core.errors import ConfigurationError, ServerIdentityError, TransportError, TrustStoreError


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
        if not isinstance(trust_policy, TrustPolicy):
            raise ConfigurationError("FingerprintTCPConnector requires a valid TrustPolicy instance.")
        if ssl_context is None:
            ssl_context = create_verified_ssl_context(trust_policy)
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


__all__ = [
    "FingerprintTCPConnector",
    "_ProtoTrackEntry",
    "extract_peer_der_cert",
    "verify_transport_peer_certificate",
]
