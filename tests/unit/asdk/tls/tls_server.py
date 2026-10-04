"""A scriptable 127.0.0.1 TLS server that records the application bytes it receives (spec 'Tests: Fixtures')."""

from __future__ import annotations

import json
import socket
import ssl
import threading
from dataclasses import dataclass, field
from pathlib import Path

MODES = ("answer", "drop_after_request", "close", "never_handshake", "never_answer", "headers_then_stall")


@dataclass
class TLSTestServer:
    certs: list[tuple[Path, Path]]  # (cert, key) per connection index; the last pair repeats
    mode: str = "answer"
    modes: list[str] | None = None  # per connection index, overrides ``mode``; the last one repeats
    payload: dict = field(default_factory=lambda: {"sid": "server-issued-sid", "uid": "u1"})
    received: dict[int, bytes] = field(default_factory=dict)
    request_lines: list[tuple[int, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        assert self.mode in MODES and all(m in MODES for m in self.modes or ())
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._sock.settimeout(0.1)  # the accept loop polls _stop, so close() can join it
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._count = 0
        self._dropped = False  # drop_after_request: only the first connection that carries a request is dropped
        self._lock = threading.Lock()
        self._open: dict[int, socket.socket] = {}  # live socket per connection, shut down by close()
        self._threads: list[threading.Thread] = [threading.Thread(target=self._accept_loop, daemon=True)]
        self._threads[0].start()

    def close(self) -> None:
        self._stop.set()
        with self._lock:
            live = list(self._open.values())
        for sock in live:  # wake handlers blocked in recv() or in the handshake
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for thread in list(self._threads):
            thread.join(5)
            assert not thread.is_alive(), "TLS test server thread did not stop"
        self._sock.close()

    def bytes_on(self, index: int) -> int:
        return len(self.received.get(index, b""))

    def _mode(self, index: int) -> str:
        return self.modes[min(index, len(self.modes) - 1)] if self.modes else self.mode

    def _context(self, index: int) -> ssl.SSLContext:
        cert, key = self.certs[min(index, len(self.certs) - 1)]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        return ctx

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            conn.settimeout(None)
            with self._lock:
                index, self._count = self._count, self._count + 1
                self._open[index] = conn
                thread = threading.Thread(target=self._handle, args=(conn, index), daemon=True)
                self._threads.append(thread)
            thread.start()

    def _track(self, index: int, sock: socket.socket | None) -> None:
        with self._lock:
            if sock is None:
                self._open.pop(index, None)
            else:
                self._open[index] = sock

    def _handle(self, raw: socket.socket, index: int) -> None:
        mode = self._mode(index)
        try:
            if mode == "never_handshake":
                self._stop.wait(30)
                raw.close()
                return
            tls = self._context(index).wrap_socket(raw, server_side=True)
        except (OSError, ssl.SSLError):
            raw.close()
            self._track(index, None)
            return
        self._track(index, tls)
        try:
            while not self._stop.is_set():
                request = self._read_request(tls, index)
                if request is None:
                    return
                if mode == "drop_after_request" and not self._dropped:
                    self._dropped = True
                    return
                if mode == "never_answer":
                    self._stop.wait(30)
                    return
                body = json.dumps(self.payload).encode()
                if mode == "headers_then_stall":
                    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
                    self._stop.wait(30)
                    return
                closing = mode == "close"
                tls.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode()
                    + (b"Connection: close\r\n" if closing else b"")
                    + b"\r\n"
                    + body
                )
                if closing:
                    return
        except (OSError, ssl.SSLError):
            return
        finally:
            tls.close()
            self._track(index, None)

    def _read_request(self, tls: ssl.SSLSocket, index: int) -> bytes | None:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = tls.recv(65536)
            if not chunk:
                return None
            data += chunk
            self.received[index] = self.received.get(index, b"") + chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                length = int(value.strip())
        while len(rest) < length:
            chunk = tls.recv(65536)
            if not chunk:
                return None
            rest += chunk
            self.received[index] = self.received.get(index, b"") + chunk
        self.request_lines.append((index, head.split(b"\r\n")[0].decode()))
        return head
