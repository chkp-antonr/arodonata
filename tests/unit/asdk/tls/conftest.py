"""Certificates and servers for tls.py tests. Unit tests here may only connect to 127.0.0.1."""

from __future__ import annotations

import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from arodonata.asdk.tls import TrustPolicy, TrustStore, reset_lab_memory
from arodonata.config.tls import TrustMode

from .tls_server import TLSTestServer


def _make_cert(directory: Path, name: str, *, expired: bool = False) -> tuple[Path, Path, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])  # like Gaia: CN = IP, no SAN
    now = datetime.now(UTC)
    start, end = (
        (now - timedelta(days=30), now - timedelta(days=1))
        if expired
        else (now - timedelta(days=1), now + timedelta(days=30))
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / f"{name}.crt", directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return cert_path, key_path, cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture(scope="session")
def certs(tmp_path_factory):
    directory = tmp_path_factory.mktemp("certs")
    return {name: _make_cert(directory, name, expired=(name == "expired")) for name in ("a", "b", "expired")}


@pytest.fixture
def server_factory(certs):
    servers: list[TLSTestServer] = []

    def make(*names: str, mode: str = "answer", modes: list[str] | None = None) -> TLSTestServer:
        server = TLSTestServer([(certs[n][0], certs[n][1]) for n in names], mode=mode, modes=modes)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


@pytest.fixture
def tofu(tmp_path):
    reset_lab_memory()
    yield TrustPolicy(TrustMode.TOFU, TrustStore(tmp_path / "trust.json"), ())
    reset_lab_memory()


@pytest.fixture(autouse=True)
def loopback_only(monkeypatch):
    real = socket.socket.connect

    def guarded(self, address):
        host = address[0] if isinstance(address, tuple) else address
        assert host in ("127.0.0.1", "::1", "localhost"), f"unit test tried to connect to {host}"
        return real(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded)
