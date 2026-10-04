"""TLS identity settings: trust modes, SHA-256 fingerprint parsing, store path (spec D6, D7, D11, D15)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from arodonata.config import ArodonataSettings
from arodonata.config.tls import (
    TrustMode,
    colon_hex,
    default_store_path,
    normalize_sha256,
    parse_fingerprints,
    resolve_store_path,
)
from arodonata.core.exceptions import (
    ApiTimeoutError,
    ArodonataError,
    CertificateMismatchError,
    ConfigurationError,
    ServerIdentityError,
    TrustStoreError,
    UnknownServerCertificateError,
)

HEX64 = "a1" * 32


@pytest.mark.parametrize(
    "value",
    [
        HEX64,
        HEX64.upper(),
        ":".join(HEX64[i : i + 2] for i in range(0, 64, 2)),
        " ".join(HEX64[i : i + 2] for i in range(0, 64, 2)).upper(),
        f"sha256:{HEX64}",
        f"SHA256 Fingerprint={colon_hex(HEX64)}",
    ],
)
def test_normalize_sha256_accepts_common_spellings(value):
    assert normalize_sha256(value) == HEX64


@pytest.mark.parametrize(
    ("value", "hint"),
    [
        ("b2" * 20, "SHA-1"),
        ("c3" * 16, "fwm fingerprint"),
        ("ABE LOAN BUSY DUET RUG HAT SAD KNEE GAWK OAK TINY ROW", "cp_conf finger"),
        ("zz" * 32, "64 hex digits"),
        ("a1" * 31, "64"),
    ],
)
def test_normalize_sha256_rejects_with_a_hint(value, hint):
    with pytest.raises(ValueError, match=hint):
        normalize_sha256(value)


def test_parse_fingerprints_splits_on_commas_and_skips_blanks():
    assert parse_fingerprints(f" {HEX64} , ,{'d4' * 32}") == [HEX64, "d4" * 32]
    assert parse_fingerprints("") == []


def test_colon_hex_is_uppercase_pairs():
    assert colon_hex("ab01") == "AB:01"


def test_default_store_path_uses_xdg_state_home(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert default_store_path() == tmp_path / "arodonata" / "tls_known_hosts.json"
    monkeypatch.delenv("XDG_STATE_HOME")
    assert default_store_path() == Path.home() / ".local" / "state" / "arodonata" / "tls_known_hosts.json"


def test_resolve_store_path_resolves_relative_against_cwd(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert resolve_store_path("trust.json") == tmp_path / "trust.json"
    assert resolve_store_path("") == default_store_path()


def test_settings_defaults(monkeypatch):
    for name in ("ARODONATA_TLS_TRUST", "ARODONATA_TLS_FINGERPRINTS", "ARODONATA_TLS_KNOWN_HOSTS_PATH"):
        monkeypatch.delenv(name, raising=False)
    s = ArodonataSettings()
    assert s.tls_trust == TrustMode.TOFU
    assert s.tls_fingerprints_list == []
    assert s.tls_known_hosts_path == ""
    assert s.connect_timeout == 30
    assert s.default_read_timeout == max(s.api_timeout, s.login_timeout) + 5


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("ARODONATA_TLS_TRUST", "PINNED")
    monkeypatch.setenv("ARODONATA_TLS_FINGERPRINTS", colon_hex(HEX64))
    monkeypatch.setenv("ARODONATA_CONNECT_TIMEOUT", "7")
    s = ArodonataSettings()
    assert s.tls_trust == "pinned"
    assert s.tls_fingerprints_list == [HEX64]
    assert s.connect_timeout == 7


@pytest.mark.parametrize(
    ("var", "value"),
    [("ARODONATA_TLS_TRUST", "off"), ("ARODONATA_TLS_FINGERPRINTS", "b2" * 20), ("ARODONATA_CONNECT_TIMEOUT", "0")],
)
def test_settings_reject_bad_values(monkeypatch, var, value):
    monkeypatch.setenv(var, value)
    with pytest.raises(ValidationError):
        ArodonataSettings()


def test_exception_hierarchy():
    assert issubclass(CertificateMismatchError, ServerIdentityError)
    assert issubclass(UnknownServerCertificateError, ServerIdentityError)
    assert issubclass(ServerIdentityError, ArodonataError) and not issubclass(ServerIdentityError, OSError)
    assert issubclass(TrustStoreError, ConfigurationError)
    assert issubclass(ApiTimeoutError, TimeoutError) and issubclass(ApiTimeoutError, ArodonataError)
    err = ApiTimeoutError("slow", phase="read", host="10.0.0.1", port=443, timeout=5.0, command="publish")
    assert (err.phase, err.host, err.port, err.timeout, err.command) == ("read", "10.0.0.1", 443, 5.0, "publish")
    ident = CertificateMismatchError(
        "x", host="h", port=443, presented_sha256="p", presented_sha1="s", expected_sha256="e", source="store"
    )
    assert (ident.host, ident.presented_sha256, ident.expected_sha256, ident.source) == ("h", "p", "e", "store")
