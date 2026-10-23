"""Unit tests for `TrustStore` and `TrustPolicy` (`src/arodonata/adapters/checkpoint/tls.py`)."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from arodonata.adapters.checkpoint.tls import (
    TrustPolicy,
    TrustStore,
    compute_der_fingerprint,
    normalize_fingerprint,
)
from arodonata.core.errors import (
    CertificateMismatchError,
    ConfigurationError,
    ServerIdentityError,
    TrustStoreError,
    UnknownServerCertificateError,
)


def _make_der(seed: str) -> tuple[bytes, str]:
    der = f"fake-der-cert-{seed}".encode()
    digest = hashlib.sha256(der).hexdigest().upper()
    formatted = ":".join(digest[i : i + 2] for i in range(0, 64, 2))
    return der, formatted


def test_untrusted_certificate_refused_in_pinned_mode(tmp_path: Path) -> None:
    """Scenario: Untrusted certificate refused in pinned mode."""
    known_hosts = tmp_path / "tls_known_hosts.json"
    der1, fp1 = _make_der("cert-1")
    der2, _fp2 = _make_der("cert-2")

    policy = TrustPolicy(
        mode="pinned",
        known_hosts_path=known_hosts,
        pinned_fingerprints=f"10.0.0.1:443={fp1}",
    )

    # Matching pinned cert succeeds
    assert policy.verify_der("10.0.0.1", 443, der1) == fp1

    # Unpinned address with unknown cert raises UnknownServerCertificateError with "No request was sent."
    with pytest.raises(UnknownServerCertificateError) as exc_info:
        policy.verify_der("10.0.0.99", 443, der2)
    assert "No request was sent." in str(exc_info.value)
    assert isinstance(exc_info.value, ServerIdentityError)

    # Pinned address presenting different cert raises CertificateMismatchError with "No request was sent."
    with pytest.raises(CertificateMismatchError) as mismatch_info:
        policy.verify_der("10.0.0.1", 443, der2)
    assert "No request was sent." in str(mismatch_info.value)


def test_first_contact_learned_in_tofu_mode_and_0600_mode(tmp_path: Path) -> None:
    """Scenario: First contact learned in TOFU mode with atomic 0600 persistence."""
    known_hosts = tmp_path / "tls_known_hosts.json"
    der1, fp1 = _make_der("tofu-1")
    der2, _fp2 = _make_der("tofu-2")

    policy = TrustPolicy(mode="tofu", known_hosts_path=known_hosts)
    learned = policy.verify_der("10.10.1.1", 443, der1)
    assert learned == fp1
    assert known_hosts.exists()

    # Check 0600 file permissions
    file_mode = stat.S_IMODE(os.stat(known_hosts).st_mode)
    assert file_mode == 0o600

    # Reload in a fresh TrustPolicy in pinned or tofu mode and verify persistence
    policy_reloaded = TrustPolicy(mode="tofu", known_hosts_path=known_hosts)
    assert policy_reloaded.verify_der("10.10.1.1", 443, der1) == fp1

    # Presenting a different certificate on subsequent connection raises CertificateMismatchError
    with pytest.raises(CertificateMismatchError) as exc_info:
        policy_reloaded.verify_der("10.10.1.1", 443, der2)
    assert "No request was sent." in str(exc_info.value)


def test_known_mds_member_fingerprint_accepted_on_new_domain_ip(tmp_path: Path) -> None:
    """Scenario: Known MDS member fingerprint accepted on a new domain IP."""
    known_hosts = tmp_path / "tls_known_hosts.json"
    mds_der, mds_fp = _make_der("mds-member-cert")

    # 1. TOFU mode: first contact on MDS IP 10.0.0.1, then domain IP 10.0.0.15 presents same cert
    tofu_policy = TrustPolicy(mode="tofu", known_hosts_path=known_hosts)
    tofu_policy.verify_der("10.0.0.1", 443, mds_der)
    assert tofu_policy.verify_der("10.0.0.15", 443, mds_der) == mds_fp

    entry = tofu_policy.trust_store.get("10.0.0.15", 443)
    assert entry is not None
    assert entry.fingerprint == mds_fp
    assert entry.source == "known-identity"

    # 2. Pinned mode: pinned for 10.0.0.1, accepted on domain IP 10.0.0.25 presenting same cert
    pinned_policy = TrustPolicy(
        mode="pinned",
        known_hosts_path=tmp_path / "empty.json",
        pinned_fingerprints={"10.0.0.1:443": mds_fp},
    )
    assert pinned_policy.verify_der("10.0.0.25", 443, mds_der) == mds_fp


def test_lab_memory_mode_restricted_to_lab_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario: Lab-memory mode restricted to lab environment."""
    monkeypatch.delenv("ARODONATA_LAB", raising=False)
    with pytest.raises(ConfigurationError, match="ARODONATA_LAB"):
        TrustPolicy(mode="lab-memory", known_hosts_path=tmp_path / "never.json")

    monkeypatch.setenv("ARODONATA_LAB", "1")
    policy = TrustPolicy(mode="lab-memory", known_hosts_path=tmp_path / "never.json")
    der1, fp1 = _make_der("lab-cert-1")
    der2, _ = _make_der("lab-cert-2")

    assert policy.verify_der("192.168.1.10", 443, der1) == fp1
    assert not (tmp_path / "never.json").exists()

    # Still detects mismatch within the same process session
    with pytest.raises(CertificateMismatchError):
        policy.verify_der("192.168.1.10", 443, der2)


def test_fingerprint_normalization_and_corrupt_store(tmp_path: Path) -> None:
    """Verify fingerprint formats and corrupt trust store handling."""
    der, fp = _make_der("norm")
    raw_hex = fp.replace(":", "").lower()
    assert normalize_fingerprint(f"SHA256:{raw_hex}") == fp
    assert compute_der_fingerprint(der) == fp

    with pytest.raises(ConfigurationError):
        normalize_fingerprint("invalid-short-hex")

    corrupt_path = tmp_path / "corrupt.json"
    corrupt_path.write_text("{not-valid-json", encoding="utf-8")
    store = TrustStore(path=corrupt_path)
    with pytest.raises(TrustStoreError) as exc_info:
        store.load()
    assert "No request was sent." in str(exc_info.value)
