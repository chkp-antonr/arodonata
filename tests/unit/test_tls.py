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
    format_host_port,
    normalize_fingerprint,
    parse_tls_fingerprints,
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
    os.chmod(corrupt_path, 0o600)
    store = TrustStore(path=corrupt_path)
    with pytest.raises(TrustStoreError) as exc_info:
        store.load()
    assert "No request was sent." in str(exc_info.value)


def test_trust_store_concurrent_tofu_merge_permission_check_and_ipv6(tmp_path: Path) -> None:
    """Adversarial test for W3 and I9:
    - Two TrustStore instances pointing to the same file merge TOFU entries without losing sibling writes
    - Conflicting concurrent TOFU fingerprint raises CertificateMismatchError
    - Group/world-writable trust store file is rejected on load
    - IPv6 literals ([2001:db8::1]:443, 2001:db8::1, [::1]:8443) normalize without splitting internal colons
    """
    known_hosts = tmp_path / "shared_known_hosts.json"
    der1, fp1 = _make_der("proc-1")
    der2, fp2 = _make_der("proc-2")
    der_conflict, _ = _make_der("proc-conflict")

    policy_a = TrustPolicy(mode="tofu", known_hosts_path=known_hosts)
    policy_b = TrustPolicy(mode="tofu", known_hosts_path=known_hosts)

    # Both load initially when file doesn't exist
    assert policy_a.trust_store.entries == {}
    assert policy_b.trust_store.entries == {}

    # Process A learns 10.0.0.1, then Process B learns 10.0.0.2
    policy_a.verify_der("10.0.0.1", 443, der1)
    policy_b.verify_der("10.0.0.2", 443, der2)

    # Reload a third store and confirm BOTH entries are preserved on disk
    store_c = TrustStore(path=known_hosts)
    assert store_c.get("10.0.0.1", 443) is not None
    assert store_c.get("10.0.0.1", 443).fingerprint == fp1  # type: ignore[union-attr]
    assert store_c.get("10.0.0.2", 443) is not None
    assert store_c.get("10.0.0.2", 443).fingerprint == fp2  # type: ignore[union-attr]

    # If a stale in-memory store tries to record a conflicting fingerprint for 10.0.0.1, merge rejects it
    stale_store = TrustStore(path=known_hosts)
    stale_store._loaded = True
    stale_store._entries = {}
    with pytest.raises(CertificateMismatchError):
        stale_store.record("10.0.0.1", 443, compute_der_fingerprint(der_conflict))

    # Unsafe file permissions (0666 / world-writable) must be rejected on load
    os.chmod(known_hosts, 0o666)
    unsafe_store = TrustStore(path=known_hosts)
    with pytest.raises(TrustStoreError, match="Unsafe permissions"):
        unsafe_store.load()
    os.chmod(known_hosts, 0o600)

    # IPv6 key formatting and pin parsing
    assert format_host_port("2001:db8::1", 443) == "[2001:db8::1]:443"
    assert format_host_port("[2001:db8:0:0::1]:8443", 443) == "[2001:db8::1]:8443"
    pins = parse_tls_fingerprints(f"[2001:db8::1]:8443={fp1},2001:db8::2={fp2}")
    assert pins["[2001:db8::1]:8443"] == fp1
    assert pins["[2001:db8::2]:443"] == fp2

    ipv6_policy = TrustPolicy(
        mode="pinned",
        known_hosts_path=known_hosts,
        pinned_fingerprints=pins,
    )
    assert ipv6_policy.verify_der("2001:db8::1", 8443, der1) == fp1
    assert ipv6_policy.verify_der("[2001:db8::2]", 443, der2) == fp2
