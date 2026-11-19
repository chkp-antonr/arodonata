"""Unit tests for `TrustStore` and `TrustPolicy` (`src/arodonata/adapters/checkpoint/tls.py`)."""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import stat
from pathlib import Path
from typing import Any

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from arodonata.adapters.checkpoint import tls as tls_mod
from arodonata.adapters.checkpoint.connection_pool import VerifiedConnectionPool
from arodonata.adapters.checkpoint.connector import FingerprintTCPConnector
from arodonata.adapters.checkpoint.tls import (
    PolicyBoundSSLContext,
    TrustPolicy,
    TrustStore,
    compute_der_fingerprint,
    create_verified_ssl_context,
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
from arodonata.core.telemetry import set_trace_modules


def _make_der(seed: str) -> tuple[bytes, str]:
    der = f"fake-der-cert-{seed}".encode()
    digest = hashlib.sha256(der).hexdigest().upper()
    formatted = ":".join(digest[i : i + 2] for i in range(0, 64, 2))
    return der, formatted


@pytest.mark.spec("SCN-TRANS-002-1")
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


@pytest.mark.spec("SCN-TRANS-003-1")
def test_first_contact_learned_in_tofu_mode_and_0600_mode(tmp_path: Path) -> None:
    """Scenario: First contact learned in TOFU mode with atomic 0600 persistence."""
    known_hosts = tmp_path / "tls_known_hosts.json"
    der1, fp1 = _make_der("tofu-1")
    der2, _fp2 = _make_der("tofu-2")

    policy = TrustPolicy(mode="tofu", known_hosts_path=known_hosts)
    learned = policy.verify_der("10.10.1.1", 443, der1)
    assert learned == fp1
    assert known_hosts.exists()

    # Check 0600 file permissions (POSIX only)
    if os.name != "nt":
        file_mode = stat.S_IMODE(os.stat(known_hosts).st_mode)
        assert file_mode == 0o600

    # Reload in a fresh TrustPolicy in pinned or tofu mode and verify persistence
    policy_reloaded = TrustPolicy(mode="tofu", known_hosts_path=known_hosts)
    assert policy_reloaded.verify_der("10.10.1.1", 443, der1) == fp1

    # Presenting a different certificate on subsequent connection raises CertificateMismatchError
    with pytest.raises(CertificateMismatchError) as exc_info:
        policy_reloaded.verify_der("10.10.1.1", 443, der2)
    assert "No request was sent." in str(exc_info.value)


@pytest.mark.spec("SCN-TRANS-002-2")
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


@pytest.mark.spec("SCN-TRANS-002-3")
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


@pytest.mark.spec("SCN-TRANS-003-1", "SCN-TRANS-003-2")
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

    # Unsafe file permissions (0666 / world-writable) must be rejected on load (POSIX only)
    if os.name != "nt":
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


@pytest.mark.spec("SCN-TRANS-002-6")
def test_tls_tofu_audit_warning_span_tls_decision_and_policy_bound_ssl_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    """SCN-TRANS-002-6: Verify TOFU/lab-memory WARNING audit logs, tls_decision span attrs, and TrustPolicy SSLContext binding."""
    set_trace_modules(None)
    exporter = InMemorySpanExporter()
    proc = SimpleSpanProcessor(exporter)
    existing_provider = trace.get_tracer_provider()
    if hasattr(existing_provider, "add_span_processor"):
        existing_provider.add_span_processor(proc)
    else:
        provider = TracerProvider()
        provider.add_span_processor(proc)
        trace.set_tracer_provider(provider)
    request.addfinalizer(proc.shutdown)
    exporter.clear()

    warn_logs: list[tuple[str, dict[str, Any]]] = []
    err_logs: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(tls_mod.logger, "warning", lambda msg, **kw: warn_logs.append((str(msg), dict(kw))))
    monkeypatch.setattr(tls_mod.logger, "error", lambda msg, **kw: err_logs.append((str(msg), dict(kw))))

    der_tofu, fp_tofu = _make_der("audit-tofu")
    der_other, _ = _make_der("audit-other")
    der_lab, fp_lab = _make_der("audit-lab")
    der_pin, fp_pin = _make_der("audit-pin")

    # 1. TOFU first contact -> WARNING audit log + tls_decision="tofu_first_contact"
    tofu_policy = TrustPolicy(mode="tofu", known_hosts_path=tmp_path / "tofu.json")
    assert tofu_policy.verify_der("10.20.0.1", 443, der_tofu) == fp_tofu
    assert len(warn_logs) == 1
    w_msg, w_kw = warn_logs[0]
    assert w_msg == "tls_tofu_first_contact"
    assert w_kw == {
        "event": "tls_tofu_first_contact",
        "host": "10.20.0.1",
        "port": 443,
        "fingerprint": fp_tofu,
        "mode": "tofu",
    }

    # Second contact on same host -> no extra first-contact warning, tls_decision="tofu_match"
    warn_logs.clear()
    assert tofu_policy.verify_der("10.20.0.1", 443, der_tofu) == fp_tofu
    assert warn_logs == []

    # Same fingerprint on new MDS member IP -> tls_decision="known_identity_match"
    assert tofu_policy.verify_der("10.20.0.2", 443, der_tofu) == fp_tofu

    # Mismatch on TOFU stored entry -> ERROR log + tls_decision="mismatch"
    with pytest.raises(CertificateMismatchError):
        tofu_policy.verify_der("10.20.0.1", 443, der_other)
    assert any(
        msg == "tls_certificate_mismatch" and kw.get("event") == "tls_certificate_mismatch" for msg, kw in err_logs
    )

    # 2. Lab-memory first contact -> WARNING audit log + tls_decision="lab_memory_first_contact" -> "lab_memory_match"
    monkeypatch.setenv("ARODONATA_LAB", "1")
    warn_logs.clear()
    lab_policy = TrustPolicy(mode="lab-memory", known_hosts_path=tmp_path / "unused.json")
    assert lab_policy.verify_der("10.30.0.1", 443, der_lab) == fp_lab
    assert len(warn_logs) == 1
    assert warn_logs[0][1]["event"] == "tls_tofu_first_contact"
    assert warn_logs[0][1]["mode"] == "lab-memory"
    assert lab_policy.verify_der("10.30.0.1", 443, der_lab) == fp_lab

    # 3. Pinned match, unpinned rejection, and missing DER cert
    warn_logs.clear()
    err_logs.clear()
    pinned_policy = TrustPolicy(
        mode="pinned",
        known_hosts_path=tmp_path / "pinned.json",
        pinned_fingerprints=f"10.40.0.1:443={fp_pin}",
    )
    assert pinned_policy.verify_der("10.40.0.1", 443, der_pin) == fp_pin
    with pytest.raises(UnknownServerCertificateError):
        pinned_policy.verify_der("10.40.0.99", 443, der_other)
    assert any(kw.get("event") == "tls_unpinned_certificate_rejected" for _, kw in warn_logs)
    with pytest.raises(TrustStoreError):
        pinned_policy.verify_der("10.40.0.1", 443, None)
    assert any(kw.get("event") == "tls_missing_peer_certificate" for _, kw in err_logs)

    # Verify OpenTelemetry span attributes across all tls_decision outcomes
    decisions = [
        (sp.attributes or {}).get("arodonata.tls_decision")
        for sp in exporter.get_finished_spans()
        if (sp.attributes or {}).get("arodonata.tls_decision") is not None
    ]
    for expected in (
        "tofu_first_contact",
        "tofu_match",
        "known_identity_match",
        "mismatch",
        "lab_memory_first_contact",
        "lab_memory_match",
        "pinned_match",
        "unpinned_rejected",
        "missing_cert",
    ):
        assert expected in decisions

    # 4. Verify TrustPolicy.create_ssl_context() and create_verified_ssl_context(policy)
    for policy in (tofu_policy, pinned_policy):
        ctx = policy.create_ssl_context()
        assert isinstance(ctx, PolicyBoundSSLContext)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx is create_verified_ssl_context(policy)
        assert ctx is policy.create_ssl_context()
        assert ctx.trust_policy_mode == policy.mode
        assert ctx.trust_policy is policy
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        assert ctx.verify_mode == ssl.CERT_NONE
        assert ctx.check_hostname is False
        assert bool(ctx.options & ssl.OP_NO_COMPRESSION)

    with pytest.raises(ConfigurationError, match="TrustPolicy"):
        create_verified_ssl_context(object())  # type: ignore[arg-type]


@pytest.mark.spec("SCN-TRANS-002-6", "SCN-TRANS-003-1")
def test_tls_concurrent_tofu_rollback_legacy_stored_decision_and_connector_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    """Verify atomic TrustStore rollback on mismatch/OSError, legacy 'stored_match' spans, and connector Policy check."""
    set_trace_modules(None)
    exporter = InMemorySpanExporter()
    proc = SimpleSpanProcessor(exporter)
    existing_provider = trace.get_tracer_provider()
    if hasattr(existing_provider, "add_span_processor"):
        existing_provider.add_span_processor(proc)
    else:
        provider = TracerProvider()
        provider.add_span_processor(proc)
        trace.set_tracer_provider(provider)
    request.addfinalizer(proc.shutdown)
    exporter.clear()

    # 1. F1: Concurrent TOFU merge mismatch must NOT poison self._entries in memory
    kh_path = tmp_path / "race_known_hosts.json"
    der_real, fp_real = _make_der("concurrent-real")
    der_evil, fp_evil = _make_der("concurrent-evil")

    policy_a = TrustPolicy(mode="tofu", known_hosts_path=kh_path)
    policy_b = TrustPolicy(mode="tofu", known_hosts_path=kh_path)

    # Simulate sibling Process A winning the write race right after Process B's store.get() saw None
    orig_b_get = policy_b.trust_store.get
    race_fired = False

    def _racy_get(host: str, port: int = 443) -> Any:
        nonlocal race_fired
        res = orig_b_get(host, port)
        if not race_fired and res is None:
            race_fired = True
            assert policy_a.verify_der(host, port, der_real) == fp_real
        return res

    monkeypatch.setattr(policy_b.trust_store, "get", _racy_get)

    with pytest.raises(CertificateMismatchError, match="concurrent TOFU merge"):
        policy_b.verify_der("10.50.0.1", 443, der_evil)

    # Second connection attempt on Process B with attacker cert must STILL fail (never tofu_match!)
    with pytest.raises(CertificateMismatchError):
        policy_b.verify_der("10.50.0.1", 443, der_evil)
    assert policy_b.verify_der("10.50.0.1", 443, der_real) == fp_real

    # Write failure (OSError) during persist must also leave _entries clean
    err_kh = tmp_path / "err_known_hosts.json"
    store_err = TrustStore(path=err_kh)

    def _boom_replace(_src: Path | str, _dst: Path | str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", _boom_replace)
    with pytest.raises(TrustStoreError, match="Failed to persist TLS trust store"):
        store_err.record("10.50.0.2", 443, fp_real, source="tofu", persist=True)
    assert store_err.get("10.50.0.2", 443) is None

    # 2. F4: Legacy flat known-hosts file reports tls_decision='stored_match', never 'pinned_match'
    legacy_kh = tmp_path / "legacy_known_hosts.json"
    der_leg, fp_leg = _make_der("legacy-flat")
    legacy_kh.write_text(json.dumps({"10.60.0.1:443": fp_leg}) + "\n", encoding="utf-8")
    os.chmod(legacy_kh, 0o600)

    exporter.clear()
    legacy_policy = TrustPolicy(mode="tofu", known_hosts_path=legacy_kh)
    assert legacy_policy.verify_der("10.60.0.1", 443, der_leg) == fp_leg
    decisions = [
        (sp.attributes or {}).get("arodonata.tls_decision")
        for sp in exporter.get_finished_spans()
        if (sp.attributes or {}).get("arodonata.tls_decision") is not None
    ]
    assert "stored_match" in decisions
    assert "pinned_match" not in decisions

    # 3. F6: FingerprintTCPConnector rejects non-TrustPolicy upfront
    with pytest.raises(ConfigurationError, match="TrustPolicy"):
        FingerprintTCPConnector(
            trust_policy=object(),  # type: ignore[arg-type]
            connection_pool=VerifiedConnectionPool(),
        )
