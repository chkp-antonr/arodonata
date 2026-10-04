"""TrustPolicy decision order, modes, lab gate and preflight (spec D6, D8, D9, D14)."""

from __future__ import annotations

import hashlib
import json
import logging
import ssl

import pytest

from arodonata.asdk.tls import TrustEntry, TrustPolicy, TrustStore, reset_lab_memory
from arodonata.config import ArodonataSettings
from arodonata.config.tls import TrustMode, colon_hex
from arodonata.core.exceptions import (
    CertificateMismatchError,
    ConfigurationError,
    TrustStoreError,
    UnknownServerCertificateError,
)

DER_A = b"certificate-A-der-bytes"
DER_B = b"certificate-B-der-bytes"
SHA_A = hashlib.sha256(DER_A).hexdigest()
SHA_B = hashlib.sha256(DER_B).hexdigest()


@pytest.fixture(autouse=True)
def _clean_memory():
    reset_lab_memory()
    yield
    reset_lab_memory()


def policy(tmp_path, mode=TrustMode.TOFU, pins=()):
    return TrustPolicy(mode, TrustStore(tmp_path / "t.json"), pins)


def test_tofu_learns_and_persists_then_accepts(tmp_path, caplog):
    p = policy(tmp_path)
    with caplog.at_level(logging.WARNING):
        assert p.check("10.0.0.1", 443, DER_A).sha256 == SHA_A
    assert "first contact" in caplog.text
    doc = json.loads((tmp_path / "t.json").read_text())
    assert doc["hosts"]["10.0.0.1:443"]["sha256"] == SHA_A and doc["hosts"]["10.0.0.1:443"]["source"] == "tofu"
    caplog.clear()
    assert policy(tmp_path).check("10.0.0.1", 443, DER_A).sha256 == SHA_A
    assert "first contact" not in caplog.text


def test_mismatch_is_refused_with_both_fingerprints_and_hints(tmp_path):
    policy(tmp_path).check("10.0.0.1", 443, DER_A)
    with pytest.raises(CertificateMismatchError) as info:
        policy(tmp_path).check("10.0.0.1", 443, DER_B)
    err = info.value
    assert (err.expected_sha256, err.presented_sha256, err.host, err.port) == (SHA_A, SHA_B, "10.0.0.1", 443)
    text = str(err)
    assert "No request was sent" in text and "api fingerprint -f json" in text and str(tmp_path / "t.json") in text
    assert json.loads((tmp_path / "t.json").read_text())["hosts"]["10.0.0.1:443"]["sha256"] == SHA_A


def test_operator_edit_applies_without_restart(tmp_path):
    p = policy(tmp_path)
    p.check("10.0.0.1", 443, DER_A)
    path = tmp_path / "t.json"
    doc = json.loads(path.read_text())
    doc["hosts"]["10.0.0.1:443"] = {"sha256": SHA_B}
    path.write_text(json.dumps(doc))
    assert p.check("10.0.0.1", 443, DER_B).sha256 == SHA_B


def test_env_pin_wins_over_a_stale_store_entry_and_never_writes(tmp_path, caplog):
    policy(tmp_path).check("10.0.0.1", 443, DER_A)
    before = (tmp_path / "t.json").read_bytes()
    with caplog.at_level(logging.WARNING):
        assert policy(tmp_path, pins=[SHA_B]).check("10.0.0.1", 443, DER_B).source == "env"
    assert "stale store entry" in caplog.text
    assert (tmp_path / "t.json").read_bytes() == before


def test_known_identity_at_a_new_address(tmp_path):
    p = policy(tmp_path)
    p.check("10.0.0.1", 443, DER_A)
    assert p.check("10.0.0.2", 443, DER_A).source == "known-identity"
    assert json.loads((tmp_path / "t.json").read_text())["hosts"]["10.0.0.2:443"]["source"] == "known-identity"


def test_pinned_refuses_unknown_accepts_pins_and_known_identity(tmp_path):
    p = policy(tmp_path, mode=TrustMode.PINNED, pins=[SHA_A])
    assert p.check("10.0.0.1", 443, DER_A).source == "env"
    with pytest.raises(UnknownServerCertificateError):
        p.check("10.0.0.3", 443, DER_B)
    assert not (tmp_path / "t.json").exists()


def test_lab_memory_learns_in_memory_and_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("ARODONATA_LAB", "home")
    ro = tmp_path / "ro"
    ro.mkdir(mode=0o555)
    try:
        p = TrustPolicy(TrustMode.LAB_MEMORY, TrustStore(ro / "t.json"), ())
        p.check("10.0.0.1", 443, DER_A)
        again = TrustPolicy(TrustMode.LAB_MEMORY, TrustStore(ro / "t.json"), ())  # shared per process
        with pytest.raises(CertificateMismatchError):
            again.check("10.0.0.1", 443, DER_B)
        assert list(ro.iterdir()) == []
    finally:
        ro.chmod(0o755)


def test_lab_memory_requires_arodonata_lab(monkeypatch):
    monkeypatch.setenv("ARODONATA_TLS_TRUST", "lab-memory")
    with pytest.raises(ConfigurationError, match="ARODONATA_LAB"):
        TrustPolicy.from_settings(ArodonataSettings())
    monkeypatch.setenv("ARODONATA_LAB", "home")
    assert TrustPolicy.from_settings(ArodonataSettings()).mode is TrustMode.LAB_MEMORY


def test_from_settings_touches_no_disk(monkeypatch, tmp_path):
    monkeypatch.setenv("ARODONATA_TLS_KNOWN_HOSTS_PATH", str(tmp_path / "x" / "t.json"))
    TrustPolicy.from_settings(ArodonataSettings())
    assert not (tmp_path / "x").exists()


def test_preflight_tofu_unwritable_raises(tmp_path):
    ro = tmp_path / "ro"
    ro.mkdir(mode=0o555)
    try:
        with pytest.raises(TrustStoreError):
            TrustPolicy(TrustMode.TOFU, TrustStore(ro / "sub" / "t.json"), ()).preflight()
        TrustPolicy(TrustMode.PINNED, TrustStore(ro / "sub" / "t.json"), ()).preflight()  # pinned never writes
    finally:
        ro.chmod(0o755)


def test_anchor_pems(tmp_path):
    p = policy(tmp_path)
    assert p.anchor_pems("10.0.0.1", 443) is None
    p.check("10.0.0.1", 443, DER_A)
    assert p.anchor_pems("10.0.0.1", 443) and "BEGIN CERTIFICATE" in p.anchor_pems("10.0.0.1", 443)[0]
    assert policy(tmp_path, pins=[SHA_A]).anchor_pems("10.0.0.1", 443) is None  # pins: probe once per process


def test_pinned_accepts_known_identity_without_writing(tmp_path):
    TrustStore(tmp_path / "t.json").record("10.0.0.1:443", _entry(DER_A))
    before = (tmp_path / "t.json").read_bytes()
    p = policy(tmp_path, mode=TrustMode.PINNED)
    assert p.check("10.0.0.2", 443, DER_A).source == "known-identity"
    assert (tmp_path / "t.json").read_bytes() == before


def _entry(der, source="tofu"):
    return TrustEntry(
        hashlib.sha256(der).hexdigest(), ssl.DER_cert_to_PEM_cert(der), source, "2026-01-01T00:00:00+00:00"
    )


def test_known_identity_race_is_refused(tmp_path, monkeypatch):
    p = policy(tmp_path)
    p.check("10.0.0.1", 443, DER_A)
    real = p.store.record

    def racing(key, entry):  # another process records B for the new key between our load and our record
        TrustStore(tmp_path / "t.json").record(key, _entry(DER_B))
        return real(key, entry)

    monkeypatch.setattr(p.store, "record", racing)
    with pytest.raises(CertificateMismatchError) as info:
        p.check("10.0.0.2", 443, DER_A)
    assert info.value.expected_sha256 == SHA_B


def test_anchor_pem_follows_the_accepted_certificate_after_retrust(tmp_path):
    p = policy(tmp_path)
    p.check("10.0.0.1", 443, DER_A)
    path = tmp_path / "t.json"
    doc = json.loads(path.read_text())
    doc["hosts"]["10.0.0.1:443"]["sha256"] = SHA_B  # operator re-trust keeps the old pem
    path.write_text(json.dumps(doc))
    assert p.check("10.0.0.1", 443, DER_B).sha256 == SHA_B
    assert p.anchor_pems("10.0.0.1", 443) == [ssl.DER_cert_to_PEM_cert(DER_B)]
    assert policy(tmp_path).anchor_pems("10.0.0.1", 443) is None  # stored pem no longer matches: probe


def test_anchor_pems_store_branch(tmp_path):
    policy(tmp_path).check("10.0.0.1", 443, DER_A)
    assert policy(tmp_path).anchor_pems("10.0.0.1", 443) == [ssl.DER_cert_to_PEM_cert(DER_A)]


def test_lab_memory_known_identity_is_memorised(tmp_path, monkeypatch):
    monkeypatch.setenv("ARODONATA_LAB", "home")
    p = TrustPolicy(TrustMode.LAB_MEMORY, TrustStore(tmp_path / "t.json"), ())
    p.check("10.0.0.1", 443, DER_A)
    assert p.check("10.0.0.2", 443, DER_A).source == "memory"
    with pytest.raises(CertificateMismatchError) as info:
        p.check("10.0.0.2", 443, DER_B)
    assert "restart the process" in str(info.value) and "replace the sha256" not in str(info.value)


def test_lab_memory_snapshot_is_a_copy(tmp_path, monkeypatch):
    monkeypatch.setenv("ARODONATA_LAB", "home")
    p = TrustPolicy(TrustMode.LAB_MEMORY, TrustStore(tmp_path / "t.json"), ())
    p.check("10.0.0.1", 443, DER_A)
    snapshot = p._memory()
    p.check("10.0.0.2", 443, DER_B)
    assert "10.0.0.2:443" not in snapshot


def test_mismatch_error_logged_once_per_key_and_presented(tmp_path, caplog):
    policy(tmp_path).check("10.0.0.1", 443, DER_A)
    with caplog.at_level(logging.ERROR):
        for _ in range(3):
            with pytest.raises(CertificateMismatchError):
                policy(tmp_path).check("10.0.0.1", 443, DER_B)
    assert [r.levelno for r in caplog.records].count(logging.ERROR) == 1


def test_pinned_refusal_logged_once_at_error_with_the_presented_fingerprint(tmp_path, caplog):
    p = policy(tmp_path, mode=TrustMode.PINNED, pins=[SHA_A])
    with caplog.at_level(logging.ERROR):
        for _ in range(3):
            with pytest.raises(UnknownServerCertificateError):
                p.check("10.0.0.3", 443, DER_B)
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert colon_hex(hashlib.sha256(DER_B).hexdigest()) in errors[0].getMessage()


def test_stale_warning_once_and_not_suppressing_mismatch_error(tmp_path, caplog):
    policy(tmp_path).check("10.0.0.1", 443, DER_A)
    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            policy(tmp_path, pins=[SHA_B]).check("10.0.0.1", 443, DER_B)
        with pytest.raises(CertificateMismatchError):
            policy(tmp_path).check("10.0.0.1", 443, DER_B)
    assert caplog.text.count("stale store entry") == 1
    assert [r.levelno for r in caplog.records].count(logging.ERROR) == 1


def test_tofu_learning_with_unwritable_store_raises(tmp_path):
    ro = tmp_path / "ro"
    ro.mkdir(mode=0o555)
    try:
        with pytest.raises(TrustStoreError):
            TrustPolicy(TrustMode.TOFU, TrustStore(ro / "sub" / "t.json"), ()).check("10.0.0.1", 443, DER_A)
    finally:
        ro.chmod(0o755)


def test_log_messages_render_literally_on_the_console(tmp_path):
    """arlogi's console handler is a RichHandler with markup on: '[fe80::1]' and ':AB:' must survive."""
    import io

    from arlogi.handlers import ColoredConsoleHandler
    from rich.console import Console

    from arodonata.asdk.tls import _emit

    buf = io.StringIO()
    handler = ColoredConsoleHandler(console=Console(file=buf, width=300, force_terminal=False))
    target = logging.getLogger("arodonata.asdk.tls")
    old_level = target.level
    target.addHandler(handler)
    target.setLevel(logging.INFO)
    try:
        _emit("warning", "TLS [fe80::1]:443 certificate 2E:AB:C1 trusted")
    finally:
        target.removeHandler(handler)
        target.setLevel(old_level)
    assert "TLS [fe80::1]:443 certificate 2E:AB:C1 trusted" in buf.getvalue()


def test_log_records_point_at_the_real_call_site(tmp_path, caplog):
    with caplog.at_level(logging.WARNING):
        policy(tmp_path).check("10.0.0.1", 443, DER_A)
    (record,) = [r for r in caplog.records if "first contact" in r.getMessage()]
    assert record.funcName == "_decide" and record.filename == "tls.py"
    assert record.markup is False
