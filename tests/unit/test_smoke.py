"""Initial smoke test for arodonata package bootstrap."""

import arodonata
from arodonata import AmbiguousObjectError, ArodonataError, ValidationError


def test_version() -> None:
    """Verify package version is exposed."""
    assert arodonata.__version__ == "2.2.0"


def test_ambiguous_object_error_inherits_validation_error() -> None:
    """Verify AmbiguousObjectError is exported at package root and inherits ValidationError."""
    candidates = [
        {"object_id": "mgmt1:DOM_A:Web-Shared", "domain": "DOM_A", "name": "Web-Shared"},
        {"object_id": "mgmt1:DOM_B:Web-Shared", "domain": "DOM_B", "name": "Web-Shared"},
    ]
    err = AmbiguousObjectError("mgmt1", "Web-Shared", candidates, known_sids=["secret_sid_123"])
    assert isinstance(err, ValidationError)
    assert isinstance(err, ArodonataError)
    assert err.mgmt_name == "mgmt1"
    assert err.query == "Web-Shared"
    assert err.candidates == candidates
    assert "DOM_A, DOM_B" in str(err)
