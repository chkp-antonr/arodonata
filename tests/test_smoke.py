"""Initial smoke test for arodonata package bootstrap."""

import arodonata


def test_version() -> None:
    """Verify package version is exposed."""
    assert arodonata.__version__ == "2.0.0a0"
