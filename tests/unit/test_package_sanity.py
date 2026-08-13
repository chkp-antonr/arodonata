"""Package sanity: the public surface imports and exposes its facade."""

import arodonata


def test_public_facade_importable():
    assert hasattr(arodonata, "ArodonataClient")
    assert hasattr(arodonata, "ArodonataSettings")


def test_version_present():
    assert isinstance(arodonata.__version__, str) and arodonata.__version__
