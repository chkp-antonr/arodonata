"""Unit tests for the Arodonata exception hierarchy.

Covers every exception class, its inheritance contract, and the
message/code propagation behaviour of the two custom ``__init__``s
(``ArodonataError`` and ``ApiError``).
"""

import pytest

from arodonata.core import exceptions as exc

# (child, expected_parent) pairs describing the full hierarchy.
_HIERARCHY = [
    (exc.ArodonataError, Exception),
    (exc.ConfigurationError, exc.ArodonataError),
    (exc.MissingConfigurationError, exc.ConfigurationError),
    (exc.ConnectionError, exc.ArodonataError),
    (exc.DatabaseConnectionError, exc.ConnectionError),
    (exc.ApiConnectionError, exc.ConnectionError),
    (exc.AuthenticationError, exc.ArodonataError),
    (exc.SessionExpiredError, exc.AuthenticationError),
    (exc.InvalidCredentialsError, exc.AuthenticationError),
    (exc.ApiError, exc.ArodonataError),
    (exc.ApiCallError, exc.ApiError),
    (exc.ApiQueryError, exc.ApiError),
    (exc.ThrottlingError, exc.ApiError),
    (exc.CacheError, exc.ArodonataError),
    (exc.CacheNotInitializedError, exc.CacheError),
    (exc.ClientError, exc.ArodonataError),
    (exc.ClientClosedError, exc.ClientError),
    (exc.ServerNotFoundError, exc.ClientError),
]

_ALL_CLASSES = [child for child, _ in _HIERARCHY]


@pytest.mark.parametrize("child, parent", _HIERARCHY)
def test_exception_inherits_expected_parent(child, parent):
    assert issubclass(child, parent)


@pytest.mark.parametrize("child, _parent", _HIERARCHY)
def test_every_exception_is_a_arodonata_error(child, _parent):
    assert issubclass(child, exc.ArodonataError)


def test_base_error_stores_message_attribute():
    err = exc.ArodonataError("boom")
    assert err.message == "boom"
    assert str(err) == "boom"


def test_base_error_forwards_extra_positional_args():
    err = exc.ArodonataError("boom", 42, "detail")
    assert err.message == "boom"
    assert err.args == ("boom", 42, "detail")


@pytest.mark.parametrize("cls", _ALL_CLASSES)
def test_every_subclass_accepts_a_message(cls):
    # ApiError-family accept the same first positional message arg.
    err = cls("something went wrong")
    assert err.message == "something went wrong"


def test_api_error_defaults_have_no_code_or_detail():
    err = exc.ApiError("api failed")
    assert err.message == "api failed"
    assert err.err_code is None
    assert err.err_message is None


def test_api_error_propagates_code_and_message():
    err = exc.ApiError(
        "api failed",
        err_code="err_validation",
        err_message="field X is required",
    )
    assert err.err_code == "err_validation"
    assert err.err_message == "field X is required"


def test_api_error_accepts_integer_code_and_extra_args():
    err = exc.ApiError("api failed", "extra", err_code=500)
    assert err.err_code == 500
    assert err.args == ("api failed", "extra")


@pytest.mark.parametrize("cls", [exc.ApiCallError, exc.ApiQueryError, exc.ThrottlingError])
def test_api_error_subclasses_inherit_code_propagation(cls):
    err = cls("nope", err_code=429, err_message="throttled")
    assert isinstance(err, exc.ApiError)
    assert err.err_code == 429
    assert err.err_message == "throttled"


def test_exceptions_are_catchable_as_base():
    with pytest.raises(exc.ArodonataError):
        raise exc.ServerNotFoundError("mgmt-x not found")


def test_specific_subclass_not_caught_by_sibling():
    # SessionExpiredError must not be an InvalidCredentialsError.
    assert not issubclass(exc.SessionExpiredError, exc.InvalidCredentialsError)


def test_all_exports_are_defined():
    for name in exc.__all__:
        assert hasattr(exc, name), name
    exported = {getattr(exc, name) for name in exc.__all__}
    for cls in _ALL_CLASSES:
        assert cls in exported
