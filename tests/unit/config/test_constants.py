"""Tests for arodonata.config.constants static values."""

from __future__ import annotations

from arodonata.config import constants


class TestDefaultValues:
    def test_default_session_expire(self):
        assert constants.DEFAULT_SESSION_EXPIRE == 3600

    def test_default_session_timeout(self):
        assert constants.DEFAULT_SESSION_TIMEOUT == 600

    def test_default_api_timeout(self):
        assert constants.DEFAULT_API_TIMEOUT == 120

    def test_default_concurrent_limit(self):
        assert constants.DEFAULT_CONCURRENT_LIMIT == 3

    def test_default_login_backoff(self):
        assert constants.DEFAULT_LOGIN_BACKOFF == 5

    def test_default_login_retries(self):
        assert constants.DEFAULT_LOGIN_RETRIES == 8


class TestErrorCodeSets:
    def test_session_error_codes_contains_expected(self):
        assert "generic_err_session_expired" in constants.SESSION_ERROR_CODES
        assert "generic_err_wrong_session_id" in constants.SESSION_ERROR_CODES
        assert "generic_err_missing_session_id" in constants.SESSION_ERROR_CODES

    def test_failover_error_codes_contains_expected(self):
        assert "generic_err_no_permissions" in constants.FAILOVER_ERROR_CODES
        assert "err_forbidden" in constants.FAILOVER_ERROR_CODES

    def test_throttle_error_code(self):
        assert constants.THROTTLE_ERROR_CODE == "err_too_many_requests"

    def test_error_code_sets_are_frozen(self):
        assert isinstance(constants.SESSION_ERROR_CODES, frozenset)
        assert isinstance(constants.FAILOVER_ERROR_CODES, frozenset)

    def test_session_and_failover_codes_disjoint(self):
        assert constants.SESSION_ERROR_CODES.isdisjoint(constants.FAILOVER_ERROR_CODES)


class TestLogLevels:
    def test_log_levels_contains_standard_levels(self):
        for level in ("TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            assert level in constants.LOG_LEVELS

    def test_log_levels_is_frozenset(self):
        assert isinstance(constants.LOG_LEVELS, frozenset)

    def test_log_levels_excludes_unknown(self):
        assert "VERBOSE" not in constants.LOG_LEVELS


class TestDunderAll:
    def test_all_exports_are_defined(self):
        for name in constants.__all__:
            assert hasattr(constants, name)
