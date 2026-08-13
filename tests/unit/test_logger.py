"""Tests for arodonata.logger (thin wrapper around arlogi)."""

from __future__ import annotations

import logging

import pytest
from arlogi import LoggerFactory, get_default_level

from arodonata.logger import get_logger, lazy_logger

# Child loggers whose levels arodonata.logger._ensure_initialized pins via
# module_levels (keep in sync with the dict in src/arodonata/logger.py).
_MODULE_LEVEL_LOGGERS = (
    "sqlalchemy",
    "sqlalchemy.engine",
    "sqlalchemy.pool",
    "httpcore",
    "httpx",
    "urllib3",
    "asyncio",
)


@pytest.fixture(autouse=True)
def _restore_logger_factory_state():
    """Snapshot/restore all global logging state arlogi's setup() mutates.

    Tests below force ``LoggerFactory._initialized = False`` and trigger a
    real re-init, which (a) may add handlers to the root logger, (b) sets the
    root logger level, and (c) pins levels on third-party child loggers.
    Restore all of it so no state leaks into other test files.
    """
    root = logging.getLogger()
    original_initialized = LoggerFactory._initialized
    original_root_level = root.level
    original_root_handlers = root.handlers[:]
    original_child_levels = {name: logging.getLogger(name).level for name in _MODULE_LEVEL_LOGGERS}
    yield
    LoggerFactory._initialized = original_initialized
    root.setLevel(original_root_level)
    for handler in root.handlers[:]:
        if handler not in original_root_handlers:
            root.removeHandler(handler)
    for handler in original_root_handlers:
        if handler not in root.handlers:
            root.addHandler(handler)
    for name, level in original_child_levels.items():
        logging.getLogger(name).setLevel(level)


class TestGetLogger:
    def test_returns_usable_logger(self):
        logger = get_logger("arodonata.test.module")
        assert hasattr(logger, "info")
        assert hasattr(logger, "debug")
        assert hasattr(logger, "warning")
        assert hasattr(logger, "error")

    def test_logger_name_matches_requested_name(self):
        logger = get_logger("arodonata.test.named")
        assert logger.name == "arodonata.test.named"

    def test_repeated_calls_return_same_underlying_logger(self):
        logger_a = get_logger("arodonata.test.same")
        logger_b = get_logger("arodonata.test.same")
        assert logger_a is logger_b

    def test_first_call_initializes_arlogi(self, monkeypatch):
        LoggerFactory._initialized = False
        setup_calls = []
        original_setup = LoggerFactory.setup

        def _spy_setup(*args, **kwargs):
            setup_calls.append(kwargs)
            return original_setup(*args, **kwargs)

        monkeypatch.setattr(LoggerFactory, "setup", classmethod(lambda cls, *a, **kw: _spy_setup(*a, **kw)))
        get_logger("arodonata.test.init")
        assert len(setup_calls) == 1

    def test_does_not_reinitialize_when_already_initialized(self, monkeypatch):
        LoggerFactory._initialized = True
        called = []
        monkeypatch.setattr(LoggerFactory, "setup", classmethod(lambda cls, *a, **kw: called.append(1)))
        get_logger("arodonata.test.already_init")
        assert called == []


class TestLogLevelConfiguration:
    def test_log_level_env_var_honored_on_first_init(self, monkeypatch):
        LoggerFactory._initialized = False
        monkeypatch.setenv("ARODONATA_LOG_LEVEL", "DEBUG")

        get_logger("arodonata.test.level_debug")

        assert logging.getLogger().level == logging.DEBUG

    def test_log_level_defaults_to_info_when_unset(self, monkeypatch):
        LoggerFactory._initialized = False
        monkeypatch.delenv("ARODONATA_LOG_LEVEL", raising=False)

        get_logger("arodonata.test.level_default")

        assert logging.getLogger().level == logging.INFO

    def test_module_levels_reduce_noise_for_external_libraries(self, monkeypatch):
        LoggerFactory._initialized = False
        monkeypatch.setenv("ARODONATA_LOG_LEVEL", "DEBUG")

        get_logger("arodonata.test.module_levels")

        assert logging.getLogger("sqlalchemy").level == logging.WARNING
        assert logging.getLogger("httpx").level == logging.WARNING

    def test_get_default_level_returns_debug_under_pytest(self):
        # arlogi resolves its fallback default via is_test_mode(): DEBUG when
        # running under a test runner, INFO otherwise. Under pytest this must
        # be DEBUG — arodonata overrides it anyway via ARODONATA_LOG_LEVEL on
        # first use, but pin the contract this suite relies on.
        assert get_default_level() == logging.DEBUG


class TestLazyLogger:
    def test_lazy_logger_returns_callable(self):
        log_fn = lazy_logger("arodonata.test.lazy")
        assert callable(log_fn)

    def test_lazy_logger_returns_logger_on_call(self):
        log_fn = lazy_logger("arodonata.test.lazy2")
        logger = log_fn()
        assert logger.name == "arodonata.test.lazy2"

    def test_lazy_logger_caches_instance(self):
        log_fn = lazy_logger("arodonata.test.lazy3")
        first = log_fn()
        second = log_fn()
        assert first is second

    def test_lazy_logger_does_not_create_logger_until_called(self, monkeypatch):
        created = []
        import arodonata.logger as logger_module

        original_get_logger = logger_module.get_logger

        def _spy(name):
            created.append(name)
            return original_get_logger(name)

        monkeypatch.setattr(logger_module, "get_logger", _spy)
        log_fn = logger_module.lazy_logger("arodonata.test.lazy4")
        assert created == []
        log_fn()
        assert created == ["arodonata.test.lazy4"]
