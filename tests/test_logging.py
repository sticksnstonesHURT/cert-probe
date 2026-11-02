"""Tests for application logging configuration."""

from __future__ import annotations

import importlib
import logging
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app import logging as app_logging
from app.config import Settings
from app.main import create_app


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(app_logging.LOG_LEVEL_ENV, raising=False)
    app_logging.reset_logging_for_tests()
    yield
    app_logging.reset_logging_for_tests()


def _managed() -> list[logging.Handler]:
    return [
        h
        for h in logging.getLogger(app_logging.APP_LOGGER_NAME).handlers
        if getattr(h, app_logging._HANDLER_ATTR, False)
    ]


# --- function-level unit tests (10) ---


def test_default_level_is_info() -> None:
    assert app_logging.configure_logging() == logging.INFO
    assert logging.getLogger(app_logging.APP_LOGGER_NAME).level == logging.INFO


def test_explicit_level_overrides_default() -> None:
    assert app_logging.configure_logging("DEBUG") == logging.DEBUG


def test_env_level_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(app_logging.LOG_LEVEL_ENV, "warning")
    assert app_logging.configure_logging() == logging.WARNING


def test_explicit_beats_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(app_logging.LOG_LEVEL_ENV, "ERROR")
    assert app_logging.configure_logging("DEBUG") == logging.DEBUG


def test_blank_env_uses_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(app_logging.LOG_LEVEL_ENV, "   ")
    assert app_logging.configure_logging() == logging.INFO


def test_invalid_level_raises() -> None:
    with pytest.raises(ValueError, match="invalid log level"):
        app_logging.configure_logging("LOUD")


def test_idempotent_no_handler_duplication() -> None:
    app_logging.configure_logging()
    app_logging.configure_logging()
    app_logging.configure_logging("DEBUG")
    assert len(_managed()) == 1


def test_root_logger_untouched() -> None:
    before = list(logging.getLogger().handlers)
    app_logging.configure_logging()
    after = list(logging.getLogger().handlers)
    assert before == after


def test_handler_output_is_key_value() -> None:
    app_logging.configure_logging("INFO")
    handler = _managed()[0]
    record = logging.LogRecord(
        name="app.example",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hostname=example.com outcome=ok",
        args=(),
        exc_info=None,
    )
    output = handler.format(record)
    assert "level=INFO" in output
    assert "logger=app.example" in output
    assert "hostname=example.com" in output
    assert "ts=" in output and "Z level=INFO" in output


def test_exception_traceback_in_output() -> None:
    app_logging.configure_logging("INFO")
    handler = _managed()[0]
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        exc_info = __import__("sys").exc_info()
    record = logging.LogRecord(
        name="app.example",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="oops",
        args=(),
        exc_info=exc_info,
    )
    output = handler.format(record)
    assert "RuntimeError: boom" in output


# --- architectural tests (4) ---


def test_lifespan_configures_logging_and_logs_config(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Lifespan installs the handler and emits the config-loaded record."""
    with caplog.at_level(logging.INFO, logger=app_logging.APP_LOGGER_NAME):
        with TestClient(create_app(Settings())):
            pass
    assert len(_managed()) == 1
    messages = [r.getMessage() for r in caplog.records]
    assert any("configuration loaded" in m for m in messages), messages
    assert any("dns_timeout=" in m for m in messages), messages


def test_import_does_not_configure_logging() -> None:
    """Importing (or re-importing) app.main must not attach the handler."""
    import app.main as main_module

    importlib.reload(main_module)
    assert _managed() == []


def test_create_app_does_not_configure_logging() -> None:
    """The factory alone must not touch logging."""
    create_app(Settings())
    assert _managed() == []


def test_invalid_level_fails_at_lifespan_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bad TLS_CHECKER_LOG_LEVEL aborts lifespan startup, not factory construction."""
    monkeypatch.setenv(app_logging.LOG_LEVEL_ENV, "LOUD")
    application = create_app(Settings())  # construction must succeed
    with pytest.raises(ValueError, match="invalid log level"):
        with TestClient(application):
            pytest.fail("lifespan should have raised")
