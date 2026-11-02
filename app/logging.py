"""Application logging configuration.

Manages only the ``app`` logger namespace. Root and uvicorn loggers are left
untouched: uvicorn owns its access/error logs, and pytest's ``caplog`` fixture
hooks the root logger, so we deliberately keep ``propagate=True`` -- records
reach both our handler and any host-installed root handler.

Plain-text key=value format per Phase 7 decision D3:

    ts=2025-01-15T10:00:00.123Z level=INFO logger=app.main msg=configuration loaded ...

Duplication guard: the installed handler is tagged with a private attribute;
``configure_logging()`` removes any previously-tagged handler before adding a
new one, so repeated lifespan entries yield one managed handler.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import UTC, datetime

APP_LOGGER_NAME = "app"
LOG_LEVEL_ENV = "TLS_CHECKER_LOG_LEVEL"
DEFAULT_LEVEL_NAME = "INFO"

_LEVELS: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "WARN": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
    "FATAL": logging.CRITICAL,
}

_HANDLER_ATTR = "_tls_checker_managed_handler"
_FORMAT = "ts=%(asctime)s level=%(levelname)s logger=%(name)s msg=%(message)s"


class _UTCFormatter(logging.Formatter):
    """Plain-text formatter with an ISO 8601 UTC timestamp."""

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        dt = datetime.fromtimestamp(record.created, tz=UTC)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _is_ours(handler: logging.Handler) -> bool:
    return bool(getattr(handler, _HANDLER_ATTR, False))


def _resolve_level(explicit: str | None) -> int:
    if explicit is not None:
        raw = explicit
    else:
        raw = os.environ.get(LOG_LEVEL_ENV, "")
        if not raw.strip():
            raw = DEFAULT_LEVEL_NAME
    normalised = raw.strip().upper()
    if normalised not in _LEVELS:
        raise ValueError(
            f"invalid log level {raw!r}; expected one of "
            "DEBUG, INFO, WARNING (or WARN), ERROR, CRITICAL (or FATAL)"
        )
    return _LEVELS[normalised]


def configure_logging(level: str | None = None) -> int:
    """Configure the ``app`` logger namespace. Idempotent. Returns the level."""
    resolved = _resolve_level(level)
    app_logger = logging.getLogger(APP_LOGGER_NAME)

    for handler in list(app_logger.handlers):
        if _is_ours(handler):
            app_logger.removeHandler(handler)
            handler.close()

    handler = logging.StreamHandler(sys.stdout)
    setattr(handler, _HANDLER_ATTR, True)
    handler.setFormatter(_UTCFormatter(_FORMAT))
    app_logger.addHandler(handler)
    app_logger.setLevel(resolved)
    return resolved


def reset_logging_for_tests() -> None:
    """Tests only: remove managed handlers and reset the app logger level."""
    app_logger = logging.getLogger(APP_LOGGER_NAME)
    for handler in list(app_logger.handlers):
        if _is_ours(handler):
            app_logger.removeHandler(handler)
            handler.close()
    app_logger.setLevel(logging.NOTSET)
