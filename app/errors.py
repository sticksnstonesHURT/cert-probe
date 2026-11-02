"""Structured error envelope and global exception handlers.

Certificate/DNS/connection findings from /check keep the ``CheckResponse``
shape and are NOT wrapped in this envelope: those are successful API
responses that *report* a finding, not protocol-level errors.

This module covers protocol errors only:

    request validation (422)  -> kind="validation_error"
    routing             (404) -> kind="not_found"
    routing             (405) -> kind="method_not_allowed"
    other HTTPException       -> kind="http_error"
    unhandled exception (500) -> kind="internal_error"

Validation failures carry per-field detail; every other kind has
``details = null``. The unhandled-exception message is generic in the
response and full-fidelity (with traceback) in the server log.
"""

from __future__ import annotations

import logging
from typing import Literal, cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ExceptionHandler

logger = logging.getLogger("app.errors")

ErrorEnvelopeKind = Literal[
    "validation_error",
    "not_found",
    "method_not_allowed",
    "http_error",
    "internal_error",
]

INTERNAL_ERROR_MESSAGE = "internal server error; see server logs"
VALIDATION_ERROR_MESSAGE = "request body is invalid"
NOT_FOUND_MESSAGE = "resource not found"
METHOD_NOT_ALLOWED_MESSAGE = "method not allowed"
GENERIC_HTTP_ERROR_MESSAGE = "request failed"

# Pydantic prefixes custom validator messages with "Value error, ".
_PYDANTIC_VALUE_PREFIX = "Value error, "


class ValidationDetail(BaseModel):
    """One field-level validation failure."""

    model_config = ConfigDict(frozen=True)

    loc: list[str | int]
    type: str
    msg: str


class ErrorBody(BaseModel):
    """Body of the error envelope."""

    model_config = ConfigDict(frozen=True)

    kind: ErrorEnvelopeKind
    message: str
    details: list[ValidationDetail] | None = None


class ErrorEnvelope(BaseModel):
    """Top-level error response shape for non-/check errors."""

    model_config = ConfigDict(frozen=True)

    error: ErrorBody


def _strip_pydantic_value_prefix(message: str) -> str:
    if message.startswith(_PYDANTIC_VALUE_PREFIX):
        return message[len(_PYDANTIC_VALUE_PREFIX) :]
    return message


def _envelope_response(
    status_code: int,
    kind: ErrorEnvelopeKind,
    message: str,
    details: list[ValidationDetail] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    payload = ErrorEnvelope(
        error=ErrorBody(kind=kind, message=message, details=details)
    ).model_dump(mode="json")
    return JSONResponse(status_code=status_code, content=payload, headers=headers)


async def _handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    details = [
        ValidationDetail(
            loc=list(error.get("loc", ())),
            type=str(error.get("type", "unknown")),
            msg=_strip_pydantic_value_prefix(str(error.get("msg", ""))),
        )
        for error in exc.errors()
    ]
    return _envelope_response(
        status_code=422,
        kind="validation_error",
        message=VALIDATION_ERROR_MESSAGE,
        details=details,
    )


async def _handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    headers = getattr(exc, "headers", None)
    if exc.status_code == 404:
        return _envelope_response(
            status_code=404, kind="not_found", message=NOT_FOUND_MESSAGE, headers=headers
        )
    if exc.status_code == 405:
        return _envelope_response(
            status_code=405,
            kind="method_not_allowed",
            message=METHOD_NOT_ALLOWED_MESSAGE,
            headers=headers,
        )
    detail = exc.detail if isinstance(exc.detail, str) and exc.detail else None
    return _envelope_response(
        status_code=exc.status_code,
        kind="http_error",
        message=detail or GENERIC_HTTP_ERROR_MESSAGE,
        headers=headers,
    )


async def _handle_unexpected_exception(request: Request, exc: Exception) -> JSONResponse:
    # logger.exception relies on sys.exc_info(); Starlette invokes this handler
    # from inside its except block, so the active exception is the one we want.
    logger.exception(
        "unhandled exception on %s %s",
        request.method,
        request.url.path,
    )
    return _envelope_response(
        status_code=500, kind="internal_error", message=INTERNAL_ERROR_MESSAGE
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Install the structured error handlers on ``app``."""
    # Starlette's dispatcher calls each handler only with the registered
    # exception type (or a subclass), so the narrowed parameter types are
    # safe at runtime; the casts satisfy mypy's callable-contravariance
    # check without widening parameters to bare ``Exception``.
    app.add_exception_handler(
        RequestValidationError,
        cast(ExceptionHandler, _handle_validation_error),
    )
    app.add_exception_handler(
        StarletteHTTPException,
        cast(ExceptionHandler, _handle_http_exception),
    )
    app.add_exception_handler(Exception, _handle_unexpected_exception)
