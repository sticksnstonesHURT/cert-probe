"""FastAPI application entry point for the TLS Certificate Checker."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, cast

from fastapi import Depends, FastAPI, Request, Response

from app.checker import CheckResult, ErrorKind, check_certificate
from app.config import Settings, get_settings
from app.schemas import CheckErrorBody, CheckRequest, CheckResponse

APP_TITLE = "TLS Certificate Checker"
APP_VERSION = "0.1.0"
logger = logging.getLogger(__name__)
_STATUS_BY_KIND: dict[ErrorKind, int] = {
    "dns_failure": 502,
    "connection_failure": 502,
    "connection_timeout": 504,
    "tls_timeout": 504,
    "expired": 200,
    "hostname_mismatch": 200,
    "certificate_invalid": 200,
    "unknown_error": 500,
}


def _settings_from_app(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def _result_to_response(result: CheckResult) -> CheckResponse:
    error: CheckErrorBody | None = None
    if result.error is not None:
        error = CheckErrorBody(kind=result.error.kind, message=result.error.message)
    return CheckResponse(
        hostname=result.hostname,
        verified=result.verified,
        hostname_verified=result.hostname_verified,
        subject=result.subject,
        issuer=result.issuer,
        not_before=result.not_before,
        not_after=result.not_after,
        days_remaining=result.days_remaining,
        error=error,
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        resolved = settings if settings is not None else get_settings()
        application.state.settings = resolved
        logger.info("configuration loaded: %s", resolved)
        yield

    api = FastAPI(title=APP_TITLE, version=APP_VERSION, lifespan=lifespan)

    @api.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @api.post("/check", response_model=CheckResponse)
    def check(
        payload: CheckRequest,
        response: Response,
        resolved_settings: Annotated[Settings, Depends(_settings_from_app)],
    ) -> CheckResponse:
        result = check_certificate(payload.hostname, resolved_settings)
        if result.error is not None:
            response.status_code = _STATUS_BY_KIND.get(result.error.kind, 500)
        return _result_to_response(result)

    return api


app = create_app()
