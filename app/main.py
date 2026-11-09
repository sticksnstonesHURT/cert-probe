"""FastAPI application entry point for the Cert Probe."""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, cast

from fastapi import Depends, FastAPI, Request, Response

from app.checker import CheckResult, ErrorKind, check_certificate
from app.config import Settings, get_settings
from app.errors import register_exception_handlers
from app.logging import configure_logging
from app.schemas import CheckErrorBody, CheckRequest, CheckResponse

APP_TITLE = "Cert Probe"
APP_VERSION = "0.1.0"
logger = logging.getLogger(__name__)
# Test seam: allows the request-duration test to patch an isolated
# symbol instead of the shared time.monotonic, which Starlette, AnyIO
# and httpx also call during the request lifecycle. Production path
# binds to the real clock and is behaviourally identical.
_clock = time.monotonic
_STATUS_BY_KIND: dict[ErrorKind, int] = {
    "dns_failure": 502,
    "dns_timeout": 504,
    "dns_capacity_exceeded": 503,
    "connection_failure": 502,
    "blocked_destination": 403,
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
        configure_logging()
        resolved = settings if settings is not None else get_settings()
        application.state.settings = resolved
        logger.info(
            "configuration loaded dns_timeout=%s connect_timeout=%s "
            "tls_handshake_timeout=%s overall_deadline=%s",
            resolved.dns_timeout_seconds,
            resolved.connect_timeout_seconds,
            resolved.tls_handshake_timeout_seconds,
            resolved.overall_deadline_seconds,
        )
        yield

    api = FastAPI(title=APP_TITLE, version=APP_VERSION, lifespan=lifespan)
    register_exception_handlers(api)

    @api.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @api.post("/check", response_model=CheckResponse)
    def check(
        payload: CheckRequest,
        response: Response,
        request: Request,
        resolved_settings: Annotated[Settings, Depends(_settings_from_app)],
    ) -> CheckResponse:
        started = _clock()
        result = check_certificate(payload.hostname, resolved_settings)
        duration_ms = int((_clock() - started) * 1000)
        if result.error is not None:
            response.status_code = _STATUS_BY_KIND.get(result.error.kind, 500)

        status_code = response.status_code or 200
        outcome = result.error.kind if result.error is not None else "ok"
        # One INFO line per /check invocation. Deliberately omits error.message,
        # resolved IP addresses, request body, client address and certificate
        # subject/issuer so operational logs stay machine-readable.
        logger.info(
            "check hostname=%s outcome=%s verified=%s status=%s duration_ms=%s "
            "address_count=%s dns_duration_ms=%s method=%s path=%s",
            result.hostname,
            outcome,
            result.verified,
            status_code,
            duration_ms,
            result.address_count,
            result.dns_duration_ms,
            request.method,
            request.url.path,
        )
        return _result_to_response(result)

    return api


app = create_app()
