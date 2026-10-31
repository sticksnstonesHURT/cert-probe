"""FastAPI application entry point for the TLS Certificate Checker."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import Settings, get_settings
from app.schemas import CheckRequest, CheckResponse

APP_TITLE = "TLS Certificate Checker"
APP_VERSION = "0.1.0"

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application.

    ``settings`` is injectable so tests can supply validated configuration
    without touching the process environment. When omitted, configuration is
    read from the environment during startup.
    """

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        # Fail fast: invalid configuration must stop the process at boot, not
        # surface as a 500 on the first real request.
        resolved = settings if settings is not None else get_settings()
        application.state.settings = resolved
        logger.info("configuration loaded: %s", resolved)
        yield

    api = FastAPI(title=APP_TITLE, version=APP_VERSION, lifespan=lifespan)

    @api.get("/health")
    def health() -> dict[str, str]:
        """Liveness probe: the process is up and serving requests."""
        return {"status": "ok"}

    @api.post("/check")
    def check(payload: CheckRequest) -> CheckResponse:
        """Validate a hostname. Certificate inspection arrives in Phase 5."""
        return CheckResponse(hostname=payload.hostname)

    return api


app = create_app()
