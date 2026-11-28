"""Mapping from the inspection engine's result to the published response shape.

This is the single mapping from :class:`app.checker.CheckResult` to
:class:`app.schemas.CheckResponse`. Both surfaces call it: the API returns it
directly and the CLI serialises it for ``--json``. Because there is exactly one
implementation, the API document and the CLI output cannot drift apart.

Deliberately free of FastAPI imports. The CLI imports this module, and reaching
``app.main`` or ``app.errors`` from here would drag FastAPI, Starlette and
Uvicorn into the frozen CLI binary.
"""

from __future__ import annotations

from app.checker import CheckResult
from app.schemas import CheckErrorBody, CheckResponse


def to_response(result: CheckResult) -> CheckResponse:
    """Map an engine result to the API/CLI response document."""
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
