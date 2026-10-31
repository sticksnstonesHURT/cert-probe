"""Request and response schemas for the TLS Certificate Checker API."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.checker import ErrorKind

MAX_HOSTNAME_LENGTH = 253
MAX_LABEL_LENGTH = 63
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class HostnameError(ValueError):
    """Raised when a hostname is not a syntactically valid DNS name."""


def validate_hostname(value: str) -> str:
    """Validate and normalise ``value`` as a DNS hostname.
    Normalisation precedes the 253-character limit. Syntax only — destination
    policy lives in ``app.netguard`` (Phase 6).
    """
    if not value:
        raise HostnameError("hostname must not be empty")
    if value != value.strip():
        raise HostnameError("hostname must not have leading or trailing whitespace")
    normalised = value.lower()
    if normalised.endswith("."):
        normalised = normalised[:-1]
    if not normalised:
        raise HostnameError("hostname must not be empty")
    if len(normalised) > MAX_HOSTNAME_LENGTH:
        raise HostnameError(
            f"hostname must be at most {MAX_HOSTNAME_LENGTH} characters; got {len(normalised)}"
        )
    for marker, description in (("://", "a URL scheme"), ("/", "a path"), ("@", "userinfo")):
        if marker in normalised:
            raise HostnameError(f"hostname must not contain {description}")
    if ":" in normalised:
        raise HostnameError("hostname must not contain ':' (no ports, no IPv6 literals)")
    if "[" in normalised or "]" in normalised:
        raise HostnameError("hostname must not contain brackets")
    if any(character.isspace() for character in normalised):
        raise HostnameError("hostname must not contain whitespace")
    if not normalised.isascii():
        raise HostnameError("hostname must be ASCII; use the punycode (IDNA) form")
    try:
        ipaddress.ip_address(normalised)
    except ValueError:
        pass
    else:
        raise HostnameError(
            "hostname must be a DNS name, not an IP literal; IP addresses have no SNI "
            "and require a separate certificate-matching path"
        )
    labels = normalised.split(".")
    if any(label == "" for label in labels):
        raise HostnameError("hostname must not contain empty labels")
    for label in labels:
        if len(label) > MAX_LABEL_LENGTH:
            raise HostnameError(
                f"each label must be at most {MAX_LABEL_LENGTH} characters; "
                f"got {len(label)} in {label!r}"
            )
        if not _LABEL_RE.match(label):
            raise HostnameError(
                f"invalid label {label!r}: use letters, digits and hyphens, and do not "
                "start or end a label with a hyphen"
            )
    return normalised


class CheckRequest(BaseModel):
    """Body of ``POST /check``."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    hostname: str = Field(description="DNS hostname to inspect, for example 'example.com'.")

    @field_validator("hostname", mode="before")
    @classmethod
    def _validate_hostname(cls, value: object) -> str:
        if not isinstance(value, str):
            raise HostnameError(f"hostname must be a string; got {type(value).__name__}")
        return validate_hostname(value)


class CheckErrorBody(BaseModel):
    """Structured error in a ``CheckResponse``."""

    model_config = ConfigDict(frozen=True)
    kind: ErrorKind
    message: str


class CheckResponse(BaseModel):
    """Body of a ``POST /check`` response."""

    model_config = ConfigDict(frozen=True)
    hostname: str
    verified: bool | None = None
    hostname_verified: bool | None = None
    subject: str | None = None
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_remaining: int | None = None
    error: CheckErrorBody | None = None
