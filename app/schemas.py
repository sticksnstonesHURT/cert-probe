"""Request and response schemas for the TLS Certificate Checker API."""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_HOSTNAME_LENGTH = 253
MAX_LABEL_LENGTH = 63

# One DNS label: 1-63 characters, alphanumeric at both ends, hyphens inside only.
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class HostnameError(ValueError):
    """Raised when a hostname is not a syntactically valid DNS name."""


def validate_hostname(value: str) -> str:
    """Validate and normalise ``value`` as a DNS hostname.

    Normalisation (lower-casing, removal of a single trailing dot) happens
    *before* the 253-character limit is applied, so a 253-character name
    written with a trailing dot is accepted and returned in its 253-character
    form.

    Returns the normalised hostname and raises :class:`HostnameError`
    otherwise.

    This is syntax and shape validation only. Whether the name resolves, and
    whether it resolves to a permitted destination, is decided by
    ``app.netguard`` before any connection is made.
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


class CheckResponse(BaseModel):
    """Body of a successful ``POST /check``.

    Placeholder contract for Phase 4. Phase 5 replaces ``status`` with the
    certificate report.
    """

    model_config = ConfigDict(frozen=True)

    hostname: str
    status: Literal["not_implemented"] = "not_implemented"
