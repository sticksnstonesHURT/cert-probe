"""TLS certificate inspection: stdlib ssl/socket plus cryptography.
Verification policy: the primary connection uses ``create_default_context()``
(chain + hostname verified by OpenSSL). Only if verification fails do we open a
second, explicitly UNVERIFIED connection to fetch the peer certificate in DER
form for metadata reporting. That second connection proves nothing about
identity — it can be steered by a man-in-the-middle — so its output never
influences ``verified`` or ``hostname_verified``.
Timeouts: each network step is bounded by ``min(phase_timeout, remaining)``
against a monotonic overall deadline recomputed before every call.
``getaddrinfo`` accepts no timeout — DNS remains unbounded until Phase 6.
SECURITY: no destination filtering here. ``app.netguard`` (Phase 6) is required
before the service leaves loopback.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from cryptography import x509

from app.config import Settings

DEFAULT_TLS_PORT = 443
_MIN_TLS_VERSION = ssl.TLSVersion.TLSv1_2
_VERIFY_CODE_EXPIRED = 10
_VERIFY_CODE_HOSTNAME_MISMATCH = 62
ErrorKind = Literal[
    "dns_failure",
    "connection_failure",
    "connection_timeout",
    "tls_timeout",
    "expired",
    "hostname_mismatch",
    "certificate_invalid",
    "unknown_error",
]
_CERTIFICATE_ERROR_KINDS: frozenset[ErrorKind] = frozenset(
    {"expired", "hostname_mismatch", "certificate_invalid"}
)


@dataclass(frozen=True)
class CheckError:
    kind: ErrorKind
    message: str


@dataclass(frozen=True)
class CheckResult:
    hostname: str
    verified: bool | None = None
    hostname_verified: bool | None = None
    subject: str | None = None
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_remaining: int | None = None
    error: CheckError | None = None


@dataclass(frozen=True)
class CertificateInfo:
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    days_remaining: int


class _CheckFailure(Exception):
    def __init__(
        self,
        kind: ErrorKind,
        message: str,
        *,
        verified: bool | None = None,
        hostname_verified: bool | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        # Explicit override for cases where verification outcome is known
        # independently of the error kind. None = fall back to kind-based
        # inference in _failure_result.
        self.verified = verified
        self.hostname_verified = hostname_verified


def check_certificate(hostname: str, settings: Settings) -> CheckResult:
    deadline = time.monotonic() + settings.overall_deadline_seconds
    try:
        info = _collect_verified(hostname, settings, deadline)
    except _CheckFailure as failure:
        return _failure_result(hostname, failure, settings, deadline)
    return CheckResult(
        hostname=hostname,
        verified=True,
        hostname_verified=True,
        subject=info.subject,
        issuer=info.issuer,
        not_before=info.not_before,
        not_after=info.not_after,
        days_remaining=info.days_remaining,
    )


def _failure_result(
    hostname: str, failure: _CheckFailure, settings: Settings, deadline: float
) -> CheckResult:
    info: CertificateInfo | None = None
    if failure.kind in _CERTIFICATE_ERROR_KINDS:
        info = _inspect_unverified(hostname, settings, deadline)

    # Precedence: explicit override from the raise site, then kind inference.
    if failure.verified is not None:
        verified = failure.verified
    elif failure.kind in _CERTIFICATE_ERROR_KINDS:
        verified = False
    else:
        verified = None

    if failure.hostname_verified is not None:
        hostname_verified = failure.hostname_verified
    elif failure.kind == "hostname_mismatch":
        hostname_verified = False
    else:
        hostname_verified = None

    return CheckResult(
        hostname=hostname,
        verified=verified,
        hostname_verified=hostname_verified,
        subject=info.subject if info is not None else None,
        issuer=info.issuer if info is not None else None,
        not_before=info.not_before if info is not None else None,
        not_after=info.not_after if info is not None else None,
        days_remaining=info.days_remaining if info is not None else None,
        error=CheckError(kind=failure.kind, message=failure.message),
    )


def _phase_timeout(phase_seconds: float, deadline: float, label: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _CheckFailure("connection_timeout", f"overall deadline exceeded before {label}")
    return min(phase_seconds, remaining)


def _open_socket(hostname: str, settings: Settings, deadline: float) -> socket.socket:
    timeout = _phase_timeout(settings.connect_timeout_seconds, deadline, "TCP connection")
    try:
        return socket.create_connection((hostname, DEFAULT_TLS_PORT), timeout=timeout)
    except TimeoutError as exc:
        raise _CheckFailure(
            "connection_timeout",
            f"connection to {hostname}:{DEFAULT_TLS_PORT} timed out after {timeout:.3f}s",
        ) from exc
    except socket.gaierror as exc:
        raise _CheckFailure(
            "dns_failure", f"DNS resolution failed for {hostname!r}: {exc}"
        ) from exc
    except OSError as exc:
        raise _CheckFailure(
            "connection_failure",
            f"could not connect to {hostname}:{DEFAULT_TLS_PORT}: {exc}",
        ) from exc


def _collect_verified(hostname: str, settings: Settings, deadline: float) -> CertificateInfo:
    sock = _open_socket(hostname, settings, deadline)
    der: bytes | None = None
    try:
        sock.settimeout(
            _phase_timeout(settings.tls_handshake_timeout_seconds, deadline, "TLS handshake")
        )
        ctx = ssl.create_default_context()
        ctx.minimum_version = _MIN_TLS_VERSION
        try:
            with ctx.wrap_socket(sock, server_hostname=hostname) as wrapped:
                der = wrapped.getpeercert(binary_form=True)
        except ssl.SSLCertVerificationError as exc:
            raise _CheckFailure(_classify_cert_error(exc), _cert_error_message(exc)) from exc
        except TimeoutError as exc:
            raise _CheckFailure("tls_timeout", f"TLS handshake with {hostname} timed out") from exc
        except ssl.SSLError as exc:
            raise _CheckFailure(
                "connection_failure", f"TLS handshake with {hostname} failed: {exc}"
            ) from exc
        except OSError as exc:
            raise _CheckFailure(
                "connection_failure", f"TLS handshake with {hostname} failed: {exc}"
            ) from exc
    finally:
        sock.close()
    if not der:  # At this point wrap_socket returned successfully, so both certificate-chain and hostname verification passed.
        raise _CheckFailure(
            "unknown_error",
            "server did not present a certificate",
            verified=True,
            hostname_verified=True,
        )
    try:
        return _parse_der(der)
    except ValueError as exc:
        raise _CheckFailure(
            "unknown_error",
            f"could not parse peer certificate: {exc}",
            verified=True,
            hostname_verified=True,
        ) from exc


def _inspect_unverified(
    hostname: str, settings: Settings, deadline: float
) -> CertificateInfo | None:
    """Fetch metadata over an explicitly unverified connection. Never raises."""
    try:
        sock = _open_socket(hostname, settings, deadline)
    except _CheckFailure:
        return None
    der: bytes | None = None
    try:
        sock.settimeout(
            _phase_timeout(
                settings.tls_handshake_timeout_seconds,
                deadline,
                "inspection handshake",
            )
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False  # must precede CERT_NONE
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = _MIN_TLS_VERSION
        with ctx.wrap_socket(sock, server_hostname=hostname) as wrapped:
            der = wrapped.getpeercert(binary_form=True)
    except (_CheckFailure, ssl.SSLError, OSError, ValueError):
        return None
    finally:
        sock.close()
    if not der:
        return None
    try:
        return _parse_der(der)
    except ValueError:
        return None


def _parse_der(der: bytes) -> CertificateInfo:
    certificate = x509.load_der_x509_certificate(der)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    return CertificateInfo(
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        not_before=not_before,
        not_after=not_after,
        days_remaining=(not_after - datetime.now(UTC)).days,
    )


def _classify_cert_error(exc: ssl.SSLCertVerificationError) -> ErrorKind:
    code = getattr(exc, "verify_code", None)
    message = (getattr(exc, "verify_message", None) or str(exc) or "").lower()
    if code == _VERIFY_CODE_EXPIRED or "expired" in message:
        return "expired"
    if (
        code == _VERIFY_CODE_HOSTNAME_MISMATCH
        or "hostname mismatch" in message
        or "doesn't match" in message
    ):
        return "hostname_mismatch"
    return "certificate_invalid"


def _cert_error_message(exc: ssl.SSLCertVerificationError) -> str:
    base = str(exc) or exc.__class__.__name__
    detail = getattr(exc, "verify_message", None)
    if detail and detail not in base:
        return f"{base} ({detail})"
    return base
