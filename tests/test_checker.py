"""Unit tests for TLS inspection: offline, deterministic, live tests opt-in."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from app import netguard
from app.checker import (
    CheckResult,
    _cert_error_message,
    _CheckFailure,
    _classify_cert_error,
    _connect_to_validated,
    _parse_der,
    _phase_timeout,
    check_certificate,
)
from app.config import Settings

PUBLIC_IP = "93.184.216.34"


def _build_der(not_before: datetime, not_after: datetime) -> bytes:
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, None)
    )
    return certificate.public_bytes(serialization.Encoding.DER)


VALID_DER = _build_der(datetime(2025, 1, 1, tzinfo=UTC), datetime(2035, 1, 1, tzinfo=UTC))
EXPIRED_DER = _build_der(datetime(2020, 1, 1, tzinfo=UTC), datetime(2021, 1, 1, tzinfo=UTC))


def _fast_settings() -> Settings:
    return Settings(
        dns_timeout_seconds=0.05,
        connect_timeout_seconds=0.1,
        tls_handshake_timeout_seconds=0.1,
        overall_deadline_seconds=0.5,
    )


def _validated(*ips: str) -> list[netguard.ValidatedAddress]:
    return [
        netguard.ValidatedAddress(
            family=socket.AF_INET,
            socktype=socket.SOCK_STREAM,
            proto=6,
            sockaddr=(ip, 443),
            ip=ipaddress.ip_address(ip),
        )
        for ip in ips
    ]


def _wrapped(der: bytes | None) -> MagicMock:
    wrapped = MagicMock()
    wrapped.__enter__ = MagicMock(return_value=wrapped)
    wrapped.__exit__ = MagicMock(return_value=None)
    wrapped.getpeercert.return_value = der
    return wrapped


def _cert_error(code: int, message: str) -> ssl.SSLCertVerificationError:
    try:
        exc = ssl.SSLCertVerificationError(1, code, message)
    except TypeError:
        exc = ssl.SSLCertVerificationError(1, f"certificate verify failed: {message}")
    for attr, value in (("verify_code", code), ("verify_message", message)):
        try:
            setattr(exc, attr, value)
        except (AttributeError, TypeError):
            pass
    return exc


def _verified_ctx(wrapped: MagicMock | None, error: Exception | None = None) -> MagicMock:
    ctx = MagicMock()
    if error is not None:
        ctx.wrap_socket.side_effect = error
    else:
        ctx.wrap_socket.return_value = wrapped
    return ctx


def _inspection_ctx(wrapped: MagicMock) -> MagicMock:
    ctx = MagicMock()
    ctx.wrap_socket.return_value = wrapped
    return ctx


def _run(
    *,
    addresses: list[netguard.ValidatedAddress] | None = None,
    resolve_error: Exception | None = None,
    connect_side_effect: list[object] | None = None,
    verified_ctx: MagicMock,
    inspection_ctx: MagicMock | None = None,
) -> CheckResult:
    if addresses is None:
        addresses = _validated(PUBLIC_IP)
    resolve_patch = (
        patch("app.checker.netguard.resolve_and_validate", side_effect=resolve_error)
        if resolve_error is not None
        else patch("app.checker.netguard.resolve_and_validate", return_value=addresses)
    )
    connect_patch = (
        patch("app.checker._connect_to_validated", side_effect=connect_side_effect)
        if connect_side_effect is not None
        else patch(
            "app.checker._connect_to_validated",
            side_effect=lambda *_a, **_kw: MagicMock(spec=socket.socket),
        )
    )
    inspection_patch = (
        patch("app.checker.ssl.SSLContext", return_value=inspection_ctx)
        if inspection_ctx is not None
        else patch("app.checker.ssl.SSLContext", return_value=MagicMock())
    )
    with (
        resolve_patch,
        connect_patch,
        patch("app.checker.ssl.create_default_context", return_value=verified_ctx),
        inspection_patch,
    ):
        return check_certificate("example.com", _fast_settings())


# --- success path ---


def test_success_parses_real_der() -> None:
    result = _run(verified_ctx=_verified_ctx(_wrapped(VALID_DER)))
    assert result.verified is True
    assert result.hostname_verified is True
    assert result.error is None
    assert result.subject is not None and "CN=example.com" in result.subject
    assert result.not_before == datetime(2025, 1, 1, tzinfo=UTC)
    assert result.not_after == datetime(2035, 1, 1, tzinfo=UTC)
    assert result.days_remaining is not None and result.days_remaining > 0


# --- verification failures trigger inspection ---


def test_expired_falls_back_to_inspection() -> None:
    result = _run(
        verified_ctx=_verified_ctx(None, _cert_error(10, "certificate has expired")),
        inspection_ctx=_inspection_ctx(_wrapped(EXPIRED_DER)),
    )
    assert result.verified is False
    assert result.error is not None and result.error.kind == "expired"
    assert result.subject is not None and "CN=example.com" in result.subject
    assert result.not_after == datetime(2021, 1, 1, tzinfo=UTC)
    assert result.hostname_verified is None


def test_hostname_mismatch_marks_hostname_not_verified() -> None:
    result = _run(
        verified_ctx=_verified_ctx(None, _cert_error(62, "Hostname mismatch")),
        inspection_ctx=_inspection_ctx(_wrapped(VALID_DER)),
    )
    assert result.verified is False
    assert result.hostname_verified is False
    assert result.error is not None and result.error.kind == "hostname_mismatch"


def test_certificate_invalid_also_inspects() -> None:
    result = _run(
        verified_ctx=_verified_ctx(None, _cert_error(18, "self-signed certificate")),
        inspection_ctx=_inspection_ctx(_wrapped(VALID_DER)),
    )
    assert result.error is not None and result.error.kind == "certificate_invalid"
    assert result.not_after is not None


def test_inspection_connection_disables_verification() -> None:
    inspection = _inspection_ctx(_wrapped(VALID_DER))
    _run(
        verified_ctx=_verified_ctx(None, _cert_error(10, "expired")),
        inspection_ctx=inspection,
    )
    assert inspection.check_hostname is False
    assert inspection.verify_mode == ssl.CERT_NONE
    assert inspection.wrap_socket.call_args.kwargs.get("server_hostname") == "example.com"


def test_inspection_connect_failure_preserves_original_error() -> None:
    """Primary cert verification fails; the fallback connect fails too.

    Assertion contract: the original ``expired`` error survives, ``verified``
    stays ``False`` (verification *did* run and failed), and metadata is
    absent because the inspection connection never delivered a certificate.
    """
    result = _run(
        verified_ctx=_verified_ctx(None, _cert_error(10, "certificate has expired")),
        connect_side_effect=[
            MagicMock(spec=socket.socket),  # primary: succeeds
            _CheckFailure("connection_failure", "inspection refused"),
        ],
    )
    assert result.verified is False
    assert result.error is not None and result.error.kind == "expired"
    assert result.subject is None
    assert result.not_after is None
    assert result.hostname_verified is None


def test_inspection_empty_der_preserves_original_error() -> None:
    result = _run(
        verified_ctx=_verified_ctx(None, _cert_error(10, "certificate has expired")),
        inspection_ctx=_inspection_ctx(_wrapped(None)),
    )
    assert result.verified is False
    assert result.error is not None and result.error.kind == "expired"
    assert result.not_after is None


# --- pre-connect failures (verified must be None) ---


def test_dns_failure_returns_verified_none() -> None:
    result = _run(
        resolve_error=netguard.DnsFailure("not found"),
        verified_ctx=_verified_ctx(None),
    )
    assert result.verified is None
    assert result.hostname_verified is None
    assert result.error is not None and result.error.kind == "dns_failure"
    assert result.subject is None


def test_dns_timeout_returns_verified_none() -> None:
    result = _run(
        resolve_error=netguard.DnsTimeout("timed out"),
        verified_ctx=_verified_ctx(None),
    )
    assert result.verified is None
    assert result.error is not None and result.error.kind == "dns_timeout"


def test_dns_capacity_exceeded_returns_verified_none() -> None:
    result = _run(
        resolve_error=netguard.DnsCapacityExceeded("at capacity"),
        verified_ctx=_verified_ctx(None),
    )
    assert result.verified is None
    assert result.hostname_verified is None
    assert result.error is not None and result.error.kind == "dns_capacity_exceeded"


def test_blocked_destination_returns_verified_none() -> None:
    result = _run(
        resolve_error=netguard.BlockedDestination(
            "example.com", ipaddress.ip_address("10.0.0.1"), "private"
        ),
        verified_ctx=_verified_ctx(None),
    )
    assert result.verified is None
    assert result.hostname_verified is None
    assert result.error is not None and result.error.kind == "blocked_destination"
    assert "private" in result.error.message


def test_connection_refused_returns_verified_none() -> None:
    result = _run(
        verified_ctx=_verified_ctx(None),
        connect_side_effect=[_CheckFailure("connection_failure", "refused")],
    )
    assert result.verified is None
    assert result.error is not None and result.error.kind == "connection_failure"


def test_connect_timeout_returns_verified_none() -> None:
    result = _run(
        verified_ctx=_verified_ctx(None),
        connect_side_effect=[_CheckFailure("connection_timeout", "timed out")],
    )
    assert result.verified is None
    assert result.error is not None and result.error.kind == "connection_timeout"


def test_tls_handshake_timeout_returns_verified_none() -> None:
    result = _run(
        verified_ctx=_verified_ctx(None, TimeoutError("handshake timed out")),
    )
    assert result.verified is None
    assert result.error is not None and result.error.kind == "tls_timeout"


def test_tls_other_error_returns_verified_none() -> None:
    result = _run(
        verified_ctx=_verified_ctx(None, ssl.SSLError("protocol version")),
    )
    assert result.verified is None
    assert result.error is not None and result.error.kind == "connection_failure"


# --- post-verification failures (verified must be True) ---


def test_post_verification_missing_der_reports_verified_true() -> None:
    result = _run(verified_ctx=_verified_ctx(_wrapped(None)))
    assert result.verified is True
    assert result.hostname_verified is True
    assert result.error is not None and result.error.kind == "unknown_error"


def test_post_verification_parse_error_reports_verified_true() -> None:
    result = _run(verified_ctx=_verified_ctx(_wrapped(b"not a certificate")))
    assert result.verified is True
    assert result.hostname_verified is True
    assert result.error is not None and result.error.kind == "unknown_error"
    assert result.subject is None


# --- multiple addresses ---


def test_multiple_addresses_first_wins() -> None:
    addresses = _validated("1.1.1.1", "8.8.8.8")
    result = _run(addresses=addresses, verified_ctx=_verified_ctx(_wrapped(VALID_DER)))
    assert result.verified is True


def test_all_addresses_fail_aggregates_error() -> None:
    addresses = _validated("1.1.1.1", "8.8.8.8")
    result = _run(
        addresses=addresses,
        verified_ctx=_verified_ctx(None),
        connect_side_effect=[
            _CheckFailure("connection_failure", "addr1 refused"),
            _CheckFailure("connection_failure", "addr2 refused"),
        ],
    )
    assert result.error is not None and result.error.kind == "connection_failure"
    assert "all 2" in result.error.message


# --- TOCTOU invariants ---


def test_connect_uses_validated_sockaddr_not_hostname() -> None:
    mock_sock = MagicMock(spec=socket.socket)
    address = _validated("93.184.216.34")[0]
    with patch("app.checker.socket.socket", return_value=mock_sock):
        _connect_to_validated(address, _fast_settings(), deadline=time.monotonic() + 10)
    mock_sock.connect.assert_called_once_with(("93.184.216.34", 443))


def test_connect_does_not_re_resolve() -> None:
    mock_sock = MagicMock(spec=socket.socket)
    address = _validated("93.184.216.34")[0]
    with (
        patch("app.checker.socket.socket", return_value=mock_sock),
        patch("app.netguard.socket.getaddrinfo") as mock_gai,
    ):
        _connect_to_validated(address, _fast_settings(), deadline=time.monotonic() + 10)
    mock_gai.assert_not_called()


# --- deadline semantics ---


def test_overall_deadline_exhausted_before_connect() -> None:
    with (
        patch(
            "app.checker.netguard.resolve_and_validate",
            return_value=_validated(PUBLIC_IP),
        ),
        patch("app.checker.time.monotonic", side_effect=[0.0, 1000.0]),
    ):
        result = check_certificate("example.com", _fast_settings())

    assert result.error is not None
    assert result.error.kind == "connection_timeout"
    assert "overall deadline" in result.error.message


def test_phase_timeout_shrinks_to_remaining_budget() -> None:
    with patch("app.checker.time.monotonic", return_value=100.0):
        budget = _phase_timeout(5.0, 101.0, "TCP connection")
    assert budget == pytest.approx(1.0, abs=1e-6)


def test_phase_timeout_raises_when_deadline_passed() -> None:
    with patch("app.checker.time.monotonic", return_value=100.0):
        with pytest.raises(_CheckFailure):
            _phase_timeout(5.0, 50.0, "TCP connection")


# --- parsing and classification ---


def test_parse_der_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        _parse_der(b"not a certificate")


@pytest.mark.parametrize(
    ("code", "message", "expected"),
    [
        (10, "certificate has expired", "expired"),
        (62, "Hostname mismatch, certificate is not valid for 'x'", "hostname_mismatch"),
        (18, "self-signed certificate", "certificate_invalid"),
    ],
)
def test_error_classification(code: int, message: str, expected: str) -> None:
    assert _classify_cert_error(_cert_error(code, message)) == expected


def test_classification_by_message_without_code() -> None:
    exc = ssl.SSLCertVerificationError(1, "certificate verify failed: hostname mismatch")
    assert _classify_cert_error(exc) == "hostname_mismatch"


def test_error_message_includes_verify_message() -> None:
    message = _cert_error_message(_cert_error(10, "certificate has expired"))
    assert "certificate has expired" in message


# --- live (opt-in, excluded by default) ---


@pytest.mark.live
def test_live_valid_certificate() -> None:
    result = check_certificate("example.com", Settings())
    assert result.error is None and result.verified is True
    assert result.hostname_verified is True
    assert result.days_remaining is not None and result.days_remaining > 0


@pytest.mark.live
def test_live_expired_certificate() -> None:
    result = check_certificate("expired.badssl.com", Settings())
    assert result.verified is False
    assert result.error is not None
    assert result.error.kind in ("expired", "certificate_invalid", "hostname_mismatch")
    assert result.subject is not None
    assert result.not_after is not None
