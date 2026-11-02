"""Tests for POST /check request logging (Phase 7, Step 4)."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import logging as app_logging
from app.checker import CheckError, CheckResult
from app.config import Settings
from app.main import create_app

FIELDS = (
    "hostname",
    "outcome",
    "verified",
    "status",
    "duration_ms",
    "address_count",
    "dns_duration_ms",
    "method",
    "path",
)


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app(Settings())) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def _clean_logging() -> Iterator[None]:
    app_logging.reset_logging_for_tests()
    yield
    app_logging.reset_logging_for_tests()


def _request_logs(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.getMessage().startswith("check ")]


def _token(msg: str, key: str) -> str | None:
    prefix = f"{key}="
    for part in msg.split():
        if part.startswith(prefix):
            return part[len(prefix) :]
    return None


def _fake(**kwargs: object) -> CheckResult:
    return CheckResult(hostname="example.com", **kwargs)  # type: ignore[arg-type]


def test_success_logs_all_nine_fields(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="app.main")
    fake = _fake(
        verified=True,
        hostname_verified=True,
        address_count=2,
        dns_duration_ms=35,
    )
    with patch("app.main.check_certificate", return_value=fake):
        response = client.post("/check", json={"hostname": "example.com"})

    assert response.status_code == 200
    logs = _request_logs(caplog)
    assert len(logs) == 1
    msg = logs[0].getMessage()
    for field in FIELDS:
        assert f"{field}=" in msg
    assert "outcome=ok" in msg
    assert "verified=True" in msg
    assert "status=200" in msg
    assert "address_count=2" in msg
    assert "dns_duration_ms=35" in msg
    assert "method=POST" in msg
    assert "path=/check" in msg
    value = _token(msg, "duration_ms")
    assert value is not None and value.isdigit()


def test_field_order_is_stable(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="app.main")
    fake = _fake(
        verified=True,
        hostname_verified=True,
        address_count=1,
        dns_duration_ms=10,
    )
    with patch("app.main.check_certificate", return_value=fake):
        client.post("/check", json={"hostname": "example.com"})

    msg = _request_logs(caplog)[0].getMessage()
    positions = [msg.index(f"{field}=") for field in FIELDS]
    assert positions == sorted(positions), f"field order broken: {positions}"


def test_expired_certificate_logs_finding_not_failure(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="app.main")
    fake = _fake(
        verified=False,
        error=CheckError(kind="expired", message="certificate has expired"),
        address_count=1,
        dns_duration_ms=10,
    )
    with patch("app.main.check_certificate", return_value=fake):
        response = client.post("/check", json={"hostname": "example.com"})

    assert response.status_code == 200
    msg = _request_logs(caplog)[0].getMessage()
    assert "outcome=expired" in msg
    assert "verified=False" in msg
    assert "status=200" in msg


def test_dns_failure_logs_semantic_outcome(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="app.main")
    fake = _fake(
        verified=None,
        error=CheckError(kind="dns_failure", message="DNS resolution failed"),
        address_count=None,
        dns_duration_ms=120,
    )
    with patch("app.main.check_certificate", return_value=fake):
        response = client.post("/check", json={"hostname": "example.com"})

    assert response.status_code == 502
    msg = _request_logs(caplog)[0].getMessage()
    assert "outcome=dns_failure" in msg
    assert "verified=None" in msg
    assert "status=502" in msg
    assert "address_count=None" in msg
    assert "dns_duration_ms=120" in msg


@pytest.mark.parametrize("verified", [True, False, None])
def test_verified_tristate(
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
    verified: bool | None,
) -> None:
    caplog.set_level(logging.INFO, logger="app.main")
    error = None if verified else CheckError(kind="hostname_mismatch", message="x")
    fake = _fake(verified=verified, error=error)
    with patch("app.main.check_certificate", return_value=fake):
        client.post("/check", json={"hostname": "example.com"})
    assert f"verified={verified}" in _request_logs(caplog)[0].getMessage()


def test_duration_is_integer_milliseconds(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="app.main")
    fake = _fake(verified=True, hostname_verified=True)
    with patch("app.main.check_certificate", return_value=fake):
        client.post("/check", json={"hostname": "example.com"})
    value = _token(_request_logs(caplog)[0].getMessage(), "duration_ms")
    assert value is not None and value.isdigit()


def test_duration_uses_isolated_clock(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    """Seam only patches app.main._clock; shared time.monotonic stays real."""
    caplog.set_level(logging.INFO, logger="app.main")
    fake = _fake(verified=True, hostname_verified=True)
    with (
        patch("app.main.check_certificate", return_value=fake),
        patch("app.main._clock", side_effect=[100.0, 100.123]),
    ):
        client.post("/check", json={"hostname": "example.com"})
    assert "duration_ms=123" in _request_logs(caplog)[0].getMessage()


def test_no_request_log_on_422(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="app.main")
    response = client.post("/check", json={"hostname": "not a hostname"})
    assert response.status_code == 422
    assert _request_logs(caplog) == []


def test_no_request_log_when_checker_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="app.main")
    application = create_app(Settings())
    with TestClient(application, raise_server_exceptions=False) as c:
        with patch("app.main.check_certificate", side_effect=RuntimeError("boom")):
            response = c.post("/check", json={"hostname": "example.com"})
    assert response.status_code == 500
    assert _request_logs(caplog) == []


def test_private_fields_are_not_logged(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    """Privacy boundary: error message, cert subject/issuer and any IPs must
    not leak into the request log even when present on the CheckResult."""
    caplog.set_level(logging.INFO, logger="app.main")
    fake = _fake(
        verified=False,
        error=CheckError(kind="expired", message="SECRET_ERR_LEAK_1.2.3.4"),
        subject="CN=SECRET_SUBJECT_LEAK",
        issuer="O=SECRET_ISSUER_LEAK",
        address_count=2,
        dns_duration_ms=10,
    )
    with patch("app.main.check_certificate", return_value=fake):
        client.post("/check", json={"hostname": "example.com"})

    msg = _request_logs(caplog)[0].getMessage()
    for leak in (
        "SECRET_ERR_LEAK",
        "SECRET_SUBJECT_LEAK",
        "SECRET_ISSUER_LEAK",
        "1.2.3.4",
    ):
        assert leak not in msg, f"leaked {leak!r} into request log"
