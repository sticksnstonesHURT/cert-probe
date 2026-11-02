"""API tests using Starlette's TestClient (backed by httpx)."""

from __future__ import annotations

import socket
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import netguard
from app.checker import CheckError, CheckResult, ErrorKind
from app.config import ConfigError, Settings, get_settings
from app.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app(Settings())) as test_client:
        yield test_client


def test_health_returns_ok(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_check_returns_success_payload(client: TestClient) -> None:
    fake = CheckResult(
        hostname="example.com",
        verified=True,
        hostname_verified=True,
        subject="CN=example.com",
        issuer="CN=Test CA",
        not_before=datetime(2025, 1, 1, tzinfo=UTC),
        not_after=datetime(2035, 12, 31, 23, 59, 59, tzinfo=UTC),
        days_remaining=3000,
    )
    with patch("app.main.check_certificate", return_value=fake):
        response = client.post("/check", json={"hostname": "example.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is True
    assert body["hostname_verified"] is True
    assert body["error"] is None
    assert body["not_after"].startswith("2035-12-31")


def test_check_normalises_case_and_trailing_dot(client: TestClient) -> None:
    fake = CheckResult(hostname="example.com", verified=True, hostname_verified=True)
    with patch("app.main.check_certificate", return_value=fake) as mock_check:
        response = client.post("/check", json={"hostname": "Example.COM."})
    assert response.status_code == 200
    assert mock_check.call_args.args[0] == "example.com"


@pytest.mark.parametrize(
    "bad_hostname",
    ["", "https://example.com", "example.com:443", "127.0.0.1", "exa mple.com"],
)
def test_check_rejects_invalid_hostname(client: TestClient, bad_hostname: str) -> None:
    response = client.post("/check", json={"hostname": bad_hostname})
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["loc"] == ["body", "hostname"]


def test_check_rejects_unknown_fields(client: TestClient) -> None:
    assert client.post("/check", json={"hostname": "example.com", "port": 443}).status_code == 422


def test_check_rejects_non_string_hostname(client: TestClient) -> None:
    assert client.post("/check", json={"hostname": 2130706433}).status_code == 422


@pytest.mark.parametrize(
    ("kind", "expected_status"),
    [
        ("dns_failure", 502),
        ("dns_timeout", 504),
        ("dns_capacity_exceeded", 503),
        ("connection_failure", 502),
        ("blocked_destination", 403),
        ("connection_timeout", 504),
        ("tls_timeout", 504),
        ("expired", 200),
        ("hostname_mismatch", 200),
        ("certificate_invalid", 200),
        ("unknown_error", 500),
    ],
)
def test_error_kind_to_http_status(
    client: TestClient, kind: ErrorKind, expected_status: int
) -> None:
    fake = CheckResult(
        hostname="example.com", verified=False, error=CheckError(kind=kind, message="x")
    )
    with patch("app.main.check_certificate", return_value=fake):
        response = client.post("/check", json={"hostname": "example.com"})
    assert response.status_code == expected_status
    assert response.json()["error"]["kind"] == kind


def test_create_app_does_not_read_environment_until_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TLS_CHECKER_OVERALL_DEADLINE", "not-a-number")
    get_settings.cache_clear()
    try:
        create_app()  # must not raise here
    finally:
        get_settings.cache_clear()


def test_startup_fails_on_invalid_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TLS_CHECKER_OVERALL_DEADLINE", "not-a-number")
    get_settings.cache_clear()
    application = create_app()
    try:
        with pytest.raises(ConfigError):
            with TestClient(application):
                pytest.fail("lifespan startup completed despite invalid configuration")
    finally:
        get_settings.cache_clear()


def test_lifespan_stores_injected_settings() -> None:
    injected = Settings(connect_timeout_seconds=1.5)
    application = create_app(injected)
    with TestClient(application):
        assert application.state.settings is injected


# --- DNS executor lifecycle (process-level resource) ---


def test_lifespan_does_not_shut_down_dns_executor() -> None:
    """Executor is a process-level resource; lifespan teardown must not replace it.

    Canary: fails if anyone re-introduces shutdown_dns_executor (or any
    executor-identity-changing call) into the FastAPI lifespan.
    """
    netguard.reset_dns_executor_for_tests()
    original = netguard._executor
    try:
        with TestClient(create_app(Settings())):
            pass
        assert netguard._executor is original, (
            "lifespan teardown must not replace netguard._executor"
        )
    finally:
        netguard.reset_dns_executor_for_tests()


def test_check_endpoint_works_after_sequential_lifespans() -> None:
    """Endpoint and DNS executor remain usable after sequential lifespans."""
    netguard.reset_dns_executor_for_tests()
    fake = CheckResult(hostname="example.com", verified=True, hostname_verified=True)

    try:
        with TestClient(create_app(Settings())):
            pass

        with TestClient(create_app(Settings())) as client:
            with patch("app.main.check_certificate", return_value=fake):
                response = client.post("/check", json={"hostname": "example.com"})

        assert response.status_code == 200
        body = response.json()
        assert body["hostname"] == "example.com"
        assert body["verified"] is True
        assert body["error"] is None

        # Prove the shared DNS executor still accepts work after both lifespans.
        dns_result = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
        ]

        with patch("app.netguard.socket.getaddrinfo", return_value=dns_result):
            addresses = netguard.resolve_and_validate(
                "example.com",
                443,
                Settings(),
                time.monotonic() + 5,
            )

        assert len(addresses) == 1
        assert str(addresses[0].ip) == "93.184.216.34"

    finally:
        netguard.reset_dns_executor_for_tests()
