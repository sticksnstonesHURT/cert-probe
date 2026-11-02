"""Tests for the structured error envelope and global exception handlers."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.checker import CheckError, CheckResult
from app.config import Settings
from app.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app(Settings())) as c:
        yield c


@pytest.fixture
def client_no_raise() -> Iterator[TestClient]:
    with TestClient(create_app(Settings()), raise_server_exceptions=False) as c:
        yield c


# --- validation errors (422) ---


def test_validation_error_uses_envelope(client: TestClient) -> None:
    response = client.post("/check", json={"hostname": "not a hostname"})

    assert response.status_code == 422
    body = response.json()
    assert set(body.keys()) == {"error"}
    assert body["error"]["kind"] == "validation_error"
    assert isinstance(body["error"]["message"], str)
    details = body["error"]["details"]
    assert isinstance(details, list) and details
    first = details[0]
    assert set(first.keys()) == {"loc", "type", "msg"}
    assert first["loc"] == ["body", "hostname"]


def test_validation_error_strips_pydantic_prefix(client: TestClient) -> None:
    response = client.post("/check", json={"hostname": "https://example.com"})

    assert response.status_code == 422
    msg = response.json()["error"]["details"][0]["msg"]
    assert "Value error, " not in msg
    assert "URL scheme" in msg


def test_extra_field_produces_structured_detail(client: TestClient) -> None:
    response = client.post("/check", json={"hostname": "example.com", "port": 443})

    assert response.status_code == 422
    details = response.json()["error"]["details"]
    assert any(d["type"] == "extra_forbidden" for d in details)


# --- routing errors (404, 405) ---


def test_not_found_uses_envelope(client: TestClient) -> None:
    response = client.get("/does-not-exist")

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "kind": "not_found",
            "message": "resource not found",
            "details": None,
        }
    }


def test_method_not_allowed_uses_envelope(client: TestClient) -> None:
    response = client.get("/check")

    assert response.status_code == 405
    body = response.json()
    assert body["error"]["kind"] == "method_not_allowed"
    assert body["error"]["details"] is None


# --- unhandled exceptions (500) ---


def test_internal_error_hides_traceback(client_no_raise: TestClient) -> None:
    with patch("app.main.check_certificate", side_effect=RuntimeError("boom")):
        response = client_no_raise.post("/check", json={"hostname": "example.com"})

    assert response.status_code == 500
    body = response.json()
    assert body["error"]["kind"] == "internal_error"
    assert body["error"]["message"] == "internal server error; see server logs"
    assert body["error"]["details"] is None
    text = response.text
    assert "RuntimeError" not in text
    assert "boom" not in text
    assert "Traceback" not in text


def test_internal_error_is_logged(
    client_no_raise: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR, logger="app.errors")
    with patch("app.main.check_certificate", side_effect=RuntimeError("boom")):
        response = client_no_raise.post("/check", json={"hostname": "example.com"})

    assert response.status_code == 500
    assert any("unhandled exception" in r.message and "/check" in r.message for r in caplog.records)


# --- /check findings must keep their existing shape ---


def test_certificate_finding_keeps_check_response_shape(client: TestClient) -> None:
    fake = CheckResult(
        hostname="example.com",
        verified=False,
        error=CheckError(kind="expired", message="certificate has expired"),
    )
    with patch("app.main.check_certificate", return_value=fake):
        response = client.post("/check", json={"hostname": "example.com"})

    assert response.status_code == 200
    body = response.json()
    assert {"hostname", "verified", "error"}.issubset(body.keys())
    assert body["hostname"] == "example.com"
    assert body["error"]["kind"] == "expired"
    assert body["error"]["message"] == "certificate has expired"


def test_upstream_failure_keeps_check_response_shape(client: TestClient) -> None:
    fake = CheckResult(
        hostname="example.com",
        verified=None,
        error=CheckError(kind="dns_failure", message="DNS resolution failed"),
    )
    with patch("app.main.check_certificate", return_value=fake):
        response = client.post("/check", json={"hostname": "example.com"})

    assert response.status_code == 502
    body = response.json()
    assert body["hostname"] == "example.com"
    assert body["error"]["kind"] == "dns_failure"
