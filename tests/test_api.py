"""API-level tests using Starlette's TestClient (backed by httpx)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.config import ConfigError, Settings, get_settings
from app.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    """Client entered as a context manager so the lifespan startup hook runs."""
    with TestClient(create_app(Settings())) as test_client:
        yield test_client


def test_health_returns_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_check_returns_stub_for_valid_hostname(client: TestClient) -> None:
    response = client.post("/check", json={"hostname": "example.com"})

    assert response.status_code == 200
    assert response.json() == {"hostname": "example.com", "status": "not_implemented"}


def test_check_normalises_case_and_trailing_dot(client: TestClient) -> None:
    response = client.post("/check", json={"hostname": "Example.COM."})

    assert response.status_code == 200
    assert response.json()["hostname"] == "example.com"


@pytest.mark.parametrize(
    "bad_hostname",
    ["", "https://example.com", "example.com:443", "127.0.0.1", "exa mple.com"],
)
def test_check_rejects_invalid_hostname(client: TestClient, bad_hostname: str) -> None:
    response = client.post("/check", json={"hostname": bad_hostname})

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "hostname"]


def test_check_rejects_unknown_fields(client: TestClient) -> None:
    response = client.post("/check", json={"hostname": "example.com", "port": 443})

    assert response.status_code == 422


def test_check_rejects_non_string_hostname(client: TestClient) -> None:
    response = client.post("/check", json={"hostname": 2130706433})

    assert response.status_code == 422


def test_create_app_does_not_read_environment_until_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail-fast belongs to startup, not to import or construction."""
    monkeypatch.setenv("TLS_CHECKER_OVERALL_DEADLINE", "not-a-number")
    get_settings.cache_clear()
    try:
        create_app()  # must not raise here
    finally:
        get_settings.cache_clear()


def test_startup_fails_on_invalid_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The lifespan startup hook must reject invalid configuration.

    ``pytest.fail`` sits inside the client context: reaching it would prove
    startup succeeded, so the test only passes when the lifespan raises.
    """
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
    """The lifespan body really runs and publishes the resolved settings."""
    injected = Settings(connect_timeout_seconds=1.5)
    application = create_app(injected)

    with TestClient(application):
        assert application.state.settings is injected
