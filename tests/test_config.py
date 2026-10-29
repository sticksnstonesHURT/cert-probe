"""Unit tests for environment-backed configuration and its invariants."""

import math
from dataclasses import FrozenInstanceError

import pytest

from app.config import (
    DEFAULT_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_DNS_TIMEOUT_SECONDS,
    DEFAULT_OVERALL_DEADLINE_SECONDS,
    DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECONDS,
    ENV_PREFIX,
    MAX_OVERALL_DEADLINE_SECONDS,
    ConfigError,
    Settings,
    get_settings,
)


def test_defaults_when_environment_is_empty() -> None:
    settings = Settings.from_env({})

    assert settings.dns_timeout_seconds == DEFAULT_DNS_TIMEOUT_SECONDS
    assert settings.connect_timeout_seconds == DEFAULT_CONNECT_TIMEOUT_SECONDS
    assert settings.tls_handshake_timeout_seconds == DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECONDS
    assert settings.overall_deadline_seconds == DEFAULT_OVERALL_DEADLINE_SECONDS


def test_environment_overrides_every_value() -> None:
    env = {
        f"{ENV_PREFIX}DNS_TIMEOUT": "1.5",
        f"{ENV_PREFIX}CONNECT_TIMEOUT": "2",
        f"{ENV_PREFIX}TLS_HANDSHAKE_TIMEOUT": "2.5",
        f"{ENV_PREFIX}OVERALL_DEADLINE": "8",
    }

    settings = Settings.from_env(env)

    assert settings == Settings(
        dns_timeout_seconds=1.5,
        connect_timeout_seconds=2.0,
        tls_handshake_timeout_seconds=2.5,
        overall_deadline_seconds=8.0,
    )


def test_process_environment_is_ignored_when_mapping_is_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}CONNECT_TIMEOUT", "1.0")

    settings = Settings.from_env({})

    assert settings.connect_timeout_seconds == DEFAULT_CONNECT_TIMEOUT_SECONDS


@pytest.mark.parametrize("raw", ["", "   "])
def test_blank_value_falls_back_to_default(raw: str) -> None:
    settings = Settings.from_env({f"{ENV_PREFIX}CONNECT_TIMEOUT": raw})

    assert settings.connect_timeout_seconds == DEFAULT_CONNECT_TIMEOUT_SECONDS


@pytest.mark.parametrize("raw", ["abc", "5s", "true"])
def test_non_numeric_value_is_rejected(raw: str) -> None:
    with pytest.raises(ConfigError, match=f"{ENV_PREFIX}CONNECT_TIMEOUT"):
        Settings.from_env({f"{ENV_PREFIX}CONNECT_TIMEOUT": raw})


@pytest.mark.parametrize("raw", ["0", "-1", "nan", "inf", "-inf"])
def test_non_positive_or_non_finite_value_is_rejected(raw: str) -> None:
    with pytest.raises(ConfigError, match="connect_timeout_seconds"):
        Settings.from_env({f"{ENV_PREFIX}CONNECT_TIMEOUT": raw})


@pytest.mark.parametrize("value", [0.0, -1.0, math.nan, math.inf])
def test_direct_construction_is_validated(value: float) -> None:
    with pytest.raises(ConfigError, match="dns_timeout_seconds"):
        Settings(dns_timeout_seconds=value)


def test_overall_deadline_must_cover_the_largest_phase() -> None:
    with pytest.raises(ConfigError, match="overall_deadline_seconds"):
        Settings(overall_deadline_seconds=2.0)


def test_overall_deadline_must_respect_the_hard_cap() -> None:
    with pytest.raises(ConfigError, match="must not exceed"):
        Settings(
            dns_timeout_seconds=1.0,
            connect_timeout_seconds=1.0,
            tls_handshake_timeout_seconds=1.0,
            overall_deadline_seconds=MAX_OVERALL_DEADLINE_SECONDS + 1.0,
        )


def test_settings_are_immutable() -> None:
    settings = Settings()
    field = "connect_timeout_seconds"

    with pytest.raises(FrozenInstanceError):
        setattr(settings, field, 1.0)


def test_get_settings_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}CONNECT_TIMEOUT", "2.5")
    get_settings.cache_clear()
    try:
        first = get_settings()
        second = get_settings()
    finally:
        get_settings.cache_clear()

    assert first is second
    assert first.connect_timeout_seconds == 2.5
