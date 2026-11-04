"""Unit tests for environment-backed configuration and its invariants."""

import math
from dataclasses import FrozenInstanceError
from pathlib import Path

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


# --- test-fixture configuration ---


def _fixture_env(**overrides: str) -> dict[str, str]:
    base = {
        f"{ENV_PREFIX}TEST_MODE": "1",
        f"{ENV_PREFIX}FIXTURE_HOSTNAME": "tls-fixture",
        f"{ENV_PREFIX}FIXTURE_IP": "172.30.0.10",
    }
    base.update({f"{ENV_PREFIX}{k}": v for k, v in overrides.items()})
    return base


def test_fixture_hostname_without_test_mode_rejected() -> None:
    with pytest.raises(ConfigError, match="require TLS_CHECKER_TEST_MODE=1"):
        Settings(fixture_hostname="tls-fixture", fixture_ip="172.30.0.10")


def test_fixture_ip_without_test_mode_rejected() -> None:
    with pytest.raises(ConfigError, match="require TLS_CHECKER_TEST_MODE=1"):
        Settings(fixture_ip="172.30.0.10")


def test_additional_ca_file_without_test_mode_rejected(tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("")
    with pytest.raises(ConfigError, match="require TLS_CHECKER_TEST_MODE=1"):
        Settings(additional_ca_file=str(ca))


def test_test_mode_without_fixture_hostname_rejected() -> None:
    with pytest.raises(ConfigError, match="requires TLS_CHECKER_FIXTURE_HOSTNAME"):
        Settings(test_mode=True, fixture_ip="172.30.0.10")


def test_test_mode_without_fixture_ip_rejected() -> None:
    with pytest.raises(ConfigError, match="requires TLS_CHECKER_FIXTURE_IP"):
        Settings(test_mode=True, fixture_hostname="tls-fixture")


@pytest.mark.parametrize("bad_ip", ["not-an-ip", "1.2.3", "example.com", ""])
def test_fixture_ip_invalid_literal_rejected(bad_ip: str) -> None:
    with pytest.raises(ConfigError, match="FIXTURE_IP"):
        Settings(test_mode=True, fixture_hostname="tls-fixture", fixture_ip=bad_ip)


@pytest.mark.parametrize(
    "bad_ip",
    [
        "8.8.8.8",  # public
        "127.0.0.1",  # loopback
        "169.254.169.254",  # link-local
        "100.64.0.1",  # CGNAT
        "192.0.2.1",  # TEST-NET-1
        "0.0.0.0",  # unspecified
    ],
)
def test_fixture_ip_non_rfc1918_rejected(bad_ip: str) -> None:
    with pytest.raises(ConfigError, match="RFC1918"):
        Settings(test_mode=True, fixture_hostname="tls-fixture", fixture_ip=bad_ip)


def test_fixture_ip_ipv6_rejected() -> None:
    with pytest.raises(ConfigError, match="must be an IPv4 address"):
        Settings(test_mode=True, fixture_hostname="tls-fixture", fixture_ip="fc00::1")


def test_additional_ca_file_missing_rejected() -> None:
    with pytest.raises(ConfigError, match="not a regular file"):
        Settings(
            test_mode=True,
            fixture_hostname="tls-fixture",
            fixture_ip="172.30.0.10",
            additional_ca_file="/nonexistent/ca.pem",
        )


def test_additional_ca_file_corrupt_pem_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pem"
    bad.write_text("this is not a PEM certificate\n")
    with pytest.raises(ConfigError, match="could not be loaded"):
        Settings(
            test_mode=True,
            fixture_hostname="tls-fixture",
            fixture_ip="172.30.0.10",
            additional_ca_file=str(bad),
        )


def test_valid_fixture_configuration_succeeds(tmp_path: Path) -> None:
    """A minimal valid CA bundle (self-signed) is accepted."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(__import__("datetime").datetime(2025, 1, 1))
        .not_valid_after(__import__("datetime").datetime(2035, 1, 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    settings = Settings(
        test_mode=True,
        fixture_hostname="tls-fixture",
        fixture_ip="172.30.0.10",
        additional_ca_file=str(ca_path),
    )
    assert settings.test_mode is True
    assert settings.fixture_hostname == "tls-fixture"
    assert settings.fixture_ip == "172.30.0.10"


def test_fixture_environment_roundtrip() -> None:
    settings = Settings.from_env(_fixture_env())
    assert settings.test_mode is True
    assert settings.fixture_hostname == "tls-fixture"
    assert settings.fixture_ip == "172.30.0.10"


@pytest.mark.parametrize("raw", ["true", "yes", "on", "0", "false"])
def test_test_mode_only_accepts_one(raw: str) -> None:
    env = _fixture_env()
    env[f"{ENV_PREFIX}TEST_MODE"] = raw
    with pytest.raises(ConfigError, match="TEST_MODE"):
        Settings.from_env(env)
