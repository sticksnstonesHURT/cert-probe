"""Runtime configuration for the TLS Certificate Checker.

Values come from environment variables and are validated once at startup.
Invalid configuration fails loudly: silently falling back to defaults hides
operator mistakes until they surface as mysterious timeouts in production.

Environment variables (seconds, plain decimal numbers; empty means unset):

    TLS_CHECKER_DNS_TIMEOUT            default 3.0
    TLS_CHECKER_CONNECT_TIMEOUT        default 5.0
    TLS_CHECKER_TLS_HANDSHAKE_TIMEOUT  default 5.0
    TLS_CHECKER_OVERALL_DEADLINE       default 10.0

Test-fixture variables (all optional; enabling any requires the trio):

    TLS_CHECKER_TEST_MODE              "1" enables; anything else is an error
    TLS_CHECKER_FIXTURE_HOSTNAME       exact hostname exempt from SSRF checks
    TLS_CHECKER_FIXTURE_IP             RFC1918 IPv4 the hostname must resolve to
    TLS_CHECKER_ADDITIONAL_CA_FILE     PEM file added to the trust store (test only)

Test mode fails closed: any fixture variable set without TEST_MODE=1 raises
ConfigError, and TEST_MODE=1 without both FIXTURE_HOSTNAME and FIXTURE_IP
raises ConfigError. Normal deployment sets none of these and the feature is
entirely absent.
"""

from __future__ import annotations

import ipaddress
import math
import os
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache

ENV_PREFIX = "TLS_CHECKER_"

DEFAULT_DNS_TIMEOUT_SECONDS = 3.0
DEFAULT_CONNECT_TIMEOUT_SECONDS = 5.0
DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECONDS = 5.0
DEFAULT_OVERALL_DEADLINE_SECONDS = 10.0

# Per-request wall-clock budget cap. Without it, a typo in
# TLS_CHECKER_OVERALL_DEADLINE could occupy a worker thread for a very long time.
MAX_OVERALL_DEADLINE_SECONDS = 30.0

# Permitted ranges for TLS_CHECKER_FIXTURE_IP. Deliberately RFC1918 only;
# loopback, link-local, CGNAT, TEST-NET, ULA and public IPs are all rejected.
_RFC1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


class ConfigError(ValueError):
    """Raised when a configuration value is malformed or inconsistent."""


def _read_seconds(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number of seconds, got {raw!r}") from exc


def _read_bool_flag(env: Mapping[str, str], name: str) -> bool:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return False
    if raw.strip() == "1":
        return True
    raise ConfigError(f"{name} must be '1' (enabled) or empty/unset (disabled); got {raw!r}")


def _read_str_opt(env: Mapping[str, str], name: str) -> str | None:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return None
    return raw.strip()


@dataclass(frozen=True)
class Settings:
    """Validated, immutable runtime configuration."""

    dns_timeout_seconds: float = DEFAULT_DNS_TIMEOUT_SECONDS
    connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT_SECONDS
    tls_handshake_timeout_seconds: float = DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECONDS
    overall_deadline_seconds: float = DEFAULT_OVERALL_DEADLINE_SECONDS
    test_mode: bool = False
    fixture_hostname: str | None = None
    fixture_ip: str | None = None
    additional_ca_file: str | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("dns_timeout_seconds", self.dns_timeout_seconds),
            ("connect_timeout_seconds", self.connect_timeout_seconds),
            ("tls_handshake_timeout_seconds", self.tls_handshake_timeout_seconds),
            ("overall_deadline_seconds", self.overall_deadline_seconds),
        ):
            if not math.isfinite(value) or value <= 0:
                raise ConfigError(
                    f"{name} must be a finite, positive number of seconds; got {value!r}"
                )

        largest_phase = max(
            self.dns_timeout_seconds,
            self.connect_timeout_seconds,
            self.tls_handshake_timeout_seconds,
        )
        if self.overall_deadline_seconds < largest_phase:
            raise ConfigError(
                "overall_deadline_seconds must be at least the largest phase timeout "
                f"({largest_phase}s); got {self.overall_deadline_seconds}s"
            )
        if self.overall_deadline_seconds > MAX_OVERALL_DEADLINE_SECONDS:
            raise ConfigError(
                f"overall_deadline_seconds must not exceed {MAX_OVERALL_DEADLINE_SECONDS}s; "
                f"got {self.overall_deadline_seconds}s"
            )

        # --- test-fixture validation ---
        any_fixture_field = (
            self.fixture_hostname is not None
            or self.fixture_ip is not None
            or self.additional_ca_file is not None
        )
        if any_fixture_field and not self.test_mode:
            raise ConfigError(
                "TLS_CHECKER_FIXTURE_HOSTNAME, TLS_CHECKER_FIXTURE_IP and "
                "TLS_CHECKER_ADDITIONAL_CA_FILE are test-only and require "
                "TLS_CHECKER_TEST_MODE=1"
            )
        if self.test_mode:
            if not self.fixture_hostname:
                raise ConfigError("TLS_CHECKER_TEST_MODE=1 requires TLS_CHECKER_FIXTURE_HOSTNAME")
            if not self.fixture_ip:
                raise ConfigError("TLS_CHECKER_TEST_MODE=1 requires TLS_CHECKER_FIXTURE_IP")
            try:
                fixture_addr = ipaddress.ip_address(self.fixture_ip)
            except ValueError as exc:
                raise ConfigError(
                    f"TLS_CHECKER_FIXTURE_IP is not a valid IP literal: {self.fixture_ip!r}"
                ) from exc
            if not isinstance(fixture_addr, ipaddress.IPv4Address):
                raise ConfigError(
                    f"TLS_CHECKER_FIXTURE_IP must be an IPv4 address; got {fixture_addr!r}"
                )
            if not any(fixture_addr in net for net in _RFC1918_NETWORKS):
                raise ConfigError(
                    "TLS_CHECKER_FIXTURE_IP must be within RFC1918 private space "
                    f"(10/8, 172.16/12 or 192.168/16); got {fixture_addr}"
                )
        if self.additional_ca_file is not None:
            _validate_ca_file(self.additional_ca_file)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        """Build settings from ``environ``, defaulting to ``os.environ``."""
        env = os.environ if environ is None else environ
        return cls(
            dns_timeout_seconds=_read_seconds(
                env, f"{ENV_PREFIX}DNS_TIMEOUT", DEFAULT_DNS_TIMEOUT_SECONDS
            ),
            connect_timeout_seconds=_read_seconds(
                env, f"{ENV_PREFIX}CONNECT_TIMEOUT", DEFAULT_CONNECT_TIMEOUT_SECONDS
            ),
            tls_handshake_timeout_seconds=_read_seconds(
                env,
                f"{ENV_PREFIX}TLS_HANDSHAKE_TIMEOUT",
                DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECONDS,
            ),
            overall_deadline_seconds=_read_seconds(
                env, f"{ENV_PREFIX}OVERALL_DEADLINE", DEFAULT_OVERALL_DEADLINE_SECONDS
            ),
            test_mode=_read_bool_flag(env, f"{ENV_PREFIX}TEST_MODE"),
            fixture_hostname=_read_str_opt(env, f"{ENV_PREFIX}FIXTURE_HOSTNAME"),
            fixture_ip=_read_str_opt(env, f"{ENV_PREFIX}FIXTURE_IP"),
            additional_ca_file=_read_str_opt(env, f"{ENV_PREFIX}ADDITIONAL_CA_FILE"),
        )


def _validate_ca_file(path: str) -> None:
    """Fail fast if the configured CA file is missing, unreadable, or not a PEM bundle."""
    if not os.path.isfile(path):
        raise ConfigError(f"TLS_CHECKER_ADDITIONAL_CA_FILE is not a regular file: {path!r}")
    probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        probe.load_verify_locations(cafile=path)
    except (ssl.SSLError, OSError) as exc:
        raise ConfigError(
            f"TLS_CHECKER_ADDITIONAL_CA_FILE could not be loaded as a CA bundle: {path!r}: {exc}"
        ) from exc


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings, read from the environment once."""
    return Settings.from_env()
