"""Runtime configuration for the TLS Certificate Checker.

Values come from environment variables and are validated once at startup.
Invalid configuration fails loudly: silently falling back to defaults hides
operator mistakes until they surface as mysterious timeouts in production.

Environment variables (seconds, plain decimal numbers; empty means unset):

    TLS_CHECKER_DNS_TIMEOUT            default 3.0
    TLS_CHECKER_CONNECT_TIMEOUT        default 5.0
    TLS_CHECKER_TLS_HANDSHAKE_TIMEOUT  default 5.0
    TLS_CHECKER_OVERALL_DEADLINE       default 10.0
"""

from __future__ import annotations

import math
import os
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


@dataclass(frozen=True)
class Settings:
    """Validated, immutable runtime configuration."""

    dns_timeout_seconds: float = DEFAULT_DNS_TIMEOUT_SECONDS
    connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT_SECONDS
    tls_handshake_timeout_seconds: float = DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECONDS
    overall_deadline_seconds: float = DEFAULT_OVERALL_DEADLINE_SECONDS

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
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings, read from the environment once."""
    return Settings.from_env()
