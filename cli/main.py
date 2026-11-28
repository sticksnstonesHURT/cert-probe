"""Entry point for the ``probe`` command-line interface.

A thin renderer over the shared inspection engine: parse and validate arguments,
call :func:`app.checker.check_certificate`, map the result to a documented exit
code, and render it. No TLS, hostname-validation, destination-policy or
response-mapping logic lives here — all four are shared with the API, so the two
surfaces cannot drift.

Contract (see ``docs/cli.md``):

* results go to stdout, diagnostics go to stderr;
* ``--json`` emits the same document the API returns, via ``app.render``;
* ``configure_logging()`` is deliberately not called, because it installs its
  handler on ``sys.stdout`` and would corrupt ``--json``;
* the hostname is validated before anything is printed or inspected, so no raw
  argument value ever reaches a log or a machine-readable stream.

Naming: the distribution is ``cert-probe``, the command is ``probe``.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from collections.abc import Sequence
from datetime import UTC, datetime

from app.checker import CERTIFICATE_ERROR_KINDS, CheckResult, ErrorKind, check_certificate
from app.config import ConfigError, Settings
from app.netguard import DestinationPolicy
from app.render import to_response
from app.schemas import CheckResponse, HostnameError, validate_hostname
from app.version import APP_VERSION

PROG = "probe"
DISTRIBUTION = "cert-probe"

# Exit codes (docs/cli.md section 7). Certificate findings are a definitive
# answer, not a failure, which is why they are distinct from network errors.
EXIT_VERIFIED = 0
EXIT_CERTIFICATE = 1
EXIT_USAGE = 2
EXIT_NETWORK = 3
EXIT_INTERNAL = 4

# Kinds that describe a destination or transport problem rather than the
# certificate itself. Together with CERTIFICATE_ERROR_KINDS and "unknown_error"
# this partitions ErrorKind; tests/test_cli.py pins the partition.
NETWORK_ERROR_KINDS: frozenset[ErrorKind] = frozenset(
    {
        "blocked_destination",
        "dns_failure",
        "dns_timeout",
        "dns_capacity_exceeded",
        "connection_failure",
        "connection_timeout",
        "tls_timeout",
    }
)

_LABEL_WIDTH = 17


def _port(value: str) -> int:
    """argparse type: a TCP port in 1-65535."""
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid port {value!r}: must be an integer") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"invalid port {port}: must be between 1 and 65535")
    return port


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the ``probe`` command."""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            f"Inspect the TLS certificate presented by a hostname ({DISTRIBUTION}). "
            "Exit codes: 0 verified, 1 certificate finding, 2 usage error, "
            "3 network or destination error, 4 unexpected internal error."
        ),
    )
    parser.add_argument("hostname", metavar="HOSTNAME", help="DNS hostname to inspect.")
    parser.add_argument(
        "--port",
        type=_port,
        default=443,
        metavar="N",
        help="TCP port to connect to (default: 443).",
    )
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help=(
            "Permit loopback, private, link-local and other non-global destinations. "
            "Use this when inspecting hosts on your own network."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json",
        help="Emit the API response document instead of human-readable text.",
    )
    parser.add_argument(
        "--dns-timeout",
        type=float,
        metavar="SECONDS",
        help="DNS resolution budget (default: $TLS_CHECKER_DNS_TIMEOUT or 3.0).",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        metavar="SECONDS",
        help="Per-address TCP connect budget (default: $TLS_CHECKER_CONNECT_TIMEOUT or 5.0).",
    )
    parser.add_argument(
        "--handshake-timeout",
        type=float,
        metavar="SECONDS",
        help=("TLS handshake budget (default: $TLS_CHECKER_TLS_HANDSHAKE_TIMEOUT or 5.0)."),
    )
    parser.add_argument(
        "--overall-deadline",
        type=float,
        metavar="SECONDS",
        help=(
            "Total budget for one inspection (default: $TLS_CHECKER_OVERALL_DEADLINE or "
            "10.0; must be at least the largest phase timeout and at most 30)."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROG} ({DISTRIBUTION}) {APP_VERSION}",
    )
    return parser


def exit_code_for(result: CheckResult) -> int:
    """Map an engine result to its documented exit code."""
    if result.error is None:
        return EXIT_VERIFIED
    kind = result.error.kind
    if kind in CERTIFICATE_ERROR_KINDS:
        return EXIT_CERTIFICATE
    if kind in NETWORK_ERROR_KINDS:
        return EXIT_NETWORK
    return EXIT_INTERNAL


def _tri_state(value: bool | None) -> str:
    """Render a tri-state flag; ``null`` means "not determined", not "no"."""
    if value is None:
        return "unknown"
    return "yes" if value else "no"


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def render_text(response: CheckResponse) -> str:
    """Render a result as human-readable text (docs/cli.md section 8.3)."""
    lines = [response.hostname, _field("verified", _tri_state(response.verified))]
    lines.append(_field("hostname", _tri_state(response.hostname_verified)))
    if response.subject is not None:
        lines.append(_field("subject", response.subject))
    if response.issuer is not None:
        lines.append(_field("issuer", response.issuer))
    if response.not_before is not None and response.not_after is not None:
        window = f"{_timestamp(response.not_before)} .. {_timestamp(response.not_after)}"
        lines.append(_field("valid", window))
    if response.days_remaining is not None:
        lines.append(_field("expires in", f"{response.days_remaining} days"))
    if response.error is not None:
        lines.append(_field("finding", response.error.kind))
        lines.append(_field("message", response.error.message))
    return "\n".join(lines)


def _field(label: str, value: str) -> str:
    return f"  {label + ':':<{_LABEL_WIDTH}}{value}"


def _settings_from_args(args: argparse.Namespace) -> Settings:
    """Build settings from the environment, with command-line overrides applied.

    ``Settings.__post_init__`` validates the result, so the CLI inherits exactly
    the same rules as the server (finite and positive, overall >= largest phase,
    overall <= 30) and any violation surfaces as a ``ConfigError``.

    The test-mode fields are copied from the environment unchanged: they fail
    closed there, and the CLI has no flag that could relax them.
    """
    base = Settings.from_env()
    return Settings(
        dns_timeout_seconds=(
            base.dns_timeout_seconds if args.dns_timeout is None else args.dns_timeout
        ),
        connect_timeout_seconds=(
            base.connect_timeout_seconds if args.connect_timeout is None else args.connect_timeout
        ),
        tls_handshake_timeout_seconds=(
            base.tls_handshake_timeout_seconds
            if args.handshake_timeout is None
            else args.handshake_timeout
        ),
        overall_deadline_seconds=(
            base.overall_deadline_seconds
            if args.overall_deadline is None
            else args.overall_deadline
        ),
        test_mode=base.test_mode,
        fixture_hostname=base.fixture_hostname,
        fixture_ip=base.fixture_ip,
        additional_ca_file=base.additional_ca_file,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    args = build_parser().parse_args(argv)

    try:
        hostname = validate_hostname(args.hostname)
    except HostnameError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        settings = _settings_from_args(args)
    except ConfigError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    policy = (
        DestinationPolicy.LOCAL_ALLOWED if args.allow_private else DestinationPolicy.PUBLIC_ONLY
    )
    try:
        result = check_certificate(hostname, settings, port=args.port, policy=policy)
    except Exception:
        # A crash must not be mistaken for a certificate finding (exit 1), so it
        # maps to the documented internal-error code. The traceback stays on
        # stderr for diagnosis.
        traceback.print_exc(file=sys.stderr)
        return EXIT_INTERNAL

    response = to_response(result)
    if args.json:
        # Compact separators match Starlette's JSONResponse, so this is the same
        # document the API sends and stays pipe-friendly for jq.
        document = response.model_dump(mode="json")
        print(json.dumps(document, separators=(",", ":"), ensure_ascii=False))
    else:
        print(render_text(response))
    return exit_code_for(result)
