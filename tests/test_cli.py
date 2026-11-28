"""Unit tests for the ``probe`` CLI: offline, deterministic, in-process.

Tests call ``cli.main.main()`` directly rather than the installed console
script. The script exists in the CI virtualenv (``uv sync --locked`` installs
the project) but not in the container image, which is built with
``--no-install-project``; a subprocess-based test would pass in CI and fail
everywhere else.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from typing import get_args
from unittest.mock import patch

import pytest

from app.checker import CheckError, CheckResult, ErrorKind
from app.netguard import DestinationPolicy
from app.render import to_response
from app.version import APP_VERSION
from cli.main import (
    EXIT_CERTIFICATE,
    EXIT_INTERNAL,
    EXIT_NETWORK,
    EXIT_USAGE,
    EXIT_VERIFIED,
    exit_code_for,
    main,
    render_text,
)

VERIFIED = CheckResult(
    hostname="example.com",
    verified=True,
    hostname_verified=True,
    subject="CN=example.com",
    issuer="CN=Example CA",
    not_before=datetime(2025, 1, 1, tzinfo=UTC),
    not_after=datetime(2035, 1, 1, tzinfo=UTC),
    days_remaining=3283,
)

# The documented exit-code table (docs/cli.md section 7). Kept explicit rather
# than derived, so a change in behaviour must be a deliberate edit here too.
EXPECTED_EXIT: dict[ErrorKind, int] = {
    "expired": EXIT_CERTIFICATE,
    "hostname_mismatch": EXIT_CERTIFICATE,
    "certificate_invalid": EXIT_CERTIFICATE,
    "blocked_destination": EXIT_NETWORK,
    "dns_failure": EXIT_NETWORK,
    "dns_timeout": EXIT_NETWORK,
    "dns_capacity_exceeded": EXIT_NETWORK,
    "connection_failure": EXIT_NETWORK,
    "connection_timeout": EXIT_NETWORK,
    "tls_timeout": EXIT_NETWORK,
    "unknown_error": EXIT_INTERNAL,
}


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    """Run ``main()`` in-process, turning argparse's ``SystemExit`` into a code."""
    try:
        code = main(argv)
    except SystemExit as exc:  # --help, --version and usage errors
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _finding(kind: ErrorKind) -> CheckResult:
    return CheckResult(
        hostname="example.com",
        error=CheckError(kind=kind, message=f"stub {kind}"),
    )


# --- completeness (F5) ---


def test_exit_table_covers_every_error_kind() -> None:
    """Adding an ErrorKind must force a decision about its exit code."""
    assert set(EXPECTED_EXIT) == set(get_args(ErrorKind))


def test_every_kind_has_both_an_http_status_and_an_exit_code() -> None:
    from app.main import _STATUS_BY_KIND

    kinds = set(get_args(ErrorKind))
    assert set(_STATUS_BY_KIND) == kinds
    assert set(EXPECTED_EXIT) == kinds


@pytest.mark.parametrize("kind", get_args(ErrorKind))
def test_exit_code_for_matches_documented_table(kind: ErrorKind) -> None:
    assert exit_code_for(_finding(kind)) == EXPECTED_EXIT[kind]


@pytest.mark.parametrize("kind", get_args(ErrorKind))
def test_every_kind_drives_the_documented_process_exit_code(
    kind: ErrorKind, capsys: pytest.CaptureFixture[str]
) -> None:
    with patch("cli.main.check_certificate", return_value=_finding(kind)):
        code, out, err = _run(["example.com"], capsys)

    assert code == EXPECTED_EXIT[kind]
    assert out != "", "a finding is a result and belongs on stdout"
    assert err == ""


def test_verified_result_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("cli.main.check_certificate", return_value=VERIFIED):
        code, out, _ = _run(["example.com"], capsys)

    assert code == EXIT_VERIFIED
    assert "verified:        yes" in out


# --- version ---


def test_version_prints_command_and_distribution(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _run(["--version"], capsys)

    assert code == 0
    assert out.strip() == f"probe (cert-probe) {APP_VERSION}"
    assert err == ""


# --- usage errors ---


def test_missing_hostname_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _run([], capsys)

    assert code == EXIT_USAGE
    assert out == ""
    assert "hostname" in err.lower()


@pytest.mark.parametrize(
    "hostname",
    ["", "https://example.com", "example.com:443", "127.0.0.1", "exa mple.com", "*.example.com"],
)
def test_invalid_hostname_is_a_usage_error(
    hostname: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with patch("cli.main.check_certificate") as mock_check:
        code, out, err = _run([hostname], capsys)

    assert code == EXIT_USAGE
    assert out == ""
    assert err.startswith("probe: ")
    mock_check.assert_not_called()


@pytest.mark.parametrize("port", ["0", "65536", "abc", "-1"])
def test_invalid_port_is_a_usage_error(port: str, capsys: pytest.CaptureFixture[str]) -> None:
    with patch("cli.main.check_certificate") as mock_check:
        code, out, _ = _run(["example.com", "--port", port], capsys)

    assert code == EXIT_USAGE
    assert out == ""
    mock_check.assert_not_called()


# --- engine wiring ---


def test_hostname_is_normalised_before_inspection(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("cli.main.check_certificate", return_value=VERIFIED) as mock_check:
        code, _, _ = _run(["Example.COM."], capsys)

    assert code == EXIT_VERIFIED
    assert mock_check.call_args.args[0] == "example.com"


def test_default_port_is_443(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("cli.main.check_certificate", return_value=VERIFIED) as mock_check:
        _run(["example.com"], capsys)

    assert mock_check.call_args.kwargs["port"] == 443


def test_custom_port_is_forwarded(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("cli.main.check_certificate", return_value=VERIFIED) as mock_check:
        _run(["example.com", "--port", "8443"], capsys)

    assert mock_check.call_args.kwargs["port"] == 8443


def test_default_policy_is_public_only(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("cli.main.check_certificate", return_value=VERIFIED) as mock_check:
        _run(["example.com"], capsys)

    assert mock_check.call_args.kwargs["policy"] is DestinationPolicy.PUBLIC_ONLY


def test_allow_private_selects_local_allowed(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("cli.main.check_certificate", return_value=VERIFIED) as mock_check:
        _run(["example.com", "--allow-private"], capsys)

    assert mock_check.call_args.kwargs["policy"] is DestinationPolicy.LOCAL_ALLOWED


# --- timeouts ---


def test_timeout_flags_override_settings(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("cli.main.check_certificate", return_value=VERIFIED) as mock_check:
        _run(
            [
                "example.com",
                "--dns-timeout",
                "1.5",
                "--connect-timeout",
                "2.5",
                "--handshake-timeout",
                "3.5",
                "--overall-deadline",
                "20",
            ],
            capsys,
        )

    settings = mock_check.call_args.args[1]
    assert settings.dns_timeout_seconds == 1.5
    assert settings.connect_timeout_seconds == 2.5
    assert settings.tls_handshake_timeout_seconds == 3.5
    assert settings.overall_deadline_seconds == 20.0


def test_timeouts_default_to_environment_then_builtin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("TLS_CHECKER_OVERALL_DEADLINE", "12")
    with patch("cli.main.check_certificate", return_value=VERIFIED) as mock_check:
        _run(["example.com"], capsys)

    settings = mock_check.call_args.args[1]
    assert settings.overall_deadline_seconds == 12.0
    assert settings.connect_timeout_seconds == 5.0


def test_overall_deadline_below_largest_phase_is_a_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, err = _run(
        ["example.com", "--overall-deadline", "1", "--connect-timeout", "5"], capsys
    )

    assert code == EXIT_USAGE
    assert out == ""
    assert "at least the largest phase timeout" in err


def test_overall_deadline_above_cap_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = _run(["example.com", "--overall-deadline", "60"], capsys)

    assert code == EXIT_USAGE
    assert "must not exceed 30" in err


# --- output contract ---


def test_json_matches_the_shared_response_document(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("cli.main.check_certificate", return_value=VERIFIED):
        code, out, err = _run(["example.com", "--json"], capsys)

    assert code == EXIT_VERIFIED
    assert err == ""
    assert json.loads(out) == to_response(VERIFIED).model_dump(mode="json")


def test_json_is_a_single_compact_line(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("cli.main.check_certificate", return_value=VERIFIED):
        _, out, _ = _run(["example.com", "--json"], capsys)

    assert out.count("\n") == 1
    assert ", " not in out and '": ' not in out


def test_json_output_is_not_contaminated_by_diagnostics(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with patch("cli.main.check_certificate", return_value=_finding("expired")):
        code, out, err = _run(["example.com", "--json"], capsys)

    assert code == EXIT_CERTIFICATE
    assert err == ""
    document = json.loads(out)  # would raise if any diagnostic leaked into stdout
    assert document["error"]["kind"] == "expired"


def test_usage_errors_write_nothing_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _run(["not a hostname"], capsys)

    assert code == EXIT_USAGE
    assert out == ""
    assert err != ""


def test_render_text_shows_unknown_for_undetermined_flags() -> None:
    """``null`` means "not determined" and must not be rendered as "no"."""
    text = render_text(to_response(_finding("hostname_mismatch")))

    assert "verified:        unknown" in text
    assert "hostname:        unknown" in text
    assert "finding:         hostname_mismatch" in text


def test_render_text_shows_metadata_and_whole_days() -> None:
    expired = CheckResult(
        hostname="expired.example.com",
        verified=False,
        hostname_verified=False,
        subject="CN=expired.example.com",
        issuer="CN=Example CA",
        not_before=datetime(2020, 1, 1, tzinfo=UTC),
        not_after=datetime(2021, 1, 1, tzinfo=UTC),
        days_remaining=-1800,
        error=CheckError(kind="expired", message="certificate has expired"),
    )

    text = render_text(to_response(expired))

    assert "verified:        no" in text
    assert "expires in:      -1800 days" in text
    assert "valid:           2020-01-01T00:00:00Z .. 2021-01-01T00:00:00Z" in text
    assert "message:         certificate has expired" in text


# --- failure containment ---


def test_unexpected_exception_exits_four_not_one(capsys: pytest.CaptureFixture[str]) -> None:
    """A crash must never be mistaken for a certificate finding."""
    with patch("cli.main.check_certificate", side_effect=RuntimeError("boom")):
        code, out, err = _run(["example.com"], capsys)

    assert code == EXIT_INTERNAL
    assert out == ""
    assert "RuntimeError: boom" in err


def test_cli_import_graph_excludes_the_web_stack_and_app_logging() -> None:
    """The frozen binary must not carry FastAPI, and the CLI must not configure
    application logging (it writes to stdout, which would corrupt --json)."""
    forbidden = ("fastapi", "starlette", "uvicorn", "app.main", "app.errors", "app.logging")
    code = f"import sys, cli.main;print(','.join(m for m in {forbidden!r} if m in sys.modules))"

    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )

    assert result.stdout.strip() == ""
