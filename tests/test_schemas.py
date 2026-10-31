"""Unit tests for hostname validation, independent of FastAPI and Pydantic."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas import MAX_HOSTNAME_LENGTH, MAX_LABEL_LENGTH, CheckRequest, validate_hostname


def _valid_hostname_of_length(length: int) -> str:
    """Build a syntactically valid, lower-case hostname of exactly ``length``.

    Uses three maximum-length labels plus a final label sized so that
    ``length`` is hit exactly, counting the three separator dots.
    """
    labels = ["a" * MAX_LABEL_LENGTH, "b" * MAX_LABEL_LENGTH, "c" * MAX_LABEL_LENGTH]
    final_label_length = length - sum(len(label) for label in labels) - len(labels)
    labels.append("d" * final_label_length)
    hostname = ".".join(labels)
    assert len(hostname) == length, f"builder produced {len(hostname)} chars, wanted {length}"
    return hostname


@pytest.mark.parametrize(
    "raw",
    ["example.com", "sub.example.co.uk", "a.io", "x-y.example.com", "localhost", "example.com."],
)
def test_valid_hostnames_are_accepted(raw: str) -> None:
    assert validate_hostname(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        ("EXAMPLE.com", "example.com"),
        ("example.com.", "example.com"),
        ("Example.COM.", "example.com"),
    ],
)
def test_normalisation(raw: str, expected: str) -> None:
    assert validate_hostname(raw) == expected


def test_label_boundaries_are_accepted() -> None:
    longest_label = "a" * MAX_LABEL_LENGTH

    assert validate_hostname(f"{longest_label}.com") == f"{longest_label}.com"


def test_hostname_at_maximum_length_is_accepted() -> None:
    hostname = _valid_hostname_of_length(MAX_HOSTNAME_LENGTH)

    assert validate_hostname(hostname) == hostname


def test_hostname_at_maximum_length_with_trailing_dot_is_accepted() -> None:
    hostname = _valid_hostname_of_length(MAX_HOSTNAME_LENGTH)
    with_dot = hostname + "."

    assert len(with_dot) == MAX_HOSTNAME_LENGTH + 1
    assert validate_hostname(with_dot) == hostname


def test_trailing_dot_does_not_count_towards_the_length_limit() -> None:
    hostname = _valid_hostname_of_length(MAX_HOSTNAME_LENGTH)

    assert validate_hostname(hostname + ".") == validate_hostname(hostname)


def test_hostname_over_maximum_length_is_rejected() -> None:
    hostname = _valid_hostname_of_length(MAX_HOSTNAME_LENGTH + 1)

    assert len(hostname) == MAX_HOSTNAME_LENGTH + 1
    with pytest.raises(ValueError, match="must be at most"):
        validate_hostname(hostname)


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("", "empty"),
        ("   ", "whitespace only"),
        (" example.com", "leading whitespace"),
        ("example.com ", "trailing whitespace"),
        ("exa mple.com", "embedded whitespace"),
        ("https://example.com", "URL scheme"),
        ("example.com/", "trailing path"),
        ("user@example.com", "userinfo"),
        ("example.com:443", "port"),
        ("::1", "bare IPv6"),
        ("[::1]", "bracketed IPv6"),
        ("127.0.0.1", "IPv4 literal"),
        ("0.0.0.0", "wildcard IPv4 literal"),
        ("*.example.com", "wildcard"),
        ("example..com", "empty label"),
        (".example.com", "leading dot"),
        ("example.com..", "double trailing dot"),
        ("-example.com", "leading hyphen"),
        ("example-.com", "trailing hyphen"),
        ("exa_mple.com", "underscore"),
        ("exämple.com", "non-ASCII"),
    ],
)
def test_invalid_hostnames_are_rejected(raw: str, reason: str) -> None:
    with pytest.raises(ValueError):
        validate_hostname(raw)


def test_label_over_maximum_length_is_rejected() -> None:
    with pytest.raises(ValueError, match="each label must be at most"):
        validate_hostname(f"{'a' * (MAX_LABEL_LENGTH + 1)}.com")


def test_numeric_only_label_is_accepted_by_schema() -> None:
    # Deliberate: 2130706433 is 127.0.0.1 in decimal and some resolvers honour
    # it. Rejecting it here is insufficient; netguard must check the resolved
    # address. Pinned so the decision is visible if it ever changes.
    assert validate_hostname("2130706433") == "2130706433"


def test_request_model_normalises_and_rejects() -> None:
    assert CheckRequest(hostname="Example.COM.").hostname == "example.com"

    with pytest.raises(ValidationError):
        CheckRequest(hostname="127.0.0.1")

    with pytest.raises(ValidationError):
        CheckRequest(hostname=2130706433)  # type: ignore[arg-type]

    with pytest.raises(ValidationError):
        CheckRequest.model_validate({"hostname": "example.com", "extra": 1})


# --- Phase 5 response model coverage ---


def test_response_accepts_full_payload() -> None:
    from datetime import UTC, datetime

    from app.schemas import CheckResponse

    payload = CheckResponse(
        hostname="example.com",
        verified=True,
        hostname_verified=True,
        subject="CN=example.com",
        issuer="CN=Test CA",
        not_before=datetime(2025, 1, 1, tzinfo=UTC),
        not_after=datetime(2035, 12, 31, tzinfo=UTC),
        days_remaining=3650,
    )
    assert payload.verified is True and payload.error is None


def test_response_accepts_error_only_payload() -> None:
    from app.schemas import CheckErrorBody, CheckResponse

    payload = CheckResponse(
        hostname="expired.example",
        verified=False,
        error=CheckErrorBody(kind="expired", message="certificate has expired"),
    )
    assert payload.error is not None and payload.error.kind == "expired"
    assert payload.days_remaining is None


def test_response_rejects_unknown_error_kind() -> None:
    from pydantic import ValidationError as PydanticValidationError

    from app.schemas import CheckErrorBody

    with pytest.raises(PydanticValidationError):
        CheckErrorBody(kind="not_a_real_kind", message="x")  # type: ignore[arg-type]
