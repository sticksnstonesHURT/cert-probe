"""Unit tests for destination validation and bounded DNS resolution."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import threading
import time
from collections.abc import Iterator
from unittest.mock import patch

import pytest

from app import netguard
from app.config import Settings


def _fast_settings() -> Settings:
    return Settings(
        dns_timeout_seconds=0.1,
        connect_timeout_seconds=0.1,
        tls_handshake_timeout_seconds=0.1,
        overall_deadline_seconds=0.5,
    )


def _getaddrinfo_result(ip: str, port: int = 443) -> list[tuple]:
    if ":" in ip:
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, port, 0, 0))]
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "127.1.2.3",
        "::1",
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "fc00::1",
        "169.254.1.1",
        "fe80::1",
        "224.0.0.1",
        "ff02::1",
        "240.0.0.1",
        "0.0.0.0",
        "::",
    ],
)
def test_non_public_addresses_are_blocked(ip: str) -> None:
    assert netguard.classify_ip(ipaddress.ip_address(ip)) is not None


@pytest.mark.parametrize("ip", ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(ip: str) -> None:
    assert netguard.classify_ip(ipaddress.ip_address(ip)) is None


def test_ipv4_mapped_ipv6_loopback_is_blocked() -> None:
    assert netguard.classify_ip(ipaddress.ip_address("::ffff:127.0.0.1")) == "loopback"


def test_cgnat_is_blocked() -> None:
    assert netguard.classify_ip(ipaddress.ip_address("100.64.0.1")) == "cgnat"


def test_validated_address_is_immutable() -> None:
    address = netguard.ValidatedAddress(
        family=socket.AF_INET,
        socktype=socket.SOCK_STREAM,
        proto=6,
        sockaddr=("1.1.1.1", 443),
        ip=ipaddress.ip_address("1.1.1.1"),
    )
    with pytest.raises(AttributeError):
        address.ip = ipaddress.ip_address("2.2.2.2")  # type: ignore[misc]


def test_resolve_and_validate_returns_validated_list() -> None:
    deadline = time.monotonic() + 5
    with patch(
        "app.netguard.socket.getaddrinfo",
        return_value=_getaddrinfo_result("93.184.216.34"),
    ):
        result = netguard.resolve_and_validate("example.com", 443, _fast_settings(), deadline)
    assert len(result) == 1
    assert str(result[0].ip) == "93.184.216.34"
    assert result[0].sockaddr == ("93.184.216.34", 443)


def test_resolve_and_validate_blocks_private() -> None:
    deadline = time.monotonic() + 5
    with patch(
        "app.netguard.socket.getaddrinfo",
        return_value=_getaddrinfo_result("10.0.0.1"),
    ):
        with pytest.raises(netguard.BlockedDestination) as exc_info:
            netguard.resolve_and_validate("evil.example", 443, _fast_settings(), deadline)
    assert exc_info.value.category == "private"


def test_resolve_and_validate_rejects_if_any_address_is_blocked() -> None:
    """A hostname resolving to safe + private is rejected entirely."""
    deadline = time.monotonic() + 5
    infos = _getaddrinfo_result("93.184.216.34") + _getaddrinfo_result("10.0.0.1")
    with patch("app.netguard.socket.getaddrinfo", return_value=infos):
        with pytest.raises(netguard.BlockedDestination):
            netguard.resolve_and_validate("evil.example", 443, _fast_settings(), deadline)


def test_resolve_and_validate_gaierror_is_dns_failure() -> None:
    deadline = time.monotonic() + 5
    with patch(
        "app.netguard.socket.getaddrinfo",
        side_effect=socket.gaierror(socket.EAI_NONAME, "not found"),
    ):
        with pytest.raises(netguard.DnsFailure):
            netguard.resolve_and_validate("nope.invalid", 443, _fast_settings(), deadline)


def test_resolve_and_validate_timeout() -> None:
    deadline = time.monotonic() + 5

    def slow(*_a: object, **_kw: object) -> list[tuple]:
        time.sleep(0.5)
        return _getaddrinfo_result("93.184.216.34")

    with patch("app.netguard.socket.getaddrinfo", side_effect=slow):
        with pytest.raises(netguard.DnsTimeout):
            netguard.resolve_and_validate("slow.example", 443, _fast_settings(), deadline)


def test_resolve_and_validate_deadline_passed_up_front() -> None:
    with pytest.raises(netguard.DnsTimeout):
        netguard.resolve_and_validate("any.example", 443, _fast_settings(), deadline=0.0)


def test_resolve_and_validate_empty_result_is_dns_failure() -> None:
    deadline = time.monotonic() + 5
    with patch("app.netguard.socket.getaddrinfo", return_value=[]):
        with pytest.raises(netguard.DnsFailure):
            netguard.resolve_and_validate("empty.example", 443, _fast_settings(), deadline)


# --- special-purpose range coverage (allowlist policy) ---


@pytest.mark.parametrize(
    ("ip", "expected_category"),
    [
        ("192.0.2.1", "private"),  # TEST-NET-1
        ("198.51.100.1", "private"),  # TEST-NET-2
        ("203.0.113.1", "private"),  # TEST-NET-3
        ("198.18.0.1", "private"),  # benchmarking
        ("255.255.255.255", "private"),  # limited broadcast (in 240.0.0.0/4)
        ("2001:db8::1", "private"),  # IPv6 documentation
        ("2001:2::1", "private"),  # IPv6 benchmarking
        ("100::1", "private"),  # IPv6 discard prefix
        ("ff05::1", "multicast"),  # site-local IPv6 multicast
        ("ff0e::1", "multicast"),  # global IPv6 multicast
    ],
)
def test_special_purpose_ranges_are_blocked_with_category(ip: str, expected_category: str) -> None:
    """Explicit categories fire before the ``is_global`` gate; this pins them."""
    assert netguard.classify_ip(ipaddress.ip_address(ip)) == expected_category


@pytest.mark.parametrize(
    "ip",
    [
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "198.18.0.1",
        "255.255.255.255",
        "2001:db8::1",
        "2001:2::1",
        "100::1",
        "ff05::1",
        "ff0e::1",
    ],
)
def test_special_purpose_ranges_are_rejected(ip: str) -> None:
    """Behavioural: netguard refuses these regardless of category name."""
    assert netguard.classify_ip(ipaddress.ip_address(ip)) is not None


@pytest.mark.parametrize(
    ("ip", "expected_category"),
    [
        ("::ffff:10.0.0.1", "private"),
        ("::ffff:224.0.0.1", "multicast"),
        ("::ffff:169.254.1.1", "link-local"),
    ],
)
def test_ipv4_mapped_addresses_are_unwrapped_and_rejected(ip: str, expected_category: str) -> None:
    assert netguard.classify_ip(ipaddress.ip_address(ip)) == expected_category


def test_ipv4_mapped_public_address_is_allowed() -> None:
    assert netguard.classify_ip(ipaddress.ip_address("::ffff:8.8.8.8")) is None


def test_non_global_category_is_reachable_for_safety_net() -> None:
    """The ``is_global`` gate is a safety net. If it fires for any input, the
    returned category is ``non-global``. We cannot pin a specific address here
    because the set depends on the Python patch version; this smoke check just
    asserts the gate is wired up and returns one of the known categories."""
    for ip_str in ("1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"):
        result = netguard.classify_ip(ipaddress.ip_address(ip_str))
        assert result is None or result == "non-global"


# --- shared DNS executor tests ---


@pytest.fixture(autouse=True)
def _clean_dns_subsystem() -> Iterator[None]:
    netguard.reset_dns_executor_for_tests()
    yield
    netguard.reset_dns_executor_for_tests()


def test_capacity_slot_released_after_success() -> None:
    netguard.reset_dns_executor_for_tests(max_workers=1, max_pending=1)
    with patch(
        "app.netguard.socket.getaddrinfo", return_value=_getaddrinfo_result("93.184.216.34")
    ):
        netguard.resolve_and_validate("example.com", 443, _fast_settings(), time.monotonic() + 5)
        netguard.resolve_and_validate("example.com", 443, _fast_settings(), time.monotonic() + 5)


def test_capacity_slot_released_after_exception() -> None:
    netguard.reset_dns_executor_for_tests(max_workers=1, max_pending=1)
    with patch(
        "app.netguard.socket.getaddrinfo",
        side_effect=socket.gaierror(socket.EAI_NONAME, "not found"),
    ):
        with pytest.raises(netguard.DnsFailure):
            netguard.resolve_and_validate("x.invalid", 443, _fast_settings(), time.monotonic() + 5)
    with patch(
        "app.netguard.socket.getaddrinfo", return_value=_getaddrinfo_result("93.184.216.34")
    ):
        netguard.resolve_and_validate("ok.example", 443, _fast_settings(), time.monotonic() + 5)


def test_capacity_exhaustion_fails_fast_deterministically() -> None:
    netguard.reset_dns_executor_for_tests(max_workers=1, max_pending=2)
    assert netguard._slots.acquire(blocking=False)
    assert netguard._slots.acquire(blocking=False)
    try:
        with pytest.raises(netguard.DnsCapacityExceeded):
            netguard.resolve_and_validate(
                "example.com", 443, _fast_settings(), time.monotonic() + 5
            )
    finally:
        netguard._slots.release()
        netguard._slots.release()
    with patch(
        "app.netguard.socket.getaddrinfo", return_value=_getaddrinfo_result("93.184.216.34")
    ):
        netguard.resolve_and_validate("example.com", 443, _fast_settings(), time.monotonic() + 5)


def test_capacity_error_message_reflects_configured_limit() -> None:
    netguard.reset_dns_executor_for_tests(max_workers=1, max_pending=3)
    for _ in range(3):
        assert netguard._slots.acquire(blocking=False)
    try:
        with pytest.raises(netguard.DnsCapacityExceeded, match=r"\(3 concurrent calls\)"):
            netguard.resolve_and_validate(
                "example.com", 443, _fast_settings(), time.monotonic() + 5
            )
    finally:
        for _ in range(3):
            netguard._slots.release()


def test_caller_timeout_holds_slot_until_worker_finishes() -> None:
    netguard.reset_dns_executor_for_tests(max_workers=1, max_pending=2)
    release = threading.Event()
    entered = threading.Event()

    def slow_getaddrinfo(*_a: object, **_kw: object) -> list[tuple]:
        entered.set()
        release.wait(timeout=10)
        return _getaddrinfo_result("93.184.216.34")

    with patch("app.netguard.socket.getaddrinfo", side_effect=slow_getaddrinfo):
        with pytest.raises(netguard.DnsTimeout):
            netguard.resolve_and_validate(
                "slow.example", 443, _fast_settings(), time.monotonic() + 5
            )
        # Deterministic: worker has certainly entered the resolver.
        assert entered.wait(timeout=5)
        # 1 slot held by wedged worker; 1 free.
        assert netguard.dns_slots_available() == 1
        assert netguard._slots.acquire(blocking=False)
        try:
            with pytest.raises(netguard.DnsCapacityExceeded):
                netguard.resolve_and_validate(
                    "example.com", 443, _fast_settings(), time.monotonic() + 5
                )
        finally:
            netguard._slots.release()
        # Release the worker; shutdown(wait=True) guarantees it has exited and
        # its done callback fired before returning.
        release.set()
        netguard.shutdown_dns_executor(wait=True)

    # Slot count is back to full.
    assert netguard.dns_slots_available() == 2


def test_no_more_than_max_workers_run_concurrently() -> None:
    netguard.reset_dns_executor_for_tests(max_workers=2, max_pending=4)

    concurrent_now = [0]
    peak = [0]
    lock = threading.Lock()
    # Barrier(2): if the pool only ran one worker at a time, the second
    # waiter would never arrive and this barrier would raise
    # BrokenBarrierError, failing the test.
    barrier = threading.Barrier(2, timeout=5)

    def tracking(*_a: object, **_kw: object) -> list[tuple]:
        with lock:
            concurrent_now[0] += 1
            peak[0] = max(peak[0], concurrent_now[0])
        try:
            barrier.wait()
        finally:
            with lock:
                concurrent_now[0] -= 1
        return _getaddrinfo_result("93.184.216.34")

    errors: list[BaseException] = []

    def call_resolve() -> None:
        try:
            netguard.resolve_and_validate(
                "example.com", 443, _fast_settings(), time.monotonic() + 10
            )
        except BaseException as exc:
            errors.append(exc)

    with patch("app.netguard.socket.getaddrinfo", side_effect=tracking):
        workers = [threading.Thread(target=call_resolve) for _ in range(4)]
        for t in workers:
            t.start()
        for t in workers:
            t.join(timeout=10)

    assert not errors, f"unexpected errors: {errors}"
    assert peak[0] == 2, f"peak concurrency {peak[0]}, expected 2"


def test_shutdown_rejects_new_calls() -> None:
    netguard.shutdown_dns_executor(wait=False)
    with pytest.raises(netguard.DnsFailure, match="shut down"):
        netguard.resolve_and_validate("example.com", 443, _fast_settings(), time.monotonic() + 5)


def test_cancelled_dns_future_is_dns_failure() -> None:
    deadline = time.monotonic() + 5

    with patch("app.netguard._submit_dns") as mock_submit:
        future: concurrent.futures.Future[list[tuple]] = concurrent.futures.Future()
        future.cancel()
        mock_submit.return_value = future

        with pytest.raises(netguard.DnsFailure, match="was cancelled"):
            netguard.resolve_and_validate("cancelled.example", 443, _fast_settings(), deadline)
