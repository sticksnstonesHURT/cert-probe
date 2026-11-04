"""Destination validation and bounded DNS resolution (SSRF protection).

Every address resolved for a hostname is checked against policy *before* any
byte is sent. Connections then target the validated ``sockaddr`` directly, so a
later DNS change cannot redirect the request (TOCTOU defence). TLS SNI still
uses the original hostname, so certificate verification is unaffected.

DNS execution uses a single shared, bounded thread pool. Total in-flight jobs
(running plus queued) are capped, so a slow or wedged resolver cannot make the
process spawn unbounded threads. Capacity exhaustion fails fast with
:class:`DnsCapacityExceeded` rather than queueing indefinitely.

Known limitation: ``ThreadPoolExecutor`` uses non-daemon worker threads, so a
call to ``getaddrinfo()`` that is stuck in the OS resolver keeps the interpreter
alive at exit. ``shutdown_dns_executor(wait=False)`` returns immediately but
cannot forcibly terminate that thread; the bounded behaviour is documented and
accepted.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import threading
import time
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address
from typing import cast

from app.config import Settings

IPAddress = IPv4Address | IPv6Address
_CGNAT_IPV4 = IPv4Network("100.64.0.0/10")

SockAddr = tuple[str, int] | tuple[str, int, int, int]

_DNS_MAX_WORKERS = 8
_DNS_MAX_QUEUE = 24
_DNS_MAX_PENDING = _DNS_MAX_WORKERS + _DNS_MAX_QUEUE

_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=_DNS_MAX_WORKERS, thread_name_prefix="netguard-dns"
)
_slots = threading.BoundedSemaphore(_DNS_MAX_PENDING)
_current_capacity: int = _DNS_MAX_PENDING


class NetguardError(Exception):
    """Base class for destination-validation failures."""


class DnsFailure(NetguardError):
    """The hostname could not be resolved, or DNS execution is unavailable."""


class DnsTimeout(NetguardError):
    """Resolution exceeded the configured or remaining deadline."""


class DnsCapacityExceeded(NetguardError):
    """DNS subsystem is saturated; the caller should back off."""


class BlockedDestination(NetguardError):
    """At least one resolved address is prohibited by policy."""

    def __init__(self, hostname: str, address: IPAddress, category: str) -> None:
        super().__init__(f"hostname {hostname!r} resolves to a {category} address ({address})")
        self.hostname = hostname
        self.address = address
        self.category = category


@dataclass(frozen=True, slots=True)
class ValidatedAddress:
    """An address that has passed :func:`classify_ip`."""

    family: int
    socktype: int
    proto: int
    sockaddr: SockAddr
    ip: IPAddress


def classify_ip(ip: IPAddress) -> str | None:
    """Return a blocked category name, or ``None`` if the address is permitted.

    Policy: allow only addresses that ``ipaddress.is_global`` reports as
    globally routable. Explicit category checks run first for message quality
    and as defence-in-depth against ``is_global``/``is_private`` regressions in
    individual Python patch versions (notably IPv6 multicast, which some
    ``is_global`` implementations have historically classified as global).

    IPv4-mapped IPv6 addresses are unwrapped first so ``::ffff:127.0.0.1``
    cannot slip past the IPv4 checks and cannot rely on ``is_global`` being
    correct for mapped addresses (a known regression in 3.12.x).
    """
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if isinstance(ip, IPv4Address) and ip in _CGNAT_IPV4:
        return "cgnat"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"

    # Allowlist gate: only globally-routable destinations pass.
    if not ip.is_global:
        return "non-global"
    return None


def dns_slots_available() -> int:
    """Return the number of free DNS submission slots. Test helper.

    Relies on ``threading.BoundedSemaphore._value``, which is a private
    attribute but stable across CPython releases (both the pure-Python and the
    ``_thread`` C implementation expose it). Not used in production code.
    """
    return _slots._value


def shutdown_dns_executor(wait: bool = False) -> None:
    """Shut down the shared DNS executor.

    ``wait=True`` blocks until running ``getaddrinfo()`` calls have returned
    and all worker threads have exited. ``wait=False`` returns immediately;
    in-flight workers keep running until the OS resolver returns, at which
    point they exit. The executor is not restarted by this function; further
    calls to :func:`resolve_and_validate` fail with :class:`DnsFailure`.

    Idempotent: a second call is a no-op.
    """
    _executor.shutdown(wait=wait, cancel_futures=True)


def reset_dns_executor_for_tests(
    max_workers: int = _DNS_MAX_WORKERS,
    max_pending: int = _DNS_MAX_PENDING,
) -> None:
    """Tests only: drain and replace the shared executor.

    ``shutdown(wait=True)`` joins any worker from the previous executor before
    capacity accounting is reset, so worker count never outlives the semaphore
    that governs it. If a test wedged a mock without releasing it, this blocks
    -- which fails the test suite visibly instead of leaking a worker into the
    next test.
    """
    global _executor, _slots, _current_capacity
    _executor.shutdown(wait=True, cancel_futures=True)
    _executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers, thread_name_prefix="netguard-dns-test"
    )
    _slots = threading.BoundedSemaphore(max_pending)
    _current_capacity = max_pending


def _submit_dns(hostname: str, port: int) -> concurrent.futures.Future[list[tuple]]:
    slots = _slots  # bind locally so the release callback uses the acquired semaphore
    if not slots.acquire(blocking=False):
        raise DnsCapacityExceeded(
            f"DNS subsystem at capacity ({_current_capacity} concurrent calls); try again shortly"
        )
    try:
        future = _executor.submit(socket.getaddrinfo, hostname, port, 0, socket.SOCK_STREAM)
    except RuntimeError as exc:
        slots.release()
        raise DnsFailure(f"DNS executor is shut down: {exc}") from exc
    except BaseException:
        slots.release()
        raise
    future.add_done_callback(lambda _future: slots.release())
    return future


def resolve_and_validate(
    hostname: str,
    port: int,
    settings: Settings,
    deadline: float,
) -> list[ValidatedAddress]:
    """Resolve ``hostname`` once and validate every returned address.

    ``deadline`` is an absolute monotonic deadline; the effective DNS timeout
    is ``min(settings.dns_timeout_seconds, deadline - now)``.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DnsTimeout("overall deadline exceeded before DNS resolution")
    timeout = min(settings.dns_timeout_seconds, remaining)

    future = _submit_dns(hostname, port)
    try:
        infos = future.result(timeout=timeout)
    except TimeoutError as exc:
        # Best-effort cancel. If the task already started, the done callback
        # keeps the slot reserved until the underlying getaddrinfo returns.
        future.cancel()
        raise DnsTimeout(f"DNS resolution for {hostname!r} exceeded {timeout:.3f}s") from exc
    except concurrent.futures.CancelledError as exc:
        raise DnsFailure(f"DNS resolution for {hostname!r} was cancelled") from exc
    except socket.gaierror as exc:
        raise DnsFailure(f"DNS resolution failed for {hostname!r}: {exc}") from exc
    except OSError as exc:
        raise DnsFailure(f"DNS resolution failed for {hostname!r}: {exc}") from exc

    if not infos:
        raise DnsFailure(f"DNS resolution for {hostname!r} returned no addresses")

    fixture_ip: IPv4Address | None = None
    if (
        settings.test_mode
        and settings.fixture_hostname == hostname
        and settings.fixture_ip is not None
    ):
        parsed = ipaddress.ip_address(settings.fixture_ip)
        if not isinstance(parsed, IPv4Address):
            raise DnsFailure(
                f"fixture configuration is invalid: {settings.fixture_ip!r} is not IPv4"
            )
        fixture_ip = parsed

    validated: list[ValidatedAddress] = []
    for family, socktype, proto, _canonname, raw_sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise DnsFailure(
                f"resolver returned unsupported address family {family} for {hostname!r}"
            )
        sockaddr = cast(SockAddr, raw_sockaddr)
        ip = ipaddress.ip_address(sockaddr[0])

        if fixture_ip is not None:
            compare_ip = ip.ipv4_mapped if isinstance(ip, IPv6Address) and ip.ipv4_mapped else ip
            if compare_ip != fixture_ip:
                raise BlockedDestination(hostname, ip, "non-fixture")
            validated.append(ValidatedAddress(family, socktype, proto, sockaddr, ip))
            continue

        category = classify_ip(ip)
        if category is not None:
            raise BlockedDestination(hostname, ip, category)
        validated.append(ValidatedAddress(family, socktype, proto, sockaddr, ip))

    return validated
