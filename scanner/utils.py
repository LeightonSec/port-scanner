"""Input validation, CIDR parsing, port parsing, and rate-limiting helpers."""

from __future__ import annotations

import ipaddress
import re
import time

from scanner.services import TOP_PORTS

_MAX_CIDR_PREFIX = 24  # hard cap: /24 = max 254 hosts
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)


def sanitise_host(host: str) -> str:
    """Return a validated host string (IP address or hostname). Raises ValueError on bad input."""
    host = host.strip()
    if not host:
        raise ValueError("Host cannot be empty.")

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    if len(host) > 253:
        raise ValueError(f"Hostname too long (max 253 chars): {host!r}")
    if not _HOSTNAME_RE.match(host):
        raise ValueError(f"Invalid hostname: {host!r}")
    return host


def parse_cidr(target: str) -> list[str]:
    """
    Parse a CIDR range and return a list of host IPs.
    Enforces a hard /24 cap — raises ValueError for larger ranges.
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR notation: {target!r}") from exc

    if network.prefixlen < _MAX_CIDR_PREFIX:
        raise ValueError(
            f"CIDR range /{network.prefixlen} is too large. "
            f"Maximum allowed is /{_MAX_CIDR_PREFIX} (254 hosts)."
        )

    return [str(ip) for ip in network.hosts()]


def parse_targets(target: str) -> list[str]:
    """Parse a target string into a list of host strings."""
    if "/" in target:
        return parse_cidr(target)
    return [sanitise_host(target)]


def parse_ports(port_spec: str) -> list[int]:
    """
    Parse a port specification into a sorted list of port numbers.

    Accepted formats:
      "top"          — curated top ports list
      "80"           — single port
      "1-1024"       — inclusive range
      "80,443,8080"  — comma-separated
      "1-65535"      — full range (warning: slow)
    """
    if port_spec.strip().lower() == "top":
        return list(TOP_PORTS)

    ports: set[int] = set()
    for part in port_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            raw_start, _, raw_end = part.partition("-")
            try:
                start, end = int(raw_start), int(raw_end)
            except ValueError:
                raise ValueError(f"Invalid port range: {part!r}")
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError(
                    f"Port range out of bounds (must be 1–65535, start ≤ end): {part!r}"
                )
            ports.update(range(start, end + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"Invalid port: {part!r}")
            if not 1 <= p <= 65535:
                raise ValueError(f"Port out of bounds (must be 1–65535): {p}")
            ports.add(p)

    if not ports:
        raise ValueError("No valid ports specified.")
    return sorted(ports)


def confirm_scan(hosts: list[str], ports: list[int]) -> bool:
    """
    Print scan scope and require explicit 'y' confirmation.
    Always returns False if the user does not type exactly 'y'.
    """
    print()
    print(f"  Targets      : {len(hosts)} host(s)")
    print(f"  Ports        : {len(ports)}")
    print(f"  Total probes : {len(hosts) * len(ports):,}")
    print()
    try:
        answer = input("  Confirm scan? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == "y"


def rate_limit_sleep(delay_ms: float) -> None:
    """Sleep for delay_ms milliseconds between connection attempts."""
    if delay_ms > 0:
        time.sleep(delay_ms / 1000.0)
