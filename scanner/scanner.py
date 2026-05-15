"""Core TCP connect scan engine."""

from __future__ import annotations

import socket
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from scanner.banner import grab_banner as _grab_banner
from scanner.services import SERVICE_NAMES
from scanner.utils import rate_limit_sleep

MAX_THREADS: int = 500


@dataclass
class ScanResult:
    host: str
    port: int
    state: str  # "open" | "closed" | "filtered"
    latency_ms: float
    service: str
    banner: str | None = field(default=None)


def scan_port(
    host: str,
    port: int,
    timeout: float = 1.0,
    grab_banners: bool = False,
    delay_ms: float = 0.0,
) -> ScanResult:
    """
    Attempt a TCP connect to host:port.

    States:
      open     — connection established
      closed   — connection refused (RST received)
      filtered — timeout or unreachable (firewall / no route)
    """
    rate_limit_sleep(delay_ms)

    service = SERVICE_NAMES.get(port, "unknown")
    start = time.monotonic()

    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = round((time.monotonic() - start) * 1000, 2)
            banner = _grab_banner(host, port) if grab_banners else None
            return ScanResult(
                host=host,
                port=port,
                state="open",
                latency_ms=latency_ms,
                service=service,
                banner=banner,
            )
    except ConnectionRefusedError:
        latency_ms = round((time.monotonic() - start) * 1000, 2)
        return ScanResult(
            host=host, port=port, state="closed", latency_ms=latency_ms, service=service
        )
    except (socket.timeout, TimeoutError, OSError):
        latency_ms = round((time.monotonic() - start) * 1000, 2)
        return ScanResult(
            host=host, port=port, state="filtered", latency_ms=latency_ms, service=service
        )


def scan_host(
    host: str,
    ports: list[int],
    threads: int = 100,
    timeout: float = 1.0,
    grab_banners: bool = False,
    delay_ms: float = 0.0,
    on_result: Callable[[ScanResult], None] | None = None,
) -> list[ScanResult]:
    """Scan all specified ports on a single host using a thread pool."""
    threads = min(max(1, threads), MAX_THREADS)
    results: list[ScanResult] = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout, grab_banners, delay_ms): port
            for port in ports
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
                if on_result is not None:
                    on_result(result)
            except Exception:
                pass

    return sorted(results, key=lambda r: r.port)


def scan(
    targets: list[str],
    ports: list[int],
    threads: int = 100,
    timeout: float = 1.0,
    grab_banners: bool = False,
    delay_ms: float = 0.0,
    on_result: Callable[[ScanResult], None] | None = None,
) -> list[ScanResult]:
    """Scan multiple targets sequentially, each host with its own thread pool."""
    all_results: list[ScanResult] = []
    for host in targets:
        host_results = scan_host(
            host, ports, threads, timeout, grab_banners, delay_ms, on_result
        )
        all_results.extend(host_results)
    return all_results
