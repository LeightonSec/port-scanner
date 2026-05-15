"""Optional banner grabbing for open ports."""

from __future__ import annotations

import socket

BANNER_TIMEOUT: float = 2.0
BANNER_MAX_BYTES: int = 256


def grab_banner(host: str, port: int, timeout: float = BANNER_TIMEOUT) -> str | None:
    """
    Attempt to read a service banner from an already-open port.

    Tries a passive recv first (works for SSH, FTP, SMTP, Telnet).
    If no data arrives, sends a minimal HTTP probe (works for HTTP/S).
    Returns None on any failure or if the banner is empty.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                raw = sock.recv(BANNER_MAX_BYTES)
            except socket.timeout:
                raw = b""

            if not raw:
                # Send a minimal probe for services that speak first only after a request
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                    raw = sock.recv(BANNER_MAX_BYTES)
                except Exception:
                    return None

        if not raw:
            return None

        decoded = raw.decode("utf-8", errors="replace").strip()
        return decoded[:BANNER_MAX_BYTES] if decoded else None

    except Exception:
        return None
