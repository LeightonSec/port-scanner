"""Tests for banner grabbing."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

from scanner.banner import BANNER_MAX_BYTES, grab_banner


def _make_mock_socket(recv_data: bytes = b"", send_raises: Exception | None = None) -> MagicMock:
    """Build a mock socket context manager."""
    mock_sock = MagicMock()
    mock_sock.recv.return_value = recv_data
    if send_raises:
        mock_sock.sendall.side_effect = send_raises
    mock_ctx = MagicMock()
    mock_ctx.__enter__ = MagicMock(return_value=mock_sock)
    mock_ctx.__exit__ = MagicMock(return_value=False)
    return mock_ctx, mock_sock


class TestGrabBanner:
    def test_returns_banner_on_success(self):
        mock_ctx, _ = _make_mock_socket(recv_data=b"SSH-2.0-OpenSSH_8.9\r\n")
        with patch("scanner.banner.socket.create_connection", return_value=mock_ctx):
            result = grab_banner("127.0.0.1", 22)
        assert result == "SSH-2.0-OpenSSH_8.9"

    def test_returns_none_on_connection_error(self):
        with patch(
            "scanner.banner.socket.create_connection",
            side_effect=ConnectionRefusedError,
        ):
            result = grab_banner("127.0.0.1", 9999)
        assert result is None

    def test_returns_none_on_timeout(self):
        with patch(
            "scanner.banner.socket.create_connection",
            side_effect=socket.timeout,
        ):
            result = grab_banner("127.0.0.1", 80)
        assert result is None

    def test_truncates_at_max_bytes(self):
        long_data = b"X" * (BANNER_MAX_BYTES + 100)
        mock_ctx, _ = _make_mock_socket(recv_data=long_data)
        with patch("scanner.banner.socket.create_connection", return_value=mock_ctx):
            result = grab_banner("127.0.0.1", 80)
        assert result is not None
        assert len(result) <= BANNER_MAX_BYTES

    def test_handles_binary_data_gracefully(self):
        binary = bytes(range(256))
        mock_ctx, _ = _make_mock_socket(recv_data=binary)
        with patch("scanner.banner.socket.create_connection", return_value=mock_ctx):
            result = grab_banner("127.0.0.1", 80)
        # Should not raise — may be None or a decoded string
        assert result is None or isinstance(result, str)

    def test_returns_none_for_empty_response(self):
        mock_ctx, mock_sock = _make_mock_socket(recv_data=b"")
        # Also make the fallback probe recv return empty
        mock_sock.recv.return_value = b""
        with patch("scanner.banner.socket.create_connection", return_value=mock_ctx):
            result = grab_banner("127.0.0.1", 80)
        assert result is None

    def test_falls_back_to_probe_when_no_initial_data(self):
        mock_ctx, mock_sock = _make_mock_socket()
        # First recv times out, second recv (after probe) returns data
        mock_sock.recv.side_effect = [socket.timeout, b"HTTP/1.1 200 OK\r\n"]
        with patch("scanner.banner.socket.create_connection", return_value=mock_ctx):
            result = grab_banner("127.0.0.1", 80)
        assert result == "HTTP/1.1 200 OK"

    def test_strips_whitespace(self):
        mock_ctx, _ = _make_mock_socket(recv_data=b"  FTP ready  \r\n")
        with patch("scanner.banner.socket.create_connection", return_value=mock_ctx):
            result = grab_banner("127.0.0.1", 21)
        assert result == "FTP ready"
