"""Tests for the core scan engine and input utilities."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import pytest

from scanner.scanner import ScanResult, scan_host, scan_port
from scanner.utils import parse_cidr, parse_ports, parse_targets, sanitise_host


# ---------------------------------------------------------------------------
# scan_port
# ---------------------------------------------------------------------------

class TestScanPort:
    def test_open_port(self):
        with patch("scanner.scanner.socket.create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            result = scan_port("127.0.0.1", 80, timeout=1.0)

        assert result.state == "open"
        assert result.port == 80
        assert result.host == "127.0.0.1"
        assert result.service == "http"
        assert result.latency_ms >= 0

    def test_closed_port(self):
        with patch(
            "scanner.scanner.socket.create_connection",
            side_effect=ConnectionRefusedError,
        ):
            result = scan_port("127.0.0.1", 9999, timeout=1.0)

        assert result.state == "closed"
        assert result.port == 9999

    def test_filtered_port_timeout(self):
        with patch(
            "scanner.scanner.socket.create_connection",
            side_effect=socket.timeout,
        ):
            result = scan_port("127.0.0.1", 9999, timeout=1.0)

        assert result.state == "filtered"

    def test_filtered_port_oserror(self):
        with patch(
            "scanner.scanner.socket.create_connection",
            side_effect=OSError("network unreachable"),
        ):
            result = scan_port("127.0.0.1", 9999, timeout=1.0)

        assert result.state == "filtered"

    def test_unknown_port_service(self):
        with patch("scanner.scanner.socket.create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            result = scan_port("127.0.0.1", 12345, timeout=1.0)

        assert result.service == "unknown"

    def test_banner_grabbed_when_enabled(self):
        with patch("scanner.scanner.socket.create_connection") as mock_conn, \
             patch("scanner.scanner._grab_banner", return_value="SSH-2.0-OpenSSH") as mock_banner:
            mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            result = scan_port("127.0.0.1", 22, timeout=1.0, grab_banners=True)

        assert result.banner == "SSH-2.0-OpenSSH"
        mock_banner.assert_called_once_with("127.0.0.1", 22)

    def test_banner_not_grabbed_when_disabled(self):
        with patch("scanner.scanner.socket.create_connection") as mock_conn, \
             patch("scanner.scanner._grab_banner") as mock_banner:
            mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            result = scan_port("127.0.0.1", 22, timeout=1.0, grab_banners=False)

        assert result.banner is None
        mock_banner.assert_not_called()

    def test_rate_limit_sleep_called(self):
        with patch("scanner.scanner.socket.create_connection") as mock_conn, \
             patch("scanner.scanner.rate_limit_sleep") as mock_sleep:
            mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            scan_port("127.0.0.1", 80, delay_ms=10.0)

        mock_sleep.assert_called_once_with(10.0)


# ---------------------------------------------------------------------------
# scan_host
# ---------------------------------------------------------------------------

class TestScanHost:
    def _mock_open(self):
        mock = MagicMock()
        mock.__enter__ = MagicMock(return_value=MagicMock())
        mock.__exit__ = MagicMock(return_value=False)
        return mock

    def test_results_sorted_by_port(self):
        with patch("scanner.scanner.socket.create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            results = scan_host("127.0.0.1", [443, 80, 22], threads=3, timeout=1.0)

        ports = [r.port for r in results]
        assert ports == sorted(ports)

    def test_on_result_callback_called(self):
        callbacks = []
        with patch("scanner.scanner.socket.create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            scan_host("127.0.0.1", [80, 443], threads=2, on_result=callbacks.append)

        assert len(callbacks) == 2
        assert all(isinstance(r, ScanResult) for r in callbacks)

    def test_thread_cap_enforced(self):
        # Patch as_completed too so the loop exits immediately — mock futures never signal done.
        with patch("scanner.scanner.ThreadPoolExecutor") as mock_pool, \
             patch("scanner.scanner.as_completed", return_value=iter([])):
            mock_executor = MagicMock()
            mock_pool.return_value.__enter__ = MagicMock(return_value=mock_executor)
            mock_pool.return_value.__exit__ = MagicMock(return_value=False)
            scan_host("127.0.0.1", [80], threads=9999)

        called_threads = mock_pool.call_args[1].get("max_workers") or mock_pool.call_args[0][0]
        assert called_threads <= 500


# ---------------------------------------------------------------------------
# utils — CIDR and port parsing
# ---------------------------------------------------------------------------

class TestParseCidr:
    def test_valid_24(self):
        hosts = parse_cidr("192.168.1.0/24")
        assert len(hosts) == 254
        assert "192.168.1.1" in hosts
        assert "192.168.1.254" in hosts

    def test_valid_28(self):
        hosts = parse_cidr("10.0.0.0/28")
        assert len(hosts) == 14

    def test_rejects_slash_23(self):
        with pytest.raises(ValueError, match="too large"):
            parse_cidr("10.0.0.0/23")

    def test_rejects_slash_16(self):
        with pytest.raises(ValueError, match="too large"):
            parse_cidr("10.0.0.0/16")

    def test_invalid_cidr_raises(self):
        with pytest.raises(ValueError):
            parse_cidr("not-a-cidr/24")

    def test_host_bits_ignored(self):
        hosts = parse_cidr("192.168.1.50/24")
        assert "192.168.1.1" in hosts


class TestSanitiseHost:
    def test_valid_ip(self):
        assert sanitise_host("192.168.1.1") == "192.168.1.1"

    def test_valid_hostname(self):
        assert sanitise_host("example.com") == "example.com"

    def test_strips_whitespace(self):
        assert sanitise_host("  127.0.0.1  ") == "127.0.0.1"

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            sanitise_host("")

    def test_invalid_hostname_raises(self):
        with pytest.raises(ValueError):
            sanitise_host("not a valid host!")


class TestParsePorts:
    def test_top_returns_list(self):
        ports = parse_ports("top")
        assert isinstance(ports, list)
        assert len(ports) > 0
        assert all(1 <= p <= 65535 for p in ports)

    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_range(self):
        ports = parse_ports("1-5")
        assert ports == [1, 2, 3, 4, 5]

    def test_comma_separated(self):
        assert parse_ports("80,443,8080") == [80, 443, 8080]

    def test_mixed(self):
        ports = parse_ports("22,80-82,443")
        assert ports == [22, 80, 81, 82, 443]

    def test_out_of_range_raises(self):
        with pytest.raises(ValueError):
            parse_ports("0")

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_ports("not-a-port")

    def test_range_reversed_raises(self):
        with pytest.raises(ValueError):
            parse_ports("443-80")


class TestParseTargets:
    def test_single_ip(self):
        assert parse_targets("127.0.0.1") == ["127.0.0.1"]

    def test_cidr_returns_multiple(self):
        hosts = parse_targets("10.0.0.0/30")
        assert len(hosts) == 2

    def test_single_hostname(self):
        assert parse_targets("example.com") == ["example.com"]
