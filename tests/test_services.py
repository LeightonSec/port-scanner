"""Tests for port/service name mappings."""

from __future__ import annotations

import pytest

from scanner.services import SERVICE_NAMES, TOP_PORTS


class TestServiceNames:
    def test_http_is_mapped(self):
        assert SERVICE_NAMES[80] == "http"

    def test_https_is_mapped(self):
        assert SERVICE_NAMES[443] == "https"

    def test_ssh_is_mapped(self):
        assert SERVICE_NAMES[22] == "ssh"

    def test_unknown_port_not_in_dict(self):
        assert 12345 not in SERVICE_NAMES

    def test_all_ports_in_valid_range(self):
        for port in SERVICE_NAMES:
            assert 1 <= port <= 65535, f"Port {port} out of valid range"

    def test_all_service_names_are_strings(self):
        for port, name in SERVICE_NAMES.items():
            assert isinstance(name, str) and name, f"Empty or non-string name for port {port}"

    def test_well_known_services_present(self):
        expected = {21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 3306: "mysql", 3389: "rdp"}
        for port, name in expected.items():
            assert SERVICE_NAMES.get(port) == name

    def test_no_duplicate_ports(self):
        ports = list(SERVICE_NAMES.keys())
        assert len(ports) == len(set(ports))


class TestTopPorts:
    def test_is_a_list(self):
        assert isinstance(TOP_PORTS, list)

    def test_all_integers(self):
        assert all(isinstance(p, int) for p in TOP_PORTS)

    def test_all_in_valid_range(self):
        assert all(1 <= p <= 65535 for p in TOP_PORTS), "Port out of 1–65535 range"

    def test_no_duplicates(self):
        assert len(TOP_PORTS) == len(set(TOP_PORTS))

    def test_common_ports_included(self):
        for port in (22, 80, 443, 3306, 3389):
            assert port in TOP_PORTS

    def test_high_value_ports_near_front(self):
        idx_80 = TOP_PORTS.index(80)
        idx_443 = TOP_PORTS.index(443)
        assert idx_80 < 20
        assert idx_443 < 20

    def test_length_reasonable(self):
        assert len(TOP_PORTS) >= 100
