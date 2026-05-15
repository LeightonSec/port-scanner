"""Tests for JSON and Markdown output formatters."""

from __future__ import annotations

import json

import pytest

from scanner.reporter import to_json, to_markdown
from scanner.scanner import ScanResult


def _make_results() -> list[ScanResult]:
    return [
        ScanResult(host="127.0.0.1", port=22, state="open", latency_ms=1.23, service="ssh", banner="SSH-2.0"),
        ScanResult(host="127.0.0.1", port=80, state="open", latency_ms=0.87, service="http"),
        ScanResult(host="127.0.0.1", port=9999, state="closed", latency_ms=0.12, service="unknown"),
        ScanResult(host="127.0.0.1", port=8888, state="filtered", latency_ms=1000.0, service="jupyter"),
    ]


class TestToJson:
    def test_returns_valid_json(self):
        output = to_json(_make_results(), "127.0.0.1", 2.5)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_metadata_present(self):
        parsed = json.loads(to_json(_make_results(), "127.0.0.1", 2.5))
        meta = parsed["metadata"]
        assert meta["target"] == "127.0.0.1"
        assert "timestamp" in meta
        assert "duration_seconds" in meta
        assert "tool" in meta
        assert "version" in meta

    def test_summary_counts_correct(self):
        parsed = json.loads(to_json(_make_results(), "127.0.0.1", 2.5))
        summary = parsed["metadata"]["summary"]
        assert summary["open"] == 2
        assert summary["closed"] == 1
        assert summary["filtered"] == 1
        assert summary["total"] == 4

    def test_results_array_present(self):
        parsed = json.loads(to_json(_make_results(), "127.0.0.1", 2.5))
        assert "results" in parsed
        assert len(parsed["results"]) == 4

    def test_all_states_represented(self):
        parsed = json.loads(to_json(_make_results(), "127.0.0.1", 2.5))
        states = {r["state"] for r in parsed["results"]}
        assert states == {"open", "closed", "filtered"}

    def test_banner_included_when_present(self):
        parsed = json.loads(to_json(_make_results(), "127.0.0.1", 2.5))
        ssh = next(r for r in parsed["results"] if r["port"] == 22)
        assert ssh["banner"] == "SSH-2.0"

    def test_banner_null_when_absent(self):
        parsed = json.loads(to_json(_make_results(), "127.0.0.1", 2.5))
        http = next(r for r in parsed["results"] if r["port"] == 80)
        assert http["banner"] is None

    def test_empty_results(self):
        output = to_json([], "127.0.0.1", 0.1)
        parsed = json.loads(output)
        assert parsed["metadata"]["summary"]["total"] == 0
        assert parsed["results"] == []


class TestToMarkdown:
    def test_returns_string(self):
        output = to_markdown(_make_results(), "127.0.0.1", 2.5)
        assert isinstance(output, str)

    def test_contains_header(self):
        output = to_markdown(_make_results(), "127.0.0.1", 2.5)
        assert "# Port Scan Report" in output
        assert "127.0.0.1" in output

    def test_contains_summary_table(self):
        output = to_markdown(_make_results(), "127.0.0.1", 2.5)
        assert "## Summary" in output
        assert "| Open" in output
        assert "| Closed" in output
        assert "| Filtered" in output

    def test_contains_results_table(self):
        output = to_markdown(_make_results(), "127.0.0.1", 2.5)
        assert "## Results" in output
        assert "| Port |" in output
        assert "22/tcp" in output

    def test_all_ports_listed(self):
        output = to_markdown(_make_results(), "127.0.0.1", 2.5)
        for port in (22, 80, 9999, 8888):
            assert f"{port}/tcp" in output

    def test_pipe_in_banner_escaped(self):
        results = [
            ScanResult(
                host="127.0.0.1", port=80, state="open",
                latency_ms=1.0, service="http", banner="Server: nginx | version"
            )
        ]
        output = to_markdown(results, "127.0.0.1", 1.0)
        assert "\\|" in output

    def test_empty_results(self):
        output = to_markdown([], "127.0.0.1", 0.1)
        assert isinstance(output, str)
        assert "## Results" in output
