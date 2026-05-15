"""Output formatting: rich terminal, JSON, and Markdown."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich import box

from scanner.scanner import ScanResult

console = Console()

_STATE_STYLE: dict[str, str] = {
    "open": "bold green",
    "closed": "dim",
    "filtered": "yellow",
}


def print_results(
    results: list[ScanResult],
    target: str,
    duration: float,
    show_closed: bool = False,
) -> None:
    """Render results to the terminal using rich."""
    open_ports = [r for r in results if r.state == "open"]
    closed_count = sum(1 for r in results if r.state == "closed")
    filtered_count = sum(1 for r in results if r.state == "filtered")

    console.print()

    if not open_ports:
        console.print(f"  [dim]No open ports found on {target}.[/dim]")
    else:
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold cyan",
            padding=(0, 1),
        )
        table.add_column("PORT", style="bold", min_width=9)
        table.add_column("STATE", min_width=8)
        table.add_column("SERVICE", min_width=14)
        table.add_column("LATENCY", min_width=9)
        table.add_column("BANNER")

        display = open_ports[:]
        if show_closed:
            display = sorted(results, key=lambda r: r.port)

        for r in display:
            style = _STATE_STYLE.get(r.state, "")
            table.add_row(
                f"{r.port}/tcp",
                f"[{style}]{r.state}[/{style}]",
                r.service,
                f"{r.latency_ms:.1f}ms",
                r.banner or "",
            )

        console.print(table)

    console.print(
        f"  [green]Open:[/green] {len(open_ports)}  "
        f"[dim]Closed:[/dim] {closed_count}  "
        f"[yellow]Filtered:[/yellow] {filtered_count}  "
        f"[dim]Duration:[/dim] {duration:.2f}s"
    )
    console.print()


def _build_metadata(target: str, duration: float, results: list[ScanResult]) -> dict[str, Any]:
    return {
        "tool": "LeightonSec Port Scanner",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "duration_seconds": round(duration, 3),
        "summary": {
            "total": len(results),
            "open": sum(1 for r in results if r.state == "open"),
            "closed": sum(1 for r in results if r.state == "closed"),
            "filtered": sum(1 for r in results if r.state == "filtered"),
        },
    }


def to_json(results: list[ScanResult], target: str, duration: float) -> str:
    """Return a JSON string of scan results with metadata."""
    payload = {
        "metadata": _build_metadata(target, duration, results),
        "results": [asdict(r) for r in results],
    }
    return json.dumps(payload, indent=2)


def to_markdown(results: list[ScanResult], target: str, duration: float) -> str:
    """Return a Markdown report string."""
    meta = _build_metadata(target, duration, results)
    lines: list[str] = [
        f"# Port Scan Report — {target}",
        "",
        f"**Tool:** {meta['tool']} v{meta['version']}  ",
        f"**Timestamp:** {meta['timestamp']}  ",
        f"**Duration:** {meta['duration_seconds']}s  ",
        "",
        "## Summary",
        "",
        f"| State    | Count |",
        f"|----------|-------|",
        f"| Open     | {meta['summary']['open']} |",
        f"| Closed   | {meta['summary']['closed']} |",
        f"| Filtered | {meta['summary']['filtered']} |",
        "",
        "## Results",
        "",
        "| Port | State | Service | Latency (ms) | Banner |",
        "|------|-------|---------|--------------|--------|",
    ]

    for r in results:
        banner = (r.banner or "").replace("|", "\\|")
        lines.append(
            f"| {r.port}/tcp | {r.state} | {r.service} | {r.latency_ms:.1f} | {banner} |"
        )

    lines.append("")
    return "\n".join(lines)


def export_results(
    results: list[ScanResult],
    target: str,
    duration: float,
    fmt: str,
    path: Path,
) -> None:
    """Write formatted output to a file. fmt must be 'json' or 'markdown'."""
    if fmt == "json":
        content = to_json(results, target, duration)
    elif fmt == "markdown":
        content = to_markdown(results, target, duration)
    else:
        raise ValueError(f"Unknown export format: {fmt!r}")

    path.write_text(content, encoding="utf-8")
    console.print(f"  [dim]Exported to {path}[/dim]")
