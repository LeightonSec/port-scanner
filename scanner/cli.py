"""Typer CLI — commands: scan, version."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from scanner import __version__
from scanner.reporter import export_results, print_results
from scanner.scanner import scan as run_scan
from scanner.utils import confirm_scan, parse_ports, parse_targets

app = typer.Typer(
    name="port-scanner",
    help="LeightonSec TCP port scanner — for authorised security assessment only.",
    add_completion=False,
)
console = Console()

_ETHICAL_WARNING = (
    "[bold yellow]Ethical use only.[/bold yellow] "
    "Only scan hosts and networks you have explicit authorisation to test. "
    "Unauthorised port scanning may be illegal in your jurisdiction."
)


@app.command()
def scan(
    target: str = typer.Argument(..., help="IP address, hostname, or CIDR range (max /24)."),
    ports: str = typer.Option(
        "top", "--ports", "-p",
        help="Ports to scan: 'top' (default), '1-1024', '80,443,8080', or '1-65535'.",
    ),
    threads: int = typer.Option(
        100, "--threads", "-t", min=1, max=500,
        help="Concurrent threads (1–500, default 100).",
    ),
    timeout: float = typer.Option(
        1.0, "--timeout",
        help="Per-connection timeout in seconds (default 1.0).",
    ),
    banner: bool = typer.Option(
        False, "--banner", "-b",
        help="Attempt to grab service banners from open ports.",
    ),
    rate_limit: float = typer.Option(
        0.0, "--rate-limit",
        help="Delay between connection attempts in milliseconds (default 0, disabled).",
    ),
    output: str = typer.Option(
        "terminal", "--output", "-o",
        help="Output format: terminal (default), json, or markdown.",
    ),
    export: Optional[Path] = typer.Option(
        None, "--export", "-e",
        help="Write output to this file path (requires --output json or markdown).",
    ),
) -> None:
    """Scan a host or CIDR range for open TCP ports."""
    console.print()
    console.print(f"  [bold cyan]LeightonSec Port Scanner[/bold cyan] [dim]v{__version__}[/dim]")
    console.print(f"  {_ETHICAL_WARNING}")

    # Validate output format
    if output not in ("terminal", "json", "markdown"):
        console.print("[red]--output must be one of: terminal, json, markdown[/red]")
        raise typer.Exit(1)

    if export and output == "terminal":
        console.print("[red]--export requires --output json or --output markdown[/red]")
        raise typer.Exit(1)

    # Parse inputs
    try:
        targets = parse_targets(target)
        port_list = parse_ports(ports)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    # Mandatory confirmation for any multi-host scan
    if len(targets) > 1:
        console.print(f"\n  [yellow]Range scan detected:[/yellow] {target}")
        if not confirm_scan(targets, port_list):
            console.print("  [dim]Scan cancelled.[/dim]")
            raise typer.Exit(0)
    else:
        console.print(
            f"\n  Target : [bold]{targets[0]}[/bold]  "
            f"Ports : [bold]{len(port_list)}[/bold]  "
            f"Threads : [bold]{threads}[/bold]"
        )

    console.print()

    # Run scan with progress indicator
    total = len(targets) * len(port_list)
    results = []
    start_time = time.monotonic()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"Scanning {target}...", total=total)

        def on_result(r):  # type: ignore[no-untyped-def]
            progress.advance(task)

        results = run_scan(
            targets=targets,
            ports=port_list,
            threads=threads,
            timeout=timeout,
            grab_banners=banner,
            delay_ms=rate_limit,
            on_result=on_result,
        )

    duration = time.monotonic() - start_time

    # Output
    if output == "terminal":
        print_results(results, target, duration)
    elif output == "json":
        from scanner.reporter import to_json
        json_out = to_json(results, target, duration)
        if export:
            export_results(results, target, duration, "json", export)
        else:
            console.print(json_out)
    elif output == "markdown":
        from scanner.reporter import to_markdown
        md_out = to_markdown(results, target, duration)
        if export:
            export_results(results, target, duration, "markdown", export)
        else:
            console.print(md_out)


@app.command()
def version() -> None:
    """Show the tool version and exit."""
    console.print(f"LeightonSec Port Scanner v{__version__}")


if __name__ == "__main__":
    app()
