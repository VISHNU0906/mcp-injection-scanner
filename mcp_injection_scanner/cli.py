"""CLI entry point — `mcp-scan [OPTIONS] <server_url>`."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from mcp_injection_scanner.models import Severity
from mcp_injection_scanner.report import render_json, render_sarif, render_terminal
from mcp_injection_scanner.scanner import MCPScanner

app = typer.Typer(
    name="mcp-scan",
    help="Security scanner for Model Context Protocol servers.",
    add_completion=False,
)
console = Console(stderr=True)


@app.command()
def scan(
    server_url: str = typer.Argument(..., help="MCP server URL to scan"),
    output: str = typer.Option("terminal", "-o", "--output", help="Output format: terminal | json | sarif"),
    out_file: Optional[Path] = typer.Option(None, "-f", "--file", help="Write output to file"),
    timeout: float = typer.Option(30.0, "--timeout", help="HTTP request timeout (seconds)"),
    no_resources: bool = typer.Option(False, "--no-resources", help="Skip resource content scanning"),
    strict: bool = typer.Option(False, "--strict", help="Enable additional heuristic checks"),
    min_severity: str = typer.Option("info", "--min-severity", help="Minimum severity to report"),
    header: list[str] = typer.Option([], "-H", "--header", help="Extra HTTP headers (key:value)"),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit code 1 if findings at this severity or above"),
    manifest_file: Optional[Path] = typer.Option(None, "--manifest", help="Scan a local manifest JSON instead of live server"),
) -> None:
    """Scan an MCP server for injection vulnerabilities."""
    headers: dict[str, str] = {}
    for h in header:
        if ":" not in h:
            console.print(f"[red]Invalid header format (expected key:value): {h}[/red]")
            raise typer.Exit(2)
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    scanner = MCPScanner(
        timeout=timeout,
        check_resources=not no_resources,
        strict=strict,
        headers=headers,
    )

    console.print(f"[dim]Scanning {server_url}...[/dim]")

    try:
        if manifest_file:
            manifest = json.loads(manifest_file.read_text())
            result = scanner.scan_manifest(server_url, manifest)
        else:
            result = scanner.scan_url(server_url)
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        raise typer.Exit(3)

    # Filter by minimum severity
    try:
        min_sev = Severity(min_severity.lower())
    except ValueError:
        console.print(f"[red]Invalid severity: {min_severity}. Choose from: {[s.value for s in Severity]}[/red]")
        raise typer.Exit(2)

    severity_rank = {s: i for i, s in enumerate(Severity)}
    result.findings = [f for f in result.findings if severity_rank[f.severity] <= severity_rank[min_sev]]

    # Render
    if output == "json":
        rendered = render_json(result)
    elif output == "sarif":
        rendered = render_sarif(result)
    else:
        if out_file:
            file_console = Console(file=out_file.open("w"))
            render_terminal(result, file_console)
        else:
            render_terminal(result, Console())
        _exit_code(result, fail_on)
        return

    if out_file:
        out_file.write_text(rendered)
        console.print(f"[green]Report written to {out_file}[/green]")
    else:
        print(rendered)

    _exit_code(result, fail_on)


def _exit_code(result: "ScanResult", fail_on: str) -> None:  # type: ignore[name-defined]
    from mcp_injection_scanner.models import ScanResult  # noqa: F401

    try:
        threshold = Severity(fail_on.lower())
    except ValueError:
        return

    severity_rank = {s: i for i, s in enumerate(Severity)}
    threshold_rank = severity_rank[threshold]

    for finding in result.findings:
        if severity_rank[finding.severity] <= threshold_rank:
            raise typer.Exit(1)


@app.command()
def version() -> None:
    """Print the scanner version."""
    from mcp_injection_scanner import __version__
    typer.echo(f"mcp-injection-scanner {__version__}")


if __name__ == "__main__":
    app()
