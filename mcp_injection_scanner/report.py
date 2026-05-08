"""Report rendering — terminal (Rich) and JSON output."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_injection_scanner.models import ScanResult, Severity

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

_SEVERITY_ICONS = {
    Severity.CRITICAL: "[!]",
    Severity.HIGH: "[H]",
    Severity.MEDIUM: "[M]",
    Severity.LOW: "[L]",
    Severity.INFO: "[I]",
}


def render_terminal(result: ScanResult, console: Console | None = None) -> None:
    if console is None:
        console = Console()

    # Header
    status_color = "green" if result.passed else "red"
    status_text = "PASSED" if result.passed else "FAILED"

    console.print()
    console.print(
        Panel(
            f"[bold]MCP Injection Scanner[/bold]\n"
            f"Target: [cyan]{result.server_url}[/cyan]\n"
            f"Server: {result.server_name or 'unknown'} {result.server_version or ''}\n"
            f"Scanned: {result.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"Duration: {result.scan_duration_ms:.0f}ms",
            title=f"[{status_color}] {status_text} [/{status_color}]",
            border_style=status_color,
        )
    )

    # Stats row
    stats_table = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    stats_table.add_column("Metric", style="dim")
    stats_table.add_column("Count")
    stats_table.add_row("Tools scanned", str(result.tools_scanned))
    stats_table.add_row("Resources scanned", str(result.resources_scanned))
    stats_table.add_row("Prompts scanned", str(result.prompts_scanned))
    stats_table.add_row("Total findings", str(result.total_findings))
    console.print(stats_table)

    if not result.findings:
        console.print("[green]No findings — server appears clean.[/green]")
        return

    # Severity summary
    summary_table = Table(
        title="Findings Summary",
        box=box.ROUNDED,
        show_header=True,
    )
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")
    for severity in Severity:
        count = sum(1 for f in result.findings if f.severity == severity)
        if count:
            summary_table.add_row(
                Text(_SEVERITY_ICONS[severity] + " " + severity.value.upper(), style=_SEVERITY_COLORS[severity]),
                str(count),
            )
    console.print(summary_table)
    console.print()

    # Individual findings
    for i, finding in enumerate(result.findings, 1):
        color = _SEVERITY_COLORS[finding.severity]
        icon = _SEVERITY_ICONS[finding.severity]

        console.print(
            Panel(
                f"[bold]Description:[/bold] {finding.description}\n\n"
                f"[bold]Evidence:[/bold]\n[dim]{finding.evidence[:300]}[/dim]\n\n"
                f"[bold]Remediation:[/bold] {finding.remediation}"
                + (f"\n[bold]CWE:[/bold] {finding.cwe}" if finding.cwe else ""),
                title=f"[{color}]{icon} [{i}] {finding.title}[/{color}]",
                border_style=color,
            )
        )


def render_json(result: ScanResult) -> str:
    def _default(obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    return json.dumps(result.model_dump(), indent=2, default=_default)


def render_sarif(result: ScanResult) -> str:
    """Output findings as SARIF v2.1.0 for IDE/CI integration."""
    rules = []
    results = []

    rule_ids: set[str] = set()
    for finding in result.findings:
        rule_id = f"MCP{finding.severity.value[:3].upper()}{finding.cwe or '000'}"
        if rule_id not in rule_ids:
            rule_ids.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "helpUri": "https://github.com/VISHNU0906/mcp-injection-scanner/wiki",
                    "properties": {
                        "tags": ["security", "injection", "mcp"],
                        "severity": finding.severity.value,
                    },
                }
            )

        level_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }
        results.append(
            {
                "ruleId": rule_id,
                "level": level_map[finding.severity],
                "message": {"text": finding.description},
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "name": finding.tool_name or finding.resource_uri or "server",
                                "kind": "tool" if finding.tool_name else "resource",
                            }
                        ]
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-injection-scanner",
                        "version": "0.3.1",
                        "informationUri": "https://github.com/VISHNU0906/mcp-injection-scanner",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
