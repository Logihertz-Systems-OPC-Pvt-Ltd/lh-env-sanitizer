# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        src.lh_env_sanitizer.exporters.table
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Rich terminal table exporter for human-readable audit findings."""

from __future__ import annotations

import io

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lh_env_sanitizer.exporters.base import BaseExporter
from lh_env_sanitizer.models import AuditResult, Severity


class TableExporter(BaseExporter):
    """Formats findings as a stylish Rich terminal table with summary statistics."""

    _SEVERITY_COLORS = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "blue",
    }

    def export(self, result: AuditResult) -> str:
        """Render the audit result as a text string formatted with ANSI or plain characters."""
        string_io = io.StringIO()
        console = Console(file=string_io, force_terminal=False, width=140)
        self.render_console(result, console)
        return string_io.getvalue()

    def render_console(self, result: AuditResult, console: Console | None = None) -> None:
        """Print the audit result directly to the provided or default Rich console."""
        out = console or Console()

        # Build summary panel
        counts = result.count_by_severity()
        summary_text = (
            f"[bold]Target:[/bold] {result.target_path} | "
            f"[bold]Scanned items:[/bold] {result.total_items_scanned} | "
            f"[bold]Total findings:[/bold] {len(result.findings)}\n"
            f"[bold red]CRITICAL:[/bold red] {counts['CRITICAL']}  "
            f"[red]HIGH:[/red] {counts['HIGH']}  "
            f"[yellow]MEDIUM:[/yellow] {counts['MEDIUM']}  "
            f"[cyan]LOW:[/cyan] {counts['LOW']}  "
            f"[blue]INFO:[/blue] {counts['INFO']}"
        )
        if result.has_failures(Severity.HIGH):
            panel_color = "red"
        elif result.findings:
            panel_color = "yellow"
        else:
            panel_color = "green"

        out.print(
            Panel(
                summary_text,
                title="[bold]lh-env Security Audit Summary[/bold]",
                border_style=panel_color,
            )
        )

        if not result.findings:
            out.print("[bold green]✔ No security issues or insecure flags detected.[/bold green]\n")
            return

        # Findings table
        table = Table(
            title="Detected Security Findings",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Severity", style="bold", no_wrap=True)
        table.add_column("Rule", no_wrap=True)
        table.add_column("Source")
        table.add_column("Key")
        table.add_column("Value (Masked)")
        table.add_column("Recommendation", style="dim")

        for finding in result.findings:
            color = self._SEVERITY_COLORS.get(finding.severity, "white")
            sev_cell = Text(finding.severity.value, style=color)

            loc = finding.source
            if finding.line_number:
                loc = f"{loc}:{finding.line_number}"

            table.add_row(
                sev_cell,
                finding.rule_id,
                loc,
                finding.key,
                finding.value_masked,
                finding.recommendation,
            )

        out.print(table)
        out.print()
