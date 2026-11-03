# ==============================================================================
# Product:       lh-env-sanitizer (lh-env)
# Module:        src.lh_env_sanitizer.cli
# Role:          CLI Interface & Execution Controller
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Command Line Interface for lh-env-sanitizer.

Entry point: lh-env
Provides audit, sanitize, and scan-proc commands for configuration security auditing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from lh_env_sanitizer import __version__
from lh_env_sanitizer.auditor import EnvironmentAuditor
from lh_env_sanitizer.exporters.json_exporter import JsonExporter
from lh_env_sanitizer.exporters.sarif import SarifExporter
from lh_env_sanitizer.exporters.table import TableExporter
from lh_env_sanitizer.models import AuditResult, OutputFormat, Severity
from lh_env_sanitizer.parsers.proc_parser import ProcEnvironError
from lh_env_sanitizer.sanitizer import EnvSanitizer

# --- Exit Code Semantics ---
# Exit Code 0: Audit passed successfully with zero policy violations.
# Exit Code 1: Security findings detected meeting or exceeding failure threshold (--fail-on).
# Exit Code 2: Command execution error, invalid arguments, or unparseable input target.

app = typer.Typer(
    name="lh-env",
    help="lh-env: Configuration & Environment Security Auditor by Logihertz Systems.",
    add_completion=False,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        msg = f"[bold cyan]lh-env[/bold cyan] version [bold green]{__version__}[/bold green]"
        console.print(msg)
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-v",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = None,
) -> None:
    """lh-env-sanitizer configuration auditor entry point."""


def _handle_output(
    result: AuditResult,
    output_format: OutputFormat,
    output_path: Path | None,
) -> None:
    """Render or write audit results according to chosen format and destination."""
    if output_format == OutputFormat.JSON:
        exporter = JsonExporter()
        content = exporter.export(result)
        if output_path:
            output_path.write_text(content, encoding="utf-8")
            console.print(f"[green]✔ Audit findings written to {output_path}[/green]")
        else:
            typer.echo(content)

    elif output_format == OutputFormat.SARIF:
        exporter = SarifExporter()
        content = exporter.export(result)
        if output_path:
            output_path.write_text(content, encoding="utf-8")
            console.print(f"[green]✔ SARIF v2.1.0 report written to {output_path}[/green]")
        else:
            typer.echo(content)

    else:  # TABLE
        table_exporter = TableExporter()
        if output_path:
            content = table_exporter.export(result)
            output_path.write_text(content, encoding="utf-8")
            console.print(f"[green]✔ Summary table written to {output_path}[/green]")
        else:
            table_exporter.render_console(result, console)


@app.command(name="audit")
def audit(
    path: Annotated[
        Path,
        typer.Argument(
            help="Path to .env, docker-compose.yml, Kubernetes manifest, or directory to audit.",
            exists=True,
            readable=True,
        ),
    ],
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format: table, json, or sarif."),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Optional output file to write audit findings."),
    ] = None,
    fail_on: Annotated[
        Severity,
        typer.Option("--fail-on", help="Minimum severity threshold to trigger non-zero exit code."),
    ] = Severity.MEDIUM,
) -> None:
    """Audit configuration files for hardcoded secrets, weak JWT keys, and insecure flags."""
    auditor = EnvironmentAuditor()
    try:
        result = auditor.audit_path(path)
    except Exception as err:
        console.print(f"[bold red]Error auditing path '{path}':[/bold red] {err}")
        raise typer.Exit(code=2) from err

    _handle_output(result, output_format, output)

    if result.has_failures(fail_on):
        raise typer.Exit(code=1)


@app.command(name="sanitize")
def sanitize(
    env_file: Annotated[
        Path,
        typer.Argument(
            help="Path to live .env file to sanitize into .env.example.",
            exists=True,
            readable=True,
        ),
    ],
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Optional destination path for sanitized template."),
    ] = None,
) -> None:
    """Sanitize live .env file into a deterministic .env.example template with type hints."""
    sanitizer = EnvSanitizer()
    try:
        sanitized_content = sanitizer.sanitize_file(env_file, output_path=output)
    except Exception as err:
        console.print(f"[bold red]Error sanitizing '{env_file}':[/bold red] {err}")
        raise typer.Exit(code=2) from err

    if output:
        console.print(f"[green]✔ Sanitized template generated at: [bold]{output}[/bold][/green]")
    else:
        typer.echo(sanitized_content, nl=False)


@app.command(name="scan-proc")
def scan_proc(
    pid: Annotated[
        int,
        typer.Option("--pid", "-p", help="Process ID to inspect in /proc/<pid>/environ."),
    ],
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format: table, json, or sarif."),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Optional output file to write scan findings."),
    ] = None,
    environ_file: Annotated[
        Optional[Path],
        typer.Option(
            "--environ-file",
            help="Custom environ file path (internal / testing use).",
            hidden=True,
        ),
    ] = None,
    fail_on: Annotated[
        Severity,
        typer.Option("--fail-on", help="Minimum severity threshold to trigger non-zero exit code."),
    ] = Severity.MEDIUM,
) -> None:
    """Inspect Linux /proc/<pid>/environ blocks for exposed plaintext credentials."""
    auditor = EnvironmentAuditor()
    try:
        result = auditor.audit_proc(pid, environ_file=environ_file)
    except ProcEnvironError as err:
        console.print(f"[bold red]Scan process failed:[/bold red] {err}")
        raise typer.Exit(code=2) from err
    except Exception as err:
        console.print(f"[bold red]Unexpected error inspecting PID {pid}:[/bold red] {err}")
        raise typer.Exit(code=2) from err

    _handle_output(result, output_format, output)

    if result.has_failures(fail_on):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
