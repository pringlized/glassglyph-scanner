"""Glassglyph Scanner command-line interface.

Usage:
    glassglyph-scanner scan FILE           # scan a file
    glassglyph-scanner scan -               # scan stdin
    glassglyph-scanner scan FILE --json     # machine-readable output
    glassglyph-scanner scan FILE --quiet    # exit code only, no output

Exit codes:
    0 — clean (no findings)
    1 — findings present but not critical (stripped or flagged)
    2 — critical findings (content should be blocked)
    64 — usage error
"""
from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

import typer

from . import __version__
from .sanitizer import sanitize

app = typer.Typer(
    name="glassglyph-scanner",
    help="Scan text for invisible unicode and homoglyph attacks.",
    add_completion=False,
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"glassglyph-scanner {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Glassglyph Scanner — character-level security scanner."""


@app.command()
def scan(
    path: str = typer.Argument(..., help="Path to file, or '-' for stdin"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of human-readable output"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress output; communicate only via exit code"),
) -> None:
    """Scan a file (or stdin) for security issues."""
    if path == "-":
        content = sys.stdin.read()
        source = "<stdin>"
    else:
        p = Path(path)
        if not p.exists():
            typer.echo(f"glassglyph-scanner: file not found: {path}", err=True)
            raise typer.Exit(code=64)
        content = p.read_text()
        source = str(p)

    result = sanitize(content)

    if json_output:
        typer.echo(json.dumps(_result_to_dict(result, source), indent=2))
    elif not quiet:
        _print_human(result, source)

    if result.has_critical_findings:
        raise typer.Exit(code=2)
    if result.findings:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


def _result_to_dict(result, source: str) -> dict:
    return {
        "source": source,
        "clean": result.clean,
        "has_critical_findings": result.has_critical_findings,
        "was_modified": result.was_modified,
        "scan_duration_ms": result.scan_duration_ms,
        "findings": [asdict(f) for f in result.findings],
        "sanitized_content": result.sanitized_content if result.was_modified else None,
    }


def _print_human(result, source: str) -> None:
    if result.clean:
        typer.secho(f"✓ {source}: clean ({result.scan_duration_ms}ms)", fg=typer.colors.GREEN)
        return

    if result.has_critical_findings:
        typer.secho(f"✗ {source}: BLOCKED ({result.scan_duration_ms}ms)", fg=typer.colors.RED, bold=True)
    elif result.was_modified:
        typer.secho(f"⚠ {source}: MODIFIED — characters stripped ({result.scan_duration_ms}ms)", fg=typer.colors.YELLOW)
    else:
        typer.secho(f"⚠ {source}: FLAGGED ({result.scan_duration_ms}ms)", fg=typer.colors.YELLOW)

    for finding in result.findings:
        colour = {
            "critical": typer.colors.RED,
            "high": typer.colors.YELLOW,
            "medium": typer.colors.CYAN,
            "low": typer.colors.WHITE,
        }.get(finding.severity, typer.colors.WHITE)
        typer.secho(
            f"  [{finding.severity:<8}] {finding.threat_category:<18} {finding.action_taken:<9} {finding.description}",
            fg=colour,
        )


if __name__ == "__main__":
    app()
