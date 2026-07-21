"""Command line interface."""

from __future__ import annotations

from typing import Annotated, Optional

import boto3
import typer
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound
from rich.console import Console
from rich.table import Table

from . import __version__
from .context import ScanContext
from .output import console as console_output
from .regions import resolve_regions
from .registry import all_checks, select_checks
from .runner import run_scan

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Read-only security checks for an AWS account you own.",
)
out = Console()
err = Console(stderr=True)


def _version(value: bool) -> None:
    if value:
        out.print(f"aws-security-audit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool], typer.Option("--version", callback=_version, is_eager=True, help="Show the version.")
    ] = None,
) -> None:
    pass


@app.command("list-checks")
def list_checks() -> None:
    """List every check with its severity and CIS mapping."""
    table = Table(header_style="bold")
    for column in ("ID", "Service", "Severity", "Scope", "CIS v3.0.0", "Title"):
        table.add_column(column, overflow="fold")
    checks = all_checks()
    for spec in checks:
        table.add_row(
            spec.id, spec.service, spec.severity.value, spec.scope.value, ", ".join(spec.cis) or "-", spec.title
        )
    out.print(table)
    out.print(f"{len(checks)} checks")


@app.command()
def scan(
    profile: Annotated[Optional[str], typer.Option(help="AWS CLI profile to use.")] = None,
    region: Annotated[
        Optional[list[str]],
        typer.Option("--region", "-r", help="Region to scan. Repeat for several. Default: all enabled regions."),
    ] = None,
    home_region: Annotated[
        Optional[str], typer.Option(help="Region used for global services. Default: the profile's region or us-east-1.")
    ] = None,
    check: Annotated[Optional[list[str]], typer.Option("--check", "-c", help="Only run this check id.")] = None,
    skip_check: Annotated[Optional[list[str]], typer.Option("--skip-check", help="Do not run this check id.")] = None,
    service: Annotated[Optional[list[str]], typer.Option("--service", "-s", help="Only run checks for a service.")] = None,
    workers: Annotated[int, typer.Option(min=1, max=32, help="Threads used to run checks.")] = 8,
    show_passed: Annotated[bool, typer.Option(help="Include passed items in the console table.")] = False,
) -> None:
    """Scan an AWS account. Makes read-only API calls only."""
    try:
        checks = select_checks(check or (), skip_check or (), service or ())
    except KeyError as exc:
        err.print(f"error: {exc.args[0]}")
        raise typer.Exit(2)
    if not checks:
        err.print("error: no checks selected")
        raise typer.Exit(2)

    try:
        session = boto3.Session(profile_name=profile)
        scan_ctx = ScanContext.from_session(session, home_region=home_region)
    except ProfileNotFound as exc:
        err.print(f"error: {exc}")
        raise typer.Exit(2)
    except NoCredentialsError:
        err.print("error: no AWS credentials found. Use --profile or configure the AWS CLI first.")
        raise typer.Exit(2)
    except (ClientError, BotoCoreError) as exc:
        err.print(f"error: could not identify the account with sts:GetCallerIdentity: {exc}")
        raise typer.Exit(2)

    regions, warnings = resolve_regions(scan_ctx, region)
    err.print(f"Scanning account {scan_ctx.account_id} with {len(checks)} checks in {len(regions)} region(s)...")
    result = run_scan(scan_ctx, checks, regions, max_workers=workers)
    result.warnings.extend(warnings)
    console_output.render(result, out, show_passed=show_passed)


if __name__ == "__main__":
    app()
