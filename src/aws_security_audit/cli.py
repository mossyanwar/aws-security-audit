"""Command line interface."""

from __future__ import annotations

from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import boto3
import typer
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from . import __version__
from .context import ScanContext
from .exitcodes import EXIT_USAGE, exit_code
from .models import Severity
from .output import console as console_output
from .output import csv_report, html_report, json_report, sarif
from .regions import resolve_regions
from .registry import all_checks, select_checks
from .runner import ScanResult, plan, run_scan
from .suppressions import SuppressionError
from .suppressions import apply as apply_suppressions
from .suppressions import load as load_suppressions

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Read-only security checks for an AWS account you own.",
)
out = Console()
err = Console(stderr=True)


class FailOn(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
    none = "none"


def write_reports(
    result: ScanResult,
    json_path: Path | None = None,
    html_path: Path | None = None,
    sarif_path: Path | None = None,
    csv_path: Path | None = None,
) -> list[Path]:
    written = []
    for path, writer in (
        (json_path, json_report.write),
        (html_path, html_report.write),
        (sarif_path, sarif.write),
        (csv_path, csv_report.write),
    ):
        if path is None:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        writer(result, path)
        written.append(path)
    return written


def _version(value: bool) -> None:
    if value:
        out.print(f"aws-security-audit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None, typer.Option("--version", callback=_version, is_eager=True, help="Show the version.")
    ] = None,
) -> None:
    pass


@app.command("list-checks")
def list_checks() -> None:
    """List every check with its severity and CIS mapping."""
    table = Table(header_style="bold")
    table.add_column("ID", no_wrap=True)
    for column in ("Service", "Severity", "Scope", "CIS v3.0.0", "Title"):
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
    profile: Annotated[str | None, typer.Option(help="AWS CLI profile to use.")] = None,
    region: Annotated[
        list[str] | None,
        typer.Option("--region", "-r", help="Region to scan. Repeat for several. Default: all enabled regions."),
    ] = None,
    home_region: Annotated[
        str | None, typer.Option(help="Region used for global services. Default: the profile's region or us-east-1.")
    ] = None,
    check: Annotated[list[str] | None, typer.Option("--check", "-c", help="Only run this check id.")] = None,
    skip_check: Annotated[list[str] | None, typer.Option("--skip-check", help="Do not run this check id.")] = None,
    service: Annotated[list[str] | None, typer.Option("--service", "-s", help="Only run checks for a service.")] = None,
    workers: Annotated[int, typer.Option(min=1, max=32, help="Threads used to run checks.")] = 8,
    show_passed: Annotated[bool, typer.Option(help="Include passed items in the console table.")] = False,
    json_path: Annotated[Path | None, typer.Option("--json", help="Write a JSON report to this path.")] = None,
    html_path: Annotated[Path | None, typer.Option("--html", help="Write a self-contained HTML report.")] = None,
    sarif_path: Annotated[Path | None, typer.Option("--sarif", help="Write a SARIF 2.1.0 report.")] = None,
    csv_path: Annotated[Path | None, typer.Option("--csv", help="Write a CSV report.")] = None,
    fail_on: Annotated[
        FailOn, typer.Option(help="Exit 1 if any open failure is at or above this severity.")
    ] = FailOn.none,
    fail_on_incomplete: Annotated[
        bool, typer.Option(help="Exit 3 if anything could not be checked (for example AccessDenied).")
    ] = False,
    suppressions: Annotated[
        Path | None, typer.Option(help="YAML file of accepted findings, each with a reason and expiry date.")
    ] = None,
) -> None:
    """Scan an AWS account. Makes read-only API calls only."""
    try:
        checks = select_checks(check or (), skip_check or (), service or ())
    except KeyError as exc:
        err.print(f"error: {exc.args[0]}")
        raise typer.Exit(EXIT_USAGE) from None
    if not checks:
        err.print("error: no checks selected")
        raise typer.Exit(EXIT_USAGE)

    # Read the suppressions before touching AWS, so a typo fails fast.
    accepted, suppression_warnings = [], []
    if suppressions is not None:
        try:
            accepted, suppression_warnings = load_suppressions(
                suppressions, {spec.id for spec in all_checks()}, date.today()
            )
        except SuppressionError as exc:
            err.print(f"error: {exc}")
            raise typer.Exit(EXIT_USAGE) from None

    try:
        session = boto3.Session(profile_name=profile)
        scan_ctx = ScanContext.from_session(session, home_region=home_region)
    except ProfileNotFound as exc:
        err.print(f"error: {exc}")
        raise typer.Exit(EXIT_USAGE) from None
    except NoCredentialsError:
        err.print("error: no AWS credentials found. Use --profile or configure the AWS CLI first.")
        raise typer.Exit(EXIT_USAGE) from None
    except (ClientError, BotoCoreError) as exc:
        err.print(f"error: could not identify the account with sts:GetCallerIdentity: {exc}")
        raise typer.Exit(EXIT_USAGE) from None

    regions, warnings = resolve_regions(scan_ctx, region)
    err.print(f"Scanning account {scan_ctx.account_id} with {len(checks)} checks in {len(regions)} region(s)...")
    # A progress bar on stderr, only when it is a terminal, so piped output stays clean.
    with Progress(
        TextColumn("Running checks"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=err,
        transient=True,
        disable=not err.is_terminal,
    ) as progress:
        task = progress.add_task("checks", total=len(plan(checks, regions)))
        result = run_scan(scan_ctx, checks, regions, max_workers=workers, on_progress=lambda _: progress.advance(task))
    result.warnings.extend(warnings)
    result.warnings.extend(suppression_warnings)
    result.warnings.extend(apply_suppressions(result.findings, accepted, {spec.id for spec in checks}))
    console_output.render(result, out, show_passed=show_passed)
    for path in write_reports(result, json_path, html_path, sarif_path, csv_path):
        err.print(f"Wrote {path}")
    threshold = None if fail_on is FailOn.none else Severity(fail_on.value)
    raise typer.Exit(exit_code(result, threshold, fail_on_incomplete))


@app.command()
def demo(
    output_dir: Annotated[Path, typer.Option(help="Where to write the sample reports.")] = Path("sample-report"),
    workers: Annotated[int, typer.Option(min=1, max=32, help="Threads used to run checks.")] = 4,
) -> None:
    """Build a misconfigured mock account in moto, scan it and write sample reports.

    Runs entirely inside moto with fake credentials; no real AWS calls are made.
    """
    from .demo import DemoUnavailable, scan_demo_account, write_demo_reports

    try:
        result, _, planted = scan_demo_account(workers)
    except DemoUnavailable as exc:
        err.print(f"error: {exc}")
        raise typer.Exit(EXIT_USAGE) from None
    console_output.render(result, out)
    for path in write_demo_reports(result, planted, output_dir):
        err.print(f"Wrote {path}")


if __name__ == "__main__":
    app()
