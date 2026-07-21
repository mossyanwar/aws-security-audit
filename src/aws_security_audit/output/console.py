"""Console output using rich tables."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..models import Severity, Status
from ..runner import ScanResult

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

STATUS_STYLE = {Status.FAIL: "red", Status.ERROR: "magenta", Status.PASS: "green"}


def render(result: ScanResult, console: Console, show_passed: bool = False) -> None:
    if result.note:
        console.print(Text(result.note, style="bold"))
    console.print(
        f"Account {result.account_id} | {len(result.checks)} checks | "
        f"{len(result.regions)} region(s): {', '.join(result.regions)}"
    )
    for warning in result.warnings:
        console.print(Text(f"warning: {warning}", style="yellow"))

    rows = [f for f in result.findings if show_passed or f.status is not Status.PASS]
    if rows:
        table = Table(show_lines=False, header_style="bold", expand=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Check", no_wrap=True)
        table.add_column("Region", no_wrap=True)
        table.add_column("Resource", overflow="fold", ratio=2)
        table.add_column("Finding", overflow="fold", ratio=3)
        for f in rows:
            status = "suppressed" if f.suppressed else f.status.label
            table.add_row(
                Text(f.severity.value, style=SEVERITY_STYLE[f.severity]),
                Text(status, style="dim" if f.suppressed else STATUS_STYLE[f.status]),
                f.check_id,
                f.region,
                f.resource_arn,
                f.message,
            )
        console.print(table)
    else:
        console.print("No failed or unchecked items.")

    counts = result.counts()
    by_sev = result.open_failures_by_severity()
    console.print(
        f"\n{counts['fail']} failed, {counts['pass']} passed, "
        f"{counts['error']} could not be checked, {counts['suppressed']} suppressed"
    )
    console.print(
        "Open failures by severity: "
        + ", ".join(f"{sev} {by_sev[sev]}" for sev in ("critical", "high", "medium", "low", "info"))
    )
    if counts["error"]:
        console.print(
            Text(
                f"{counts['error']} item(s) could not be checked. These are not passes; "
                "see the report for the error behind each one.",
                style="magenta",
            )
        )
