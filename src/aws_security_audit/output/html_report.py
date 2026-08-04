"""Self-contained HTML report: one file, inline CSS, no external requests."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from jinja2 import Environment

from ..models import Status
from ..runner import ScanResult
from .common import check_summaries


def _environment() -> Environment:
    # Autoescape matters here: resource names, tags and policy text come from
    # the account being scanned and must never be able to inject markup.
    return Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True)


def render(result: ScanResult) -> str:
    source = files("aws_security_audit").joinpath("templates/report.html.j2").read_text(encoding="utf-8")
    template = _environment().from_string(source)
    findings = result.findings
    return template.render(
        r=result,
        summaries=check_summaries(result),
        counts=result.counts(),
        by_sev=result.open_failures_by_severity(),
        duration=round((result.finished_at - result.started_at).total_seconds(), 1),
        failures=[f for f in findings if f.is_open_failure],
        errors=[f for f in findings if f.status is Status.ERROR],
        suppressed=[f for f in findings if f.suppressed],
        passed=[f for f in findings if f.status is Status.PASS],
    )


def write(result: ScanResult, path: Path) -> None:
    path.write_text(render(result), encoding="utf-8")
