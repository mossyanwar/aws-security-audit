"""Run selected checks across regions with a thread pool."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from botocore.exceptions import BotoCoreError, ClientError

from . import __version__
from .context import GLOBAL_REGION, CheckRun, ScanContext
from .errors import classify
from .models import Finding, Severity, Status
from .registry import CheckSpec, Scope


@dataclass
class Execution:
    """One check run in one region (or once, for global checks)."""

    check_id: str
    region: str
    duration_seconds: float
    findings: int
    error: str | None = None


@dataclass
class ScanResult:
    account_id: str
    partition: str
    regions: list[str]
    checks: list[CheckSpec]
    findings: list[Finding]
    executions: list[Execution]
    started_at: datetime
    finished_at: datetime
    tool_version: str = __version__
    caller_arn: str | None = None
    # Free text shown at the top of every report, e.g. that a scan ran against a mock.
    note: str | None = None
    warnings: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        counts = {"pass": 0, "fail": 0, "error": 0, "suppressed": 0}
        for f in self.findings:
            if f.suppressed:
                counts["suppressed"] += 1
            else:
                counts[f.status.value] += 1
        return counts

    def open_failures_by_severity(self) -> dict[str, int]:
        result = {s.value: 0 for s in Severity}
        for f in self.findings:
            if f.is_open_failure:
                result[f.severity.value] += 1
        return result

    def has_open_failure_at_or_above(self, threshold: Severity) -> bool:
        return any(f.is_open_failure and f.severity.rank >= threshold.rank for f in self.findings)

    @property
    def incomplete(self) -> bool:
        return any(f.status is Status.ERROR for f in self.findings)


def _execute(scan: ScanContext, spec: CheckSpec, region: str) -> tuple[list[Finding], Execution]:
    run = CheckRun(scan, spec, region)
    started = time.monotonic()
    error = None
    try:
        spec.func(run)
    except (ClientError, BotoCoreError) as exc:
        # The whole check failed, usually on its first list/describe call.
        run.could_not_check(scan.account_arn, exc)
        error = classify(exc).describe()
    except Exception as exc:  # noqa: BLE001 - a bug in one check must not stop the scan
        run.could_not_check(scan.account_arn, exc)
        error = f"internal error in check: {type(exc).__name__}: {exc}"
    duration = time.monotonic() - started
    return run.findings, Execution(spec.id, region, round(duration, 3), len(run.findings), error)


def plan(checks: list[CheckSpec], regions: list[str]) -> list[tuple[CheckSpec, str]]:
    tasks: list[tuple[CheckSpec, str]] = []
    for spec in checks:
        if spec.scope is Scope.GLOBAL:
            tasks.append((spec, GLOBAL_REGION))
        else:
            tasks.extend((spec, region) for region in regions)
    return tasks


def run_scan(
    scan: ScanContext,
    checks: list[CheckSpec],
    regions: list[str],
    max_workers: int = 8,
    on_progress: Callable[[Execution], None] | None = None,
) -> ScanResult:
    started_at = datetime.now(timezone.utc)
    findings: list[Finding] = []
    executions: list[Execution] = []
    tasks = plan(checks, regions)
    with ThreadPoolExecutor(max_workers=max(1, max_workers), thread_name_prefix="check") as pool:
        futures = [pool.submit(_execute, scan, spec, region) for spec, region in tasks]
        for future in as_completed(futures):
            task_findings, execution = future.result()
            findings.extend(task_findings)
            executions.append(execution)
            if on_progress:
                on_progress(execution)
    findings.sort(key=Finding.sort_key)
    executions.sort(key=lambda e: (e.check_id, e.region))
    return ScanResult(
        account_id=scan.account_id,
        partition=scan.partition,
        regions=list(regions),
        checks=list(checks),
        findings=findings,
        executions=executions,
        started_at=started_at,
        finished_at=datetime.now(timezone.utc),
        caller_arn=scan.caller_arn,
    )
