"""JSON report: everything the scan found, for scripts and later comparison."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..runner import ScanResult
from .common import check_summaries

SCHEMA_VERSION = 1


def build(result: ScanResult) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "aws-security-audit", "version": result.tool_version},
        "scan": {
            "account_id": result.account_id,
            "partition": result.partition,
            "caller_arn": result.caller_arn,
            "regions": result.regions,
            "started_at": result.started_at.isoformat(),
            "finished_at": result.finished_at.isoformat(),
            "duration_seconds": round((result.finished_at - result.started_at).total_seconds(), 2),
            "note": result.note,
            "warnings": result.warnings,
        },
        "summary": {
            "counts": result.counts(),
            "open_failures_by_severity": result.open_failures_by_severity(),
            "incomplete": result.incomplete,
        },
        "checks": [summary.to_dict() for summary in check_summaries(result)],
        "findings": [finding.to_dict() for finding in result.findings],
    }


def write(result: ScanResult, path: Path) -> None:
    path.write_text(json.dumps(build(result), indent=2, default=str) + "\n", encoding="utf-8")
