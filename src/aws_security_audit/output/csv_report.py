"""CSV output, one row per finding, for spreadsheets and ticket imports."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ..runner import ScanResult

COLUMNS = [
    "status",
    "severity",
    "check_id",
    "title",
    "region",
    "resource_arn",
    "message",
    "cis",
    "suppressed",
    "suppression_reason",
    "remediation_cli",
    "evidence",
]

# Spreadsheet apps treat a cell starting with one of these as a formula.
# Security group names and descriptions can contain them, and those come
# from the scanned account, so such cells are prefixed with a quote.
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def write(result: ScanResult, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(COLUMNS)
        for f in result.findings:
            row = [
                f.status.label,
                f.severity.value,
                f.check_id,
                f.title,
                f.region,
                f.resource_arn,
                f.message,
                " ".join(f.cis),
                "yes" if f.suppressed else "no",
                f.suppression_reason or "",
                f.remediation.cli if f.remediation else "",
                json.dumps(f.evidence, sort_keys=True, default=str) if f.evidence else "",
            ]
            writer.writerow([safe_cell(value) for value in row])
