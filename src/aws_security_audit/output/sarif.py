"""SARIF 2.1.0 output, for tools that already ingest static analysis results.

Cloud resources have no file and line, so each result uses a logical
location whose fully qualified name is the resource ARN. "Could not check"
items are not results; they go in the invocation's notifications so a SARIF
viewer still shows that the scan was incomplete.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import __version__
from ..models import Severity, Status
from ..runner import ScanResult

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub-style numeric severity (0-10), used by some SARIF consumers for sorting.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def _rule(spec) -> dict[str, Any]:
    tags = ["security", "aws", spec.service] + [f"CIS-AWS-Foundations-v3.0.0-{c}" for c in spec.cis]
    return {
        "id": spec.id,
        "name": "".join(part.capitalize() for part in spec.id.split("-")),
        "shortDescription": {"text": spec.title},
        "fullDescription": {"text": spec.description},
        "help": {"text": f"Console: {spec.remediation.console}\n\nCLI: {spec.remediation.cli}"},
        "defaultConfiguration": {"level": LEVEL[spec.severity]},
        "properties": {"tags": tags, "security-severity": SECURITY_SEVERITY[spec.severity]},
    }


def build(result: ScanResult) -> dict[str, Any]:
    rule_index = {spec.id: i for i, spec in enumerate(result.checks)}
    results = []
    notifications = []
    for finding in result.findings:
        if finding.status is Status.ERROR:
            text = f"{finding.check_id} ({finding.region}) {finding.resource_arn}: {finding.message}"
            notifications.append({"level": "error", "message": {"text": text}, "descriptor": {"id": finding.check_id}})
            continue
        if finding.status is not Status.FAIL:
            continue
        entry: dict[str, Any] = {
            "ruleId": finding.check_id,
            "level": LEVEL[finding.severity],
            "message": {"text": finding.message},
            "locations": [{"logicalLocations": [{"fullyQualifiedName": finding.resource_arn, "kind": "resource"}]}],
            "properties": {
                "severity": finding.severity.value,
                "region": finding.region,
                "cis": list(finding.cis),
                "evidence": finding.evidence,
            },
        }
        if finding.check_id in rule_index:
            entry["ruleIndex"] = rule_index[finding.check_id]
        if finding.suppressed:
            entry["suppressions"] = [{"kind": "external", "justification": finding.suppression_reason or ""}]
        results.append(entry)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aws-security-audit",
                        "version": __version__,
                        "rules": [_rule(spec) for spec in result.checks],
                    }
                },
                "invocations": [
                    {
                        # The scan itself completed; unchecked items are listed as notifications.
                        "executionSuccessful": True,
                        "startTimeUtc": result.started_at.isoformat(),
                        "endTimeUtc": result.finished_at.isoformat(),
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "results": results,
                "properties": {
                    "account_id": result.account_id,
                    "regions": result.regions,
                    "note": result.note,
                    "warnings": result.warnings,
                },
            }
        ],
    }


def write(result: ScanResult, path: Path) -> None:
    path.write_text(json.dumps(build(result), indent=2, default=str) + "\n", encoding="utf-8")
