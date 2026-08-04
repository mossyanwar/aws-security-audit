"""Summaries shared by the report writers."""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Status
from ..registry import CheckSpec
from ..runner import ScanResult


@dataclass
class CheckSummary:
    spec: CheckSpec
    passed: int = 0
    failed: int = 0
    errors: int = 0
    suppressed: int = 0

    @property
    def outcome(self) -> str:
        """One word for the check as a whole. Failures win over errors, errors over passes."""
        if self.failed:
            return "fail"
        if self.errors:
            return "could not check"
        if self.suppressed:
            return "suppressed"
        if self.passed:
            return "pass"
        return "no resources"

    def to_dict(self) -> dict:
        return {
            "id": self.spec.id,
            "title": self.spec.title,
            "service": self.spec.service,
            "severity": self.spec.severity.value,
            "scope": self.spec.scope.value,
            "cis": list(self.spec.cis),
            "description": self.spec.description,
            "outcome": self.outcome,
            "results": {
                "pass": self.passed,
                "fail": self.failed,
                "error": self.errors,
                "suppressed": self.suppressed,
            },
        }


def check_summaries(result: ScanResult) -> list[CheckSummary]:
    summaries = {spec.id: CheckSummary(spec) for spec in result.checks}
    for finding in result.findings:
        summary = summaries.get(finding.check_id)
        if summary is None:
            continue
        if finding.suppressed:
            summary.suppressed += 1
        elif finding.status is Status.FAIL:
            summary.failed += 1
        elif finding.status is Status.ERROR:
            summary.errors += 1
        else:
            summary.passed += 1
    order = {"fail": 0, "could not check": 1, "suppressed": 2, "pass": 3, "no resources": 4}
    return sorted(summaries.values(), key=lambda s: (order[s.outcome], -s.spec.severity.rank, s.spec.id))
