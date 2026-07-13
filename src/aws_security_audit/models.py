"""Data types shared by checks, the runner and the report writers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher is worse. Used for sorting and for --fail-on thresholds."""
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(value.lower())
        except ValueError:
            choices = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r}, expected one of: {choices}") from None


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    # The check ran but could not reach a verdict for this resource or region,
    # for example because of AccessDenied. This is never treated as a pass.
    ERROR = "error"

    @property
    def label(self) -> str:
        return "could not check" if self is Status.ERROR else self.value


@dataclass(frozen=True)
class Remediation:
    console: str
    cli: str

    def to_dict(self) -> dict[str, str]:
        return {"console": self.console, "cli": self.cli}


@dataclass
class Finding:
    check_id: str
    title: str
    status: Status
    severity: Severity
    resource_arn: str
    region: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)
    cis: tuple[str, ...] = ()
    remediation: Remediation | None = None
    suppressed: bool = False
    suppression_reason: str | None = None

    @property
    def is_open_failure(self) -> bool:
        """A failed check that has not been accepted through a suppression."""
        return self.status is Status.FAIL and not self.suppressed

    def sort_key(self) -> tuple:
        status_order = {Status.FAIL: 0, Status.ERROR: 1, Status.PASS: 2}
        return (
            status_order[self.status],
            -self.severity.rank,
            self.check_id,
            self.region,
            self.resource_arn,
            self.message,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "resource_arn": self.resource_arn,
            "region": self.region,
            "message": self.message,
            "evidence": self.evidence,
            "cis": list(self.cis),
            "remediation": self.remediation.to_dict() if self.remediation else None,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
        }
