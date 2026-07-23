"""Small helpers for picking findings out of a scan result."""

from __future__ import annotations

from aws_security_audit.models import Status
from aws_security_audit.runner import ScanResult

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def findings(result: ScanResult, status: Status, check_id: str | None = None):
    return [f for f in result.findings if f.status is status and (check_id is None or f.check_id == check_id)]


def failed(result: ScanResult, check_id: str | None = None):
    return findings(result, Status.FAIL, check_id)


def passed(result: ScanResult, check_id: str | None = None):
    return findings(result, Status.PASS, check_id)


def errors(result: ScanResult, check_id: str | None = None):
    return findings(result, Status.ERROR, check_id)
