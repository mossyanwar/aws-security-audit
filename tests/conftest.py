"""Shared fixtures. Every test runs against moto with fake credentials.

The autouse fixture below replaces any AWS settings in the environment with
fake values and points the AWS config files at an empty file, so a test can
never pick up a real profile or make a real API call.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws

from aws_security_audit.context import ScanContext
from aws_security_audit.registry import get_check
from aws_security_audit.runner import ScanResult, run_scan

from .helpers import REGION

FAKE_ENV = {
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_CONFIG_FILE": os.devnull,
    "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
}



@pytest.fixture(autouse=True)
def fake_aws_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("AWS_"):
            monkeypatch.delenv(name, raising=False)
    for name, value in FAKE_ENV.items():
        monkeypatch.setenv(name, value)


@pytest.fixture
def aws():
    with mock_aws():
        yield


@pytest.fixture
def scan(aws):
    """Run some checks against the moto account and return the ScanResult."""

    def _scan(*check_ids: str, regions=(REGION,), days_later: int = 0) -> ScanResult:
        now = datetime.now(timezone.utc) + timedelta(days=days_later)
        ctx = ScanContext.from_session(boto3.Session(region_name=REGION), now=now)
        checks = [get_check(c) for c in check_ids]
        return run_scan(ctx, checks, list(regions), max_workers=4)

    return _scan
