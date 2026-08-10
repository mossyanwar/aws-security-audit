"""The demo account, end to end, plus a check that the IAM policy matches the code.

The demo scan exercises every check against a moto account with known
problems, so it doubles as an integration test.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from aws_security_audit.context import is_read_only_operation
from aws_security_audit.demo import DEMO_NOTE, scan_demo_account, write_demo_reports
from aws_security_audit.models import Severity, Status
from aws_security_audit.registry import all_checks

POLICY_PATH = Path(__file__).parent.parent / "iam" / "scanner-policy.json"

# Where the IAM action name differs from "<service>:<Operation>".
ACTION_NAMES = {
    ("s3", "ListBuckets"): "s3:ListAllMyBuckets",
    ("s3", "GetBucketEncryption"): "s3:GetEncryptionConfiguration",
    ("s3", "GetPublicAccessBlock"): "s3:GetBucketPublicAccessBlock",
    ("s3control", "GetPublicAccessBlock"): "s3:GetAccountPublicAccessBlock",
}
# Used by the CLI when no --region is given; the demo passes regions explicitly.
NOT_EXERCISED_BY_DEMO = {"ec2:DescribeRegions"}


@pytest.fixture(scope="module")
def demo():
    result, operations, planted = scan_demo_account(workers=4)
    return result, operations, planted


def fails(result, check_id):
    return [f for f in result.findings if f.check_id == check_id and f.status is Status.FAIL]


def passes(result, check_id):
    return [f for f in result.findings if f.check_id == check_id and f.status is Status.PASS]


def test_demo_finds_the_planted_problems(demo):
    result, _, _ = demo
    assert fails(result, "iam-root-mfa")
    assert [f.resource_arn for f in fails(result, "iam-user-console-mfa")] == ["arn:aws:iam::123456789012:user/alice"]
    assert [f.resource_arn for f in fails(result, "iam-user-admin-policy")] == [
        "arn:aws:iam::123456789012:user/deploy-bot"
    ]
    [public] = fails(result, "s3-bucket-policy-public")
    assert public.resource_arn == "arn:aws:s3:::demo-public-assets"
    assert public.severity is Severity.CRITICAL
    sg = {f.message.split("(")[1].split(")")[0]: f.cis for f in fails(result, "ec2-sg-open-to-internet")}
    assert sg == {"legacy-admin": ("5.2", "5.3"), "reporting-db": ()}
    assert [f.region for f in fails(result, "ec2-ebs-default-encryption")] == ["us-east-1"]
    assert len(fails(result, "ec2-public-amis-snapshots")) == 2
    assert fails(result, "cloudtrail-multi-region")[0].evidence["problems"] == {"org-audit": ["logging is stopped"]}
    assert [f.resource_arn.split(":")[-1] for f in fails(result, "rds-public-access")] == ["orders-db"]
    assert [f.region for f in fails(result, "guardduty-enabled")] == ["us-east-1"]
    assert [f.region for f in fails(result, "config-recorder-enabled")] == ["us-east-1"]


def test_demo_passes_what_was_set_up_properly(demo):
    result, _, _ = demo
    assert [f.resource_arn for f in passes(result, "iam-user-console-mfa")] == ["arn:aws:iam::123456789012:user/bob"]
    app_data = [f for f in result.findings if f.resource_arn == "arn:aws:s3:::demo-app-data"]
    assert app_data and all(f.status is Status.PASS for f in app_data)
    assert [f.resource_arn.split(":")[-1] for f in passes(result, "rds-storage-encrypted")] == ["billing-db"]
    assert [f.region for f in passes(result, "kms-key-rotation")] == ["eu-west-2"]
    assert [f.region for f in passes(result, "ec2-imdsv2-required")] == ["eu-west-2"]


def test_every_check_ran_and_nothing_was_left_unchecked(demo):
    result, _, _ = demo
    assert {f.check_id for f in result.findings} == {spec.id for spec in all_checks()}
    assert not [f for f in result.findings if f.status is Status.ERROR]
    assert result.note == DEMO_NOTE


def test_demo_suppression_is_applied(demo):
    result, _, _ = demo
    [suppressed] = [f for f in result.findings if f.suppressed]
    assert suppressed.resource_arn == "arn:aws:s3:::demo-access-logs"
    assert "logging" in suppressed.message


def test_every_api_call_is_a_read(demo):
    _, operations, _ = demo
    assert operations
    assert all(is_read_only_operation(op) for _, op in operations)


def test_scanner_policy_covers_every_call_and_nothing_more(demo):
    _, operations, _ = demo
    policy = json.loads(POLICY_PATH.read_text())
    allowed = set(policy["Statement"][0]["Action"])
    used = {ACTION_NAMES.get((service, op), f"{service}:{op}") for service, op in operations}
    assert used - allowed == set(), "calls missing from iam/scanner-policy.json"
    assert allowed - used - NOT_EXERCISED_BY_DEMO == set(), "actions in the policy that no check uses"


def test_demo_reports_are_written_and_labelled(demo, tmp_path):
    result, _, planted = demo
    written = write_demo_reports(result, planted, tmp_path)
    assert {p.name for p in written} == {
        "report.json",
        "report.html",
        "report.sarif",
        "report.csv",
        "console.txt",
        "planted.txt",
    }
    assert "moto mock account" in (tmp_path / "report.html").read_text()
    assert "moto mock account" in json.loads((tmp_path / "report.json").read_text())["scan"]["note"]
    assert "moto mock account" in (tmp_path / "console.txt").read_text()


def test_demo_puts_the_environment_back(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "should-survive")
    before = {k: v for k, v in os.environ.items() if k.startswith(("AWS_", "MOTO_"))}
    scan_demo_account(workers=2)
    after = {k: v for k, v in os.environ.items() if k.startswith(("AWS_", "MOTO_"))}
    assert after == before
