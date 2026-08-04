"""Report writers and exit codes, using a hand-built scan result (no AWS needed)."""

from __future__ import annotations

import csv
import json
import re
from datetime import UTC, datetime, timedelta

import pytest

from aws_security_audit.exitcodes import EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_OK, exit_code
from aws_security_audit.models import Finding, Severity, Status
from aws_security_audit.output import csv_report, html_report, json_report, sarif
from aws_security_audit.output.common import check_summaries
from aws_security_audit.registry import get_check
from aws_security_audit.runner import ScanResult

ACCOUNT = "123456789012"


def finding(check_id, status, severity, resource, message, **kwargs):
    spec = get_check(check_id)
    return Finding(
        check_id=check_id,
        title=spec.title,
        status=status,
        severity=severity,
        resource_arn=resource,
        region=kwargs.pop("region", "us-east-1"),
        message=message,
        remediation=spec.remediation if status is Status.FAIL else None,
        cis=kwargs.pop("cis", spec.cis),
        **kwargs,
    )


@pytest.fixture
def result():
    sg = f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/sg-0abc"
    findings = [
        finding(
            "ec2-sg-open-to-internet",
            Status.FAIL,
            Severity.HIGH,
            sg,
            "Security group sg-0abc (<script>alert(1)</script>) allows SSH (22) from 0.0.0.0/0",
            evidence={"exposures": [{"port": 22, "source": "0.0.0.0/0"}]},
            cis=("5.2",),
        ),
        finding(
            "iam-root-mfa",
            Status.FAIL,
            Severity.CRITICAL,
            f"arn:aws:iam::{ACCOUNT}:root",
            "MFA is not enabled for the root user",
            region="global",
            suppressed=True,
            suppression_reason="break-glass account, MFA token in the safe",
        ),
        finding(
            "s3-bucket-policy-public",
            Status.ERROR,
            Severity.CRITICAL,
            "arn:aws:s3:::locked-down",
            "Could not check: access denied (AccessDenied) calling GetBucketPolicy",
            evidence={"error_code": "AccessDenied"},
        ),
        finding(
            "ec2-ebs-default-encryption",
            Status.PASS,
            Severity.MEDIUM,
            f"arn:aws:iam::{ACCOUNT}:root",
            "EBS encryption by default is on in us-east-1",
        ),
        finding(
            "ec2-imdsv2-required",
            Status.FAIL,
            Severity.MEDIUM,
            f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-1",
            '=HYPERLINK("http://evil.example")',
        ),
    ]
    findings.sort(key=Finding.sort_key)
    started = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    checks = [
        get_check(c)
        for c in (
            "ec2-sg-open-to-internet",
            "iam-root-mfa",
            "s3-bucket-policy-public",
            "ec2-ebs-default-encryption",
            "ec2-imdsv2-required",
            "rds-public-access",
        )
    ]
    return ScanResult(
        account_id=ACCOUNT,
        partition="aws",
        regions=["us-east-1"],
        checks=checks,
        findings=findings,
        executions=[],
        started_at=started,
        finished_at=started + timedelta(seconds=3),
        note="Generated against a moto mock account, not a real AWS account.",
        warnings=["example warning"],
    )


# --- shared summaries ----------------------------------------------------------------


def test_counts_keep_suppressed_and_errors_separate(result):
    assert result.counts() == {"pass": 1, "fail": 2, "error": 1, "suppressed": 1}
    assert result.open_failures_by_severity()["critical"] == 0  # the only critical fail is suppressed
    assert result.incomplete


def test_check_outcomes(result):
    outcomes = {s.spec.id: s.outcome for s in check_summaries(result)}
    assert outcomes == {
        "ec2-sg-open-to-internet": "fail",
        "ec2-imdsv2-required": "fail",
        "s3-bucket-policy-public": "could not check",
        "iam-root-mfa": "suppressed",
        "ec2-ebs-default-encryption": "pass",
        "rds-public-access": "no resources",
    }


# --- exit codes ----------------------------------------------------------------------


def test_fail_on_threshold(result):
    assert exit_code(result, Severity.HIGH) == EXIT_FINDINGS
    assert exit_code(result, Severity.MEDIUM) == EXIT_FINDINGS
    # The critical root MFA failure is suppressed, so it does not trip --fail-on critical.
    assert exit_code(result, Severity.CRITICAL) == EXIT_OK
    assert exit_code(result, None) == EXIT_OK


def test_fail_on_incomplete(result):
    assert exit_code(result, Severity.CRITICAL, fail_on_incomplete=True) == EXIT_INCOMPLETE
    # A threshold breach takes priority over the incomplete exit code.
    assert exit_code(result, Severity.HIGH, fail_on_incomplete=True) == EXIT_FINDINGS


# --- JSON ------------------------------------------------------------------------------


def test_json_report(result, tmp_path):
    path = tmp_path / "report.json"
    json_report.write(result, path)
    data = json.loads(path.read_text())
    assert data["schema_version"] == 1
    assert data["scan"]["account_id"] == ACCOUNT
    assert data["scan"]["note"].startswith("Generated against a moto mock account")
    assert data["summary"]["counts"] == result.counts()
    assert data["summary"]["incomplete"] is True
    assert len(data["findings"]) == 5
    sg = next(f for f in data["findings"] if f["check_id"] == "ec2-sg-open-to-internet")
    assert sg["cis"] == ["5.2"]
    assert sg["remediation"]["cli"].startswith("aws ec2 revoke-security-group-ingress")
    assert {c["id"] for c in data["checks"]} == {spec.id for spec in result.checks}


# --- HTML ------------------------------------------------------------------------------


def test_html_report_is_self_contained_and_escaped(result, tmp_path):
    path = tmp_path / "report.html"
    html_report.write(result, path)
    html = path.read_text()
    assert html.startswith("<!doctype html>")
    assert "Generated against a moto mock account" in html
    # Resource names from the account must not be able to inject markup.
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    # No external stylesheets, scripts, images or fonts.
    assert not re.search(r"""(src|href)=["']?(https?:)?//""", html)
    assert "<link" not in html
    assert "break-glass account" in html
    assert "Could not check (1)" in html
    assert "Failed (2)" in html


# --- SARIF ------------------------------------------------------------------------------


def test_sarif_report(result, tmp_path):
    path = tmp_path / "report.sarif"
    sarif.write(result, path)
    data = json.loads(path.read_text())
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == [spec.id for spec in result.checks]
    assert "CIS-AWS-Foundations-v3.0.0-5.2" in rules[0]["properties"]["tags"]

    # Only failures are results; the suppressed one carries its justification.
    by_rule = {r["ruleId"]: r for r in run["results"]}
    assert set(by_rule) == {"ec2-sg-open-to-internet", "iam-root-mfa", "ec2-imdsv2-required"}
    assert by_rule["ec2-sg-open-to-internet"]["level"] == "error"
    assert by_rule["ec2-imdsv2-required"]["level"] == "warning"
    location = by_rule["ec2-sg-open-to-internet"]["locations"][0]["logicalLocations"][0]
    assert location["fullyQualifiedName"].endswith("security-group/sg-0abc")
    assert by_rule["iam-root-mfa"]["suppressions"][0]["justification"].startswith("break-glass")
    for entry in run["results"]:
        assert rules[entry["ruleIndex"]]["id"] == entry["ruleId"]

    # Could-not-check items are notifications, never silently dropped.
    [note] = run["invocations"][0]["toolExecutionNotifications"]
    assert note["descriptor"]["id"] == "s3-bucket-policy-public"
    assert "AccessDenied" in note["message"]["text"]


# --- CSV --------------------------------------------------------------------------------


def test_csv_report(result, tmp_path):
    path = tmp_path / "report.csv"
    csv_report.write(result, path)
    rows = list(csv.DictReader(path.open(newline="")))
    assert len(rows) == 5
    assert list(rows[0].keys()) == csv_report.COLUMNS
    statuses = sorted(r["status"] for r in rows)
    assert statuses == ["could not check", "fail", "fail", "fail", "pass"]
    suppressed = next(r for r in rows if r["check_id"] == "iam-root-mfa")
    assert suppressed["suppressed"] == "yes"
    # A message that looks like a spreadsheet formula is neutralised.
    imds = next(r for r in rows if r["check_id"] == "ec2-imdsv2-required")
    assert imds["message"].startswith("'=")


@pytest.mark.parametrize("value", ["=1+1", "+1", "-1", "@SUM(A1)", "\tx"])
def test_safe_cell_prefixes_formula_characters(value):
    assert csv_report.safe_cell(value) == "'" + value
