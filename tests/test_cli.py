"""The command line interface, run in-process against moto."""

from __future__ import annotations

import json

import boto3
from typer.testing import CliRunner

from aws_security_audit.cli import app

# A wide terminal so rich does not wrap table cells mid-sentence.
runner = CliRunner(env={"COLUMNS": "200"})


def test_list_checks_shows_all_25():
    result = runner.invoke(app, ["list-checks"])
    assert result.exit_code == 0
    assert "25 checks" in result.output


def test_unknown_check_id_is_a_usage_error(aws):
    result = runner.invoke(app, ["scan", "--check", "no-such-check"])
    assert result.exit_code == 2
    assert "unknown check id" in result.output


def test_fail_on_high_exits_1_when_root_has_no_mfa(aws):
    result = runner.invoke(app, ["scan", "--region", "us-east-1", "--check", "iam-root-mfa", "--fail-on", "high"])
    assert result.exit_code == 1, result.output
    assert "MFA is not enabled for the root user" in result.output


def test_fail_on_threshold_above_findings_exits_0(aws):
    result = runner.invoke(
        app, ["scan", "--region", "us-east-1", "--check", "ec2-ebs-default-encryption", "--fail-on", "critical"]
    )
    assert result.exit_code == 0, result.output
    assert "1 failed" in result.output


def test_scan_writes_every_report_format(aws, tmp_path):
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="cli-test-bucket")
    args = ["scan", "--region", "us-east-1", "--service", "s3"]
    for flag, name in (("--json", "r.json"), ("--html", "r.html"), ("--sarif", "r.sarif"), ("--csv", "r.csv")):
        args += [flag, str(tmp_path / "out" / name)]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    data = json.loads((tmp_path / "out" / "r.json").read_text())
    assert {c["id"] for c in data["checks"]} == {
        "s3-account-public-access-block",
        "s3-bucket-public-access-block",
        "s3-bucket-policy-public",
        "s3-default-encryption",
        "s3-versioning-and-logging",
    }
    assert json.loads((tmp_path / "out" / "r.sarif").read_text())["version"] == "2.1.0"
    assert "cli-test-bucket" in (tmp_path / "out" / "r.html").read_text()
    assert (tmp_path / "out" / "r.csv").read_text().startswith("status,severity,check_id")


def test_missing_credentials_is_a_clear_usage_error(monkeypatch):
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    result = runner.invoke(app, ["scan", "--region", "us-east-1"])
    assert result.exit_code == 2
    assert "no AWS credentials found" in result.output
