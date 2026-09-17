"""Suppressions file parsing, matching and CLI wiring."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aws_security_audit.cli import app
from aws_security_audit.models import Finding, Severity, Status
from aws_security_audit.registry import all_checks
from aws_security_audit.suppressions import Suppression, SuppressionError, apply, load, parse

TODAY = date(2026, 9, 17)
KNOWN = {spec.id for spec in all_checks()}
ROOT = "arn:aws:iam::123456789012:root"


def make_finding(check_id="iam-root-mfa", resource=ROOT, status=Status.FAIL):
    return Finding(
        check_id=check_id,
        title="t",
        status=status,
        severity=Severity.CRITICAL,
        resource_arn=resource,
        region="global",
        message="m",
    )


def entry(**overrides):
    values = {
        "check": "iam-root-mfa",
        "resource": ROOT,
        "reason": "break-glass account",
        "expires": "2027-01-31",
        **overrides,
    }
    return "suppressions:\n  - " + "\n    ".join(f"{k}: {v}" for k, v in values.items()) + "\n"


# --- parsing --------------------------------------------------------------------------


def test_valid_entry_is_loaded():
    [s], warnings = parse(entry(), KNOWN, TODAY)
    assert s == Suppression("iam-root-mfa", ROOT, "break-glass account", date(2027, 1, 31))
    assert warnings == []


def test_empty_file_means_no_suppressions():
    assert parse("", KNOWN, TODAY) == ([], [])


def test_example_file_in_the_repo_is_valid():
    path = Path(__file__).parent.parent / "examples" / "suppressions.example.yaml"
    active, _ = load(path, KNOWN, TODAY)
    assert len(active) == 3


@pytest.mark.parametrize(
    "text, message",
    [
        ("- just a list\n", "top-level 'suppressions:' list"),
        (entry(reason='""'), "missing reason"),
        (entry(check="iam-root-mfaa"), "unknown check id 'iam-root-mfaa'"),
        (entry(expires="next week"), "expires must be a date"),
        (entry(resource='"*"'), "would match everything"),
        (entry(owner="me"), "unknown key(s) owner"),
        ("suppressions:\n  - iam-root-mfa\n", "must be a mapping"),
    ],
)
def test_bad_entries_are_rejected(text, message):
    with pytest.raises(SuppressionError) as excinfo:
        parse(text, KNOWN, TODAY)
    assert message in str(excinfo.value)


def test_missing_expiry_is_rejected():
    text = "suppressions:\n  - check: iam-root-mfa\n    resource: x\n    reason: y\n"
    with pytest.raises(SuppressionError, match="missing expires"):
        parse(text, KNOWN, TODAY)


def test_expired_entry_is_ignored_with_a_warning():
    active, warnings = parse(entry(expires="2026-09-16"), KNOWN, TODAY)
    assert active == []
    assert "expired on 2026-09-16" in warnings[0]


def test_entry_expiring_today_still_applies():
    active, _ = parse(entry(expires="2026-09-17"), KNOWN, TODAY)
    assert len(active) == 1


def test_long_lived_entry_gets_a_warning():
    active, warnings = parse(entry(expires="2028-06-01"), KNOWN, TODAY)
    assert len(active) == 1
    assert "more than a year away" in warnings[0]


def test_invalid_yaml_is_a_suppression_error(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("suppressions: [unclosed\n")
    with pytest.raises(SuppressionError, match="not valid YAML"):
        load(path, KNOWN, TODAY)


def test_yaml_tags_cannot_build_python_objects():
    with pytest.raises(SuppressionError):
        parse("suppressions: !!python/object/apply:os.system ['echo hi']\n", KNOWN, TODAY)


# --- matching ---------------------------------------------------------------------------


def test_matching_failure_is_marked_but_kept():
    findings = [make_finding()]
    warnings = apply(findings, [Suppression("iam-root-mfa", ROOT, "reason", date(2027, 1, 1))], {"iam-root-mfa"})
    assert findings[0].suppressed
    assert findings[0].suppression_reason == "reason (until 2027-01-01)"
    assert findings[0].is_open_failure is False
    assert warnings == []


def test_glob_pattern_matches_resources():
    findings = [
        make_finding("s3-bucket-policy-public", "arn:aws:s3:::site-blog"),
        make_finding("s3-bucket-policy-public", "arn:aws:s3:::payroll"),
    ]
    rule = Suppression("s3-bucket-policy-public", "arn:aws:s3:::site-*", "public sites", date(2027, 1, 1))
    apply(findings, [rule], {"s3-bucket-policy-public"})
    assert [f.suppressed for f in findings] == [True, False]


def test_could_not_check_and_pass_are_never_suppressed():
    findings = [make_finding(status=Status.ERROR), make_finding(status=Status.PASS)]
    apply(findings, [Suppression("iam-root-mfa", ROOT, "r", date(2027, 1, 1))], {"iam-root-mfa"})
    assert not any(f.suppressed for f in findings)


def test_unused_suppression_warns_only_if_its_check_ran():
    rule = Suppression("iam-root-mfa", ROOT, "r", date(2027, 1, 1))
    assert apply([], [rule], {"iam-root-mfa"}) == [f"suppression for iam-root-mfa on {ROOT} matched no failed finding"]
    assert apply([], [rule], {"kms-key-rotation"}) == []


# --- CLI ---------------------------------------------------------------------------------


runner = CliRunner(env={"COLUMNS": "200"})


def test_cli_suppression_turns_a_failing_gate_green(aws, tmp_path):
    path = tmp_path / "suppressions.yaml"
    path.write_text(entry(expires="2099-01-01"))
    args = ["scan", "--region", "us-east-1", "--check", "iam-root-mfa", "--fail-on", "critical"]
    assert runner.invoke(app, args).exit_code == 1
    result = runner.invoke(app, [*args, "--suppressions", str(path)])
    assert result.exit_code == 0, result.output
    assert "suppressed" in result.output


def test_cli_rejects_a_bad_file_before_scanning(tmp_path):
    path = tmp_path / "suppressions.yaml"
    path.write_text(entry(check="not-a-check"))
    # No moto here: the error must come before any AWS call is attempted.
    result = runner.invoke(app, ["scan", "--suppressions", str(path)])
    assert result.exit_code == 2
    assert "unknown check id 'not-a-check'" in result.output
