"""Runner behaviour: scoping, error handling and the read-only guard."""

from __future__ import annotations

import boto3
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from botocore.stub import Stubber

from aws_security_audit.context import ScanContext
from aws_security_audit.errors import ReadOnlyViolation
from aws_security_audit.models import Remediation, Severity, Status
from aws_security_audit.regions import resolve_regions
from aws_security_audit.registry import CheckSpec, Scope
from aws_security_audit.runner import run_scan

from .helpers import REGION


def make_spec(func, scope=Scope.REGIONAL, check_id="test-check"):
    return CheckSpec(
        id=check_id,
        title="Test check",
        service="test",
        severity=Severity.HIGH,
        scope=scope,
        description="test",
        remediation=Remediation(console="console steps", cli="aws something"),
        func=func,
    )


@pytest.fixture
def ctx(aws):
    return ScanContext.from_session(boto3.Session(region_name=REGION))


def access_denied(operation="ListThings"):
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "not allowed"}}, operation)


def test_regional_check_runs_once_per_region_and_global_once(ctx):
    seen = []

    def regional(run):
        seen.append(("regional", run.region, run.api_region))
        run.passed(ctx.account_arn, "ok")

    def global_(run):
        seen.append(("global", run.region, run.api_region))
        run.passed(ctx.account_arn, "ok")

    result = run_scan(
        ctx,
        [make_spec(regional), make_spec(global_, Scope.GLOBAL, "test-global")],
        ["eu-west-2", "us-east-1"],
    )
    assert sorted(seen) == [
        ("global", "global", REGION),
        ("regional", "eu-west-2", "eu-west-2"),
        ("regional", "us-east-1", "us-east-1"),
    ]
    assert len(result.executions) == 3
    assert result.counts()["pass"] == 3


def test_access_denied_is_could_not_check_not_a_pass(ctx):
    def denied(run):
        raise access_denied("ListBuckets")

    result = run_scan(ctx, [make_spec(denied)], [REGION])
    assert [f.status for f in result.findings] == [Status.ERROR]
    finding = result.findings[0]
    assert "access denied" in finding.message
    assert finding.evidence["error_code"] == "AccessDenied"
    assert finding.evidence["operation"] == "ListBuckets"
    assert result.incomplete
    assert result.counts()["pass"] == 0


def test_unreachable_region_endpoint_is_could_not_check(ctx):
    def no_endpoint(run):
        raise EndpointConnectionError(endpoint_url="https://guardduty.xx-fake-1.amazonaws.com")

    result = run_scan(ctx, [make_spec(no_endpoint)], ["xx-fake-1"])
    finding = result.findings[0]
    assert finding.status is Status.ERROR
    assert finding.region == "xx-fake-1"
    assert finding.evidence["error_category"] == "region-unavailable"


def test_opt_in_region_error_is_could_not_check(ctx):
    def not_enabled(run):
        raise ClientError({"Error": {"Code": "OptInRequired", "Message": "opt in"}}, "DescribeInstances")

    result = run_scan(ctx, [make_spec(not_enabled)], ["me-south-1"])
    assert result.findings[0].status is Status.ERROR
    assert result.findings[0].evidence["error_category"] == "region-unavailable"


def test_bug_in_a_check_is_reported_and_other_checks_still_run(ctx):
    def broken(run):
        raise KeyError("Buckets")

    def fine(run):
        run.failed(ctx.account_arn, "something is wrong")

    result = run_scan(ctx, [make_spec(broken, check_id="broken"), make_spec(fine, check_id="fine")], [REGION])
    statuses = {f.check_id: f.status for f in result.findings}
    assert statuses == {"broken": Status.ERROR, "fine": Status.FAIL}
    broken_exec = next(e for e in result.executions if e.check_id == "broken")
    assert "internal error" in broken_exec.error


def test_guard_records_one_resource_and_carries_on(ctx):
    def partly_denied(run):
        for name in ("a", "b", "c"):
            with run.guard(f"arn:aws:s3:::{name}"):
                if name == "b":
                    raise access_denied("GetBucketPolicy")
                run.passed(f"arn:aws:s3:::{name}", "fine")

    result = run_scan(ctx, [make_spec(partly_denied)], [REGION])
    by_resource = {f.resource_arn: f.status for f in result.findings}
    assert by_resource == {
        "arn:aws:s3:::a": Status.PASS,
        "arn:aws:s3:::b": Status.ERROR,
        "arn:aws:s3:::c": Status.PASS,
    }


def test_failed_finding_carries_check_remediation_and_cis(ctx):
    spec = make_spec(lambda run: run.failed(ctx.account_arn, "bad"))
    spec = CheckSpec(**{**spec.__dict__, "cis": ("1.4",)})
    result = run_scan(ctx, [spec], [REGION])
    finding = result.findings[0]
    assert finding.remediation.cli == "aws something"
    assert finding.cis == ("1.4",)


def test_read_only_guard_blocks_write_calls(ctx):
    with pytest.raises(ReadOnlyViolation):
        ctx.client("s3").create_bucket(Bucket="should-not-exist")
    with pytest.raises(ReadOnlyViolation):
        ctx.client("ec2").authorize_security_group_ingress(GroupId="sg-123", IpPermissions=[])
    # Reads still work and are recorded.
    ctx.client("s3").list_buckets()
    assert ("s3", "ListBuckets") in ctx.operations


def test_cached_lookup_runs_once_and_caches_failures(ctx):
    calls = []

    def loader():
        calls.append(1)
        raise access_denied()

    for _ in range(3):
        with pytest.raises(ClientError):
            ctx.cached("thing", loader)
    assert len(calls) == 1


def test_regions_fall_back_to_home_region_with_a_warning(ctx):
    stubber = Stubber(ctx.client("ec2"))
    stubber.add_client_error("describe_regions", service_error_code="UnauthorizedOperation")
    with stubber:
        regions, warnings = resolve_regions(ctx, None)
    assert regions == [REGION]
    assert "only us-east-1 was scanned" in warnings[0]


def test_requested_regions_are_used_as_given(ctx):
    regions, warnings = resolve_regions(ctx, ["eu-west-2", "us-east-1", "eu-west-2"])
    assert regions == ["eu-west-2", "us-east-1"]
    assert warnings == []
