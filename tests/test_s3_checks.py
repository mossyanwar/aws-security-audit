"""S3 checks against moto."""

from __future__ import annotations

import json

import boto3
import pytest
from botocore.stub import Stubber

from aws_security_audit.models import Severity

from .helpers import ACCOUNT_ID, errors, failed, passed

ALL_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


@pytest.fixture
def s3(aws):
    return boto3.client("s3", region_name="us-east-1")


def make_bucket(name, region="us-east-1"):
    client = boto3.client("s3", region_name=region)
    if region == "us-east-1":
        client.create_bucket(Bucket=name)
    else:
        client.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": region})
    return client


def public_policy(bucket, condition=None):
    statement = {
        "Sid": "PublicRead",
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{bucket}/*",
    }
    if condition:
        statement["Condition"] = condition
    return json.dumps({"Version": "2012-10-17", "Statement": [statement]})


def block_account():
    boto3.client("s3control", region_name="us-east-1").put_public_access_block(
        AccountId=ACCOUNT_ID, PublicAccessBlockConfiguration=ALL_ON
    )


# --- account level ---------------------------------------------------------------


def test_account_block_missing_fails(scan):
    [finding] = failed(scan("s3-account-public-access-block"))
    assert finding.cis == ("2.1.4",)
    assert finding.evidence == dict.fromkeys(ALL_ON, False)


def test_account_block_partly_on_fails(scan, aws):
    boto3.client("s3control", region_name="us-east-1").put_public_access_block(
        AccountId=ACCOUNT_ID, PublicAccessBlockConfiguration={**ALL_ON, "RestrictPublicBuckets": False}
    )
    [finding] = failed(scan("s3-account-public-access-block"))
    assert "RestrictPublicBuckets" in finding.message


def test_account_block_fully_on_passes(scan, aws):
    block_account()
    result = scan("s3-account-public-access-block")
    assert len(passed(result)) == 1 and not failed(result)


# --- bucket level ------------------------------------------------------------------


def test_bucket_without_block_fails_and_uses_bucket_region(scan, aws):
    make_bucket("london-data", "eu-west-2")
    [finding] = failed(scan("s3-bucket-public-access-block"))
    assert finding.resource_arn == "arn:aws:s3:::london-data"
    assert finding.region == "eu-west-2"


def test_bucket_with_own_block_passes(scan, s3):
    make_bucket("locked")
    s3.put_public_access_block(Bucket="locked", PublicAccessBlockConfiguration=ALL_ON)
    result = scan("s3-bucket-public-access-block")
    assert not failed(result)
    assert "bucket settings" in passed(result)[0].message


def test_bucket_covered_by_account_block_passes(scan, aws):
    make_bucket("covered")
    block_account()
    result = scan("s3-bucket-public-access-block")
    assert not failed(result)
    assert "combined" in passed(result)[0].message


# --- bucket policy -----------------------------------------------------------------


def test_public_bucket_policy_fails_critical(scan, s3):
    make_bucket("website")
    s3.put_bucket_policy(Bucket="website", Policy=public_policy("website"))
    [finding] = failed(scan("s3-bucket-policy-public"))
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence["public_statements"][0]["sid"] == "PublicRead"
    assert finding.evidence["restrict_public_buckets"] is False


def test_public_policy_is_downgraded_when_restrict_public_buckets_is_on(scan, s3):
    make_bucket("website")
    s3.put_bucket_policy(Bucket="website", Policy=public_policy("website"))
    block_account()
    [finding] = failed(scan("s3-bucket-policy-public"))
    assert finding.severity is Severity.MEDIUM


def test_conditioned_or_missing_policy_passes(scan, s3):
    make_bucket("vpc-only")
    s3.put_bucket_policy(
        Bucket="vpc-only",
        Policy=public_policy("vpc-only", condition={"StringEquals": {"aws:SourceVpce": "vpce-1234"}}),
    )
    make_bucket("no-policy")
    result = scan("s3-bucket-policy-public")
    assert not failed(result)
    assert len(passed(result)) == 2


def test_access_denied_on_one_bucket_does_not_stop_the_others(scan, make_ctx, s3):
    make_bucket("aaa-denied")
    make_bucket("bbb-fine")
    ctx = make_ctx()
    client = ctx.client("s3", "us-east-1")
    stubber = Stubber(client)
    stubber.add_response("list_buckets", {"Buckets": [{"Name": "aaa-denied"}, {"Name": "bbb-fine"}]})
    stubber.add_response("get_bucket_location", {"LocationConstraint": ""}, {"Bucket": "aaa-denied"})
    stubber.add_response("get_bucket_location", {"LocationConstraint": ""}, {"Bucket": "bbb-fine"})
    stubber.add_client_error("get_bucket_policy", "AccessDenied", http_status_code=403)
    stubber.add_client_error("get_bucket_policy", "NoSuchBucketPolicy", http_status_code=404)
    with stubber:
        result = scan("s3-bucket-policy-public", ctx=ctx)
    assert [f.resource_arn for f in errors(result)] == ["arn:aws:s3:::aaa-denied"]
    assert [f.resource_arn for f in passed(result)] == ["arn:aws:s3:::bbb-fine"]


# --- encryption, versioning, logging ---------------------------------------------------


def test_bucket_without_default_encryption_fails(scan, aws):
    # moto, unlike current AWS, creates buckets without a default encryption config.
    make_bucket("plain")
    [finding] = failed(scan("s3-default-encryption"))
    assert finding.severity is Severity.LOW


def test_bucket_with_kms_encryption_passes(scan, s3):
    make_bucket("encrypted")
    s3.put_bucket_encryption(
        Bucket="encrypted",
        ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]},
    )
    [finding] = passed(scan("s3-default-encryption"))
    assert finding.evidence == {"algorithms": ["aws:kms"]}


def test_bucket_without_versioning_or_logging_fails_twice(scan, aws):
    make_bucket("scratch")
    findings = failed(scan("s3-versioning-and-logging"))
    messages = sorted(f.message for f in findings)
    assert messages == [
        "Bucket scratch does not have server access logging enabled",
        "Bucket scratch does not have versioning enabled (never enabled)",
    ]
    # Each finding carries the fix for its own problem.
    assert {f.remediation.cli.split()[2] for f in findings} == {"put-bucket-logging", "put-bucket-versioning"}


def test_bucket_with_versioning_and_logging_passes(scan, s3):
    make_bucket("app-log-target")
    s3.put_bucket_policy(
        Bucket="app-log-target",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "logging.s3.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::app-log-target/*",
                    }
                ],
            }
        ),
    )
    make_bucket("app-data")
    s3.put_bucket_versioning(Bucket="app-data", VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_logging(
        Bucket="app-data", BucketLoggingStatus={"LoggingEnabled": {"TargetBucket": "app-log-target", "TargetPrefix": "app-data/"}}
    )
    result = scan("s3-versioning-and-logging")
    app = [f for f in result.findings if f.resource_arn == "arn:aws:s3:::app-data"]
    assert {f.status.value for f in app} == {"pass"}
    assert len(app) == 2
