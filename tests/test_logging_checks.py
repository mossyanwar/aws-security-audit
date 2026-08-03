"""CloudTrail, KMS, GuardDuty and AWS Config checks against moto."""

from __future__ import annotations

import boto3
import pytest
from botocore.stub import Stubber

from aws_security_audit.checks.cloudtrail import records_all_management_events

from .helpers import ACCOUNT_ID, errors, failed, passed

KMS_ARN = f"arn:aws:kms:us-east-1:{ACCOUNT_ID}:key/11111111-2222-3333-4444-555555555555"


def make_trail(name, region="us-east-1", start=True, **kwargs):
    bucket = f"{name}-cloudtrail-logs"
    s3 = boto3.client("s3", region_name=region)
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    cloudtrail = boto3.client("cloudtrail", region_name=region)
    trail = cloudtrail.create_trail(Name=name, S3BucketName=bucket, **kwargs)
    if start:
        cloudtrail.start_logging(Name=name)
    return trail


# --- multi-region trail ------------------------------------------------------------


def test_no_trail_fails(scan):
    [finding] = failed(scan("cloudtrail-multi-region"))
    assert finding.message == "There is no multi-region CloudTrail trail"
    assert finding.cis == ("3.1",)


def test_single_region_trail_is_not_enough(aws, scan):
    make_trail("local-only")
    [finding] = failed(scan("cloudtrail-multi-region"))
    assert finding.evidence["multi_region_trails"] == []


def test_stopped_multi_region_trail_fails(aws, scan):
    make_trail("main", IsMultiRegionTrail=True, start=False)
    [finding] = failed(scan("cloudtrail-multi-region"))
    assert finding.evidence["problems"] == {"main": ["logging is stopped"]}


def test_write_only_multi_region_trail_fails(aws, scan):
    make_trail("main", IsMultiRegionTrail=True)
    boto3.client("cloudtrail").put_event_selectors(
        TrailName="main", EventSelectors=[{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}]
    )
    [finding] = failed(scan("cloudtrail-multi-region"))
    assert "management events" in finding.message


def test_logging_multi_region_trail_passes_even_if_homed_elsewhere(aws, scan):
    make_trail("main", region="eu-west-2", IsMultiRegionTrail=True)
    result = scan("cloudtrail-multi-region")
    assert not failed(result)
    [finding] = passed(result)
    assert finding.resource_arn == f"arn:aws:cloudtrail:eu-west-2:{ACCOUNT_ID}:trail/main"


def test_trail_status_access_denied_is_not_a_fail_or_pass(aws, scan, make_ctx):
    make_trail("main", IsMultiRegionTrail=True)
    ctx = make_ctx()
    client = ctx.client("cloudtrail", "us-east-1")
    stubber = Stubber(client)
    stubber.add_response(
        "describe_trails",
        {
            "trailList": [
                {
                    "Name": "main",
                    "TrailARN": f"arn:aws:cloudtrail:us-east-1:{ACCOUNT_ID}:trail/main",
                    "HomeRegion": "us-east-1",
                    "IsMultiRegionTrail": True,
                }
            ]
        },
    )
    stubber.add_client_error("get_trail_status", "AccessDeniedException", http_status_code=400)
    with stubber:
        result = scan("cloudtrail-multi-region", ctx=ctx)
    assert len(errors(result)) == 1
    assert not failed(result) and not passed(result)


@pytest.mark.parametrize(
    "selectors, expected",
    [
        ({"EventSelectors": [], "AdvancedEventSelectors": []}, True),
        ({"EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": True}]}, True),
        ({"EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": False}]}, False),
        (
            {
                "AdvancedEventSelectors": [
                    {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]},
                ]
            },
            True,
        ),
        (
            {
                "AdvancedEventSelectors": [
                    {
                        "FieldSelectors": [
                            {"Field": "eventCategory", "Equals": ["Management"]},
                            {"Field": "readOnly", "Equals": ["false"]},
                        ]
                    },
                ]
            },
            False,
        ),
    ],
)
def test_management_event_selector_parsing(selectors, expected):
    assert records_all_management_events(selectors) is expected


# --- log validation and KMS -------------------------------------------------------------


def test_trail_without_validation_or_kms_fails_both(aws, scan):
    make_trail("plain")
    result = scan("cloudtrail-log-validation", "cloudtrail-kms-encryption")
    assert {f.check_id: f.cis for f in failed(result)} == {
        "cloudtrail-log-validation": ("3.2",),
        "cloudtrail-kms-encryption": ("3.5",),
    }


def test_trail_with_validation_and_kms_passes_both(aws, scan):
    make_trail("hardened", EnableLogFileValidation=True, KmsKeyId=KMS_ARN)
    result = scan("cloudtrail-log-validation", "cloudtrail-kms-encryption")
    assert not failed(result)
    assert len(passed(result)) == 2


def test_trail_is_only_judged_in_its_home_region(aws, scan):
    make_trail("main", IsMultiRegionTrail=True)
    result = scan("cloudtrail-log-validation", regions=("us-east-1", "eu-west-2"))
    assert [f.region for f in result.findings] == ["us-east-1"]


# --- KMS rotation ------------------------------------------------------------------------


def test_key_without_rotation_fails(aws, scan):
    key_id = boto3.client("kms").create_key(Description="app data")["KeyMetadata"]["KeyId"]
    [finding] = failed(scan("kms-key-rotation"))
    assert finding.resource_arn.endswith(key_id)
    assert finding.cis == ("3.6",)


def test_key_with_rotation_passes_and_asymmetric_keys_are_skipped(aws, scan):
    kms = boto3.client("kms")
    key_id = kms.create_key()["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=key_id)
    kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")  # rotation not supported, not checked
    result = scan("kms-key-rotation")
    assert not failed(result)
    assert [f.resource_arn.split("/")[-1] for f in passed(result)] == [key_id]


def test_disabled_key_is_skipped(aws, scan):
    kms = boto3.client("kms")
    key_id = kms.create_key()["KeyMetadata"]["KeyId"]
    kms.disable_key(KeyId=key_id)
    assert scan("kms-key-rotation").findings == []


# --- GuardDuty ----------------------------------------------------------------------------


def test_guardduty_missing_fails_per_region(aws, scan):
    boto3.client("guardduty", region_name="eu-west-2").create_detector(Enable=True)
    result = scan("guardduty-enabled", regions=("us-east-1", "eu-west-2"))
    assert [f.region for f in failed(result)] == ["us-east-1"]
    assert [f.region for f in passed(result)] == ["eu-west-2"]


def test_suspended_guardduty_detector_fails(aws, scan):
    boto3.client("guardduty").create_detector(Enable=False)
    [finding] = failed(scan("guardduty-enabled"))
    assert finding.evidence == {"status": "DISABLED"}
    assert ":guardduty:us-east-1:" in finding.resource_arn


# --- AWS Config ------------------------------------------------------------------------------


def put_recorder(all_supported=True, start=True):
    config = boto3.client("config")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": f"arn:aws:iam::{ACCOUNT_ID}:role/config-recorder",
            "recordingGroup": {"allSupported": all_supported, "includeGlobalResourceTypes": all_supported}
            if all_supported
            else {"allSupported": False, "includeGlobalResourceTypes": False, "resourceTypes": ["AWS::EC2::Instance"]},
        }
    )
    if start:
        boto3.client("s3").create_bucket(Bucket="config-delivery-bucket")
        config.put_delivery_channel(DeliveryChannel={"name": "default", "s3BucketName": "config-delivery-bucket"})
        config.start_configuration_recorder(ConfigurationRecorderName="default")


def test_no_config_recorder_fails(aws, scan):
    [finding] = failed(scan("config-recorder-enabled"))
    assert finding.cis == ("3.3",)


def test_stopped_or_partial_recorder_fails(aws, scan):
    put_recorder(all_supported=False, start=False)
    [finding] = failed(scan("config-recorder-enabled"))
    assert "is not recording" in finding.message
    assert "does not record all supported resource types" in finding.message


def test_recording_all_resources_passes(aws, scan):
    put_recorder()
    result = scan("config-recorder-enabled")
    assert not failed(result)
    assert passed(result)[0].evidence["recording"] is True
