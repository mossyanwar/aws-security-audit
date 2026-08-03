"""KMS checks: automatic rotation of customer managed keys."""

from __future__ import annotations

from ..context import CheckRun, paginate
from ..models import Severity
from ..registry import Scope, check


@check(
    id="kms-key-rotation",
    title="Customer managed KMS keys have automatic rotation on",
    service="kms",
    severity=Severity.MEDIUM,
    scope=Scope.REGIONAL,
    cis=("3.6",),
    description=(
        "Rotation creates new key material on a schedule and keeps the old material for decryption, "
        "which limits how much data any one version of the key protects. Only enabled, symmetric, "
        "customer managed keys with AWS-generated material support it, so only those are checked."
    ),
    console="KMS > Customer managed keys > choose the key > Key rotation > tick Automatically rotate this KMS key.",
    cli="aws kms enable-key-rotation --key-id <KEY_ID>",
)
def key_rotation(run: CheckRun) -> None:
    kms = run.client("kms")
    for key in paginate(kms, "list_keys", "Keys"):
        arn = key.get("KeyArn") or run.scan.arn("kms", run.region, f"key/{key['KeyId']}")
        with run.guard(arn):
            meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            spec = meta.get("KeySpec") or meta.get("CustomerMasterKeySpec")
            if (
                meta.get("KeyManager") != "CUSTOMER"
                or meta.get("KeyState") != "Enabled"
                or spec != "SYMMETRIC_DEFAULT"
                or meta.get("Origin") != "AWS_KMS"
            ):
                continue
            status = kms.get_key_rotation_status(KeyId=key["KeyId"])
            evidence = {"KeyRotationEnabled": status.get("KeyRotationEnabled"), "description": meta.get("Description")}
            if status.get("RotationPeriodInDays"):
                evidence["RotationPeriodInDays"] = status["RotationPeriodInDays"]
            if status.get("KeyRotationEnabled"):
                run.passed(arn, f"KMS key {key['KeyId']} rotates automatically", evidence)
            else:
                run.failed(arn, f"KMS key {key['KeyId']} does not have automatic rotation on", evidence)
