"""Detection and inventory services: GuardDuty and AWS Config."""

from __future__ import annotations

from ..context import CheckRun, paginate
from ..models import Severity
from ..registry import Scope, check


@check(
    id="guardduty-enabled",
    title="GuardDuty is enabled in every region",
    service="guardduty",
    severity=Severity.MEDIUM,
    scope=Scope.REGIONAL,
    description=(
        "GuardDuty watches CloudTrail, VPC flow logs and DNS logs for signs of compromise, such as "
        "credentials used from unusual places or instances talking to known bad hosts."
    ),
    console="GuardDuty (in the region) > Get started > Enable GuardDuty. In an organisation, use a delegated admin account.",
    cli="aws guardduty create-detector --enable --region <REGION>",
)
def guardduty_enabled(run: CheckRun) -> None:
    guardduty = run.client("guardduty")
    detectors = list(paginate(guardduty, "list_detectors", "DetectorIds"))
    if not detectors:
        run.failed(run.scan.account_arn, f"GuardDuty is not enabled in {run.region}", {"detectors": 0})
        return
    for detector_id in detectors:
        arn = run.scan.arn("guardduty", run.region, f"detector/{detector_id}")
        with run.guard(arn):
            status = guardduty.get_detector(DetectorId=detector_id).get("Status")
            if status == "ENABLED":
                run.passed(arn, f"GuardDuty detector {detector_id} is enabled", {"status": status})
            else:
                run.failed(arn, f"GuardDuty detector {detector_id} exists but is {status}", {"status": status})


@check(
    id="config-recorder-enabled",
    title="AWS Config is recording all resource types in every region",
    service="config",
    severity=Severity.MEDIUM,
    scope=Scope.REGIONAL,
    cis=("3.3",),
    description=(
        "AWS Config keeps a history of how each resource was configured, which is what you need to "
        "answer 'when did this security group open port 22?' during an incident. CIS also expects "
        "global resource types (IAM) to be recorded in one region; that part is shown in the evidence "
        "but not enforced per region."
    ),
    console=(
        "AWS Config (in the region) > Settings > Edit. Record all resource types, choose a delivery "
        "bucket and make sure recording is on."
    ),
    cli=(
        "aws configservice put-configuration-recorder --configuration-recorder "
        "name=default,roleARN=<CONFIG_ROLE_ARN> --recording-group allSupported=true,includeGlobalResourceTypes=true\n"
        "aws configservice put-delivery-channel --delivery-channel name=default,s3BucketName=<BUCKET>\n"
        "aws configservice start-configuration-recorder --configuration-recorder-name default"
    ),
)
def config_recorder(run: CheckRun) -> None:
    config = run.client("config")
    recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if not recorders:
        run.failed(run.scan.account_arn, f"AWS Config has no configuration recorder in {run.region}", {"recorders": 0})
        return
    statuses = {
        s["name"]: s for s in config.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
    }
    for recorder in recorders:
        name = recorder["name"]
        group = recorder.get("recordingGroup", {})
        all_supported = bool(group.get("allSupported")) or (
            group.get("recordingStrategy", {}).get("useOnly") == "ALL_SUPPORTED_RESOURCE_TYPES"
        )
        recording = bool(statuses.get(name, {}).get("recording"))
        evidence = {
            "recorder": name,
            "recording": recording,
            "all_supported": all_supported,
            "include_global_resource_types": bool(group.get("includeGlobalResourceTypes")),
        }
        problems = []
        if not recording:
            problems.append("is not recording")
        if not all_supported:
            problems.append("does not record all supported resource types")
        if problems:
            run.failed(run.scan.account_arn, f"AWS Config recorder {name} in {run.region} {' and '.join(problems)}", evidence)
        else:
            run.passed(run.scan.account_arn, f"AWS Config recorder {name} is recording all resource types", evidence)
