"""CloudTrail checks: a logging multi-region trail, log file validation and KMS encryption."""

from __future__ import annotations

from typing import Any

from ..context import CheckRun
from ..models import Severity
from ..registry import Scope, check


def records_all_management_events(selectors: dict[str, Any]) -> bool:
    """True if a trail's event selectors include read and write management events.

    A trail with no selectors at all uses the default, which is all
    management events. AWS returns that default explicitly; moto returns an
    empty list, and both are handled the same way here.
    """
    basic = selectors.get("EventSelectors") or []
    advanced = selectors.get("AdvancedEventSelectors") or []
    if not basic and not advanced:
        return True
    for selector in basic:
        if selector.get("IncludeManagementEvents") and selector.get("ReadWriteType", "All") == "All":
            return True
    for selector in advanced:
        fields = {f.get("Field"): f for f in selector.get("FieldSelectors", [])}
        category = fields.get("eventCategory", {})
        if "Management" in (category.get("Equals") or []) and "readOnly" not in fields:
            return True
    return False


def trails_homed_here(run: CheckRun) -> list[dict[str, Any]]:
    """Trails whose home region is the region being scanned (shadow copies left out)."""
    return run.client("cloudtrail").describe_trails(includeShadowTrails=False).get("trailList", [])


@check(
    id="cloudtrail-multi-region",
    title="A multi-region CloudTrail trail is logging all management events",
    service="cloudtrail",
    severity=Severity.HIGH,
    scope=Scope.GLOBAL,
    cis=("3.1",),
    description=(
        "Without a trail covering every region there is no record of who did what, including in "
        "regions you do not use, which is exactly where an attacker would go."
    ),
    console=(
        "CloudTrail > Trails > Create trail. Apply it to all regions (the default for new trails), "
        "log read and write management events, and send logs to a dedicated S3 bucket. "
        "If a trail exists but is stopped, open it and choose Start logging."
    ),
    cli=(
        "aws cloudtrail create-trail --name <TRAIL> --s3-bucket-name <BUCKET> --is-multi-region-trail "
        "--enable-log-file-validation --kms-key-id <KMS_KEY_ARN>\n"
        "aws cloudtrail start-logging --name <TRAIL>"
    ),
)
def multi_region_trail(run: CheckRun) -> None:
    # Multi-region trails appear in every region, so one call finds them all.
    trails = run.client("cloudtrail").describe_trails(includeShadowTrails=True).get("trailList", [])
    multi = [t for t in trails if t.get("IsMultiRegionTrail")]
    good, problems, unverified = [], {}, 0
    for trail in multi:
        before = len(run.findings)
        with run.guard(trail["TrailARN"], region=trail.get("HomeRegion")):
            client = run.client("cloudtrail", trail.get("HomeRegion"))
            logging = client.get_trail_status(Name=trail["TrailARN"]).get("IsLogging", False)
            management = records_all_management_events(client.get_event_selectors(TrailName=trail["TrailARN"]))
            issues = []
            if not logging:
                issues.append("logging is stopped")
            if not management:
                issues.append("does not record all read and write management events")
            if issues:
                problems[trail["Name"]] = issues
            else:
                good.append(trail)
        if len(run.findings) > before:
            unverified += 1

    if good:
        names = [t["Name"] for t in good]
        run.passed(good[0]["TrailARN"], f"Multi-region trail(s) logging management events: {', '.join(names)}", {"trails": names})
    elif unverified and not problems:
        # Every multi-region trail hit an API error; those are already reported as could not check.
        return
    else:
        evidence = {"multi_region_trails": [t["Name"] for t in multi], "problems": problems}
        if multi:
            detail = "; ".join(f"{name}: {', '.join(issues)}" for name, issues in problems.items())
            message = f"No multi-region trail is fully logging management events ({detail})"
        else:
            message = "There is no multi-region CloudTrail trail"
        run.failed(run.scan.account_arn, message, evidence)


@check(
    id="cloudtrail-log-validation",
    title="CloudTrail log file validation is on",
    service="cloudtrail",
    severity=Severity.MEDIUM,
    scope=Scope.REGIONAL,
    cis=("3.2",),
    description="Validation writes signed digest files, so you can prove later that log files were not altered or deleted.",
    console="CloudTrail > Trails > choose the trail > General details > Edit > Log file validation: Enabled.",
    cli="aws cloudtrail update-trail --name <TRAIL> --enable-log-file-validation",
)
def log_validation(run: CheckRun) -> None:
    for trail in trails_homed_here(run):
        evidence = {"LogFileValidationEnabled": bool(trail.get("LogFileValidationEnabled"))}
        if trail.get("LogFileValidationEnabled"):
            run.passed(trail["TrailARN"], f"Trail {trail['Name']} has log file validation on", evidence)
        else:
            run.failed(trail["TrailARN"], f"Trail {trail['Name']} has log file validation off", evidence)


@check(
    id="cloudtrail-kms-encryption",
    title="CloudTrail logs are encrypted with a KMS key",
    service="cloudtrail",
    severity=Severity.MEDIUM,
    scope=Scope.REGIONAL,
    cis=("3.5",),
    description=(
        "SSE-KMS adds a second permission check: reading the logs needs kms:Decrypt on the key as well "
        "as access to the bucket, and every decrypt is itself logged."
    ),
    console=(
        "CloudTrail > Trails > choose the trail > General details > Edit > Log file SSE-KMS encryption: "
        "Enabled, then pick or create a key whose policy lets CloudTrail use it."
    ),
    cli="aws cloudtrail update-trail --name <TRAIL> --kms-key-id <KMS_KEY_ARN>",
)
def kms_encryption(run: CheckRun) -> None:
    for trail in trails_homed_here(run):
        key = trail.get("KmsKeyId")
        if key:
            run.passed(trail["TrailARN"], f"Trail {trail['Name']} logs are encrypted with KMS", {"KmsKeyId": key})
        else:
            run.failed(trail["TrailARN"], f"Trail {trail['Name']} logs are not encrypted with a KMS key", {"KmsKeyId": None})
