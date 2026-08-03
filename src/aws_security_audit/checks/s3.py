"""S3 checks: public access blocks, public bucket policies, encryption, versioning and logging."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..context import CheckRun, paginate
from ..errors import error_code
from ..models import Remediation, Severity
from ..policy import as_list, load_document, public_allow_statements
from ..registry import Scope, check

PAB_SETTINGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


@dataclass(frozen=True)
class Bucket:
    name: str
    arn: str
    region: str | None
    # Set when the bucket's region could not be read, so checks can report it.
    location_error: BaseException | None = None


def _bucket_region(s3: Any, name: str) -> str:
    location = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
    # Buckets in us-east-1 report no location; very old EU buckets report "EU".
    if not location:
        return "us-east-1"
    if location == "EU":
        return "eu-west-1"
    return location


def buckets(run: CheckRun) -> list[Bucket]:
    """Every bucket in the account with its region, listed once per scan.

    ListBuckets is global, so bucket checks cover all buckets whatever
    --region says; each bucket is then queried in its own region.
    """

    def load() -> list[Bucket]:
        s3 = run.client("s3")
        result = []
        for item in paginate(s3, "list_buckets", "Buckets"):
            name = item["Name"]
            arn = f"arn:{run.scan.partition}:s3:::{name}"
            region = item.get("BucketRegion")
            if region:
                result.append(Bucket(name, arn, region))
                continue
            try:
                result.append(Bucket(name, arn, _bucket_region(s3, name)))
            except (ClientError, BotoCoreError) as exc:
                result.append(Bucket(name, arn, None, exc))
        return result

    return run.scan.cached("s3:buckets", load)


def for_each_bucket(run: CheckRun, func: Callable[[Bucket, Any], None]) -> None:
    """Call ``func(bucket, s3_client)`` for every bucket.

    An API error on one bucket is recorded as "could not check" for that
    bucket and the loop moves on to the next.
    """
    for bucket in buckets(run):
        if bucket.location_error is not None:
            run.could_not_check(bucket.arn, bucket.location_error, region="unknown")
            continue
        with run.guard(bucket.arn, region=bucket.region):
            func(bucket, run.client("s3", bucket.region))


def account_public_access_block(run: CheckRun) -> dict[str, bool] | None:
    def load() -> dict[str, bool] | None:
        try:
            response = run.client("s3control").get_public_access_block(AccountId=run.scan.account_id)
        except ClientError as exc:
            if error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
                return None
            raise
        return response["PublicAccessBlockConfiguration"]

    return run.scan.cached("s3:account_pab", load)


def bucket_public_access_block(run: CheckRun, bucket: Bucket, s3: Any) -> dict[str, bool] | None:
    def load() -> dict[str, bool] | None:
        try:
            return s3.get_public_access_block(Bucket=bucket.name)["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            if error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
                return None
            raise

    return run.scan.cached(f"s3:bucket_pab:{bucket.name}", load)


def _settings(config: dict[str, bool] | None) -> dict[str, bool]:
    return {key: bool((config or {}).get(key)) for key in PAB_SETTINGS}


def _account_settings_or_none(run: CheckRun) -> dict[str, bool] | None:
    """Account-level settings, or None if they could not be read.

    Bucket checks only use these to give credit for account-wide blocking.
    If they cannot be read, the bucket is judged on its own settings.
    """
    try:
        return _settings(account_public_access_block(run))
    except (ClientError, BotoCoreError):
        return None


@check(
    id="s3-account-public-access-block",
    title="S3 Block Public Access is on for the account",
    service="s3",
    severity=Severity.HIGH,
    scope=Scope.GLOBAL,
    cis=("2.1.4",),
    description=(
        "The account-level Block Public Access settings stop any bucket in the account being made "
        "public by an ACL or bucket policy, whatever its own settings say."
    ),
    console="S3 > Block Public Access settings for this account > Edit > tick all four settings > Save.",
    cli=(
        "aws s3control put-public-access-block --account-id <ACCOUNT_ID> --public-access-block-configuration "
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    ),
)
def account_pab(run: CheckRun) -> None:
    settings = _settings(account_public_access_block(run))
    off = [key for key, value in settings.items() if not value]
    if off:
        message = f"Account-level Block Public Access is not fully on (off: {', '.join(off)})"
        run.failed(run.scan.account_arn, message, settings)
    else:
        run.passed(run.scan.account_arn, "All four account-level Block Public Access settings are on", settings)


@check(
    id="s3-bucket-public-access-block",
    title="Each bucket is covered by Block Public Access",
    service="s3",
    severity=Severity.MEDIUM,
    scope=Scope.GLOBAL,
    cis=("2.1.4",),
    description=(
        "S3 applies the stricter of the bucket and account settings. A bucket passes if, for each of "
        "the four settings, either the bucket or the account has it on."
    ),
    console="S3 > choose the bucket > Permissions > Block public access (bucket settings) > Edit > tick all four.",
    cli=(
        "aws s3api put-public-access-block --bucket <BUCKET> --public-access-block-configuration "
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    ),
)
def bucket_pab(run: CheckRun) -> None:
    account = _account_settings_or_none(run)

    def one(bucket: Bucket, s3: Any) -> None:
        own = _settings(bucket_public_access_block(run, bucket, s3))
        effective = {key: own[key] or bool(account and account[key]) for key in PAB_SETTINGS}
        evidence = {
            "bucket_settings": own,
            "account_settings": account if account is not None else "could not be read",
        }
        off = [key for key, value in effective.items() if not value]
        if not off:
            source = "bucket settings" if all(own.values()) else "bucket and account settings combined"
            run.passed(
                bucket.arn,
                f"Bucket {bucket.name} is fully covered by Block Public Access ({source})",
                evidence,
                region=bucket.region,
            )
        else:
            run.failed(
                bucket.arn,
                f"Bucket {bucket.name} is not fully covered by Block Public Access (off: {', '.join(off)})",
                evidence,
                region=bucket.region,
            )

    for_each_bucket(run, one)


@check(
    id="s3-bucket-policy-public",
    title="No bucket policy allows access to anyone",
    service="s3",
    severity=Severity.CRITICAL,
    scope=Scope.GLOBAL,
    description=(
        "A bucket policy statement that allows Principal '*' with no Condition lets anyone on the "
        "internet perform the listed actions, unless RestrictPublicBuckets is on."
    ),
    console=(
        "S3 > choose the bucket > Permissions > Bucket policy > Edit. Replace Principal '*' with the "
        "accounts or roles that need access, or add a Condition. For a public website, serve it through "
        "CloudFront with origin access control instead."
    ),
    cli=(
        "aws s3api get-bucket-policy --bucket <BUCKET> --query Policy --output text > policy.json\n"
        "# edit policy.json, then:\n"
        "aws s3api put-bucket-policy --bucket <BUCKET> --policy file://policy.json\n"
        "# or remove it entirely: aws s3api delete-bucket-policy --bucket <BUCKET>"
    ),
)
def bucket_policy_public(run: CheckRun) -> None:
    account = _account_settings_or_none(run)

    def one(bucket: Bucket, s3: Any) -> None:
        try:
            policy = load_document(s3.get_bucket_policy(Bucket=bucket.name)["Policy"])
        except ClientError as exc:
            if error_code(exc) != "NoSuchBucketPolicy":
                raise
            run.passed(bucket.arn, f"Bucket {bucket.name} has no bucket policy", region=bucket.region)
            return
        public = public_allow_statements(policy)
        if not public:
            message = f"Bucket {bucket.name} policy has no unconditioned Principal '*' allow"
            run.passed(bucket.arn, message, region=bucket.region)
            return
        own = _settings(bucket_public_access_block(run, bucket, s3))
        restricted = own["RestrictPublicBuckets"] or bool(account and account["RestrictPublicBuckets"])
        evidence = {
            "public_statements": [
                {"sid": st.get("Sid"), "actions": as_list(st.get("Action")), "resources": as_list(st.get("Resource"))}
                for st in public
            ],
            "restrict_public_buckets": restricted,
        }
        if restricted:
            run.failed(
                bucket.arn,
                f"Bucket {bucket.name} policy allows Principal '*', but RestrictPublicBuckets currently blocks "
                "access from outside the account",
                evidence,
                region=bucket.region,
                severity=Severity.MEDIUM,
            )
        else:
            run.failed(
                bucket.arn,
                f"Bucket {bucket.name} policy allows access to anyone (Principal '*')",
                evidence,
                region=bucket.region,
            )

    for_each_bucket(run, one)


@check(
    id="s3-default-encryption",
    title="Buckets have default encryption configured",
    service="s3",
    severity=Severity.LOW,
    scope=Scope.GLOBAL,
    description=(
        "Since January 2023 AWS applies SSE-S3 to new buckets automatically, so on current accounts this "
        "mostly reports which algorithm each bucket uses. It fails if no default encryption is configured."
    ),
    console="S3 > choose the bucket > Properties > Default encryption > Edit > choose SSE-S3 or SSE-KMS.",
    cli=(
        "aws s3api put-bucket-encryption --bucket <BUCKET> --server-side-encryption-configuration "
        '\'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"},'
        '"BucketKeyEnabled":true}]}\''
    ),
)
def default_encryption(run: CheckRun) -> None:
    def one(bucket: Bucket, s3: Any) -> None:
        try:
            rules = s3.get_bucket_encryption(Bucket=bucket.name)["ServerSideEncryptionConfiguration"]["Rules"]
        except ClientError as exc:
            if error_code(exc) != "ServerSideEncryptionConfigurationNotFoundError":
                raise
            run.failed(bucket.arn, f"Bucket {bucket.name} has no default encryption configured", region=bucket.region)
            return
        algorithms = sorted(
            {r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "unknown") for r in rules}
        )
        run.passed(
            bucket.arn,
            f"Bucket {bucket.name} encrypts new objects by default ({', '.join(algorithms)})",
            {"algorithms": algorithms},
            region=bucket.region,
        )

    for_each_bucket(run, one)


VERSIONING_FIX = Remediation(
    console="S3 > choose the bucket > Properties > Bucket Versioning > Edit > Enable.",
    cli="aws s3api put-bucket-versioning --bucket <BUCKET> --versioning-configuration Status=Enabled",
)
LOGGING_FIX = Remediation(
    console=(
        "S3 > choose the bucket > Properties > Server access logging > Edit > Enable, and pick a separate "
        "log bucket. Do not log a bucket into itself."
    ),
    cli=(
        "aws s3api put-bucket-logging --bucket <BUCKET> --bucket-logging-status "
        '\'{"LoggingEnabled":{"TargetBucket":"<LOG_BUCKET>","TargetPrefix":"<BUCKET>/"}}\''
    ),
)


@check(
    id="s3-versioning-and-logging",
    title="Buckets have versioning and server access logging",
    service="s3",
    severity=Severity.LOW,
    scope=Scope.GLOBAL,
    description=(
        "Versioning lets you recover objects that were overwritten or deleted, including by ransomware "
        "or a bad script. Server access logs record who requested what. Each bucket gets one finding for "
        "versioning and one for logging."
    ),
    console=VERSIONING_FIX.console + "\n" + LOGGING_FIX.console,
    cli=VERSIONING_FIX.cli + "\n" + LOGGING_FIX.cli,
)
def versioning_and_logging(run: CheckRun) -> None:
    def one(bucket: Bucket, s3: Any) -> None:
        versioning = s3.get_bucket_versioning(Bucket=bucket.name)
        status = versioning.get("Status", "never enabled")
        evidence = {"versioning": status, "mfa_delete": versioning.get("MFADelete", "Disabled")}
        if status == "Enabled":
            run.passed(bucket.arn, f"Bucket {bucket.name} has versioning enabled", evidence, region=bucket.region)
        else:
            run.failed(
                bucket.arn,
                f"Bucket {bucket.name} does not have versioning enabled ({status})",
                evidence,
                region=bucket.region,
                remediation=VERSIONING_FIX,
            )

        logging = s3.get_bucket_logging(Bucket=bucket.name).get("LoggingEnabled")
        if logging:
            run.passed(
                bucket.arn,
                f"Bucket {bucket.name} has server access logging to {logging.get('TargetBucket')}",
                {"target_bucket": logging.get("TargetBucket"), "target_prefix": logging.get("TargetPrefix")},
                region=bucket.region,
            )
        else:
            run.failed(
                bucket.arn,
                f"Bucket {bucket.name} does not have server access logging enabled",
                {"logging": "disabled"},
                region=bucket.region,
                remediation=LOGGING_FIX,
            )

    for_each_bucket(run, one)
