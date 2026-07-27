"""IAM checks."""

from __future__ import annotations

import csv
import io
import time
from datetime import datetime

from botocore.exceptions import ClientError

from ..context import CheckRun
from ..errors import error_code
from ..models import Severity
from ..registry import Scope, check

ROOT_ROW = "<root_account>"
KEY_ROTATION_DAYS = 90
UNUSED_CREDENTIAL_DAYS = 45
MIN_PASSWORD_LENGTH = 14
PASSWORD_REUSE_COUNT = 24


# --- shared lookups -------------------------------------------------------


def account_summary(run: CheckRun) -> dict[str, int]:
    return run.scan.cached(
        "iam:account_summary", lambda: run.client("iam").get_account_summary()["SummaryMap"]
    )


def credential_report(run: CheckRun) -> list[dict[str, str]]:
    """The IAM credential report as a list of rows, fetched once per scan."""

    def load() -> list[dict[str, str]]:
        iam = run.client("iam")
        for _ in range(15):
            iam.generate_credential_report()
            try:
                content = iam.get_credential_report()["Content"]
            except ClientError as exc:
                # The report is built asynchronously; wait and ask again.
                if error_code(exc) in {"ReportInProgress", "ReportNotPresent", "ReportExpired"}:
                    time.sleep(2)
                    continue
                raise
            text = content.decode("utf-8") if isinstance(content, bytes) else content
            return list(csv.DictReader(io.StringIO(text)))
        raise TimeoutError("the IAM credential report was not ready after 30 seconds")

    return run.scan.cached("iam:credential_report", load)


def report_time(value: str | None) -> datetime | None:
    """Parse a credential report timestamp. N/A, no_information etc. become None."""
    if not value or value in {"N/A", "no_information", "not_supported"}:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def days_since(run: CheckRun, moment: datetime) -> int:
    return (run.scan.now - moment).days


def user_rows(run: CheckRun) -> list[dict[str, str]]:
    return [row for row in credential_report(run) if row.get("user") != ROOT_ROW]


# --- root user ------------------------------------------------------------


@check(
    id="iam-root-access-keys",
    title="Root user has no access keys",
    service="iam",
    severity=Severity.CRITICAL,
    scope=Scope.GLOBAL,
    cis=("1.4",),
    description="Access keys on the root user give unrestricted, unscoped API access to the whole account.",
    console=(
        "Sign in as the root user, open Security credentials from the account menu, "
        "and delete every key under Access keys. Use IAM roles for programmatic access instead."
    ),
    cli=(
        "Root keys can only be removed with root credentials. While signed in as root: "
        "aws iam list-access-keys && aws iam delete-access-key --access-key-id <KEY_ID>"
    ),
)
def root_access_keys(run: CheckRun) -> None:
    present = account_summary(run).get("AccountAccessKeysPresent", 0)
    evidence = {"AccountAccessKeysPresent": present}
    if present:
        run.failed(run.scan.account_arn, "The root user has at least one access key", evidence)
    else:
        run.passed(run.scan.account_arn, "The root user has no access keys", evidence)


@check(
    id="iam-root-mfa",
    title="Root user has MFA enabled",
    service="iam",
    severity=Severity.CRITICAL,
    scope=Scope.GLOBAL,
    cis=("1.5",),
    description="Without MFA, the root user is protected by a password alone.",
    console=(
        "Sign in as the root user, open Security credentials from the account menu, "
        "and choose Assign MFA device. A hardware key or passkey is the stronger choice."
    ),
    cli="Root MFA has to be set up while signed in as the root user; use the console steps.",
)
def root_mfa(run: CheckRun) -> None:
    enabled = account_summary(run).get("AccountMFAEnabled", 0)
    evidence = {"AccountMFAEnabled": enabled}
    if enabled == 1:
        run.passed(run.scan.account_arn, "MFA is enabled for the root user", evidence)
    else:
        run.failed(run.scan.account_arn, "MFA is not enabled for the root user", evidence)
