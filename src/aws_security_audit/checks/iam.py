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


# --- console users ----------------------------------------------------------


@check(
    id="iam-user-console-mfa",
    title="IAM users with a console password have MFA",
    service="iam",
    severity=Severity.HIGH,
    scope=Scope.GLOBAL,
    cis=("1.10",),
    description="A console password without MFA can be phished or guessed.",
    console=(
        "IAM > Users > choose the user > Security credentials > Assign MFA device. "
        "If the user does not need the console, remove the console password instead."
    ),
    cli=(
        "aws iam create-virtual-mfa-device --virtual-mfa-device-name <USER> "
        "--outfile <USER>-qr.png --bootstrap-method QRCodePNG\n"
        "aws iam enable-mfa-device --user-name <USER> --serial-number arn:aws:iam::<ACCOUNT_ID>:mfa/<USER> "
        "--authentication-code1 <CODE1> --authentication-code2 <CODE2>\n"
        "Or, if console access is not needed: aws iam delete-login-profile --user-name <USER>"
    ),
)
def user_console_mfa(run: CheckRun) -> None:
    for row in user_rows(run):
        if row.get("password_enabled") != "true":
            continue
        evidence = {
            "password_enabled": True,
            "mfa_active": row.get("mfa_active") == "true",
            "password_last_used": row.get("password_last_used"),
        }
        if row.get("mfa_active") == "true":
            run.passed(row["arn"], f"User {row['user']} has a console password and MFA", evidence)
        else:
            run.failed(row["arn"], f"User {row['user']} has a console password but no MFA device", evidence)


@check(
    id="iam-password-policy",
    title="Password policy requires 14+ characters and prevents reuse",
    service="iam",
    severity=Severity.MEDIUM,
    scope=Scope.GLOBAL,
    cis=("1.8", "1.9"),
    description="Short or reused passwords are easier to guess or to replay from another breach.",
    console=(
        "IAM > Account settings > Password policy > Edit. Set the minimum length to 14 or more "
        "and turn on 'Prevent password reuse' with 24 remembered passwords."
    ),
    cli=(
        "aws iam update-account-password-policy --minimum-password-length 14 --password-reuse-prevention 24 "
        "(this call resets any setting you leave out to its default, so include your current settings too)"
    ),
)
def password_policy(run: CheckRun) -> None:
    resource = run.scan.account_arn
    try:
        policy = run.client("iam").get_account_password_policy()["PasswordPolicy"]
    except ClientError as exc:
        if error_code(exc) != "NoSuchEntity":
            raise
        run.failed(
            resource,
            "No custom password policy is set; the AWS default does not require 14 characters or prevent reuse",
            {"password_policy": None},
        )
        return

    length = policy.get("MinimumPasswordLength", 0)
    evidence = {"MinimumPasswordLength": length}
    if length >= MIN_PASSWORD_LENGTH:
        run.passed(resource, f"Minimum password length is {length}", evidence, cis=("1.8",))
    else:
        run.failed(
            resource, f"Minimum password length is {length}, below {MIN_PASSWORD_LENGTH}", evidence, cis=("1.8",)
        )

    reuse = policy.get("PasswordReusePrevention", 0)
    evidence = {"PasswordReusePrevention": reuse}
    if reuse >= PASSWORD_REUSE_COUNT:
        run.passed(resource, f"The last {reuse} passwords cannot be reused", evidence, cis=("1.9",))
    elif reuse:
        run.failed(
            resource,
            f"Only the last {reuse} passwords are blocked from reuse (recommended {PASSWORD_REUSE_COUNT})",
            evidence,
            cis=("1.9",),
        )
    else:
        run.failed(resource, "The password policy does not prevent password reuse", evidence, cis=("1.9",))
