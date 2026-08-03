"""IAM checks against moto.

moto always reports the root user as having no access keys and no MFA, and
there is no API to change that, so the root checks use botocore's Stubber for
the side moto cannot produce.
"""

from __future__ import annotations

import json

import boto3
import pytest
from botocore.stub import Stubber

from .helpers import ACCOUNT_ID, errors, failed, passed

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
STAR_POLICY = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
READ_POLICY = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
)


@pytest.fixture
def iam(aws):
    return boto3.client("iam")


def summary_stub(ctx, **values):
    stubber = Stubber(ctx.client("iam"))
    summary = {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0, **values}
    stubber.add_response("get_account_summary", {"SummaryMap": summary})
    return stubber


# --- root -------------------------------------------------------------------


def test_root_access_keys_pass_when_none(scan):
    result = scan("iam-root-access-keys")
    assert len(passed(result)) == 1 and not failed(result)
    assert passed(result)[0].resource_arn == f"arn:aws:iam::{ACCOUNT_ID}:root"


def test_root_access_keys_fail_when_present(scan, make_ctx):
    ctx = make_ctx()
    with summary_stub(ctx, AccountAccessKeysPresent=1):
        result = scan("iam-root-access-keys", ctx=ctx)
    [finding] = failed(result)
    assert finding.cis == ("1.4",)
    assert finding.severity.value == "critical"
    assert finding.region == "global"


def test_root_mfa_fails_without_mfa(scan):
    [finding] = failed(scan("iam-root-mfa"))
    assert finding.evidence == {"AccountMFAEnabled": 0}
    assert finding.cis == ("1.5",)


def test_root_mfa_passes_with_mfa(scan, make_ctx):
    ctx = make_ctx()
    with summary_stub(ctx, AccountMFAEnabled=1):
        result = scan("iam-root-mfa", ctx=ctx)
    assert len(passed(result)) == 1 and not failed(result)


def test_root_checks_share_one_summary_call(scan, make_ctx):
    ctx = make_ctx()
    # Only one response is queued; a second call would raise and show up as an error.
    with summary_stub(ctx, AccountMFAEnabled=1):
        result = scan("iam-root-mfa", "iam-root-access-keys", ctx=ctx)
    assert not errors(result)
    assert len(passed(result)) == 2


# --- console users ------------------------------------------------------------


def test_console_user_without_mfa_fails(iam, scan):
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Correct-Horse-1")
    iam.create_user(UserName="api-only")  # no password, so not in scope
    [finding] = failed(scan("iam-user-console-mfa"))
    assert finding.resource_arn == f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
    assert finding.cis == ("1.10",)


def test_console_user_with_mfa_passes(iam, scan):
    iam.create_user(UserName="bob")
    iam.create_login_profile(UserName="bob", Password="Correct-Horse-1")
    serial = iam.create_virtual_mfa_device(VirtualMFADeviceName="bob")["VirtualMFADevice"]["SerialNumber"]
    iam.enable_mfa_device(
        UserName="bob", SerialNumber=serial, AuthenticationCode1="123456", AuthenticationCode2="654321"
    )
    result = scan("iam-user-console-mfa")
    assert not failed(result)
    assert [f.resource_arn for f in passed(result)] == [f"arn:aws:iam::{ACCOUNT_ID}:user/bob"]


# --- password policy -------------------------------------------------------------


def test_missing_password_policy_fails(scan):
    [finding] = failed(scan("iam-password-policy"))
    assert "No custom password policy" in finding.message
    assert finding.cis == ("1.8", "1.9")


def test_weak_password_policy_fails_both_controls(iam, scan):
    iam.update_account_password_policy(MinimumPasswordLength=8, PasswordReusePrevention=5)
    findings = failed(scan("iam-password-policy"))
    assert sorted(f.cis for f in findings) == [("1.8",), ("1.9",)]


def test_strong_password_policy_passes(iam, scan):
    iam.update_account_password_policy(MinimumPasswordLength=16, PasswordReusePrevention=24)
    result = scan("iam-password-policy")
    assert not failed(result)
    assert len(passed(result)) == 2


# --- access keys -------------------------------------------------------------


def test_new_access_key_passes_rotation(iam, scan):
    iam.create_user(UserName="ci")
    iam.create_access_key(UserName="ci")
    result = scan("iam-access-key-rotation")
    assert not failed(result)
    assert passed(result)[0].evidence["age_days"] == 0


def test_old_access_key_fails_rotation(iam, scan):
    iam.create_user(UserName="ci")
    iam.create_access_key(UserName="ci")
    # moto stamps keys with the current time, so move the scanner's clock forward instead.
    [finding] = failed(scan("iam-access-key-rotation", days_later=120))
    assert finding.evidence["age_days"] == 120
    assert finding.cis == ("1.14",)


def test_inactive_old_key_is_ignored(iam, scan):
    iam.create_user(UserName="ci")
    key = iam.create_access_key(UserName="ci")["AccessKey"]
    iam.update_access_key(UserName="ci", AccessKeyId=key["AccessKeyId"], Status="Inactive")
    result = scan("iam-access-key-rotation", days_later=120)
    assert not failed(result) and not passed(result)


def test_recent_credentials_pass_unused_check(iam, scan):
    iam.create_user(UserName="dev")
    iam.create_login_profile(UserName="dev", Password="Correct-Horse-1")
    iam.create_access_key(UserName="dev")
    result = scan("iam-unused-credentials", days_later=10)
    assert not failed(result)
    assert len(passed(result)) == 1


def test_never_used_credentials_fail_after_45_days(iam, scan):
    iam.create_user(UserName="dev")
    iam.create_login_profile(UserName="dev", Password="Correct-Horse-1")
    iam.create_access_key(UserName="dev")
    [finding] = failed(scan("iam-unused-credentials", days_later=60))
    assert finding.cis == ("1.12",)
    assert finding.evidence["stale"] == [
        "console password never used for 60 days",
        "access key 1 never used for 60 days",
    ]


# --- admin attached to users ------------------------------------------------------


@pytest.mark.managed_policies
def test_user_with_administrator_access_fails(iam, scan):
    iam.create_user(UserName="deploy-bot")
    iam.attach_user_policy(UserName="deploy-bot", PolicyArn=ADMIN_ARN)
    [finding] = failed(scan("iam-user-admin-policy"))
    assert finding.evidence["policies"] == ["AdministratorAccess (AWS managed)"]
    assert finding.cis == ()


def test_customer_managed_and_inline_star_policies_fail(iam, scan):
    iam.create_user(UserName="ops")
    policy = iam.create_policy(PolicyName="everything", PolicyDocument=STAR_POLICY)["Policy"]
    iam.attach_user_policy(UserName="ops", PolicyArn=policy["Arn"])
    iam.put_user_policy(UserName="ops", PolicyName="inline-admin", PolicyDocument=STAR_POLICY)
    [finding] = failed(scan("iam-user-admin-policy"))
    assert finding.evidence["policies"] == [
        "everything (customer managed, allows *:*)",
        "inline-admin (inline, allows *:*)",
    ]


def test_user_with_scoped_policy_passes(iam, scan):
    iam.create_user(UserName="reader")
    policy = iam.create_policy(PolicyName="read-objects", PolicyDocument=READ_POLICY)["Policy"]
    iam.attach_user_policy(UserName="reader", PolicyArn=policy["Arn"])
    result = scan("iam-user-admin-policy")
    assert not failed(result)
    assert len(passed(result)) == 1


def test_access_denied_on_credential_report_is_could_not_check(scan, make_ctx):
    ctx = make_ctx()
    stubber = Stubber(ctx.client("iam"))
    stubber.add_client_error("generate_credential_report", service_error_code="AccessDenied", http_status_code=403)
    with stubber:
        result = scan("iam-user-console-mfa", "iam-unused-credentials", ctx=ctx)
    # One cached failure, reported by both checks that needed the report.
    assert {f.check_id for f in errors(result)} == {"iam-user-console-mfa", "iam-unused-credentials"}
    assert not passed(result)
