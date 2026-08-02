"""EC2, VPC and RDS checks against moto."""

from __future__ import annotations

import boto3
import pytest

from aws_security_audit.models import Severity

from .helpers import ACCOUNT_ID, failed, passed

AMI = "ami-12345678"  # moto accepts any image id once default AMIs are turned off


@pytest.fixture
def ec2(aws):
    return boto3.client("ec2", region_name="us-east-1")


def make_group(ec2, name, rules):
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    group_id = ec2.create_security_group(GroupName=name, Description=name, VpcId=vpc_id)["GroupId"]
    if rules:
        ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=rules)
    return group_id


def tcp(port, v4=None, v6=None, to_port=None):
    rule = {"IpProtocol": "tcp", "FromPort": port, "ToPort": to_port or port}
    if v4:
        rule["IpRanges"] = [{"CidrIp": v4}]
    if v6:
        rule["Ipv6Ranges"] = [{"CidrIpv6": v6}]
    return rule


def default_group(ec2):
    return ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": ["default"]}])["SecurityGroups"][0]


def empty_default_group(ec2):
    group = default_group(ec2)
    if group["IpPermissionsEgress"]:
        ec2.revoke_security_group_egress(GroupId=group["GroupId"], IpPermissions=group["IpPermissionsEgress"])
    if group["IpPermissions"]:
        ec2.revoke_security_group_ingress(GroupId=group["GroupId"], IpPermissions=group["IpPermissions"])
    return group["GroupId"]


# --- security groups open to the internet ----------------------------------------


def test_ssh_open_to_ipv4_fails_with_cis_5_2(ec2, scan):
    group_id = make_group(ec2, "legacy-ssh", [tcp(22, v4="0.0.0.0/0")])
    findings = [f for f in failed(scan("ec2-sg-open-to-internet")) if group_id in f.resource_arn]
    [finding] = findings
    assert finding.cis == ("5.2",)
    assert finding.resource_arn == f"arn:aws:ec2:us-east-1:{ACCOUNT_ID}:security-group/{group_id}"
    assert "SSH (22) from 0.0.0.0/0" in finding.message


def test_database_port_open_to_ipv6_fails_without_cis(ec2, scan):
    group_id = make_group(ec2, "db-open", [tcp(5432, v6="::/0")])
    [finding] = [f for f in failed(scan("ec2-sg-open-to-internet")) if group_id in f.resource_arn]
    assert finding.cis == ()
    assert finding.evidence["exposures"][0]["service"] == "PostgreSQL"


def test_port_range_and_rdp_over_ipv6_map_to_both_controls(ec2, scan):
    group_id = make_group(ec2, "wide", [tcp(0, v4="0.0.0.0/0", to_port=65535), tcp(3389, v6="::/0")])
    [finding] = [f for f in failed(scan("ec2-sg-open-to-internet")) if group_id in f.resource_arn]
    assert finding.cis == ("5.2", "5.3")
    assert finding.severity is Severity.HIGH


def test_restricted_source_or_web_port_passes(ec2, scan):
    group_id = make_group(ec2, "office-ssh-and-web", [tcp(22, v4="203.0.113.0/24"), tcp(443, v4="0.0.0.0/0")])
    result = scan("ec2-sg-open-to-internet")
    assert not [f for f in failed(result) if group_id in f.resource_arn]
    assert [f for f in passed(result) if group_id in f.resource_arn]


# --- default security group ---------------------------------------------------------


def test_default_group_with_rules_fails(ec2, scan):
    # moto's default group keeps the standard allow-all outbound rule.
    [finding] = failed(scan("ec2-default-sg-restricts-traffic"))
    assert finding.cis == ("5.4",)
    assert finding.evidence["outbound_rules"] == 1


def test_default_group_without_rules_or_users_passes(ec2, scan):
    empty_default_group(ec2)
    result = scan("ec2-default-sg-restricts-traffic")
    assert not failed(result)
    assert len(passed(result)) == 1


def test_default_group_in_use_without_rules_is_low(ec2, scan):
    empty_default_group(ec2)
    ec2.run_instances(ImageId=AMI, MinCount=1, MaxCount=1)
    [finding] = failed(scan("ec2-default-sg-restricts-traffic"))
    assert finding.severity is Severity.LOW
    assert finding.cis == ()
    assert finding.evidence["attached_network_interfaces"] == 1


# --- EBS default encryption -----------------------------------------------------------


def test_ebs_default_encryption_off_fails(ec2, scan):
    [finding] = failed(scan("ec2-ebs-default-encryption"))
    assert finding.cis == ("2.2.1",)
    assert finding.region == "us-east-1"


def test_ebs_default_encryption_is_checked_per_region(aws, scan):
    boto3.client("ec2", region_name="eu-west-2").enable_ebs_encryption_by_default()
    result = scan("ec2-ebs-default-encryption", regions=("us-east-1", "eu-west-2"))
    assert [f.region for f in passed(result)] == ["eu-west-2"]
    assert [f.region for f in failed(result)] == ["us-east-1"]


# --- public AMIs and snapshots ------------------------------------------------------------


def test_public_ami_and_snapshot_fail(ec2, scan):
    instance_id = ec2.run_instances(ImageId=AMI, MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
    image_id = ec2.create_image(InstanceId=instance_id, Name="golden")["ImageId"]
    ec2.modify_image_attribute(ImageId=image_id, LaunchPermission={"Add": [{"Group": "all"}]})
    volume_id = ec2.create_volume(AvailabilityZone="us-east-1a", Size=1)["VolumeId"]
    public_snap = ec2.create_snapshot(VolumeId=volume_id)["SnapshotId"]
    ec2.create_snapshot(VolumeId=volume_id)  # private, must not be reported
    ec2.modify_snapshot_attribute(
        SnapshotId=public_snap, Attribute="createVolumePermission", OperationType="add", GroupNames=["all"]
    )
    arns = sorted(f.resource_arn for f in failed(scan("ec2-public-amis-snapshots")))
    assert arns == [
        f"arn:aws:ec2:us-east-1::image/{image_id}",
        f"arn:aws:ec2:us-east-1::snapshot/{public_snap}",
    ]


def test_private_images_and_snapshots_pass(ec2, scan):
    volume_id = ec2.create_volume(AvailabilityZone="us-east-1a", Size=1)["VolumeId"]
    ec2.create_snapshot(VolumeId=volume_id)
    result = scan("ec2-public-amis-snapshots")
    assert not failed(result)
    assert len(passed(result)) == 1


# --- IMDSv2 -----------------------------------------------------------------------------


def test_instance_allowing_imdsv1_fails(ec2, scan):
    ec2.run_instances(ImageId=AMI, MinCount=1, MaxCount=1)
    [finding] = failed(scan("ec2-imdsv2-required"))
    assert finding.cis == ("5.6",)
    assert finding.evidence["http_tokens"] == "optional"


def test_instance_requiring_imdsv2_passes(ec2, scan):
    ec2.run_instances(ImageId=AMI, MinCount=1, MaxCount=1, MetadataOptions={"HttpTokens": "required"})
    result = scan("ec2-imdsv2-required")
    assert not failed(result)
    assert len(passed(result)) == 1


# --- RDS ---------------------------------------------------------------------------------


def make_db(name, region="us-east-1", **kwargs):
    boto3.client("rds", region_name=region).create_db_instance(
        DBInstanceIdentifier=name,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        MasterUsername="app",
        MasterUserPassword="not-a-real-password",
        AllocatedStorage=20,
        **kwargs,
    )


def test_public_unencrypted_rds_fails_both_checks(aws, scan):
    make_db("orders", region="eu-west-2", PubliclyAccessible=True, StorageEncrypted=False)
    result = scan("rds-public-access", "rds-storage-encrypted", regions=("eu-west-2",))
    by_check = {f.check_id: f for f in failed(result)}
    assert by_check["rds-public-access"].cis == ("2.3.3",)
    assert by_check["rds-storage-encrypted"].cis == ("2.3.1",)
    assert by_check["rds-public-access"].resource_arn == f"arn:aws:rds:eu-west-2:{ACCOUNT_ID}:db:orders"


def test_private_encrypted_rds_passes_both_checks(aws, scan):
    make_db("billing", PubliclyAccessible=False, StorageEncrypted=True)
    result = scan("rds-public-access", "rds-storage-encrypted")
    assert not failed(result)
    assert len(passed(result)) == 2
