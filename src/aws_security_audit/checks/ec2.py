"""EC2 and VPC checks: security groups, EBS encryption, public images and snapshots, IMDSv2."""

from __future__ import annotations

from typing import Any

from ..context import CheckRun, paginate
from ..models import Severity
from ..registry import Scope, check

ANYWHERE_V4 = "0.0.0.0/0"
ANYWHERE_V6 = "::/0"

# CIS 5.2 and 5.3 cover remote administration ports.
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
# Database and cache ports. Not part of a CIS control, but just as bad to expose.
DATA_PORTS = {
    1433: "SQL Server",
    1521: "Oracle",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    5439: "Redshift",
    6379: "Redis",
    9042: "Cassandra",
    9200: "Elasticsearch/OpenSearch",
    11211: "Memcached",
    27017: "MongoDB",
}
WATCHED_PORTS = {**ADMIN_PORTS, **DATA_PORTS}


def sg_arn(run: CheckRun, group_id: str) -> str:
    return run.scan.arn("ec2", run.region, f"security-group/{group_id}")


def security_groups(run: CheckRun) -> list[dict[str, Any]]:
    return run.scan.cached(
        f"ec2:security_groups:{run.region}",
        lambda: list(paginate(run.client("ec2"), "describe_security_groups", "SecurityGroups")),
    )


def _ports_in_rule(rule: dict[str, Any]) -> list[int] | None:
    """Watched ports a rule opens. None means the rule opens every port."""
    protocol = str(rule.get("IpProtocol"))
    if protocol == "-1":
        return None
    if protocol not in {"tcp", "udp", "6", "17"}:
        return []
    low, high = rule.get("FromPort"), rule.get("ToPort")
    if low is None or high is None:
        return []
    return [port for port in WATCHED_PORTS if low <= port <= high]


def open_exposures(group: dict[str, Any]) -> list[dict[str, Any]]:
    """Inbound rules that let the whole internet reach an admin or data port."""
    exposures = []
    for rule in group.get("IpPermissions", []):
        sources = [r["CidrIp"] for r in rule.get("IpRanges", []) if r.get("CidrIp") == ANYWHERE_V4]
        sources += [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", []) if r.get("CidrIpv6") == ANYWHERE_V6]
        if not sources:
            continue
        ports = _ports_in_rule(rule)
        for source in sources:
            if ports is None:
                exposures.append({"port": "all", "service": "all traffic", "source": source, "admin": True})
                continue
            for port in sorted(ports):
                exposures.append(
                    {"port": port, "service": WATCHED_PORTS[port], "source": source, "admin": port in ADMIN_PORTS}
                )
    return exposures


def _cis_for(exposures: list[dict[str, Any]]) -> tuple[str, ...]:
    """CIS 5.2 is IPv4 admin ports, 5.3 is IPv6 admin ports. Data ports map to neither."""
    cis = set()
    for exposure in exposures:
        if exposure["admin"]:
            cis.add("5.2" if exposure["source"] == ANYWHERE_V4 else "5.3")
    return tuple(sorted(cis))


@check(
    id="ec2-sg-open-to-internet",
    title="No security group opens admin or database ports to the internet",
    service="ec2",
    severity=Severity.HIGH,
    scope=Scope.REGIONAL,
    cis=("5.2", "5.3"),
    description=(
        "Inbound rules from 0.0.0.0/0 or ::/0 to SSH, RDP or common database ports invite brute force "
        "and exploit attempts within minutes. CIS 5.2/5.3 are attached per finding, only when an admin "
        "port is exposed over IPv4 or IPv6 respectively."
    ),
    console=(
        "EC2 > Security Groups > choose the group > Inbound rules > Edit inbound rules. Remove the "
        "0.0.0.0/0 and ::/0 rules for these ports. Reach instances through Systems Manager Session Manager "
        "or a VPN, and allow databases only from the application's security group."
    ),
    cli=(
        "aws ec2 revoke-security-group-ingress --group-id <SG_ID> "
        "--ip-permissions 'IpProtocol=tcp,FromPort=<PORT>,ToPort=<PORT>,IpRanges=[{CidrIp=0.0.0.0/0}]'\n"
        "aws ec2 revoke-security-group-ingress --group-id <SG_ID> "
        "--ip-permissions 'IpProtocol=tcp,FromPort=<PORT>,ToPort=<PORT>,Ipv6Ranges=[{CidrIpv6=::/0}]'"
    ),
)
def sg_open_to_internet(run: CheckRun) -> None:
    for group in security_groups(run):
        arn = sg_arn(run, group["GroupId"])
        label = f"{group['GroupId']} ({group.get('GroupName', '')})"
        exposures = open_exposures(group)
        evidence = {"vpc_id": group.get("VpcId"), "exposures": exposures}
        if not exposures:
            run.passed(arn, f"Security group {label} has no admin or database ports open to the internet")
            continue
        described = ", ".join(
            f"{e['service']} ({e['port']}) from {e['source']}"
            if e["port"] != "all"
            else f"all ports from {e['source']}"
            for e in exposures
        )
        run.failed(arn, f"Security group {label} allows {described}", evidence, cis=_cis_for(exposures))


@check(
    id="ec2-default-sg-restricts-traffic",
    title="Default security groups have no rules and are not in use",
    service="ec2",
    severity=Severity.MEDIUM,
    scope=Scope.REGIONAL,
    cis=("5.4",),
    description=(
        "Anything launched without a chosen security group lands in the VPC's default group. If that group "
        "allows traffic, those resources are reachable without anyone deciding they should be. A default "
        "group with rules fails (CIS 5.4); one with no rules but attached interfaces gets a low finding."
    ),
    console=(
        "VPC > Security groups > the group named 'default' > remove every inbound and outbound rule. "
        "Move any instances or interfaces using it onto purpose-built security groups first."
    ),
    cli=(
        "aws ec2 describe-security-groups --group-ids <SG_ID>   # copy the rules to revoke\n"
        "aws ec2 revoke-security-group-ingress --group-id <SG_ID> --ip-permissions '<INBOUND_RULES_JSON>'\n"
        "aws ec2 revoke-security-group-egress --group-id <SG_ID> "
        "--ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]'\n"
        "aws ec2 modify-network-interface-attribute --network-interface-id <ENI_ID> --groups <OTHER_SG_ID>"
    ),
)
def default_sg(run: CheckRun) -> None:
    ec2 = run.client("ec2")
    for group in security_groups(run):
        if group.get("GroupName") != "default":
            continue
        arn = sg_arn(run, group["GroupId"])
        with run.guard(arn):
            interfaces = list(
                paginate(
                    ec2,
                    "describe_network_interfaces",
                    "NetworkInterfaces",
                    Filters=[{"Name": "group-id", "Values": [group["GroupId"]]}],
                )
            )
            evidence = {
                "vpc_id": group.get("VpcId"),
                "inbound_rules": len(group.get("IpPermissions", [])),
                "outbound_rules": len(group.get("IpPermissionsEgress", [])),
                "attached_network_interfaces": len(interfaces),
            }
            where = f"Default security group {group['GroupId']} in {group.get('VpcId')}"
            in_use = f", attached to {len(interfaces)} network interface(s)" if interfaces else ""
            if evidence["inbound_rules"] or evidence["outbound_rules"]:
                run.failed(
                    arn,
                    f"{where} has {evidence['inbound_rules']} inbound and {evidence['outbound_rules']} "
                    f"outbound rule(s){in_use}",
                    evidence,
                )
            elif interfaces:
                run.failed(
                    arn,
                    f"{where} has no rules but is in use{in_use}",
                    evidence,
                    severity=Severity.LOW,
                    cis=(),
                )
            else:
                run.passed(arn, f"{where} has no rules and is not in use", evidence)


@check(
    id="ec2-ebs-default-encryption",
    title="EBS encryption by default is on in every region",
    service="ec2",
    severity=Severity.MEDIUM,
    scope=Scope.REGIONAL,
    cis=("2.2.1",),
    description="With this on, every new EBS volume and snapshot copy in the region is encrypted automatically.",
    console=(
        "EC2 (in the region) > Settings > Data protection and security > EBS encryption > Manage > Enable. "
        "Existing volumes are not changed; they need a snapshot, an encrypted copy and a restore."
    ),
    cli="aws ec2 enable-ebs-encryption-by-default --region <REGION>",
)
def ebs_default_encryption(run: CheckRun) -> None:
    enabled = run.client("ec2").get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    evidence = {"EbsEncryptionByDefault": enabled}
    if enabled:
        run.passed(run.scan.account_arn, f"EBS encryption by default is on in {run.region}", evidence)
    else:
        run.failed(run.scan.account_arn, f"EBS encryption by default is off in {run.region}", evidence)


@check(
    id="ec2-public-amis-snapshots",
    title="No AMIs or EBS snapshots are shared publicly",
    service="ec2",
    severity=Severity.HIGH,
    scope=Scope.REGIONAL,
    description=(
        "A public AMI or snapshot can be copied by any AWS account. Disk images often contain "
        "credentials, keys and data that were never meant to leave the account."
    ),
    console=(
        "EC2 > AMIs > choose the AMI > Actions > Edit AMI permissions > Private. "
        "EC2 > Snapshots > choose the snapshot > Actions > Snapshot settings > Modify permissions > Private. "
        "Then turn on 'Block public access' for AMIs and for EBS snapshots in EC2 > Settings."
    ),
    cli=(
        "aws ec2 modify-image-attribute --image-id <AMI_ID> --launch-permission 'Remove=[{Group=all}]'\n"
        "aws ec2 modify-snapshot-attribute --snapshot-id <SNAPSHOT_ID> --attribute createVolumePermission "
        "--operation-type remove --group-names all\n"
        "aws ec2 enable-image-block-public-access --image-block-public-access-state block-new-sharing\n"
        "aws ec2 enable-snapshot-block-public-access --state block-all-sharing"
    ),
)
def public_amis_snapshots(run: CheckRun) -> None:
    ec2 = run.client("ec2")
    public = 0
    for image in paginate(ec2, "describe_images", "Images", Owners=["self"]):
        if image.get("Public"):
            public += 1
            arn = f"arn:{run.scan.partition}:ec2:{run.region}::image/{image['ImageId']}"
            run.failed(arn, f"AMI {image['ImageId']} ({image.get('Name', '')}) is public", {"public": True})

    # RestorableByUserIds=all narrows the list to snapshots anyone can restore.
    # Each one is confirmed with DescribeSnapshotAttribute before it is reported.
    candidates = paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"], RestorableByUserIds=["all"])
    for snapshot in candidates:
        snapshot_id = snapshot["SnapshotId"]
        arn = f"arn:{run.scan.partition}:ec2:{run.region}::snapshot/{snapshot_id}"
        with run.guard(arn):
            permissions = ec2.describe_snapshot_attribute(SnapshotId=snapshot_id, Attribute="createVolumePermission")
            if any(p.get("Group") == "all" for p in permissions.get("CreateVolumePermissions", [])):
                public += 1
                run.failed(
                    arn,
                    f"EBS snapshot {snapshot_id} is public",
                    {"volume_id": snapshot.get("VolumeId"), "encrypted": snapshot.get("Encrypted")},
                )
    if not public:
        run.passed(run.scan.account_arn, f"No public AMIs or EBS snapshots owned by the account in {run.region}")


@check(
    id="ec2-imdsv2-required",
    title="EC2 instances require IMDSv2",
    service="ec2",
    severity=Severity.MEDIUM,
    scope=Scope.REGIONAL,
    cis=("5.6",),
    description=(
        "IMDSv1 answers plain GET requests, so a server-side request forgery bug in an app on the "
        "instance can be used to read the instance role's credentials. IMDSv2 needs a session token."
    ),
    console=(
        "EC2 > Instances > choose the instance > Actions > Instance settings > Modify instance metadata "
        "options > IMDSv2: Required. Check that the software on the instance uses a recent AWS SDK first."
    ),
    cli=(
        "aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> "
        "--http-tokens required --http-endpoint enabled"
    ),
)
def imdsv2_required(run: CheckRun) -> None:
    for reservation in paginate(run.client("ec2"), "describe_instances", "Reservations"):
        for instance in reservation.get("Instances", []):
            state = instance.get("State", {}).get("Name")
            if state in {"terminated", "shutting-down"}:
                continue
            instance_id = instance["InstanceId"]
            arn = run.scan.arn("ec2", run.region, f"instance/{instance_id}")
            options = instance.get("MetadataOptions", {})
            evidence = {
                "state": state,
                "http_tokens": options.get("HttpTokens"),
                "http_endpoint": options.get("HttpEndpoint"),
            }
            if options.get("HttpEndpoint") == "disabled":
                run.passed(arn, f"Instance {instance_id} has the metadata service turned off", evidence)
            elif options.get("HttpTokens") == "required":
                run.passed(arn, f"Instance {instance_id} requires IMDSv2", evidence)
            else:
                run.failed(arn, f"Instance {instance_id} still accepts IMDSv1 requests", evidence)
