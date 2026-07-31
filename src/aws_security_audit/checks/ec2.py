"""EC2 and VPC checks."""

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
            f"{e['service']} ({e['port']}) from {e['source']}" if e["port"] != "all" else f"all ports from {e['source']}"
            for e in exposures
        )
        run.failed(arn, f"Security group {label} allows {described}", evidence, cis=_cis_for(exposures))
