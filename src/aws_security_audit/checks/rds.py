"""RDS checks: public accessibility and storage encryption."""

from __future__ import annotations

from typing import Any

from ..context import CheckRun, paginate
from ..models import Severity
from ..registry import Scope, check


def db_instances(run: CheckRun) -> list[dict[str, Any]]:
    return run.scan.cached(
        f"rds:instances:{run.region}",
        lambda: list(paginate(run.client("rds"), "describe_db_instances", "DBInstances")),
    )


@check(
    id="rds-public-access",
    title="RDS instances are not publicly accessible",
    service="rds",
    severity=Severity.HIGH,
    scope=Scope.REGIONAL,
    cis=("2.3.3",),
    description=(
        "A publicly accessible instance gets a public DNS name and IP. Whether it is actually reachable "
        "also depends on its security groups and subnet routes, which this check does not evaluate."
    ),
    console=(
        "RDS > Databases > choose the instance > Modify > Connectivity > Additional configuration > "
        "Not publicly accessible > Continue > Apply immediately (or in the next maintenance window)."
    ),
    cli="aws rds modify-db-instance --db-instance-identifier <DB_ID> --no-publicly-accessible --apply-immediately",
)
def rds_public_access(run: CheckRun) -> None:
    for db in db_instances(run):
        evidence = {"engine": db.get("Engine"), "endpoint": (db.get("Endpoint") or {}).get("Address")}
        name = db["DBInstanceIdentifier"]
        if db.get("PubliclyAccessible"):
            run.failed(db["DBInstanceArn"], f"RDS instance {name} is publicly accessible", evidence)
        else:
            run.passed(db["DBInstanceArn"], f"RDS instance {name} is not publicly accessible", evidence)


@check(
    id="rds-storage-encrypted",
    title="RDS instances have encrypted storage",
    service="rds",
    severity=Severity.MEDIUM,
    scope=Scope.REGIONAL,
    cis=("2.3.1",),
    description="Encryption at rest protects the data files, backups, snapshots and read replicas.",
    console=(
        "Encryption cannot be turned on for an existing instance. Take a snapshot, copy it with "
        "encryption enabled (RDS > Snapshots > Actions > Copy snapshot), restore a new instance from "
        "the encrypted copy, then move traffic over."
    ),
    cli=(
        "aws rds create-db-snapshot --db-instance-identifier <DB_ID> --db-snapshot-identifier <DB_ID>-plain\n"
        "aws rds copy-db-snapshot --source-db-snapshot-identifier <DB_ID>-plain "
        "--target-db-snapshot-identifier <DB_ID>-encrypted --kms-key-id <KMS_KEY_ID>\n"
        "aws rds restore-db-instance-from-db-snapshot --db-instance-identifier <NEW_DB_ID> "
        "--db-snapshot-identifier <DB_ID>-encrypted"
    ),
)
def rds_storage_encrypted(run: CheckRun) -> None:
    for db in db_instances(run):
        name = db["DBInstanceIdentifier"]
        evidence = {"engine": db.get("Engine"), "kms_key_id": db.get("KmsKeyId")}
        if db.get("StorageEncrypted"):
            run.passed(db["DBInstanceArn"], f"RDS instance {name} has encrypted storage", evidence)
        else:
            run.failed(db["DBInstanceArn"], f"RDS instance {name} storage is not encrypted", evidence)
