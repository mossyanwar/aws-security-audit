"""Check modules. Importing this package registers every check."""

from . import cloudtrail, ec2, iam, kms, monitoring, rds, s3  # noqa: F401
