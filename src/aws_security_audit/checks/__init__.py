"""Check modules. Importing this package registers every check."""

from . import ec2, iam, rds, s3  # noqa: F401
