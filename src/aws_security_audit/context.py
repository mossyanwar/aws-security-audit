"""Scan-wide state (session, clients, caches) and the per-check helper object."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, TypeVar

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from . import __version__
from .errors import ReadOnlyViolation, classify
from .models import Finding, Remediation, Severity, Status
from .registry import CheckSpec

GLOBAL_REGION = "global"
DEFAULT_HOME_REGION = "us-east-1"

# Every API call the scanner makes must start with one of these, or be listed
# in READ_ONLY_EXTRA. The guard below refuses anything else before it is sent.
READ_ONLY_PREFIXES = ("Describe", "Get", "List")
# GenerateCredentialReport only builds the IAM credential report; AWS classes
# it as a read action and it is part of the SecurityAudit managed policy.
READ_ONLY_EXTRA = frozenset({"GenerateCredentialReport"})

BOTO_CONFIG = Config(
    retries={"mode": "standard", "max_attempts": 5},
    connect_timeout=5,
    read_timeout=30,
    user_agent_extra=f"aws-security-audit/{__version__}",
)

T = TypeVar("T")


def is_read_only_operation(operation: str) -> bool:
    return operation.startswith(READ_ONLY_PREFIXES) or operation in READ_ONLY_EXTRA


class ScanContext:
    """Holds what every check in a scan shares.

    boto3 clients are safe to share between threads once created, but creating
    them from one session is not, so creation happens under a lock. Lookups that
    several checks need (the IAM credential report, the bucket list) go through
    ``cached`` so they are fetched once per scan.
    """

    def __init__(
        self,
        session: boto3.Session,
        account_id: str,
        partition: str = "aws",
        home_region: str = DEFAULT_HOME_REGION,
        now: datetime | None = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.partition = partition
        self.home_region = home_region
        self.now = now or datetime.now(UTC)
        self.caller_arn: str | None = None
        self.operations: set[tuple[str, str]] = set()
        self._clients: dict[tuple[str, str], Any] = {}
        self._client_lock = threading.Lock()
        self._cache: dict[str, tuple[bool, Any]] = {}
        self._key_locks: dict[str, threading.Lock] = {}
        self._cache_guard = threading.Lock()
        self._ops_lock = threading.Lock()
        install_read_only_guard(session, self._record_operation)

    @classmethod
    def from_session(
        cls,
        session: boto3.Session,
        home_region: str | None = None,
        now: datetime | None = None,
    ) -> ScanContext:
        """Look up the account behind the session's credentials with sts:GetCallerIdentity."""
        region = home_region or session.region_name or DEFAULT_HOME_REGION
        sts = session.client("sts", region_name=region, config=BOTO_CONFIG)
        identity = sts.get_caller_identity()
        partition = identity["Arn"].split(":")[1]
        ctx = cls(session, identity["Account"], partition=partition, home_region=region, now=now)
        ctx.caller_arn = identity["Arn"]
        return ctx

    @property
    def account_arn(self) -> str:
        """The account's root ARN, used as the resource for account-level settings."""
        return f"arn:{self.partition}:iam::{self.account_id}:root"

    def arn(self, service: str, region: str, resource: str) -> str:
        return f"arn:{self.partition}:{service}:{region}:{self.account_id}:{resource}"

    def client(self, service: str, region: str | None = None) -> Any:
        region = region or self.home_region
        key = (service, region)
        with self._client_lock:
            client = self._clients.get(key)
            if client is None:
                client = self.session.client(service, region_name=region, config=BOTO_CONFIG)
                self._clients[key] = client
            return client

    def cached(self, key: str, loader: Callable[[], T]) -> T:
        """Run ``loader`` once per scan and share the result between threads.

        Failures are cached too, so an AccessDenied on a shared lookup is
        reported consistently by every check that needed it.
        """
        with self._cache_guard:
            lock = self._key_locks.setdefault(key, threading.Lock())
        with lock:
            if key not in self._cache:
                try:
                    self._cache[key] = (True, loader())
                except Exception as exc:  # noqa: BLE001 - re-raised below
                    self._cache[key] = (False, exc)
            ok, value = self._cache[key]
        if ok:
            return value
        raise value

    def _record_operation(self, service: str, operation: str) -> None:
        with self._ops_lock:
            self.operations.add((service, operation))


def install_read_only_guard(session: boto3.Session, record: Callable[[str, str], None] | None = None) -> None:
    """Refuse any API call that is not a read, before botocore sends it."""

    def guard(model: Any, **_: Any) -> None:
        service = model.service_model.service_name
        if not is_read_only_operation(model.name):
            raise ReadOnlyViolation(f"refusing to call {service}:{model.name}; the scanner is read-only")
        if record:
            record(service, model.name)

    session.events.register("before-call", guard, unique_id="aws-security-audit-read-only-guard")


def paginate(client: Any, method: str, result_key: str, **kwargs: Any) -> Iterator[Any]:
    """Yield every item under ``result_key``, following pagination when the API has it."""
    if client.can_paginate(method):
        for page in client.get_paginator(method).paginate(**kwargs):
            yield from page.get(result_key, [])
    else:
        yield from getattr(client, method)(**kwargs).get(result_key, [])


class CheckRun:
    """What a check function receives: its region, clients and finding helpers."""

    def __init__(self, scan: ScanContext, spec: CheckSpec, region: str) -> None:
        self.scan = scan
        self.spec = spec
        self.region = region
        self.api_region = scan.home_region if region == GLOBAL_REGION else region
        self.findings: list[Finding] = []

    def client(self, service: str, region: str | None = None) -> Any:
        return self.scan.client(service, region or self.api_region)

    def _add(
        self,
        status: Status,
        resource_arn: str,
        message: str,
        evidence: dict[str, Any] | None,
        region: str | None,
        severity: Severity | None,
        cis: tuple[str, ...] | list[str] | None,
        remediation: Remediation | None,
    ) -> Finding:
        finding = Finding(
            check_id=self.spec.id,
            title=self.spec.title,
            status=status,
            severity=severity or self.spec.severity,
            resource_arn=resource_arn,
            region=region or self.region,
            message=message,
            evidence=dict(evidence or {}),
            cis=tuple(self.spec.cis if cis is None else cis),
            remediation=remediation,
        )
        self.findings.append(finding)
        return finding

    def passed(
        self,
        resource_arn: str,
        message: str,
        evidence: dict[str, Any] | None = None,
        *,
        region: str | None = None,
        cis: tuple[str, ...] | list[str] | None = None,
    ) -> Finding:
        return self._add(Status.PASS, resource_arn, message, evidence, region, None, cis, None)

    def failed(
        self,
        resource_arn: str,
        message: str,
        evidence: dict[str, Any] | None = None,
        *,
        region: str | None = None,
        severity: Severity | None = None,
        cis: tuple[str, ...] | list[str] | None = None,
        remediation: Remediation | None = None,
    ) -> Finding:
        return self._add(
            Status.FAIL,
            resource_arn,
            message,
            evidence,
            region,
            severity,
            cis,
            remediation or self.spec.remediation,
        )

    def could_not_check(self, resource_arn: str, exc: BaseException, *, region: str | None = None) -> Finding:
        error = classify(exc)
        return self._add(Status.ERROR, resource_arn, error.describe(), error.to_evidence(), region, None, None, None)

    @contextmanager
    def guard(self, resource_arn: str, *, region: str | None = None) -> Iterator[None]:
        """Record an API error for one resource as "could not check" and carry on with the next."""
        try:
            yield
        except (ClientError, BotoCoreError, ReadOnlyViolation) as exc:
            self.could_not_check(resource_arn, exc, region=region)
