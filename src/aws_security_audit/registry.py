"""Check registry.

Each check is a plain function decorated with ``@check(...)``. The decorator
records its metadata in a module-level registry, so adding a check means
writing one function in one of the modules under ``checks/`` and nothing else.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from .models import Remediation, Severity

if TYPE_CHECKING:
    from .context import CheckRun


class Scope(StrEnum):
    # Runs once per scan, for account-wide settings (IAM, S3 account settings).
    GLOBAL = "global"
    # Runs once in every scanned region.
    REGIONAL = "regional"


CheckFunc = Callable[["CheckRun"], None]


@dataclass(frozen=True)
class CheckSpec:
    id: str
    title: str
    service: str
    severity: Severity
    scope: Scope
    description: str
    remediation: Remediation
    func: CheckFunc
    # CIS AWS Foundations Benchmark v3.0.0 control IDs. Only filled in where the
    # check matches the control; empty otherwise.
    cis: tuple[str, ...] = ()


_REGISTRY: dict[str, CheckSpec] = {}


def check(
    *,
    id: str,
    title: str,
    service: str,
    severity: Severity,
    scope: Scope,
    description: str,
    console: str,
    cli: str,
    cis: Iterable[str] = (),
) -> Callable[[CheckFunc], CheckFunc]:
    """Register a check function under ``id``."""

    def decorator(func: CheckFunc) -> CheckFunc:
        if id in _REGISTRY:
            raise ValueError(f"check id {id!r} is registered twice")
        _REGISTRY[id] = CheckSpec(
            id=id,
            title=title,
            service=service,
            severity=severity,
            scope=scope,
            description=description,
            remediation=Remediation(console=console.strip(), cli=cli.strip()),
            func=func,
            cis=tuple(cis),
        )
        return func

    return decorator


def _load_checks() -> None:
    # Importing the package imports every check module, which fills the registry.
    importlib.import_module("aws_security_audit.checks")


def all_checks() -> list[CheckSpec]:
    _load_checks()
    return sorted(_REGISTRY.values(), key=lambda c: (c.service, c.id))


def get_check(check_id: str) -> CheckSpec:
    _load_checks()
    try:
        return _REGISTRY[check_id]
    except KeyError:
        raise KeyError(f"unknown check id {check_id!r}") from None


def select_checks(
    include: Iterable[str] = (),
    exclude: Iterable[str] = (),
    services: Iterable[str] = (),
) -> list[CheckSpec]:
    """Pick checks by id and service. Unknown ids raise rather than being ignored."""
    include, exclude, services = set(include), set(exclude), {s.lower() for s in services}
    checks = all_checks()
    known = {c.id for c in checks}
    unknown = (include | exclude) - known
    if unknown:
        raise KeyError(f"unknown check id(s): {', '.join(sorted(unknown))}")
    selected = []
    for spec in checks:
        if include and spec.id not in include:
            continue
        if spec.id in exclude:
            continue
        if services and spec.service not in services:
            continue
        selected.append(spec)
    return selected
