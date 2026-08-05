"""Suppressions: accepted findings, each with a reason and an expiry date.

A suppression never hides a finding. The finding stays in every report,
marked as suppressed with its reason, and stops counting towards --fail-on.
Every entry must expire, so accepted risks come back up for review.

    suppressions:
      - check: s3-versioning-and-logging
        resource: arn:aws:s3:::example-access-logs
        reason: Target bucket for access logs; logging it into itself would loop.
        expires: 2027-03-31
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from fnmatch import fnmatchcase
from pathlib import Path

import yaml

from .models import Finding, Status

REQUIRED_KEYS = ("check", "resource", "reason", "expires")
LONG_LIVED = timedelta(days=365)


class SuppressionError(ValueError):
    """The suppressions file is malformed. The scan refuses to guess what was meant."""


@dataclass(frozen=True)
class Suppression:
    check: str
    # Exact ARN, or a shell-style pattern such as arn:aws:s3:::logs-*
    resource: str
    reason: str
    expires: date

    def matches(self, finding: Finding) -> bool:
        return finding.check_id == self.check and fnmatchcase(finding.resource_arn, self.resource)


def _parse_date(value: object, where: str) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            pass
    raise SuppressionError(f"{where}: expires must be a date like 2027-03-31, got {value!r}")


def parse(text: str, known_checks: set[str], today: date) -> tuple[list[Suppression], list[str]]:
    """Return (active suppressions, warnings). Raises SuppressionError on bad input."""
    # safe_load only builds plain types; yaml.load could construct arbitrary objects.
    data = yaml.safe_load(text)
    if data is None:
        return [], []
    if not isinstance(data, dict) or not isinstance(data.get("suppressions"), list):
        raise SuppressionError("the file must contain a top-level 'suppressions:' list")

    active: list[Suppression] = []
    warnings: list[str] = []
    for number, entry in enumerate(data["suppressions"], start=1):
        where = f"suppression {number}"
        if not isinstance(entry, dict):
            raise SuppressionError(f"{where}: each entry must be a mapping with {', '.join(REQUIRED_KEYS)}")
        missing = [key for key in REQUIRED_KEYS if entry.get(key) in (None, "")]
        if missing:
            raise SuppressionError(f"{where}: missing {', '.join(missing)}")
        unknown = set(entry) - set(REQUIRED_KEYS)
        if unknown:
            raise SuppressionError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")

        check, resource, reason = (str(entry[k]).strip() for k in ("check", "resource", "reason"))
        if check not in known_checks:
            raise SuppressionError(f"{where}: unknown check id {check!r}")
        if not resource.strip("*?"):
            raise SuppressionError(
                f"{where}: resource {resource!r} would match everything; use --skip-check to turn a check off"
            )
        if not reason:
            raise SuppressionError(f"{where}: reason must not be empty")
        expires = _parse_date(entry["expires"], where)

        if expires < today:
            warnings.append(f"{where} ({check} on {resource}) expired on {expires} and no longer applies")
            continue
        if expires - today > LONG_LIVED:
            warnings.append(f"{where} ({check} on {resource}) is set to last until {expires}, more than a year away")
        active.append(Suppression(check, resource, reason, expires))
    return active, warnings


def load(path: Path, known_checks: set[str], today: date) -> tuple[list[Suppression], list[str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SuppressionError(f"cannot read {path}: {exc.strerror}") from None
    try:
        return parse(text, known_checks, today)
    except yaml.YAMLError as exc:
        raise SuppressionError(f"{path} is not valid YAML: {exc}") from None


def apply(findings: list[Finding], suppressions: list[Suppression], checks_run: set[str]) -> list[str]:
    """Mark matching failures as suppressed. Returns warnings for suppressions that matched nothing.

    Only failures can be suppressed. A "could not check" result stays visible
    because nobody knows yet what it would have found.
    """
    used: set[Suppression] = set()
    for finding in findings:
        if finding.status is not Status.FAIL:
            continue
        for suppression in suppressions:
            if suppression.matches(finding):
                finding.suppressed = True
                finding.suppression_reason = f"{suppression.reason} (until {suppression.expires.isoformat()})"
                used.add(suppression)
                break
    return [
        f"suppression for {s.check} on {s.resource} matched no failed finding"
        for s in suppressions
        if s not in used and s.check in checks_run
    ]
