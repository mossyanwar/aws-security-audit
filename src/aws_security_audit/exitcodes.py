"""Exit codes, so the scanner can gate a pipeline or a script."""

from __future__ import annotations

from .models import Severity
from .runner import ScanResult

EXIT_OK = 0
# An open (unsuppressed) failure at or above the --fail-on severity.
EXIT_FINDINGS = 1
# Bad arguments, a bad suppressions file, or no usable credentials.
EXIT_USAGE = 2
# --fail-on-incomplete was given and at least one item could not be checked.
EXIT_INCOMPLETE = 3


def exit_code(result: ScanResult, fail_on: Severity | None, fail_on_incomplete: bool = False) -> int:
    if fail_on is not None and result.has_open_failure_at_or_above(fail_on):
        return EXIT_FINDINGS
    if fail_on_incomplete and result.incomplete:
        return EXIT_INCOMPLETE
    return EXIT_OK
