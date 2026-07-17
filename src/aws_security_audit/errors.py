"""Turn AWS API errors into "could not check" explanations.

The rule this module exists for: if the scanner could not read something, the
report says so. A permissions error or a region that is not enabled must never
look like a clean result.
"""

from __future__ import annotations

from dataclasses import dataclass

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    UnknownEndpointError,
)

ACCESS_DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "AuthorizationError",
        "AuthorizationErrorException",
        "Forbidden",
        "UnauthorizedAccess",
        "UnauthorizedOperation",
    }
)

# Errors AWS returns when a region is not enabled for the account (opt-in
# regions) or the service has not been subscribed to there.
REGION_UNAVAILABLE_CODES = frozenset(
    {
        "AuthFailure",
        "InvalidClientTokenId",
        "OptInRequired",
        "SubscriptionRequiredException",
        "UnrecognizedClientException",
    }
)

THROTTLING_CODES = frozenset(
    {
        "RequestLimitExceeded",
        "SlowDown",
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
    }
)


class ReadOnlyViolation(RuntimeError):
    """Raised before sending any API call that is not on the read-only allow list."""


@dataclass(frozen=True)
class CheckError:
    category: str  # access-denied, region-unavailable, throttled, no-credentials, error
    code: str
    operation: str | None
    detail: str

    def describe(self) -> str:
        reasons = {
            "access-denied": "access denied",
            "region-unavailable": "region or service not available to this account",
            "throttled": "throttled by AWS after retries",
            "no-credentials": "no credentials",
            "read-only-guard": "blocked by the read-only guard",
            "error": "API error",
        }
        where = f" calling {self.operation}" if self.operation else ""
        return f"Could not check: {reasons[self.category]} ({self.code}){where}"

    def to_evidence(self) -> dict[str, str]:
        evidence = {"error_category": self.category, "error_code": self.code, "error_detail": self.detail}
        if self.operation:
            evidence["operation"] = self.operation
        return evidence


def classify(exc: BaseException) -> CheckError:
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        code = str(error.get("Code", "Unknown"))
        detail = str(error.get("Message", "")) or str(exc)
        operation = getattr(exc, "operation_name", None)
        if code in ACCESS_DENIED_CODES:
            category = "access-denied"
        elif code in REGION_UNAVAILABLE_CODES:
            category = "region-unavailable"
        elif code in THROTTLING_CODES:
            category = "throttled"
        else:
            category = "error"
        return CheckError(category, code, operation, detail)
    if isinstance(exc, (EndpointConnectionError, UnknownEndpointError)):
        return CheckError("region-unavailable", type(exc).__name__, None, str(exc))
    if isinstance(exc, NoCredentialsError):
        return CheckError("no-credentials", type(exc).__name__, None, str(exc))
    if isinstance(exc, ReadOnlyViolation):
        return CheckError("read-only-guard", type(exc).__name__, None, str(exc))
    if isinstance(exc, BotoCoreError):
        return CheckError("error", type(exc).__name__, None, str(exc))
    # Anything else is a bug in a check. Report it rather than hiding it.
    return CheckError("error", type(exc).__name__, None, str(exc))


def error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))
