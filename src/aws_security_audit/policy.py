"""Small helpers for reading IAM and S3 policy documents."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import unquote


def load_document(document: Any) -> dict[str, Any]:
    """Return a policy document as a dict.

    boto3 usually decodes IAM policy documents already, but the raw API returns
    them URL-encoded and S3 bucket policies come back as a JSON string.
    """
    if isinstance(document, dict):
        return document
    text = str(document)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(unquote(text))


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def statements(document: Any) -> list[dict[str, Any]]:
    return [s for s in as_list(load_document(document).get("Statement")) if isinstance(s, dict)]


def grants_full_admin(document: Any) -> bool:
    """True if any statement allows every action on every resource ("*:*")."""
    for st in statements(document):
        if st.get("Effect") != "Allow":
            continue
        actions = {str(a) for a in as_list(st.get("Action"))}
        resources = {str(r) for r in as_list(st.get("Resource"))}
        if actions & {"*", "*:*"} and "*" in resources:
            return True
    return False


def principal_is_wildcard(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any("*" in as_list(v) for v in principal.values())
    return False


def public_allow_statements(document: Any) -> list[dict[str, Any]]:
    """Allow statements whose principal is anyone ("*") and that have no Condition.

    A Condition (for example aws:SourceVpce or aws:PrincipalOrgID) can narrow
    a wildcard principal to something safe, and judging that properly needs
    the full IAM policy evaluation logic. Those statements are left out here
    and the limitation is documented in the README.
    """
    return [
        st
        for st in statements(document)
        if st.get("Effect") == "Allow" and principal_is_wildcard(st.get("Principal")) and not st.get("Condition")
    ]
