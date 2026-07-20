"""Decide which regions to scan."""

from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from .context import ScanContext
from .errors import classify


def resolve_regions(scan: ScanContext, requested: list[str] | None) -> tuple[list[str], list[str]]:
    """Return (regions, warnings).

    With no regions requested, ask EC2 for the regions enabled on the account.
    DescribeRegions without AllRegions only returns enabled regions, so opt-in
    regions the account has not turned on are left out. If that call fails the
    scan falls back to the home region and says so, rather than quietly
    scanning less than the user expects.
    """
    if requested:
        return sorted(dict.fromkeys(requested)), []
    try:
        response = scan.client("ec2").describe_regions()
    except (ClientError, BotoCoreError) as exc:
        reason = classify(exc).describe()
        return [scan.home_region], [
            f"Could not list enabled regions ({reason}); only {scan.home_region} was scanned. "
            "Pass --region to choose regions explicitly."
        ]
    regions = sorted(r["RegionName"] for r in response.get("Regions", []))
    return regions or [scan.home_region], []
