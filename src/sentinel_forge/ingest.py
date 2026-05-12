from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SAMPLE_GROUPS = ("cloudtrail", "guardduty", "securityhub")


def load_json(path: Path) -> dict[str, Any]:
    """
    Load JSON content from a file.

    Args:
        path: Path to the JSON file.

    Returns:
        The parsed JSON content as a dictionary.
    """
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def iter_sample_paths(samples_root: Path) -> list[Path]:
    """
    Iterate over sample file paths in the samples root directory.

    Args:
        samples_root: Root directory containing sample groups.

    Returns:
        A list of paths to JSON sample files.
    """
    paths: list[Path] = []
    for group in SAMPLE_GROUPS:
        group_root = samples_root / group
        if not group_root.exists():
            continue
        paths.extend(sorted(group_root.glob("*.json")))
    return paths


def detect_source_family(payload: dict[str, Any]) -> str:
    """
    Detect the AWS source family of a given event payload.

    Args:
        payload: The event payload dictionary.

    Returns:
        The detected source family string ('guardduty', 'securityhub', or 'cloudtrail').

    Raises:
        ValueError: If the payload shape is unrecognized, with a descriptive error message.
    """
    # Check for GuardDuty
    if (
        payload.get("source") == "aws.guardduty"
        or payload.get("detail-type") == "GuardDuty Finding"
    ):
        if (
            payload.get("source") == "aws.guardduty"
            and payload.get("detail-type") == "GuardDuty Finding"
        ):
            return "guardduty"
        missing = []
        if payload.get("source") != "aws.guardduty":
            missing.append("'source' must be 'aws.guardduty'")
        if payload.get("detail-type") != "GuardDuty Finding":
            missing.append("'detail-type' must be 'GuardDuty Finding'")
        raise ValueError(f"Partial GuardDuty match but missing fields: {', '.join(missing)}")

    # Check for SecurityHub
    if payload.get("SchemaVersion") == "2018-10-08" or "ProductArn" in payload:
        if payload.get("SchemaVersion") == "2018-10-08" and "ProductArn" in payload:
            return "securityhub"
        missing = []
        if payload.get("SchemaVersion") != "2018-10-08":
            missing.append("'SchemaVersion' must be '2018-10-08'")
        if "ProductArn" not in payload:
            missing.append("missing 'ProductArn'")
        raise ValueError(f"Partial SecurityHub match but missing fields: {', '.join(missing)}")

    # Check for CloudTrail
    cloudtrail_fields = {"eventSource", "eventName", "userIdentity"}
    present_fields = cloudtrail_fields.intersection(payload.keys())
    if present_fields:
        if cloudtrail_fields.issubset(payload.keys()):
            return "cloudtrail"
        missing = sorted(cloudtrail_fields - present_fields)
        raise ValueError(f"Partial CloudTrail match but missing fields: {', '.join(missing)}")

    raise ValueError(
        "Unsupported AWS event shape. Could not identify as GuardDuty, SecurityHub, or CloudTrail."
    )
