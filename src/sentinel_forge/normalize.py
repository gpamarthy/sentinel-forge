from __future__ import annotations

from datetime import datetime
from typing import Any

from sentinel_forge.ingest import detect_source_family
from sentinel_forge.models import NormalizedEvent


def _parse_time(value: str | None) -> datetime | None:
    """
    Parse an ISO timestamp into a datetime object.

    Args:
        value: The timestamp string, or None.

    Returns:
        The parsed datetime object, or None.
    """
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _normalize_cloudtrail(payload: dict[str, Any]) -> NormalizedEvent:
    """
    Normalize a CloudTrail event payload.

    Args:
        payload: The raw CloudTrail event payload.

    Returns:
        The normalized event representation.
    """
    identity = payload.get("userIdentity", {})
    request_parameters = payload.get("requestParameters", {})
    resource_ids: list[str] = []

    role_arn = request_parameters.get("roleArn")
    if role_arn:
        resource_ids.append(role_arn)
    group_id = request_parameters.get("groupId")
    if group_id:
        resource_ids.append(group_id)

    ip_permissions = request_parameters.get("ipPermissions", {}).get("items", [])
    public_cidrs: list[str] = []
    sensitive_ports: list[int] = []
    for permission in ip_permissions:
        from_port = permission.get("fromPort")
        ip_ranges = permission.get("ipRanges", {}).get("items", [])
        for ip_range in ip_ranges:
            cidr_ip = ip_range.get("cidrIp")
            if cidr_ip == "0.0.0.0/0":
                public_cidrs.append(cidr_ip)
                if isinstance(from_port, int):
                    sensitive_ports.append(from_port)

    return NormalizedEvent(
        provider="aws",
        event_type=f"cloudtrail:{payload.get('eventSource')}:{payload.get('eventName')}",
        account_id=identity.get("accountId"),
        region=payload.get("awsRegion"),
        event_time=_parse_time(payload.get("eventTime")),
        principal=identity.get("arn") or identity.get("principalId") or identity.get("userName"),
        resource_ids=resource_ids,
        raw_source="cloudtrail",
        raw_payload=payload,
        attributes={
            "event_name": payload.get("eventName"),
            "event_source": payload.get("eventSource"),
            "source_ip": payload.get("sourceIPAddress"),
            "mfa_used": payload.get("additionalEventData", {}).get("MFAUsed"),
            "role_arn": role_arn,
            "console_login_result": payload.get("responseElements", {}).get("ConsoleLogin"),
            "group_id": group_id,
            "public_cidrs": public_cidrs,
            "sensitive_ports": sensitive_ports,
            "principal_name": identity.get("userName"),
            "principal_id": identity.get("principalId"),
        },
    )


def _normalize_guardduty(payload: dict[str, Any]) -> NormalizedEvent:
    """
    Normalize a GuardDuty finding payload.

    Args:
        payload: The raw GuardDuty event payload.

    Returns:
        The normalized event representation.
    """
    detail = payload.get("detail", {})
    resource = detail.get("resource", {})
    access_key_details = resource.get("accessKeyDetails", {})
    api_action = detail.get("service", {}).get("action", {}).get("awsApiCallAction", {})
    resource_ids: list[str] = []

    access_key_id = access_key_details.get("accessKeyId")
    if access_key_id:
        resource_ids.append(access_key_id)

    return NormalizedEvent(
        provider="aws",
        event_type=f"guardduty:{detail.get('type')}",
        account_id=detail.get("accountId") or payload.get("account"),
        region=detail.get("region") or payload.get("region"),
        event_time=_parse_time(payload.get("time")),
        principal=access_key_details.get("userName") or access_key_details.get("principalId"),
        resource_ids=resource_ids,
        raw_source="guardduty",
        raw_payload=payload,
        attributes={
            "finding_id": detail.get("id"),
            "finding_type": detail.get("type"),
            "severity": detail.get("severity"),
            "api": api_action.get("api"),
            "service_name": api_action.get("serviceName"),
            "remote_ip": api_action.get("remoteIpDetails", {}).get("ipAddressV4"),
            "title": detail.get("title"),
            "principal_name": access_key_details.get("userName"),
            "principal_id": access_key_details.get("principalId"),
        },
    )


def _normalize_securityhub(payload: dict[str, Any]) -> NormalizedEvent:
    """
    Normalize a SecurityHub finding payload.

    Args:
        payload: The raw SecurityHub event payload.

    Returns:
        The normalized event representation.
    """
    resources = payload.get("Resources", [])
    resource_ids: list[str] = [resource.get("Id") for resource in resources if resource.get("Id")]

    return NormalizedEvent(
        provider="aws",
        event_type="securityhub:finding",
        account_id=payload.get("AwsAccountId"),
        region=resources[0].get("Region") if resources else None,
        event_time=_parse_time(payload.get("UpdatedAt") or payload.get("CreatedAt")),
        principal=resource_ids[0] if resource_ids else None,
        resource_ids=resource_ids,
        raw_source="securityhub",
        raw_payload=payload,
        attributes={
            "finding_id": payload.get("Id"),
            "generator_id": payload.get("GeneratorId"),
            "title": payload.get("Title"),
            "description": payload.get("Description"),
            "severity_label": payload.get("Severity", {}).get("Label"),
            "workflow_status": payload.get("Workflow", {}).get("Status"),
        },
    )


def normalize_event(payload: dict[str, Any]) -> NormalizedEvent:
    """
    Identify and normalize an AWS event payload regardless of its family.

    Args:
        payload: The raw event payload.

    Returns:
        The normalized event representation.

    Raises:
        ValueError: If the source family is unrecognized or cannot be normalized.
    """
    family = detect_source_family(payload)
    if family == "cloudtrail":
        return _normalize_cloudtrail(payload)
    if family == "guardduty":
        return _normalize_guardduty(payload)
    if family == "securityhub":
        return _normalize_securityhub(payload)
    raise ValueError(f"Unsupported source family: {family}")
