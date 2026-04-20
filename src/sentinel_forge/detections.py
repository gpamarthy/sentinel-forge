import os
from collections import Counter
from typing import Any

import yaml
from pydantic import BaseModel, Field

from sentinel_forge.models import Finding, IncidentSummary, NormalizedEvent
from sentinel_forge.logger import get_logger

logger = get_logger(__name__)


class RuleCondition(BaseModel):
    field: str
    op: str
    value: Any


class DetectionRule(BaseModel):
    id: str
    title: str
    summary: str
    severity: str
    confidence: int
    source: str | None = None
    conditions: list[RuleCondition] = Field(default_factory=list)
    recommended_next_step: str | None = None


def get_field_value(event: NormalizedEvent, field_path: str) -> Any:
    """
    Get a value from a NormalizedEvent using a dot-notation field path.
    Example: 'attributes.event_name'
    """
    parts = field_path.split(".")
    current: Any = event
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
        if current is None:
            break
    return current


def evaluate_condition(event: NormalizedEvent, condition: RuleCondition) -> bool:
    """
    Evaluate a single condition against a normalized event.
    """
    val = get_field_value(event, condition.field)
    if val is None:
        return False

    op = condition.op
    expected = condition.value

    if op == "eq":
        return val == expected
    if op == "not_eq":
        return val != expected
    if op == "contains":
        return expected in val if isinstance(val, (list, str)) else False
    if op == "contains_any":
        if isinstance(val, (list, str)) and isinstance(expected, list):
            return any(item in val for item in expected)
        return False
    if op == "in":
        return val in expected if isinstance(expected, list) else False

    logger.warning("unknown_operator", op=op, field=condition.field)
    return False


def evaluate_rule(rule: DetectionRule, event: NormalizedEvent, sample: str) -> list[Finding]:
    """
    Evaluate a detection rule against a normalized event.
    """
    if rule.source and event.raw_source != rule.source:
        return []

    if not all(evaluate_condition(event, c) for c in rule.conditions):
        return []

    return [
        Finding(
            detection_id=rule.id,
            title=rule.title,
            summary=rule.summary,
            severity=rule.severity,
            confidence=rule.confidence,
            sample=sample,
            principal=event.principal,
            event_type=event.event_type,
            event_time=event.event_time,
            evidence={c.field: get_field_value(event, c.field) for c in rule.conditions},
            recommended_next_step=rule.recommended_next_step,
        )
    ]


def load_rules(rules_dir: str = "rules") -> list[DetectionRule]:
    """
    Load all YAML rules from the specified directory.
    """
    rules = []
    if not os.path.exists(rules_dir):
        logger.warning("rules_directory_missing", path=rules_dir)
        return rules

    for filename in os.listdir(rules_dir):
        if filename.endswith(".yaml") or filename.endswith(".yml"):
            path = os.path.join(rules_dir, filename)
            try:
                with open(path, "r") as f:
                    data = yaml.safe_load(f)
                    rules.append(DetectionRule(**data))
            except Exception as e:
                logger.error("failed_to_load_rule", path=path, error=str(e))

    logger.info("rules_loaded", count=len(rules))
    return rules


SEVERITY_ORDER: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def detect_guardduty_corroborated_activity(
    events: list[tuple[str, NormalizedEvent]],
) -> list[Finding]:
    """
    Correlate GuardDuty findings with CloudTrail activity for stronger detection.

    Args:
        events: A list of (sample_name, normalized_event) tuples.

    Returns:
        A list of Findings for corroborated activities.
    """
    findings: list[Finding] = []
    guardduty_events = [
        (sample, event) for sample, event in events if event.raw_source == "guardduty"
    ]
    cloudtrail_events = [event for _, event in events if event.raw_source == "cloudtrail"]

    for sample, gd_event in guardduty_events:
        gd_ip = gd_event.attributes.get("remote_ip")
        gd_api = gd_event.attributes.get("api")
        principal = gd_event.principal
        gd_principal_name = gd_event.attributes.get("principal_name")
        gd_principal_id = gd_event.attributes.get("principal_id")
        match = next(
            (
                event
                for event in cloudtrail_events
                if (
                    event.principal == principal
                    or event.attributes.get("principal_name") == gd_principal_name
                    or event.attributes.get("principal_id") == gd_principal_id
                )
                and event.attributes.get("source_ip") == gd_ip
                and event.attributes.get("event_name") == gd_api
            ),
            None,
        )
        if not match:
            continue

        findings.append(
            Finding(
                detection_id="guardduty-corroborated-activity",
                title="GuardDuty finding corroborated by CloudTrail activity",
                summary="A GuardDuty finding aligns with CloudTrail activity for the same principal and network source.",
                severity="high",
                confidence=95,
                sample=sample,
                principal=principal,
                event_type=gd_event.event_type,
                event_time=gd_event.event_time,
                evidence={
                    "guardduty_finding_type": gd_event.attributes.get("finding_type"),
                    "remote_ip": gd_ip,
                    "api": gd_api,
                    "correlated_cloudtrail_event": match.event_type,
                },
                recommended_next_step="Review the correlated API sequence, determine whether the credentials are compromised, and contain the affected principal if needed.",
            )
        )
    return findings


def run_detections(events: list[tuple[str, NormalizedEvent]]) -> list[Finding]:
    """
    Run all configured detections against a set of normalized events.

    Args:
        events: A list of (sample_name, normalized_event) tuples.

    Returns:
        A consolidated list of all findings detected.
    """
    rules_path = os.path.join(os.getcwd(), "rules")
    rules = load_rules(rules_path)
    findings: list[Finding] = []

    for sample, event in events:
        for rule in rules:
            findings.extend(evaluate_rule(rule, event, sample))

    findings.extend(detect_guardduty_corroborated_activity(events))
    return findings


def build_incident_summary(findings: list[Finding]) -> IncidentSummary:
    """
    Build a high-level summary of all findings for an incident report.

    Args:
        findings: A list of all Findings detected.

    Returns:
        An IncidentSummary object containing aggregated statistics and metadata.
    """
    if not findings:
        return IncidentSummary(finding_count=0)

    counts = Counter(finding.detection_id for finding in findings)
    principal_map: dict[str, str] = {}
    for finding in findings:
        if not finding.principal:
            continue
        principal = finding.principal
        if principal.startswith("arn:aws:iam::") and "/" in principal:
            principal_map[principal.rsplit("/", 1)[-1]] = principal
        else:
            principal_map.setdefault(principal, principal)
    principals = sorted(principal_map.values())
    highest = max(findings, key=lambda item: SEVERITY_ORDER.get(item.severity, 0)).severity

    return IncidentSummary(
        finding_count=len(findings),
        findings_by_detection=dict(counts),
        principals=principals,
        highest_severity=highest,
    )
