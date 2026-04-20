from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class NormalizedEvent(BaseModel):
    """
    Represents a normalized event from various AWS sources.
    """

    provider: str = Field(description="The cloud provider (e.g., 'aws').")
    event_type: str = Field(description="The normalized event type or action name.")
    account_id: str | None = Field(default=None, description="The AWS account ID.")
    region: str | None = Field(default=None, description="The AWS region.")
    event_time: datetime | None = Field(default=None, description="The event timestamp.")
    principal: str | None = Field(default=None, description="The principal (user/role) identity.")
    resource_ids: list[str] = Field(
        default_factory=list, description="List of resource IDs involved."
    )
    raw_source: str | None = Field(default=None, description="The raw source family.")
    raw_payload: dict[str, Any] = Field(
        default_factory=dict, description="The full original event payload."
    )
    attributes: dict[str, Any] = Field(
        default_factory=dict, description="Extracted normalized attributes."
    )


class Finding(BaseModel):
    """
    Represents a specific security finding detected from one or more events.
    """

    detection_id: str = Field(description="Unique ID for the detection logic.")
    title: str = Field(description="Short title of the finding.")
    summary: str = Field(description="Detailed summary of why this was flagged.")
    severity: str = Field(description="Severity level (low, medium, high, critical).")
    confidence: int | None = Field(default=None, description="Confidence score (0-100).")
    sample: str | None = Field(default=None, description="The sample file that triggered this.")
    principal: str | None = Field(default=None, description="The principal associated with it.")
    event_type: str | None = Field(default=None, description="The event type associated with it.")
    event_time: datetime | None = Field(default=None, description="When the event occurred.")
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Supporting evidence for the finding."
    )
    recommended_next_step: str | None = Field(
        default=None, description="Actionable guidance for analysts."
    )


class IncidentSummary(BaseModel):
    """
    Aggregated summary of multiple findings.
    """

    finding_count: int = Field(description="Total number of findings.")
    findings_by_detection: dict[str, int] = Field(
        default_factory=dict, description="Count of findings per detection ID."
    )
    principals: list[str] = Field(
        default_factory=list, description="List of unique principals involved."
    )
    highest_severity: str | None = Field(
        default=None, description="The highest severity level seen."
    )


class TimelineEntry(BaseModel):
    """
    A single entry in a reconstructed incident timeline.
    """

    sample: str = Field(description="The source sample name.")
    event_time: datetime | None = Field(default=None, description="The event timestamp.")
    principal: str | None = Field(default=None, description="The principal identity.")
    event_type: str = Field(description="The type of event.")
    raw_source: str | None = Field(
        default=None, description="The original source (e.g., cloudtrail)."
    )
    summary: str = Field(description="A brief human-readable summary of the event.")


class AnalystReport(BaseModel):
    """
    The final report containing summary, timeline, and all findings.
    """

    summary: IncidentSummary = Field(description="High-level incident summary.")
    timeline: list[TimelineEntry] = Field(
        default_factory=list, description="Reconstructed timeline."
    )
    findings: list[Finding] = Field(default_factory=list, description="All individual findings.")
