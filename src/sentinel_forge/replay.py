from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel_forge.reporting import analyst_report_json, manager_summary_text
from sentinel_forge.pipeline import generate_findings, load_normalized_samples, summarize_findings


def replay_samples(samples_root: Path) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for sample, event in load_normalized_samples(samples_root):
        normalized.append(
            {
                "sample": sample,
                "provider": event.provider,
                "event_type": event.event_type,
                "account_id": event.account_id,
                "region": event.region,
                "event_time": event.event_time.isoformat() if event.event_time else None,
                "principal": event.principal,
                "resource_ids": event.resource_ids,
                "raw_source": event.raw_source,
                "attributes": event.attributes,
            }
        )
    return normalized


def replay_samples_json(samples_root: Path) -> str:
    return json.dumps(replay_samples(samples_root), indent=2, sort_keys=True)


def replay_findings(samples_root: Path) -> list[dict[str, Any]]:
    findings = generate_findings(samples_root)
    return [
        {
            "detection_id": finding.detection_id,
            "title": finding.title,
            "summary": finding.summary,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "sample": finding.sample,
            "principal": finding.principal,
            "event_type": finding.event_type,
            "event_time": finding.event_time.isoformat() if finding.event_time else None,
            "evidence": finding.evidence,
            "recommended_next_step": finding.recommended_next_step,
        }
        for finding in findings
    ]


def replay_findings_json(samples_root: Path) -> str:
    return json.dumps(replay_findings(samples_root), indent=2, sort_keys=True)


def replay_summary_json(samples_root: Path) -> str:
    summary = summarize_findings(samples_root)
    return json.dumps(summary.model_dump(), indent=2, sort_keys=True)


def replay_analyst_report_json(samples_root: Path) -> str:
    return analyst_report_json(samples_root)


def replay_manager_summary_text(samples_root: Path) -> str:
    return manager_summary_text(samples_root)
