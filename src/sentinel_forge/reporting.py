from __future__ import annotations

import json
from pathlib import Path

from sentinel_forge.models import AnalystReport
from sentinel_forge.pipeline import generate_findings, load_normalized_samples, summarize_findings
from sentinel_forge.timeline import build_timeline


def build_analyst_report(samples_root: Path) -> AnalystReport:
    events = load_normalized_samples(samples_root)
    findings = generate_findings(samples_root)
    summary = summarize_findings(samples_root)
    timeline = build_timeline(events)
    return AnalystReport(summary=summary, timeline=timeline, findings=findings)


def analyst_report_json(samples_root: Path) -> str:
    report = build_analyst_report(samples_root)
    return json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True)


def manager_summary_text(samples_root: Path) -> str:
    report = build_analyst_report(samples_root)
    lines = [
        "Sentinel Forge Manager Summary",
        f"Findings: {report.summary.finding_count}",
        f"Highest severity: {report.summary.highest_severity}",
        f"Detections fired: {', '.join(sorted(report.summary.findings_by_detection))}",
        f"Principals involved: {', '.join(report.summary.principals)}",
    ]
    return "\n".join(lines)
