from __future__ import annotations

from pathlib import Path

from sentinel_forge.detections import build_incident_summary, run_detections
from sentinel_forge.ingest import iter_sample_paths, load_json
from sentinel_forge.models import Finding, IncidentSummary, NormalizedEvent
from sentinel_forge.normalize import normalize_event
from sentinel_forge.database import DatabaseManager
from sentinel_forge.logger import get_logger

logger = get_logger(__name__)


def load_normalized_samples(samples_root: Path) -> list[tuple[str, NormalizedEvent]]:
    db = DatabaseManager()
    normalized: list[tuple[str, NormalizedEvent]] = []
    for path in iter_sample_paths(samples_root):
        payload = load_json(path)
        event = normalize_event(payload)
        normalized.append((str(path.relative_to(samples_root)), event))
        # Persist event to DB
        db.save_event(event)
    logger.info("samples_normalized_and_persisted", count=len(normalized))
    return normalized


def generate_findings(samples_root: Path) -> list[Finding]:
    db = DatabaseManager()
    events = load_normalized_samples(samples_root)
    findings = run_detections(events)
    # Persist findings to DB
    for finding in findings:
        db.save_finding(finding)
    logger.info("findings_generated_and_persisted", count=len(findings))
    return findings


def summarize_findings(samples_root: Path) -> IncidentSummary:
    findings = generate_findings(samples_root)
    return build_incident_summary(findings)
