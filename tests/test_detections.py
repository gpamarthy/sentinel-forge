from pathlib import Path

from sentinel_forge.detections import build_incident_summary
from sentinel_forge.pipeline import generate_findings


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_generate_findings_returns_expected_detection_ids() -> None:
    findings = generate_findings(SAMPLES)
    detection_ids = {finding.detection_id for finding in findings}
    assert "root-account-usage" in detection_ids
    assert "console-login-without-mfa" in detection_ids
    assert "suspicious-privileged-assume-role" in detection_ids
    assert "cloudtrail-tampering" in detection_ids
    assert "public-sensitive-port-exposure" in detection_ids
    assert "guardduty-corroborated-activity" in detection_ids


def test_build_incident_summary_aggregates_findings() -> None:
    findings = generate_findings(SAMPLES)
    summary = build_incident_summary(findings)
    assert summary.finding_count >= 6
    assert summary.highest_severity == "high"
    assert "arn:aws:iam::123456789012:root" in summary.principals
