from pathlib import Path

from sentinel_forge.replay import replay_analyst_report_json, replay_findings, replay_summary_json


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_replay_findings_includes_evidence() -> None:
    findings = replay_findings(SAMPLES)
    assert len(findings) >= 6
    assert any(finding["evidence"] for finding in findings)


def test_replay_summary_json_contains_counts() -> None:
    output = replay_summary_json(SAMPLES)
    assert '"finding_count"' in output
    assert '"highest_severity": "high"' in output


def test_analyst_report_json_contains_timeline() -> None:
    output = replay_analyst_report_json(SAMPLES)
    assert '"timeline"' in output
