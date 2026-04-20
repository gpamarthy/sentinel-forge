from pathlib import Path

from sentinel_forge.pipeline import load_normalized_samples
from sentinel_forge.reporting import build_analyst_report, manager_summary_text
from sentinel_forge.timeline import build_timeline


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_timeline_contains_all_events_in_order() -> None:
    events = load_normalized_samples(SAMPLES)
    timeline = build_timeline(events)
    assert len(timeline) == 6
    assert timeline[0].sample == "cloudtrail/root_console_login.json"
    assert timeline[-1].sample == "cloudtrail/security_group_open_ssh.json"


def test_analyst_report_contains_findings_and_timeline() -> None:
    report = build_analyst_report(SAMPLES)
    assert report.summary.finding_count == len(report.findings)
    assert len(report.timeline) == 6
    assert len(report.findings) >= 5


def test_manager_summary_text_contains_key_fields() -> None:
    text = manager_summary_text(SAMPLES)
    assert "Sentinel Forge Manager Summary" in text
    assert "Findings:" in text
