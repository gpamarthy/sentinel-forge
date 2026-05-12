from pathlib import Path

from sentinel_forge.ingest import load_json
from sentinel_forge.normalize import normalize_event
from sentinel_forge.replay import replay_samples


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_normalize_cloudtrail_root_login() -> None:
    event = normalize_event(load_json(SAMPLES / "cloudtrail/root_console_login.json"))
    assert event.raw_source == "cloudtrail"
    assert event.principal == "arn:aws:iam::123456789012:root"
    assert event.attributes["mfa_used"] == "No"


def test_normalize_guardduty_finding() -> None:
    event = normalize_event(load_json(SAMPLES / "guardduty/credential_access_finding.json"))
    assert event.raw_source == "guardduty"
    assert event.attributes["finding_type"] == "CredentialAccess:IAMUser/AnomalousBehavior"
    assert event.resource_ids == ["ASIAEXAMPLE"]


def test_normalize_securityhub_finding() -> None:
    event = normalize_event(load_json(SAMPLES / "securityhub/iam_root_mfa_finding.json"))
    assert event.raw_source == "securityhub"
    assert event.attributes["severity_label"] == "HIGH"
    assert event.resource_ids == ["arn:aws:iam::123456789012:root"]


def test_replay_samples_returns_all_normalized_events() -> None:
    replayed = replay_samples(SAMPLES)
    assert len(replayed) == 6
    assert replayed[0]["provider"] == "aws"
