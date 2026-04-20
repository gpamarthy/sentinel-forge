from sentinel_forge.models import Finding, NormalizedEvent


def test_normalized_event_defaults() -> None:
    event = NormalizedEvent(provider="aws", event_type="example")
    assert event.provider == "aws"
    assert event.resource_ids == []
    assert event.attributes == {}


def test_finding_defaults() -> None:
    finding = Finding(
        detection_id="root-account-usage",
        title="Root account usage detected",
        summary="A root account event was observed.",
        severity="high",
    )
    assert finding.detection_id == "root-account-usage"
    assert finding.evidence == {}
