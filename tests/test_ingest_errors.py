import pytest
from sentinel_forge.ingest import detect_source_family

def test_detect_source_family_unsupported() -> None:
    payload = {"foo": "bar"}
    with pytest.raises(ValueError, match="Unsupported AWS event shape"):
        detect_source_family(payload)

def test_detect_source_family_partial_guardduty() -> None:
    payload = {"source": "aws.guardduty"}
    with pytest.raises(ValueError, match="Partial GuardDuty match but missing fields: 'detail-type' must be 'GuardDuty Finding'"):
        detect_source_family(payload)

def test_detect_source_family_partial_securityhub() -> None:
    payload = {"SchemaVersion": "2018-10-08"}
    with pytest.raises(ValueError, match="Partial SecurityHub match but missing fields: missing 'ProductArn'"):
        detect_source_family(payload)

def test_detect_source_family_partial_cloudtrail() -> None:
    payload = {"eventSource": "iam.amazonaws.com"}
    with pytest.raises(ValueError, match="Partial CloudTrail match but missing fields: eventName, userIdentity"):
        detect_source_family(payload)
