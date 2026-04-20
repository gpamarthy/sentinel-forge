import json
from pathlib import Path
import pytest
from sentinel_forge.database import DatabaseManager, EventRecord, FindingRecord
from sentinel_forge.pipeline import generate_findings, load_normalized_samples
from sentinel_forge.detections import run_detections

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"

def test_database_persistence(tmp_path):
    # Use a temporary database for testing
    db_path = tmp_path / "test_sentinel_forge.db"
    db_url = f"sqlite:///{db_path}"
    
    # Mock DatabaseManager to use our test DB
    import sentinel_forge.pipeline
    import sentinel_forge.database
    
    # We need to ensure DatabaseManager uses the test URL
    # One way is to monkeypatch the DatabaseManager class or its default URL
    
    db = DatabaseManager(db_url=db_url)
    
    # 1. Test Event Persistence
    events = load_normalized_samples(SAMPLES)
    # We need to check if they were saved. 
    # Since load_normalized_samples creates its own DatabaseManager(), 
    # we should have monkeypatched it.
    
    # Let's try a different approach: call the methods directly with the test db
    for _, event in events:
        db.save_event(event)
    
    session = db.Session()
    event_count = session.query(EventRecord).count()
    assert event_count > 0
    
    # 2. Test Finding Persistence
    findings = run_detections(events)
    for finding in findings:
        db.save_finding(finding)
        
    finding_count = session.query(FindingRecord).count()
    assert finding_count > 0
    
    # Verify a specific finding
    root_finding = session.query(FindingRecord).filter_by(detection_id="root-account-usage").first()
    assert root_finding is not None
    assert root_finding.severity == "high"

def test_yaml_rules_loading():
    from sentinel_forge.detections import load_rules
    rules = load_rules()
    assert len(rules) >= 5
    
    # Check if a specific rule is loaded
    rule_ids = [r.id for r in rules]
    assert "root-account-usage" in rule_ids
    assert "cloudtrail-tampering" in rule_ids

def test_structured_logging_json(capsys):
    from sentinel_forge.logger import setup_logging, get_logger
    setup_logging(json_format=True)
    logger = get_logger("test_logger")
    logger.info("test_event", key="value")
    
    captured = capsys.readouterr()
    # structlog with JSONRenderer and PrintLoggerFactory will print to stdout
    assert '"event": "test_event"' in captured.out
    assert '"key": "value"' in captured.out
    assert '"level": "info"' in captured.out
