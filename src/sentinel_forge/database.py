import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Column, DateTime, Integer, JSON, String, create_engine, Text
from sqlalchemy.orm import declarative_base, sessionmaker

from sentinel_forge.models import Finding, NormalizedEvent

Base = declarative_base()


class EventRecord(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    provider = Column(String(50))
    event_type = Column(String(100))
    account_id = Column(String(50))
    region = Column(String(50))
    event_time = Column(DateTime)
    principal = Column(String(255))
    raw_source = Column(String(50))
    attributes = Column(JSON)
    raw_payload = Column(JSON)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class FindingRecord(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    detection_id = Column(String(100))
    title = Column(String(255))
    summary = Column(Text)
    severity = Column(String(20))
    confidence = Column(Integer)
    sample = Column(String(255))
    principal = Column(String(255))
    event_type = Column(String(100))
    event_time = Column(DateTime)
    evidence = Column(JSON)
    recommended_next_step = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class DatabaseManager:
    def __init__(self, db_url: str = "sqlite:///sentinel_forge.db"):
        self.engine = create_engine(db_url)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def save_event(self, event: NormalizedEvent):
        session = self.Session()
        record = EventRecord(
            provider=event.provider,
            event_type=event.event_type,
            account_id=event.account_id,
            region=event.region,
            event_time=event.event_time,
            principal=event.principal,
            raw_source=event.raw_source,
            attributes=event.attributes,
            raw_payload=event.raw_payload,
        )
        session.add(record)
        session.commit()
        session.close()

    def save_finding(self, finding: Finding):
        session = self.Session()
        record = FindingRecord(
            detection_id=finding.detection_id,
            title=finding.title,
            summary=finding.summary,
            severity=finding.severity,
            confidence=finding.confidence,
            sample=finding.sample,
            principal=finding.principal,
            event_type=finding.event_type,
            event_time=finding.event_time,
            evidence=finding.evidence,
            recommended_next_step=finding.recommended_next_step,
        )
        session.add(record)
        session.commit()
        session.close()

    def get_all_events(self) -> list[NormalizedEvent]:
        session = self.Session()
        records = session.query(EventRecord).all()
        events = [
            NormalizedEvent(
                provider=r.provider,
                event_type=r.event_type,
                account_id=r.account_id,
                region=r.region,
                event_time=r.event_time,
                principal=r.principal,
                raw_source=r.raw_source,
                attributes=r.attributes,
                raw_payload=r.raw_payload,
            )
            for r in records
        ]
        session.close()
        return events

    def get_findings_by_detection(self, detection_id: str):
        session = self.Session()
        records = session.query(FindingRecord).filter_by(detection_id=detection_id).all()
        session.close()
        return records
