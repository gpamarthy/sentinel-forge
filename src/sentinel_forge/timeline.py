from __future__ import annotations

from sentinel_forge.models import NormalizedEvent, TimelineEntry


def build_timeline(events: list[tuple[str, NormalizedEvent]]) -> list[TimelineEntry]:
    entries = [
        TimelineEntry(
            sample=sample,
            event_time=event.event_time,
            principal=event.principal,
            event_type=event.event_type,
            raw_source=event.raw_source,
            summary=_summarize_event(event),
        )
        for sample, event in events
    ]
    entries.sort(key=lambda item: (item.event_time is None, item.event_time))
    return entries


def _summarize_event(event: NormalizedEvent) -> str:
    event_name = event.attributes.get("event_name")
    if event.raw_source == "cloudtrail" and event_name:
        return f"{event_name} from {event.attributes.get('source_ip', 'unknown source')}"
    if event.raw_source == "guardduty":
        return f"{event.attributes.get('finding_type', 'GuardDuty finding')} from {event.attributes.get('remote_ip', 'unknown source')}"
    if event.raw_source == "securityhub":
        return event.attributes.get("title", "Security Hub finding")
    return event.event_type
