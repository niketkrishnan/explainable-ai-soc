"""Data-quality checks for defensive telemetry fixtures."""

from __future__ import annotations

from collections import Counter

from .soc_detector import SecurityEvent


def check_events(events: list[SecurityEvent]) -> list[str]:
    issues: list[str] = []
    identities = Counter((event.timestamp, event.user, event.asset) for event in events)
    duplicates = [key for key, count in identities.items() if count > 1]
    if duplicates:
        issues.append(f"duplicate event identities: {len(duplicates)}")
    if any(not event.user or not event.asset for event in events):
        issues.append("event has empty user or asset")
    return issues
