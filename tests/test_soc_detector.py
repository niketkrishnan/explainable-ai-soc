from datetime import datetime, timezone

from soc_detector import Alert, HybridSOCDetector, SecurityEvent, correlate_incidents


def event(index: int, **overrides) -> SecurityEvent:
    base = {
        "timestamp": f"2026-01-01T10:{index:02d}:00Z",
        "user": "alice",
        "asset": "host-1",
        "source_ip": "10.0.0.1",
        "event_type": "login",
        "success": True,
    }
    base.update(overrides)
    return SecurityEvent(**base)


def test_rule_evidence_is_explainable():
    detector = HybridSOCDetector()
    reasons, techniques, score = detector._rule_evidence(
        event(1, event_type="admin", user="guest", privilege_change=True)
    )
    assert score > 0.5
    assert "privilege change observed" in reasons
    assert "T1098" in techniques


def test_detector_returns_alerts_with_evidence():
    events = [
        event(1),
        event(2, event_type="dns", destination="internal.example"),
        event(3, event_type="login", success=False),
        event(4, event_type="admin", user="guest", privilege_change=True),
        event(5, event_type="file", bytes_out=200_000),
    ]
    alerts = HybridSOCDetector(contamination=0.2).detect(events)
    assert len(alerts) == len(events)
    assert all(isinstance(alert, Alert) for alert in alerts)
    assert any("privilege change observed" in alert.reasons for alert in alerts)


def test_incident_correlation_groups_same_user_and_asset():
    events = [event(1), event(2, event_type="admin", privilege_change=True)]
    alerts = [
        Alert(0, "low", 0.2, ("baseline",), (), "alice", "host-1", "login"),
        Alert(1, "high", 0.9, ("privilege change observed",), ("T1098",), "alice", "host-1", "admin"),
    ]
    incidents = correlate_incidents(events, alerts)
    assert len(incidents) == 1
    assert len(incidents[0]["alerts"]) == 2
    assert incidents[0]["max_score"] == 0.9


def test_security_event_rejects_invalid_values():
    import pytest

    with pytest.raises(ValueError):
        event(6, event_type="unknown")
    with pytest.raises(ValueError):
        event(7, bytes_out=-1)
