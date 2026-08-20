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


def test_csv_loader_reads_fixture():
    from src.event_loader import load_csv_events

    loaded = load_csv_events("data/events.csv")
    assert len(loaded) == 10
    assert loaded[0].user == "alice"


def test_csv_loader_rejects_missing_columns(tmp_path):
    from src.event_loader import load_csv_events

    bad = tmp_path / "bad.csv"
    bad.write_text("timestamp,user\n2026-01-01T00:00:00Z,x\n")
    import pytest
    with pytest.raises(ValueError, match="Missing required columns"):
        load_csv_events(bad)


def test_failed_login_burst_is_explainable():
    from soc_detector import failed_login_burst

    events = [event(10, success=False), event(11, success=False), event(12, success=False)]
    matches = failed_login_burst(events)
    assert 2 in matches
    assert "3 failed logins" in matches[2].reason


def test_outbound_threshold_can_be_lowered():
    detector = HybridSOCDetector(outbound_threshold=500)
    reasons, _, score = detector._rule_evidence(event(13, event_type="file", bytes_out=600))
    assert "unusually large outbound transfer" in reasons
    assert score > 0


def test_risk_band_boundaries():
    from soc_detector import risk_band
    import pytest

    assert risk_band(0.0) == "low"
    assert risk_band(0.2) == "medium"
    assert risk_band(0.6) == "high"
    with pytest.raises(ValueError):
        risk_band(1.1)
