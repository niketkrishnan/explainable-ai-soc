from datetime import datetime, timezone

from soc_detector import Alert, HybridSOCDetector, SecurityEvent, correlate_incidents, summarize_alert_quality


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


def test_alert_validation_and_incident_summary():
    from soc_detector import summarize_incidents, validate_alert_payload

    alert = {"event_index": 0, "severity": "medium", "score": 0.3, "reasons": [], "techniques": [], "user": "a", "asset": "h", "event_type": "login"}
    validate_alert_payload(alert)
    summary = summarize_incidents([{"max_score": 0.9}, {"max_score": 0.1}])
    assert summary["incident_count"] == 2
    assert summary["severity_distribution"]["high"] == 1


def test_technique_coverage_counts_alert_evidence():
    from soc_detector import technique_coverage
    alerts = [Alert(0, "medium", 0.3, (), ("T1110",), "a", "h", "login"), Alert(1, "high", 0.8, (), ("T1110", "T1098"), "a", "h", "admin")]
    assert technique_coverage(alerts) == {"T1098": 1, "T1110": 2}


def test_data_quality_detects_duplicate_identity():
    from src.data_quality import check_events
    events = [event(20), event(20)]
    assert check_events(events) == ["duplicate event identities: 1"]


def test_alert_quality_summary_reports_explanation_coverage():
    alerts = [Alert(0, "high", 0.8, ("rule matched",), ("T1110",), "alice", "host-1", "login"), Alert(1, "low", 0.1, (), (), "alice", "host-1", "dns")]
    assert summarize_alert_quality(alerts) == {
        "alert_count": 2,
        "with_reasons": 1,
        "with_techniques": 1,
        "explanation_coverage": 0.5,
    }
