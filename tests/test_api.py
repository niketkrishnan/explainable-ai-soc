from fastapi.testclient import TestClient

from src.api import app


def test_health_endpoint():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_endpoint_requires_four_events():
    response = TestClient(app).post("/analyze", json={"events": []})
    assert response.status_code == 422


def test_audit_record_excludes_raw_event_data():
    from src.audit import audit_record

    record = audit_record("analyze", event_count=4, alert_count=1)
    assert record == {"action": "analyze", "event_count": 4, "alert_count": 1, "mode": "demo"}
    assert "source_ip" not in record


def test_evaluation_report_contract():
    import json
    from pathlib import Path

    result_path = Path("artifacts/demo_results.json")
    if result_path.exists():
        result = json.loads(result_path.read_text())
        assert {"report_version", "data_note", "feature_names", "technique_coverage"}.issubset(result)
