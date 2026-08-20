from fastapi.testclient import TestClient

from src.api import app


def test_health_endpoint():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_endpoint_requires_four_events():
    response = TestClient(app).post("/analyze", json={"events": []})
    assert response.status_code == 422
