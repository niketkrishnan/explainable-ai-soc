"""Read-only API for local SOC analysis demos."""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .soc_detector import HybridSOCDetector, SecurityEvent, correlate_incidents

app = FastAPI(title="Explainable AI SOC API", version="0.2.0")


class AnalyzeRequest(BaseModel):
    events: list[SecurityEvent] = Field(min_length=4)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "read-only-demo"}


@app.post("/analyze")
def analyze(request: AnalyzeRequest) -> dict[str, object]:
    alerts = HybridSOCDetector().detect(request.events)
    incidents = correlate_incidents(request.events, alerts)
    return {"alerts": [alert.to_dict() for alert in alerts], "incidents": incidents}
