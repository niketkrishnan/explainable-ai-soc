"""Explainable hybrid SOC detection primitives.

This module is intentionally defensive: it scores supplied telemetry and never
executes commands, contacts external systems, or performs active scanning.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Iterable

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: str
    user: str
    asset: str
    source_ip: str
    event_type: str
    success: bool
    privilege_change: bool = False
    bytes_out: int = 0
    process_name: str = ""
    destination: str = ""

    @property
    def dt(self) -> datetime:
        value = self.timestamp.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Alert:
    event_index: int
    severity: str
    score: float
    reasons: tuple[str, ...]
    techniques: tuple[str, ...]
    user: str
    asset: str
    event_type: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["reasons"] = list(self.reasons)
        data["techniques"] = list(self.techniques)
        return data


class HybridSOCDetector:
    """Combine transparent rules with an unsupervised anomaly detector."""

    EVENT_TYPES = ("login", "dns", "process", "file", "admin")

    def __init__(self, contamination: float = 0.15, random_state: int = 42) -> None:
        self.contamination = contamination
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=120,
            random_state=random_state,
        )
        self._fitted = False

    def _vectorize(self, event: SecurityEvent) -> list[float]:
        return [
            float(event.success),
            float(event.privilege_change),
            np.log1p(event.bytes_out),
            float(event.event_type in {"admin", "process"}),
            float(event.event_type == "login"),
            float(event.event_type == "dns"),
            float(event.process_name.lower() in {"powershell", "rundll32", "wscript"}),
            float(bool(event.destination)),
        ]

    def fit(self, events: Iterable[SecurityEvent]) -> "HybridSOCDetector":
        rows = [self._vectorize(event) for event in events]
        if len(rows) < 4:
            raise ValueError("At least four events are required to fit the anomaly model")
        matrix = self.scaler.fit_transform(np.asarray(rows, dtype=float))
        self.model.fit(matrix)
        self._fitted = True
        return self

    def _rule_evidence(self, event: SecurityEvent) -> tuple[list[str], list[str], float]:
        reasons: list[str] = []
        techniques: list[str] = []
        score = 0.0
        if event.event_type == "login" and not event.success:
            reasons.append("failed authentication event")
            techniques.append("T1110")
            score += 0.30
        if event.privilege_change:
            reasons.append("privilege change observed")
            techniques.append("T1098")
            score += 0.35
        if event.bytes_out >= 100_000:
            reasons.append("unusually large outbound transfer")
            techniques.append("T1041")
            score += 0.25
        if event.process_name.lower() in {"powershell", "rundll32", "wscript"}:
            reasons.append("high-risk process name in telemetry")
            techniques.append("T1059")
            score += 0.25
        if event.event_type == "admin" and event.user in {"guest", "unknown"}:
            reasons.append("administrative activity by unexpected identity")
            techniques.append("T1078")
            score += 0.35
        return reasons, techniques, min(score, 1.0)

    def score_event(self, event_index: int, event: SecurityEvent) -> Alert:
        if not self._fitted:
            raise RuntimeError("Call fit() before score_event()")
        reasons, techniques, rule_score = self._rule_evidence(event)
        vector = self.scaler.transform([self._vectorize(event)])
        raw = float(-self.model.score_samples(vector)[0])
        anomaly_score = float(np.clip((raw - 0.25) / 0.9, 0.0, 1.0))
        combined = float(np.clip(0.65 * rule_score + 0.35 * anomaly_score, 0.0, 1.0))
        if anomaly_score >= 0.65:
            reasons.append(f"ML anomaly score={anomaly_score:.2f}")
        if combined >= 0.60:
            severity = "high"
        elif combined >= 0.20:
            severity = "medium"
        else:
            severity = "low"
        return Alert(
            event_index=event_index,
            severity=severity,
            score=round(combined, 4),
            reasons=tuple(reasons),
            techniques=tuple(dict.fromkeys(techniques)),
            user=event.user,
            asset=event.asset,
            event_type=event.event_type,
        )

    def detect(self, events: list[SecurityEvent]) -> list[Alert]:
        self.fit(events)
        return [self.score_event(index, event) for index, event in enumerate(events)]


def correlate_incidents(
    events: list[SecurityEvent], alerts: list[Alert], window_minutes: int = 30
) -> list[dict[str, Any]]:
    """Group alerts by user/asset when they occur within a time window."""
    incidents: list[dict[str, Any]] = []
    for alert in sorted(alerts, key=lambda item: events[item.event_index].dt):
        event = events[alert.event_index]
        match = None
        for incident in incidents:
            same_entity = incident["user"] == event.user and incident["asset"] == event.asset
            within_window = (event.dt - incident["last_seen"]).total_seconds() <= window_minutes * 60
            if same_entity and within_window:
                match = incident
                break
        if match is None:
            match = {
                "incident_id": f"INC-{len(incidents)+1:04d}",
                "user": event.user,
                "asset": event.asset,
                "first_seen": event.timestamp,
                "last_seen": event.dt,
                "max_score": alert.score,
                "alerts": [],
            }
            incidents.append(match)
        match["alerts"].append(alert.to_dict())
        match["last_seen"] = max(match["last_seen"], event.dt)
        match["max_score"] = max(match["max_score"], alert.score)
    for incident in incidents:
        incident["last_seen"] = incident["last_seen"].isoformat().replace("+00:00", "Z")
    return incidents
