from __future__ import annotations

import csv
import json
from pathlib import Path

from src.soc_detector import HybridSOCDetector, correlate_incidents, technique_coverage
from src.event_loader import load_csv_events
from src.audit import audit_record


ROOT = Path(__file__).parent
DATA = ROOT / "data" / "events.csv"
OUTPUT = ROOT / "artifacts" / "demo_results.json"


def load_events():
    return load_csv_events(DATA)


def main() -> None:
    events = load_events()
    detector = HybridSOCDetector(contamination=0.2)
    alerts = detector.detect(events)
    incidents = correlate_incidents(events, alerts)
    result = {
        "report_version": "0.2.0",
        "events": len(events),
        "alerts": len(alerts),
        "high_or_medium_alerts": sum(alert.severity != "low" for alert in alerts),
        "incidents": incidents,
        "alerts_detail": [alert.to_dict() for alert in alerts],
        "feature_names": list(detector.feature_names()),
        "technique_coverage": technique_coverage(alerts),
        "audit": audit_record("evaluate", event_count=len(events), alert_count=len(alerts)),
        "data_note": "Local defensive fixture; not a production benchmark.",
    }
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
