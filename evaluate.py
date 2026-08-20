from __future__ import annotations

import csv
import json
from pathlib import Path

from soc_detector import SecurityEvent, HybridSOCDetector, correlate_incidents


ROOT = Path(__file__).parent
DATA = ROOT / "data" / "events.csv"
OUTPUT = ROOT / "artifacts" / "demo_results.json"


def load_events() -> list[SecurityEvent]:
    with DATA.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    return [
        SecurityEvent(
            timestamp=row["timestamp"],
            user=row["user"],
            asset=row["asset"],
            source_ip=row["source_ip"],
            event_type=row["event_type"],
            success=row["success"].lower() == "true",
            privilege_change=row["privilege_change"].lower() == "true",
            bytes_out=int(row["bytes_out"]),
            process_name=row["process_name"],
            destination=row["destination"],
        )
        for row in rows
    ]


def main() -> None:
    events = load_events()
    detector = HybridSOCDetector(contamination=0.2)
    alerts = detector.detect(events)
    incidents = correlate_incidents(events, alerts)
    result = {
        "events": len(events),
        "alerts": len(alerts),
        "high_or_medium_alerts": sum(alert.severity != "low" for alert in alerts),
        "incidents": incidents,
        "alerts_detail": [alert.to_dict() for alert in alerts],
        "data_note": "Local defensive fixture; not a production benchmark.",
    }
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
