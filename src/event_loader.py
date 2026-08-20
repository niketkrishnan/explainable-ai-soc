"""Safe CSV-to-event loading for local defensive telemetry."""

from __future__ import annotations

import csv
from pathlib import Path

from .soc_detector import SecurityEvent



def load_csv_events(path: str | Path) -> list[SecurityEvent]:
    source = Path(path)
    with source.open(newline="", encoding="utf-8") as handle:
        rows = csv.DictReader(handle)
        required = {"timestamp", "user", "asset", "source_ip", "event_type", "success"}
        if not required.issubset(set(rows.fieldnames or [])):
            missing = sorted(required - set(rows.fieldnames or []))
            raise ValueError(f"Missing required columns: {missing}")
        events = []
        for row in rows:
            events.append(SecurityEvent(
                timestamp=row["timestamp"],
                user=row["user"],
                asset=row["asset"],
                source_ip=row["source_ip"],
                event_type=row["event_type"],
                success=row["success"].strip().lower() == "true",
                privilege_change=row.get("privilege_change", "false").strip().lower() == "true",
                bytes_out=int(row.get("bytes_out", "0") or 0),
                process_name=row.get("process_name", "") or "",
                destination=row.get("destination", "") or "",
            ))
        return events
