"""Minimal structured audit logging without raw telemetry payloads."""

from __future__ import annotations

import json
import logging
from typing import Any


def configure_audit_logger(name: str = "soc.audit") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def audit_record(action: str, *, event_count: int, alert_count: int, mode: str = "demo") -> dict[str, Any]:
    return {"action": action, "event_count": event_count, "alert_count": alert_count, "mode": mode}


def emit_audit(logger: logging.Logger, record: dict[str, Any]) -> None:
    logger.info(json.dumps(record, sort_keys=True))
