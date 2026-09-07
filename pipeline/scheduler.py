"""SCHEDULER / WATCHTOWER (section 4.6).

Scheduler state (`interval`, `enabled`, `last_run`) lives in `scheduler.json`,
editable from the dashboard (section 9.2-c). Validated minimum interval = 10 minutes
(spec: "validated minimum 10 min"). The loop itself runs on the operator
workstation (dashboard service / CLI); this module owns the state machine so
both entrypoints share one frozen implementation.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pipeline.params import Params


def load_schedule(params: Params) -> dict[str, Any]:
    path = params.root / str(params.require("scheduler_filename"))
    if not path.is_file():
        return default_schedule(params)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return default_schedule(params)
    return doc if isinstance(doc, dict) else default_schedule(params)


def default_schedule(params: Params) -> dict[str, Any]:
    return {
        "interval_minutes": int(params.require("scheduler_default_interval_min")),
        "enabled": False,
        "last_run": None,
    }


def save_schedule(params: Params, doc: dict[str, Any]) -> Path:
    path = params.root / str(params.require("scheduler_filename"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return path


def validate(doc: dict[str, Any], min_interval_min: int) -> list[str]:
    """section 4.6 validation -- interval must be an integer >= the 10-minute floor."""
    errors: list[str] = []
    interval = doc.get("interval_minutes")
    if not isinstance(interval, int) or isinstance(interval, bool):
        errors.append("interval_minutes must be an integer")
    elif interval < min_interval_min:
        errors.append(f"interval_minutes {interval} is below the validated minimum {min_interval_min}")
    if not isinstance(doc.get("enabled"), bool):
        errors.append("enabled must be a boolean")
    last = doc.get("last_run")
    if last is not None and not isinstance(last, str):
        errors.append("last_run must be null or an ISO-8601 UTC string")
    return errors


def due(doc: dict[str, Any], now_epoch: float | None = None) -> bool:
    """A scheduled run is due when enabled AND (never run OR interval elapsed)."""
    if not doc.get("enabled"):
        return False
    interval = doc.get("interval_minutes")
    if not isinstance(interval, int) or interval <= 0:
        return False
    last = doc.get("last_run")
    if not last:
        return True
    try:
        last_epoch = datetime.fromisoformat(str(last).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return True
    now = now_epoch if now_epoch is not None else datetime.now(timezone.utc).timestamp()
    return now - last_epoch >= interval * 60


def mark_run(doc: dict[str, Any], now_epoch: float | None = None) -> dict[str, Any]:
    now = now_epoch if now_epoch is not None else datetime.now(timezone.utc).timestamp()
    doc = dict(doc)
    doc["last_run"] = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return doc
