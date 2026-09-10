"""Soft-delete for per-target workspaces.

SCAN hides a site immediately. The isolated recon/<target>/ tree (including
warehouse.sqlite) stays on disk for deleted_target_keep_days, then purge
removes that tree only.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pipeline.params import Params

MARKER = ".deleted"
DEFAULT_KEEP_DAYS = 7


def keep_days(params: Params) -> int:
    try:
        days = int(params.require("deleted_target_keep_days"))
    except (KeyError, TypeError, ValueError):
        days = DEFAULT_KEEP_DAYS
    return max(1, min(days, 365))


def marker_path(target_dir: Path) -> Path:
    return target_dir / MARKER


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: str) -> datetime | None:
    raw = str(value or "").strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def read_tombstone(target_dir: Path) -> dict[str, Any] | None:
    path = marker_path(target_dir)
    if not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {"deleted_at": None, "purge_after": None, "corrupt": True}
    return doc if isinstance(doc, dict) else {"deleted_at": None, "purge_after": None, "corrupt": True}


def is_tombstoned(target_dir: Path) -> bool:
    return marker_path(target_dir).is_file()


def write_tombstone(params: Params, target_dir: Path, target: str) -> dict[str, Any]:
    days = keep_days(params)
    now = _now()
    purge_at = now + timedelta(days=days)
    payload = {
        "schema_version": 1,
        "target": target,
        "deleted_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "purge_after": purge_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "keep_days": days,
    }
    path = marker_path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def clear_tombstone(target_dir: Path) -> None:
    path = marker_path(target_dir)
    if path.is_file():
        path.unlink()


def _confined(params: Params, target_dir: Path) -> Path | None:
    recon = (params.root / str(params.require("recon_root"))).resolve()
    try:
        resolved = target_dir.resolve()
        common = os.path.commonpath([str(recon), str(resolved)])
    except (ValueError, OSError):
        return None
    if common != str(recon) or resolved == recon:
        return None
    return resolved


def purge_if_expired(params: Params, target_dir: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Hard-delete one tombstoned target dir after the keep window."""
    marker = read_tombstone(target_dir)
    if not marker:
        return {"purged": False, "reason": "not tombstoned"}
    confined = _confined(params, target_dir)
    if confined is None:
        return {"purged": False, "reason": "outside recon root"}
    due = _parse_iso(str(marker.get("purge_after") or ""))
    clock = now or _now()
    if due is not None and clock < due:
        return {"purged": False, "reason": "keep window", "purge_after": marker.get("purge_after")}
    shutil.rmtree(confined)
    return {"purged": True, "path": str(confined)}


def purge_expired_all(params: Params, *, now: datetime | None = None) -> dict[str, Any]:
    recon = params.root / str(params.require("recon_root"))
    purged: list[str] = []
    if not recon.is_dir():
        return {"purged": purged}
    from pipeline.target_profiles import TARGET_NAME_RE

    for child in list(recon.iterdir()):
        if not child.is_dir() or not TARGET_NAME_RE.match(child.name):
            continue
        if not is_tombstoned(child):
            continue
        led = purge_if_expired(params, child, now=now)
        if led.get("purged"):
            purged.append(child.name)
    return {"purged": purged}
