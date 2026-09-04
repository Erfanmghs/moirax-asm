"""state.json engine — pending|running|done|failed + timestamps (§6.4)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pipeline.params import Params

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def state_path(params: Params, target_dir: Path) -> Path:
    return target_dir / str(params.require("state_filename"))


def empty_state(params: Params, target: str) -> dict[str, Any]:
    modules = {}
    for name in params.require("pipeline_modules"):
        modules[str(name)] = {
            "status": "pending",
            "started_at": None,
            "finished_at": None,
        }
    return {
        "schema_version": int(params.require("schema_version")),
        "target": target,
        "updated_at": _now(),
        "modules": modules,
    }


def load_state(params: Params, target_dir: Path, target: str) -> dict[str, Any]:
    path = state_path(params, target_dir)
    if not path.exists():
        return empty_state(params, target)
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        return empty_state(params, target)
    return data


def save_state(params: Params, target_dir: Path, state: dict[str, Any]) -> Path:
    state["updated_at"] = _now()
    path = state_path(params, target_dir)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path


def init_state(params: Params, target_dir: Path, target: str) -> dict[str, Any]:
    path = state_path(params, target_dir)
    if path.exists():
        return load_state(params, target_dir, target)
    state = empty_state(params, target)
    save_state(params, target_dir, state)
    return state


def set_status(params: Params, target_dir: Path, module: str, status: str) -> dict[str, Any]:
    allowed = tuple(params.require("module_status_values"))
    if status not in allowed:
        raise ValueError(f"invalid module status {status!r}")
    state = load_state(params, target_dir, target_dir.name)
    modules = state.setdefault("modules", {})
    row = modules.get(module) or {"status": "pending", "started_at": None, "finished_at": None}
    if status == "running":
        row["started_at"] = _now()
        row["finished_at"] = None
    elif status in ("done", "failed"):
        row["finished_at"] = _now()
    row["status"] = status
    modules[module] = row
    save_state(params, target_dir, state)
    return state


def skip_done(state: dict[str, Any], module: str) -> bool:
    row = (state.get("modules") or {}).get(module) or {}
    return row.get("status") == "done"
