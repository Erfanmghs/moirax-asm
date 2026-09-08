"""state.json engine -- modules + run-level status + breaker pauses (section 6.4, section 11.4)."""

from __future__ import annotations

import json
import os
import threading
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
        "run": {
            "status": str(params.require("run_status_running")),
            "reason": None,
            "failing_module": None,
            "updated_at": _now(),
        },
        "breaker": {"paused": {}},
    }


def load_state(params: Params, target_dir: Path, target: str) -> dict[str, Any]:
    path = state_path(params, target_dir)
    if not path.exists():
        return empty_state(params, target)
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        return empty_state(params, target)
    data.setdefault("breaker", {"paused": {}})
    data.setdefault(
        "run",
        {
            "status": str(params.require("run_status_running")),
            "reason": None,
            "failing_module": None,
            "updated_at": _now(),
        },
    )
    return data


def save_state(params: Params, target_dir: Path, state: dict[str, Any]) -> Path:
    state["updated_at"] = _now()
    path = state_path(params, target_dir)
    # REM26 (run #40 evidence): the passive and active branches run CONCURRENTLY
    # and both persist state -- a SHARED tmp filename races (thread A replaces
    # tmp -> state.json while thread B still holds the same tmp path, B's
    # replace then raises FileNotFoundError and the whole branch dies). Unique
    # tmp per (pid, thread) keeps every writer's replace atomic.
    tmp = path.with_suffix(f"{path.suffix}.{os.getpid()}.{threading.get_ident()}.tmp")
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


def new_run_state(params: Params, target_dir: Path, target: str) -> dict[str, Any]:
    """Reset module rows for a fresh run but KEEP persisted breaker pauses (section 11.4)."""
    previous = load_state(params, target_dir, target) if state_path(params, target_dir).exists() else {}
    state = empty_state(params, target)
    paused = ((previous.get("breaker") or {}).get("paused")) or {}
    if isinstance(paused, dict) and paused:
        state["breaker"] = {"paused": dict(paused)}
    save_state(params, target_dir, state)
    return state


def set_status(params: Params, target_dir: Path, module: str, status: str) -> dict[str, Any]:
    allowed = tuple(params.require("module_status_values"))
    if status not in allowed:
        raise ValueError(f"invalid module status {status!r}")
    # Operator STOP wins: do not start or complete modules after the run is stopped.
    if status in ("running", "done") and operator_stopped(params, target_dir, target_dir.name):
        if status == "running":
            return load_state(params, target_dir, target_dir.name)
        status = "failed"
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


def set_run_status(
    params: Params,
    target_dir: Path,
    target: str,
    status: str,
    reason: str | None = None,
    failing_module: str | None = None,
    *,
    overwrite_stopped: bool = False,
) -> dict[str, Any]:
    state = load_state(params, target_dir, target)
    stopped = str(params.require("run_status_stopped"))
    current = str((state.get("run") or {}).get("status") or "")
    if current == stopped and status != stopped and not overwrite_stopped:
        return state
    state["run"] = {
        "status": status,
        "reason": reason,
        "failing_module": failing_module,
        "updated_at": _now(),
    }
    save_state(params, target_dir, state)
    return state


def run_pid_path(target_dir: Path) -> Path:
    return target_dir / "run.pid"


def write_run_pid(target_dir: Path, pid: int) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)
    path = run_pid_path(target_dir)
    path.write_text(f"{int(pid)}\n", encoding="utf-8")
    return path


def read_run_pid(target_dir: Path) -> int | None:
    path = run_pid_path(target_dir)
    if not path.is_file():
        return None
    try:
        pid = int(path.read_text(encoding="utf-8").strip().split()[0])
    except (OSError, ValueError, IndexError):
        return None
    return pid if pid > 1 else None


def clear_run_pid(target_dir: Path) -> None:
    path = run_pid_path(target_dir)
    try:
        path.unlink()
    except OSError:
        return


def operator_stopped(params: Params, target_dir: Path, target: str) -> bool:
    state = load_state(params, target_dir, target)
    return str((state.get("run") or {}).get("status") or "") == str(
        params.require("run_status_stopped")
    )


def fail_running_modules(params: Params, target_dir: Path, target: str) -> list[str]:
    """Mark in-flight module rows failed. module_status_values has no 'stopped'."""
    state = load_state(params, target_dir, target)
    names = [
        name
        for name, row in (state.get("modules") or {}).items()
        if (row or {}).get("status") == "running"
    ]
    for name in names:
        set_status(params, target_dir, name, "failed")
    return names


def paused_modules(params: Params, target_dir: Path, target: str) -> dict[str, Any]:
    state = load_state(params, target_dir, target)
    paused = ((state.get("breaker") or {}).get("paused")) or {}
    return paused if isinstance(paused, dict) else {}


def persist_pause(params: Params, target_dir: Path, target: str, module: str, reason: str) -> None:
    state = load_state(params, target_dir, target)
    breaker = state.setdefault("breaker", {"paused": {}})
    paused = breaker.setdefault("paused", {})
    paused[module] = {"reason": reason, "paused_at": _now()}
    # Mirror into run object immediately so ANOMALY is observable mid-run.
    state["run"] = {
        "status": str(params.require("run_status_anomaly")),
        "reason": reason,
        "failing_module": module,
        "updated_at": _now(),
    }
    save_state(params, target_dir, state)


def clear_breaker_pauses(params: Params, target_dir: Path, target: str) -> dict[str, Any]:
    state = load_state(params, target_dir, target)
    state["breaker"] = {"paused": {}}
    run = state.get("run") or {}
    if str(run.get("status") or "") == str(params.require("run_status_anomaly")):
        state["run"] = {
            "status": str(params.require("run_status_completed")),
            "reason": "breaker reset",
            "failing_module": None,
            "updated_at": _now(),
        }
    save_state(params, target_dir, state)
    return state


def skip_done(state: dict[str, Any], module: str) -> bool:
    row = (state.get("modules") or {}).get(module) or {}
    return row.get("status") == "done"
