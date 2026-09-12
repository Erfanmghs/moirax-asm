"""Operator-visible scan health: QPS collapse, breaker pauses, current dnsx job."""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any

from pipeline.params import Params
from pipeline.textio import tail_lines

_THROTTLE_RE = re.compile(r"throttle_factor=([0-9.]+)")
_RL_RE = re.compile(r"-rl\s+(\d+)")
_PARENT_RE = re.compile(r"-d\s+([A-Za-z0-9._-]+)")
_BRUTE_NAME = re.compile(r"brute_l(\d+)_(.+)_chunk_")


def live_status(params: Params, target_dir: Path) -> dict[str, Any]:
    state = _read_json(target_dir / str(params.require("state_filename")))
    run = state.get("run") if isinstance(state.get("run"), dict) else {}
    breaker = (state.get("breaker") or {}).get("paused") or {}
    issues: list[dict[str, str]] = []
    live: dict[str, Any] = {}

    paused = breaker if isinstance(breaker, dict) else {}
    for name, row in paused.items():
        reason = ""
        if isinstance(row, dict):
            reason = str(row.get("reason") or "")
        issues.append({
            "level": "alert",
            "code": "breaker",
            "text": f"{name} paused" + (f": {reason}" if reason else "") + " (auto-clears at the next module)",
        })
    reason = str(run.get("reason") or "")
    if reason and not any(i["code"] == "breaker" for i in issues):
        issues.append({"level": "alert", "code": "run_reason", "text": reason})

    log_issues, qps_hint = _from_run_log(target_dir / "logs" / "run.log")
    issues.extend(log_issues)
    if qps_hint is not None:
        live["logged_qps"] = qps_hint
        if qps_hint <= 4:
            issues.append({
                "level": "warn",
                "code": "qps_collapse",
                "text": f"dnsx throttled to {qps_hint} QPS (batch wall-clock was treated as latency)",
            })

    brute = _latest_brute(target_dir / "20_dns" / "dnsx")
    if brute:
        live.update(brute)
        live["host_hits"] = brute.get("lines") or 0

    running = str(run.get("status") or "") == str(params.settings.get("run_status_running") or "running")
    if running:
        docker = _docker_dnsx()
        if docker:
            live.update(docker)
            rl = docker.get("qps")
            if isinstance(rl, int) and rl <= 4:
                if not any(i["code"] == "qps_collapse" for i in issues):
                    issues.append({
                        "level": "warn",
                        "code": "qps_collapse",
                        "text": f"live dnsx -rl {rl} (tool itself is far faster; limiter collapsed QPS)",
                    })

    return {"issues": issues, "live": live, "run_status": run.get("status")}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _from_run_log(path: Path) -> tuple[list[dict[str, str]], int | None]:
    issues: list[dict[str, str]] = []
    qps: int | None = None
    if not path.is_file():
        return issues, qps
    lines = tail_lines(path, 120)
    for line in lines:
        m = _THROTTLE_RE.search(line)
        if m:
            try:
                factor = float(m.group(1))
            except ValueError:
                factor = 1.0
            if factor < 0.5:
                issues.append({
                    "level": "warn",
                    "code": "throttle",
                    "text": "circuit breaker halved QPS (latency drift on a long dnsx job)",
                })
        if "canary bad" in line:
            issues.append({
                "level": "warn",
                "code": "canary",
                "text": "load-balance canary marked a window bad (often Docker start time, not resolver failure)",
            })
        if "\t124\tfail" in line or "dnsx\t124\tfail" in line:
            issues.append({
                "level": "warn",
                "code": "timeout",
                "text": "dnsx hit the module timeout and was retried (QPS 1 makes a 6k wordlist miss the budget)",
            })
        if " -rl " in line:
            rm = _RL_RE.search(line)
            if rm:
                qps = int(rm.group(1))
    # de-dupe by code keeping last
    by_code: dict[str, dict[str, str]] = {}
    for row in issues:
        by_code[row["code"]] = row
    return list(by_code.values()), qps


def _latest_brute(dnsx_dir: Path) -> dict[str, Any] | None:
    if not dnsx_dir.is_dir():
        return None
    files = [p for p in dnsx_dir.glob("brute_l*_chunk_*.json") if p.is_file()]
    if not files:
        return None
    newest = max(files, key=lambda p: p.stat().st_mtime)
    m = _BRUTE_NAME.search(newest.name)
    parent = m.group(2).replace("_", ".") if m else newest.name
    try:
        lines = sum(1 for _ in newest.open("r", encoding="utf-8", errors="replace"))
    except OSError:
        lines = 0
    return {"dnsx_file": newest.name, "parent": parent, "lines": lines, "level": int(m.group(1)) if m else None}


_DOCKER_CACHE: dict[str, Any] = {"at": 0.0, "val": None}
_DOCKER_LOCK = threading.Lock()
_DOCKER_TTL_SEC = 3.0


def _docker_dnsx() -> dict[str, Any] | None:
    """Global 'is a recon dnsx container live' probe.

    This is target-INDEPENDENT (one `docker ps` for the whole board), so it is
    memoized with a short TTL: a board tick that renders N target rows shells
    out to Docker once instead of N times, and polling never hammers the daemon.
    """
    now = time.monotonic()
    with _DOCKER_LOCK:
        if now - _DOCKER_CACHE["at"] < _DOCKER_TTL_SEC:
            return _DOCKER_CACHE["val"]
    val = _docker_dnsx_uncached()
    with _DOCKER_LOCK:
        _DOCKER_CACHE["at"] = time.monotonic()
        _DOCKER_CACHE["val"] = val
    return val


def _docker_dnsx_uncached() -> dict[str, Any] | None:
    import subprocess

    try:
        proc = subprocess.run(
            ["docker", "ps", "--filter", "name=recon-", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    names = [n.strip() for n in (proc.stdout or "").splitlines() if n.strip()]
    if not names:
        return None
    name = names[0]
    try:
        ins = subprocess.run(
            ["docker", "inspect", name, "--format", "{{json .Args}}"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"container": name}
    args = (ins.stdout or "").strip()
    out: dict[str, Any] = {"container": name, "containers": names}
    rm = _RL_RE.search(args.replace('"', " "))
    if rm:
        out["qps"] = int(rm.group(1))
    pm = _PARENT_RE.search(args.replace('"', " "))
    if pm:
        out["docker_parent"] = pm.group(1)
    return out
