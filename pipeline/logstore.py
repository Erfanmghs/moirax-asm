"""Storage management: history retention + size-capped log rotation + total cap.

User directive 2026-09-06 ("logs growing forever must not eat storage"). Runs
at EVERY run end (engine hook) and is dashboard-configurable via
dashboard/config.json `retention.*` on top of the tools.yaml defaults.

Contract:
- NEVER-FAIL for the pipeline: housekeep() raises nothing to the run verdict --
  the engine call-site wraps it in try/except exactly like reporting (section 10.1).
- PROTECTED (never deleted): data.json, runs.json, state.json, diff.json,
  warehouse.sqlite (and WAL/SHM), the current report dir (90_report), the
  current logs/run.log and logs/agent-journal.jsonl, and anything outside
  the two managed surfaces.
- MANAGED SURFACES ONLY:
    1. history/<stamp>/ snapshots -- keep the newest N, prune older.
    2. logs/*.gz -- rotation archives created here (gzip level 9); prune
       beyond the keep count; also consumed by the total-size cap.
- Rotation: when a managed log exceeds its cap it is archived to
  <name>.<UTC stamp>.gz and the live file is truncated in place (append-only
  writers keep working -- the engine opens run.log in "a" mode per line).

Purity: stdlib only, no dashboard import (dashboard imports pipeline, never
the reverse); reads the dashboard config JSON with a defensive loader so a
malformed config degrades to tools.yaml defaults instead of crashing a run.
"""

from __future__ import annotations

import gzip
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pipeline.params import Params

_STAMP_RE = re.compile(r"^\d{8}T\d{6}Z$")  # history snapshot dirs we own
_GZ_RE = re.compile(
    r"^run\.log\.\d{8}T\d{6}Z(?:-\d+)?\.gz$|^agent-journal\.jsonl\.\d{8}T\d{6}Z(?:-\d+)?\.gz$"
)

_RETENTION_KEYS = ("keep_runs", "log_max_mb", "journal_max_mb", "log_keep_gz", "max_total_mb")


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _retention_config(params: Params) -> dict[str, int]:
    """tools.yaml defaults <- dashboard/config.json retention.* overrides.
    Malformed values degrade to the default; every value clamped >= 1."""
    cfg: dict[str, int] = {
        "keep_runs": int(params.require("retention_keep_runs")),
        "log_max_mb": int(params.require("retention_log_max_mb")),
        "journal_max_mb": int(params.require("retention_journal_max_mb")),
        "log_keep_gz": int(params.require("retention_log_keep_gz")),
        "max_total_mb": int(params.require("retention_max_total_mb")),
    }
    cfg_path = params.root / str(params.require("dashboard_config_relpath"))
    try:
        doc = json.loads(cfg_path.read_text(encoding="utf-8"))
        overrides = doc.get("retention") if isinstance(doc, dict) else None
        if isinstance(overrides, dict):
            for key in _RETENTION_KEYS:
                value = overrides.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
                    cfg[key] = value
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return {k: max(1, v) for k, v in cfg.items()}


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            continue
    return total


def _history_dirs(target_dir: Path) -> list[Path]:
    """Snapshot dirs we own -- strictly timestamp-named, sorted oldest first."""
    hist = target_dir / "history"
    if not hist.is_dir():
        return []
    dirs = [d for d in hist.iterdir() if d.is_dir() and _STAMP_RE.match(d.name)]
    return sorted(dirs, key=lambda d: d.name)


def _archives(logs_dir: Path) -> list[Path]:
    if not logs_dir.is_dir():
        return []
    gz = [p for p in logs_dir.iterdir() if p.is_file() and _GZ_RE.match(p.name)]
    return sorted(gz, key=lambda p: p.name)


def rotate_log(path: Path, max_mb: int, keep_gz: int) -> dict[str, Any]:
    """Size-capped rotation: oversize -> gzip archive + truncate live file."""
    result: dict[str, Any] = {"file": str(path), "rotated": False, "archived": None, "freed_bytes": 0}
    if not path.is_file() or path.stat().st_size <= max_mb * 1024 * 1024:
        return result
    stamp = _utc_stamp()
    # Collision-proof archive name: two rotations inside the same second must
    # not overwrite each other's archive (counter suffix keeps the regex owns).
    archive = path.parent / f"{path.name}.{stamp}.gz"
    n = 0
    while archive.exists():
        n += 1
        archive = path.parent / f"{path.name}.{stamp}-{n}.gz"
    original = path.stat().st_size
    with path.open("rb") as src, gzip.open(archive, "wb", compresslevel=9) as dst:
        shutil.copyfileobj(src, dst, length=1024 * 1024)
    # Truncate the LIVE file in place (never delete: append-mode writers and
    # the dashboard tail endpoint expect it to exist).
    with path.open("r+b") as handle:
        handle.truncate(0)
    result.update(rotated=True, archived=archive.name, freed_bytes=max(0, original - archive.stat().st_size))
    # Prune oldest archives of THIS log beyond keep count (name-scoped, so
    # run.log rotation never eats agent-journal archives or vice versa).
    prefix = path.name + "."
    archives = [p for p in _archives(path.parent) if p.name.startswith(prefix)]
    for old in archives[: max(0, len(archives) - keep_gz)]:
        try:
            result["freed_bytes"] += old.stat().st_size
            old.unlink()
        except OSError:
            continue
    return result


def prune_history(params: Params, target_dir: Path, keep_runs: int) -> dict[str, Any]:
    """Keep the newest `keep_runs` snapshots; delete strictly-older ones."""
    result: dict[str, Any] = {"pruned": [], "freed_bytes": 0}
    dirs = _history_dirs(target_dir)
    for old in dirs[: max(0, len(dirs) - keep_runs)]:
        try:
            result["freed_bytes"] += _dir_size(old)
            shutil.rmtree(old)
            result["pruned"].append(old.name)
        except OSError:
            continue
    return result


def enforce_total_cap(params: Params, target_dir: Path, max_mb: int) -> dict[str, Any]:
    """Hard cap on the target dir. Order of sacrifice: oldest history
    snapshots, then oldest .gz archives. Protected files are never touched."""
    result: dict[str, Any] = {"capped": False, "freed_bytes": 0, "purged_runs": [], "purged_archives": []}
    limit = max_mb * 1024 * 1024
    total = _dir_size(target_dir)
    if total <= limit:
        return result
    result["capped"] = True
    for old in _history_dirs(target_dir):
        if _dir_size(target_dir) <= limit:
            break
        try:
            result["freed_bytes"] += _dir_size(old)
            shutil.rmtree(old)
            result["purged_runs"].append(old.name)
        except OSError:
            continue
    for old in _archives(target_dir / "logs"):
        if _dir_size(target_dir) <= limit:
            break
        try:
            result["freed_bytes"] += old.stat().st_size
            old.unlink()
            result["purged_archives"].append(old.name)
        except OSError:
            continue
    return result


def housekeep(params: Params, target_dir: Path) -> dict[str, Any]:
    """Run-end storage hygiene. Composes rotation + history retention + total
    cap. Returns a printable ledger; callers must try/except (never-fail)."""
    if not target_dir.is_dir():
        return {"applied": False, "reason": "no target dir yet", "freed_bytes": 0}
    cfg = _retention_config(params)
    ledgers: list[dict[str, Any]] = []
    ledgers.append(rotate_log(target_dir / str(params.require("run_log")), cfg["log_max_mb"], cfg["log_keep_gz"]))
    journal = target_dir / str(params.require("agent_journal_relpath"))
    if journal.is_file():
        ledgers.append(rotate_log(journal, cfg["journal_max_mb"], cfg["log_keep_gz"]))
    pruned = prune_history(params, target_dir, cfg["keep_runs"])
    capped = enforce_total_cap(params, target_dir, cfg["max_total_mb"])
    ledgers.append(pruned)
    ledgers.append(capped)
    freed = sum(int(entry.get("freed_bytes") or 0) for entry in ledgers)
    return {
        "applied": True,
        "policy": cfg,
        "rotated": [entry["archived"] for entry in ledgers if entry.get("rotated")],
        "pruned_runs": pruned["pruned"] + capped["purged_runs"],
        "capped": capped["capped"],
        "freed_bytes": freed,
        "detail": ledgers,
    }
