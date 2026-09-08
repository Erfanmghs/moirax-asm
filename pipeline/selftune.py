"""SELFTUNE -- C7 self-improvement loop (operator roadmap).

Roadmap item C7 (docs/HANDOVER.md section 13): self-improvement beyond the
platform-learned wordlist -- auto-tuning budgets from run evidence.

WHAT IT OBSERVES (never invented, always from the run itself):
- branch budget exhaustion markers in the run's partial list
  ("passive_budget" / "active_budget" -- the engine appends them when the
  branch deadline fires with modules still pending)
- the absence of those markers (a clean run)

WHAT IT CHANGES (bounded, disclosed, reversible):
- per-branch budget MULTIPLIERS for the NEXT run of the same target, stored
  in `80_selftune/tuning.json`. Growth: x selftune_growth_step on a marker.
  Decay: x selftune_decay_step back toward 1.0 after selftune_clean_runs_decay
  consecutive clean runs. Multipliers are clamped to
  [selftune_multiplier_min, selftune_multiplier_max] at write AND read time,
  and decay never goes below 1.0 -- the loop may GIVE the branch more time
  after exhaustion, but it never silently shrinks the operator's committed
  budget below the base value.

HONESTY LAWS:
- never silent: every change appends a ledger row (observation -> new
  multipliers -> reason) capped at selftune_ledger_max rows (newest kept)
- module failures do NOT move budgets -- module health belongs to the
  circuit breaker (section 11.4); the tuner only answers "did the branch
  run out of time?"
- toggle selftune_enabled=false disables both read and write (disclosed)
- never-fail: corrupt state is treated as absent and rewritten; the update
  path returns an error row instead of raising (verdict can never flip)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pipeline.textio import atomic_write_text


def _enabled(params: Any) -> bool:
    return bool(params.require("selftune_enabled"))


def _state_path(params: Any, target_dir: Path) -> Path:
    return target_dir / str(params.require("selftune_dirname")) / str(
        params.require("selftune_state_filename")
    )


def _clamp(params: Any, value: float) -> float:
    low = float(params.require("selftune_multiplier_min"))
    high = float(params.require("selftune_multiplier_max"))
    return round(min(high, max(low, value)), 4)


def _load_state(params: Any, target_dir: Path) -> dict[str, Any]:
    path = _state_path(params, target_dir)
    if not path.is_file():
        return _fresh_state()
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(doc, dict) or not isinstance(doc.get("multipliers"), dict):
            return _fresh_state()
        return doc
    except (ValueError, OSError):
        return _fresh_state()


def _fresh_state() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "module": "selftune",
        "multipliers": {"passive": 1.0, "active": 1.0},
        "clean_streak": 0,
        "ledger": [],
    }


def applied_budgets(
    params: Any, target_dir: Path, passive_base: float, active_base: float
) -> tuple[float, float, str]:
    """Start-of-run hook: base budgets scaled by the persisted multipliers.

    Returns (passive_budget, active_budget, note). The note is empty when
    both multipliers are 1.0 -- silence where there is nothing to say.
    """
    if not _enabled(params):
        return passive_base, active_base, ""
    state = _load_state(params, target_dir)
    raw = state.get("multipliers") or {}
    try:
        passive_mult = _clamp(params, float(raw.get("passive", 1.0)))
        active_mult = _clamp(params, float(raw.get("active", 1.0)))
    except (TypeError, ValueError):
        return passive_base, active_base, ""
    passive_eff = round(passive_base * passive_mult, 2)
    active_eff = round(active_base * active_mult, 2)
    if passive_mult == 1.0 and active_mult == 1.0:
        return passive_eff, active_eff, ""
    note = (
        f"applied tuning multipliers: passive x{passive_mult} ({passive_base:.0f}s -> "
        f"{passive_eff:.0f}s), active x{active_mult} ({active_base:.0f}s -> {active_eff:.0f}s)"
    )
    return passive_eff, active_eff, note


def update_tuning(
    params: Any, target_dir: Path, target: str, partial: list[str], stamp: str | None = None
) -> dict[str, Any]:
    """End-of-run hook: observe this run, write the NEXT run's multipliers.

    Never raises. Returns a summary dict for the engine's honesty line.
    """
    summary: dict[str, Any] = {"updated": False, "reason": "", "passive": None, "active": None}
    if not _enabled(params):
        summary["reason"] = "toggle off"
        return summary
    try:
        markers = [str(p) for p in (partial or [])]
        passive_marker = "passive_budget" in markers
        active_marker = "active_budget" in markers
        failures = sum(1 for p in markers if p.startswith(("passive:", "active:", "portsweep:", "owasp:")))

        state = _load_state(params, target_dir)
        multipliers = state.get("multipliers") or {}
        passive_mult = _clamp(params, float(multipliers.get("passive", 1.0)))
        active_mult = _clamp(params, float(multipliers.get("active", 1.0)))

        growth = float(params.require("selftune_growth_step"))
        decay = float(params.require("selftune_decay_step"))
        clean_needed = int(params.require("selftune_clean_runs_decay"))

        observations: list[str] = []
        if passive_marker:
            passive_mult = _clamp(params, passive_mult * growth)
            observations.append("passive branch budget exhausted -> grew passive multiplier")
        if active_marker:
            active_mult = _clamp(params, active_mult * growth)
            observations.append("active branch budget exhausted -> grew active multiplier")

        if not (passive_marker or active_marker):
            state["clean_streak"] = int(state.get("clean_streak") or 0) + 1
            observations.append(f"clean run (streak {state['clean_streak']})")
            if state["clean_streak"] >= clean_needed:
                if passive_mult > 1.0:
                    passive_mult = _clamp(params, max(1.0, passive_mult * decay))
                    observations.append("clean-run decay pulled passive multiplier toward 1.0")
                if active_mult > 1.0:
                    active_mult = _clamp(params, max(1.0, active_mult * decay))
                    observations.append("clean-run decay pulled active multiplier toward 1.0")
        else:
            state["clean_streak"] = 0

        if failures:
            observations.append(
                f"{failures} module failure marker(s) recorded -- budgets untouched "
                "(module health belongs to the circuit breaker, section 11.4)"
            )

        changed = (passive_mult, active_mult) != (
            _clamp(params, float((state.get("multipliers") or {}).get("passive", 1.0))),
            _clamp(params, float((state.get("multipliers") or {}).get("active", 1.0))),
        )
        state["multipliers"] = {"passive": passive_mult, "active": active_mult}
        ledger = list(state.get("ledger") or [])
        ledger.append({
            "run": stamp or "adhoc",
            "observation": "; ".join(observations) or "no budget signals",
            "passive": passive_mult,
            "active": active_mult,
            "changed": changed,
        })
        cap = int(params.require("selftune_ledger_max"))
        state["ledger"] = ledger[-cap:]
        path = _state_path(params, target_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path, json.dumps(state, indent=2, sort_keys=True) + "\n")
        # keep the JSON contract honest: rewrite through write_json is not
        # needed -- the atomic text write above IS the persisted document.
        summary.update({
            "updated": changed,
            "reason": "; ".join(observations),
            "passive": passive_mult,
            "active": active_mult,
            "state": str(path.relative_to(target_dir)),
        })
        return summary
    except Exception as exc:  # noqa: BLE001 -- tuning must never flip a verdict
        summary["reason"] = f"error (disclosed, state untouched): {exc}"
        return summary
