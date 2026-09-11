"""CLI: run | resume | restart | stop | status | report | module | reset-breaker | info-gather -- no network before a valid scope."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from pipeline.factory import ensure_layout, sanitize_target, target_root
from pipeline.params import Params
from pipeline.scope import SETUP_INSTRUCTIONS, ScopeError, ScopeGate
from pipeline import state as state_engine

USAGE = """Usage:
  ./recon.sh run <target> [--aggressive]
  ./recon.sh resume <target> [--aggressive]
  ./recon.sh restart <target> [--aggressive]
  ./recon.sh stop <target>
  ./recon.sh status [target]
  ./recon.sh report <target>
  ./recon.sh module <name> <target> [--aggressive]
  ./recon.sh reset-breaker <target>
  ./recon.sh info-gather <target|*.wildcard>   # section 12.2 one-command autonomy (agent on)
  ./recon.sh wordlist-sync                     # C2: index the full SecLists clone (all lists selectable)
  ./recon.sh wordlist-add <name> <file>        # C2: register an operator custom list
  ./recon.sh wordlist-rm <name>                # C2: remove an operator custom list
  ./recon.sh target-profile set <target> <json-file>   # C3: upsert per-target settings
  ./recon.sh target-profile get <target>               # C3: show per-target profile
  ./recon.sh fleet run [--targets a,b,c|all] [--concurrency N]  # C4: concurrent multi-target run
  ./recon.sh fleet status                              # C4: latest fleet ledger
"""


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except SystemExit as exc:
        if isinstance(exc.code, int):
            return exc.code
        if exc.code:
            sys.stderr.write(str(exc.code) if not str(exc.code).endswith("\n") else str(exc.code))
            if not str(exc.code).endswith("\n"):
                sys.stderr.write("\n")
        return 2
    except Exception as exc:  # noqa: BLE001 -- CLI never dumps a worker; exit 1 with a line
        print(f"fatal: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        sys.stderr.write(USAGE)
        return 2
    command = args[0]
    root = repo_root()
    params = Params(root)
    if command == "status":
        return cmd_status(params, args[1] if len(args) > 1 else None)
    if command == "run":
        target, aggressive = _target_and_aggressive(args, 1)
        return cmd_run(params, target, aggressive)
    if command == "resume":
        target, aggressive = _target_and_aggressive(args, 1)
        return cmd_resume(params, target, aggressive)
    if command == "restart":
        target, aggressive = _target_and_aggressive(args, 1)
        return cmd_restart(params, target, aggressive)
    if command == "stop":
        return cmd_stop(params, _need(args, 1))
    if command == "report":
        return cmd_report(params, _need(args, 1))
    if command == "module":
        name = _need(args, 1)
        target, aggressive = _target_and_aggressive(args, 2)
        return cmd_module(params, name, target, aggressive)
    if command == "reset-breaker":
        return cmd_reset_breaker(params, _need(args, 1))
    if command == "info-gather":
        return cmd_info_gather(params, _need(args, 1))
    if command == "wordlist-sync":
        return cmd_wordlist_sync(params)
    if command == "wordlist-add":
        return cmd_wordlist_add(params, _need(args, 1), _need(args, 2))
    if command == "wordlist-rm":
        return cmd_wordlist_rm(params, _need(args, 1))
    if command == "fleet" and len(args) >= 2:
        sub = args[1]
        if sub == "run":
            return cmd_fleet_run(params, args[2:])
        if sub == "status":
            return cmd_fleet_status(params)
    if command == "target-profile" and len(args) >= 3:
        sub = args[1]
        if sub == "set":
            return cmd_target_profile_set(params, args[2], args[3] if len(args) > 3 else None)
        if sub == "get":
            return cmd_target_profile_get(params, args[2])
    sys.stderr.write(USAGE)
    return 2


def _need(args: list[str], index: int) -> str:
    if len(args) <= index or str(args[index]).startswith("--"):
        raise SystemExit(USAGE)
    return args[index]


def _target_and_aggressive(args: list[str], index: int) -> tuple[str, bool]:
    target = _need(args, index)
    aggressive = False
    rest = args[index + 1 :]
    for item in rest:
        if item == "--aggressive":
            aggressive = True
        else:
            raise SystemExit(USAGE)
    return target, aggressive


def cmd_status(params: Params, target: str | None) -> int:
    recon = params.root / str(params.require("recon_root"))
    if target:
        path = target_root(params, sanitize_target(target))
        state_file = state_engine.state_path(params, path)
        if not state_file.exists():
            print(f"status: no run state for {target}")
            return 0
        print(state_file.read_text(encoding="utf-8"))
        return 0
    if not recon.exists():
        print("status: empty workspace (no recon/ directory)")
        return 0
    found = False
    for child in sorted(p for p in recon.iterdir() if p.is_dir()):
        state_file = state_engine.state_path(params, child)
        if not state_file.exists():
            continue
        found = True
        try:
            data = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            print(f"{child.name}: unreadable state.json")
            continue
        if not isinstance(data, dict):
            print(f"{child.name}: unreadable state.json")
            continue
        modules = data.get("modules") or {}
        summary = ", ".join(f"{name}={row.get('status')}" for name, row in modules.items())
        run = data.get("run") or {}
        print(f"{child.name}: run={run.get('status')} {data.get('updated_at')} [{summary}]")
    if not found:
        print("status: empty workspace (no state.json files)")
    return 0


def _run_with_target_profile(params: Params, target: str, runner: Callable[[], int]) -> int:
    """Apply per-target SETUP for this run, then restore global files.

    Empty / description-only profiles leave tools.yaml and wordlists.yaml
    untouched, so SETTINGS and WORDLISTS apply as-is.
    """
    from pipeline.target_profiles import ProfileError, apply_transient, restore_transient

    snap = Path(tempfile.mkdtemp(prefix="recon-profile-"))
    applied: dict[str, Any] | None = None
    try:
        try:
            applied = apply_transient(params, target, snap)
        except ProfileError as exc:
            print(f"target profile apply failed: {exc}")
            return 1
        # Disk edits land in tools.yaml; in-memory Params must refresh or
        # recon_depth / module order stay at the pre-SETUP globals.
        params.reload()
        try:
            return runner()
        except Exception as exc:  # noqa: BLE001 -- profile restore still runs in finally
            print(f"run failed: {type(exc).__name__}: {exc}")
            return 1
    finally:
        if applied:
            restore_transient(applied)


def cmd_run(params: Params, target: str, aggressive: bool = False) -> int:
    target = sanitize_target(target)
    try:
        gate = _load_gate(params)
    except ScopeError as exc:
        return _fail_scope(exc)
    allowed, reason = gate.validate_candidate(target)
    if not allowed:
        target_dir = ensure_layout(params, target)
        log_rel = Path(str(params.require("out_of_scope_log")))
        gate.log_rejection(target_dir / log_rel, target, reason)
        print(f"out of scope: {target} ({reason})")
        print(f"logged: {target_dir / log_rel}")
        return 1
    from pipeline.engine import run_pipeline

    return _run_with_target_profile(
        params, target, lambda: run_pipeline(params, gate, target, aggressive=aggressive)
    )


def cmd_resume(params: Params, target: str, aggressive: bool = False) -> int:
    target = sanitize_target(target)
    try:
        gate = _load_gate(params)
    except ScopeError as exc:
        return _fail_scope(exc)
    target_dir = target_root(params, target)
    if not state_engine.state_path(params, target_dir).exists():
        print(f"nothing to resume for {target}")
        return 1
    from pipeline.engine import run_pipeline

    return _run_with_target_profile(
        params,
        target,
        lambda: run_pipeline(params, gate, target, aggressive=aggressive, resume=True),
    )


def cmd_restart(params: Params, target: str, aggressive: bool = False) -> int:
    """Stop a live scan for this target, then run the ladder from module 1.

    Not START: START leaves a live process alone (dashboard returns 409).
    Not RESUME: RESUME keeps done modules; RESTART resets rows via new_run_state.
    """
    target = sanitize_target(target)
    try:
        gate = _load_gate(params)
    except ScopeError as exc:
        return _fail_scope(exc)
    allowed, reason = gate.validate_candidate(target)
    if not allowed:
        target_dir = ensure_layout(params, target)
        log_rel = Path(str(params.require("out_of_scope_log")))
        gate.log_rejection(target_dir / log_rel, target, reason)
        print(f"out of scope: {target} ({reason})")
        print(f"logged: {target_dir / log_rel}")
        return 1
    target_dir = ensure_layout(params, target)
    from pipeline.engine import run_pipeline, stop_target

    stop_target(params, target_dir)
    return _run_with_target_profile(
        params,
        target,
        lambda: run_pipeline(params, gate, target, aggressive=aggressive, resume=False),
    )


def cmd_stop(params: Params, target: str) -> int:
    target = sanitize_target(target)
    target_dir = target_root(params, target)
    from pipeline.engine import stop_target

    running: list[str] = []
    if state_engine.state_path(params, target_dir).exists():
        st = state_engine.load_state(params, target_dir, target)
        running = [
            name
            for name, row in (st.get("modules") or {}).items()
            if (row or {}).get("status") == "running"
        ]
    stopped = stop_target(params, target_dir)
    print(f"stop requested for: {', '.join(running) or '(none)'}; containers={len(stopped)}")
    return int(params.require("exit_code_stopped"))


def cmd_report(params: Params, target: str) -> int:
    target = sanitize_target(target)
    target_dir = target_root(params, target)
    report_dir = target_dir / "90_report"
    if not report_dir.exists():
        print(f"report: no workspace for {target}")
        return 1
    artifacts = list(report_dir.iterdir()) if report_dir.exists() else []
    if not artifacts:
        print(f"report: {report_dir} is empty")
        return 0
    for item in artifacts:
        print(item)
    return 0


def cmd_module(params: Params, name: str, target: str, aggressive: bool = False) -> int:
    target = sanitize_target(target)
    try:
        gate = _load_gate(params)
    except ScopeError as exc:
        return _fail_scope(exc)
    allowed, reason = gate.validate_candidate(target)
    if not allowed:
        target_dir = ensure_layout(params, target)
        log_rel = Path(str(params.require("out_of_scope_log")))
        gate.log_rejection(target_dir / log_rel, target, reason)
        print(f"out of scope: {target} ({reason})")
        return 1
    from pipeline.engine import run_module

    return run_module(params, gate, name, target, aggressive=aggressive)


def cmd_reset_breaker(params: Params, target: str) -> int:
    target = sanitize_target(target)
    target_dir = target_root(params, target)
    if not state_engine.state_path(params, target_dir).exists():
        print(f"reset-breaker: no state for {target}")
        return 1
    before = state_engine.paused_modules(params, target_dir, target)
    state_engine.clear_breaker_pauses(params, target_dir, target)
    after = state_engine.paused_modules(params, target_dir, target)
    print(f"reset-breaker: cleared {sorted(before.keys())} for {target}; paused_now={sorted(after.keys())}")
    return 0


def _load_gate(params: Params) -> ScopeGate:
    return ScopeGate.load(params, params.root / "scope.yaml")


def _fail_scope(exc: ScopeError) -> int:
    print(str(exc), file=sys.stderr)
    if exc.instructions:
        print(SETUP_INSTRUCTIONS, file=sys.stderr)
    return 2


# ----------------------------------------------------------- C2 wordlists

def cmd_wordlist_sync(params: Params) -> int:
    """C2: index the local SecLists clone -- every list becomes selectable."""
    from pipeline.seclists_sync import sync_seclists_index

    ledger = sync_seclists_index(params)
    print(
        f"wordlist-sync: lists={ledger['lists']} "
        f"total_entries={ledger['total_entries']} index={ledger['index']}"
    )
    return 0


def cmd_wordlist_add(params: Params, name: str, file_arg: str) -> int:
    """C2: register an operator custom list (validated, secret-scanned)."""
    from pathlib import Path as _Path

    from pipeline.custom_lists import CustomListError, add_custom_list

    try:
        ledger = add_custom_list(params, name.strip(), _Path(file_arg))
    except (CustomListError, UnicodeDecodeError, OSError) as exc:
        print(f"wordlist-add: REFUSED {name!r}: {exc}")
        return 1
    print(f"wordlist-add: registered {ledger['name']} entries={ledger['entries']} path={ledger['path']}")
    return 0


def cmd_wordlist_rm(params: Params, name: str) -> int:
    """C2: remove an operator custom list (platform-learned is protected)."""
    from pipeline.custom_lists import CustomListError, remove_custom_list

    try:
        ledger = remove_custom_list(params, name.strip())
    except CustomListError as exc:
        print(f"wordlist-rm: REFUSED {name!r}: {exc}")
        return 1
    print(f"wordlist-rm: removed {ledger['removed']}")
    return 0


# --------------------------------------------------------- C3 profiles

def cmd_target_profile_set(params: Params, target: str, json_file: str | None) -> int:
    """C3: upsert a per-target settings profile from a JSON file (or stdin)."""
    import json as _json
    import sys as _sys

    from pipeline.target_profiles import ProfileError, set_profile

    raw = _sys.stdin.read() if json_file in (None, "-") else Path(json_file).read_text(encoding="utf-8")
    try:
        profile = _json.loads(raw or "{}")
        ledger = set_profile(params, target.strip(), profile)
    except (ProfileError, _json.JSONDecodeError, OSError) as exc:
        print(f"target-profile: REFUSED {target!r}: {exc}")
        return 1
    print(f"target-profile: saved {ledger['target']} sections={ledger['sections']}")
    return 0


def cmd_target_profile_get(params: Params, target: str) -> int:
    """C3: show the effective per-target profile (empty = committed defaults)."""
    import json as _json

    from pipeline.target_profiles import get_profile

    print(_json.dumps(get_profile(params, target.strip()), indent=2, sort_keys=True))
    return 0


# ------------------------------------------------------------- C4 fleet

def cmd_fleet_run(params: Params, rest: list[str]) -> int:
    """C4: concurrent multi-target run with automatic resource management."""
    from pipeline.fleet import FleetError, run_fleet

    targets = "all"
    concurrency = None
    i = 0
    while i < len(rest):
        if rest[i] == "--targets" and i + 1 < len(rest):
            targets = rest[i + 1]
            i += 2
        elif rest[i] == "--concurrency" and i + 1 < len(rest):
            try:
                concurrency = int(rest[i + 1])
            except ValueError:
                print("fleet: --concurrency must be an integer")
                return 1
            i += 2
        else:
            i += 1
    try:
        ledger = run_fleet(params, targets, concurrency=concurrency)
    except FleetError as exc:
        print(f"fleet: REFUSED {exc}")
        return 1
    print(f"fleet: requested={ledger['requested']} concurrency={ledger['concurrency']} clean={ledger['clean']}")
    for r in ledger["results"]:
        print(f"  member {r['target']}: exit={r.get('exit_code')} {'err=' + r['error'] if r.get('error') else ''}")
    print(f"fleet ledger: history/fleet/ (latest run)")
    return 0 if ledger["clean"] else 1


def cmd_fleet_status(params: Params) -> int:
    """C4: show the latest fleet ledger."""
    import json as _json

    root = Path(params.root) / "history" / "fleet"
    if not root.is_dir():
        print("fleet: no fleet runs recorded")
        return 1
    latest = sorted(d.name for d in root.iterdir() if d.is_dir())[-1]
    doc = _json.loads((root / latest / "fleet-ledger.json").read_text(encoding="utf-8"))
    print(_json.dumps({"run": latest, "clean": doc["clean"], "concurrency": doc["concurrency"],
                        "results": [{"target": r["target"], "exit": r.get("exit_code")} for r in doc["results"]]},
                       indent=1))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        os._exit(0)


def cmd_info_gather(params: Params, raw_target: str) -> int:
    """section 12.2 ONE-COMMAND AUTONOMY: validate scope -> run pipeline -> monitor ->
    remediate (agent opt-in inside the engine) -> report. Zero further input."""
    from pathlib import Path as _Path

    from pipeline.engine import run_pipeline
    from pipeline.reporting import generate_all

    raw = raw_target.strip()
    target = sanitize_target(raw.lstrip("*.") if raw.startswith("*.") else raw)
    print(f"info-gather: one-command autonomy for {raw} (agent ON, section 12.2)")
    try:
        gate = _load_gate(params)
    except ScopeError as exc:
        return _fail_scope(exc)
    # section 12.7 guardrail: the ONLY scope action is validation -- never modification.
    allowed, reason = gate.validate_candidate(target)
    if not allowed:
        target_dir = ensure_layout(params, target)
        log_rel = Path(str(params.require("out_of_scope_log")))
        gate.log_rejection(target_dir / log_rel, target, reason)
        print(f"out of scope: {target} ({reason}) -- agent never modifies scope.yaml (section 12.7)")
        return 1
    cfg = {
        "enabled": True,
    }
    # enable the agent persistently for this repo state (dashboard toggle equivalent)
    import json as _json

    config_path = params.root / str(params.require("dashboard_config_relpath"))
    try:
        doc = _json.loads(config_path.read_text(encoding="utf-8")) if config_path.is_file() else {}
    except (OSError, ValueError, _json.JSONDecodeError):
        doc = {}
    agent_cfg = doc.get("agent") or {}
    agent_cfg.setdefault("enabled", True)
    doc["agent"] = agent_cfg
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(_json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    code = run_pipeline(params, gate, target, aggressive=False)
    report_dir = target_root(params, target) / str(params.require("report_dirname"))
    print(f"info-gather: complete -- report at {report_dir} (exit={code})")
    _ = generate_all, cfg, _Path  # referenced for contract clarity
    return code
