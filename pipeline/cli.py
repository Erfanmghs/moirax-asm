"""CLI: run | resume | stop | status | report | module | reset-breaker — no network before a valid scope."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from pipeline.factory import ensure_layout, sanitize_target, target_root
from pipeline.params import Params
from pipeline.scope import SETUP_INSTRUCTIONS, ScopeError, ScopeGate
from pipeline import state as state_engine

USAGE = """Usage:
  ./recon.sh run <target> [--aggressive]
  ./recon.sh resume <target> [--aggressive]
  ./recon.sh stop <target>
  ./recon.sh status [target]
  ./recon.sh report <target>
  ./recon.sh module <name> <target> [--aggressive]
  ./recon.sh reset-breaker <target>
"""


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
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
        data = json.loads(state_file.read_text(encoding="utf-8"))
        modules = data.get("modules") or {}
        summary = ", ".join(f"{name}={row.get('status')}" for name, row in modules.items())
        run = data.get("run") or {}
        print(f"{child.name}: run={run.get('status')} {data.get('updated_at')} [{summary}]")
    if not found:
        print("status: empty workspace (no state.json files)")
    return 0


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

    return run_pipeline(params, gate, target, aggressive=aggressive)


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

    return run_pipeline(params, gate, target, aggressive=aggressive, resume=True)


def cmd_stop(params: Params, target: str) -> int:
    target = sanitize_target(target)
    target_dir = target_root(params, target)
    if not state_engine.state_path(params, target_dir).exists():
        print(f"stop: no run in progress for {target}")
        return 0
    st = state_engine.load_state(params, target_dir, target)
    running = [
        name
        for name, row in (st.get("modules") or {}).items()
        if (row or {}).get("status") == "running"
    ]
    from pipeline.engine import stop_target

    stopped = stop_target(params, target_dir)
    if not running and not stopped:
        print(f"stop: no running modules for {target}")
        return 0
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


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        os._exit(0)
