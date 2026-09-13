"""WIDE pipeline engine: PASSIVE || ACTIVE, branch budgets, MERGE, history (section 7)."""

from __future__ import annotations

import os
import signal
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from pipeline.adapter import Adapter, InvokeResult
from pipeline.breaker import CircuitBreaker, Clock
from pipeline.ceiling import ResourceCeiling
from pipeline.factory import ensure_layout
from pipeline.history import append_run, previous_timestamp, snapshot, utc_stamp, write_diff
from pipeline.jsonio import read_json
from pipeline.merge import append_active_doc, load_tool_doc, merge_branches
from pipeline.modules.dns_resolve import expand_nested_after_vhosts
from pipeline.modules import RUNNERS
from pipeline.notify import run_end_notifications, send_status
from pipeline.ip_rotation import gate_pool_or_legacy
from pipeline.params import Params
from pipeline.reporting import generate_all
from pipeline.scope import ScopeGate
from pipeline.wordlist_forge import EmptyWordlistError, ingest_if_completed
from pipeline import state as state_engine


# Debounce window for mid-run live warehouse ingests. Each ingest does a full
# tree rglob + fact rewrite; on a fast module sequence that is pure overhead.
# The authoritative index is always rebuilt by ingest_run_end() at run end, so
# skipping an intermediate live ingest only costs a few seconds of dashboard
# freshness -- never correctness.
_LIVE_INGEST_MIN_INTERVAL_SEC = 10.0
_LAST_LIVE_INGEST: dict[str, float] = {}


def _ingest_live(params: Params, target_dir: Path, target: str, *, force: bool = False) -> None:
    key = str(target_dir)
    now = time.monotonic()
    last = _LAST_LIVE_INGEST.get(key, 0.0)
    if not force and (now - last) < _LIVE_INGEST_MIN_INTERVAL_SEC:
        # Disclosed, not silent: the next module boundary (or run-end ingest)
        # will refresh the live index.
        print(f"warehouse: live ingest debounced ({now - last:.1f}s < {_LIVE_INGEST_MIN_INTERVAL_SEC:.0f}s)")
        return
    _LAST_LIVE_INGEST[key] = now
    try:
        from pipeline.warehouse import ingest_live

        ledger = ingest_live(params, target_dir, target)
        print(
            "warehouse: live "
            f"ok={ledger.get('ok')} facts={ledger.get('facts')} stamp={ledger.get('stamp')}"
        )
    except Exception as exc:  # noqa: BLE001 -- derived index must never flip a module
        print(f"warehouse: live disclosed failure: {exc}")


def _release_breaker(breaker: CircuitBreaker, module: str) -> None:
    """If the limiter paused this module, clear it so the ladder continues.

    Mid-module invokes still see a live pause (protects the target). The next
    module boundary, or the next run, auto-resets -- the operator never has
    to click RESET LIMITER.
    """
    if breaker.allow(module):
        return
    cleared = breaker.reset_paused(module, reason="continue run")
    if cleared:
        print(f"breaker: auto-reset {cleared} so {module} can run")


class OperatorStop(Exception):
    """Operator requested stop; branches must not start the next module."""


def _engage_agent(
    params: Params,
    target_dir: Path,
    module: str,
    branch: str,
    reason: str,
    hooks: dict[str, Any] | None = None,
    holder: dict[str, Any] | None = None,
) -> None:
    """Opt-in supervisor hook. Never raises -- a NameError here used to abort
    the whole PASSIVE branch because the helper lived inside run_pipeline."""
    try:
        from pipeline.agent import Supervisor

        box = holder if holder is not None else {}
        if "supervisor" not in box:
            box["supervisor"] = Supervisor(params, target_dir)
        supervisor = box["supervisor"]
        if not supervisor.enabled():
            return
        verdict = supervisor.on_module_failure(module, branch, str(reason), hooks=hooks)
        print(f"agent: {module} verdict={ {k: v for k, v in verdict.items() if k != 'engaged'} }")
    except Exception as exc:  # noqa: BLE001 -- agent must never fail the module path
        print(f"agent: engage failed (disclosed, ignored): {exc}")


def _tuned_budgets(params: Params, target_dir: Path) -> tuple[float, float, str]:
    """C7 start-of-run hook: base branch budgets scaled by persisted selftune
    multipliers (bounded; corrupt state ignored, disclosed, never fail)."""
    try:
        from pipeline.selftune import applied_budgets

        return applied_budgets(
            params,
            target_dir,
            float(params.require("passive_branch_budget_sec")),
            float(params.require("active_branch_budget_sec")),
        )
    except Exception as exc:  # noqa: BLE001 -- tuning must never start-fail a run
        return (
            float(params.require("passive_branch_budget_sec")),
            float(params.require("active_branch_budget_sec")),
            f"tuning read failed (disclosed, base budgets kept): {exc}",
        )


def run_pipeline(
    params: Params,
    gate: ScopeGate,
    target: str,
    aggressive: bool = False,
    clock: Clock | None = None,
    runner: Any | None = None,
    resume: bool = False,
) -> int:
    """Public entry: a crash inside the ladder still marks the run failed
    and clears the PID so the dashboard never sits on a zombie 'running'."""
    try:
        return _run_pipeline_impl(
            params, gate, target, aggressive=aggressive, clock=clock, runner=runner, resume=resume
        )
    except OperatorStop:
        clock = clock or Clock()
        target_dir = ensure_layout(params, target)
        return _finalize_stopped(params, gate, target_dir, target, clock, clock.time(), None)
    except Exception as exc:  # noqa: BLE001 -- last-chance: never abort without a terminal status
        traceback.print_exc()
        try:
            target_dir = ensure_layout(params, target)
            return _finalize_crash(params, target_dir, target, exc)
        except Exception as inner:  # noqa: BLE001
            print(f"engine crash: {exc}; finalize failed: {inner}")
            return 1


def _run_pipeline_impl(
    params: Params,
    gate: ScopeGate,
    target: str,
    aggressive: bool = False,
    clock: Clock | None = None,
    runner: Any | None = None,
    resume: bool = False,
) -> int:
    target_dir = ensure_layout(params, target)
    # PID first so an overlapping STOP can signal this process even before state.json exists.
    state_engine.write_run_pid(target_dir, os.getpid())
    if resume:
        state_engine.init_state(params, target_dir, target)
    else:
        state_engine.new_run_state(params, target_dir, target)
    state_engine.set_run_status(
        params,
        target_dir,
        target,
        str(params.require("run_status_running")),
        reason=None,
        failing_module=None,
        overwrite_stopped=resume,
    )
    clock = clock or Clock()
    run_started = clock.time()
    if state_engine.operator_stopped(params, target_dir, target):
        return _finalize_stopped(params, gate, target_dir, target, clock, run_started, None)
    # section 9.3 PROXY RULE + C5 IP ROTATION: a configured pool is gated
    # entry-by-entry (fail-fast, credentials masked) and rotated per module;
    # no pool -> the legacy single-proxy law, byte for byte.
    pool_ok, proxy_reason, assigner = gate_pool_or_legacy(params)
    if not pool_ok:
        print(f"PROXY RULE fail-fast (section 9.3): {proxy_reason}")
        return _finalize_crash(params, target_dir, target, RuntimeError(proxy_reason))
    if proxy_reason != "proxy unset -- direct connection (section 9.3)":
        print(f"proxy: {proxy_reason}")
    if runner is None:
        from pipeline.local_images import ensure_local_tool_images

        ensure_local_tool_images(params)
    if assigner is not None:
        # C5 v2 health telemetry: seed per-IP outcomes from THIS target's
        # previous runs (masked keys only; corrupt state ignored -- never-fail).
        assigner.load_health(target_dir)
    alerts: list[tuple[str, str, str]] = []

    # section 12 opt-in supervisor: lazily created ONLY when enabled (section 12.1/section 12.4 --
    # event-driven, zero cost and zero LLM calls on healthy runs).
    agent_holder: dict[str, Any] = {}

    def _on_anomaly(status: str, module: str, reason: str) -> None:
        alerts.append((status, module, reason))
        send_status(params, status, module, reason)

    breaker = CircuitBreaker(
        params,
        clock=clock,
        notify=_on_anomaly,
        target_dir=target_dir,
        target=target,
    )
    # Operator starting/resuming a run means "continue". Never leave them
    # stuck behind a persisted limiter pause (RESET LIMITER is automatic).
    released = breaker.reset_paused(reason="run start")
    if released:
        print(f"breaker: auto-reset at run start {released}")
    ceiling = ResourceCeiling(params)
    adapter = Adapter(params, target_dir, breaker, ceiling, clock=clock, runner=runner,
                      aggressive=aggressive, proxy_pool=assigner)
    extra = {"target_domain": target}
    partial: list[str] = []
    failed = False

    # C7 SELFTUNE (operator roadmap): persisted branch-budget multipliers for
    # THIS target scale the committed base budgets at start (bounded, never
    # below base after decay-to-1.0 law); the end-of-run hook updates them.
    passive_budget, active_budget, tune_note = _tuned_budgets(params, target_dir)
    if tune_note:
        print(f"selftune: {tune_note}")

    passive_names = _filter_paused(
        params, target_dir, breaker, _branch_tools(params, "passive_branch_tools")
    )
    active_names = _filter_paused(
        params, target_dir, breaker, _branch_tools(params, "active_branch_tools")
    )
    planned = max(1, len(passive_names) + (1 if active_names else 0))
    limits = ceiling.plan(planned)
    passive_workers = max(1, limits.concurrency - (1 if active_names else 0)) if planned > 1 else max(1, len(passive_names) or 1)

    passive_docs: list[dict[str, Any]] = []
    active_docs: list[dict[str, Any]] = []

    def passive_branch() -> list[dict[str, Any]]:
        docs: list[dict[str, Any]] = _run_passive_modules(
            params,
            gate,
            adapter,
            target_dir,
            target,
            extra,
            passive_budget,
            clock,
            planned,
            partial,
        )
        if not passive_names:
            msg = "passive branch: no generic passive tools registered (B3 PSV chain handles the branch) -- skipped, not an error"
            _append_note(params, target_dir, "passive", msg)
            print(msg)
            return docs
        docs.extend(
            _run_parallel(
                params,
                adapter,
                target_dir,
                passive_names,
                extra,
                passive_budget,
                clock,
                max(1, min(len(passive_names), passive_workers) or 1),
                planned,
                partial,
                "passive",
            )
        )
        return docs

    def active_branch() -> list[dict[str, Any]]:
        docs: list[dict[str, Any]] = []
        if not _echo_fixture_mode(params):
            docs = _run_active_modules(
                params,
                gate,
                adapter,
                target_dir,
                target,
                extra,
                active_budget,
                clock,
                planned,
                partial,
            )
        tool_docs = _run_sequential(
            params,
            adapter,
            target_dir,
            active_names,
            extra,
            active_budget,
            clock,
            planned,
            partial,
            "active",
        )
        return docs + tool_docs

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            fut_p = pool.submit(_guard, passive_branch, partial, "passive")
            fut_a = pool.submit(_guard, active_branch, partial, "active")
            p_docs = fut_p.result()
            a_docs = fut_a.result()
            if isinstance(p_docs, list):
                passive_docs = p_docs
            else:
                failed = True
            if isinstance(a_docs, list):
                active_docs = a_docs
            else:
                failed = True
    except OperatorStop:
        print("stop: operator stop -- skipping remaining modules")

    if state_engine.operator_stopped(params, target_dir, target):
        return _finalize_stopped(params, gate, target_dir, target, clock, run_started, assigner)

    merge_name = str(params.require("merge_module"))
    st = state_engine.load_state(params, target_dir, target)
    if not state_engine.skip_done(st, merge_name):
        if state_engine.operator_stopped(params, target_dir, target):
            return _finalize_stopped(params, gate, target_dir, target, clock, run_started, assigner)
        state_engine.set_status(params, target_dir, merge_name, "running")
        try:
            merge_branches(params, gate, target_dir, target, passive_docs, active_docs)
            state_engine.set_status(params, target_dir, merge_name, "done")
            # MERGE is the canonical-assets milestone: always refresh the live view.
            _ingest_live(params, target_dir, target, force=True)
        except Exception as exc:
            failed = True
            partial.append(f"merge:{exc}")
            _append_log(params, target_dir, merge_name, merge_name, 1, str(exc))
            state_engine.set_status(params, target_dir, merge_name, "failed")

    # B4 PORT-SWEEP (spec section 8, order-4): post-MERGE stage consuming assets.json.
    # Not a branch member -- it runs strictly after MERGE and before the run
    # status is classified, so its partial markers (window breach / canary
    # pause) shape the final status like every other stage.
    sweep_name = str(params.require("portsweep_module"))
    if sweep_name in RUNNERS:
        if state_engine.operator_stopped(params, target_dir, target):
            return _finalize_stopped(params, gate, target_dir, target, clock, run_started, assigner)
        st = state_engine.load_state(params, target_dir, target)
        if state_engine.skip_done(st, sweep_name):
            print(f"skip: module={sweep_name} reason=already done (resume)")
        else:
            _release_breaker(adapter.breaker, sweep_name)
            # fall through to run — do not skip a stage because the limiter tripped.
            state_engine.set_status(params, target_dir, sweep_name, "running")
            try:
                RUNNERS[sweep_name](
                    params, gate, adapter, target_dir, target, extra, planned, None, partial
                )
                state_engine.set_status(params, target_dir, sweep_name, "done")
                # PORT-SWEEP is the ports milestone: always refresh the live view.
                _ingest_live(params, target_dir, target, force=True)
            except Exception as exc:
                state_engine.set_status(params, target_dir, sweep_name, "failed")
                partial.append(f"portsweep:{exc}")
                _append_log(params, target_dir, sweep_name, sweep_name, 1, str(exc))
                _engage_agent(params, target_dir, sweep_name, "active", str(exc), holder=agent_holder)
                traceback.print_exc()

    # FFUF-4: vhost enum on HTTP-like ports found by PORT-SWEEP (ip:port + Host).
    # After the sweep, before OWASP-PASSIVE. Not a branch member.
    ffuf4_name = str(params.require("ffuf4_module"))
    if ffuf4_name in RUNNERS:
        if state_engine.operator_stopped(params, target_dir, target):
            return _finalize_stopped(params, gate, target_dir, target, clock, run_started, assigner)
        st = state_engine.load_state(params, target_dir, target)
        if state_engine.skip_done(st, ffuf4_name):
            print(f"skip: module={ffuf4_name} reason=already done (resume)")
        else:
            _release_breaker(adapter.breaker, ffuf4_name)
            state_engine.set_status(params, target_dir, ffuf4_name, "running")
            try:
                RUNNERS[ffuf4_name](
                    params, gate, adapter, target_dir, target, extra, planned, None, partial
                )
                try:
                    nested = expand_nested_after_vhosts(
                        params, gate, adapter, target_dir, target, extra, planned, None, partial
                    )
                    if nested:
                        append_active_doc(params, gate, target_dir, target, nested)
                except Exception as exc:  # noqa: BLE001
                    partial.append(f"nested-dns-ffuf4:{exc}")
                    _append_log(params, target_dir, "dns-resolve", "dns-resolve", 0, f"nested-after-ffuf4: {exc}")
                state_engine.set_status(params, target_dir, ffuf4_name, "done")
                _ingest_live(params, target_dir, target)
            except Exception as exc:
                state_engine.set_status(params, target_dir, ffuf4_name, "failed")
                partial.append(f"ffuf4:{exc}")
                _append_log(params, target_dir, ffuf4_name, ffuf4_name, 1, str(exc))
                _engage_agent(params, target_dir, ffuf4_name, "post-merge", str(exc), holder=agent_holder)
                traceback.print_exc()

    # C6 OWASP-PASSIVE (operator roadmap): post-MERGE zero-packet artifact
    # analyzer, mirroring the PORT-SWEEP hook law exactly -- resume-aware,
    # breaker-aware, partial markers shape the final verdict like any stage.
    owasp_name = str(params.require("owasp_module"))
    if owasp_name in RUNNERS:
        if state_engine.operator_stopped(params, target_dir, target):
            return _finalize_stopped(params, gate, target_dir, target, clock, run_started, assigner)
        st = state_engine.load_state(params, target_dir, target)
        if state_engine.skip_done(st, owasp_name):
            print(f"skip: module={owasp_name} reason=already done (resume)")
        else:
            _release_breaker(adapter.breaker, owasp_name)
            state_engine.set_status(params, target_dir, owasp_name, "running")
            try:
                RUNNERS[owasp_name](
                    params, gate, adapter, target_dir, target, extra, planned, None, partial
                )
                state_engine.set_status(params, target_dir, owasp_name, "done")
                _ingest_live(params, target_dir, target)
            except Exception as exc:
                state_engine.set_status(params, target_dir, owasp_name, "failed")
                partial.append(f"owasp:{exc}")
                _append_log(params, target_dir, owasp_name, owasp_name, 1, str(exc))
                _engage_agent(params, target_dir, owasp_name, "post-merge", str(exc), holder=agent_holder)
                traceback.print_exc()

    # C5 IP rotation ledger: every module's pool assignment is always visible
    # (never-fail, credentials masked) -- honesty law for the rotation feature.
    if assigner is not None:
        try:
            assigner.write_ledger(target_dir)
            assigner.write_health(target_dir)
            for line in assigner.pool.summary_lines():
                print(line)
            for line in assigner.pool.health_lines():
                print(line)
        except Exception as exc:  # noqa: BLE001 -- rotation ledger never flips the run
            print(f"rotation ledger: disclosed write failure: {exc}")

    if state_engine.operator_stopped(params, target_dir, target):
        return _finalize_stopped(params, gate, target_dir, target, clock, run_started, assigner)

    stamp = utc_stamp()
    st_now = state_engine.load_state(params, target_dir, target)
    live_stamp = str((st_now.get("run") or {}).get("live_stamp") or "").strip()
    if live_stamp:
        stamp = live_stamp
    counts = _counts(params, target_dir, passive_docs, active_docs)
    status, reason, failing_module = _classify_status(params, breaker, alerts, partial, failed, passive_docs, active_docs)
    if state_engine.operator_stopped(params, target_dir, target):
        return _finalize_stopped(params, gate, target_dir, target, clock, run_started, assigner)
    state_engine.set_run_status(params, target_dir, target, status, reason=reason, failing_module=failing_module)
    if state_engine.operator_stopped(params, target_dir, target):
        return _finalize_stopped(params, gate, target_dir, target, clock, run_started, assigner)
    try:
        ingest_if_completed(params, gate, target_dir, target, status)
        snapshot(params, target_dir, stamp)
        prev = previous_timestamp(params, target_dir, stamp)
        append_run(params, target_dir, stamp, status, counts)
        write_diff(params, target_dir, prev, stamp)
    except Exception as exc:  # noqa: BLE001 -- history is derived; never leave status unset
        print(f"history: disclosed failure (run verdict kept): {exc}")
    try:
        from pipeline.warehouse import ingest_run_end

        warehouse_ledger = ingest_run_end(params, target_dir, target, stamp, status, counts)
    except Exception as exc:  # noqa: BLE001 -- warehouse is derived; never flip the run verdict
        warehouse_ledger = {"ok": False, "reason": f"disclosed ingest failure: {exc}"}
    print(
        "warehouse: "
        f"ok={warehouse_ledger.get('ok')} "
        f"target={target} "
        f"facts={warehouse_ledger.get('facts')} "
        f"isolated={warehouse_ledger.get('isolated', False)}"
    )
    notify_ledger = run_end_notifications(
        params,
        target_dir,
        target,
        status,
        reason,
        failing_module,
        counts,
        clock.time() - run_started,
    )
    print(
        "notify: "
        f"summary={notify_ledger.get('summary_sent')} "
        f"status_alert={notify_ledger.get('status_alert_sent')} "
        f"alerts={notify_ledger.get('alerts')}"
    )
    report_ledger: dict[str, Any] = {"generated": False}
    # section 10.1 "generated on run end": EVERY terminal status gets its report --
    # REM24 (run #36 evidence): an anomaly-terminated run still owns canonical
    # data.json files and the operator needs the report most when it degraded.
    terminal = {
        str(params.require("run_status_completed")), str(params.require("run_status_partial")),
        str(params.require("run_status_failed")), str(params.require("run_status_anomaly")),
        str(params.require("run_status_stopped")),
    }
    if status in terminal:
        try:
            report_ledger = generate_all(params, target_dir, stamp)
            report_ledger["generated"] = True
        except Exception as exc:  # noqa: BLE001 -- reporting must never flip a verdict
            report_ledger = {"generated": False, "error": str(exc)}
    print(f"report: generated={report_ledger.get('generated')} dir={target_dir / params.require('report_dirname')} counts={report_ledger.get('counts')}")
    # Storage hygiene (user directive 2026-09-06): run-end housekeeping --
    # history retention + size-capped log rotation + total cap. Never-fail
    # exactly like reporting: a storage error must never flip a verdict.
    storage_ledger: dict[str, Any] = {"applied": False}
    try:
        from pipeline.logstore import housekeep

        storage_ledger = housekeep(params, target_dir)
    except Exception as exc:  # noqa: BLE001
        storage_ledger = {"applied": False, "error": str(exc)}
    print(
        f"storage: applied={storage_ledger.get('applied')} "
        f"freed_bytes={storage_ledger.get('freed_bytes', 0)} "
        f"rotated={len(storage_ledger.get('rotated', []))} "
        f"pruned_runs={len(storage_ledger.get('pruned_runs', []))} "
        f"capped={storage_ledger.get('capped', False)}"
    )
    # C2 (release directive): run-end platform-learning -- in-scope discovered
    # hosts feed the selectable platform-learned wordlist. Append-only,
    # deduplicated, never-fail exactly like reporting/storage above.
    learned_ledger: dict[str, Any] = {"added": 0, "total": 0}
    try:
        from pipeline.custom_lists import ingest_learned_labels

        learned_ledger = ingest_learned_labels(params, target_dir, target, gate=gate)
    except Exception as exc:  # noqa: BLE001 -- learning must never flip a verdict
        learned_ledger = {"added": 0, "total": 0, "error": str(exc)}
    print(
        f"learned: target={target} added={learned_ledger.get('added')} "
        f"total={learned_ledger.get('total')} always_on=platform_learned"
    )
    # C7 SELFTUNE end-of-run hook: observe this run's budget markers, update
    # the NEXT run's multipliers (never-fail exactly like reporting/storage).
    try:
        from pipeline.selftune import update_tuning

        tune_ledger = update_tuning(params, target_dir, target, partial, stamp)
    except Exception as exc:  # noqa: BLE001 -- tuning must never flip a verdict
        tune_ledger = {"updated": False, "reason": f"error (disclosed): {exc}"}
    print(
        f"selftune: updated={tune_ledger.get('updated')} "
        f"passive={tune_ledger.get('passive')} active={tune_ledger.get('active')} "
        f"reason={tune_ledger.get('reason')}"
    )
    code = _exit_code(params, status)
    print(f"run {status}: {target_dir}")
    print(f"history: {target_dir / params.require('history_dirname') / stamp}")
    print(f"diff: {target_dir / params.require('diff_filename')}")
    if alerts:
        print(f"anomaly: {alerts[-1]}")
    return code


def run_module(
    params: Params,
    gate: ScopeGate,
    tool_name: str,
    target: str,
    aggressive: bool = False,
    runner: Any | None = None,
) -> int:
    target_dir = ensure_layout(params, target)
    breaker = CircuitBreaker(params, target_dir=target_dir, target=target)
    _release_breaker(breaker, tool_name)
    ceiling = ResourceCeiling(params)
    adapter = Adapter(params, target_dir, breaker, ceiling, runner=runner, aggressive=aggressive)
    extra = {"target_domain": target}
    if tool_name in RUNNERS:
        partial: list[str] = []
        state_engine.set_status(params, target_dir, tool_name, "running")
        try:
            doc = RUNNERS[tool_name](
                params,
                gate,
                adapter,
                target_dir,
                target,
                extra,
                1,
                None,
                partial,
            )
        except EmptyWordlistError as exc:
            state_engine.set_status(params, target_dir, tool_name, "failed")
            print(f"fail-fast: {exc}")
            return 1
        except Exception as exc:
            state_engine.set_status(params, target_dir, tool_name, "failed")
            _append_log(params, target_dir, tool_name, tool_name, 1, str(exc))
            _engage_agent(params, target_dir, tool_name, "active", str(exc))
            print(f"module {tool_name} failed: {exc}")
            return 1
        state_engine.set_status(params, target_dir, tool_name, "done")
        print(f"module {tool_name} data={target_dir} partial={partial}")
        if doc:
            merge_branches(params, gate, target_dir, target, [], [doc])
        if breaker.any_paused():
            return _exit_code(params, str(params.require("run_status_anomaly")))
        return 0
    spec = adapter.spec(tool_name)
    module = str(spec.get("branch") or tool_name)
    result = adapter.invoke(tool_name, module=module, extra=extra, planned_concurrency=1)
    print(f"module {tool_name} exit={result.exit_code} fallback={result.used_fallback} data={result.data_json}")
    if result.exit_code == 0 and result.data_json:
        kind = str(spec.get("data_kind") or "passive")
        docs = [read_json(result.data_json)]
        merge_branches(
            params,
            gate,
            target_dir,
            target,
            docs if kind == "passive" else [],
            docs if kind == "active" else [],
        )
    if breaker.any_paused():
        return _exit_code(params, str(params.require("run_status_anomaly")))
    return 0 if result.exit_code == 0 else 1


def stop_target(params: Params, target_dir: Path) -> list[str]:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from pipeline.dockerbin import docker_prefix
    import subprocess

    target = target_dir.name
    target_dir.mkdir(parents=True, exist_ok=True)
    # Persist STOP even when state.json is missing so a late engine start
    # cannot clobber the request, and a live engine refuses the next module.
    state_engine.set_run_status(
        params,
        target_dir,
        target,
        str(params.require("run_status_stopped")),
        reason="operator stop",
        failing_module=None,
    )
    state_engine.fail_running_modules(params, target_dir, target)

    # Kill the pipeline process FIRST so it cannot spawn more tool containers
    # while we tear down Docker. UI must feel instant.
    recorded = state_engine.read_run_pid(target_dir)
    killed = _kill_run_processes(target, recorded)
    state_engine.clear_run_pid(target_dir)

    prefix = docker_prefix(params)
    label = str(params.require("docker_label_target"))
    ids: list[str] = []
    try:
        listed = subprocess.run(
            [*prefix, "ps", "-q", "--filter", f"label={label}={target}"],
            capture_output=True,
            text=True,
            check=False,
        )
        ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    except OSError as exc:
        print(f"stop: docker list failed (status already stopped): {exc}")

    def _kill_one(cid: str) -> None:
        # kill = immediate SIGKILL in the container runtime (no graceful wait).
        try:
            subprocess.run([*prefix, "kill", cid], capture_output=True, text=True, check=False)
            subprocess.run([*prefix, "rm", "-f", cid], capture_output=True, text=True, check=False)
        except OSError:
            return

    if ids:
        workers = min(16, len(ids))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_kill_one, cid) for cid in ids]
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception:  # noqa: BLE001 -- never fail STOP
                    pass

    print(f"stop: killed_pids={killed} containers={len(ids)}")
    return ids


def _kill_run_processes(target: str, recorded: int | None) -> list[int]:
    pids = []
    if recorded and recorded != os.getpid():
        pids.append(recorded)
    for pid in _pids_for_cli_run(target):
        if pid not in pids and pid != os.getpid():
            pids.append(pid)
    killed: list[int] = []
    for pid in pids:
        if _terminate_pid(pid):
            killed.append(pid)
    return killed


def _pids_for_cli_run(target: str) -> list[int]:
    found: list[int] = []
    proc = Path("/proc")
    if not proc.is_dir():
        return found
    needles = (
        f"pipeline.cli run {target}".encode(),
        f"pipeline.cli resume {target}".encode(),
        f"pipeline.cli restart {target}".encode(),
        f"recon.sh run {target}".encode(),
        f"recon.sh resume {target}".encode(),
        f"recon.sh restart {target}".encode(),
    )
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmd = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        flat = cmd.replace(b"\x00", b" ")
        if any(n in flat for n in needles):
            found.append(int(entry.name))
    return found


def _terminate_pid(pid: int) -> bool:
    if pid <= 1 or pid == os.getpid():
        return False

    def _signal(sig: int) -> bool:
        try:
            os.killpg(pid, sig)
            return True
        except ProcessLookupError:
            return False
        except (PermissionError, OSError):
            try:
                os.kill(pid, sig)
                return True
            except ProcessLookupError:
                return False
            except (PermissionError, OSError):
                return False

    if not _signal(signal.SIGTERM):
        return False
    deadline = time.time() + 0.35
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return True
        time.sleep(0.03)
    _signal(signal.SIGKILL)
    return True


def _finalize_crash(params: Params, target_dir: Path, target: str, exc: BaseException) -> int:
    """Mark the run failed and drop the PID. Used when the ladder throws."""
    try:
        if state_engine.operator_stopped(params, target_dir, target):
            state_engine.clear_run_pid(target_dir)
            return _exit_code(params, str(params.require("run_status_stopped")))
    except Exception as inner:  # noqa: BLE001
        print(f"crash finalize: stop check failed: {inner}")
    status = str(params.require("run_status_failed"))
    reason = f"engine crash (disclosed): {type(exc).__name__}: {exc}"
    print(reason)
    try:
        state_engine.fail_running_modules(params, target_dir, target)
    except Exception as inner:  # noqa: BLE001
        print(f"crash finalize: fail_running_modules: {inner}")
    try:
        state_engine.set_run_status(
            params,
            target_dir,
            target,
            status,
            reason=reason[:500],
            failing_module=None,
        )
    except Exception as inner:  # noqa: BLE001
        print(f"crash finalize: set_run_status: {inner}")
    try:
        state_engine.clear_run_pid(target_dir)
    except Exception as inner:  # noqa: BLE001
        print(f"crash finalize: clear_run_pid: {inner}")
    try:
        return _exit_code(params, status)
    except Exception:
        return 1


def _finalize_stopped(
    params: Params,
    gate: ScopeGate,
    target_dir: Path,
    target: str,
    clock: Clock,
    run_started: float,
    assigner: Any,
) -> int:
    state_engine.fail_running_modules(params, target_dir, target)
    status = str(params.require("run_status_stopped"))
    state_engine.set_run_status(params, target_dir, target, status, reason="operator stop", failing_module=None)
    state_engine.clear_run_pid(target_dir)
    stamp = utc_stamp()
    counts = _counts(params, target_dir, [], [])
    if assigner is not None:
        try:
            assigner.write_ledger(target_dir)
            assigner.write_health(target_dir)
        except Exception:  # noqa: BLE001
            pass
    try:
        ingest_if_completed(params, gate, target_dir, target, status)
        snapshot(params, target_dir, stamp)
        prev = previous_timestamp(params, target_dir, stamp)
        append_run(params, target_dir, stamp, status, counts)
        write_diff(params, target_dir, prev, stamp)
    except Exception as exc:  # noqa: BLE001 -- STOP still returns stopped even if history fails
        print(f"history: disclosed failure on stop (status kept): {exc}")
    try:
        from pipeline.warehouse import ingest_run_end

        ingest_run_end(params, target_dir, target, stamp, status, counts)
    except Exception as exc:  # noqa: BLE001
        print(f"warehouse: ok=False reason=disclosed ingest failure: {exc}")
    run_end_notifications(params, target_dir, target, status, "operator stop", None, counts, clock.time() - run_started)
    print(f"run {status}: {target_dir}")
    return _exit_code(params, status)


def _classify_status(
    params: Params,
    breaker: CircuitBreaker,
    alerts: list[tuple[str, str, str]],
    partial: list[str],
    failed: bool,
    passive_docs: list[dict[str, Any]],
    active_docs: list[dict[str, Any]],
) -> tuple[str, str | None, str | None]:
    if alerts or breaker.any_paused():
        if alerts:
            _status, module, reason = alerts[-1]
            return str(params.require("run_status_anomaly")), reason, module
        names = breaker.paused_module_names()
        module = names[0] if names else None
        reason = breaker.pause_reason(module) if module else "circuit breaker paused"
        return str(params.require("run_status_anomaly")), reason, module
    if failed and not (passive_docs or active_docs):
        return str(params.require("run_status_failed")), "no branch produced assets", None
    if partial or failed:
        return str(params.require("run_status_partial")), "; ".join(partial) if partial else "branch failure", None
    return str(params.require("run_status_completed")), None, None


def _exit_code(params: Params, status: str) -> int:
    mapping = {
        str(params.require("run_status_completed")): int(params.require("exit_code_completed")),
        str(params.require("run_status_failed")): int(params.require("exit_code_failed")),
        str(params.require("run_status_anomaly")): int(params.require("exit_code_anomaly")),
        str(params.require("run_status_partial")): int(params.require("exit_code_partial")),
        str(params.require("run_status_stopped")): int(params.require("exit_code_stopped")),
    }
    return mapping.get(status, 1)


def _filter_paused(
    params: Params,
    target_dir: Path,
    breaker: CircuitBreaker,
    names: list[str],
) -> list[str]:
    # Limiter pauses are auto-cleared at module boundaries so the branch
    # continues. The operator is never asked to click RESET LIMITER.
    for name in names:
        _release_breaker(breaker, name)
    return list(names)


def _branch_tools(params: Params, key: str) -> list[str]:
    names = params.require(key)
    if not isinstance(names, list):
        return []
    tools = params.tools
    out: list[str] = []
    for name in names:
        spec = tools.get(str(name)) or {}
        if isinstance(spec, dict) and spec.get("enabled", True):
            out.append(str(name))
    return out


def _run_passive_modules(
    params: Params,
    gate: ScopeGate,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    budget: float,
    clock: Clock,
    planned: int,
    partial: list[str],
) -> list[dict[str, Any]]:
    """PASSIVE branch module runner (B3): mirrors _run_active_modules for the
    passive side. Order law lives INSIDE the passive-recon orchestrator
    (PSV-0 first ... PSV-6 last)."""
    names = params.require("passive_branch_modules")
    if not isinstance(names, list):
        return []
    deadline = clock.time() + budget
    docs: list[dict[str, Any]] = []
    st = state_engine.load_state(params, target_dir, target)
    data_keys = {
        "passive-recon": "passive_data_json",
    }
    for name in names:
        name = str(name)
        if name not in RUNNERS:
            continue
        if state_engine.operator_stopped(params, target_dir, target):
            raise OperatorStop("operator stop")
        if state_engine.skip_done(st, name):
            key = data_keys.get(name)
            if key:
                doc = load_tool_doc(target_dir / str(params.require(key)))
                if doc:
                    docs.append(doc)
            continue
        _release_breaker(adapter.breaker, name)
        left = deadline - clock.time()
        if left <= 0:
            partial.append("passive_budget")
            break
        state_engine.set_status(params, target_dir, name, "running")
        try:
            doc = RUNNERS[name](
                params,
                gate,
                adapter,
                target_dir,
                target,
                extra,
                planned,
                left,
                partial,
            )
            if doc:
                docs.append(doc)
            if state_engine.operator_stopped(params, target_dir, target):
                state_engine.set_status(params, target_dir, name, "failed")
                raise OperatorStop("operator stop")
            state_engine.set_status(params, target_dir, name, "done")
            st = state_engine.load_state(params, target_dir, target)
            _ingest_live(params, target_dir, target)
        except OperatorStop:
            raise
        except Exception as exc:
            state_engine.set_status(params, target_dir, name, "failed")
            _append_log(params, target_dir, name, name, 1, str(exc))
            partial.append(f"passive:{name}:{exc}")
            _engage_agent(params, target_dir, name, "passive", str(exc))
            traceback.print_exc()
            continue
    return docs


def _run_active_modules(
    params: Params,
    gate: ScopeGate,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    budget: float,
    clock: Clock,
    planned: int,
    partial: list[str],
) -> list[dict[str, Any]]:
    names = params.require("active_branch_modules")
    if not isinstance(names, list):
        return []
    # Post-merge-only stages must never sit in the ACTIVE branch (SETUP UI
    # used to offer ffuf-4 here; that ran too early with empty port data).
    banned = {"ffuf-4", "port-sweep", "owasp-passive", "merge", "passive-recon"}
    cleaned: list[str] = []
    for raw in names:
        name = str(raw)
        if name in banned:
            print(f"skip: module={name} reason=not an active-branch member (post-merge or other branch)")
            continue
        cleaned.append(name)
    names = cleaned
    deadline = clock.time() + budget
    docs: list[dict[str, Any]] = []
    st = state_engine.load_state(params, target_dir, target)
    data_keys = {
        "ffuf": "ffuf_data_json",
        "dns-resolve": "dnsr_data_json",
        "ffuf-3": "ffuf3_data_json",
        "port-check": "portcheck_data_json",
    }

    def _one(name: str) -> dict[str, Any] | None:
        nonlocal st
        if name not in RUNNERS:
            return None
        if state_engine.operator_stopped(params, target_dir, target):
            raise OperatorStop("operator stop")
        if state_engine.skip_done(st, name):
            key = data_keys.get(name)
            if key:
                return load_tool_doc(target_dir / str(params.require(key)))
            return None
        _release_breaker(adapter.breaker, name)
        left = deadline - clock.time()
        if left <= 0:
            partial.append("active_budget")
            return None
        state_engine.set_status(params, target_dir, name, "running")
        try:
            doc = RUNNERS[name](
                params,
                gate,
                adapter,
                target_dir,
                target,
                extra,
                planned,
                left,
                partial,
            )
            if name == "ffuf":
                try:
                    nested = expand_nested_after_vhosts(
                        params, gate, adapter, target_dir, target, extra, planned, left, partial
                    )
                    if nested:
                        docs[:] = [d for d in docs if d.get("module") != "dns-resolve"]
                        docs.append(nested)
                except Exception as exc:  # noqa: BLE001 -- nested DNS never fails the vhost pass
                    partial.append(f"nested-dns:{exc}")
                    _append_log(params, target_dir, "dns-resolve", "dns-resolve", 0, f"nested-after-vhost: {exc}")
            if state_engine.operator_stopped(params, target_dir, target):
                state_engine.set_status(params, target_dir, name, "failed")
                raise OperatorStop("operator stop")
            state_engine.set_status(params, target_dir, name, "done")
            st = state_engine.load_state(params, target_dir, target)
            _ingest_live(params, target_dir, target)
            return doc if isinstance(doc, dict) else None
        except OperatorStop:
            raise
        except EmptyWordlistError as exc:
            state_engine.set_status(params, target_dir, name, "failed")
            partial.append(f"empty_wordlist:{exc}")
            print(f"fail-fast: {exc}")
            raise
        except Exception as exc:
            state_engine.set_status(params, target_dir, name, "failed")
            _append_log(params, target_dir, name, name, 1, str(exc))
            partial.append(f"active:{name}:{exc}")
            _engage_agent(params, target_dir, name, "active", str(exc))
            traceback.print_exc()
            return None

    # dns-resolve first (feeds vhost + early ports). Then port-check runs
    # beside ffuf/ffuf-3 so the PORTS panel fills without waiting for vhost.
    before: list[str] = []
    after: list[str] = []
    seen_dns = False
    for name in names:
        if not seen_dns:
            before.append(name)
            if name == "dns-resolve":
                seen_dns = True
        else:
            after.append(name)

    try:
        for name in before:
            doc = _one(name)
            if doc:
                docs.append(doc)

        port_names = [n for n in after if n == "port-check"]
        vhost_names = [n for n in after if n != "port-check"]
        if port_names and vhost_names:
            print("active: port-check || ffuf/ffuf-3 (early PORTS)")
            with ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(_one, port_names[0])
                try:
                    for name in vhost_names:
                        doc = _one(name)
                        if doc:
                            docs.append(doc)
                finally:
                    port_doc = fut.result()
                    if port_doc:
                        docs.append(port_doc)
        else:
            for name in after:
                doc = _one(name)
                if doc:
                    docs.append(doc)
    except EmptyWordlistError:
        return docs
    return docs


def _run_parallel(
    params: Params,
    adapter: Adapter,
    target_dir: Path,
    names: list[str],
    extra: dict[str, Any],
    budget: float,
    clock: Clock,
    workers: int,
    planned: int,
    partial: list[str],
    branch: str,
) -> list[dict[str, Any]]:
    deadline = clock.time() + budget
    docs: list[dict[str, Any]] = []
    if not names:
        return docs
    remaining = list(names)
    workers = max(1, workers)

    def one(name: str) -> InvokeResult | None:
        if state_engine.operator_stopped(params, target_dir, target_dir.name):
            raise OperatorStop("operator stop")
        left = deadline - clock.time()
        if left <= 0:
            return None
        return adapter.invoke(name, module=name, extra=extra, planned_concurrency=planned, timeout_sec=left)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(one, name): name for name in remaining}
        for fut in as_completed(futs):
            name = futs[fut]
            if state_engine.operator_stopped(params, target_dir, target_dir.name):
                raise OperatorStop("operator stop")
            if clock.time() >= deadline:
                partial.append(f"{branch}_budget")
                break
            try:
                result = fut.result()
            except OperatorStop:
                raise
            except Exception as exc:
                _append_log(params, target_dir, branch, name, 1, str(exc))
                partial.append(f"{branch}:{name}:{exc}")
                continue
            if result is None:
                partial.append(f"{branch}_budget")
                continue
            if result.data_json:
                doc = load_tool_doc(result.data_json)
                if doc:
                    docs.append(doc)
            elif result.exit_code != 0:
                _append_log(params, target_dir, branch, name, result.exit_code, result.stderr)
    if clock.time() >= deadline and f"{branch}_budget" not in partial:
        partial.append(f"{branch}_budget")
    return docs


def _run_sequential(
    params: Params,
    adapter: Adapter,
    target_dir: Path,
    names: list[str],
    extra: dict[str, Any],
    budget: float,
    clock: Clock,
    planned: int,
    partial: list[str],
    branch: str,
) -> list[dict[str, Any]]:
    deadline = clock.time() + budget
    docs: list[dict[str, Any]] = []
    for name in names:
        if state_engine.operator_stopped(params, target_dir, target_dir.name):
            raise OperatorStop("operator stop")
        left = deadline - clock.time()
        if left <= 0:
            partial.append(f"{branch}_budget")
            break
        try:
            result = adapter.invoke(name, module=name, extra=extra, planned_concurrency=planned, timeout_sec=left)
        except Exception as exc:
            _append_log(params, target_dir, branch, name, 1, str(exc))
            partial.append(f"{branch}:{name}:{exc}")
            continue
        if result.data_json:
            doc = load_tool_doc(result.data_json)
            if doc:
                docs.append(doc)
        elif result.exit_code != 0:
            _append_log(params, target_dir, branch, name, result.exit_code, result.stderr)
    return docs


def _guard(fn, partial: list[str], branch: str):
    try:
        return fn()
    except OperatorStop:
        raise
    except Exception as exc:
        partial.append(f"{branch}_crash:{exc}")
        traceback.print_exc()
        return exc


def _echo_fixture_mode(params: Params) -> bool:
    names = params.require("active_branch_tools")
    if not isinstance(names, list) or "echo-tool-active" not in [str(item) for item in names]:
        return False
    spec = params.tools.get("echo-tool-active") or {}
    return bool(isinstance(spec, dict) and spec.get("enabled", True))


def _append_log(params: Params, target_dir: Path, module: str, tool: str, code: int, detail: str) -> None:
    try:
        if state_engine.operator_stopped(params, target_dir, target_dir.name):
            return
        path = target_dir / str(params.require("run_log"))
        path.parent.mkdir(parents=True, exist_ok=True)
        tail_n = int(params.require("stderr_tail_lines"))
        tail = " | ".join(detail.splitlines()[-tail_n:])
        from datetime import datetime, timezone

        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp}\t{module}\t{tool}\t{code}\tfail\t{tail}\n")
    except Exception as exc:  # noqa: BLE001 -- log write never fails a module
        print(f"run.log write failed (disclosed): {exc}")


def _append_note(params: Params, target_dir: Path, module: str, detail: str) -> None:
    try:
        if state_engine.operator_stopped(params, target_dir, target_dir.name):
            return
        path = target_dir / str(params.require("run_log"))
        path.parent.mkdir(parents=True, exist_ok=True)
        from datetime import datetime, timezone

        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp}\t{module}\t-\t0\tok\t{detail}\n")
    except Exception as exc:  # noqa: BLE001 -- notes never fail a branch
        print(f"run.log note failed (disclosed): {exc}")


def _counts(
    params: Params,
    target_dir: Path,
    passive_docs: list[dict[str, Any]],
    active_docs: list[dict[str, Any]],
) -> dict[str, int]:
    counts = {
        "passive_docs": len(passive_docs),
        "active_docs": len(active_docs),
    }
    assets_path = target_dir / str(params.require("assets_relpath"))
    if assets_path.is_file():
        try:
            doc = read_json(assets_path)
            counts["assets"] = len(doc.get("assets") or [])
            counts["quarantine"] = len(doc.get("quarantine") or [])
        except Exception as exc:  # noqa: BLE001 -- counts are informational
            print(f"counts: disclosed assets read failure: {exc}")
    return counts
