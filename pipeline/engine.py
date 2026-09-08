"""WIDE pipeline engine: PASSIVE || ACTIVE, branch budgets, MERGE, history (section 7)."""

from __future__ import annotations

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
from pipeline.merge import load_tool_doc, merge_branches
from pipeline.modules import RUNNERS
from pipeline.notify import run_end_notifications, send_status
from pipeline.ip_rotation import gate_pool_or_legacy
from pipeline.params import Params
from pipeline.reporting import generate_all
from pipeline.scope import ScopeGate
from pipeline.wordlist_forge import EmptyWordlistError, ingest_if_completed
from pipeline import state as state_engine


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
    target_dir = ensure_layout(params, target)
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
    )
    clock = clock or Clock()
    run_started = clock.time()
    # section 9.3 PROXY RULE + C5 IP ROTATION: a configured pool is gated
    # entry-by-entry (fail-fast, credentials masked) and rotated per module;
    # no pool -> the legacy single-proxy law, byte for byte.
    pool_ok, proxy_reason, assigner = gate_pool_or_legacy(params)
    if not pool_ok:
        print(f"PROXY RULE fail-fast (section 9.3): {proxy_reason}")
        return _exit_code(params, str(params.require("run_status_failed")))
    if proxy_reason != "proxy unset -- direct connection (section 9.3)":
        print(f"proxy: {proxy_reason}")
    alerts: list[tuple[str, str, str]] = []

    # section 12 opt-in supervisor: lazily created ONLY when enabled (section 12.1/section 12.4 --
    # event-driven, zero cost and zero LLM calls on healthy runs).
    agent_holder: dict[str, Any] = {}

    def _engage_agent(module: str, branch: str, reason: str, hooks: dict[str, Any] | None = None) -> None:
        from pipeline.agent import Supervisor

        if "supervisor" not in agent_holder:
            agent_holder["supervisor"] = Supervisor(params, target_dir)
        supervisor = agent_holder["supervisor"]
        if not supervisor.enabled():
            return
        verdict = supervisor.on_module_failure(module, branch, str(reason), hooks=hooks)
        print(f"agent: {module} verdict={ {k: v for k, v in verdict.items() if k != 'engaged'} }")


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

    merge_name = str(params.require("merge_module"))
    st = state_engine.load_state(params, target_dir, target)
    if not state_engine.skip_done(st, merge_name):
        state_engine.set_status(params, target_dir, merge_name, "running")
        try:
            merge_branches(params, gate, target_dir, target, passive_docs, active_docs)
            state_engine.set_status(params, target_dir, merge_name, "done")
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
        st = state_engine.load_state(params, target_dir, target)
        if state_engine.skip_done(st, sweep_name):
            print(f"skip: module={sweep_name} reason=already done (resume)")
        elif not adapter.breaker.allow(sweep_name):
            reason = adapter.breaker.pause_reason(sweep_name) or "circuit breaker paused this module"
            _append_log(params, target_dir, sweep_name, sweep_name, 0, f"skip: {reason}")
            print(f"skip: module={sweep_name} reason={reason}")
        else:
            state_engine.set_status(params, target_dir, sweep_name, "running")
            try:
                RUNNERS[sweep_name](
                    params, gate, adapter, target_dir, target, extra, planned, None, partial
                )
                state_engine.set_status(params, target_dir, sweep_name, "done")
            except Exception as exc:
                state_engine.set_status(params, target_dir, sweep_name, "failed")
                partial.append(f"portsweep:{exc}")
                _append_log(params, target_dir, sweep_name, sweep_name, 1, str(exc))
                _engage_agent(sweep_name, "active", str(exc))
                traceback.print_exc()

    # C6 OWASP-PASSIVE (operator roadmap): post-MERGE zero-packet artifact
    # analyzer, mirroring the PORT-SWEEP hook law exactly -- resume-aware,
    # breaker-aware, partial markers shape the final verdict like any stage.
    owasp_name = str(params.require("owasp_module"))
    if owasp_name in RUNNERS:
        st = state_engine.load_state(params, target_dir, target)
        if state_engine.skip_done(st, owasp_name):
            print(f"skip: module={owasp_name} reason=already done (resume)")
        elif not adapter.breaker.allow(owasp_name):
            reason = adapter.breaker.pause_reason(owasp_name) or "circuit breaker paused this module"
            _append_log(params, target_dir, owasp_name, owasp_name, 0, f"skip: {reason}")
            print(f"skip: module={owasp_name} reason={reason}")
        else:
            state_engine.set_status(params, target_dir, owasp_name, "running")
            try:
                RUNNERS[owasp_name](
                    params, gate, adapter, target_dir, target, extra, planned, None, partial
                )
                state_engine.set_status(params, target_dir, owasp_name, "done")
            except Exception as exc:
                state_engine.set_status(params, target_dir, owasp_name, "failed")
                partial.append(f"owasp:{exc}")
                _append_log(params, target_dir, owasp_name, owasp_name, 1, str(exc))
                _engage_agent(owasp_name, "post-merge", str(exc))
                traceback.print_exc()

    # C5 IP rotation ledger: every module's pool assignment is always visible
    # (never-fail, credentials masked) -- honesty law for the rotation feature.
    if assigner is not None:
        assigner.write_ledger(target_dir)
        for line in assigner.pool.summary_lines():
            print(line)

    stamp = utc_stamp()
    counts = _counts(params, target_dir, passive_docs, active_docs)
    status, reason, failing_module = _classify_status(params, breaker, alerts, partial, failed, passive_docs, active_docs)
    state_engine.set_run_status(params, target_dir, target, status, reason=reason, failing_module=failing_module)
    ingest_if_completed(params, gate, target_dir, target, status)
    snapshot(params, target_dir, stamp)
    prev = previous_timestamp(params, target_dir, stamp)
    append_run(params, target_dir, stamp, status, counts)
    write_diff(params, target_dir, prev, stamp)
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
        f"total={learned_ledger.get('total')} selectable=platform_learned"
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
    if not breaker.allow(tool_name):
        reason = breaker.pause_reason(tool_name) or "circuit breaker paused this module"
        _append_log(params, target_dir, tool_name, tool_name, 0, f"skip: {reason}")
        print(f"skip: module={tool_name} reason={reason}")
        return _exit_code(params, str(params.require("run_status_anomaly")))
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
            _engage_agent(tool_name, "active", str(exc))
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
    from pipeline.dockerbin import docker_prefix
    import subprocess

    prefix = docker_prefix(params)
    label = str(params.require("docker_label_target"))
    listed = subprocess.run(
        [*prefix, "ps", "-q", "--filter", f"label={label}={target_dir.name}"],
        capture_output=True,
        text=True,
        check=False,
    )
    ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    for cid in ids:
        subprocess.run([*prefix, "stop", cid], capture_output=True, text=True, check=False)
    state_engine.set_run_status(
        params,
        target_dir,
        target_dir.name,
        str(params.require("run_status_stopped")),
        reason="operator stop",
        failing_module=None,
    )
    return ids


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
    kept: list[str] = []
    for name in names:
        if breaker.allow(name):
            kept.append(name)
            continue
        reason = breaker.pause_reason(name) or "circuit breaker paused this module"
        _append_log(params, target_dir, name, name, 0, f"skip: {reason}")
        print(f"skip: module={name} reason={reason}")
    return kept


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
        if state_engine.skip_done(st, name):
            key = data_keys.get(name)
            if key:
                doc = load_tool_doc(target_dir / str(params.require(key)))
                if doc:
                    docs.append(doc)
            continue
        if not adapter.breaker.allow(name):
            reason = adapter.breaker.pause_reason(name) or "circuit breaker paused this module"
            _append_log(params, target_dir, name, name, 0, f"skip: {reason}")
            print(f"skip: module={name} reason={reason}")
            continue
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
            state_engine.set_status(params, target_dir, name, "done")
            st = state_engine.load_state(params, target_dir, target)
        except Exception as exc:
            state_engine.set_status(params, target_dir, name, "failed")
            _append_log(params, target_dir, name, name, 1, str(exc))
            partial.append(f"passive:{name}:{exc}")
            _engage_agent(name, "passive", str(exc))
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
    deadline = clock.time() + budget
    docs: list[dict[str, Any]] = []
    st = state_engine.load_state(params, target_dir, target)
    data_keys = {
        "ffuf": "ffuf_data_json",
        "dns-resolve": "dnsr_data_json",
        "ffuf-3": "ffuf3_data_json",
        "port-check": "portcheck_data_json",
    }
    for name in names:
        name = str(name)
        if name not in RUNNERS:
            continue
        if state_engine.skip_done(st, name):
            key = data_keys.get(name)
            if key:
                doc = load_tool_doc(target_dir / str(params.require(key)))
                if doc:
                    docs.append(doc)
            continue
        if not adapter.breaker.allow(name):
            reason = adapter.breaker.pause_reason(name) or "circuit breaker paused this module"
            _append_log(params, target_dir, name, name, 0, f"skip: {reason}")
            print(f"skip: module={name} reason={reason}")
            continue
        left = deadline - clock.time()
        if left <= 0:
            partial.append("active_budget")
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
            state_engine.set_status(params, target_dir, name, "done")
            st = state_engine.load_state(params, target_dir, target)
        except EmptyWordlistError as exc:
            state_engine.set_status(params, target_dir, name, "failed")
            partial.append(f"empty_wordlist:{exc}")
            print(f"fail-fast: {exc}")
            break
        except Exception as exc:
            state_engine.set_status(params, target_dir, name, "failed")
            _append_log(params, target_dir, name, name, 1, str(exc))
            partial.append(f"active:{name}:{exc}")
            traceback.print_exc()
            continue
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
        left = deadline - clock.time()
        if left <= 0:
            return None
        return adapter.invoke(name, module=name, extra=extra, planned_concurrency=planned, timeout_sec=left)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(one, name): name for name in remaining}
        for fut in as_completed(futs):
            name = futs[fut]
            if clock.time() >= deadline:
                partial.append(f"{branch}_budget")
                break
            try:
                result = fut.result()
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
    path = target_dir / str(params.require("run_log"))
    path.parent.mkdir(parents=True, exist_ok=True)
    tail_n = int(params.require("stderr_tail_lines"))
    tail = " | ".join(detail.splitlines()[-tail_n:])
    from datetime import datetime, timezone

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{stamp}\t{module}\t{tool}\t{code}\tfail\t{tail}\n")


def _append_note(params: Params, target_dir: Path, module: str, detail: str) -> None:
    path = target_dir / str(params.require("run_log"))
    path.parent.mkdir(parents=True, exist_ok=True)
    from datetime import datetime, timezone

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{stamp}\t{module}\t-\t0\tok\t{detail}\n")


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
        doc = read_json(assets_path)
        counts["assets"] = len(doc.get("assets") or [])
        counts["quarantine"] = len(doc.get("quarantine") or [])
    return counts
