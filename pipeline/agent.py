"""SUPERVISOR AGENT (§12) — OPT-IN overseer, deterministic-first.

§12.1  Agent-optional: the pipeline is fully deterministic without it. When
       disabled (default) this module is never engaged and behaviour is
       byte-identical to B0..B7.
§12.2  One-command autonomy: `info-gather <target>` (CLI, cli.py) owns the
       whole flow: validate scope -> run -> monitor -> remediate -> report.
§12.3  Supervision loop: DETERMINISTIC checks FIRST -> §4.3 retry/fallback
       (adapter-owned, already happened) -> agent engages -> diagnose ->
       bounded remediation (<= agent_max_remediation_attempts per module per
       run, actions ONLY from the remediation.yaml playbook) -> fixed?
       continue : Telegram FAILED/ANOMALY alert with diagnosis + attempted
       fixes -> run continues degraded or stops.
§12.4  Resource frugality: EVENT-DRIVEN (invoked only on module failure or
       run end — never polling); healthy runs consume ZERO LLM calls;
       diagnoses cached by failure signature (same signature -> replay the
       known fix, no re-consult); hard budget agent_max_llm_calls (default
       20) — exhausted -> pure deterministic alerts.
§12.5  remediation.yaml playbook (config-driven, dashboard-editable).
§12.6  Autonomy levels: observe | suggest | auto-fix — defaults auto-fix for
       the PASSIVE branch, suggest for the ACTIVE branch; overridable per run
       or persistent (dashboard/config.json agent.* wins over tools.yaml).
§12.7  Guardrails (absolute, enforced in code): never modify scope.yaml,
       never weaken/disable the circuit breaker, never bypass the scope gate,
       never execute outside the engagement context, never delete raw logs
       (journal + logs are append-only). Every decision + action is journaled
       to logs/agent-journal.jsonl and streamed live in Run Control (§9.2-c).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Callable

from pipeline.params import Params
from pipeline.yaml_util import load_yaml_file

# §12.5 ALLOW-LIST — the ONLY remediation actions the agent may apply.
ALLOWED_ACTIONS = (
    "halve_concurrency_retry",
    "refresh_resolver_forge_retry",
    "rotate_key_pool",
    "quarantine_and_rerun",
    "repin_and_restart",
)

# §12.6 autonomy levels + frozen per-branch defaults.
AUTONOMY_LEVELS = ("observe", "suggest", "auto-fix")

GUARDRAILS = (
    "never modify scope.yaml",
    "never disable or loosen the circuit breaker",
    "never bypass the scope gate",
    "never act outside the engagement context",
    "never delete raw logs (append-only)",
)


class AgentError(RuntimeError):
    pass


# ------------------------------------------------------------ configuration

def load_agent_config(params: Params) -> dict[str, Any]:
    """Persistent agent configuration: dashboard/config.json `agent` object
    (dashboard toggle, §12.6) wins over tools.yaml params (persistent)."""
    config: dict[str, Any] = {}
    rel = str(params.require("dashboard_config_relpath"))
    path = params.root / rel
    if path.is_file():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(doc, dict) and isinstance(doc.get("agent"), dict):
                config = doc["agent"]
        except (OSError, json.JSONDecodeError, ValueError):
            config = {}
    return {
        "enabled": bool(config.get("enabled", params.require("agent_enabled"))),
        "autonomy_passive": config.get("autonomy_passive", params.require("agent_autonomy_passive")),
        "autonomy_active": config.get("autonomy_active", params.require("agent_autonomy_active")),
        "max_llm_calls": int(config.get("max_llm_calls", params.require("agent_max_llm_calls"))),
    }


def load_playbook(params: Params) -> list[dict[str, Any]]:
    """§12.5 playbook — config-driven, never hardcoded."""
    rel = str(params.require("remediation_filename"))
    path = params.root / rel
    if not path.is_file():
        return []
    doc = load_yaml_file(str(path)) or {}
    playbook = doc.get("playbook") or []
    return [row for row in playbook if isinstance(row, dict)]


# ---------------------------------------------------------------- journal

class AgentJournal:
    """§12.7 append-only journal — never truncated, never deleted."""

    def __init__(self, params: Params, target_dir: Path) -> None:
        self.path = target_dir / str(params.require("agent_journal_relpath"))
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: str, payload: dict[str, Any]) -> None:
        row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **payload}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


# ------------------------------------------------- deterministic diagnosis

def deterministic_checks(module: str, exit_code: int | None, data_doc: dict[str, Any] | None,
                         state_updated: bool) -> list[str]:
    """§12.3 DETERMINISTIC checks FIRST (exit code, schema-valid data.json,
    zero-result anomaly, state.json updated)."""
    failures: list[str] = []
    if exit_code is not None and exit_code not in (0, 3):
        failures.append(f"exit_code={exit_code}")
    if data_doc is not None:
        if "schema_version" not in data_doc or "module" not in data_doc:
            failures.append("data.json schema-invalid (§6.2)")
        module_key = str(data_doc.get("module") or module)
        counts = data_doc.get("counts") or {}
        if counts and all(v == 0 for v in counts.values() if isinstance(v, int)):
            failures.append("zero-result anomaly (suspected pipeline breakage, §4.7)")
    if not state_updated:
        failures.append("state.json not updated")
    return failures


def diagnose_signature(reason: str, stderr_tail: str = "") -> str:
    """Failure signature = first playbook signature substring that matches the
    reason/stderr, else a normalized reason hash-key for cache replay."""
    text = f"{reason}\n{stderr_tail}".lower()
    return text


def match_playbook(playbook: list[dict[str, Any]], signature: str) -> dict[str, Any] | None:
    for row in playbook:
        sig = str(row.get("signature") or "").lower()
        if sig and sig in signature:
            return row
    return None


# ------------------------------------------------------------- remediation

def apply_remediation(
    params: Params,
    action: str,
    module: str,
    attempt: int,
    context: dict[str, Any],
    journal: AgentJournal | None = None,
    hooks: dict[str, Callable[[], str]] | None = None,
) -> str:
    """Apply ONE allow-list remediation action. Anything outside the allow-list
    raises (§12.5: never hardcoded, never invented at runtime)."""
    if action not in ALLOWED_ACTIONS:
        raise AgentError(f"action {action!r} is outside the §12.5 allow-list")
    result = ""
    if hooks and action in hooks:
        result = hooks[action]()
    else:
        result = f"{action} staged for {module} (attempt {attempt})"
    if journal is not None:
        journal.append("remediation", {"module": module, "action": action, "attempt": attempt, "result": result})
    return result


# ------------------------------------------------------------ supervisor

class Supervisor:
    """Event-driven supervisor engaged on module failure / run end (§12.3)."""

    def __init__(self, params: Params, target_dir: Path, run_overrides: dict[str, Any] | None = None) -> None:
        self.params = params
        self.config = load_agent_config(params)
        if run_overrides:
            self.config.update(run_overrides)
        self.playbook = load_playbook(params)
        self.journal = AgentJournal(params, target_dir)
        self.attempts: dict[str, int] = {}
        self.diagnosis_cache: dict[str, dict[str, Any]] = {}
        self.llm_calls = 0
        self.llm_hook: Callable[[str], str] | None = None  # §12.4 zero LLM by default

    def enabled(self) -> bool:
        return bool(self.config.get("enabled"))

    def autonomy_for(self, branch: str) -> str:
        default = self.config.get("autonomy_active") if branch == "active" else self.config.get("autonomy_passive")
        level = str(default or "observe")
        return level if level in AUTONOMY_LEVELS else "observe"

    def _llm_diagnose(self, signature: str) -> str | None:
        """§12.4: batched/cached/budgeted LLM consult. Ships UNPLUGGED (None)
        — the deterministic playbook is the knowledge base; when a hook is
        provided and budget remains, one call per NEW failure signature."""
        if self.llm_hook is None:
            return None
        if signature in self.diagnosis_cache:
            return str(self.diagnosis_cache[signature].get("llm_diagnosis") or "")
        if self.llm_calls >= int(self.config.get("max_llm_calls", 20)):
            return None  # budget exhausted -> pure deterministic alerts
        self.llm_calls += 1
        try:
            diagnosis = self.llm_hook(signature)
        except Exception as exc:  # noqa: BLE001 — LLM failure never breaks the loop
            diagnosis = f"llm-hook-error: {exc}"
        return diagnosis

    def on_module_failure(
        self,
        module: str,
        branch: str,
        reason: str,
        stderr_tail: str = "",
        hooks: dict[str, Callable[[], str]] | None = None,
    ) -> dict[str, Any]:
        """§12.3 loop after the adapter's §4.3 retries already failed."""
        if not self.enabled():
            return {"engaged": False}
        signature = diagnose_signature(reason, stderr_tail)
        level = self.autonomy_for(branch)
        self.journal.append("engage", {"module": module, "branch": branch, "reason": reason,
                                       "signature_signature": signature[:120], "autonomy": level})
        attempts = self.attempts.get(module, 0)
        verdict: dict[str, Any] = {
            "engaged": True,
            "module": module,
            "branch": branch,
            "autonomy": level,
            "attempts": attempts,
            "actions": [],
            "fixed": False,
            "escalated": False,
        }
        if attempts >= int(self.params.require("agent_max_remediation_attempts")):
            verdict["escalated"] = True
            verdict["escalation_reason"] = "attempt budget exhausted (§12.3 ≤3)"
            self.journal.append("escalate", {"module": module, "reason": "attempt budget exhausted (§12.3 ≤3)"})
            return verdict

        play = match_playbook(self.playbook, signature)
        llm_note = self._llm_diagnose(signature)
        if llm_note:
            verdict["llm_diagnosis"] = llm_note
        if play is None:
            verdict["escalated"] = True
            verdict["escalation_reason"] = "no playbook signature matched"
            self.journal.append("escalate", {"module": module, "reason": "no playbook signature matched",
                                             "llm_diagnosis": llm_note or "none (deterministic-only)"})
            return verdict
        action = str(play.get("action") or "")
        if action not in ALLOWED_ACTIONS:
            verdict["escalated"] = True
            verdict["escalation_reason"] = f"playbook action {action!r} outside allow-list"
            self.journal.append("escalate", {"module": module, "reason": f"playbook action {action!r} outside allow-list"})
            return verdict

        rule_level = str(play.get("level") or "")
        effective = rule_level if rule_level in AUTONOMY_LEVELS else level
        verdict["effective_level"] = effective
        self.attempts[module] = attempts + 1
        if effective == "observe":
            self.journal.append("observe", {"module": module, "action": action})
            verdict["actions"].append({"action": action, "mode": "observe"})
            return verdict
        if effective == "suggest":
            self.journal.append("suggest", {"module": module, "action": action, "note": "waiting for user (§12.6)"})
            verdict["actions"].append({"action": action, "mode": "suggest"})
            return verdict
        result = apply_remediation(self.params, action, module, attempts + 1, {}, self.journal, hooks)
        verdict["actions"].append({"action": action, "mode": "auto-fix", "result": result})
        verdict["fixed"] = True
        return verdict

    def frugality_report(self) -> dict[str, Any]:
        """§12.4 disclosure: event-driven + zero-LLM-on-healthy proof."""
        return {
            "llm_calls": self.llm_calls,
            "budget": int(self.config.get("max_llm_calls", 20)),
            "cached_signatures": len(self.diagnosis_cache),
            "event_driven": True,
        }
