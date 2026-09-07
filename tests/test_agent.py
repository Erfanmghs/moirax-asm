"""B8 SUPERVISOR AGENT unit proof (spec section 12) -- deterministic, no network, no LLM."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pipeline.agent import (
    ALLOWED_ACTIONS,
    AgentError,
    AgentJournal,
    Supervisor,
    apply_remediation,
    deterministic_checks,
    diagnose_signature,
    load_agent_config,
    load_playbook,
    match_playbook,
)
from pipeline.params import Params

_ROOT = Path(__file__).resolve().parents[1]


def _isolated_params(playbook: bool = True) -> Params:
    tmp = Path(tempfile.mkdtemp())
    for rel in ("tools.yaml", "wordlists.yaml", "scheduler.json", "scope.yaml"):
        src = _ROOT / rel
        if src.is_file():
            (tmp / rel).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    if playbook:
        (tmp / "remediation.yaml").write_text((_ROOT / "remediation.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    (tmp / "dashboard").mkdir(exist_ok=True)
    params = Params(tmp)
    return params


def _supervisor(params: Params, run_overrides: dict | None = None) -> Supervisor:
    return Supervisor(params, params.root, run_overrides=run_overrides)


class TestOptInDefault(unittest.TestCase):
    """section 12.1 agent-optional: default OFF; disabled -> zero engagement."""

    def test_default_disabled(self):
        s = _supervisor(_isolated_params())
        self.assertFalse(s.enabled())
        verdict = s.on_module_failure("ffuf", "active", "boom")
        self.assertEqual(verdict, {"engaged": False})

    def test_engine_default_off_marker(self):
        text = (_ROOT / "tools.yaml").read_text(encoding="utf-8")
        self.assertIn("agent_enabled: false", text)
        engine = (_ROOT / "pipeline" / "engine.py").read_text(encoding="utf-8")
        self.assertIn("ONLY when enabled", engine)


class TestDeterministicChecks(unittest.TestCase):
    """section 12.3 DETERMINISTIC checks FIRST."""

    def test_exit_code_failure(self):
        self.assertIn("exit_code=2", deterministic_checks("m", 2, None, True))

    def test_schema_invalid(self):
        fails = deterministic_checks("m", 0, {"counts": {"a": 1}}, True)
        self.assertIn("data.json schema-invalid (section 6.2)", fails)

    def test_zero_result_anomaly(self):
        fails = deterministic_checks("m", 0, {"schema_version": 1, "module": "m", "counts": {"a": 0, "b": 0}}, True)
        self.assertIn("zero-result anomaly (suspected pipeline breakage, section 4.7)", fails)

    def test_state_not_updated(self):
        fails = deterministic_checks("m", 0, None, False)
        self.assertIn("state.json not updated", fails)

    def test_healthy_all_clear(self):
        self.assertEqual(deterministic_checks("m", 0, {"schema_version": 1, "module": "m", "counts": {"a": 2}}, True), [])


class TestPlaybook(unittest.TestCase):
    """section 12.5 config-driven playbook + allow-list."""

    def test_playbook_loads_spec_examples(self):
        params = _isolated_params()
        playbook = load_playbook(params)
        actions = {row["action"] for row in playbook}
        for required in ("halve_concurrency_retry", "refresh_resolver_forge_retry", "rotate_key_pool",
                         "quarantine_and_rerun", "repin_and_restart"):
            self.assertIn(required, actions)

    def test_signature_match(self):
        playbook = load_playbook(_isolated_params())
        row = match_playbook(playbook, diagnose_signature("container killed: OOM kill"))
        self.assertEqual(row["action"], "halve_concurrency_retry")
        row403 = match_playbook(playbook, diagnose_signature("HTTP 403 quota exceeded"))
        self.assertEqual(row403["action"], "rotate_key_pool")
        self.assertIsNone(match_playbook(playbook, "totally unknown failure xyz"))

    def test_allow_list_enforced(self):
        with self.assertRaises(AgentError):
            apply_remediation(_isolated_params(), "rm_rf_everything", "m", 1, {})
        self.assertNotIn("modify_scope", ALLOWED_ACTIONS)


class TestSupervisionLoop(unittest.TestCase):
    """section 12.3 bounded remediation + escalation; section 12.6 autonomy levels."""

    def test_passive_default_auto_fix_applies(self):
        params = _isolated_params()
        s = _supervisor(params, {"enabled": True})
        verdict = s.on_module_failure("subfinder", "passive", "resolver timeout cascade")
        self.assertEqual(verdict["effective_level"], "auto-fix")
        self.assertTrue(verdict["fixed"])
        self.assertEqual(verdict["actions"][0]["action"], "refresh_resolver_forge_retry")
        self.assertEqual(s.attempts["subfinder"], 1)

    def test_active_default_suggest_waits(self):
        params = _isolated_params()
        s = _supervisor(params, {"enabled": True})
        verdict = s.on_module_failure("naabu", "active", "OOM killed")
        self.assertEqual(verdict["effective_level"], "suggest")
        self.assertFalse(verdict["fixed"])
        self.assertEqual(verdict["actions"][0]["mode"], "suggest")

    def test_attempt_budget_three_then_escalate(self):
        params = _isolated_params()
        s = _supervisor(params, {"enabled": True})
        for i in range(3):
            verdict = s.on_module_failure("subfinder", "passive", "resolver timeout cascade")
            self.assertTrue(verdict.get("fixed"), f"attempt {i + 1} applies")
        verdict = s.on_module_failure("subfinder", "passive", "resolver timeout cascade")
        self.assertTrue(verdict["escalated"])
        self.assertFalse(verdict.get("fixed"), "4th attempt is beyond the <=3 budget (section 12.3)")

    def test_no_signature_escalates_with_diagnosis(self):
        params = _isolated_params()
        s = _supervisor(params, {"enabled": True})
        verdict = s.on_module_failure("m", "passive", "unmapped failure xyz")
        self.assertTrue(verdict["escalated"])
        self.assertIn("no playbook signature", json.dumps(verdict))

    def test_observe_level_journal_only(self):
        params = _isolated_params()
        s = _supervisor(params, {"enabled": True, "autonomy_passive": "observe"})
        verdict = s.on_module_failure("subfinder", "passive", "resolver timeout cascade")
        self.assertEqual(verdict["effective_level"], "observe")
        self.assertFalse(verdict["fixed"])


class TestFrugality(unittest.TestCase):
    """section 12.4 event-driven, zero LLM on healthy runs, cache + budget."""

    def test_zero_llm_calls_by_default(self):
        s = _supervisor(_isolated_params(), {"enabled": True})
        s.on_module_failure("subfinder", "passive", "resolver timeout cascade")
        report = s.frugality_report()
        self.assertEqual(report["llm_calls"], 0, "deterministic playbook consumes ZERO LLM calls")
        self.assertTrue(report["event_driven"])

    def test_llm_hook_budget_and_cache(self):
        params = _isolated_params()
        s = _supervisor(params, {"enabled": True, "max_llm_calls": 1})
        calls = {"n": 0}

        def hook(sig: str) -> str:
            calls["n"] += 1
            return "diagnosis"

        s.llm_hook = hook
        s.on_module_failure("a", "passive", "resolver timeout cascade")
        s.on_module_failure("a", "passive", "resolver timeout cascade")  # same signature -> cache replay
        s.on_module_failure("b", "passive", "totally unknown xyz")       # budget exhausted -> deterministic
        self.assertEqual(calls["n"], 1, "one LLM call total: cache for the repeat + budget cap for the third")


class TestJournal(unittest.TestCase):
    """section 12.7 append-only journal."""

    def test_journal_append_only_jsonl(self):
        params = _isolated_params()
        s = _supervisor(params, {"enabled": True})
        s.on_module_failure("subfinder", "passive", "resolver timeout cascade")
        s.on_module_failure("subfinder", "passive", "resolver timeout cascade")
        path = params.root / "logs" / "agent-journal.jsonl"
        rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        self.assertTrue(all("ts" in r and "event" in r for r in rows))
        events = [r["event"] for r in rows]
        self.assertIn("engage", events)
        self.assertIn("remediation", events)

    def test_journal_streams_via_dashboard(self):
        app_text = (_ROOT / "dashboard" / "app.py").read_text(encoding="utf-8")
        self.assertIn("/api/run/agent-journal/{target}", app_text)


class TestGuardrails(unittest.TestCase):
    """section 12.7 absolute guardrails, enforced in code."""

    def test_allow_list_never_contains_scope_or_breaker_actions(self):
        forbidden = ("modify_scope", "disable_breaker", "bypass_scope", "delete_logs")
        for action in ALLOWED_ACTIONS:
            for bad in forbidden:
                self.assertNotIn(bad, action)

    def test_scope_never_written_by_agent_surface(self):
        agent_text = (_ROOT / "pipeline" / "agent.py").read_text(encoding="utf-8")
        self.assertNotIn('scope.yaml", "w"', agent_text, "agent never opens scope.yaml for writing")

    def test_info_gather_validates_never_modifies_scope(self):
        cli_text = (_ROOT / "pipeline" / "cli.py").read_text(encoding="utf-8")
        self.assertIn("info-gather", cli_text)
        self.assertIn("agent never modifies scope.yaml (section 12.7)", cli_text)

    def test_config_validation_of_autonomy(self):
        from dashboard.service import validate_settings

        self.assertTrue(validate_settings({"agent": {"autonomy_passive": "nuke"}}))
        self.assertTrue(validate_settings({"agent": {"max_llm_calls": -1}}))
        self.assertEqual(validate_settings({"agent": {"enabled": True, "autonomy_active": "suggest"}}), [])


if __name__ == "__main__":
    unittest.main()
