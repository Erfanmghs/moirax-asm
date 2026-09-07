"""B8 SUPERVISOR AGENT preflight gates -- run BEFORE the vehicle `recon.sh run`.

  G-N1  committed section 12 defaults: agent_enabled FALSE (section 12.1 opt-in), budget 20,
        autonomy defaults auto-fix(PASSIVE)/suggest(ACTIVE), attempts <=3,
        journal relpath + remediation filename registered
  G-N2  playbook: remediation.yaml carries the 5 section 12.5 example signatures,
        every action inside ALLOWED_ACTIONS
  G-N3  engine wiring: opt-in lazy supervisor at the module failure sites
        (passive loop, portsweep, single-module) -- zero engagement when off
  G-N4  section 12.2 one-command autonomy: `info-gather` CLI verb + section 12.7 scope
        guardrail line
  G-N5  section 12.7 journal: append-only relpath + dashboard live-stream endpoint;
        SPA carries the agent toggle + journal panel
  G-N6  verify_b1.py has no working-tree diff (frozen since handoff)
  G-N7  vehicle scope: example.com retained
  G-N8  unit coverage markers in tests/test_agent.py

Exit 0 = all gates hold; any GATE-FAIL exits 1.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.agent import ALLOWED_ACTIONS, load_playbook  # noqa: E402
from pipeline.params import Params  # noqa: E402
from pipeline.yaml_util import load_yaml_file  # noqa: E402

failures: list[str] = []


def check(name: str, ok: bool, detail: str) -> None:
    mark = "PASS" if ok else "GATE-FAIL"
    print(f"{mark}\t{name}\t{detail}")
    if not ok:
        failures.append(name)


def main() -> int:
    params = Params(ROOT)

    # ---- G-N1 committed defaults -------------------------------------------
    defaults = {
        "agent_enabled": False,
        "agent_max_llm_calls": 20,
        "agent_autonomy_passive": "auto-fix",
        "agent_autonomy_active": "suggest",
        "agent_max_remediation_attempts": 3,
        "agent_journal_relpath": "logs/agent-journal.jsonl",
        "remediation_filename": "remediation.yaml",
    }
    bad = {k: params.require(k) for k, v in defaults.items() if params.require(k) != v}
    check("G-N1 committed-defaults", not bad, f"violations={bad}")

    # ---- G-N2 playbook ----------------------------------------------------------
    params.root = ROOT  # playbook loader resolves against the repo root
    playbook = load_playbook(params)
    actions = {str(row.get("action")) for row in playbook}
    required = {"halve_concurrency_retry", "refresh_resolver_forge_retry", "rotate_key_pool",
                "quarantine_and_rerun", "repin_and_restart"}
    outside = actions - set(ALLOWED_ACTIONS)
    check("G-N2 playbook", required <= actions and not outside,
          f"entries={len(playbook)} actions={sorted(actions)} outside_allow_list={sorted(outside)}")

    # ---- G-N3 engine wiring ---------------------------------------------------------
    engine_text = (ROOT / "pipeline" / "engine.py").read_text(encoding="utf-8")
    wired = (
        engine_text.count("_engage_agent(") >= 4  # 1 def + 3 call sites
        and "Supervisor(params, target_dir)" in engine_text
        and "ONLY when enabled" in engine_text
    )
    check("G-N3 engine-wiring", wired, f"engage_sites={engine_text.count('_engage_agent(') - 1}")

    # ---- G-N4 one-command autonomy -----------------------------------------------------
    cli_text = (ROOT / "pipeline" / "cli.py").read_text(encoding="utf-8")
    cli_ok = "info-gather" in cli_text and "cmd_info_gather" in cli_text and "agent never modifies scope.yaml" in cli_text
    check("G-N4 info-gather", cli_ok, "section 12.2 verb + section 12.7 guardrail")

    # ---- G-N5 journal + dashboard surface -------------------------------------------------
    app_text = (ROOT / "dashboard" / "app.py").read_text(encoding="utf-8")
    html = (ROOT / "dashboard" / "static" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "dashboard" / "static" / "app.js").read_text(encoding="utf-8")
    surface_ok = (
        "/api/run/agent-journal/{target}" in app_text
        and "AGENT JOURNAL" in html
        and "startJournalStream" in js
        and "s-agent-enabled" in html and "s-agent-passive" in html and "s-agent-active" in html
    )
    check("G-N5 journal-surface", surface_ok, "journal endpoint + SPA toggle + live stream")

    # ---- G-N6 verify_b1 clean -----------------------------------------------------------------
    diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    check("G-N6 verify_b1-clean", diff.stdout.strip() == "", "no working-tree diff")

    # ---- G-N7 vehicle scope ---------------------------------------------------------------------
    scope = load_yaml_file(str(ROOT / "scope.yaml"))
    includes = [str(i) for i in (scope.get("includes") or [])]
    check("G-N7 vehicle-scope", "example.com" in includes and "*.example.com" in includes, f"includes={includes}")

    # ---- G-N8 unit coverage ------------------------------------------------------------------------
    test_text = (ROOT / "tests" / "test_agent.py").read_text(encoding="utf-8")
    markers = (
        "test_default_disabled",
        "test_playbook_loads_spec_examples",
        "test_allow_list_enforced",
        "test_passive_default_auto_fix_applies",
        "test_active_default_suggest_waits",
        "test_attempt_budget_three_then_escalate",
        "test_zero_llm_calls_by_default",
        "test_llm_hook_budget_and_cache",
        "test_journal_append_only_jsonl",
        "test_scope_never_written_by_agent_surface",
    )
    covered = all(m in test_text for m in markers)
    check("G-N8 unit-coverage", covered, f"markers={len(markers)}")

    print(f"PREFLIGHT {'PASS' if not failures else 'FAIL'} ({len(failures)} failing)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
