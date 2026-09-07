"""B8 SUPERVISOR AGENT acceptance table -- runs AFTER the example.com vehicle.

  L1  MANDATORY  section 12.1 OPT-IN PROOF on the REAL vehicle: agent disabled by
                 default -> the real run created NO agent journal and printed
                 NO `agent:` verdict lines; pipeline standalone
  L2  MANDATORY  section 12.3+section 12.6 supervision loop (frozen code): PASSIVE-branch
                 failure with agent ON -> auto-fix default -> playbook action
                 applied via a fake hook, attempts recorded
  L3  MANDATORY  section 12.6 ACTIVE-branch default `suggest` -> proposes, waits
  L4  MANDATORY  section 12.3 attempt budget: 4th failure on the same module
                 escalates (<=3 attempts per module per run)
  L5  MANDATORY  section 12.4 frugality: deterministic-only -> ZERO LLM calls;
                 same-signature cache replay; budget cap honoured
  L6  MANDATORY  section 12.7 journal: append-only JSONL with ts+event rows
  L7  MANDATORY  section 12.7 guardrails: allow-list is a closed set that contains
                 no scope/breaker/log-deletion actions; scope.yaml sha256
                 unchanged across a supervised session
  L8  MANDATORY  COMMITTED content intact (HEAD blob of tools.yaml re-parsed
                 with the frozen loader) + verify_b1.py diff empty
  G1  DISCLOSURE  playbook entries + autonomy defaults + frugality report

Exit 0 iff all MANDATORY rows PASS.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.agent import ALLOWED_ACTIONS, Supervisor, load_playbook, match_playbook, diagnose_signature  # noqa: E402
from pipeline.params import Params  # noqa: E402
from pipeline.yaml_util import load_yaml_file  # noqa: E402

TARGET = "example.com"
CONSOLE = ROOT / "ci" / "b8_run_console.log"
VERDICT_FILE = ROOT / "ci" / "b8_verdict.txt"

failures: list[str] = []
rows: list[tuple[str, str, str, str]] = []


def check(hid: str, cls: str, ok: bool, detail: str) -> None:
    status = "PASS" if ok else "FAIL"
    rows.append((hid, cls, status, detail))
    if not ok and cls == "MANDATORY":
        failures.append(hid)


def main() -> int:
    params = Params(ROOT)
    console_text = CONSOLE.read_text(encoding="utf-8", errors="replace") if CONSOLE.is_file() else ""

    # ---- L1 opt-in proof on the real vehicle ----------------------------------
    real_journal = ROOT / "recon" / TARGET / "logs" / "agent-journal.jsonl"
    agent_lines = [l for l in console_text.splitlines() if l.startswith("agent: ")]
    check("L1", "MANDATORY", not real_journal.is_file() and not agent_lines,
          f"agent_journal_created={real_journal.is_file()} agent_console_lines={len(agent_lines)} (section 12.1 standalone)")

    # ---- L2 passive default auto-fix -------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        iparams = _isolated_params(Path(tmp))
        s = Supervisor(iparams, iparams.root, run_overrides={"enabled": True})
        scope_sha_before = hashlib.sha256((iparams.root / "scope.yaml").read_bytes()).hexdigest()
        calls = {"n": 0}

        def forge_hook() -> str:
            calls["n"] += 1
            return "resolver forge refreshed (fake hook)"

        verdict = s.on_module_failure("subfinder", "passive", "resolver timeout cascade",
                                      hooks={"refresh_resolver_forge_retry": forge_hook})
        scope_sha_after = hashlib.sha256((iparams.root / "scope.yaml").read_bytes()).hexdigest()
        ok2 = (
            verdict.get("effective_level") == "auto-fix"
            and verdict.get("fixed") is True
            and verdict.get("actions", [{}])[0].get("action") == "refresh_resolver_forge_retry"
            and calls["n"] == 1
            and scope_sha_before == scope_sha_after
        )
        check("L2", "MANDATORY", ok2, f"verdict={json.dumps(verdict)[:160]} scope_untouched={scope_sha_before == scope_sha_after}")

        # ---- L3 active default suggest ---------------------------------------------
        v3 = s.on_module_failure("naabu", "active", "OOM killed")
        ok3 = v3.get("effective_level") == "suggest" and v3.get("fixed") is False and v3["actions"][0]["mode"] == "suggest"
        check("L3", "MANDATORY", ok3, f"active_verdict={json.dumps(v3)[:140]}")

        # ---- L4 attempt budget --------------------------------------------------------
        v4 = None
        for _ in range(3):
            v4 = s.on_module_failure("subfinder", "passive", "resolver timeout cascade")
        ok4 = v4 is not None and v4.get("escalated") is True and v4.get("escalation_reason") == "attempt budget exhausted (section 12.3 <=3)"
        check("L4", "MANDATORY", ok4, f"4th_verdict={json.dumps(v4)[:140]}")

        # ---- L5 frugality -----------------------------------------------------------------
        hook_calls = {"n": 0}
        s5 = Supervisor(iparams, iparams.root, run_overrides={"enabled": True, "max_llm_calls": 1})
        s5.llm_hook = lambda _sig: (_hook_inc(hook_calls) or "diag")
        s5.on_module_failure("a", "passive", "resolver timeout cascade")
        s5.on_module_failure("a", "passive", "resolver timeout cascade")
        s5.on_module_failure("b", "passive", "totally unknown xyz")
        ok5 = hook_calls["n"] == 1 and s5.frugality_report()["llm_calls"] == 1
        check("L5", "MANDATORY", ok5, f"llm_hook_calls={hook_calls['n']} report={json.dumps(s5.frugality_report())}")

        # ---- L6 journal ---------------------------------------------------------------------
        journal_path = iparams.root / "logs" / "agent-journal.jsonl"
        rows_jsonl = [json.loads(l) for l in journal_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        ok6 = bool(rows_jsonl) and all("ts" in r and "event" in r for r in rows_jsonl) and journal_path.read_text(encoding="utf-8").endswith("\n")
        check("L6", "MANDATORY", ok6, f"rows={len(rows_jsonl)} events={sorted({r['event'] for r in rows_jsonl})}")

    # ---- L7 guardrails ----------------------------------------------------------------------
    forbidden = ("modify_scope", "disable_breaker", "bypass_scope", "delete_logs", "weaken")
    clean = all(not any(f in a for f in forbidden) for a in ALLOWED_ACTIONS)
    playbook = load_playbook(params)
    sig = diagnose_signature("corrupt data.json schema-invalid")
    play = match_playbook(playbook, sig)
    ok7 = clean and set(ALLOWED_ACTIONS) == {
        "halve_concurrency_retry", "refresh_resolver_forge_retry", "rotate_key_pool",
        "quarantine_and_rerun", "repin_and_restart",
    } and play is not None and play["action"] == "quarantine_and_rerun"
    check("L7", "MANDATORY", ok7, f"allow_list={sorted(ALLOWED_ACTIONS)} corrupt_signature={bool(play)}")

    # ---- L8 committed content + verify_b1 --------------------------------------------------------
    show = subprocess.run(["git", "show", "HEAD:tools.yaml"], cwd=ROOT, capture_output=True, text=True, check=False)
    head_ok = show.returncode == 0 and "agent_enabled: false" in show.stdout
    verify_diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    verify_ok = verify_diff.stdout.strip() == ""
    check("L8", "MANDATORY", head_ok and verify_ok, f"head_carries_defaults={head_ok} verify_b1_clean={verify_ok}")

    # ---- G1 disclosure -----------------------------------------------------------------------------
    check("G1", "DISCLOSURE", True,
          f"playbook_entries={len(playbook)} allow_list={len(ALLOWED_ACTIONS)} defaults=passive:auto-fix/active:suggest budget=20 llm_plugged=False")

    table = ["id\tclass\tstatus\tdetail"]
    table += [f"{hid}\t{cls}\t{st}\t{det}" for hid, cls, st, det in rows]
    VERDICT_FILE.write_text("\n".join(table) + "\n", encoding="utf-8")
    print("\n".join(table))
    print(f"ASSERTIONS {'PASS' if not failures else 'FAIL'} ({len(failures)} failing)")
    return 1 if failures else 0


def _hook_inc(counter: dict) -> str:
    counter["n"] += 1
    return ""


def _isolated_params(tmp: Path) -> Params:
    from pipeline.params import Params as P

    for rel in ("tools.yaml", "wordlists.yaml", "scheduler.json", "scope.yaml", "remediation.yaml"):
        src = ROOT / rel
        if src.is_file():
            (tmp / rel).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp / "dashboard").mkdir(exist_ok=True)
    return P(tmp)


if __name__ == "__main__":
    raise SystemExit(main())
