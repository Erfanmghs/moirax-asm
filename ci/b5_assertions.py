"""B5 NOTIFICATIONS & SCHEDULER acceptance table -- runs AFTER the example.com vehicle.

  I1  MANDATORY  Engine fan-out ran on the REAL vehicle: run.log carries the
                 `notify:` ledger line emitted after write_diff
  I2  MANDATORY  ACCEPTANCE (forced module failure -> FAILED alert naming
                 module + reason) -- re-proven in-CI against the FROZEN
                 run_end_notifications with a fake sender
  I3  MANDATORY  ACCEPTANCE (new-asset flood above threshold -> exactly ONE
                 digest message) -- same frozen evaluate_diff_alerts
  I4  MANDATORY  ACCEPTANCE (closed-port-only diff -> NO Telegram alert,
                 dashboard diff view only) -- same frozen evaluate_diff_alerts
  I5  MANDATORY  Real vehicle diff.json exists + its notify ledger discloses
                 the section 4.6 evaluation (skip reason or alertable counts)
  I6  MANDATORY  COMMITTED content intact (HEAD blobs of tools.yaml re-parsed
                 with the frozen loader -- B3 F10 discipline) + verify_b1.py
                 working-tree diff empty
  I7  MANDATORY  Scheduler section 4.6 floor: interval < 10 min rejected by the
                 frozen validate(); committed scheduler.json passes
  I8  DISCLOSURE Honest skip-silently on the vehicle: no Telegram credentials
                 in CI -> notify ledger shows summary=False / status_alert=False
                 and the run verdict is untouched by notification failure

Exit 0 iff all MANDATORY rows PASS.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.notify import evaluate_diff_alerts, run_end_notifications  # noqa: E402
from pipeline.params import Params  # noqa: E402
from pipeline.scheduler import validate  # noqa: E402
from pipeline.yaml_util import load_yaml_file  # noqa: E402

TARGET = "example.com"
TD = ROOT / "recon" / TARGET
RUN_LOG = TD / "logs" / "run.log"
# The engine prints the notify ledger to STDOUT (tee'd to the console log in
# CI) -- run.log only carries per-module lines. REM21: read BOTH sources.
CONSOLE_LOG = ROOT / "ci" / "b5_run_console.log"
DIFF = TD / "diff.json"
VERDICT_FILE = ROOT / "ci" / "b5_verdict.txt"

failures: list[str] = []
rows: list[tuple[str, str, str, str]] = []


def _notify_lines() -> list[str]:
    lines: list[str] = []
    for path in (RUN_LOG, CONSOLE_LOG):
        if path.is_file():
            lines += [l for l in path.read_text(encoding="utf-8", errors="replace").splitlines()
                      if l.startswith("notify: ")]
    return lines


def check(hid: str, cls: str, ok: bool, detail: str) -> None:
    status = "PASS" if ok else "FAIL"
    rows.append((hid, cls, status, detail))
    if not ok and cls == "MANDATORY":
        failures.append(hid)


def _classes() -> dict:
    return {"hosts": [], "vhosts": [], "ports": [], "services": [], "passive_ips": []}


def main() -> int:
    params = Params(ROOT)
    notify_lines = _notify_lines()

    # ---- I1 engine fan-out ran on the real vehicle ---------------------------
    check("I1", "MANDATORY", bool(notify_lines), f"notify_lines={len(notify_lines)} first={notify_lines[0][:120] if notify_lines else '-'} (source: run.log or console tee)")

    # ---- I2 forced failure -> FAILED alert naming module + reason -------------
    sink2: list[str] = []
    failed_status = str(params.require("run_status_failed"))
    with tempfile.TemporaryDirectory() as tmp:
        _p = params
        saved = _p.settings.get("dashboard_config_relpath")
        _p.settings["dashboard_config_relpath"] = str(Path(tmp) / "absent-config.json")
        ledger2 = run_end_notifications(
            _p, Path(tmp), TARGET, failed_status, "forced-failure-reason", "ffuf",
            {"passive_docs": 1}, 12, sender=sink2.append,
        )
        _p.settings["dashboard_config_relpath"] = saved
    failed_alerts = [t for t in sink2 if t.startswith("FAILED")]
    ok2 = (
        len(failed_alerts) == 1
        and "module=ffuf" in failed_alerts[0]
        and "reason=forced-failure-reason" in failed_alerts[0]
        and ledger2.get("summary_sent") is True
    )
    check("I2", "MANDATORY", ok2, f"alerts={failed_alerts} summary_sent={ledger2.get('summary_sent')}")

    # ---- I3 flood above threshold -> exactly ONE digest ------------------------
    sink3: list[str] = []
    flood = {"hosts": [{"host": f"h{i}.example.com", "sources": ["subfinder"]} for i in range(12)]}
    diff3 = {"schema_version": 1, "from_run": "a", "to_run": "b", "added": flood, "removed": _classes(), "changed": _classes()}
    ledger3 = evaluate_diff_alerts(params, diff3, sender=sink3.append)
    ok3 = len(sink3) == 1 and "DIGEST: 12 new findings" in sink3[0] and ledger3.get("digest_sent") is True
    check("I3", "MANDATORY", ok3, f"messages={len(sink3)} digest_sent={ledger3.get('digest_sent')} threshold={ledger3.get('digest_threshold')}")

    # ---- I4 closed-port-only diff -> silence -----------------------------------
    sink4: list[str] = []
    closed_only = {"ports": [{"host": "a.example.com", "ip": "93.184.215.14", "port": 80, "proto": "tcp"}]}
    diff4 = {"schema_version": 1, "from_run": "a", "to_run": "b", "added": _classes(), "removed": closed_only, "changed": _classes()}
    ledger4 = evaluate_diff_alerts(params, diff4, sender=sink4.append)
    ok4 = sink4 == [] and ledger4.get("alertable") == 0 and ledger4.get("skipped_reason") in ("no_added_assets", "no_alertable_assets")
    check("I4", "MANDATORY", ok4, f"messages={len(sink4)} ledger_alertable={ledger4.get('alertable')} reason={ledger4.get('skipped_reason')}")

    # ---- I5 real diff.json + disclosed section 4.6 evaluation ------------------------
    diff_ok = DIFF.is_file()
    alerts_field = None
    if notify_lines:
        try:
            alerts_field = notify_lines[0].split("alerts=", 1)[1].strip()
        except IndexError:
            alerts_field = None
    disclosed = bool(alerts_field and alerts_field != "None")
    check("I5", "MANDATORY", diff_ok and disclosed, f"diff_exists={diff_ok} alerts_field={str(alerts_field)[:140]}")

    # ---- I6 committed content via HEAD blobs + verify_b1 ----------------------
    head_ok = True
    head_detail = ""
    show = subprocess.run(["git", "show", "HEAD:tools.yaml"], cwd=ROOT, capture_output=True, text=True, check=False)
    if show.returncode != 0 or not show.stdout.strip():
        head_ok = False
        head_detail = "HEAD:tools.yaml unreadable"
    else:
        with tempfile.NamedTemporaryFile("w", suffix="tools.yaml", delete=False, encoding="utf-8") as handle:
            handle.write(show.stdout)
            tmp = handle.name
        try:
            doc = load_yaml_file(tmp) or {}
            s = doc.get("settings") or {}
            core = {
                "digest_threshold": 10,
                "scheduler_min_interval_min": 10,
                "dashboard_config_relpath": "dashboard/config.json",
                "report_dirname": "90_report",
            }
            violations = {k: s.get(k) for k, v in core.items() if s.get(k) != v}
            if violations:
                head_ok = False
                head_detail = f"HEAD tools.yaml violations={violations}"
        finally:
            Path(tmp).unlink(missing_ok=True)
    verify_diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    verify_ok = verify_diff.stdout.strip() == ""
    check("I6", "MANDATORY", head_ok and verify_ok, f"committed_head_ok={head_ok} {head_detail} verify_b1_clean={verify_ok}")

    # ---- I7 scheduler floor re-proof ------------------------------------------
    rejected = validate({"interval_minutes": 9, "enabled": True, "last_run": None}, 10)
    sched_path = ROOT / str(params.require("scheduler_filename"))
    committed_ok = False
    if sched_path.is_file():
        import json as _json

        try:
            committed_ok = not validate(_json.loads(sched_path.read_text(encoding="utf-8")), 10)
        except (ValueError, OSError):
            committed_ok = False
    check("I7", "MANDATORY", bool(rejected) and committed_ok,
          f"floor_reject={bool(rejected)} committed_scheduler_valid={committed_ok}")

    # ---- I8 honest skip-silently disclosure ------------------------------------
    summary_false = bool(notify_lines and "summary=False" in notify_lines[0])
    status_false = bool(notify_lines and "status_alert=False" in notify_lines[0])
    import os as _os

    no_creds = not str(_os.environ.get("TELEGRAM_BOT_TOKEN", "")).strip()
    check("I8", "DISCLOSURE", summary_false and status_false and no_creds,
          f"summary_false={summary_false} status_false={status_false} no_creds_in_ci={no_creds} (skip silently, verdict untouched)")

    # ---- verdict ---------------------------------------------------------------
    table = ["id\tclass\tstatus\tdetail"]
    table += [f"{hid}\t{cls}\t{st}\t{det}" for hid, cls, st, det in rows]
    VERDICT_FILE.write_text("\n".join(table) + "\n", encoding="utf-8")
    print("\n".join(table))
    print(f"ASSERTIONS {'PASS' if not failures else 'FAIL'} ({len(failures)} failing)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
