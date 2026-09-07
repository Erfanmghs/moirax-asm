"""B5 NOTIFICATIONS & SCHEDULER preflight gates -- run BEFORE the vehicle `recon.sh run`.

  G-Y1  committed B5 defaults per spec section 4.5/section 4.6/section 4.7/section 9.2-e (digest threshold
        10, scheduler min interval 10 min, default interval 240, dashboard
        config relpath, report dirname 90_report, scheduler filename, telegram
        env names + timeout from B0)
  G-Y2  wiring: engine imports + calls run_end_notifications AFTER write_diff;
        notify exposes send_run_summary / evaluate_diff_alerts / alert_worthy /
        run_end_notifications / send_status; scheduler exposes due / mark_run /
        validate
  G-Y3  committed scheduler.json is valid per pipeline.scheduler.validate
        (interval >= 10 min floor, enabled bool) and carries the 3 spec keys
  G-Y4  dashboard/config.json is gitignored + NOT committed (section 9.2-e)
  G-Y5  .env is gitignored + NOT committed (keys never committed)
  G-Y6  verify_b1.py has no working-tree diff (frozen since handoff)
  G-Y7  vehicle scope: example.com retained
  G-Y8  unit suite covers the stage: tests/test_notify.py acceptance markers

Exit 0 = all gates hold; any GATE-FAIL exits 1.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.params import Params  # noqa: E402
from pipeline.scheduler import validate  # noqa: E402
from pipeline.yaml_util import load_yaml_file  # noqa: E402

failures: list[str] = []


def check(name: str, ok: bool, detail: str) -> None:
    mark = "PASS" if ok else "GATE-FAIL"
    print(f"{mark}\t{name}\t{detail}")
    if not ok:
        failures.append(name)


def main() -> int:
    params = Params(ROOT)

    # ---- G-Y1 committed defaults -------------------------------------------
    defaults = {
        "digest_threshold": 10,
        "scheduler_min_interval_min": 10,
        "scheduler_default_interval_min": 240,
        "scheduler_filename": "scheduler.json",
        "dashboard_config_relpath": "dashboard/config.json",
        "report_dirname": "90_report",
        "telegram_timeout_sec": 10,
        "telegram_bot_token_env": "TELEGRAM_BOT_TOKEN",
        "telegram_chat_id_env": "TELEGRAM_CHAT_ID",
        "diff_filename": "diff.json",
    }
    bad = {k: params.require(k) for k, v in defaults.items() if params.require(k) != v}
    check("G-Y1 committed-defaults", not bad, f"violations={bad}")

    # ---- G-Y2 wiring ---------------------------------------------------------
    engine_text = (ROOT / "pipeline" / "engine.py").read_text(encoding="utf-8")
    notify_text = (ROOT / "pipeline" / "notify.py").read_text(encoding="utf-8")
    scheduler_text = (ROOT / "pipeline" / "scheduler.py").read_text(encoding="utf-8")
    order_idx = engine_text.find("write_diff(params, target_dir, prev, stamp)")
    notify_idx = engine_text.find("run_end_notifications(")
    wired = (
        "from pipeline.notify import run_end_notifications" in engine_text
        and order_idx != -1
        and notify_idx != -1
        and notify_idx > order_idx
    )
    notify_api = all(
        f"def {fn}(" in notify_text
        for fn in ("send_run_summary", "evaluate_diff_alerts", "alert_worthy", "run_end_notifications", "send_status")
    )
    scheduler_api = all(f"def {fn}(" in scheduler_text for fn in ("due", "mark_run", "validate"))
    check(
        "G-Y2 wiring",
        wired and notify_api and scheduler_api,
        f"engine_wired={wired} notify_api={notify_api} scheduler_api={scheduler_api}",
    )

    # ---- G-Y3 scheduler.json committed state valid ---------------------------
    sched_path = ROOT / str(params.require("scheduler_filename"))
    sched_ok = False
    detail = "missing"
    if sched_path.is_file():
        try:
            import json

            doc = json.loads(sched_path.read_text(encoding="utf-8"))
            errors = validate(doc, int(params.require("scheduler_min_interval_min")))
            keys_ok = {"interval_minutes", "enabled", "last_run"} <= set(doc)
            sched_ok = not errors and keys_ok
            detail = f"errors={errors} keys_ok={keys_ok}"
        except (ValueError, OSError) as exc:
            detail = f"parse-error={exc}"
    check("G-Y3 scheduler-state", sched_ok, detail)

    # ---- G-Y4/G-Y5 secrets never committed -----------------------------------
    def _untracked_secret(rel: str) -> bool:
        ignored = subprocess.run(
            ["git", "check-ignore", rel], cwd=ROOT, capture_output=True, text=True, check=False
        )
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch", rel], cwd=ROOT, capture_output=True, text=True, check=False
        )
        return ignored.returncode == 0 and tracked.returncode != 0

    check("G-Y4 dashboard-config-gitignored", _untracked_secret("dashboard/config.json"), "ignored + untracked")
    check("G-Y5 env-gitignored", _untracked_secret(".env"), "ignored + untracked")

    # ---- G-Y6 verify_b1 clean -------------------------------------------------
    diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    check("G-Y6 verify_b1-clean", diff.stdout.strip() == "", "no working-tree diff")

    # ---- G-Y7 vehicle scope ---------------------------------------------------
    scope = load_yaml_file(str(ROOT / "scope.yaml"))
    includes = [str(i) for i in (scope.get("includes") or [])]
    check(
        "G-Y7 vehicle-scope",
        "example.com" in includes and "*.example.com" in includes,
        f"includes={includes}",
    )

    # ---- G-Y8 unit coverage ----------------------------------------------------
    test_text = (ROOT / "tests" / "test_notify.py").read_text(encoding="utf-8")
    markers = (
        "test_summary_content",
        "test_unset_credentials_skips_silently",
        "test_new_subdomain_instant",
        "test_newly_opened_port_instant",
        "test_closed_port_only_diff_is_silent",
        "test_flood_above_threshold_sends_exactly_one_digest",
        "test_disabled_class_suppresses",
        "test_require_new_ip_known_ip_not_alerted",
        "test_failed_status_alert_names_module_and_reason",
        "test_validate_enforces_10_min_floor",
    )
    covered = all(m in test_text for m in markers)
    check("G-Y8 unit-coverage", covered, f"markers={len(markers)}")

    print(f"PREFLIGHT {'PASS' if not failures else 'FAIL'} ({len(failures)} failing)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
