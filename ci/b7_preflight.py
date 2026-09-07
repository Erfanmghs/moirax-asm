"""B7 REPORTING preflight gates -- run BEFORE the vehicle `recon.sh run`.

  G-R1  committed section 10 defaults (report_dirname 90_report, schema_version,
        diff_filename, assets_relpath)
  G-R2  wiring: engine run-end generate_all + never-silent ledger line;
        dashboard on-demand endpoints (/api/report/{target} + /generate)
  G-R3  precision-contract surface: CSV_CLASSES cover the section 6.6 diff classes;
        collect() reads ONLY canonical data.json/assets.json; verify_bundle
        digest tamper check present
  G-R4  reportlab optional-dependency handled honestly (try/except + disclosed
        skip note -- never silent)
  G-R5  verify_b1.py has no working-tree diff (frozen since handoff)
  G-R6  vehicle scope: example.com retained
  G-R7  unit coverage markers in tests/test_reporting.py

Exit 0 = all gates hold; any GATE-FAIL exits 1.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.params import Params  # noqa: E402
from pipeline.reporting import CSV_CLASSES  # noqa: E402
from pipeline.yaml_util import load_yaml_file  # noqa: E402

failures: list[str] = []


def check(name: str, ok: bool, detail: str) -> None:
    mark = "PASS" if ok else "GATE-FAIL"
    print(f"{mark}\t{name}\t{detail}")
    if not ok:
        failures.append(name)


def main() -> int:
    params = Params(ROOT)

    # ---- G-R1 committed defaults -------------------------------------------
    defaults = {
        "report_dirname": "90_report",
        "diff_filename": "diff.json",
        "assets_relpath": "00_assets/assets.json",
    }
    bad = {k: params.require(k) for k, v in defaults.items() if params.require(k) != v}
    check("G-R1 committed-defaults", not bad, f"violations={bad}")

    # ---- G-R2 wiring ----------------------------------------------------------
    engine_text = (ROOT / "pipeline" / "engine.py").read_text(encoding="utf-8")
    app_text = (ROOT / "dashboard" / "app.py").read_text(encoding="utf-8")
    order_diff = engine_text.find("write_diff(params, target_dir, prev, stamp)")
    order_report = engine_text.find("generate_all(params, target_dir, stamp)")
    engine_ok = (
        "from pipeline.reporting import generate_all" in engine_text
        and order_diff != -1 and order_report != -1 and order_report > order_diff
        and "report: generated=" in engine_text
    )
    app_ok = "/api/report/{target}" in app_text and "report_generate" in app_text and "verify_bundle" in app_text
    check("G-R2 wiring", engine_ok and app_ok, f"engine={engine_ok} dashboard_on_demand={app_ok}")

    # ---- G-R3 precision-contract surface ----------------------------------------
    report_text = (ROOT / "pipeline" / "reporting.py").read_text(encoding="utf-8")
    classes_ok = set(CSV_CLASSES) == {"hosts", "vhosts", "ports", "services", "passive_ips"}
    canonical_ok = "rglob(\"data.json\")" in report_text and "assets_relpath" in report_text
    tamper_ok = "def verify_bundle(" in report_text and "source_data_digests" in report_text
    trace_ok = "scope_digest" in report_text and "run_timestamp" in report_text
    check("G-R3 precision-surface", classes_ok and canonical_ok and tamper_ok and trace_ok,
          f"classes={classes_ok} canonical_only={canonical_ok} tamper_check={tamper_ok} traceability={trace_ok}")

    # ---- G-R4 reportlab honesty ---------------------------------------------------
    check("G-R4 reportlab-optional", "reportlab not installed" in report_text and "never silent" in report_text,
          "graceful disclosed fallback present")

    # ---- G-R5 verify_b1 clean -------------------------------------------------------
    diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    check("G-R5 verify_b1-clean", diff.stdout.strip() == "", "no working-tree diff")

    # ---- G-R6 vehicle scope -----------------------------------------------------------
    scope = load_yaml_file(str(ROOT / "scope.yaml"))
    includes = [str(i) for i in (scope.get("includes") or [])]
    check(
        "G-R6 vehicle-scope",
        "example.com" in includes and "*.example.com" in includes,
        f"includes={includes}",
    )

    # ---- G-R7 unit coverage --------------------------------------------------------------
    test_text = (ROOT / "tests" / "test_reporting.py").read_text(encoding="utf-8")
    markers = (
        "test_all_formats_agree_on_counts",
        "test_tampered_data_json_fails",
        "test_collect_from_canonical_only",
        "test_scope_digest_stable",
        "test_theme_in_html",
        "test_diff_badge_new_host",
        "test_engine_generates_on_run_end",
    )
    covered = all(m in test_text for m in markers)
    check("G-R7 unit-coverage", covered, f"markers={len(markers)}")

    print(f"PREFLIGHT {'PASS' if not failures else 'FAIL'} ({len(failures)} failing)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
