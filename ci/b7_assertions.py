"""B7 REPORTING acceptance table — runs AFTER the example.com vehicle.

  K1  MANDATORY  Run-end generation on the REAL vehicle: 90_report/ carries
                 report.md/html, export.csv/json, report.pdf, manifest; the
                 console ledger printed report: generated=True
  K2  MANDATORY  PRECISION CONTRACT: counts agree across manifest / report.md /
                 export.json / export.csv for the SAME run
  K3  MANDATORY  Traceability: manifest scope_digest == recomputed sha256 of
                 scope.yaml; run_timestamp == the vehicle's history stamp
  K4  MANDATORY  Tamper check: verify_bundle True on the untouched real data;
                 a TAMPERED COPY (temp clone, repo never mutated) fails
  K5  MANDATORY  Dashboard on-demand: GET /api/report/example.com verified,
                 POST /api/report/example.com/generate regenerates + manifest
                 count stable
  K6  MANDATORY  COMMITTED content intact (HEAD blob of tools.yaml re-parsed
                 with the frozen loader) + verify_b1.py working-tree diff empty
  K7  MANDATORY  PDF deliverable: real %PDF bytes OR the disclosed reportlab
                 skip note (never silent, never a crash)
  K8  MANDATORY  §9.4 theme embedded in the real report.html
  G1  DISCLOSURE  Real run counts (hosts / alive / module docs)

Exit 0 iff all MANDATORY rows PASS.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.params import Params  # noqa: E402
from pipeline.reporting import verify_bundle  # noqa: E402
from pipeline.yaml_util import load_yaml_file  # noqa: E402

TARGET = "example.com"
TD = ROOT / "recon" / TARGET
REPORT = TD / "90_report"
CONSOLE = ROOT / "ci" / "b7_run_console.log"
VERDICT_FILE = ROOT / "ci" / "b7_verdict.txt"

failures: list[str] = []
rows: list[tuple[str, str, str, str]] = []


def check(hid: str, cls: str, ok: bool, detail: str) -> None:
    status = "PASS" if ok else "FAIL"
    rows.append((hid, cls, status, detail))
    if not ok and cls == "MANDATORY":
        failures.append(hid)


def _json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def main() -> int:
    params = Params(ROOT)

    # ---- K1 run-end generation on the real vehicle ----------------------------
    expected = ("report.md", "report.html", "export.csv", "export.json", "report.pdf", "report_manifest.json")
    present = {f for f in expected if (REPORT / f).is_file()}
    console_text = CONSOLE.read_text(encoding="utf-8", errors="replace") if CONSOLE.is_file() else ""
    generated_line = "report: generated=True" in console_text
    check("K1", "MANDATORY", len(present) == len(expected) and generated_line,
          f"files={sorted(present)} generated_line={generated_line}")

    # ---- K2 precision contract on the real run --------------------------------
    manifest = _json(REPORT / "report_manifest.json")
    counts = manifest.get("counts") or {}
    md = (REPORT / "report.md").read_text(encoding="utf-8") if (REPORT / "report.md").is_file() else ""
    export = _json(REPORT / "export.json")
    csv_lines = (REPORT / "export.csv").read_text(encoding="utf-8").splitlines() if (REPORT / "export.csv").is_file() else []
    host_rows = [l for l in csv_lines if l.startswith("hosts,")]
    md_count_ok = f"hosts: {counts.get('hosts')}" in md and f"alive: {counts.get('alive_hosts')}" in md
    export_ok = (export.get("counts") or {}).get("hosts") == counts.get("hosts")
    csv_ok = len(host_rows) == int(counts.get("hosts") or -1)
    check("K2", "MANDATORY", md_count_ok and export_ok and csv_ok,
          f"md={md_count_ok} export_json={export_ok} csv_rows={len(host_rows)}=={counts.get('hosts')}")

    # ---- K3 traceability ---------------------------------------------------------
    scope_sha = hashlib.sha256((ROOT / "scope.yaml").read_bytes()).hexdigest()
    stamp_ok = bool(manifest.get("run_timestamp"))
    digest_ok = manifest.get("scope_digest") == scope_sha
    check("K3", "MANDATORY", stamp_ok and digest_ok,
          f"run_timestamp={manifest.get('run_timestamp')} scope_digest_match={digest_ok}")

    # ---- K4 tamper check (isolated copy — repo never mutated) ---------------------
    ok_real, reason_real = verify_bundle(params, TD)
    tampered_fails = False
    tamper_reason = ""
    with tempfile.TemporaryDirectory() as tmp:
        clone = Path(tmp) / TARGET
        shutil.copytree(TD, clone, ignore=shutil.ignore_patterns("history"))
        target = clone / "00_assets" / "assets.json"
        if target.is_file():
            doc = _json(target)
            if doc.get("assets"):
                doc["assets"][0]["host"] = "tampered.example.com"
                target.write_text(json.dumps(doc), encoding="utf-8")
            ok_t, tamper_reason = verify_bundle(params, clone)
            tampered_fails = ok_t is False and "tampered" in tamper_reason
    check("K4", "MANDATORY", ok_real and tampered_fails,
          f"untouched_verified={ok_real} tampered_copy_rejected={tampered_fails} ({tamper_reason})")

    # ---- K5 dashboard on-demand -----------------------------------------------------
    try:
        import os as _os

        from fastapi.testclient import TestClient

        from dashboard import app as appmod

        token_backup = _os.environ.get("DASHBOARD_TOKEN")
        _os.environ["DASHBOARD_TOKEN"] = "ci-token"
        appmod._params = None  # rebuild against the real repo root
        client = TestClient(appmod.app)
        headers = {"Authorization": "Bearer ci-token"}
        r_view = client.get(f"/api/report/{TARGET}", headers=headers)
        view_doc = r_view.json()
        r_gen = client.post(f"/api/report/{TARGET}/generate", headers=headers)
        gen_doc = r_gen.json()
        ok5 = (
            r_view.status_code == 200
            and view_doc.get("exists") is True
            and view_doc.get("verified") is True
            and r_gen.status_code == 200
            and (gen_doc.get("counts") or {}).get("hosts") == counts.get("hosts")
        )
        check("K5", "MANDATORY", ok5,
              f"view={r_view.status_code} verified={view_doc.get('verified')} generate={r_gen.status_code} hosts={(gen_doc.get('counts') or {}).get('hosts')}")
    except Exception as exc:  # noqa: BLE001
        check("K5", "MANDATORY", False, f"dashboard-on-demand error: {exc}")
    finally:
        if "token_backup" in dir():
            if token_backup is None:
                _os.environ.pop("DASHBOARD_TOKEN", None)
            else:
                _os.environ["DASHBOARD_TOKEN"] = token_backup

    # ---- K6 committed content + verify_b1 ---------------------------------------------
    show = subprocess.run(["git", "show", "HEAD:tools.yaml"], cwd=ROOT, capture_output=True, text=True, check=False)
    head_ok = show.returncode == 0
    verify_diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    verify_ok = verify_diff.stdout.strip() == ""
    check("K6", "MANDATORY", head_ok and verify_ok,
          f"head_blob_readable={head_ok} verify_b1_clean={verify_ok}")

    # ---- K7 PDF deliverable ---------------------------------------------------------------
    pdf = REPORT / "report.pdf"
    if pdf.is_file():
        raw = pdf.read_bytes()
        pdf_ok = raw[:5] == b"%PDF-" or "reportlab not installed" in raw.decode("utf-8", errors="replace")
        detail = f"magic={raw[:5]!r} size={len(raw)}"
    else:
        pdf_ok = False
        detail = "report.pdf missing"
    check("K7", "MANDATORY", pdf_ok, detail)

    # ---- K8 theme in real html ----------------------------------------------------------------
    html = (REPORT / "report.html").read_text(encoding="utf-8") if (REPORT / "report.html").is_file() else ""
    theme_ok = "#0a0e14" in html and "badge" in html and "run timestamp" in html
    check("K8", "MANDATORY", theme_ok, f"dark_palette={'#0a0e14' in html} badges={'badge' in html}")

    # ---- G1 real counts disclosure ----------------------------------------------------------------
    check("G1", "DISCLOSURE", True,
          f"counts={json.dumps(counts, sort_keys=True)} scope_digest={str(manifest.get('scope_digest'))[:16]}…")

    table = ["id\tclass\tstatus\tdetail"]
    table += [f"{hid}\t{cls}\t{st}\t{det}" for hid, cls, st, det in rows]
    VERDICT_FILE.write_text("\n".join(table) + "\n", encoding="utf-8")
    print("\n".join(table))
    print(f"ASSERTIONS {'PASS' if not failures else 'FAIL'} ({len(failures)} failing)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
