"""E2E FIXTURE acceptance table (E0..E10) — full-pipeline vehicle on the
multi-port/nested-subdomain fixture (fixture-target.test -> 172.17.0.1).

Discipline (B3 F10 / REM19 H8 / REM4-R A4 lineage):
- E0 stale-evidence guard: every asserted data.json must be NEWER than the
  workflow start (env E2E_RUN_STARTED_AT, epoch seconds) — a skipped module
  must never pass on committed stale files.
- The table asserts the RUN'S OWN evidence under recon/fixture-target.test,
  never committed artifacts.
- Disclosure row: run status/reason/failing_module printed verbatim — a
  degraded run can still PASS stage-scoped checks as long as the ACTIVE
  chain (DNSR -> ffuf3 -> merge -> port-sweep -> report) is proven and the
  disclosure is honest.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from pipeline.params import Params
from pipeline.yaml_util import load_yaml_file

ROOT = Path(__file__).resolve().parents[1]
TARGET_DIR = ROOT / "recon" / "fixture-target.test"
FLAT = ("www", "app", "dev", "api", "mail")
NESTED = ("dev.app", "k8s.dev", "api.dev.app", "git.staging.app", "mail.api.dev.app")
EXPECTED_PORTS = {80, 8080, 8443, 2222, 6379, 9200}
FIXTURE_IP = "172.17.0.1"
RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str) -> None:
    RESULTS.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _fresh(path: Path) -> bool:
    """Stale-evidence guard: file must postdate the workflow start."""
    started = float(os.environ.get("E2E_RUN_STARTED_AT") or 0)
    try:
        return path.is_file() and path.stat().st_mtime > started
    except OSError:
        return False


def _params() -> Params:
    return Params(ROOT)


def _dnsr_rows(doc: Any) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for row in (doc or {}).get("resolved") or []:
        if isinstance(row, dict) and row.get("host"):
            rows[str(row["host"]).lower()] = row
    return rows


def main() -> int:
    started_wall = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(os.environ.get("E2E_RUN_STARTED_AT") or 0)))
    print(f"e2e-assertions: evidence window starts {started_wall}")

    state = _read_json(TARGET_DIR / "state.json") or {}
    run = state.get("run") or {}
    print(
        "DISCLOSURE run status="
        f"{run.get('status')} reason={run.get('reason')} failing_module={run.get('failing_module')}"
    )

    # --- E0 evidence freshness ------------------------------------------------
    dnsr_path = TARGET_DIR / "20_dns" / "dnsx" / "data.json"
    sweep_path = TARGET_DIR / "30_ports" / "naabu-full" / "data.json"
    manifest_path = TARGET_DIR / "90_report" / "report_manifest.json"
    check(
        "E0 evidence-freshness",
        all(_fresh(p) for p in (dnsr_path, sweep_path, manifest_path, TARGET_DIR / "00_assets" / "assets.json")),
        "dnsx/ports/assets/report all newer than workflow start",
    )

    # --- E1/E2 discovery (dnsx brute) ----------------------------------------
    dnsr_rows = _dnsr_rows(_read_json(dnsr_path))
    flat_missing = [n for n in FLAT if f"{n}.fixture-target.test" not in dnsr_rows]
    check("E1 flat-discovery", not flat_missing, f"resolved flat={sorted(set(FLAT) - set(flat_missing))} missing={flat_missing}")
    nested_missing = [n for n in NESTED if f"{n}.fixture-target.test" not in dnsr_rows]
    check("E2 nested-discovery", not nested_missing, f"resolved nested={sorted(set(NESTED) - set(nested_missing))} missing={nested_missing}")
    ip_ok = all(
        FIXTURE_IP in [str(x) for x in (dnsr_rows.get(f"{n}.fixture-target.test", {}).get("ips") or [])]
        for n in FLAT[:2] + NESTED[:2]
    )
    check("E2b resolution-ip", ip_ok, f"answers point at {FIXTURE_IP}")

    # --- E3 merged assets attribution ----------------------------------------
    assets_doc = _read_json(TARGET_DIR / "00_assets" / "assets.json") or {}
    assets = {str(a.get("host") or "").lower(): a for a in assets_doc.get("assets") or [] if isinstance(a, dict)}
    want_hosts = [f"{n}.fixture-target.test" for n in FLAT] + [f"{n}.fixture-target.test" for n in NESTED]
    merged_missing = [h for h in want_hosts if h not in assets]
    check("E3 merge-assets", not merged_missing, f"merged={len(want_hosts) - len(merged_missing)}/{len(want_hosts)} missing={merged_missing}")
    attributed = all(
        any("dns" in str(s).lower() for s in (assets.get(h, {}).get("sources") or []))
        for h in want_hosts
        if h in assets
    )
    check("E3b source-attribution", attributed, "every fixture asset carries a dns-source attribution")

    # --- E4 alive signal (httpx probe path engaged) ---------------------------
    alive_hosts = [h for h, a in assets.items() if a.get("alive") is True and h.endswith(".fixture-target.test")]
    check("E4 alive-probe", len(alive_hosts) >= 2, f"alive fixture assets: {sorted(alive_hosts)}")

    # --- E5 port sweep ---------------------------------------------------------
    sweep = _read_json(sweep_path) or {}
    scans = {str(s.get("ip")): s for s in (sweep.get("scans") or []) if isinstance(s, dict)}
    scan = scans.get(FIXTURE_IP) or {}
    open_ports = {int(p) for p in (scan.get("ports") or scan.get("open_ports") or [])}
    missing_ports = sorted(EXPECTED_PORTS - open_ports)
    check("E5 port-sweep", not missing_ports and scan, f"open on {FIXTURE_IP}: {sorted(open_ports)} missing={missing_ports}")
    pace = sweep.get("pace") or {}
    check(
        "E5b pace-disclosure",
        bool(pace) and sweep.get("skipped") is None,
        f"pace keys={sorted(pace)[:6]} skipped={sweep.get('skipped')}",
    )

    # --- E6 vhost lane ran ------------------------------------------------------
    ffuf3 = _read_json(TARGET_DIR / "15_vhosts" / "ffuf-3" / "data.json")
    check("E6 ffuf3-vhost-lane", isinstance(ffuf3, dict) and "schema_version" in ffuf3, "ffuf-3 data.json present + schema-stamped")

    # --- E7 report bundle + tamper check --------------------------------------
    from pipeline.reporting import verify_bundle

    verified, reason = verify_bundle(_params(), TARGET_DIR)
    check("E7 report-bundle-verified", bool(manifest_path.is_file()) and verified, str(reason))

    # --- E8 storage housekeeping engaged --------------------------------------
    run_log = TARGET_DIR / "logs" / "run.log"
    storage_lines = [ln for ln in run_log.read_text(encoding="utf-8").splitlines() if ln.startswith("storage: applied=")] if run_log.is_file() else []
    check("E8 storage-housekeeping", any("storage: applied=True" in ln for ln in storage_lines), f"{len(storage_lines)} ledger line(s)")

    # --- E9 scope clean ---------------------------------------------------------
    oos = TARGET_DIR / "logs" / "out_of_scope.log"
    oos_lines = [ln for ln in oos.read_text(encoding="utf-8").splitlines() if ln.strip()] if oos.is_file() else []
    check("E9 scope-clean", not oos_lines, f"{len(oos_lines)} out-of-scope rejection(s)")

    # --- E10 frozen-code / transient discipline --------------------------------
    ledger = ROOT / "ci" / "e2e_transient_edits.log"
    status = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout
    mutable_prefixes = (
        "resolvers.yaml", "tools.yaml", "wordlists.yaml",
        "resolvers/forge/", "wordlists/forge/", "recon/", "logs/", "ci/", "dashboard/config.json",
    )
    outside = [ln for ln in status.splitlines() if ln.strip() and not ln.startswith("?? ") and not any(ln[3:].startswith(p) for p in mutable_prefixes)]
    untracked_outside = [
        ln for ln in status.splitlines()
        if ln.startswith("?? ") and not any(ln[3:].startswith(p) for p in mutable_prefixes)
    ]
    check(
        "E10 transient-discipline",
        ledger.is_file() and not outside and not untracked_outside,
        f"tracked-outside={outside} untracked-outside={untracked_outside}",
    )

    # --- verdict ----------------------------------------------------------------
    failed = [name for name, ok, _ in RESULTS if not ok]
    verdict = "PASS" if not failed else "FAIL"
    table = "\n".join(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}" for name, ok, detail in RESULTS)
    line = f"E2E VERDICT ({TARGET_DIR.name} vehicle): {verdict} ({len(RESULTS) - len(failed)}/{len(RESULTS)})"
    print(table)
    print(line)
    (ROOT / "ci" / "e2e_verdict.txt").write_text(table + "\n" + line + "\n", encoding="utf-8")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
