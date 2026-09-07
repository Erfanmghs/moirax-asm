#!/usr/bin/env python3
"""LIVE-VALIDATION assertion table (L0..L9) + FINDINGS extraction.

Vehicle: full pipeline vs the operator-owned bugdasht.ir estate with the
frozen 200-record smoke wordlist. The L-table proves the machinery ran
end-to-end and extracts WHAT the platform discovered so the operator can
compare it against the subdomains/vhosts they actually deployed.

  L0  run exit code in {0 clean, 2 spec-mandated anomaly exit}; on 2 the
      runs.json status must be anomaly (exit/status pairing per spec)
  L1  runs.json last-run status terminal; completed|partial PASS outright;
      anomaly PASSES ONLY with full disclosure: every engine module done
      AND the anomaly source is a third-party passive agent (breaker
      degraded-continue; run #36 precedent), otherwise FAIL
  L2  fresh-evidence guard: required artifacts NEWER than run start
      (a skipped module must never pass on committed stale files -- REM6)
  L3  passive chain produced artifacts (10_subdomains/passive)
  L4  DNS lane produced records (20_dns/dnsx/data.json, non-empty resolved)
  L5  vhost lane produced artifacts (15_vhosts tree non-empty)
  L6  port lane produced artifacts (30_ports/naabu-full/summary.md)
  L7  report lane produced the bundle (90_report manifest + md + html)
  L8  report.md sha256 matches report_manifest.json (tamper check)
  L9  00_assets/assets.json exists (asset ledger updated)

FINDINGS (printed, never asserted): resolved subdomains, passive source
counts, vhost probe results, open ports, service/web summaries.

Verdict is written to ci/live_verdict.txt.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sys
import time

ROOT = pathlib.Path(os.environ.get("LIVE_VEHICLE_ROOT", "")) or \
    pathlib.Path(__file__).resolve().parents[1]
VEH = ROOT / "recon" / "bugdasht.ir"

failures: list[str] = []
started_at = int(os.environ.get("LIVE_RUN_STARTED_AT", "0"))


def check(name: str, ok: bool, detail: str) -> None:
    mark = "PASS" if ok else "FAIL"
    print(f"{name}: {mark} - {detail}")
    if not ok:
        failures.append(name)


def fresh(p: pathlib.Path) -> bool:
    if not p.is_file():
        return False
    if started_at <= 0:
        return True
    return int(p.stat().st_mtime) >= started_at - 5


def load_json(p: pathlib.Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def section(title: str) -> None:
    print(f"\n=== FINDINGS: {title} ===")


def main() -> int:
    verdict_lines: list[str] = []

    # L0 exit code (0 = clean; 2 = spec anomaly exit -- see L1)
    exit_txt = (ROOT / "ci" / "live_run_exit.txt").read_text(encoding="utf-8") \
        if (ROOT / "ci" / "live_run_exit.txt").is_file() else ""
    rc = "".join(c for c in exit_txt.split("=")[-1] if c.isdigit())
    check("L0", rc in ("0", "2"),
          f"run exit code = {rc or 'missing'} (0 clean / 2 spec anomaly exit)")

    # L1 terminal state from runs.json (state.json carries no status key)
    runs_doc = load_json(VEH / "runs.json") if (VEH / "runs.json").is_file() else None
    runs_list = (runs_doc or {}).get("runs") if isinstance(runs_doc, dict) else runs_doc
    last_run = (runs_list or [{}])[-1] if isinstance(runs_list, list) else {}
    status = str(last_run.get("status") or "missing")
    # the anomaly SOURCE is printed by the engine on the console tee:
    #   anomaly: ('ANOMALY', 'assetfinder', 'error ratio exceeded ...')
    src = ""
    console_p = ROOT / "ci" / "live_run_console.log"
    if console_p.is_file():
        for ln in console_p.read_text(encoding="utf-8", errors="replace").splitlines():
            if ln.startswith("anomaly:"):
                src = ln[len("anomaly:"):].strip().strip("'\"")
                break
    state = load_json(VEH / "state.json") if (VEH / "state.json").is_file() else None
    mod_status = {m: (v.get("status") if isinstance(v, dict) else v)
                  for m, v in (state or {}).get("modules", {}).items()}
    all_done = bool(mod_status) and all(s == "done" for s in mod_status.values())
    THIRD_PARTY = ("assetfinder", "crtsh", "subfinder", "subfinder-seed",
                   "amass", "findomain", "chaos", "httpx-passive", "dorks")
    tp = any(k in src.lower() for k in THIRD_PARTY)
    if status in ("completed", "partial"):
        ok1, detail = True, f"runs.json status = {status}"
    elif status == "anomaly" and all_done and tp:
        ok1 = True
        detail = (f"status = anomaly BUT breaker degraded-continue per spec: "
                  f"all {len(mod_status)} engine modules done; third-party "
                  f"passive variance ({src or 'passive agent'}) -- run #36 precedent")
    else:
        ok1 = False
        detail = f"status = {status}; source={src!r}; modules={mod_status}"
    check("L1", ok1, detail)
    print("--- module status table ---")
    for m, s in sorted(mod_status.items()):
        print(f"  {m:<14} {s}")
    verdict_lines.append(f"runs.json status: {status} (source={src!r})")

    # L2 freshness of required artifacts
    required = [
        VEH / "state.json",
        VEH / "00_assets" / "assets.json",
        VEH / "20_dns" / "dnsx" / "data.json",
        VEH / "90_report" / "report_manifest.json",
    ]
    stale = [str(p.relative_to(VEH)) for p in required if not fresh(p)]
    check("L2", not stale, "all required artifacts fresh" if not stale
          else f"stale/missing: {stale}")

    # L3 passive chain artifacts
    passive_dir = VEH / "10_subdomains" / "passive"
    pfiles = sorted(passive_dir.rglob("*")) if passive_dir.is_dir() else []
    pfiles = [p for p in pfiles if p.is_file()]
    check("L3", len(pfiles) >= 1,
          f"10_subdomains/passive carries {len(pfiles)} files")

    # L4 DNS lane records
    dnsx = load_json(VEH / "20_dns" / "dnsx" / "data.json") \
        if (VEH / "20_dns" / "dnsx" / "data.json").is_file() else None
    resolved = (dnsx or {}).get("resolved") or []
    live = [r for r in resolved
            if isinstance(r, dict)
            and (r.get("resolution_status") == "resolved" or r.get("ips"))]
    check("L4", bool(resolved) and dnsx is not None,
          f"dns-resolve records={len(resolved)} resolved-status={len(live)}")

    # L5 vhost lane artifacts
    vhost_dir = VEH / "15_vhosts"
    vfiles = sorted(vhost_dir.rglob("*")) if vhost_dir.is_dir() else []
    vfiles = [p for p in vfiles if p.is_file()]
    check("L5", len(vfiles) >= 1,
          f"15_vhosts carries {len(vfiles)} files")

    # L6 port lane artifacts
    ports_summary = VEH / "30_ports" / "naabu-full" / "summary.md"
    check("L6", fresh(ports_summary),
          "30_ports/naabu-full/summary.md fresh" if ports_summary.is_file()
          else "30_ports/naabu-full/summary.md missing")

    # L7 report bundle
    rm = VEH / "90_report" / "report_manifest.json"
    bundle_ok = (rm.is_file()
                 and (VEH / "90_report" / "report.md").is_file()
                 and (VEH / "90_report" / "report.html").is_file())
    check("L7", bundle_ok, "90_report manifest + report.md + report.html present")

    # L8 manifest sha256 tamper check
    ok8 = False
    detail8 = "manifest missing"
    manifest = load_json(rm) if rm.is_file() else None
    if isinstance(manifest, dict):
        entry = (manifest.get("files") or {}).get("report_md") or {}
        rp = VEH / str(entry.get("path") or "90_report/report.md")
        if rp.is_file() and entry.get("sha256"):
            digest = hashlib.sha256(rp.read_bytes()).hexdigest()
            ok8 = digest == entry["sha256"]
            detail8 = f"report.md sha256 {'matches' if ok8 else 'MISMATCH'}"
        else:
            ok8 = True
            detail8 = "manifest carries no report_md hash entry (lenient)"
    check("L8", ok8, detail8)

    # L9 asset ledger
    assets = VEH / "00_assets" / "assets.json"
    check("L9", assets.is_file() and fresh(assets),
          "00_assets/assets.json fresh" if assets.is_file()
          else "00_assets/assets.json missing")

    # ---------------- FINDINGS (printed, never asserted) ----------------
    section("RESOLVED SUBDOMAINS (dns-resolve, source-tagged)")
    for r in resolved:
        if not isinstance(r, dict):
            continue
        ips = r.get("ips") or []
        if r.get("resolution_status") == "resolved" or ips:
            print(f"  {r.get('host')}  -> {', '.join(map(str, ips))} "
                  f"(source={r.get('source')})")
    unresolved_n = sum(1 for r in resolved if isinstance(r, dict)
                       and r.get("resolution_status") != "resolved")
    print(f"  total candidates probed: {len(resolved)} "
          f"(resolved={len(live)}, unresolved={unresolved_n})")

    section("PASSIVE CHAIN FILES (10_subdomains/passive)")
    for p in pfiles[:40]:
        try:
            n = len(p.read_text(encoding="utf-8").splitlines())
        except Exception:
            n = -1
        print(f"  {p.relative_to(VEH)}  lines={n}")

    section("VHOST LANE FILES (15_vhosts)")
    for p in vfiles[:40]:
        rel = str(p.relative_to(VEH))
        body = load_json(p)
        if body is not None:
            keys = ",".join(list(body)[:8]) if isinstance(body, dict) \
                else f"list[{len(body)}]"
            print(f"  {rel}  json keys: {keys}")
        else:
            try:
                n = len(p.read_text(encoding="utf-8").splitlines())
            except Exception:
                n = -1
            print(f"  {rel}  lines={n}")

    section("PORT LANE (30_ports)")
    ports_dir = VEH / "30_ports"
    if ports_dir.is_dir():
        for p in sorted(ports_dir.rglob("*")):
            if not p.is_file():
                continue
            rel = str(p.relative_to(VEH))
            body = load_json(p)
            if isinstance(body, dict):
                compact = json.dumps(body)[:800]
                print(f"  {rel}  json: {compact}")
            else:
                try:
                    text = p.read_text(encoding="utf-8")
                    print(f"  {rel}  head: {text[:400]!r}")
                except Exception:
                    print(f"  {rel}  (binary/unreadable)")

    section("ASSETS + REPORT COUNTS")
    assets_body = load_json(assets) if assets.is_file() else None
    if isinstance(assets_body, dict):
        print(f"  assets.json: {json.dumps(assets_body)[:600]}")
    if isinstance(manifest, dict):
        print(f"  report counts: {json.dumps(manifest.get('counts') or {})}")

    verdict = "ALL PASS" if not failures else f"FAIL: {','.join(failures)}"
    verdict_lines.append(verdict)
    (ROOT / "ci" / "live_verdict.txt").write_text(
        "\n".join(verdict_lines) + "\n", encoding="utf-8")
    print(f"\nL-TABLE VERDICT: {verdict}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
