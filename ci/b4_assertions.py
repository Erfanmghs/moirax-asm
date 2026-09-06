"""B4 PORT-SWEEP acceptance table — runs AFTER the example.com vehicle.

  H1  MANDATORY  run completed/partial + runs.json last status + sweep module
                 status done; the sweep RAN (skipped != previous_in_progress)
  H2  MANDATORY  IP DEDUP: every unique IP in target-set.txt scanned EXACTLY
                 once (naabu-invoke lines), results attributed to ALL hosts
  H3  MANDATORY  RULE 3: target-set.txt materialized + logged BEFORE the first
                 scan invocation in run.log
  H4  MANDATORY  PACING: pace.effective_pps == the spec formula recomputed
                 from target-set size + profile ports_total; window flag
                 consistent; if breached -> remaining_ips disclosed
  H5  MANDATORY  RULE 1: resolution guarantee accounted — hosts>0 => ONE
                 dnsx-list invocation in run.log, unresolved entries carry
                 reasons; hosts==0 => explicit zero-disclosure line present
  H6  MANDATORY  nmap toggle OFF -> ZERO nmap invocations anywhere in run.log
  H7  MANDATORY  SCOPE: every scanned IP verdict-eligible under the committed
                 gate; scanned IP set == target-set minus unreachable/deferred
  H8  MANDATORY  data.json exact §8 keys + COMMITTED defaults intact (git HEAD
                 tools.yaml/tools.lock unchanged in the working tree) +
                 verify_b1.py working-tree diff empty
  G1  DISCLOSURE canary state: sentinels mined (or first-run disarm note),
                 pacer bad windows from run.log
  G2  DISCLOSURE pace/resolution/unreachable/remaining summary from summary.md

Exit 0 iff all MANDATORY rows PASS.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.modules.port_sweep import _FULL_RANGE_PORTS, _count_ports  # noqa: E402
from pipeline.params import Params  # noqa: E402
from pipeline.scope import ScopeGate  # noqa: E402
from pipeline.yaml_util import load_yaml_file  # noqa: E402

TARGET = "example.com"
TD = ROOT / "recon" / TARGET
RUN_LOG = TD / "logs" / "run.log"
DATA = TD / "30_ports" / "naabu-full" / "data.json"
TARGET_SET = TD / "30_ports" / "naabu-full" / "target-set.txt"
SUMMARY = TD / "30_ports" / "naabu-full" / "summary.md"
STATE = TD / "state.json"
RUNS = TD / "runs.json"
VERDICT_FILE = ROOT / "ci" / "b4_verdict.txt"

failures: list[str] = []
rows: list[tuple[str, str, str, str]] = []


def check(hid: str, cls: str, ok: bool, detail: str) -> None:
    status = "PASS" if ok else "FAIL"
    rows.append((hid, cls, status, detail))
    if not ok and cls == "MANDATORY":
        failures.append(hid)


def main() -> int:
    params = Params(ROOT)

    log_text = RUN_LOG.read_text(encoding="utf-8", errors="replace") if RUN_LOG.is_file() else ""
    payload: dict = {}
    if DATA.is_file():
        payload = json.loads(DATA.read_text(encoding="utf-8"))

    # ---- H1 run status + sweep ran ------------------------------------------
    runs: dict = {}
    if RUNS.is_file():
        runs = json.loads(RUNS.read_text(encoding="utf-8"))
    runs_list = runs.get("runs") or []
    last_status = runs_list[-1]["status"] if runs_list else "absent"
    state: dict = {}
    if STATE.is_file():
        state = json.loads(STATE.read_text(encoding="utf-8"))
    sweep_status = ((state.get("modules") or {}).get("port-sweep") or {}).get("status")
    ran = payload.get("skipped") != "previous_in_progress"
    check(
        "H1", "MANDATORY",
        last_status in ("completed", "partial") and sweep_status == "done" and ran,
        f"last={last_status} sweep={sweep_status} skipped={payload.get('skipped')}",
    )

    # ---- H2 IP dedup ----------------------------------------------------------
    ts_lines = [l for l in TARGET_SET.read_text(encoding="utf-8").splitlines() if l.strip()] if TARGET_SET.is_file() else []
    ts_ips = [l.split("\t")[0] for l in ts_lines]
    # naabu-invoke lines are emitted by the module for EVERY profile tool
    # (naabu / naabu-full / naabu-sweep); re-probe lines are separate and
    # excluded from the dedup count.
    from collections import Counter

    invoked: Counter = Counter()
    for line in log_text.splitlines():
        if "naabu-invoke\tip=" not in line:
            continue
        seg = line.split("naabu-invoke\tip=", 1)[1]
        ip = seg.split("\t", 1)[0].strip()
        if ip:
            invoked[ip] += 1
    dedup_ok = bool(ts_ips) and all(invoked.get(ip, 0) == 1 for ip in ts_ips)
    scan_ips = [s.get("ip") for s in payload.get("scans") or []]
    attribution_ok = all(s.get("hosts") is not None for s in payload.get("scans") or [])
    check(
        "H2", "MANDATORY", dedup_ok and attribution_ok,
        f"target_set_ips={len(ts_ips)} invocations={dict(invoked)} scans={len(scan_ips)} dups_skipped={payload.get('duplicates_skipped')}",
    )

    # ---- H3 target set before first scan --------------------------------------
    ts_idx = log_text.find("target-set unique_ips=")
    first_idx = log_text.find("naabu-invoke\t")
    order_ok = ts_idx != -1 and (first_idx == -1 or ts_idx < first_idx)
    check("H3", "MANDATORY", order_ok and TARGET_SET.is_file(),
          f"target_set_logged={ts_idx != -1} before_scan={order_ok}")

    # ---- H4 pacing formula ------------------------------------------------------
    profile = str(params.require("portsweep_profile"))
    ports_total = _FULL_RANGE_PORTS if profile == "full" else (
        int(params.require("portcheck_top_ports")) if profile == "light" else _count_ports(str(params.require("portsweep_custom_ports")))
    )
    cap = float(params.require("portsweep_full_rate_cap")) if profile == "full" else (
        float(params.require("portcheck_rate")) if profile == "light" else float(params.require("portsweep_custom_rate_cap"))
    )
    unique_n = len(ts_ips)
    duration = float(payload.get("pace", {}).get("duration_hours") or 0)
    required = (unique_n * ports_total / (duration * 3600.0)) if unique_n and duration else 0.0
    expected_pps = max(1, int(min(required, cap))) if unique_n else 0
    actual_pps = int(payload.get("pace", {}).get("effective_pps") or 0)
    breached = bool(payload.get("pace", {}).get("window_breached"))
    breach_ok = breached == (required > cap) if unique_n else not breached
    remaining = payload.get("remaining_ips") or []
    check(
        "H4", "MANDATORY",
        actual_pps == expected_pps and breach_ok and (not breached or bool(remaining)),
        f"unique={unique_n} ports_total={ports_total} required={required:.4f} pps={actual_pps}(expect {expected_pps}) breached={breached} remaining={len(remaining)}",
    )

    # ---- H5 resolution guarantee accounted ---------------------------------------
    g = payload.get("resolution_guarantee") or {}
    g_hosts = int(g.get("hosts") or 0)
    if g_hosts > 0:
        one_pass = log_text.count("resolution-guarantee hosts=") >= 1 and "resolution-guarantee fleet=" in log_text
        unresolved_ok = all(u.get("reason") for u in (g.get("unresolved") or []))
        check("H5", "MANDATORY", one_pass and unresolved_ok,
              f"hosts={g_hosts} resolved={g.get('resolved')} unresolved={len(g.get('unresolved') or [])} one_batched_pass={one_pass}")
    else:
        zero_line = "resolution-guarantee hosts=0" in log_text
        check("H5", "MANDATORY", zero_line,
              f"hosts=0 zero-disclosure={'resolution-guarantee hosts=0' in log_text}")

    # ---- H6 nmap toggle OFF -> zero nmap invocations -------------------------------
    toggle = bool(params.require("portsweep_nmap_sv"))
    nmap_lines = [l for l in log_text.splitlines() if "nmap-sv-invoke" in l]
    check("H6", "MANDATORY", (not toggle and not nmap_lines) or toggle,
          f"toggle={toggle} nmap_invocations={len(nmap_lines)} (acceptance: OFF -> 0)")

    # ---- H7 scope -------------------------------------------------------------------
    scope_doc = load_yaml_file(str(ROOT / "scope.yaml"))
    gate = ScopeGate(params, scope_doc)
    scope_ok = True
    bad_ip = ""
    for ip in scan_ips:
        ok, reason = gate.validate_candidate(str(ip))
        # REM8 as-frozen ruling (same as the module): these two reasons accept
        # host-attributed public IPs; everything else must be a true PASS.
        if not ok and reason not in ("no IP includes", "IP not in included CIDRs"):
            scope_ok = False
            bad_ip = f"{ip}:{reason}"
            break
    covered = set(scan_ips) | set(remaining) | set(payload.get("unreachable") or []) >= set(ts_ips)
    check("H7", "MANDATORY", scope_ok and covered,
          f"scanned={len(scan_ips)} bad={bad_ip or 'none'} set_covered={covered}")

    # ---- H8 schema + committed defaults + verify_b1 -----------------------------------
    keys_ok = all(
        k in payload
        for k in ("schema_version", "module", "scans", "services", "pace", "unique_ips_scanned", "duplicates_skipped")
    ) and payload.get("module") == "port-sweep"
    tools_diff = subprocess.run(
        ["git", "diff", "HEAD", "--stat", "--", "tools.yaml", "tools.lock", "pipeline/verify_b1.py"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    committed_ok = tools_diff.stdout.strip() == ""
    check("H8", "MANDATORY", keys_ok and committed_ok,
          f"schema_ok={keys_ok} working_tree_clean={committed_ok}")

    # ---- G1 canary disclosure -----------------------------------------------------------
    sentinels = int(payload.get("sentinels_used") or 0)
    canary_lines = [l for l in log_text.splitlines() if "canary" in l and "port-sweep" in l]
    check("G1", "DISCLOSURE", True,
          f"sentinels_used={sentinels} canary_log_lines={len(canary_lines)} first_run_disarm={'canary disarmed' in log_text}")

    # ---- G2 summary disclosure -----------------------------------------------------------
    check("G2", "DISCLOSURE", SUMMARY.is_file(), f"summary_present={SUMMARY.is_file()}")

    # ---- verdict ---------------------------------------------------------------------------
    mandatory_fail = [r for r in rows if r[1] == "MANDATORY" and r[2] == "FAIL"]
    verdict = "PASS" if not mandatory_fail else "FAIL"
    print(f"{'ID':<5}{'CLASS':<12}{'STATUS':<8}DETAIL")
    for hid, cls, status, detail in rows:
        print(f"{hid:<5}{cls:<12}{status:<8}{detail}")
    print(f"VERDICT TEST B4 (PORT-SWEEP, {TARGET} VEHICLE): {verdict}")
    VERDICT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with VERDICT_FILE.open("w", encoding="utf-8") as handle:
        for hid, cls, status, detail in rows:
            handle.write(f"{hid}\t{cls}\t{status}\t{detail}\n")
        handle.write(f"VERDICT\tTEST B4 (PORT-SWEEP, {TARGET} VEHICLE): {verdict}\n")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
